"""GraphQL security module — vendored OpKnock/graphql-security-tester ("gqlscan").

Probes common GraphQL endpoints on the target; if an endpoint speaks
GraphQL, runs introspection-exposure and (optionally) query-complexity
analysis.  Gracefully skips when the target has no GraphQL surface.

Probe strategy
--------------
1. Iterate ``CANDIDATE_PATHS`` (``/graphql``, ``/api/graphql``, …) with
   ``POST <base+path> { "query": "{ __schema { … } }" }``.
2. Auth token passthrough — when ``ctx.auth_token`` is present the probe
   sends ``Authorization: Bearer …`` so that authenticated GraphQL
   deployments are also tested.
3. ``200`` + JSON containing ``data.__schema`` → GraphQL confirmed.
4. Introspection body is saved as ``http_exchange`` evidence and analysed
   with :func:`analyze_introspection`.  Findings are emitted only when
   that analyser returns textual findings (introspection is otherwise
   silently “no issue”).

The module never sends destructive mutations; probes are read-only.

Robustness
----------
* Per-request timeout from ``ctx.effective_timeout()`` (default 10 s).
* ``requests.RequestException`` and JSON-decode errors are tolerated —
  the probe simply tries the next candidate.
* ``scan_target`` on emitted findings is the *actual* GraphQL endpoint URL
  (``https://host/graphql``), not the assessment root, so retest targets
  the right resource.
* Evidence is persisted exactly once per successful probe.
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

import requests

from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule
from ..vendor.graphql_security_tester import analyze_introspection, parse_query  # parse_query kept for future depth checks

logger = logging.getLogger(__name__)

__all__ = ["GraphqlModule"]

CANDIDATE_PATHS: tuple[str, ...] = ("/graphql", "/api/graphql", "/graphiql", "/v1/graphql")

INTROSPECTION_QUERY: dict[str, str] = {"query": "{ __schema { queryType { name } types { name } } }"}


class GraphqlModule(ScannerModule):
    name = "graphql"
    category = "API_SECURITY"
    description = "Detects GraphQL introspection / schema exposure"

    def _probe(self, session: requests.Session, base: str, timeout: float) -> tuple[str | None, dict[str, Any] | None]:
        """Return ``(endpoint_url, parsed_json)`` for the first GraphQL endpoint found."""
        base = base.rstrip("/")
        for path in CANDIDATE_PATHS:
            url = base + path
            try:
                # Explicit JSON content-type — some GraphQL servers reject
                # form-encoded bodies.
                r = session.post(url, json=INTROSPECTION_QUERY, timeout=timeout, allow_redirects=False)
            except requests.RequestException as exc:
                logger.debug("GraphQL probe %s failed: %s", url, exc)
                continue
            if r.status_code != 200:
                continue
            try:
                body = r.json()
            except ValueError:
                logger.debug("GraphQL probe %s returned non-JSON 200", url)
                continue
            if not isinstance(body, dict):
                continue
            data = body.get("data")
            if isinstance(data, dict) and "__schema" in data:
                return url, body
            # Some servers wrap errors as 200 with `errors` key — not a hit.
        return None, None

    def run(self, ctx: ScanContext) -> ScanResult:
        started = time.perf_counter()
        if not ctx.has_http_target:
            return ScanResult(
                scanner=self.name,
                status="failed",
                errors=["HTTP target is required for GraphQL probes"],
                checks_total=len(CANDIDATE_PATHS),
                duration_s=round(time.perf_counter() - started, 3),
            )
        store = ctx.require_evidence()
        timeout = ctx.effective_timeout(10.0)

        session = requests.Session()
        # Content-Type is required for GraphQL JSON; User-Agent identifies us.
        headers: dict[str, str] = {"User-Agent": "world-monitor-scanner/1.0", "Content-Type": "application/json"}
        if ctx.auth_token:
            headers["Authorization"] = f"Bearer {ctx.auth_token}"
        session.headers.update(headers)

        url, body = self._probe(session, ctx.target, timeout=timeout)

        if not url or body is None:
            # No GraphQL surface — counts as all checks safe.
            return ScanResult(
                scanner=self.name,
                status="completed",
                findings=[],
                checks_total=len(CANDIDATE_PATHS),
                checks_safe=len(CANDIDATE_PATHS),
                duration_s=round(time.perf_counter() - started, 3),
                notes=["No GraphQL endpoint responded affirmatively on known paths"],
            )

        # Persist the raw introspection response (truncated, masked).
        try:
            evidence_body = json.dumps(body)
        except (TypeError, ValueError):
            evidence_body = str(body)
        try:
            store.save_http_exchange(
                method="POST",
                url=url,
                status_code=200,
                request_headers=dict(session.headers),
                response_body=evidence_body[:4000],
                note="introspection accepted — schema is exposed",
            )
        except Exception as exc:
            logger.warning("Failed to persist GraphQL http_exchange: %s", exc, exc_info=True)

        # Extract schema text for the vendored analyser.  The analyser expects
        # SDL-like text; we reconstruct a minimal type list from the JSON.
        data = body.get("data") if isinstance(body.get("data"), dict) else {}
        schema = data.get("__schema") if isinstance(data, dict) else {}  # type: ignore
        if not isinstance(schema, dict):
            schema = {}
        types_list: list[dict[str, Any]] = schema.get("types") if isinstance(schema.get("types"), list) else []
        sdl_lines = [f"type {t.get('name', 'Unknown')}" for t in types_list if isinstance(t, dict) and t.get("name")]

        # ``analyze_introspection`` may be re-entrant and may enumerate
        # risky fields from SDL text; feed it the joined type list.
        try:
            report = analyze_introspection("\n".join(sdl_lines) if sdl_lines else json.dumps(body)[:2000])
        except Exception as exc:
            logger.warning("analyze_introspection failed: %s", exc, exc_info=True)
            report = None

        findings: list[RawFinding] = []
        issues: list[Any] = []
        if report is not None:
            # report.findings may be a list or a callable returning a list
            # (older vendored shape).  Normalize.
            raw_findings = getattr(report, "findings", [])
            if callable(raw_findings):
                try:
                    raw_findings = raw_findings()  # type: ignore[call-arg]
                except Exception as exc:
                    logger.debug("report.findings() callable failed: %s", exc)
                    raw_findings = []
            # raw_findings should now be iterable.
            try:
                for entry in list(raw_findings or []):
                    issues.append(entry)
            except TypeError:
                # Not iterable — wrap as single issue.
                issues.append(str(raw_findings))

        # Fallback: if the analyser returned no structured findings but we
        # *did* get a valid __schema back, that itself is an exposure.
        if not issues:
            # Check if the schema response is substantive (types > threshold).
            # Empty __schema types is not interesting; treat as safe.
            if len(types_list) > 2:
                issues.append("introspection enabled — __schema disclosed to caller")

        if issues:
            try:
                doc = store.save(
                    kind="scanner_output",
                    summary=f"introspection open at {url}",
                    payload={
                        "endpoint": url,
                        "types": [t.get("name") for t in types_list if isinstance(t, dict)][:40],
                        "type_count": len(types_list),
                        "analysis": str(issues)[:1500],
                        "raw_issue_count": len(issues),
                    },
                )
            except Exception as exc:
                logger.debug("Failed to persist GraphQL finding evidence: %s", exc)
                doc = {"path": "", "kind": "scanner_output", "summary": f"introspection open at {url}"}

            findings.append(
                RawFinding(
                    title="GraphQL introspection enabled on production-style API",
                    description=(
                        f"The endpoint {url} answers arbitrary introspection queries, "
                        f"disclosing the full schema ({len(types_list)} types) to callers."
                    ),
                    severity="MEDIUM",
                    category=self.category,
                    affected_component=url,
                    scanner=self.name,
                    check_id="graphql.introspection_enabled",
                    scan_target=url,
                    reproduction=[
                        f'POST {url} with body {{ "query": "{INTROSPECTION_QUERY["query"]}" }}',
                        "Observe the full type system returned in data.__schema.types.",
                    ],
                    impact="Attackers map the entire API surface and craft precisely-targeted abuse queries.",
                    business_impact="Schema disclosure enables targeted attacks against resolvers.",
                    remediation="Disable introspection in production builds; gate it behind admin auth or build-time flag.",
                    references=["https://graphql.org/learn/security/"],
                    meta={"types_exposed": len(types_list), "issues": [str(i)[:200] for i in issues[:5]]},
                    evidence_payloads=[doc],
                )
            )

        duration = round(time.perf_counter() - started, 3)
        # checks_total is candidate paths probed; safe is that minus findings
        # (introspection collapse: number of GraphQL risks, capped at total).
        total = len(CANDIDATE_PATHS)
        # If we found an endpoint, that's the only one that matters for safe
        # count — report 1 exposure max (multiple paths hitting same GQL is
        # not multiple findings).
        exposed = min(len(findings), total)
        return ScanResult(
            scanner=self.name,
            status="completed",
            findings=findings,
            checks_total=total,
            checks_safe=max(total - exposed, 0),
            duration_s=duration,
        )
