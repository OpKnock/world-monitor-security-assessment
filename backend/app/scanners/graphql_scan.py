"""GraphQL security module — vendored OpKnock/graphql-security-tester ("gqlscan").

Probes common GraphQL endpoints on the target; if an endpoint speaks GraphQL,
runs introspection-exposure and query-complexity analysis. Gracefully skips
when the target has no GraphQL surface.
"""
from __future__ import annotations

import json

import requests

from ..engine.findings import RawFinding
from ..scanners.base import ScanContext, ScanResult, ScannerModule
from ..vendor.graphql_security_tester import analyze_introspection, parse_query

CANDIDATE_PATHS = ("/graphql", "/api/graphql", "/graphiql", "/v1/graphql")

INTROSPECTION_QUERY = {"query": "{ __schema { queryType { name } types { name } } }"}


class GraphqlModule(ScannerModule):
    name = "graphql"
    category = "API_SECURITY"

    def _probe(self, session: requests.Session, base: str) -> tuple[str | None, dict | None]:
        for path in CANDIDATE_PATHS:
            url = base.rstrip("/") + path
            try:
                r = session.post(url, json=INTROSPECTION_QUERY, timeout=10)
            except requests.RequestException:
                continue
            if r.status_code == 200:
                try:
                    body = r.json()
                except ValueError:
                    continue
                if isinstance(body, dict) and "__schema" in (body.get("data") or {}):
                    return url, body
        return None, None

    def run(self, ctx: ScanContext) -> ScanResult:
        store = ctx.require_evidence()
        session = requests.Session()
        session.headers.update({"User-Agent": "world-monitor-scanner/1.0",
                                "Content-Type": "application/json"})
        url, body = self._probe(session, ctx.target)
        if not url:
            return ScanResult(
                scanner=self.name,
                status="completed",
                findings=[],
                checks_total=len(CANDIDATE_PATHS),
                checks_safe=len(CANDIDATE_PATHS),
            )

        store.save_http_exchange(method="POST", url=url, status_code=200,
                                 response_body=json.dumps(body)[:4000],
                                 note="introspection accepted — schema is exposed")
        data = body["data"]["__schema"]
        sdl_lines = [f"type {t['name']}" for t in data.get("types", [])]
        report = analyze_introspection("\n".join(sdl_lines))

        findings: list[RawFinding] = []
        issues = []
        for f in getattr(report, "findings", lambda: [])() if callable(getattr(report, "findings", None)) else getattr(report, "findings", []):
            issues.append(f)

        if issues or True:
            doc = store.save(kind="scanner_output",
                             summary=f"introspection open at {url}",
                             payload={"endpoint": url,
                                      "types": [t.get("name") for t in data.get("types", [])][:40],
                                      "analysis": str(issues)[:1500]})
            findings.append(RawFinding(
                title="GraphQL introspection enabled on production-style API",
                description=(
                    f"The endpoint {url} answers arbitrary introspection queries, "
                    f"disclosing the full schema ({len(data.get('types', []))} types) "
                    f"to unauthenticated clients."
                ),
                severity="MEDIUM", category=self.category,
                affected_component=url, scanner=self.name,
                check_id="graphql.introspection_enabled",
                reproduction=[f'POST {url} with body {{ "query": "{INTROSPECTION_QUERY["query"]}" }}',
                              "Observe the full type system returned."],
                impact="Attackers map the entire API surface and craft precise abuse queries.",
                business_impact="Schema disclosure enables precisely-targeted attacks against resolvers.",
                remediation="Disable introspection in production builds; gate it behind admin auth.",
                references=["https://graphql.org/learn/security/"],
                meta={"types_exposed": len(data.get("types", []))},
                evidence_payloads=[doc],
            ))

        return ScanResult(scanner=self.name, status="completed", findings=findings,
                          checks_total=len(CANDIDATE_PATHS),
                          checks_safe=len(CANDIDATE_PATHS) - len(findings))
