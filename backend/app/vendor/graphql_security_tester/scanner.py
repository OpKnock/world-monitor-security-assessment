from __future__ import annotations

import re
from dataclasses import dataclass, field

FIELD_RE = re.compile(r"\s*(?P<alias>[A-Za-z_][A-Za-z0-9_]*\s*:\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(\([^)]*\))?")
STRING_RE = re.compile(r'"[^"]*"|\'[^\']*\'')

RISKY_NAMES = {"introspectionquery", "systemquery", "admin", "users", "token", "password", "secret", "keys", "debug"}
MAX_ALIASES = 10
MAX_DEPTH = 10
MAX_DUPLICATES = 3


@dataclass
class QueryAnalysis:
    operation: str | None
    fields: list[str] = field(default_factory=list)
    depth: int = 0
    aliases: int = 0
    duplicate_fields: int = 0
    risky_names: list[str] = field(default_factory=list)

    @property
    def complexity(self) -> int:
        return self.depth + len(self.fields) + self.aliases * 2 + self.duplicate_fields * 3

    @property
    def risky(self) -> bool:
        return bool(self.risky_names) or self.depth > MAX_DEPTH or self.aliases > MAX_ALIASES

    def issues(self, max_depth: int = MAX_DEPTH, max_aliases: int = MAX_ALIASES,
               max_duplicates: int = MAX_DUPLICATES) -> list[str]:
        out = []
        if self.depth > max_depth:
            out.append(f"depth {self.depth} exceeds limit {max_depth}")
        if self.aliases > max_aliases:
            out.append(f"{self.aliases} aliases exceed limit {max_aliases}")
        if self.duplicate_fields > max_duplicates:
            out.append(f"{self.duplicate_fields} duplicated fields exceed limit {max_duplicates}")
        if self.risky_names:
            out.append("risky fields: " + ", ".join(sorted(self.risky_names)))
        return out


@dataclass
class IntrospectionReport:
    query_type: list[str] = field(default_factory=list)
    mutation_type: list[str] = field(default_factory=list)
    subscription_type: list[str] = field(default_factory=list)
    exposed_count: int = 0
    findings: list[str] = field(default_factory=list)


def _strip_strings(text: str) -> str:
    out = STRING_RE.sub("", text)
    out = re.sub(r"#.*$", "", out, flags=re.MULTILINE)
    return out


def _find_matching(text: str, start: int) -> int | None:
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _split_entries(segment: str) -> list[str]:
    entries: list[str] = []
    current = ""
    depth = 0
    paren = 0
    n = len(segment)
    for idx, ch in enumerate(segment):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        if ch == "," and depth == 0 and paren == 0:
            entries.append(current)
            current = ""
        elif ch.isspace() and depth == 0 and paren == 0:
            nxt = idx + 1
            while nxt < n and segment[nxt].isspace():
                nxt += 1
            if nxt < n and segment[nxt] == "{":
                current += ch
            elif current.strip().endswith(":"):
                current += ch
            elif current.strip():
                entries.append(current)
                current = ""
        else:
            current += ch
    if current.strip():
        entries.append(current)
    return entries


def _parse_selection_set(text: str, depth: int, fields: list[str], aliases: list[bool], risky: list[str]) -> int:
    max_seen = depth
    i = 0
    while True:
        brace = text.find("{", i)
        if brace == -1:
            return max_seen
        close = _find_matching(text, brace)
        if close is None:
            return max_seen
        segment = text[brace + 1 : close]
        for entry in _split_entries(segment):
            m = FIELD_RE.match(entry)
            if not m:
                continue
            name = m.group("name")
            if name in ("query", "mutation", "subscription"):
                continue
            fields.append(name)
            aliases.append(1 if m.group("alias") else 0)
            if name.lower() in RISKY_NAMES:
                risky.append(name)
            sub = entry.find("{")
            if sub != -1:
                sub_close = _find_matching(entry, sub)
                if sub_close is not None:
                    child_depth = _parse_selection_set(entry[sub : sub_close + 1], depth + 1, fields, aliases, risky)
                    max_seen = max(max_seen, child_depth)
        i = close + 1


def parse_query(query: str) -> QueryAnalysis:
    """Analyze a GraphQL query document (structure only)."""
    cleaned = _strip_strings(query)
    op_match = re.search(r"\b(query|mutation|subscription)\b", cleaned)
    operation = op_match.group(1) if op_match else None
    fields: list[str] = []
    aliases: list[bool] = []
    risky: list[str] = []
    max_depth = 0

    def walk(text: str, d: int) -> None:
        nonlocal max_depth
        depth_seen = _parse_selection_set(text, d, fields, aliases, risky)
        max_depth = max(max_depth, depth_seen)

    if "{" in cleaned:
        walk(cleaned, 1)
    counts: dict[str, int] = {}
    for f in fields:
        counts[f] = counts.get(f, 0) + 1
    duplicates = sum(1 for c in counts.values() if c > 1)
    return QueryAnalysis(
        operation=operation,
        fields=fields,
        depth=max_depth,
        aliases=sum(aliases),
        duplicate_fields=duplicates,
        risky_names=list(dict.fromkeys(risky)),
    )


def _field_name(entry: str) -> str:
    m = re.match(r"(?:[A-Za-z_][A-Za-z0-9_]*\s*:\s*)?([A-Za-z_][A-Za-z0-9_]*)", entry)
    return m.group(1) if m else entry.split("(")[0].strip()


def analyze_introspection(schema_text: str) -> IntrospectionReport:
    """Scan an SDL/JSON schema for introspection exposure signals."""
    report = IntrospectionReport()
    if "__schema" in schema_text or "__type" in schema_text:
        report.findings.append("introspection exposed (__schema/__type present)")
    for m in re.finditer(r"\btype\s+Query\s*{([^}]*)}", schema_text):
        report.query_type = [_field_name(f) for f in _split_entries(m.group(1)) if f.strip()]
    for m in re.finditer(r"\btype\s+Mutation\s*{([^}]*)}", schema_text):
        report.mutation_type = [_field_name(f) for f in _split_entries(m.group(1)) if f.strip()]
    for m in re.finditer(r"\btype\s+Subscription\s*{([^}]*)}", schema_text):
        report.subscription_type = [_field_name(f) for f in _split_entries(m.group(1)) if f.strip()]
    report.exposed_count = len(report.query_type) + len(report.mutation_type) + len(report.subscription_type)
    if any("password" in f.lower() or "secret" in f.lower() or "token" in f.lower() for f in
           report.query_type + report.mutation_type):
        report.findings.append("sensitive-named fields exposed")
    if not report.query_type and not report.mutation_type:
        report.findings.append("no Query/Mutation root types found")
    return report
