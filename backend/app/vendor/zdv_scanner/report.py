import json


def finding_to_dict(finding):
    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return {
        "plugin": getattr(finding, "plugin", ""),
        "severity": getattr(finding, "severity", "medium"),
        "title": getattr(finding, "title", ""),
        "detail": getattr(finding, "detail", ""),
        "score": getattr(finding, "score", 0.0),
        "evidence": getattr(finding, "evidence", ""),
    }


def to_json(result, indent=2):
    payload = result.to_dict() if hasattr(result, "to_dict") else result
    return json.dumps(payload, indent=indent)


def to_markdown(result):
    data = result.to_dict() if hasattr(result, "to_dict") else result
    target = data.get("target", {})
    lines = [
        f"# Vulnerability scan report: {target.get('name', 'unknown')}",
        "",
        f"- Host: `{target.get('host')}`  Port: `{target.get('port')}`  Scheme: `{target.get('scheme')}`",
        f"- Elapsed: {data.get('elapsed', 0)} s",
        "",
    ]
    findings = data.get("findings", [])
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)
    lines.append(f"## Findings ({len(findings)})")
    lines.append("")
    for index, finding in enumerate(findings, start=1):
        lines.append(f"### {index}. [{finding.get('severity', 'medium').upper()}] {finding.get('title')}")
        lines.append("")
        if finding.get("detail"):
            lines.append(f"{finding['detail']}")
            lines.append("")
        if finding.get("evidence"):
            lines.append(f"Evidence: `{finding['evidence']}`")
            lines.append("")
        if finding.get("score"):
            lines.append(f"CVSS score: {finding['score']}")
            lines.append("")
    return "\n".join(lines)


def write_report(result, fmt="json", path=None):
    if fmt == "json":
        content = to_json(result)
        default_name = "scan_report.json"
    elif fmt == "markdown":
        content = to_markdown(result)
        default_name = "scan_report.md"
    else:
        raise ValueError(f"unsupported format: {fmt}")
    if path is None:
        return content
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path
