"""Dependency reachability analysis — determines if vulnerable code is actually called."""
from pathlib import Path
from typing import Any
import json
import re

# Known vulnerable function patterns for common CVEs
# In production, this would come from a vulnerability database
VULN_PATTERNS: dict[str, list[str]] = {
    # Example: CVE-2023-xxxx in package@version
    "nanoid@<3.3.4": ["nanoid"],
    "image-size@<1.0.1": ["imageSize", "sizeOf"],
    "lodash@<4.17.21": ["_.template", "_.merge", "_.defaultsDeep"],
    "axios@<1.6.0": ["axios"],
}

def extract_imports(source_path: Path, language: str) -> list[str]:
    """Extract imported/used function names from source code."""
    imports: set[str] = set()
    patterns = {
        "javascript": [
            r"import\s+.*\s+from\s+['\"]([^'\"]+)['\"]",
            r"require\(['\"]([^'\"]+)['\"]\)",
            r"from\s+['\"]([^'\"]+)['\"]\s+import",
        ],
        "typescript": [
            r"import\s+.*\s+from\s+['\"]([^'\"]+)['\"]",
            r"require\(['\"]([^'\"]+)['\"]\)",
        ],
        "python": [
            r"^import\s+([A-Za-z0-9_.]+)",
            r"^from\s+([A-Za-z0-9_.]+)\s+import",
        ],
        "go": [
            r"import\s+\(",
            r"import\s+\"([^\"]+)\"",
        ],
        "rust": [
            r"use\s+([A-Za-z0-9_:]+);",
            r"extern\s+crate\s+(\w+);",
        ],
    }
    
    lang_patterns = patterns.get(language, [])
    if not lang_patterns:
        return []
    
    for ext in {".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".rs"}:
        for file in source_path.rglob(f"*{ext}"):
            try:
                content = file.read_text(encoding="utf-8", errors="ignore")
                for pattern in lang_patterns:
                    for match in re.finditer(pattern, content, re.MULTILINE):
                        imports.add(match.group(1))
            except Exception:
                pass
    return list(imports)

def check_reachability(components: list[dict], source_path: Path) -> list[dict]:
    """Annotate SBOM components with reachability status."""
    # Detect languages from source
    languages = set()
    if list(source_path.rglob("*.js")) or list(source_path.rglob("*.ts")):
        languages.add("javascript")
    if list(source_path.rglob("*.py")):
        languages.add("python")
    if list(source_path.rglob("*.go")):
        languages.add("go")
    if list(source_path.rglob("*.rs")):
        languages.add("rust")
    
    all_imports = set()
    for lang in languages:
        all_imports.update(extract_imports(source_path, lang))
    
    for comp in components:
        name = comp.get("name", "").lower()
        version = comp.get("version", "")
        key = f"{name}@{version}"
        
        # Check if any vulnerable pattern matches
        reachable = False
        matched_functions = []
        for vuln_key, funcs in VULN_PATTERNS.items():
            if name in vuln_key.lower():
                for func in funcs:
                    if func in all_imports or any(func in imp for imp in all_imports):
                        reachable = True
                        matched_functions.append(func)
        
        comp["reachability"] = {
            "reachable": reachable,
            "matched_functions": matched_functions,
            "confidence": "high" if reachable else "unknown",
        }
    
    return components

def analyze_dependencies(assessment_id: str, source_path: str = "") -> dict[str, Any]:
    """Full dependency analysis with reachability."""
    from .sbom import generate_sbom
    
    sbom = generate_sbom(assessment_id, source_path)
    if source_path:
        sbom["components"] = check_reachability(sbom["components"], Path(source_path))
    
    # Summary
    total = len(sbom["components"])
    reachable = sum(1 for c in sbom["components"] if c.get("reachability", {}).get("reachable"))
    
    return {
        "sbom": sbom,
        "summary": {
            "total_components": total,
            "reachable_vulns": reachable,
            "reachability_percentage": round((reachable / total * 100) if total > 0 else 0, 1),
        },
    }