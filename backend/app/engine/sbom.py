"""SBOM generation (CycloneDX 1.4) — parses lockfiles for reproducible source of truth."""
from pathlib import Path
import json
import re
import hashlib
from typing import Any

LOCKFILE_PARSERS = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "requirements.txt": "pip",
    "poetry.lock": "poetry",
    "uv.lock": "uv",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.toml": "cargo",
    "Cargo.lock": "cargo",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "gradle.lockfile": "gradle",
}

def parse_package_lock(path: Path) -> list[dict]:
    """Parse npm package-lock.json v2+."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        components = []
        packages = data.get("packages", {})
        for pkg_path, pkg_info in packages.items():
            if pkg_path == "":
                continue
            name = pkg_path.split("node_modules/")[-1]
            version = pkg_info.get("version", "unknown")
            resolved = pkg_info.get("resolved", "")
            integrity = pkg_info.get("integrity", "")
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}",
                "hashes": [{"alg": "SHA-512", "content": integrity}] if integrity else [],
                "externalReferences": [{"type": "distribution", "url": resolved}] if resolved else [],
            })
        return components
    except Exception:
        return []

def parse_cargo_lock(path: Path) -> list[dict]:
    """Parse Cargo.lock for exact versions."""
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        components = []
        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            source = pkg.get("source", "")
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:cargo/{name}@{version}",
                "externalReferences": [{"type": "distribution", "url": source}] if source and "registry" in source else [],
            })
        return components
    except Exception:
        return []

def parse_go_mod(path: Path) -> list[dict]:
    """Parse go.mod for module declarations."""
    try:
        content = path.read_text(encoding="utf-8")
        components = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("require") or (line and not line.startswith("//") and "/" in line and " " in line):
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    version = parts[1].replace("v", "")
                    components.append({
                        "type": "library",
                        "name": name,
                        "version": version,
                        "purl": f"pkg:golang/{name}@{version}",
                    })
        return components
    except Exception:
        return []

def parse_requirements_txt(path: Path) -> list[dict]:
    """Parse requirements.txt."""
    try:
        components = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                match = re.match(r"([A-Za-z0-9_.-]+)(?:==|>=|<=|~=|!=)?(.*)", line)
                if match:
                    name, version = match.groups()
                    components.append({
                        "type": "library",
                        "name": name.lower(),
                        "version": version or "unknown",
                        "purl": f"pkg:pypi/{name.lower()}@{version or 'unknown'}",
                    })
        return components
    except Exception:
        return []

def parse_poetry_lock(path: Path) -> list[dict]:
    """Parse poetry.lock."""
    try:
        import tomllib
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        components = []
        for pkg in data.get("package", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
            })
        return components
    except Exception:
        return []

PARSERS = {
    "package-lock.json": parse_package_lock,
    "Cargo.lock": parse_cargo_lock,
    "go.mod": parse_go_mod,
    "requirements.txt": parse_requirements_txt,
    "poetry.lock": parse_poetry_lock,
}

def scan_lockfiles(root: Path) -> list[dict]:
    """Walk source tree and parse all recognized lockfiles."""
    all_components: list[dict] = []
    for lockfile, parser in PARSERS.items():
        for found in root.rglob(lockfile):
            try:
                all_components.extend(parser(found))
            except Exception:
                pass
    return all_components

def generate_sbom(assessment_id: str, source_path: str = "") -> dict:
    """Generate CycloneDX 1.4 SBOM from lockfiles in source_path."""
    components = []
    if source_path:
        root = Path(source_path)
        if root.exists():
            components = scan_lockfiles(root)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{hashlib.md5(assessment_id.encode()).hexdigest()}",
        "version": 1,
        "metadata": {
            "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "tools": [{"name": "world-monitor", "version": "1.0"}],
        },
        "components": components,
    }

def generate_sbom_json(assessment_id: str, source_path: str = "") -> str:
    return json.dumps(generate_sbom(assessment_id, source_path), indent=2)