"""Dependency vulnerability scanner — OSV + NVD + MITRE.

Supported manifests: requirements.txt, Pipfile.lock, pyproject.toml,
package.json, package-lock.json, yarn.lock, Cargo.lock, go.sum, Gemfile.lock
"""
import re
import json
from pathlib import Path
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.models import Finding, CVEReference, Severity
from validators import osv, nvd, mitre

Package = Tuple[str, str, str]  # (name, version, osv_ecosystem)

_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", ".pytest_cache", "vendor",
    "third_party", ".tox", "site-packages",
}


def get_packages(path: str) -> List[dict]:
    """Return list of packages as dicts for SBOM: [{"name", "version", "ecosystem"}, ...]."""
    root = Path(path)
    packages: List[Package] = []
    for manifest in _find_manifests(root):
        packages.extend(_parse_manifest(manifest))
    seen = set()
    out = []
    for name, version, ecosystem in sorted(set(packages)):
        key = (name, version, ecosystem)
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "version": version, "ecosystem": ecosystem})
    return out


def scan(path: str, progress_callback=None) -> List[Finding]:
    root = Path(path)
    packages: List[Package] = []
    for manifest in _find_manifests(root):
        packages.extend(_parse_manifest(manifest))

    packages = list(set(packages))
    if not packages:
        return []

    findings: List[Finding] = []
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_check_package, pkg): pkg for pkg in packages}
        for future in as_completed(futures):
            if progress_callback:
                progress_callback()
            result = future.result()
            if result:
                findings.extend(result)
    return findings


def _find_manifests(root: Path) -> List[Path]:
    names = {
        "requirements.txt", "package-lock.json", "package.json",
        "yarn.lock", "Cargo.lock", "go.sum", "Gemfile.lock",
        "Pipfile.lock", "pyproject.toml",
    }
    found = []
    for p in root.rglob("*"):
        if p.is_file() and p.name in names and not any(part in _SKIP_DIRS for part in p.parts):
            found.append(p)
    for p in root.rglob("requirements*.txt"):
        if p not in found and not any(part in _SKIP_DIRS for part in p.parts):
            found.append(p)
    return found


def _parse_manifest(path: Path) -> List[Package]:
    name = path.name
    try:
        if name.startswith("requirements") and name.endswith(".txt"):
            return _parse_requirements_txt(path)
        elif name == "package-lock.json":
            return _parse_package_lock(path)
        elif name == "package.json":
            return _parse_package_json(path)
        elif name == "yarn.lock":
            return _parse_yarn_lock(path)
        elif name == "Cargo.lock":
            return _parse_cargo_lock(path)
        elif name == "go.sum":
            return _parse_go_sum(path)
        elif name == "Gemfile.lock":
            return _parse_gemfile_lock(path)
        elif name == "Pipfile.lock":
            return _parse_pipfile_lock(path)
        elif name == "pyproject.toml":
            return _parse_pyproject_toml(path)
    except Exception:
        pass
    return []


def _parse_requirements_txt(path: Path) -> List[Package]:
    packages = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+")):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)", line)
        if m:
            packages.append((m.group(1).lower().replace("-", "_"), m.group(2), "PyPI"))
    return packages


def _parse_package_lock(path: Path) -> List[Package]:
    packages = []
    data = json.loads(path.read_text())
    for pkg_path, info in data.get("packages", {}).items():
        if not pkg_path:
            continue
        name = re.sub(r"^(node_modules/)+", "", pkg_path)
        version = info.get("version", "")
        if name and version:
            packages.append((name, version, "npm"))
    if not packages:
        for name, info in data.get("dependencies", {}).items():
            version = info.get("version", "")
            if name and version:
                packages.append((name, version, "npm"))
    return packages


def _parse_package_json(path: Path) -> List[Package]:
    packages = []
    data = json.loads(path.read_text())
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, spec in data.get(section, {}).items():
            m = re.match(r"[\^~>=<v]*([\d]+\.[\d]+\.[\d]+)", spec)
            if m:
                packages.append((name, m.group(1), "npm"))
    return packages


def _parse_yarn_lock(path: Path) -> List[Package]:
    packages = []
    content = path.read_text(errors="replace")
    pattern = re.compile(
        r'^"?([^"@\n,]+)@[^:]+:\n(?:[ \t]+[^\n]+\n)*?[ \t]+version[: ]+"?([^\n"]+)',
        re.MULTILINE,
    )
    seen = set()
    for m in pattern.finditer(content):
        name = m.group(1).strip().strip('"')
        version = m.group(2).strip().strip('"')
        if (name, version) not in seen:
            seen.add((name, version))
            packages.append((name, version, "npm"))
    return packages


def _parse_cargo_lock(path: Path) -> List[Package]:
    packages = []
    content = path.read_text(errors="replace")
    for block in re.compile(r'\[\[package\]\](.*?)(?=\[\[package\]\]|\Z)', re.DOTALL).finditer(content):
        name_m = re.search(r'name\s*=\s*"([^"]+)"', block.group(1))
        ver_m = re.search(r'version\s*=\s*"([^"]+)"', block.group(1))
        if name_m and ver_m:
            packages.append((name_m.group(1), ver_m.group(1), "crates.io"))
    return packages


def _parse_go_sum(path: Path) -> List[Package]:
    packages = []
    seen = set()
    for line in path.read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version = parts[1].split("/")[0].lstrip("v")
        if (module, version) not in seen:
            seen.add((module, version))
            packages.append((module, version, "Go"))
    return packages


def _parse_gemfile_lock(path: Path) -> List[Package]:
    packages = []
    for m in re.compile(r"^    ([a-zA-Z0-9_-]+) \(([^)]+)\)$", re.MULTILINE).finditer(
        path.read_text(errors="replace")
    ):
        packages.append((m.group(1), m.group(2), "RubyGems"))
    return packages


def _parse_pipfile_lock(path: Path) -> List[Package]:
    packages = []
    data = json.loads(path.read_text())
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            if isinstance(info, dict):
                version = info.get("version", "").lstrip("=")
                if name and version:
                    packages.append((name.lower(), version, "PyPI"))
    return packages


def _parse_pyproject_toml(path: Path) -> List[Package]:
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore
        data = tomllib.loads(path.read_text())
    except Exception:
        return []
    packages = []
    for dep in data.get("project", {}).get("dependencies", []):
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([^\s,;]+)", dep)
        if m:
            packages.append((m.group(1).lower(), m.group(2), "PyPI"))
    return packages


def _check_package(pkg: Package) -> List[Finding]:
    name, version, ecosystem = pkg
    vulns = osv.query_package(name, version, ecosystem)
    findings = []

    for vuln in vulns:
        cve_ids = osv.extract_cve_ids(vuln)
        fixed_versions = osv.extract_fixed_versions(vuln)
        summary = osv.extract_summary(vuln)
        cve_refs: List[CVEReference] = []

        for cve_id in cve_ids:
            cve_data = nvd.get_cve(cve_id)
            if cve_data:
                score, vector = nvd.extract_cvss(cve_data)
                description = nvd.extract_description(cve_data) or summary
                published = nvd.extract_published(cve_data)
                cwes = nvd.extract_cwes(cve_data)
                sev = Severity.from_cvss(score)
            else:
                # NVD unavailable or CVE not yet indexed — fall back to MITRE
                mitre_data = mitre.get_cve(cve_id)
                score, vector, cwes = None, None, []
                if mitre_data:
                    description = mitre.extract_description(mitre_data) or summary
                    published = mitre.extract_published(mitre_data)
                    cwes = mitre.extract_cwes(mitre_data)
                else:
                    description, published = summary, None
                sev = Severity.UNKNOWN

            cve_refs.append(CVEReference(
                cve_id=cve_id,
                description=description,
                cvss_score=score,
                cvss_vector=vector,
                severity=sev,
                nvd_url=nvd.nvd_web_url(cve_id),
                mitre_url=mitre.cve_web_url(cve_id),
                published=published,
                fixed_versions=fixed_versions,
            ))

        if not cve_ids and vuln.get("id"):
            cve_refs.append(CVEReference(
                cve_id=vuln["id"],
                description=summary,
                severity=Severity.UNKNOWN,
                nvd_url="",
                mitre_url="",
                fixed_versions=fixed_versions,
            ))

        if not cve_refs:
            continue

        best_sev = min(cve_refs, key=lambda r: r.severity.sort_key).severity
        fix_text = f"Upgrade to: {', '.join(sorted(set(fixed_versions)))}" if fixed_versions else None

        findings.append(Finding(
            title=f"{name} {version}  [{vuln.get('id', 'unknown')}]",
            description=summary,
            scanner="dependency",
            severity=best_sev,
            location=f"{name}=={version} ({ecosystem})",
            cve_refs=cve_refs,
            remediation=fix_text,
            evidence=(vuln.get("details", "")[:400] if vuln.get("details") else None),
        ))

    return findings
