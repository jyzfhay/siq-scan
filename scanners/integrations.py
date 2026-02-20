"""External tool integrations — Semgrep · Bandit · Trivy · Nuclei · Nmap"""
import json
import os
import shutil
import subprocess
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from core.models import Finding, CVEReference, Severity
from validators import nvd, mitre

# Extra directories to search for tool binaries (Python user scripts, etc.)
_EXTRA_PATHS = [
    str(Path.home() / "Library" / "Python" / f"{sys.version_info.major}.{sys.version_info.minor}" / "bin"),
    str(Path.home() / ".local" / "bin"),
    "/opt/homebrew/bin",
    "/usr/local/bin",
]


def _find_tool(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_PATHS:
        candidate = Path(d) / name
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return str(candidate)
    return None


def available_tools() -> List[str]:
    tools = ["semgrep", "bandit", "trivy", "nuclei", "nmap"]
    return [t for t in tools if _find_tool(t)]


def _run(cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timed out"
    except FileNotFoundError:
        return -1, "", f"Tool not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


SEMGREP_RULESETS = [
    "p/owasp-top-ten",
    "p/secrets",
    "p/security-audit",
    "p/python",
    "p/javascript",
    "p/typescript",
    "p/go",
    "p/java",
    "p/ruby",
]


def run_semgrep(path: str, rulesets: Optional[List[str]] = None) -> List[Finding]:
    """Run Semgrep with OWASP + secrets rulesets."""
    bin_path = _find_tool("semgrep")
    if not bin_path:
        return []

    if rulesets is None:
        rulesets = ["p/owasp-top-ten", "p/secrets"]

    config_args = []
    for rs in rulesets:
        config_args += ["--config", rs]

    cmd = [
        bin_path,
        "--json",
        "--quiet",
        "--no-git-ignore",
        *config_args,
        path,
    ]

    _, stdout, stderr = _run(cmd, timeout=300)
    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    findings: List[Finding] = []
    for result in data.get("results", []):
        check_id = result.get("check_id", "")
        message = result.get("extra", {}).get("message", "")
        severity_raw = result.get("extra", {}).get("severity", "WARNING").upper()
        sev_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        sev = sev_map.get(severity_raw, Severity.MEDIUM)

        path_str = result.get("path", "")
        line = result.get("start", {}).get("line")
        code_snippet = result.get("extra", {}).get("lines", "").strip()

        # Some Semgrep rules embed CVE IDs in the check_id or message
        cve_refs = _extract_cve_refs_from_text(f"{check_id} {message}")

        findings.append(Finding(
            title=f"[semgrep] {check_id.split('.')[-1]}",
            description=message,
            scanner="sast",
            severity=sev,
            location=path_str,
            line_number=line,
            evidence=code_snippet[:200] if code_snippet else None,
            remediation=(
                result.get("extra", {}).get("fix") or
                result.get("extra", {}).get("metadata", {}).get("fix", None)
            ),
            cve_refs=cve_refs,
        ))

    return findings


def run_bandit(path: str) -> List[Finding]:
    """Run Bandit for deep Python AST security analysis."""
    bin_path = _find_tool("bandit")
    if not bin_path:
        return []

    cmd = [bin_path, "-r", "-f", "json", "-ll", path]
    _, stdout, _ = _run(cmd, timeout=120)

    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    bandit_sev_map = {
        "HIGH":   Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW":    Severity.LOW,
    }

    findings: List[Finding] = []
    for issue in data.get("results", []):
        sev = bandit_sev_map.get(issue.get("issue_severity", "LOW"), Severity.LOW)
        cwe = issue.get("issue_cwe", {})
        cwe_str = f"CWE-{cwe.get('id', '')}" if cwe else ""

        findings.append(Finding(
            title=f"[bandit] {issue.get('test_id', '')} — {issue.get('test_name', '')}",
            description=issue.get("issue_text", ""),
            scanner="sast",
            severity=sev,
            location=issue.get("filename", ""),
            line_number=issue.get("line_number"),
            evidence=issue.get("code", "").strip()[:200],
            remediation=(
                f"More info: {issue.get('more_info', '')}"
                + (f"\n{cwe_str}" if cwe_str else "")
            ),
        ))

    return findings


def run_trivy(target: str, scan_type: str = "fs") -> List[Finding]:
    """Run Trivy to scan filesystem, container images, or IaC configs."""
    bin_path = _find_tool("trivy")
    if not bin_path:
        return []

    cmd = [
        bin_path, scan_type,
        "--format", "json",
        "--quiet",
        "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
        target,
    ]

    _, stdout, _ = _run(cmd, timeout=300)
    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    trivy_sev_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH":     Severity.HIGH,
        "MEDIUM":   Severity.MEDIUM,
        "LOW":      Severity.LOW,
        "UNKNOWN":  Severity.UNKNOWN,
    }

    findings: List[Finding] = []
    for result in data.get("Results", []):
        target_name = result.get("Target", "")
        for vuln in result.get("Vulnerabilities", []):
            cve_id = vuln.get("VulnerabilityID", "")
            sev = trivy_sev_map.get(vuln.get("Severity", "UNKNOWN"), Severity.UNKNOWN)
            score = vuln.get("CVSS", {}).get("nvd", {}).get("V3Score")
            if score is None:
                score = vuln.get("CVSS", {}).get("nvd", {}).get("V2Score")

            cve_ref = CVEReference(
                cve_id=cve_id,
                description=vuln.get("Description", ""),
                cvss_score=score,
                severity=sev,
                nvd_url=nvd.nvd_web_url(cve_id) if cve_id.startswith("CVE-") else "",
                mitre_url=mitre.cve_web_url(cve_id) if cve_id.startswith("CVE-") else "",
                fixed_versions=[vuln.get("FixedVersion", "")] if vuln.get("FixedVersion") else [],
            )

            pkg_name = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")

            findings.append(Finding(
                title=f"[trivy] {pkg_name} {installed} — {cve_id}",
                description=vuln.get("Title") or vuln.get("Description", "")[:200],
                scanner="dependency",
                severity=sev,
                location=f"{target_name} → {pkg_name}=={installed}",
                cve_refs=[cve_ref],
                remediation=f"Upgrade {pkg_name} to {fixed}" if fixed else None,
            ))

        # Misconfigurations (IaC / container config)
        for misc in result.get("Misconfigurations", []):
            sev = trivy_sev_map.get(misc.get("Severity", "UNKNOWN"), Severity.UNKNOWN)
            findings.append(Finding(
                title=f"[trivy] {misc.get('ID', '')} — {misc.get('Title', '')}",
                description=misc.get("Description", ""),
                scanner="sast",
                severity=sev,
                location=target_name,
                remediation=misc.get("Resolution"),
                evidence=misc.get("Message"),
            ))

    return findings


def run_nuclei(
    targets: List[str],
    templates: Optional[List[str]] = None,
    severity: str = "medium,high,critical",
) -> List[Finding]:
    """Run Nuclei CVE/vulnerability templates against web/network targets."""
    bin_path = _find_tool("nuclei")
    if not bin_path:
        return []

    if templates is None:
        template_args = ["-t", "cves/", "-t", "vulnerabilities/", "-t", "misconfigurations/"]
    else:
        template_args = []
        for t in templates:
            template_args += ["-t", t]

    cmd = [
        bin_path,
        "-json",
        "-severity", severity,
        "-silent",
        *template_args,
        "-list", "-",  # Targets from stdin
    ]

    try:
        proc = subprocess.run(
            cmd,
            input="\n".join(targets),
            capture_output=True,
            text=True,
            timeout=600,
        )
        output = proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return []

    findings: List[Finding] = []
    nuclei_sev_map = {
        "critical": Severity.CRITICAL,
        "high":     Severity.HIGH,
        "medium":   Severity.MEDIUM,
        "low":      Severity.LOW,
        "info":     Severity.INFO,
    }

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = result.get("info", {})
        sev = nuclei_sev_map.get(info.get("severity", "info"), Severity.INFO)
        template_id = result.get("template-id", "")
        matched_at = result.get("matched-at", "")
        name = info.get("name", template_id)
        description = info.get("description", "")

        # Extract CVE IDs from template metadata
        cve_refs = []
        classification = info.get("classification", {})
        for cve_id in classification.get("cve-id", []):
            cve_refs.append(CVEReference(
                cve_id=cve_id,
                description=description,
                severity=sev,
                nvd_url=nvd.nvd_web_url(cve_id),
                mitre_url=mitre.cve_web_url(cve_id),
            ))

        findings.append(Finding(
            title=f"[nuclei] {name}",
            description=description,
            scanner="network",
            severity=sev,
            location=matched_at,
            cve_refs=cve_refs,
            evidence=result.get("extracted-results", [""])[0][:200] if result.get("extracted-results") else None,
            remediation=info.get("remediation"),
        ))

    return findings


def run_nmap(
    targets: List[str],
    ports: Optional[str] = None,
    scripts: str = "vuln,auth,default",
) -> List[Finding]:
    """Run Nmap with service version detection and NSE vulnerability scripts."""
    bin_path = _find_tool("nmap")
    if not bin_path:
        return []

    port_arg = ["-p", ports] if ports else ["-p", "21,22,23,25,53,80,110,143,389,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,10250,11211,27017"]

    cmd = [
        bin_path,
        "-sV",
        "--script", scripts,
        "-oX", "-",
        "--open",
        "-T4",
        *port_arg,
        *targets,
    ]

    _, stdout, _ = _run(cmd, timeout=600)
    if not stdout:
        return []

    return _parse_nmap_xml(stdout)


def _parse_nmap_xml(xml_output: str) -> List[Finding]:
    """Parse Nmap XML output into Finding objects. Uses defusedxml to prevent XXE."""
    findings: List[Finding] = []
    try:
        from defusedxml.ElementTree import fromstring as safe_fromstring
        root = safe_fromstring(xml_output)
    except Exception:
        return []

    for host_el in root.findall(".//host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host_el.find("address")
        host = addr_el.attrib.get("addr", "unknown") if addr_el is not None else "unknown"

        for port_el in host_el.findall(".//port"):
            portid = port_el.attrib.get("portid", "")
            protocol = port_el.attrib.get("protocol", "tcp")
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue

            service_el = port_el.find("service")
            service_name = ""
            service_version = ""
            if service_el is not None:
                service_name = service_el.attrib.get("name", "")
                product = service_el.attrib.get("product", "")
                version = service_el.attrib.get("version", "")
                extrainfo = service_el.attrib.get("extrainfo", "")
                service_version = " ".join(filter(None, [product, version, extrainfo]))

            location = f"{host}:{portid}/{protocol}"

            # Parse NSE script output
            for script_el in port_el.findall("script"):
                script_id = script_el.attrib.get("id", "")
                output = script_el.attrib.get("output", "")

                if not output or "ERROR" in output:
                    continue

                # Determine severity from script category
                sev = Severity.INFO
                if any(k in script_id for k in ("vuln", "exploit", "backdoor", "brute")):
                    sev = Severity.HIGH
                elif any(k in script_id for k in ("auth", "default", "safe")):
                    sev = Severity.MEDIUM

                # Extract CVE IDs from script output
                cve_refs = _extract_cve_refs_from_text(output)

                if cve_refs or sev in (Severity.HIGH, Severity.CRITICAL):
                    findings.append(Finding(
                        title=f"[nmap] {script_id} on {location}",
                        description=f"NSE script {script_id}: {output[:300]}",
                        scanner="network",
                        severity=sev,
                        location=location,
                        evidence=output[:400],
                        cve_refs=cve_refs,
                    ))

            # Report open port with service version (INFO)
            if service_version:
                findings.append(Finding(
                    title=f"[nmap] {service_name} {service_version}",
                    description=f"Service fingerprint on {location}: {service_version}",
                    scanner="network",
                    severity=Severity.INFO,
                    location=location,
                    evidence=service_version,
                    remediation=f"Verify {service_version} is up to date. Check NVD: https://nvd.nist.gov/vuln/search/results?query={service_name}+{service_version.split()[0]}",
                ))

    return findings


_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _extract_cve_refs_from_text(text: str) -> List[CVEReference]:
    cve_ids = list(set(_CVE_PATTERN.findall(text)))
    refs = []
    for cve_id in cve_ids:
        cve_id = cve_id.upper()
        refs.append(CVEReference(
            cve_id=cve_id,
            description="",
            nvd_url=nvd.nvd_web_url(cve_id),
            mitre_url=mitre.cve_web_url(cve_id),
        ))
    return refs
