"""Baseline / suppressions: exclude known findings by title+location or fingerprint."""
import json
from pathlib import Path
from typing import List, Set

from core.models import Finding


def load_baseline(baseline_path: str) -> List[dict]:
    """Load baseline file; return list of suppression entries {title, location, scanner} (any can be omitted)."""
    path = Path(baseline_path)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    suppressions = data.get("suppressions") if isinstance(data, dict) else data
    if not isinstance(suppressions, list):
        return []
    out = []
    for s in suppressions:
        if isinstance(s, dict):
            out.append({k: str(v) for k, v in s.items() if k in ("title", "location", "scanner") and v})
        elif isinstance(s, str):
            out.append({"fingerprint": s})
    return out


def fingerprint(f: Finding) -> str:
    """Stable string id for a finding (for baseline matching)."""
    return f"{f.scanner}|{f.title or ''}|{f.location or ''}|{f.line_number or 0}"


def apply_baseline(findings: List[Finding], baseline_path: str) -> List[Finding]:
    """Exclude findings that match the baseline suppressions."""
    suppressions = load_baseline(baseline_path)
    if not suppressions:
        return findings
    exclude_fp: Set[str] = set()
    for s in suppressions:
        if "fingerprint" in s:
            exclude_fp.add(s["fingerprint"])
    kept = []
    for f in findings:
        if fingerprint(f) in exclude_fp:
            continue
        matched = False
        for s in suppressions:
            if "fingerprint" in s:
                continue
            if (s.get("title") is None or (f.title or "") == s["title"]) and \
               (s.get("location") is None or (f.location or "") == s["location"]) and \
               (s.get("scanner") is None or f.scanner == s["scanner"]):
                matched = True
                break
        if not matched:
            kept.append(f)
    return kept
