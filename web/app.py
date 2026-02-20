#!/usr/bin/env python3
"""Lightweight web interface for VulnScan."""
import json
import os
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path
from flask import Flask, render_template, request, jsonify

app = Flask(__name__, static_folder='static', template_folder='templates')

# CORS is optional - only needed if serving frontend from different origin
try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    pass  # CORS not required for local development

# Get the project root directory
PROJECT_ROOT = Path(__file__).parent.parent
VULNSCAN_SCRIPT = PROJECT_ROOT / "vulnscan.py"

# Safeguards (override via env)
API_KEY = os.environ.get("VULNSCAN_API_KEY")  # If set, POST /api/scan requires X-API-Key or Authorization: Bearer <key>
MAX_TIMEOUT = float(os.environ.get("VULNSCAN_MAX_TIMEOUT", "300"))  # Max scan timeout in seconds
MAX_REQUEST_BODY = int(os.environ.get("VULNSCAN_MAX_REQUEST_BODY", "65536"))  # 64KB max JSON body
RATE_LIMIT_N = int(os.environ.get("VULNSCAN_RATE_LIMIT_N", "10"))  # Max requests per window
RATE_LIMIT_WINDOW = int(os.environ.get("VULNSCAN_RATE_LIMIT_WINDOW", "60"))  # Seconds
MAX_CONCURRENT_SCANS = int(os.environ.get("VULNSCAN_MAX_CONCURRENT_SCANS", "2"))
AUDIT_LOG_PATH = os.environ.get("VULNSCAN_AUDIT_LOG")  # If set, append scan events here

# In-memory rate limit: key -> list of timestamps
_rate_limit_store: defaultdict = defaultdict(list)
_rate_limit_lock = threading.Lock()
_scan_semaphore = threading.Semaphore(MAX_CONCURRENT_SCANS)


def _rate_limit_key():
    """Identify client for rate limiting (IP or API key)."""
    key = request.headers.get("X-API-Key") or (request.headers.get("Authorization") or "").replace("Bearer ", "").strip()
    if key:
        return "key:" + key[:32]
    return "ip:" + (request.remote_addr or "unknown")


def _rate_limit_allowed() -> bool:
    """True if under rate limit (N requests per window)."""
    now = time.monotonic()
    k = _rate_limit_key()
    with _rate_limit_lock:
        ts_list = _rate_limit_store[k]
        ts_list[:] = [t for t in ts_list if now - t < RATE_LIMIT_WINDOW]
        if len(ts_list) >= RATE_LIMIT_N:
            return False
        ts_list.append(now)
    return True


def _webhook_notify(response_data: dict, path: str) -> None:
    """If VULNSCAN_WEBHOOK_URL is set, POST scan summary (Slack/Discord/custom)."""
    url = os.environ.get("VULNSCAN_WEBHOOK_URL")
    if not url or not url.strip():
        return
    payload = json.dumps({
        "source": "vulnscan",
        "scan_target": path,
        "total_findings": response_data.get("total_findings", 0),
        "severity_counts": response_data.get("severity_counts", {}),
        "generated_at": response_data.get("generated_at", ""),
    }).encode("utf-8")
    try:
        import urllib.request
        req = urllib.request.Request(url, data=payload, method="POST", headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def _audit_log(scan_type: str, path: str, total_findings: int, status: str = "ok"):
    """Log scan request for compliance (file or stdout)."""
    line = json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scan": scan_type,
        "path": path,
        "total_findings": total_findings,
        "status": status,
        "client": _rate_limit_key(),
    }) + "\n"
    if AUDIT_LOG_PATH:
        try:
            with open(AUDIT_LOG_PATH, "a") as f:
                f.write(line)
        except OSError:
            pass
    else:
        print(line, end="", flush=True)


@app.after_request
def _security_headers(response):
    """Add security headers to all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    if request.is_secure or os.environ.get("VULNSCAN_FORCE_HSTS"):
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Relaxed CSP for the dashboard (inline scripts and styles are used)
    csp = os.environ.get("VULNSCAN_CSP")
    if csp:
        response.headers["Content-Security-Policy"] = csp
    return response


@app.route('/')
def index():
    """Serve the dashboard."""
    return render_template('dashboard.html')


@app.route('/scan')
def scan():
    """Serve the scan interface."""
    return render_template('scan.html')


@app.route('/reports')
def reports():
    """Serve the reports/history page."""
    return render_template('reports.html')


@app.route('/report/<report_id>')
def report_view(report_id):
    """Serve a specific report viewer."""
    return render_template('report_view.html', report_id=report_id)


@app.route('/api/docs')
def api_docs():
    """Serve the API documentation page."""
    return render_template('api_docs.html')


def _check_api_key():
    """If API_KEY is set, require X-API-Key or Authorization: Bearer."""
    if not API_KEY:
        return True
    key = request.headers.get("X-API-Key") or (
        request.headers.get("Authorization") or ""
    ).replace("Bearer ", "").strip()
    return key == API_KEY


def _resolve_and_validate_path(path_str: str):
    """Resolve path relative to PROJECT_ROOT; reject traversal outside."""
    path_str = (path_str or ".").strip()
    if not path_str or path_str == ".":
        return "."
    resolved = (PROJECT_ROOT / path_str).resolve()
    try:
        resolved.relative_to(PROJECT_ROOT.resolve())
    except ValueError:
        return None  # Outside allowed root
    return path_str


@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Execute a vulnerability scan via the agent API."""
    if not _check_api_key():
        return jsonify({'error': 'Unauthorized'}), 401
    if not _rate_limit_allowed():
        return jsonify({'error': 'Too many requests', 'retry_after': RATE_LIMIT_WINDOW}), 429
    if request.content_length and request.content_length > MAX_REQUEST_BODY:
        return jsonify({'error': 'Request body too large'}), 413
    data = request.get_json(force=True, silent=True)
    if data is None:
        return jsonify({'error': 'Invalid or missing JSON body'}), 400
    if len(json.dumps(data)) > MAX_REQUEST_BODY:
        return jsonify({'error': 'Request body too large'}), 413

    scan_type = data.get('scan', 'all')
    if scan_type not in ['deps', 'sast', 'net', 'all']:
        return jsonify({'error': 'Invalid scan type'}), 400

    path_str = data.get('path', '.')
    safe_path = _resolve_and_validate_path(path_str)
    if safe_path is None:
        return jsonify({'error': 'Path not allowed (must be under server root)'}), 400

    raw_timeout = data.get('timeout', 1.5)
    try:
        timeout = min(float(raw_timeout), MAX_TIMEOUT)
        if timeout <= 0:
            timeout = 1.5
    except (TypeError, ValueError):
        timeout = 1.5

    request_payload = {
        'scan': scan_type,
        'path': safe_path,
        'tools': data.get('tools', 'auto'),
        'timeout': timeout,
    }
    if scan_type == 'net':
        targets = data.get('targets', [])
        if not targets:
            return jsonify({'error': 'targets required for network scan'}), 400
        request_payload['targets'] = targets if isinstance(targets, list) else [targets]
        if data.get('ports'):
            request_payload['ports'] = data.get('ports')
    elif scan_type == 'all' and data.get('net_targets'):
        request_payload['net_targets'] = data.get('net_targets') if isinstance(data.get('net_targets'), list) else [data.get('net_targets')]
        if data.get('ports'):
            request_payload['ports'] = data.get('ports')

    if not _scan_semaphore.acquire(blocking=True, timeout=0):
        return jsonify({'error': 'Scan queue full', 'retry_after': 60}), 503
    try:
        cmd = [
            sys.executable,
            str(VULNSCAN_SCRIPT),
            'agent',
            '--request-file', '-',
            '--output-file', '-',
            '--no-banner',
        ]
        request_json = json.dumps(request_payload)
        result = subprocess.run(
            cmd,
            input=request_json,
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(PROJECT_ROOT),
        )
        if result.returncode != 0:
            _audit_log(scan_type, safe_path, -1, status="fail")
            return jsonify({'error': 'Scan failed', 'stderr': result.stderr}), 500
        try:
            response_data = json.loads(result.stdout)
            total = response_data.get('total_findings', 0)
            _audit_log(scan_type, safe_path, total, status="ok")
            _webhook_notify(response_data, safe_path)
            return jsonify(response_data)
        except json.JSONDecodeError:
            _audit_log(scan_type, safe_path, -1, status="error")
            return jsonify({'error': 'Invalid JSON response', 'stdout': result.stdout[:500]}), 500
    except subprocess.TimeoutExpired:
        _audit_log(scan_type, safe_path, -1, status="timeout")
        return jsonify({'error': 'Scan timed out'}), 504
    except Exception as e:
        _audit_log(scan_type, safe_path, -1, status="error")
        return jsonify({'error': str(e)}), 500
    finally:
        _scan_semaphore.release()


@app.route('/api/health', methods=['GET'])
def health():
    """Health check: basic status plus optional NVD/OSV reachability and disk space."""
    import shutil
    status = "ok"
    checks = {"api": "ok"}
    try:
        usage = shutil.disk_usage(PROJECT_ROOT)
        checks["disk_free_gb"] = round(usage.free / (1024 ** 3), 2)
        if usage.free < 100 * 1024 * 1024:  # < 100 MB
            status = "degraded"
            checks["disk"] = "low"
        else:
            checks["disk"] = "ok"
    except OSError:
        checks["disk"] = "unknown"
    if os.environ.get("VULNSCAN_HEALTH_CHECK_NETWORK", "").lower() in ("1", "true", "yes"):
        try:
            import urllib.request
            req = urllib.request.Request("https://api.osv.dev/v1/query", method="POST", data=b'{"package":{}}', headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status in (200, 400):  # 400 = bad request but service is up
                    checks["osv"] = "reachable"
                else:
                    checks["osv"] = "unreachable"
                    status = "degraded"
        except Exception:
            checks["osv"] = "unreachable"
            status = "degraded"
        try:
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
            with urllib.request.urlopen(nvd_url, timeout=8) as r:
                if r.status == 200:
                    checks["nvd"] = "reachable"
                else:
                    checks["nvd"] = "unreachable"
                    status = "degraded"
        except Exception:
            checks["nvd"] = "unreachable"
            status = "degraded"
    return jsonify({"status": status, "checks": checks})


@app.route('/api/reports', methods=['GET'])
def list_reports():
    """List all stored scan reports."""
    # For now, return empty list - can be extended with file-based storage
    return jsonify({'reports': []})


@app.route('/api/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get a specific scan report."""
    # For now, return 404 - can be extended with file-based storage
    return jsonify({'error': 'Report not found'}), 404


@app.route('/api/reports', methods=['POST'])
def save_report():
    """Save a scan report."""
    data = request.get_json()
    # For now, just return success - can be extended with file-based storage
    return jsonify({'status': 'saved', 'id': data.get('id', 'temp')})


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 8080))  # Default to 8080
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() in ('1', 'true', 'yes')
    host = os.environ.get('BIND_ADDRESS', '127.0.0.1')  # Use 0.0.0.0 to allow remote access
    app.run(debug=debug, host=host, port=port)
