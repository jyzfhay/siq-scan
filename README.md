# VulnScan

CVE-validated vulnerability scanner — **OSV · NVD · MITRE**

Scans dependencies, source code (SAST), and network targets. All findings are enriched with CVSS scores, CVE IDs, NVD links, and MITRE CVE links.

## Architecture

```
o-vuln/
├── vulnscan.py           # CLI entrypoint
├── core/
│   └── models.py         # Finding, CVEReference, Severity
├── scanners/
│   ├── dependency.py     # OSV + NVD + MITRE (deps)
│   ├── sast.py           # Built-in SAST rules
│   ├── network.py        # TCP port scan
│   └── integrations.py   # semgrep, bandit, trivy, nmap, nuclei
├── validators/
│   ├── osv.py            # OSV API
│   ├── nvd.py            # NVD API v2
│   └── mitre.py          # MITRE CVE
├── reporters/
│   ├── report.py         # JSON + HTML report generation
│   └── console.py        # Rich console output
├── web/                  # Web interface
│   ├── app.py            # Flask app, /api/scan, /api/health
│   ├── templates/        # Dashboard, Scan, Reports, API Docs
│   └── static/           # CSS, JS (common, scan, dashboard, reports)
├── requirements.txt
├── AGENTS.md             # Agent/automation contract
└── README.md
```

The **CLI** runs scans and writes reports to disk. The **agent** subcommand reads JSON from stdin and writes JSON to stdout for automation. The **web** app exposes the same scan logic via REST and a multi-page UI.

## Install

```bash
pip install -r requirements.txt
```

## Usage

### Dependency scan (PyPI, npm, Cargo, Go, RubyGems…)

```bash
python vulnscan.py deps ./my-project
```

### SAST — static analysis

```bash
python vulnscan.py sast ./my-project --verbose
```

### Network scan *(only scan hosts you own / are authorized to test)*

```bash
python vulnscan.py net 192.168.1.1 --ports 22,80,443,3306,6379
python vulnscan.py net 10.0.0.0/24
```

### All-in-one

```bash
python vulnscan.py all ./my-project --net-targets 192.168.1.1
```

### Agent JSON mode (for automation / AI agents)

```bash
cat > /tmp/vulnscan-request.json <<'JSON'
{
  "scan": "all",
  "path": "./my-project",
  "net_targets": ["192.168.1.10"],
  "ports": [22, 80, 443],
  "tools": "auto",
  "timeout": 1.5
}
JSON

python vulnscan.py agent --request-file /tmp/vulnscan-request.json --output-file /tmp/vulnscan-response.json
cat /tmp/vulnscan-response.json
```

## Web interface

A multi-page web UI runs scans, stores reports, and exposes the REST API with inline docs.

### Run the web server

```bash
cd web
python app.py
```

Default URL: **http://localhost:8080** (override with `PORT=3000 python app.py`).

### Pages

| Page        | Path        | Description                          |
|------------|-------------|--------------------------------------|
| Dashboard  | `/`         | Overview, quick stats, recent scans  |
| New Scan   | `/scan`     | Configure and run a scan             |
| Reports    | `/reports`  | List and manage saved reports        |
| Report     | `/report/<id>` | View a single report              |
| API Docs   | `/api/docs` | REST API reference and “Try it”      |

Reports are stored in the browser (localStorage). The UI uses the same TraKNC-style dark theme and Signal Green accents as the main product site.

## REST API

The web app exposes a REST API for CI/CD and scripting.

| Method | Endpoint     | Description        |
|--------|--------------|--------------------|
| POST   | `/api/scan`  | Run a scan (JSON body) |
| GET    | `/api/health`| Health check       |

Full request/response schemas, examples, and an interactive tester are at **http://localhost:8080/api/docs** when the server is running.

### Example

```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"scan": "deps", "path": "."}'
```

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--output` / `-o` | `./vulnscan-report` | Report output directory |
| `--format` / `-f` | `both` | `html`, `json`, or `both` |
| `--verbose` / `-v` | off | Show all findings in detail |
| `--ports` / `-p` | common | Comma-separated port list for network scan |
| `--timeout` / `-t` | `1.5` | Per-port TCP timeout (seconds) |
| `--no-banner` | off | Disable startup banner (useful for automation) |

Global options (e.g. `--no-banner`) must come before the subcommand:  
`python vulnscan.py --no-banner deps .`.

## Environment variables

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | NVD API key — higher rate limit (5 → 50 req/30s). [Request one](https://nvd.nist.gov/developers/request-an-api-key). |
| `PORT` | Port for the web server (default: 8080). |

## Data sources

| Source | What it provides |
|--------|------------------|
| [OSV](https://osv.dev) | Package vulnerability database (PyPI, npm, crates.io, Go, RubyGems, Maven…) |
| [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities) | CVSS scores, vectors, descriptions |
| [MITRE CVE](https://cveawg.mitre.org) | Authoritative CVE records + web links |

## SAST checks

Secrets · AWS keys · Private keys · Shell injection · SQL injection · Pickle deserialization · yaml.load · eval/exec · MD5/SHA-1 · Insecure random · Path traversal · XSS (innerHTML, dangerouslySetInnerHTML) · SSRF · XXE · Debug mode · Assert-for-auth · and more.

## Integrating with CI/CD

You can run VulnScan in pipelines in two ways: **CLI** (and **agent** JSON mode) or **REST API**. Use the CLI/agent when the runner has Python and the repo; use the API when a VulnScan server is already running.

### Option 1: CLI (recommended for most CI)

Install dependencies, run a scan, then fail the build if severity thresholds are exceeded:

```bash
# Install
pip install -r requirements.txt

# Run scan (deps, sast, or all)
python vulnscan.py deps . --format json --output ./vulnscan-report --no-banner
# or:  python vulnscan.py all . --format json --output ./vulnscan-report --no-banner

# Fail the build if any CRITICAL or HIGH findings
python - <<'EOF'
import json, sys
with open("./vulnscan-report/vulnscan-report.json") as f:
    data = json.load(f)
count = sum(1 for f in data.get("findings", []) if f.get("severity") in ("CRITICAL", "HIGH"))
sys.exit(1 if count > 0 else 0)
EOF
```

Optional: set `NVD_API_KEY` in your CI secrets for a higher NVD rate limit.

### Option 2: Agent mode (JSON in/out)

Use the **agent** subcommand for automation that passes a JSON request and reads a JSON response (e.g. from another tool or script):

```bash
echo '{"scan": "deps", "path": "."}' | python vulnscan.py agent --request-file - --output-file - --no-banner > report.json
# Then parse report.json and fail the job if severity counts exceed your policy
```

Request schema: `scan` (deps|sast|net|all), `path`, optional `targets`/`net_targets`, `ports`, `tools`, `timeout`. See [AGENTS.md](AGENTS.md) for the full contract.

### Option 3: REST API (when the web server is running)

If VulnScan is deployed as a service, call the API from your pipeline:

```bash
# Run scan and get JSON response
curl -s -X POST http://your-vulnscan-host:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"scan": "deps", "path": "."}' \
  -o report.json

# Fail the build if CRITICAL/HIGH (e.g. with jq)
critical=$(jq '[.findings[]? | select(.severity == "CRITICAL" or .severity == "HIGH")] | length' report.json)
exit $([ "$critical" -gt 0 ] && echo 1 || echo 0)
```

Use `GET /api/health` for readiness checks.

### Example: GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  vulnscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install VulnScan
        run: pip install -r requirements.txt

      - name: Run VulnScan
        run: |
          python vulnscan.py deps . --format json --output ./report --no-banner
          python vulnscan.py sast . --format json --output ./report --no-banner

      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: vulnscan-report
          path: report/

      - name: Fail on critical/high
        run: |
          python - <<'EOF'
          import json, sys
          with open("./report/vulnscan-report.json") as f:
            data = json.load(f)
          n = sum(1 for r in data.get("findings", []) if r.get("severity") in ("CRITICAL", "HIGH"))
          sys.exit(1 if n > 0 else 0)
          EOF
```

You can add `NVD_API_KEY` and/or `FLASK_DEBUG` in the repo or environment secrets as needed.

### Example: GitLab CI

```yaml
vulnscan:
  image: python:3.11-slim
  script:
    - pip install -r requirements.txt
    - python vulnscan.py deps . --format json --output ./report --no-banner
    - python -c "
      import json, sys
      d = json.load(open('./report/vulnscan-report.json'))
      n = sum(1 for f in d.get('findings', []) if f.get('severity') in ('CRITICAL', 'HIGH'))
      sys.exit(1 if n > 0 else 0)
      "
  artifacts:
    paths:
      - report/
```

JSON reports are written even when there are zero findings.

## Scanning this repository

You can run VulnScan on this codebase:

```bash
python vulnscan.py all . --format both --output ./vulnscan-report
```

Reports are written to `./vulnscan-report/` (JSON and HTML). The SAST scanner may report findings in the scanner code (e.g. rule definitions in `scanners/sast.py`) and in the web UI (e.g. dynamic HTML). Treat those as input to review and harden over time.

## Legal

Only scan systems you own or have explicit written authorization to test. Unauthorized scanning may be illegal.
