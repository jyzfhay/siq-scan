# VulnScan Roadmap

Ideas to make the product more robust, add features, and connect to platforms.

---

## Robustness & Safeguards

| Area | Option | Description |
|------|--------|-------------|
| **API security** | API key auth | Optional `X-API-Key` or `Authorization: Bearer` for `/api/scan`; reject unauthenticated requests when `VULNSCAN_API_KEY` is set. |
| **API security** | Rate limiting | Limit requests per IP or per key (e.g. 10 scans/minute) to avoid abuse. |
| **Input validation** | Path traversal | Reject `path` or targets that escape allowed dirs (e.g. `../`, absolute paths outside workspace). |
| **Input validation** | Timeout / size caps | Enforce max timeout (e.g. 300s) and max request body size. |
| **Operational** | Audit logging | Log scan requests (timestamp, path, mode, result count) to file or stdout for compliance. |
| **Operational** | Health checks | `/api/health` could check NVD/OSV reachability or disk space. |
| **Security headers** | CSP / HSTS | Add Content-Security-Policy and Strict-Transport-Security when serving the web UI. |
| **Concurrency** | Scan queue | Limit concurrent scans (e.g. 1–2) to avoid resource exhaustion. |

---

## Features

| Area | Option | Description |
|------|--------|-------------|
| **Output formats** | SARIF | Export findings as [SARIF 2.1](https://sarifweb.azurewebsites.net/) for GitHub Code Scanning, GitLab SAST, and other tools. |
| **Output formats** | SBOM | Export dependency list as CycloneDX or SPDX for supply-chain tooling. |
| **Output formats** | CSV / Markdown | Simple tables for reports or tickets. |
| **Policy** | Severity thresholds | Configurable “fail only if CRITICAL” or “fail if CRITICAL or HIGH” (env or config file). |
| **Policy** | Baseline / suppressions | Ignore known findings via a baseline file or inline comments. |
| **Diff** | Compare reports | Compare two scan results (e.g. new/regressed findings). |
| **Scheduling** | Cron / scheduled scans | Run scans on a schedule and store or notify. |
| **Notifications** | Webhook | POST scan summary to a configurable URL (e.g. Slack, custom dashboard). |
| **Notifications** | Email | Send a short summary email when findings exceed a threshold. |
| **UI** | Trends | Dashboard showing finding counts over time (requires persisting reports server-side). |
| **UI** | Filters & search | Filter findings by severity, scanner, or path in the report viewer. |

---

## Connectors & Integrations

| Platform | Integration | Description |
|----------|-------------|-------------|
| **GitHub** | Actions | Official or community action that runs VulnScan and posts status (and optionally PR comments). |
| **GitHub** | Code Scanning | Emit SARIF so results show in Security → Code scanning. |
| **GitHub** | Advanced Security | Align with Dependabot/CodeQL workflow (SARIF, dependency scope). |
| **GitLab** | CI template | `.gitlab-ci.yml` snippet and SAST integration via SARIF. |
| **GitLab** | Merge request widget | Comment or widget with scan summary and link to report. |
| **Slack** | Incoming webhook | Post “Scan completed: X findings (Y critical)” with link to report. |
| **Discord** | Webhook | Same idea as Slack. |
| **Jira** | Create issues | Create Jira tickets for each finding (or for CRITICAL/HIGH only). |
| **PagerDuty** | Events | Send events when critical count &gt; 0. |
| **Defect Dojo** | Import | Push findings into Defect Dojo for tracking and metrics. |
| **ThreadFix** | Import | Similar to Defect Dojo. |
| **OpenSSF Scorecard** | Companion | Run Scorecard in the same pipeline and combine with VulnScan in a single report. |
| **TraKNC / SecurIQ** | Connector | If you have an API, push scan results into the security control plane. |

---

## Implementation priority (suggested)

1. ~~**Path validation & timeout caps**~~ — Done (API path validation; timeout capped at 600s in agent, configurable max in API).
2. ~~**SARIF export**~~ — Done (`--format sarif`; use for GitHub Code Scanning / GitLab SAST).
3. ~~**Optional API key**~~ — Done (`VULNSCAN_API_KEY` + `X-API-Key` or `Authorization: Bearer`).
4. ~~**Webhook notification**~~ — Done (`VULNSCAN_WEBHOOK_URL`; POST scan summary from CLI and API to Slack/Discord/custom).
5. ~~**Baseline / suppressions**~~ — Done (`--baseline path/to/baseline.json` with `suppressions` list; title/location/scanner or fingerprint).
6. ~~**Rate limiting**~~ — Done (per-IP/per-key; `VULNSCAN_RATE_LIMIT_N`, `VULNSCAN_RATE_LIMIT_WINDOW`; 429 when exceeded).
7. ~~**SBOM export**~~ — Done (`--format sbom`; CycloneDX 1.4 JSON from dependency scan; `deps`/`all` only).
8. ~~**GitHub Action**~~ — Done (`.github/workflows/vulnscan.yml`; scan on push/PR, upload artifact + SARIF for Code Scanning).
9. ~~**CSV / Markdown**~~ — Done (`--format csv`, `--format md`).
10. ~~**Severity thresholds**~~ — Done (`--fail-on CRITICAL` or `VULNSCAN_FAIL_SEVERITY`; exit 1 if any finding meets threshold).
11. ~~**Compare reports**~~ — Done (`vulnscan diff baseline.json current.json`; new/fixed/unchanged).
12. ~~**Audit logging**~~ — Done (`VULNSCAN_AUDIT_LOG` file or stdout).
13. ~~**Health checks**~~ — Done (`/api/health`; disk free, optional NVD/OSV reachability via `VULNSCAN_HEALTH_CHECK_NETWORK`).
14. ~~**Security headers**~~ — Done (X-Content-Type-Options, X-Frame-Options; optional HSTS, CSP via `VULNSCAN_CSP`).
15. ~~**Scan queue**~~ — Done (`VULNSCAN_MAX_CONCURRENT_SCANS`; 503 when queue full).
16. ~~**UI filters**~~ — Done (Report viewer: filter by severity and scanner).

**Still open:** Email notifications, trends over time (server-side report storage), Jira/PagerDuty/Defect Dojo/ThreadFix connectors, scheduled scans (cron example in docs).

This file can be updated as items are implemented or deprioritized.
