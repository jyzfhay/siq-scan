#!/usr/bin/env python3
"""VulnScan — CVE-validated vulnerability scanner (OSV · NVD · MITRE)"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent))

import click  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn  # noqa: E402

from core.models import Finding, Severity  # noqa: E402
from core import baseline as baseline_module  # noqa: E402
from reporters import console as con_reporter  # noqa: E402
from reporters import report as rep  # noqa: E402

console = Console()


@click.group()
@click.option(
    "--no-banner",
    is_flag=True,
    envvar="VULNSCAN_NO_BANNER",
    help="Disable startup banner output.",
)
@click.version_option("1.0.0", prog_name="vulnscan")
@click.pass_context
def cli(ctx: click.Context, no_banner: bool):
    """VulnScan — CVE-validated vulnerability scanner (OSV · NVD · MITRE)"""
    if not no_banner and ctx.invoked_subcommand != "agent":
        con_reporter.print_banner()


_output_option = click.option(
    "--output", "-o", default="./vulnscan-report", show_default=True,
    help="Report output directory",
)
_format_option = click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["html", "json", "sarif", "csv", "md", "sbom", "both"], case_sensitive=False),
    default="both", show_default=True,
    help="Report format: html, json, sarif, csv, md, sbom, or both (html+json)",
)
_verbose_option = click.option("--verbose", "-v", is_flag=True, help="Verbose output")
_tools_option = click.option(
    "--tools", "-T", default="auto", show_default=True,
    help="External tools: auto, all, none, or comma-separated (semgrep,bandit,trivy,nmap,nuclei)",
)
_baseline_option = click.option(
    "--baseline", "-b", "baseline_path", default=None,
    help="JSON file with suppressions to exclude known findings (see README).",
)
_fail_on_option = click.option(
    "--fail-on", default=None, envvar="VULNSCAN_FAIL_SEVERITY",
    help="Exit with code 1 if any finding has this severity or higher (e.g. CRITICAL or HIGH).",
)


def _fail_severity_set(fail_on: Optional[str]) -> set:
    """Return set of Severity values that trigger exit(1). E.g. HIGH -> {CRITICAL, HIGH}."""
    if not fail_on or not str(fail_on).strip():
        return set()
    order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO, Severity.UNKNOWN]
    names = [s.strip().upper() for s in str(fail_on).split(",") if s.strip()]
    out = set()
    for name in names:
        for sev in order:
            out.add(sev)
            if sev.value == name:
                break
    return out


def _should_fail(findings: List[Finding], fail_on: Optional[str]) -> bool:
    """True if any finding has severity in the fail-on set."""
    fail_set = _fail_severity_set(fail_on)
    if not fail_set:
        return False
    for f in findings:
        if f.worst_severity() in fail_set:
            return True
    return False


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@_output_option
@_format_option
@_verbose_option
@_tools_option
@_baseline_option
@_fail_on_option
def deps(path: str, output: str, fmt: str, verbose: bool, tools: str, baseline_path: Optional[str], fail_on: Optional[str]):
    """Scan project dependencies for known CVEs via OSV + NVD."""
    from scanners import dependency
    from scanners import integrations

    con_reporter.print_scan_start("dependency", path)
    findings: List[Finding] = []

    with _spinner("Querying OSV & NVD…"):
        findings = dependency.scan(path)

    active_tools = _resolve_tools(tools, ["trivy"])
    if "trivy" in active_tools:
        console.print("  [dim]→ trivy fs scan…[/dim]")
        with _spinner("Running trivy…"):
            findings += integrations.run_trivy(path, scan_type="fs")

    if baseline_path:
        findings = baseline_module.apply_baseline(findings, baseline_path)
    packages = dependency.get_packages(path) if fmt == "sbom" else None
    _report(findings, output, fmt, path, verbose, packages=packages)
    if _should_fail(findings, fail_on):
        sys.exit(1)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@_output_option
@_format_option
@_verbose_option
@_tools_option
@_baseline_option
@_fail_on_option
def sast(path: str, output: str, fmt: str, verbose: bool, tools: str, baseline_path: Optional[str], fail_on: Optional[str]):
    """Run static analysis for security anti-patterns."""
    from scanners import sast as sast_scanner
    from scanners import integrations

    con_reporter.print_scan_start("sast", path)
    findings: List[Finding] = []

    with _spinner("Scanning source files…"):
        findings = sast_scanner.scan(path)

    active_tools = _resolve_tools(tools, ["semgrep", "bandit"])

    if "semgrep" in active_tools:
        console.print("  [dim]→ semgrep (owasp-top-ten + secrets)…[/dim]")
        with _spinner("Running semgrep…"):
            findings += integrations.run_semgrep(path)

    if "bandit" in active_tools:
        console.print("  [dim]→ bandit (Python AST analysis)…[/dim]")
        with _spinner("Running bandit…"):
            findings += integrations.run_bandit(path)

    if baseline_path:
        findings = baseline_module.apply_baseline(findings, baseline_path)
    _report(findings, output, fmt, path, verbose)
    if _should_fail(findings, fail_on):
        sys.exit(1)


@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--ports", "-p", default=None, help="Comma-separated ports")
@click.option("--timeout", "-t", default=1.5, show_default=True, help="TCP timeout (seconds)")
@click.option("--nse-scripts", default="vuln,auth,default", show_default=True,
              help="Nmap NSE script categories")
@_output_option
@_format_option
@_verbose_option
@_tools_option
@_baseline_option
@_fail_on_option
def net(targets, ports, timeout, nse_scripts, output, fmt, verbose, tools, baseline_path, fail_on):
    """
    Scan network targets for open ports and misconfigurations.

    \b
    TARGETS  Hosts, IPs, or CIDR ranges.
             Only scan targets you own or have explicit written authorization to test.

    \b
    Examples:
      vulnscan net 192.0.2.1
      vulnscan net 198.51.100.0/24 --ports 22,80,443,3306,6379
    """
    from scanners import network
    from scanners import integrations

    console.print(
        "\n[bold yellow]⚠  Only scan hosts you own or have explicit written authorization to test.[/bold yellow]\n"
    )

    port_list = _parse_ports(ports)
    port_arg = ",".join(str(p) for p in port_list) if port_list else None

    con_reporter.print_scan_start("network", ", ".join(targets))
    findings: List[Finding] = []

    with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                  BarColumn(), TaskProgressColumn(),
                  console=console, transient=True) as progress:
        task = progress.add_task(f"Scanning {len(targets)} target(s)…", total=len(targets))
        findings = network.scan(list(targets), ports=port_list, timeout=timeout,
                                progress_callback=lambda: progress.advance(task))

    active_tools = _resolve_tools(tools, ["nmap", "nuclei"])

    if "nmap" in active_tools:
        console.print("  [dim]→ nmap (service versions + NSE scripts)…[/dim]")
        with _spinner("Running nmap…"):
            findings += integrations.run_nmap(list(targets), ports=port_arg, scripts=nse_scripts)

    if "nuclei" in active_tools:
        console.print("  [dim]→ nuclei (CVE templates)…[/dim]")
        with _spinner("Running nuclei…"):
            http_targets = [t if t.startswith("http") else f"http://{t}" for t in targets]
            findings += integrations.run_nuclei(http_targets)

    if baseline_path:
        findings = baseline_module.apply_baseline(findings, baseline_path)
    _report(findings, output, fmt, ", ".join(targets), verbose)
    if _should_fail(findings, fail_on):
        sys.exit(1)


@cli.command("all")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--net-targets", "-n", default=None,
              help="Comma-separated network targets (optional)")
@click.option("--ports", "-p", default=None, help="Ports for network scan")
@_output_option
@_format_option
@_verbose_option
@_tools_option
@_baseline_option
@_fail_on_option
def all_scan(path: str, net_targets: Optional[str], ports: Optional[str],
             output: str, fmt: str, verbose: bool, tools: str, baseline_path: Optional[str], fail_on: Optional[str]):
    """Run all scanners: dependencies, SAST, and optionally network."""
    from scanners import dependency, sast as sast_scanner, network
    from scanners import integrations

    targets: List[str] = []
    if net_targets:
        targets = [t.strip() for t in net_targets.split(",") if t.strip()]
        if not targets:
            raise click.ClickException("--net-targets cannot be empty.")
    port_list = _parse_ports(ports) if net_targets else None
    port_arg = ",".join(str(p) for p in port_list) if port_list else None

    available = integrations.available_tools()
    active_tools = [t for t in _resolve_tools(tools, ["semgrep", "bandit", "trivy"]) if t in available]
    network_tools = [t for t in _resolve_tools(tools, ["nmap", "nuclei"]) if t in available]

    tools_shown = active_tools + [t for t in network_tools if t not in active_tools]
    if tools_shown:
        console.print(f"[dim]External tools: {', '.join(tools_shown)}[/dim]\n")

    all_findings: List[Finding] = []

    con_reporter.print_scan_start("dependency", path)
    with _spinner("Scanning dependencies (OSV + NVD)…"):
        all_findings += dependency.scan(path)
    if "trivy" in active_tools:
        with _spinner("Running trivy…"):
            all_findings += integrations.run_trivy(path, scan_type="fs")
    console.print(f"  [dim]→ {sum(1 for f in all_findings if f.scanner == 'dependency')} findings[/dim]")

    con_reporter.print_scan_start("sast", path)
    sast_start = len(all_findings)
    with _spinner("Scanning source code…"):
        all_findings += sast_scanner.scan(path)
    if "semgrep" in active_tools:
        with _spinner("Running semgrep…"):
            all_findings += integrations.run_semgrep(path)
    if "bandit" in active_tools:
        with _spinner("Running bandit…"):
            all_findings += integrations.run_bandit(path)
    console.print(f"  [dim]→ {len(all_findings) - sast_start} findings[/dim]")

    if net_targets:
        console.print(
            "\n[bold yellow]⚠  Only scan hosts you own or have explicit written authorization to test.[/bold yellow]\n"
        )
        con_reporter.print_scan_start("network", net_targets)
        net_start = len(all_findings)
        with _spinner("Scanning network…"):
            all_findings += network.scan(targets, ports=port_list)
        if "nmap" in network_tools:
            with _spinner("Running nmap…"):
                all_findings += integrations.run_nmap(targets, ports=port_arg)
        if "nuclei" in network_tools:
            with _spinner("Running nuclei…"):
                http_targets = [t if t.startswith("http") else f"http://{t}" for t in targets]
                all_findings += integrations.run_nuclei(http_targets)
        console.print(f"  [dim]→ {len(all_findings) - net_start} findings[/dim]")

    if baseline_path:
        all_findings = baseline_module.apply_baseline(all_findings, baseline_path)
    packages = dependency.get_packages(path) if fmt == "sbom" else None
    _report(all_findings, output, fmt, path, verbose, packages=packages)
    if _should_fail(all_findings, fail_on):
        sys.exit(1)


@cli.command("diff")
@click.argument("report_a", type=click.Path(exists=True), metavar="BASELINE_REPORT.json")
@click.argument("report_b", type=click.Path(exists=True), metavar="CURRENT_REPORT.json")
@click.option("--format", "-f", "fmt", type=click.Choice(["text", "json"], case_sensitive=False), default="text",
              help="Output format")
def diff_reports(report_a: str, report_b: str, fmt: str):
    """Compare two VulnScan JSON reports (e.g. baseline vs current). Shows new, fixed, and unchanged counts."""
    data_a = json.loads(Path(report_a).read_text(encoding="utf-8"))
    data_b = json.loads(Path(report_b).read_text(encoding="utf-8"))
    findings_a = data_a.get("findings") or []
    findings_b = data_b.get("findings") or []

    def fp(f: dict) -> str:
        return "{}|{}|{}|{}".format(
            f.get("scanner", ""),
            f.get("title", ""),
            f.get("location", ""),
            f.get("line_number") or 0,
        )
    set_a = {fp(f) for f in findings_a}
    set_b = {fp(f) for f in findings_b}
    new_fps = set_b - set_a
    fixed_fps = set_a - set_b
    new_findings = [f for f in findings_b if fp(f) in new_fps]
    fixed_findings = [f for f in findings_a if fp(f) in fixed_fps]

    if fmt == "json":
        out = {
            "baseline": report_a,
            "current": report_b,
            "new_count": len(new_findings),
            "fixed_count": len(fixed_findings),
            "unchanged_count": len(set_a & set_b),
            "new": new_findings,
            "fixed": fixed_findings,
        }
        click.echo(json.dumps(out, indent=2))
        return
    console.print(f"\n[bold]Diff:[/bold] [cyan]{report_a}[/cyan] vs [cyan]{report_b}[/cyan]\n")
    console.print(f"  New:     [red]{len(new_findings)}[/red]")
    console.print(f"  Fixed:   [green]{len(fixed_findings)}[/green]")
    console.print(f"  Unchanged: {len(set_a & set_b)}")
    if new_findings:
        console.print("\n[bold]New findings:[/bold]")
        for f in new_findings[:20]:
            console.print(f"  [{f.get('severity', '?')}] {f.get('title', '')[:60]} @ {f.get('location', '')[:50]}")
        if len(new_findings) > 20:
            console.print(f"  ... and {len(new_findings) - 20} more")
    console.print()


@cli.command()
def tools():
    """Show which external tools are installed and available."""
    from scanners import integrations
    available = integrations.available_tools()
    all_tools = {
        "semgrep": "SAST — OWASP rules, secrets detection (pip install semgrep)",
        "bandit":  "SAST — Python AST analysis (pip install bandit)",
        "trivy":   "Dependencies + IaC — CVE scanning (brew install trivy)",
        "nuclei":  "Network/Web — CVE templates (brew install nuclei)",
        "nmap":    "Network — service versions + NSE scripts (brew install nmap)",
    }
    console.print()
    for name, desc in all_tools.items():
        status = "[bold green]✓ installed[/bold green]" if name in available else "[dim]✗ not found[/dim]"
        console.print(f"  {status}  [bold]{name}[/bold]  [dim]{desc}[/dim]")
    console.print()


@cli.command("agent")
@click.option(
    "--request-file",
    "-r",
    default="-",
    show_default=True,
    help="JSON request path, or '-' to read from stdin.",
)
@click.option(
    "--output-file",
    "-o",
    default="-",
    show_default=True,
    help="JSON response path, or '-' to write to stdout.",
)
@click.option("--pretty/--compact", default=True, show_default=True, help="Pretty-print JSON output.")
def agent_command(request_file: str, output_file: str, pretty: bool):
    """Run scans from JSON input for AI/automation workflows."""
    request = _load_agent_request(request_file)
    response = _run_agent_request(request)
    rendered = json.dumps(response, indent=2 if pretty else None)

    if output_file == "-":
        click.echo(rendered)
        return

    out_path = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered + ("\n" if pretty else ""))


def _load_agent_request(request_file: str) -> Dict[str, Any]:
    try:
        raw = sys.stdin.read() if request_file == "-" else Path(request_file).read_text(errors="replace")
    except OSError as exc:
        raise click.ClickException(f"Unable to read request file: {exc}") from exc

    if not raw.strip():
        raise click.ClickException("Agent request JSON is empty.")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise click.ClickException(
            f"Invalid JSON request: {exc.msg} (line {exc.lineno}, column {exc.colno})"
        ) from exc

    if not isinstance(payload, dict):
        raise click.ClickException("Agent request must be a JSON object.")
    return payload


def _run_agent_request(request: Dict[str, Any]) -> Dict[str, Any]:
    from scanners import dependency, integrations, network, sast as sast_scanner

    mode = _parse_agent_mode(request.get("scan", request.get("mode", "all")))
    path = str(request.get("path", "."))
    tools_flag = _normalize_tools_flag(request.get("tools", "auto"))
    timeout = _parse_timeout(request.get("timeout", 1.5))

    findings: List[Finding] = []
    enabled_tools: List[str] = []
    net_targets: List[str] = []

    if mode in ("deps", "all"):
        findings += dependency.scan(path)
        dep_tools = _resolve_tools(tools_flag, ["trivy"])
        enabled_tools.extend(t for t in dep_tools if t not in enabled_tools)
        if "trivy" in dep_tools:
            findings += integrations.run_trivy(path, scan_type="fs")

    if mode in ("sast", "all"):
        findings += sast_scanner.scan(path)
        sast_tools = _resolve_tools(tools_flag, ["semgrep", "bandit"])
        enabled_tools.extend(t for t in sast_tools if t not in enabled_tools)
        if "semgrep" in sast_tools:
            findings += integrations.run_semgrep(path)
        if "bandit" in sast_tools:
            findings += integrations.run_bandit(path)

    if mode == "net":
        net_targets = _parse_agent_targets(request.get("targets"), field_name="targets", required=True)
    elif mode == "all":
        net_targets = _parse_agent_targets(request.get("net_targets"), field_name="net_targets")

    ports_list: Optional[List[int]] = None
    ports_arg: Optional[str] = None
    if net_targets:
        ports_list, ports_arg = _parse_ports_value(request.get("ports"))
        findings += network.scan(net_targets, ports=ports_list, timeout=timeout)
        net_tools = _resolve_tools(tools_flag, ["nmap", "nuclei"])
        enabled_tools.extend(t for t in net_tools if t not in enabled_tools)
        if "nmap" in net_tools:
            findings += integrations.run_nmap(net_targets, ports=ports_arg)
        if "nuclei" in net_tools:
            http_targets = [t if t.startswith("http") else f"http://{t}" for t in net_targets]
            findings += integrations.run_nuclei(http_targets)

    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload = rep.build_report_data(findings, generated_at=generated_at)
    payload.update(
        {
            "mode": mode,
            "path": path,
            "targets": net_targets,
            "tools_requested": tools_flag,
            "tools_enabled": enabled_tools,
            "timeout": timeout,
        }
    )
    return payload


def _resolve_tools(tools_flag: str, defaults: List[str]) -> List[str]:
    from scanners import integrations
    available = integrations.available_tools()
    normalized = (tools_flag or "auto").strip().lower()

    if normalized == "none":
        return []
    if normalized == "all":
        return available
    if normalized == "auto":
        return [t for t in defaults if t in available]

    requested = [t.strip().lower() for t in normalized.split(",") if t.strip()]
    return [t for t in dict.fromkeys(requested) if t in available]


def _parse_agent_mode(raw_mode: Any) -> str:
    mode = str(raw_mode or "all").strip().lower()
    aliases = {
        "deps": "deps",
        "dependency": "deps",
        "sast": "sast",
        "net": "net",
        "network": "net",
        "all": "all",
    }
    resolved = aliases.get(mode)
    if resolved is None:
        raise click.ClickException("scan/mode must be one of: deps, sast, net, all.")
    return resolved


def _normalize_tools_flag(tools_value: Any) -> str:
    if tools_value is None:
        return "auto"
    if isinstance(tools_value, str):
        return tools_value
    if isinstance(tools_value, list):
        tools: List[str] = []
        for item in tools_value:
            if not isinstance(item, str):
                raise click.ClickException("tools list entries must be strings.")
            item = item.strip()
            if item:
                tools.append(item)
        return ",".join(tools) if tools else "none"
    raise click.ClickException("tools must be a string or list of strings.")


def _parse_timeout(timeout_value: Any) -> float:
    try:
        timeout = float(timeout_value)
    except (TypeError, ValueError) as exc:
        raise click.ClickException("timeout must be a positive number.") from exc
    if timeout <= 0:
        raise click.ClickException("timeout must be greater than 0.")
    # Cap at 10 minutes for agent/API to avoid runaway scans
    return min(timeout, 600.0)


def _parse_agent_targets(raw_targets: Any, field_name: str, required: bool = False) -> List[str]:
    if raw_targets is None:
        if required:
            raise click.ClickException(f"'{field_name}' is required for this scan mode.")
        return []

    if isinstance(raw_targets, str):
        targets = [t.strip() for t in raw_targets.split(",") if t.strip()]
    elif isinstance(raw_targets, list):
        targets = []
        for item in raw_targets:
            if not isinstance(item, str):
                raise click.ClickException(f"'{field_name}' entries must be strings.")
            item = item.strip()
            if item:
                targets.append(item)
    else:
        raise click.ClickException(f"'{field_name}' must be a string or list of strings.")

    if required and not targets:
        raise click.ClickException(f"'{field_name}' cannot be empty.")
    return targets


def _parse_ports(ports_value: Optional[str]) -> Optional[List[int]]:
    if ports_value is None:
        return None

    raw_parts = [p.strip() for p in ports_value.split(",") if p.strip()]
    if not raw_parts:
        raise click.ClickException("--ports cannot be empty.")

    parsed: List[int] = []
    for raw in raw_parts:
        try:
            port = int(raw)
        except ValueError as exc:
            raise click.ClickException("--ports must be a comma-separated list of integers.") from exc
        if port < 1 or port > 65535:
            raise click.ClickException("--ports values must be between 1 and 65535.")
        parsed.append(port)
    return list(dict.fromkeys(parsed))


def _parse_ports_value(raw_ports: Any) -> Tuple[Optional[List[int]], Optional[str]]:
    if raw_ports is None:
        return None, None

    if isinstance(raw_ports, str):
        ports = _parse_ports(raw_ports)
    elif isinstance(raw_ports, list):
        if not raw_ports:
            raise click.ClickException("'ports' cannot be an empty list.")
        parsed: List[int] = []
        for item in raw_ports:
            if isinstance(item, bool) or not isinstance(item, int):
                raise click.ClickException("'ports' list entries must be integers.")
            if item < 1 or item > 65535:
                raise click.ClickException("'ports' values must be between 1 and 65535.")
            parsed.append(item)
        ports = list(dict.fromkeys(parsed))
    else:
        raise click.ClickException("'ports' must be a comma-separated string or list of integers.")

    return ports, ",".join(str(p) for p in ports)


def _webhook_notify(findings: List[Finding], target: str) -> None:
    """If VULNSCAN_WEBHOOK_URL is set, POST scan summary (non-blocking best-effort)."""
    import urllib.request
    url = os.environ.get("VULNSCAN_WEBHOOK_URL")
    if not url or not url.strip():
        return
    counts = {}
    for f in findings:
        counts[f.worst_severity().value] = counts.get(f.worst_severity().value, 0) + 1
    payload = json.dumps({
        "source": "vulnscan",
        "scan_target": target,
        "total_findings": len(findings),
        "severity_counts": counts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }).encode("utf-8")
    try:
        req = urllib.request.Request(url, data=payload, method="POST", headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass  # Best-effort; don't fail the scan


def _report(findings: List[Finding], output: str, fmt: str, target: str, verbose: bool, packages: Optional[List[dict]] = None) -> None:
    if findings:
        con_reporter.print_findings(findings, verbose=verbose)
    else:
        console.print("\n[bold green]✓ No findings.[/bold green]\n")

    out = Path(output)
    saved = []
    if fmt in ("json", "both"):
        saved.append(rep.save_json(findings, str(out / "vulnscan-report.json")))
    if fmt in ("html", "both"):
        saved.append(rep.save_html(findings, str(out / "vulnscan-report.html"), scan_target=target))
    if fmt == "sarif":
        saved.append(rep.save_sarif(findings, str(out / "vulnscan-report.sarif")))
    if fmt == "csv":
        saved.append(rep.save_csv(findings, str(out / "vulnscan-report.csv")))
    if fmt == "md":
        saved.append(rep.save_md(findings, str(out / "vulnscan-report.md"), scan_target=target))
    if fmt == "sbom" and packages is not None:
        saved.append(rep.save_sbom(packages, str(out / "vulnscan-sbom.json")))
    if saved:
        console.print("\n[bold]Reports:[/bold]")
        for p in saved:
            console.print(f"  [cyan]{p}[/cyan]")
        console.print()
    _webhook_notify(findings, target)


class _spinner:
    def __init__(self, msg: str):
        self._progress = Progress(
            SpinnerColumn(), TextColumn(f"[progress.description]{msg}"),
            console=console, transient=True,
        )

    def __enter__(self):
        self._progress.__enter__()
        self._progress.add_task("", total=None)
        return self

    def __exit__(self, *args):
        self._progress.__exit__(*args)


if __name__ == "__main__":
    cli()
