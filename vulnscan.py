#!/usr/bin/env python3
"""VulnScan — CVE-validated vulnerability scanner (OSV · NVD · MITRE)"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent))

import click  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn  # noqa: E402

from core.models import Finding  # noqa: E402
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
    type=click.Choice(["html", "json", "both"], case_sensitive=False),
    default="both", show_default=True,
    help="Report format",
)
_verbose_option = click.option("--verbose", "-v", is_flag=True, help="Verbose output")
_tools_option = click.option(
    "--tools", "-T", default="auto", show_default=True,
    help="External tools: auto, all, none, or comma-separated (semgrep,bandit,trivy,nmap,nuclei)",
)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@_output_option
@_format_option
@_verbose_option
@_tools_option
def deps(path: str, output: str, fmt: str, verbose: bool, tools: str):
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

    _report(findings, output, fmt, path, verbose)


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@_output_option
@_format_option
@_verbose_option
@_tools_option
def sast(path: str, output: str, fmt: str, verbose: bool, tools: str):
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

    _report(findings, output, fmt, path, verbose)


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
def net(targets, ports, timeout, nse_scripts, output, fmt, verbose, tools):
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

    _report(findings, output, fmt, ", ".join(targets), verbose)


@cli.command("all")
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--net-targets", "-n", default=None,
              help="Comma-separated network targets (optional)")
@click.option("--ports", "-p", default=None, help="Ports for network scan")
@_output_option
@_format_option
@_verbose_option
@_tools_option
def all_scan(path: str, net_targets: Optional[str], ports: Optional[str],
             output: str, fmt: str, verbose: bool, tools: str):
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

    _report(all_findings, output, fmt, path, verbose)


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
    return timeout


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


def _report(findings: List[Finding], output: str, fmt: str, target: str, verbose: bool) -> None:
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
    if saved:
        console.print("\n[bold]Reports:[/bold]")
        for p in saved:
            console.print(f"  [cyan]{p}[/cyan]")
        console.print()


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
