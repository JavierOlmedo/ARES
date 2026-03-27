"""
ARES - Console Logger (Rich-based)
"""
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich import box
import time

console = Console()

BANNER = r"""
[bold red]
    ___    ____  ___________
   /   |  / __ \/ ____/ ___/
  / /| | / /_/ / __/  \__ \ 
 / ___ |/ _, _/ /___ ___/ / 
/_/  |_/_/ |_/_____//____/  
[/bold red]
[dim]Advanced Reconnaissance & Enumeration Scanner[/dim]
[dim italic]v1.0.0 — by hackpuntes.com[/dim italic]
"""


def print_banner():
    console.print(BANNER)


def phase_start(phase_name: str, description: str = ""):
    console.print()
    console.rule(f"[bold cyan]⚔  {phase_name}", style="cyan")
    if description:
        console.print(f"  [dim]{description}[/dim]")
    console.print()


def phase_end(phase_name: str, duration: float = 0):
    elapsed = f" ({duration:.1f}s)" if duration else ""
    console.print(f"\n  [bold green]✓[/bold green] [green]{phase_name} completed{elapsed}[/green]\n")


def info(msg: str):
    console.print(f"  [bold blue]ℹ[/bold blue]  {msg}")


def success(msg: str):
    console.print(f"  [bold green]✓[/bold green]  {msg}")


def warning(msg: str):
    console.print(f"  [bold yellow]⚠[/bold yellow]  {msg}")


def error(msg: str):
    console.print(f"  [bold red]✗[/bold red]  {msg}")


def finding(title: str, detail: str = "", severity: str = "info"):
    colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "blue",
    }
    color = colors.get(severity, "blue")
    icon = "🔥" if severity in ("critical", "high") else "📌"
    console.print(f"  {icon} [{color}]{title}[/{color}]")
    if detail:
        console.print(f"      [dim]{detail}[/dim]")


def print_ports_table(ports_data: list):
    """Display discovered ports in a nice table."""
    if not ports_data:
        warning("No open ports found.")
        return

    table = Table(
        title="Open Ports",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
    )
    table.add_column("Port", style="cyan", justify="right", width=8)
    table.add_column("State", style="green", width=8)
    table.add_column("Service", style="yellow", width=15)
    table.add_column("Version", style="white", width=40)

    for p in ports_data:
        table.add_row(
            str(p.get("port", "")),
            p.get("state", ""),
            p.get("service", ""),
            p.get("version", ""),
        )
    console.print(table)


def print_summary(results: dict, total_time: float):
    """Final summary panel."""
    console.print()

    summary_lines = []
    if "nmap" in results:
        n_ports = len(results["nmap"].get("ports", []))
        summary_lines.append(f"[cyan]Ports discovered:[/cyan] {n_ports}")
    if "fuzzing" in results:
        n_dirs = len(results["fuzzing"].get("directories", []))
        n_vhosts = len(results["fuzzing"].get("vhosts", []))
        summary_lines.append(f"[cyan]Directories found:[/cyan] {n_dirs}")
        summary_lines.append(f"[cyan]VHosts found:[/cyan] {n_vhosts}")
    if "bruteforce" in results:
        n_creds = len(results["bruteforce"].get("credentials", []))
        summary_lines.append(f"[cyan]Credentials cracked:[/cyan] {n_creds}")
    if "nuclei" in results:
        n_vulns = len(results["nuclei"].get("vulnerabilities", []))
        summary_lines.append(f"[cyan]Vulnerabilities found:[/cyan] {n_vulns}")

    summary_lines.append(f"\n[dim]Total time: {total_time:.1f}s[/dim]")

    panel = Panel(
        "\n".join(summary_lines),
        title="[bold red]⚔ ARES — Scan Summary[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(1, 2),
    )
    console.print(panel)


def get_progress():
    """Return a Rich progress bar context manager."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )
