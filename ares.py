#!/usr/bin/env python3
"""
ARES — Advanced Reconnaissance & Enumeration Scanner
by hackpuntes.com

Usage:
    sudo python3 ares.py -t 10.10.11.100
    sudo python3 ares.py -t 10.10.11.100 -H target.htb
    sudo python3 ares.py -t 10.10.11.100 -H target.htb --aggressive --udp
    sudo python3 ares.py -t 10.10.11.100 -m nmap,fuzzing
"""
import argparse
import subprocess
import sys
import os

# Add parent dir to path for module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import AresConfig
from core.orchestrator import Orchestrator
from core import logger


def parse_args():
    parser = argparse.ArgumentParser(
        description="⚔ ARES — Advanced Reconnaissance & Enumeration Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 ares.py -t 10.10.11.100
  sudo python3 ares.py -t 10.10.11.100 -H target.htb
  sudo python3 ares.py -t 10.10.11.100 -H target.htb --aggressive --udp
  sudo python3 ares.py -t 10.10.11.100 -m nmap,fuzzing --threads 20
  sudo python3 ares.py -t 10.10.11.100 --no-brute --no-nuclei

Made with ☠  by hackpuntes.com
        """
    )

    # Required (not needed for --check)
    parser.add_argument("-t", "--target", default="", help="Target IP address")

    # Optional target config
    parser.add_argument("-H", "--hostname", default="", help="Target hostname (e.g., target.htb)")
    parser.add_argument("-o", "--output", default="", help="Output directory (default: ares_<target>)")

    # Scan intensity
    intensity = parser.add_mutually_exclusive_group()
    intensity.add_argument("--quiet", action="store_const", const="quiet", dest="intensity", help="Minimal scanning (quick)")
    intensity.add_argument("--aggressive", action="store_const", const="aggressive", dest="intensity", help="Full port scan, more thorough")
    parser.set_defaults(intensity="normal")

    # Module control
    parser.add_argument("-m", "--modules", default="nmap,fuzzing,bruteforce",
                        help="Comma-separated list of modules to run (default: nmap,fuzzing,bruteforce)")
    parser.add_argument("--no-nmap", action="store_true", help="Skip nmap module")
    parser.add_argument("--no-brute", action="store_true", help="Skip brute-force module")
    parser.add_argument("--no-nuclei", action="store_true", help="Skip nuclei module")
    parser.add_argument("--no-fuzz", action="store_true", help="Skip fuzzing module")

    # Scan options
    parser.add_argument("--post-nmap-delay", type=int, default=5,
                        help="Seconds to wait after nmap before fuzzing (default: 5, 0 to disable)")
    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning")
    parser.add_argument("--threads", type=int, default=23, help="Number of threads (default: 23)")
    parser.add_argument("--fuzz-depth", type=int, default=0,
                        help="Max recursion depth for fuzzing (default: 1, 0 = use config)")
    parser.add_argument("--top-ports", type=int, default=1000, help="Nmap top ports (default: 1000)")

    # Wordlists (defaults resolved from wordlists/ folder — see AresConfig)
    parser.add_argument("--wordlist-web", default="",
                        help="Wordlist for directory fuzzing (default: wordlists/web/raft-large-directories-*)")
    parser.add_argument("--wordlist-web-files", default="",
                        help="Wordlist for file fuzzing (default: wordlists/web/raft-large-files-*)")
    parser.add_argument("--wordlist-vhost", default="",
                        help="Wordlist for vhost fuzzing (default: wordlists/vhost/hackpuntes-subdomains-*)")
    parser.add_argument("--wordlist-users", default="",
                        help="Wordlist for username brute-force (default: wordlists/users/hackpuntes-usernames-*)")
    parser.add_argument("--wordlist-passwords", default="",
                        help="Wordlist for password brute-force (default: wordlists/passwords/hackpuntes-passwords-*)")

    # Extensions
    parser.add_argument("--extensions", default="php,html,txt,asp,aspx,jsp,bak,old,config",
                        help="File extensions for directory fuzzing")

    # Report formats
    parser.add_argument("--report", default="console,markdown,html",
                        help="Report formats: console,markdown,html (default: all)")

    # Nuclei
    parser.add_argument("--nuclei-severity", default="low,medium,high,critical",
                        help="Nuclei severity filter (default: low,medium,high,critical)")

    # Proxy
    parser.add_argument("--proxy", default="",
                        help="HTTP proxy for fuzzing/brute-force (e.g. http://127.0.0.1:8080)")

    # Network discovery
    parser.add_argument("--discover", action="store_true",
                        help="Network host discovery mode (use -t <network/CIDR>)")

    # Update
    parser.add_argument("--update", action="store_true",
                        help="Update ARES to the latest version from GitHub")

    # Version
    from core import __version__
    parser.add_argument("--version", action="version", version=f"ARES v{__version__}")

    # Preflight
    parser.add_argument("--check", action="store_true",
                        help="Check dependencies and exit (no scan)")

    return parser.parse_args()


GITHUB_URL = "https://github.com/JavierOlmedo/ARES.git"
ARES_DIR   = os.path.dirname(os.path.abspath(__file__))


def cmd_update():
    """Pull latest version from GitHub, update pip deps, re-install wrapper."""
    from rich.panel import Panel
    from rich import box

    logger.print_banner()
    logger.info(f"Source : {GITHUB_URL}")
    logger.info(f"Install: {ARES_DIR}")
    logger.console.print()

    # ── Ensure git is available ──────────────────────────────────────────────
    if not subprocess.run(["which", "git"], capture_output=True).returncode == 0:
        logger.error("git not found — cannot update.")
        sys.exit(1)

    # ── Point origin to the canonical GitHub URL ─────────────────────────────
    subprocess.run(
        ["git", "-C", ARES_DIR, "remote", "set-url", "origin", GITHUB_URL],
        capture_output=True,
    )

    # ── git pull ─────────────────────────────────────────────────────────────
    logger.info("Pulling latest changes...")
    result = subprocess.run(
        ["git", "-C", ARES_DIR, "pull", "origin", "main"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error(f"git pull failed:\n{result.stderr.strip()}")
        sys.exit(1)

    stdout = result.stdout.strip()
    if "Already up to date" in stdout:
        logger.success("Already on the latest version.")
    else:
        logger.success("Repository updated.")
        logger.console.print(f"  [dim]{stdout}[/dim]")

    # Show new version
    try:
        with open(os.path.join(ARES_DIR, "VERSION")) as _f:
            new_ver = _f.read().strip()
        logger.info(f"Version: {new_ver}")
    except FileNotFoundError:
        pass

    # ── pip deps ─────────────────────────────────────────────────────────────
    logger.info("Updating Python dependencies...")
    req = os.path.join(ARES_DIR, "requirements.txt")
    pip = subprocess.run(
        ["pip3", "install", "-r", req, "-q"],
        capture_output=True, text=True,
    )
    if pip.returncode == 0:
        logger.success("Python dependencies up to date.")
    else:
        logger.warning(f"pip had issues: {pip.stderr.strip()}")

    # ── Re-install wrapper (/usr/local/bin/ares) ─────────────────────────────
    logger.info("Refreshing /usr/local/bin/ares wrapper...")
    wrapper_content = (
        "#!/usr/bin/env bash\n"
        f"if [[ $EUID -ne 0 ]]; then\n"
        f"    exec sudo python3 {ARES_DIR}/ares.py \"$@\"\n"
        f"else\n"
        f"    exec python3 {ARES_DIR}/ares.py \"$@\"\n"
        f"fi\n"
    )
    try:
        wrapper_path = "/usr/local/bin/ares"
        with open(wrapper_path, "w") as f:
            f.write(wrapper_content)
        os.chmod(wrapper_path, 0o755)
        logger.success(f"Wrapper updated: {wrapper_path}")
    except PermissionError:
        logger.warning("Cannot write /usr/local/bin/ares — re-run with sudo to refresh wrapper.")

    logger.console.print()
    logger.console.print(Panel(
        "[green]ARES updated successfully![/green]\n[dim]ares -t <TARGET_IP>[/dim]",
        border_style="green", box=box.ROUNDED,
    ))
    sys.exit(0)


def cmd_check():
    """Run dependency check and display results with Rich."""
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from core.utils import dependency_check

    logger.print_banner()
    results = dependency_check()
    errors = 0

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta",
                  border_style="dim", padding=(0, 1))
    table.add_column("Component", style="cyan", width=22)
    table.add_column("Status", width=8)
    table.add_column("Detail", style="dim")

    # Python
    py = results["python"]
    status = "[green]✓  OK[/green]" if py["ok"] else "[red]✗  FAIL[/red]"
    if not py["ok"]:
        errors += 1
    table.add_row("Python", status, py["version"] + ("" if py["ok"] else " (need 3.10+)"))

    # Required tools
    for tool, available in results["tools"].items():
        status = "[green]✓  OK[/green]" if available else "[red]✗  MISS[/red]"
        detail = "found in PATH" if available else f"sudo apt install {tool}"
        if not available:
            errors += 1
        table.add_row(tool, status, detail)

    # Fuzzers (at least one)
    fuzzer_found = [f for f, ok in results["fuzzers"].items() if ok]
    if fuzzer_found:
        table.add_row("fuzzer", "[green]✓  OK[/green]", ", ".join(fuzzer_found))
    else:
        errors += 1
        table.add_row("fuzzer", "[red]✗  MISS[/red]",
                      "need gobuster, ffuf or feroxbuster")

    # Wordlists
    for label, info in results["wordlists"].items():
        status = "[green]✓  OK[/green]" if info["ok"] else "[yellow]⚠  MISS[/yellow]"
        detail = info["path"] if info["ok"] else f"not found: {info['path']}"
        table.add_row(label, status, detail)

    logger.console.print(table)
    logger.console.print()

    if errors == 0:
        logger.console.print(Panel(
            "[green]All dependencies satisfied — ARES is ready![/green]\n"
            "[dim]sudo python3 ares.py -t <TARGET_IP>[/dim]",
            border_style="green", box=box.ROUNDED
        ))
    else:
        logger.console.print(Panel(
            f"[red]{errors} missing dependenc{'y' if errors == 1 else 'ies'}[/red] — "
            "run [cyan]bash install.sh[/cyan] to fix them",
            border_style="red", box=box.ROUNDED
        ))

    sys.exit(0 if errors == 0 else 1)


def build_config(args) -> AresConfig:
    """Build AresConfig from CLI arguments."""
    config = AresConfig(
        target_ip=args.target,
        hostname=args.hostname,
        discover_mode=args.discover,
        output_dir=args.output,
        threads=args.threads,
        intensity=args.intensity,
        nmap_top_ports=args.top_ports,
        run_udp=args.udp,
        proxy=args.proxy,
        fuzz_extensions=args.extensions,
        nuclei_severity=args.nuclei_severity,
        report_formats=[f.strip() for f in args.report.split(",")],
    )
    # Only override wordlists if explicitly passed — otherwise keep auto-detected defaults
    if args.wordlist_web:
        config.wordlist_web = args.wordlist_web
    if args.wordlist_web_files:
        config.wordlist_web_files = args.wordlist_web_files
    if args.wordlist_vhost:
        config.wordlist_vhost = args.wordlist_vhost
    if args.wordlist_users:
        config.wordlist_users = args.wordlist_users
    if args.wordlist_passwords:
        config.wordlist_passwords = args.wordlist_passwords
    if args.fuzz_depth:
        config.fuzz_max_depth = args.fuzz_depth
    config.post_nmap_delay = args.post_nmap_delay

    # Process module selection
    modules = [m.strip() for m in args.modules.split(",")]
    if args.no_nmap and "nmap" in modules:
        modules.remove("nmap")
    if args.no_brute and "bruteforce" in modules:
        modules.remove("bruteforce")
    if args.no_nuclei and "nuclei" in modules:
        modules.remove("nuclei")
    if args.no_fuzz and "fuzzing" in modules:
        modules.remove("fuzzing")
    config.modules_enabled = modules

    return config


def main():
    # Check if running as root (needed for SYN scan)
    args = parse_args()

    if args.update:
        cmd_update()  # exits

    if args.check:
        cmd_check()  # exits

    if not args.target:
        logger.error("Target is required. Use -t <IP> or --check to verify dependencies.")
        sys.exit(1)

    if os.geteuid() != 0:
        logger.warning("ARES works best with root privileges (SYN scan, etc.)")
        logger.warning("Consider running with: sudo python3 ares.py ...")
        logger.console.print()

    config = build_config(args)

    try:
        orchestrator = Orchestrator(config)
        orchestrator.run()
    except KeyboardInterrupt:
        logger.console.print("\n")
        logger.warning("Scan interrupted by user. Partial results may be available.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    main()
