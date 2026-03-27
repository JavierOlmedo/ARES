"""
ARES - Shared Utilities
"""
import subprocess
import shutil
import os
from core.logger import warning, error


def check_tool(tool_name: str) -> bool:
    """Check if a system tool is available in PATH."""
    return shutil.which(tool_name) is not None


def check_required_tools(tools: list) -> dict:
    """Check multiple tools, return dict of {tool: available}."""
    results = {}
    for tool in tools:
        available = check_tool(tool)
        results[tool] = available
        if not available:
            warning(f"Tool not found: {tool} — related module may fail")
    return results


def run_command(cmd: list | str, timeout: int = 600, cwd: str = None) -> dict:
    """
    Run a shell command and capture output.
    Returns dict with stdout, stderr, returncode, timed_out.
    """
    try:
        if isinstance(cmd, str):
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                timeout=timeout, cwd=cwd
            )
        else:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, cwd=cwd
            )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        warning(f"Command timed out after {timeout}s: {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
        return {"stdout": "", "stderr": "TIMEOUT", "returncode": -1, "timed_out": True}
    except Exception as e:
        error(f"Command failed: {e}")
        return {"stdout": "", "stderr": str(e), "returncode": -1, "timed_out": False}


def parse_nmap_service(service_str: str) -> str:
    """Normalize nmap service names for brute-force targeting."""
    mapping = {
        "ssh": "ssh",
        "ftp": "ftp",
        "http": "http-get",
        "https": "https-get",
        "http-proxy": "http-get",
        "smb": "smb",
        "microsoft-ds": "smb",
        "mysql": "mysql",
        "ms-sql-s": "mssql",
        "postgresql": "postgres",
        "vnc": "vnc",
        "rdp": "rdp",
        "ms-wbt-server": "rdp",
        "telnet": "telnet",
        "pop3": "pop3",
        "imap": "imap",
        "smtp": "smtp",
    }
    return mapping.get(service_str.lower(), None)


def add_to_hosts(ip: str, hostname: str):
    """Check if /etc/hosts has the entry, suggest adding if not."""
    try:
        with open("/etc/hosts", "r") as f:
            content = f.read()
        if hostname in content:
            return True
        warning(f"{hostname} not in /etc/hosts. Run: echo '{ip} {hostname}' | sudo tee -a /etc/hosts")
        return False
    except PermissionError:
        return False


def file_has_content(filepath: str) -> bool:
    """Check if a file exists and is non-empty."""
    return os.path.isfile(filepath) and os.path.getsize(filepath) > 0


def dependency_check() -> dict:
    """
    Check all ARES runtime dependencies.
    Returns a structured dict consumed by --check and install.sh logic.
    """
    import sys

    results = {"tools": {}, "fuzzers": {}, "wordlists": {}, "python": {}}

    # Python version
    vi = sys.version_info
    results["python"] = {
        "version": f"{vi.major}.{vi.minor}.{vi.micro}",
        "ok": vi.major >= 3 and vi.minor >= 10,
    }

    # Required single tools
    for tool in ["nmap", "hydra", "nuclei"]:
        results["tools"][tool] = check_tool(tool)

    # Fuzzers — at least one required
    for fuzzer in ["gobuster", "ffuf", "feroxbuster"]:
        results["fuzzers"][fuzzer] = check_tool(fuzzer)

    # Wordlists
    wordlists = {
        "seclists": "/usr/share/seclists",
        "rockyou.txt": "/usr/share/wordlists/rockyou.txt",
        "dirbuster-medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    }
    for label, path in wordlists.items():
        exists = os.path.exists(path)
        results["wordlists"][label] = {"path": path, "ok": exists}

    return results
