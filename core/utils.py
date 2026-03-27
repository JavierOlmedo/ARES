"""
ARES - Shared Utilities
"""
import subprocess
import shutil
import os
import re
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


def run_command_live(cmd: str, timeout: int = 600, on_line=None, cwd: str = None) -> dict:
    """
    Run a shell command streaming stdout line by line.
    Calls on_line(line) for each output line (stripped).
    Returns same dict as run_command.
    """
    import threading
    stdout_lines = []
    stderr_lines = []

    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=cwd,
        )

        def _read_stderr():
            for line in proc.stderr:
                stderr_lines.append(line)

        t = threading.Thread(target=_read_stderr, daemon=True)
        t.start()

        for line in proc.stdout:
            stdout_lines.append(line)
            if on_line:
                on_line(line.rstrip())

        proc.wait(timeout=timeout)
        t.join(timeout=5)

        return {
            "stdout": "".join(stdout_lines),
            "stderr": "".join(stderr_lines),
            "returncode": proc.returncode,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired:
        proc.kill()
        warning(f"Command timed out after {timeout}s")
        return {"stdout": "".join(stdout_lines), "stderr": "TIMEOUT", "returncode": -1, "timed_out": True}
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


def add_to_hosts(ip: str, hostname: str) -> bool:
    """
    Ensure /etc/hosts has the correct ip → hostname entry.
    - If the exact pair already exists: skip.
    - If the hostname exists with a different IP: ask user whether to update.
    - If not present: add it.
    """
    hosts_file = "/etc/hosts"
    entry = f"{ip}\t{hostname}"

    try:
        with open(hosts_file, "r") as f:
            lines = f.readlines()
    except PermissionError:
        warning(f"Cannot read /etc/hosts — run as root or add manually:")
        warning(f"  echo '{entry}' | sudo tee -a /etc/hosts")
        return False

    content = "".join(lines)

    # Exact pair already present
    if re.search(rf'\b{re.escape(ip)}\b.*\b{re.escape(hostname)}\b', content):
        from core.logger import info
        info(f"/etc/hosts: {entry} already present")
        return True

    # Hostname exists but with a different IP
    existing_match = re.search(rf'^(\S+)\s+.*\b{re.escape(hostname)}\b', content, re.MULTILINE)
    if existing_match:
        old_ip = existing_match.group(1)
        from core.logger import warning as warn
        warn(f"/etc/hosts: {hostname} already mapped to {old_ip}")
        try:
            answer = input(f"  Update to {ip}? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"

        if answer != "y":
            from core.logger import info
            info("Keeping existing /etc/hosts entry.")
            return False

        # Replace the existing line
        new_lines = []
        for line in lines:
            if re.search(rf'\b{re.escape(hostname)}\b', line) and not line.strip().startswith("#"):
                new_lines.append(f"{entry}\n")
            else:
                new_lines.append(line)
        try:
            with open(hosts_file, "w") as f:
                f.writelines(new_lines)
            from core.logger import success
            success(f"/etc/hosts updated: {old_ip} → {ip} for {hostname}")
            return True
        except PermissionError:
            warning(f"Cannot write /etc/hosts — run as root")
            return False

    # Not present at all — append
    try:
        with open(hosts_file, "a") as f:
            f.write(f"\n{entry}\n")
        from core.logger import success
        success(f"Added to /etc/hosts: {entry}")
        return True
    except PermissionError:
        warning(f"Cannot write /etc/hosts — run as root or add manually:")
        warning(f"  echo '{entry}' | sudo tee -a /etc/hosts")
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
    for tool in ["nmap", "patator", "nuclei"]:
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
