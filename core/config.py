"""
ARES - Configuration Management
"""
import os
import json
from dataclasses import dataclass, field
from typing import Optional

# Local wordlists directory (project root/wordlists/)
_LOCAL_WORDLISTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists")


def _get_ares_home() -> str:
    """Return ~/.ares for the real user, even when running under sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return os.path.join(pwd.getpwnam(sudo_user).pw_dir, ".ares")
        except (KeyError, ImportError):
            pass
    return os.path.join(os.path.expanduser("~"), ".ares")


def _local_find(subdir: str, prefixes: list, fallback: str) -> str:
    """
    Find the first file in wordlists/{subdir}/ whose name starts with any
    of the given prefixes (tried in order). Falls back to system path if none found.
    """
    import glob
    folder = os.path.join(_LOCAL_WORDLISTS, subdir)
    for prefix in prefixes:
        matches = sorted(glob.glob(os.path.join(folder, f"{prefix}*")))
        if matches:
            return matches[0]
    return fallback


def _sys_first(candidates: list) -> str:
    """Return first existing system path, or last entry as default."""
    for c in candidates:
        if os.path.isfile(c):
            return c
    return candidates[-1]


@dataclass
class AresConfig:
    """Global configuration for ARES."""
    target_ip: str = ""
    hostname: str = ""
    output_dir: str = ""
    threads: int = 10
    intensity: str = "normal"  # quiet, normal, aggressive
    discover_mode: bool = False
    proxy: str = ""  # e.g. http://127.0.0.1:8080

    # Wordlists — local lists take priority, auto-detected by prefix
    wordlist_users: str = field(default_factory=lambda: _local_find(
        "users", ["hackpuntes-usernames", "hackpuntes-basic"],
        _sys_first(["/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                    "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"])))

    wordlist_passwords: str = field(default_factory=lambda: _local_find(
        "passwords", ["hackpuntes-passwords", "most-common-passwords"],
        "/usr/share/wordlists/rockyou.txt"))

    # Web: directories wordlist (phase 1 fuzzing)
    wordlist_web: str = field(default_factory=lambda: _local_find(
        "web", ["raft-large-directories", "raft-medium-directories"],
        _sys_first(["/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"])))

    # Web: files wordlist (phase 2 fuzzing — with extensions)
    wordlist_web_files: str = field(default_factory=lambda: _local_find(
        "web", ["raft-large-files", "raft-medium-files"],
        _sys_first(["/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt",
                    "/usr/share/seclists/Discovery/Web-Content/common.txt",
                    "/usr/share/wordlists/dirb/common.txt"])))

    wordlist_vhost: str = field(default_factory=lambda: _local_find(
        "vhost", ["hackpuntes-subdomains", "subdomains"],
        _sys_first(["/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"])))

    nmap_top_ports: int = 1000
    nmap_scripts: bool = True
    run_udp: bool = False
    fuzz_extensions: str = "php,html,txt,asp,aspx,jsp,bak,old,config"
    fuzz_max_depth: int = 2
    nuclei_severity: str = "low,medium,high,critical"
    brute_services: list = field(default_factory=lambda: [
        "ssh", "ftp", "smb", "rdp", "http-get", "mysql", "postgres", "mssql"
    ])
    modules_enabled: list = field(default_factory=lambda: ["nmap", "fuzzing", "bruteforce"])
    report_formats: list = field(default_factory=lambda: ["console", "markdown", "html"])

    def setup_workspace(self):
        """Create organized folder structure for the target."""
        if not self.output_dir:
            safe_name = self.hostname.replace(".", "_") if self.hostname else self.target_ip.replace(".", "_")
            self.output_dir = os.path.join(_get_ares_home(), safe_name)

        dirs = [
            self.output_dir,
            os.path.join(self.output_dir, "nmap"),
            os.path.join(self.output_dir, "fuzzing"),
            os.path.join(self.output_dir, "bruteforce"),
            os.path.join(self.output_dir, "nuclei"),
            os.path.join(self.output_dir, "reports"),
            os.path.join(self.output_dir, "loot"),
            os.path.join(self.output_dir, "exploits"),
        ]
        for d in dirs:
            os.makedirs(d, exist_ok=True)
        return self.output_dir

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}

    def save(self, path: Optional[str] = None):
        path = path or os.path.join(self.output_dir, "ares_config.json")
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
