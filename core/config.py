"""
ARES - Configuration Management
"""
import os
import json
from dataclasses import dataclass, field
from typing import Optional

# Local wordlists directory (project root/wordlists/)
_LOCAL_WORDLISTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists")


def _local_first(candidates: list, fallback: str) -> str:
    """Try local wordlist candidates in order, return first found, else fallback."""
    for subpath in candidates:
        local = os.path.join(_LOCAL_WORDLISTS, subpath)
        if os.path.isfile(local):
            return local
    return fallback


@dataclass
class AresConfig:
    """Global configuration for ARES."""
    target_ip: str = ""
    hostname: str = ""
    output_dir: str = ""
    threads: int = 10
    intensity: str = "normal"  # quiet, normal, aggressive
    discover_mode: bool = False

    # Wordlists — local hackpuntes lists take priority over system defaults
    wordlist_users: str = field(default_factory=lambda: _local_first([
        "users/hackpuntes-usernames-12534.txt",
        "users/hackpuntes-basic-23.txt",
        "users/custom.txt",
    ], "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"))

    wordlist_passwords: str = field(default_factory=lambda: _local_first([
        "passwords/hackpuntes-passwords-23.txt",
        "passwords/most-common-passwords-1000.txt",
        "passwords/custom.txt",
    ], "/usr/share/wordlists/rockyou.txt"))

    wordlist_web: str = field(default_factory=lambda: _local_first([
        "web/custom.txt",
    ], "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"))

    wordlist_vhost: str = field(default_factory=lambda: _local_first([
        "vhost/custom.txt",
    ], "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"))

    nmap_top_ports: int = 1000
    nmap_scripts: bool = True
    run_udp: bool = False
    fuzz_extensions: str = "php,html,txt,asp,aspx,jsp,bak,old,config"
    fuzz_max_depth: int = 2
    nuclei_severity: str = "low,medium,high,critical"
    brute_services: list = field(default_factory=lambda: [
        "ssh", "ftp", "smb", "rdp", "http-get", "mysql", "postgres", "mssql"
    ])
    modules_enabled: list = field(default_factory=lambda: ["nmap", "fuzzing", "bruteforce", "nuclei"])
    report_formats: list = field(default_factory=lambda: ["console", "markdown", "html"])

    def setup_workspace(self):
        """Create organized folder structure for the target."""
        if not self.output_dir:
            safe_name = self.hostname.replace(".", "_") if self.hostname else self.target_ip.replace(".", "_")
            self.output_dir = os.path.join(os.getcwd(), f"ares_{safe_name}")

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
