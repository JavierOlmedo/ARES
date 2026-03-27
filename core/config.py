"""
ARES - Configuration Management
"""
import os
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AresConfig:
    """Global configuration for ARES."""
    target_ip: str = ""
    hostname: str = ""
    output_dir: str = ""
    threads: int = 10
    intensity: str = "normal"  # quiet, normal, aggressive
    wordlist_dir: str = "/usr/share/wordlists"
    wordlist_web: str = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    wordlist_vhost: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    wordlist_users: str = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    wordlist_passwords: str = "/usr/share/wordlists/rockyou.txt"
    nmap_top_ports: int = 1000
    nmap_scripts: bool = True
    run_udp: bool = False
    fuzz_extensions: str = "php,html,txt,asp,aspx,jsp,bak,old,config"
    nuclei_severity: str = "low,medium,high,critical"
    brute_services: list = field(default_factory=lambda: ["ssh", "ftp", "smb", "http-get"])
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
