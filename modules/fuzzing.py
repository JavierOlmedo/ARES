"""
ARES - Fuzzing Module
Directory brute-forcing and virtual host enumeration.
Uses gobuster/ffuf depending on availability.
"""
import os
import re
import json
from modules.base import BaseModule
from core.utils import run_command, check_tool
from core import logger


class FuzzingModule(BaseModule):
    name = "fuzzing"
    description = "Directory brute-forcing & virtual host enumeration"
    required_tools = []  # Will check gobuster OR ffuf
    phase = 1

    def preflight(self) -> bool:
        """At least one fuzzer must be available."""
        self.fuzzer = None
        if check_tool("gobuster"):
            self.fuzzer = "gobuster"
        elif check_tool("ffuf"):
            self.fuzzer = "ffuf"
        elif check_tool("feroxbuster"):
            self.fuzzer = "feroxbuster"

        if not self.fuzzer:
            logger.error("[fuzzing] No fuzzer found. Install gobuster, ffuf, or feroxbuster.")
            return False

        logger.info(f"Using fuzzer: {self.fuzzer}")

        # Check wordlist
        if not os.path.isfile(self.config.wordlist_web):
            logger.warning(f"Wordlist not found: {self.config.wordlist_web}")
            # Try common fallbacks
            fallbacks = [
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            ]
            for fb in fallbacks:
                if os.path.isfile(fb):
                    self.config.wordlist_web = fb
                    logger.info(f"Using fallback wordlist: {fb}")
                    break
        return True

    def run(self, context: dict) -> dict:
        results = {
            "directories": [],
            "vhosts": [],
            "raw_files": [],
        }

        # Get web ports from nmap results
        web_ports = context.get("nmap", {}).get("web_ports", [])
        if not web_ports:
            # Fallback: try common web ports
            logger.warning("No web ports from nmap, trying port 80...")
            web_ports = [{"port": 80, "scheme": "http"}]

        for wp in web_ports:
            port = wp["port"]
            scheme = wp["scheme"]

            # Determine target URL
            if self.config.hostname:
                base_url = f"{scheme}://{self.config.hostname}:{port}" if port not in (80, 443) else f"{scheme}://{self.config.hostname}"
            else:
                base_url = f"{scheme}://{self.config.target_ip}:{port}" if port not in (80, 443) else f"{scheme}://{self.config.target_ip}"

            # ── Directory fuzzing ──
            logger.info(f"Directory fuzzing: {base_url}")
            dirs = self._fuzz_directories(base_url, port)
            results["directories"].extend(dirs)

            # ── VHost fuzzing (only if hostname set) ──
            if self.config.hostname:
                logger.info(f"VHost fuzzing: {self.config.hostname}:{port}")
                vhosts = self._fuzz_vhosts(scheme, port)
                results["vhosts"].extend(vhosts)

        if results["directories"]:
            logger.success(f"Found {len(results['directories'])} directories/files")
            for d in results["directories"][:20]:  # Show first 20
                logger.finding(
                    f"{d['status']} — {d['path']}",
                    f"Size: {d.get('size', '?')}",
                    severity="info"
                )
            if len(results["directories"]) > 20:
                logger.info(f"... and {len(results['directories']) - 20} more (see report)")

        if results["vhosts"]:
            logger.success(f"Found {len(results['vhosts'])} virtual hosts")
            for v in results["vhosts"]:
                logger.finding(f"VHost: {v['hostname']}", severity="medium")

        return results

    def _fuzz_directories(self, base_url: str, port: int) -> list:
        """Directory/file brute-force."""
        outfile = os.path.join(self.output_path, f"dirs_{port}.txt")
        exts = self.config.fuzz_extensions

        if self.fuzzer == "gobuster":
            cmd = (
                f"gobuster dir -u {base_url} "
                f"-w {self.config.wordlist_web} "
                f"-x {exts} "
                f"-t {self.config.threads} "
                f"-o {outfile} "
                f"--no-error -q "
                f"-k "  # skip TLS verification
                f"--timeout 10s"
            )
        elif self.fuzzer == "ffuf":
            cmd = (
                f"ffuf -u {base_url}/FUZZ "
                f"-w {self.config.wordlist_web} "
                f"-e .{exts.replace(',', ',.')} "
                f"-t {self.config.threads} "
                f"-o {outfile.replace('.txt', '.json')} -of json "
                f"-mc all -fc 404 "
                f"-c -s"
            )
        elif self.fuzzer == "feroxbuster":
            cmd = (
                f"feroxbuster -u {base_url} "
                f"-w {self.config.wordlist_web} "
                f"-x {exts} "
                f"-t {self.config.threads} "
                f"-o {outfile} "
                f"-k --quiet"
            )
        else:
            return []

        result = run_command(cmd, timeout=600)
        return self._parse_directory_results(outfile, result, port)

    def _fuzz_vhosts(self, scheme: str, port: int) -> list:
        """Virtual host enumeration."""
        if not self.config.hostname:
            return []

        wordlist = self.config.wordlist_vhost
        if not os.path.isfile(wordlist):
            logger.warning(f"VHost wordlist not found: {wordlist}")
            return []

        outfile = os.path.join(self.output_path, f"vhosts_{port}.txt")
        target_url = f"{scheme}://{self.config.hostname}:{port}" if port not in (80, 443) else f"{scheme}://{self.config.hostname}"

        if self.fuzzer == "gobuster":
            cmd = (
                f"gobuster vhost -u {target_url} "
                f"-w {wordlist} "
                f"-t {self.config.threads} "
                f"-o {outfile} "
                f"--append-domain "
                f"-k -q"
            )
        elif self.fuzzer == "ffuf":
            cmd = (
                f"ffuf -u {target_url} "
                f"-H 'Host: FUZZ.{self.config.hostname}' "
                f"-w {wordlist} "
                f"-t {self.config.threads} "
                f"-o {outfile.replace('.txt', '.json')} -of json "
                f"-mc all -fc 404 -fs 0 "
                f"-c -s"
            )
        else:
            return []

        result = run_command(cmd, timeout=300)
        return self._parse_vhost_results(outfile, result)

    def _parse_directory_results(self, outfile: str, cmd_result: dict, port: int) -> list:
        """Parse directory fuzzing output."""
        dirs = []

        # Try JSON (ffuf output)
        json_file = outfile.replace(".txt", ".json")
        if os.path.isfile(json_file):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    dirs.append({
                        "path": r.get("input", {}).get("FUZZ", r.get("url", "")),
                        "status": r.get("status", 0),
                        "size": r.get("length", 0),
                        "port": port,
                    })
                return dirs
            except (json.JSONDecodeError, KeyError):
                pass

        # Parse text output (gobuster/feroxbuster)
        if os.path.isfile(outfile):
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Gobuster format: /path (Status: 200) [Size: 1234]
                    match = re.search(r'(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]', line)
                    if match:
                        dirs.append({
                            "path": match.group(1),
                            "status": int(match.group(2)),
                            "size": int(match.group(3)),
                            "port": port,
                        })
                        continue
                    # Feroxbuster: STATUS LINES WORDS CHARS URL
                    match = re.search(r'^(\d{3})\s+\d+l\s+\d+w\s+(\d+)c\s+(http\S+)', line)
                    if match:
                        dirs.append({
                            "path": match.group(3),
                            "status": int(match.group(1)),
                            "size": int(match.group(2)),
                            "port": port,
                        })

        # Also parse stdout if file parsing failed
        if not dirs and cmd_result.get("stdout"):
            for line in cmd_result["stdout"].splitlines():
                match = re.search(r'(\S+)\s+\(Status:\s*(\d+)\)', line)
                if match:
                    dirs.append({
                        "path": match.group(1),
                        "status": int(match.group(2)),
                        "size": 0,
                        "port": port,
                    })

        return dirs

    def _parse_vhost_results(self, outfile: str, cmd_result: dict) -> list:
        """Parse vhost enumeration results."""
        vhosts = []

        json_file = outfile.replace(".txt", ".json")
        if os.path.isfile(json_file):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    vhosts.append({
                        "hostname": r.get("input", {}).get("FUZZ", ""),
                        "status": r.get("status", 0),
                    })
                return vhosts
            except (json.JSONDecodeError, KeyError):
                pass

        if os.path.isfile(outfile):
            with open(outfile) as f:
                for line in f:
                    line = line.strip()
                    if "Found:" in line:
                        match = re.search(r'Found:\s+(\S+)', line)
                        if match:
                            vhosts.append({"hostname": match.group(1), "status": 200})

        return vhosts
