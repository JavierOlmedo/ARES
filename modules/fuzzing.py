"""
ARES - Fuzzing Module
Directory brute-forcing and virtual host enumeration.
Uses gobuster/ffuf/feroxbuster depending on availability.

Flow per web port:
  1. Directory discovery (no extensions)
  2. File discovery (with extensions)
  3. Recursive into found directories (up to fuzz_max_depth)
"""
import os
import re
import json
from modules.base import BaseModule
from core.utils import run_command, run_command_live, check_tool
from core import logger


class FuzzingModule(BaseModule):
    name = "fuzzing"
    description = "Directory & file brute-forcing with recursive crawl + VHost enumeration"
    required_tools = []  # gobuster OR ffuf OR feroxbuster
    phase = 1

    def preflight(self) -> bool:
        self.fuzzer = None
        for candidate in ("gobuster", "ffuf", "feroxbuster"):
            if check_tool(candidate):
                self.fuzzer = candidate
                break

        if not self.fuzzer:
            logger.error("[fuzzing] No fuzzer found. Install gobuster, ffuf, or feroxbuster.")
            return False

        logger.info(f"Fuzzer: {self.fuzzer}")

        if not os.path.isfile(self.config.wordlist_web):
            for fb in (
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            ):
                if os.path.isfile(fb):
                    self.config.wordlist_web = fb
                    logger.info(f"Wordlist fallback: {fb}")
                    break
        return True

    def run(self, context: dict) -> dict:
        results = {"directories": [], "vhosts": [], "raw_files": []}

        web_ports = context.get("nmap", {}).get("web_ports", [])
        if not web_ports:
            logger.warning("No web ports from nmap, trying port 80...")
            web_ports = [{"port": 80, "scheme": "http"}]

        for wp in web_ports:
            port = wp["port"]
            scheme = wp["scheme"]
            host = self.config.hostname or self.config.target_ip
            base_url = (
                f"{scheme}://{host}"
                if port in (80, 443)
                else f"{scheme}://{host}:{port}"
            )

            logger.info(f"Target: {base_url}")

            # ── Phase 1: Directory discovery ─────────────────────────────────
            logger.info("  [1/3] Directory discovery...")
            dirs = self._fuzz(base_url, port, mode="dirs", label=f"dirs_{port}")
            self._show_findings(dirs, "directory")
            results["directories"].extend(dirs)

            # ── Phase 2: File discovery ───────────────────────────────────────
            logger.info("  [2/3] File discovery...")
            files = self._fuzz(base_url, port, mode="files", label=f"files_{port}")
            self._show_findings(files, "file")
            results["directories"].extend(files)

            # ── Phase 3: Recursive into found directories ─────────────────────
            if dirs:
                logger.info(f"  [3/3] Recursing into {len(dirs)} director{'y' if len(dirs) == 1 else 'ies'}...")
                self._recurse(dirs, port, results, depth=1)
            else:
                logger.info("  [3/3] No directories found — skipping recursion")

            # ── VHost fuzzing ─────────────────────────────────────────────────
            if self.config.hostname:
                logger.info(f"  VHost enumeration on {self.config.hostname}:{port}")
                vhosts = self._fuzz_vhosts(scheme, port)
                results["vhosts"].extend(vhosts)
                if vhosts:
                    for v in vhosts:
                        logger.finding(f"VHost: {v['hostname']}", severity="medium")

        total = len(results["directories"])
        if total:
            logger.success(f"Total findings: {total}")
        else:
            logger.info("No directories or files found.")

        return results

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _recurse(self, dirs: list, port: int, results: dict, depth: int):
        if depth > self.config.fuzz_max_depth:
            return
        indent = "  " * (depth + 1)
        for d in dirs:
            sub_url = d["path"].rstrip("/")
            logger.info(f"{indent}→ {sub_url}")

            sub_dirs = self._fuzz(sub_url, port, mode="dirs",
                                   label=f"dirs_{port}_d{depth}_{self._slug(sub_url)}")
            sub_files = self._fuzz(sub_url, port, mode="files",
                                    label=f"files_{port}_d{depth}_{self._slug(sub_url)}")

            self._show_findings(sub_dirs, "directory", indent=indent + "  ")
            self._show_findings(sub_files, "file", indent=indent + "  ")

            results["directories"].extend(sub_dirs)
            results["directories"].extend(sub_files)

            if sub_dirs:
                self._recurse(sub_dirs, port, results, depth + 1)

    def _show_findings(self, findings: list, kind: str, indent: str = "    "):
        if not findings:
            return
        label = "dir" if kind == "directory" else "file"
        logger.success(f"{indent}Found {len(findings)} {label}(s)")
        for f in findings[:15]:
            logger.finding(
                f"{f['status']} — {f['path']}",
                f"Size: {f.get('size', '?')}",
                severity="info",
            )
        if len(findings) > 15:
            logger.info(f"{indent}  ... and {len(findings) - 15} more")

    @staticmethod
    def _slug(url: str) -> str:
        """Turn a URL path into a safe filename fragment."""
        return re.sub(r"[^\w]", "_", url.split("://")[-1])[:40]

    def _fuzz(self, url: str, port: int, mode: str, label: str) -> list:
        """
        Run one fuzzing pass with real-time output.
        mode='dirs'  → no extensions (directory discovery)
        mode='files' → with extensions (file discovery)
        """
        outfile = os.path.join(self.output_path, f"{label}.txt")
        exts = self.config.fuzz_extensions
        threads = self.config.threads
        found_live = []  # filled by the streaming callback

        # Use dedicated wordlist per mode
        wordlist = self.config.wordlist_web_files if mode == "files" else self.config.wordlist_web
        logger.info(f"  Wordlist ({mode}): {wordlist}")

        if self.fuzzer == "gobuster":
            cmd = (
                f"gobuster dir -u {url} "
                f"-w {wordlist} "
                + (f"-x {exts} " if mode == "files" else "")
                + f"-t {threads} --no-error -q -k --timeout 10s"
            )
            result = run_command_live(
                cmd, timeout=600,
                on_line=lambda line: self._on_gobuster_line(line, port, mode, found_live),
            )
            # Save raw output to file
            with open(outfile, "w") as f:
                f.write(result.get("stdout", ""))
            return found_live

        elif self.fuzzer == "ffuf":
            ext_flag = f"-e .{exts.replace(',', ',.')}" if mode == "files" else ""
            json_out = outfile.replace(".txt", ".json")
            cmd = (
                f"ffuf -u {url}/FUZZ "
                f"-w {wordlist} "
                f"{ext_flag} "
                f"-t {threads} -o {json_out} -of json -mc all -fc 404 -c"
            )
            result = run_command_live(
                cmd, timeout=600,
                on_line=lambda line: self._on_ffuf_line(line, port, mode, found_live),
            )
            return found_live or self._parse_results(outfile, result, port, mode)

        elif self.fuzzer == "feroxbuster":
            cmd = (
                f"feroxbuster -u {url} "
                f"-w {wordlist} "
                + (f"-x {exts} " if mode == "files" else "")
                + f"-t {threads} -o {outfile} -k --depth 1"
            )
            result = run_command_live(
                cmd, timeout=600,
                on_line=lambda line: self._on_ferox_line(line, port, mode, found_live),
            )
            return found_live or self._parse_results(outfile, result, port, mode)

        return []

    def _fuzz_vhosts(self, scheme: str, port: int) -> list:
        wordlist = self.config.wordlist_vhost
        if not os.path.isfile(wordlist):
            logger.warning(f"VHost wordlist not found: {wordlist}")
            return []

        outfile = os.path.join(self.output_path, f"vhosts_{port}.txt")
        target_url = (
            f"{scheme}://{self.config.hostname}"
            if port in (80, 443)
            else f"{scheme}://{self.config.hostname}:{port}"
        )

        if self.fuzzer == "gobuster":
            cmd = (
                f"gobuster vhost -u {target_url} "
                f"-w {wordlist} -t {self.config.threads} "
                f"-o {outfile} --append-domain -k -q"
            )
        elif self.fuzzer == "ffuf":
            json_out = outfile.replace(".txt", ".json")
            cmd = (
                f"ffuf -u {target_url} "
                f"-H 'Host: FUZZ.{self.config.hostname}' "
                f"-w {wordlist} -t {self.config.threads} "
                f"-o {json_out} -of json -mc all -fc 404 -fs 0 -c -s"
            )
        else:
            return []

        run_command(cmd, timeout=300)
        return self._parse_vhosts(outfile)

    # ── Live callbacks (real-time output) ────────────────────────────────────

    def _on_gobuster_line(self, line: str, port: int, mode: str, found: list):
        """Parse gobuster stdout line and print finding immediately."""
        m = re.search(r'(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]', line)
        if not m:
            return
        path, status, size = m.group(1), int(m.group(2)), int(m.group(3))
        self._print_live_finding(path, status, size)
        found.append({"path": path, "status": status, "size": size, "port": port, "type": mode})

    def _on_ffuf_line(self, line: str, port: int, mode: str, found: list):
        """Print ffuf findings from its non-JSON stdout (status lines)."""
        # ffuf prints: [Status: 200, Size: 123, Words: 10, Lines: 5] /path
        m = re.search(r'\[Status:\s*(\d+),\s*Size:\s*(\d+).*?\]\s+(\S+)', line)
        if not m:
            return
        status, size, path = int(m.group(1)), int(m.group(2)), m.group(3)
        self._print_live_finding(path, status, size)
        found.append({"path": path, "status": status, "size": size, "port": port, "type": mode})

    def _on_ferox_line(self, line: str, port: int, mode: str, found: list):
        """Parse feroxbuster stdout line."""
        m = re.search(r'^(\d{3})\s+\d+l\s+\d+w\s+(\d+)c\s+(http\S+)', line)
        if not m:
            return
        status, size, path = int(m.group(1)), int(m.group(2)), m.group(3)
        self._print_live_finding(path, status, size)
        found.append({"path": path, "status": status, "size": size, "port": port, "type": mode})

    @staticmethod
    def _print_live_finding(path: str, status: int, size: int):
        if status in (200, 204):
            color = "green"
        elif status in (301, 302, 307, 308):
            color = "yellow"
        elif status == 403:
            color = "red"
        else:
            color = "cyan"
        logger.console.print(
            f"    [{color}]{status}[/{color}]  {path}  [dim]{size}b[/dim]"
        )

    # ── Parsers ───────────────────────────────────────────────────────────────

    def _parse_results(self, outfile: str, cmd_result: dict, port: int, mode: str) -> list:
        findings = []

        # ffuf → JSON
        json_file = outfile.replace(".txt", ".json")
        if os.path.isfile(json_file):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    findings.append({
                        "path": r.get("url", r.get("input", {}).get("FUZZ", "")),
                        "status": r.get("status", 0),
                        "size": r.get("length", 0),
                        "port": port,
                        "type": mode,
                    })
                return findings
            except (json.JSONDecodeError, KeyError):
                pass

        # gobuster / feroxbuster → text
        src = outfile if os.path.isfile(outfile) else None
        lines = []
        if src:
            with open(src) as f:
                lines = f.readlines()
        elif cmd_result.get("stdout"):
            lines = cmd_result["stdout"].splitlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # gobuster: /path (Status: 200) [Size: 1234]
            m = re.search(r'(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]', line)
            if m:
                findings.append({
                    "path": m.group(1), "status": int(m.group(2)),
                    "size": int(m.group(3)), "port": port, "type": mode,
                })
                continue
            # feroxbuster: 200 1l 2w 123c http://...
            m = re.search(r'^(\d{3})\s+\d+l\s+\d+w\s+(\d+)c\s+(http\S+)', line)
            if m:
                findings.append({
                    "path": m.group(3), "status": int(m.group(1)),
                    "size": int(m.group(2)), "port": port, "type": mode,
                })

        return findings

    def _parse_vhosts(self, outfile: str) -> list:
        vhosts = []
        json_file = outfile.replace(".txt", ".json")
        if os.path.isfile(json_file):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    vhosts.append({"hostname": r.get("input", {}).get("FUZZ", ""), "status": r.get("status", 0)})
                return vhosts
            except (json.JSONDecodeError, KeyError):
                pass
        if os.path.isfile(outfile):
            with open(outfile) as f:
                for line in f:
                    m = re.search(r'Found:\s+(\S+)', line)
                    if m:
                        vhosts.append({"hostname": m.group(1), "status": 200})
        return vhosts
