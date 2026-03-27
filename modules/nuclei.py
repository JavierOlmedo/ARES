"""
ARES - Nuclei Module
Vulnerability scanning with Project Discovery's Nuclei.
"""
import os
import json
from modules.base import BaseModule
from core.utils import run_command, check_tool
from core import logger


class NucleiModule(BaseModule):
    name = "nuclei"
    description = "Automated vulnerability scanning (CVEs, misconfigs, exposures)"
    required_tools = ["nuclei"]
    phase = 2

    def run(self, context: dict) -> dict:
        results = {
            "vulnerabilities": [],
            "raw_files": [],
        }

        # Build target list from nmap web ports
        targets = self._build_targets(context)
        if not targets:
            logger.warning("No web targets identified for Nuclei scanning.")
            return results

        # Update nuclei templates (if not recently updated)
        self._update_templates()

        for target_url in targets:
            logger.info(f"Scanning: {target_url}")
            vulns = self._run_nuclei(target_url)
            results["vulnerabilities"].extend(vulns)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        results["vulnerabilities"].sort(key=lambda v: severity_order.get(v.get("severity", "unknown"), 5))

        if results["vulnerabilities"]:
            logger.success(f"Found {len(results['vulnerabilities'])} vulnerabilities!")
            for v in results["vulnerabilities"]:
                logger.finding(
                    f"[{v['severity'].upper()}] {v['name']}",
                    f"{v.get('matched_url', '')} — {v.get('template_id', '')}",
                    severity=v["severity"]
                )
        else:
            logger.info("No vulnerabilities found by Nuclei.")

        return results

    def _build_targets(self, context: dict) -> list:
        """Build target URLs from nmap results."""
        targets = []
        web_ports = context.get("nmap", {}).get("web_ports", [])

        for wp in web_ports:
            port = wp["port"]
            scheme = wp["scheme"]
            # Use hostname if available
            host = self.config.hostname or self.config.target_ip
            if port in (80, 443):
                targets.append(f"{scheme}://{host}")
            else:
                targets.append(f"{scheme}://{host}:{port}")

        # Also add IP-based URLs if hostname is set (catches different vhosts)
        if self.config.hostname:
            for wp in web_ports:
                port = wp["port"]
                scheme = wp["scheme"]
                if port in (80, 443):
                    targets.append(f"{scheme}://{self.config.target_ip}")
                else:
                    targets.append(f"{scheme}://{self.config.target_ip}:{port}")

        return list(set(targets))

    def _update_templates(self):
        """Update nuclei templates if needed."""
        result = run_command("nuclei -update-templates -silent", timeout=120)
        if result["returncode"] == 0:
            logger.info("Nuclei templates updated.")
        else:
            logger.warning("Could not update Nuclei templates, using cached.")

    def _run_nuclei(self, target_url: str) -> list:
        """Run nuclei against a single target."""
        safe_target = target_url.replace("://", "_").replace("/", "_").replace(":", "_")
        json_output = os.path.join(self.output_path, f"nuclei_{safe_target}.json")
        txt_output = os.path.join(self.output_path, f"nuclei_{safe_target}.txt")

        cmd = (
            f"nuclei -u {target_url} "
            f"-severity {self.config.nuclei_severity} "
            f"-jsonl -o {json_output} "
            f"-silent "
            f"-rate-limit 100 "
            f"-bulk-size 25 "
            f"-concurrency 10 "
            f"-timeout 10 "
            f"-retries 1"
        )

        if self.config.intensity == "aggressive":
            cmd += " -rl 200"

        result = run_command(cmd, timeout=600)

        # Also save readable output
        cmd_txt = cmd.replace(f"-jsonl -o {json_output}", f"-o {txt_output}").replace("-silent", "")
        # Skip running twice, just parse JSON

        return self._parse_nuclei_json(json_output)

    def _parse_nuclei_json(self, json_file: str) -> list:
        """Parse nuclei JSONL output."""
        vulns = []
        if not os.path.isfile(json_file):
            return vulns

        with open(json_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    vuln = {
                        "name": entry.get("info", {}).get("name", "Unknown"),
                        "template_id": entry.get("template-id", ""),
                        "severity": entry.get("info", {}).get("severity", "unknown"),
                        "description": entry.get("info", {}).get("description", ""),
                        "matched_url": entry.get("matched-at", entry.get("host", "")),
                        "matcher_name": entry.get("matcher-name", ""),
                        "extracted_results": entry.get("extracted-results", []),
                        "curl_command": entry.get("curl-command", ""),
                        "type": entry.get("type", ""),
                        "tags": entry.get("info", {}).get("tags", []),
                        "reference": entry.get("info", {}).get("reference", []),
                        "cve_id": self._extract_cve(entry),
                    }
                    vulns.append(vuln)
                except json.JSONDecodeError:
                    continue

        return vulns

    def _extract_cve(self, entry: dict) -> str:
        """Extract CVE ID from nuclei entry."""
        # Check classification
        classification = entry.get("info", {}).get("classification", {})
        cve = classification.get("cve-id", "")
        if cve:
            return cve if isinstance(cve, str) else ", ".join(cve)

        # Check template ID
        tid = entry.get("template-id", "")
        if tid.upper().startswith("CVE-"):
            return tid.upper()

        return ""
