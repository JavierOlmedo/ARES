"""
ARES - Markdown Report Generator
"""
import os
from datetime import datetime
from core.config import AresConfig


class MarkdownReporter:
    def __init__(self, config: AresConfig, results: dict, total_time: float):
        self.config = config
        self.results = results
        self.total_time = total_time

    def generate(self) -> str:
        lines = []
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines.append(f"# ⚔ ARES Scan Report")
        lines.append(f"")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Target** | `{self.config.target_ip}` |")
        if self.config.hostname:
            lines.append(f"| **Hostname** | `{self.config.hostname}` |")
        lines.append(f"| **Date** | {ts} |")
        lines.append(f"| **Duration** | {self.total_time:.1f}s |")
        lines.append(f"| **Intensity** | {self.config.intensity} |")
        lines.append(f"")

        # ── Nmap Results ──
        nmap = self.results.get("nmap", {})
        if nmap and not nmap.get("error"):
            lines.append(f"## 🔍 Port Scan (Nmap)")
            lines.append(f"")
            ports = nmap.get("ports", [])
            if ports:
                lines.append(f"| Port | State | Service | Version |")
                lines.append(f"|------|-------|---------|---------|")
                for p in ports:
                    lines.append(f"| {p['port']}/{p.get('protocol','tcp')} | {p['state']} | {p['service']} | {p.get('version','')} |")
                lines.append(f"")

                # NSE Script output
                for p in ports:
                    scripts = p.get("scripts", {})
                    if scripts:
                        lines.append(f"### Port {p['port']} — NSE Scripts")
                        for script_id, output in scripts.items():
                            lines.append(f"**{script_id}:**")
                            lines.append(f"```")
                            lines.append(output[:2000])  # Truncate long output
                            lines.append(f"```")
                        lines.append(f"")

            if nmap.get("os_guess"):
                lines.append(f"**OS Detection:** {nmap['os_guess']}")
                lines.append(f"")

            udp = nmap.get("udp_ports", [])
            if udp:
                lines.append(f"### UDP Ports")
                lines.append(f"| Port | State | Service |")
                lines.append(f"|------|-------|---------|")
                for p in udp:
                    lines.append(f"| {p['port']} | {p['state']} | {p['service']} |")
                lines.append(f"")

        # ── Fuzzing Results ──
        fuzzing = self.results.get("fuzzing", {})
        if fuzzing and not fuzzing.get("error"):
            lines.append(f"## 📂 Directory & VHost Fuzzing")
            lines.append(f"")
            dirs = fuzzing.get("directories", [])
            if dirs:
                lines.append(f"### Directories / Files ({len(dirs)} found)")
                lines.append(f"| Status | Path | Size |")
                lines.append(f"|--------|------|------|")
                for d in dirs:
                    lines.append(f"| {d['status']} | `{d['path']}` | {d.get('size', '?')} |")
                lines.append(f"")

            vhosts = fuzzing.get("vhosts", [])
            if vhosts:
                lines.append(f"### Virtual Hosts ({len(vhosts)} found)")
                for v in vhosts:
                    lines.append(f"- `{v['hostname']}` (Status: {v['status']})")
                lines.append(f"")

        # ── Brute Force Results ──
        brute = self.results.get("bruteforce", {})
        if brute and not brute.get("error"):
            lines.append(f"## 🔑 Brute Force")
            lines.append(f"")
            creds = brute.get("credentials", [])
            if creds:
                lines.append(f"### 🔥 Credentials Found!")
                lines.append(f"| Service | Port | Username | Password |")
                lines.append(f"|---------|------|----------|----------|")
                for c in creds:
                    lines.append(f"| {c['service']} | {c['port']} | `{c['username']}` | `{c['password']}` |")
                lines.append(f"")
            else:
                lines.append(f"No credentials found.")
                lines.append(f"")

            attempted = brute.get("attempted_services", [])
            if attempted:
                svc_list = ', '.join(f"{s['service']}:{s['port']}" for s in attempted)
                lines.append(f"**Services tested:** {svc_list}")
                lines.append(f"")

        # ── Nuclei Results ──
        nuclei = self.results.get("nuclei", {})
        if nuclei and not nuclei.get("error"):
            lines.append(f"## ⚠️ Vulnerability Scan (Nuclei)")
            lines.append(f"")
            vulns = nuclei.get("vulnerabilities", [])
            if vulns:
                # Group by severity
                for sev in ["critical", "high", "medium", "low", "info"]:
                    sev_vulns = [v for v in vulns if v.get("severity") == sev]
                    if sev_vulns:
                        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(sev, "")
                        lines.append(f"### {emoji} {sev.upper()} ({len(sev_vulns)})")
                        for v in sev_vulns:
                            lines.append(f"- **{v['name']}**")
                            if v.get("cve_id"):
                                lines.append(f"  - CVE: `{v['cve_id']}`")
                            lines.append(f"  - URL: `{v.get('matched_url', '')}`")
                            lines.append(f"  - Template: `{v.get('template_id', '')}`")
                            if v.get("description"):
                                lines.append(f"  - {v['description'][:200]}")
                        lines.append(f"")
            else:
                lines.append(f"No vulnerabilities detected.")
                lines.append(f"")

        # ── Footer ──
        lines.append(f"---")
        lines.append(f"*Generated by ARES v1.0.0 — hackpuntes.com*")

        report = "\n".join(lines)
        outpath = os.path.join(self.config.output_dir, "reports", "ares_report.md")
        with open(outpath, "w") as f:
            f.write(report)
        return outpath
