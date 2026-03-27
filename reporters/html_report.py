"""
ARES - HTML Report Generator
Dark-themed, single-file HTML report.
"""
import os
from datetime import datetime
from core.config import AresConfig


class HTMLReporter:
    def __init__(self, config: AresConfig, results: dict, total_time: float):
        self.config = config
        self.results = results
        self.total_time = total_time

    def generate(self) -> str:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        nmap = self.results.get("nmap", {})
        fuzzing = self.results.get("fuzzing", {})
        brute = self.results.get("bruteforce", {})
        nuclei = self.results.get("nuclei", {})

        ports_html = self._ports_table(nmap.get("ports", []))
        dirs_html = self._dirs_table(fuzzing.get("directories", []))
        vhosts_html = self._vhosts_list(fuzzing.get("vhosts", []))
        creds_html = self._creds_table(brute.get("credentials", []))
        vulns_html = self._vulns_section(nuclei.get("vulnerabilities", []))

        # Count stats
        n_ports = len(nmap.get("ports", []))
        n_dirs = len(fuzzing.get("directories", []))
        n_creds = len(brute.get("credentials", []))
        n_vulns = len(nuclei.get("vulnerabilities", []))

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ARES Report — {self.config.target_ip}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
.header {{ text-align: center; padding: 2rem 0; border-bottom: 2px solid #c9302c; margin-bottom: 2rem; }}
.header h1 {{ font-size: 2.5rem; color: #c9302c; letter-spacing: 4px; }}
.header .subtitle {{ color: #8b949e; font-size: 0.9rem; margin-top: 0.5rem; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
.stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.2rem; text-align: center; }}
.stat .number {{ font-size: 2rem; font-weight: 700; color: #c9302c; }}
.stat .label {{ font-size: 0.85rem; color: #8b949e; }}
.meta {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 2rem; font-size: 0.9rem; }}
.meta span {{ color: #58a6ff; }}
section {{ margin-bottom: 2.5rem; }}
section h2 {{ font-size: 1.4rem; color: #c9302c; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; margin-bottom: 1rem; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }}
th {{ background: #1c2128; color: #c9302c; text-align: left; padding: 0.6rem 0.8rem; border-bottom: 2px solid #30363d; }}
td {{ padding: 0.5rem 0.8rem; border-bottom: 1px solid #21262d; }}
tr:hover {{ background: #161b22; }}
.severity {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }}
.sev-critical {{ background: #c9302c; color: #fff; }}
.sev-high {{ background: #d48806; color: #fff; }}
.sev-medium {{ background: #d4a006; color: #000; }}
.sev-low {{ background: #58a6ff; color: #000; }}
.sev-info {{ background: #30363d; color: #c9d1d9; }}
.cred {{ color: #3fb950; font-weight: 700; }}
.vuln-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; margin-bottom: 0.8rem; }}
.vuln-card h4 {{ color: #c9d1d9; margin-bottom: 0.3rem; }}
.vuln-meta {{ font-size: 0.8rem; color: #8b949e; }}
code {{ background: #1c2128; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }}
.footer {{ text-align: center; padding: 2rem 0; border-top: 1px solid #30363d; color: #484f58; font-size: 0.8rem; }}
.empty {{ color: #484f58; font-style: italic; padding: 1rem 0; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>⚔ ARES</h1>
        <div class="subtitle">Advanced Reconnaissance &amp; Enumeration Scanner</div>
    </div>

    <div class="meta">
        <strong>Target:</strong> <span>{self.config.target_ip}</span>
        {f' &nbsp;|&nbsp; <strong>Hostname:</strong> <span>{self.config.hostname}</span>' if self.config.hostname else ''}
        &nbsp;|&nbsp; <strong>Date:</strong> {ts}
        &nbsp;|&nbsp; <strong>Duration:</strong> {self.total_time:.1f}s
        &nbsp;|&nbsp; <strong>Intensity:</strong> {self.config.intensity}
    </div>

    <div class="stats">
        <div class="stat"><div class="number">{n_ports}</div><div class="label">Open Ports</div></div>
        <div class="stat"><div class="number">{n_dirs}</div><div class="label">Directories</div></div>
        <div class="stat"><div class="number">{n_creds}</div><div class="label">Credentials</div></div>
        <div class="stat"><div class="number">{n_vulns}</div><div class="label">Vulnerabilities</div></div>
    </div>

    <section>
        <h2>🔍 Port Scan</h2>
        {ports_html}
    </section>

    <section>
        <h2>📂 Directory Fuzzing</h2>
        {dirs_html}
    </section>

    <section>
        <h2>🌐 Virtual Hosts</h2>
        {vhosts_html}
    </section>

    <section>
        <h2>🔑 Brute Force</h2>
        {creds_html}
    </section>

    <section>
        <h2>⚠️ Vulnerabilities</h2>
        {vulns_html}
    </section>

    <div class="footer">
        Generated by ARES v1.0.0 — <a href="https://hackpuntes.com" style="color:#c9302c;">hackpuntes.com</a>
    </div>
</div>
</body>
</html>"""

        outpath = os.path.join(self.config.output_dir, "reports", "ares_report.html")
        with open(outpath, "w") as f:
            f.write(html)
        return outpath

    def _ports_table(self, ports: list) -> str:
        if not ports:
            return '<p class="empty">No open ports found.</p>'
        rows = ""
        for p in ports:
            rows += f"<tr><td><code>{p['port']}/{p.get('protocol','tcp')}</code></td><td>{p['state']}</td><td>{p['service']}</td><td>{p.get('version','')}</td></tr>\n"
        return f"<table><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>{rows}</table>"

    def _dirs_table(self, dirs: list) -> str:
        if not dirs:
            return '<p class="empty">No directories found.</p>'
        rows = ""
        for d in dirs[:100]:
            rows += f"<tr><td>{d['status']}</td><td><code>{d['path']}</code></td><td>{d.get('size','?')}</td></tr>\n"
        extra = f"<p class='empty'>... and {len(dirs)-100} more</p>" if len(dirs) > 100 else ""
        return f"<table><tr><th>Status</th><th>Path</th><th>Size</th></tr>{rows}</table>{extra}"

    def _vhosts_list(self, vhosts: list) -> str:
        if not vhosts:
            return '<p class="empty">No virtual hosts found.</p>'
        items = "".join(f"<tr><td><code>{v['hostname']}</code></td><td>{v['status']}</td></tr>" for v in vhosts)
        return f"<table><tr><th>Hostname</th><th>Status</th></tr>{items}</table>"

    def _creds_table(self, creds: list) -> str:
        if not creds:
            return '<p class="empty">No credentials found.</p>'
        rows = ""
        for c in creds:
            rows += f"<tr><td>{c['service']}</td><td>{c['port']}</td><td class='cred'>{c['username']}</td><td class='cred'>{c['password']}</td></tr>\n"
        return f"<table><tr><th>Service</th><th>Port</th><th>Username</th><th>Password</th></tr>{rows}</table>"

    def _vulns_section(self, vulns: list) -> str:
        if not vulns:
            return '<p class="empty">No vulnerabilities detected.</p>'
        cards = ""
        for v in vulns:
            sev = v.get("severity", "unknown")
            sev_class = f"sev-{sev}" if sev in ("critical","high","medium","low","info") else "sev-info"
            cve = f" &mdash; <code>{v['cve_id']}</code>" if v.get("cve_id") else ""
            cards += f"""<div class="vuln-card">
    <h4><span class="severity {sev_class}">{sev}</span> {v['name']}{cve}</h4>
    <div class="vuln-meta">Template: <code>{v.get('template_id','')}</code> | URL: <code>{v.get('matched_url','')}</code></div>
    {f"<p style='margin-top:0.4rem;font-size:0.85rem'>{v['description'][:300]}</p>" if v.get('description') else ''}
</div>"""
        return cards
