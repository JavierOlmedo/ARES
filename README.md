<div align="center">
    <img src="assets/logo.png" width="300px" alt="ARES Logo">
    <h1>Advanced Reconnaissance & Enumeration Scanner</h1>
</div>

## Features

- **Nmap Module** — Quick SYN scan → full port discovery (`-p-`) → deep version/script scan + optional UDP
- **Fuzzing Module** — 3-phase web fuzzing: directories → files → recursive crawl + VHost enumeration (auto-detects gobuster/ffuf/feroxbuster)
- **Brute Force Module** — Patator-based credential attacks on detected services (SSH, FTP, SMB, RDP, MySQL, PostgreSQL...)
- **Nuclei Module** — Automated vulnerability scanning with severity filtering (opt-in)
- **Smart pipeline** — Each module passes context to the next (nmap → fuzzing/brute targets)
- **Real-time output** — Streaming console feedback while scanning (ports, directories, credentials found)
- **Proxy support** — Route fuzzing and brute-force through Burp Suite or any HTTP proxy
- **Triple reporting** — Rich console output + Markdown + HTML dark-themed report
- **Organized workspace** — Projects saved in `~/.ares/<target>/` (like `.nxc`)
- **Local wordlists** — Drop your own lists in `wordlists/` and ARES picks them up automatically

![Architecture](assets/architecture.svg)

## Installation

### Automatic (recommended)

```bash
git clone https://github.com/JavierOlmedo/ARES.git
cd ARES
chmod +x install.sh
sudo bash install.sh
```

`install.sh` checks Python 3.10+, installs Python deps, verifies (or installs via `apt`) all required system tools and wordlists, and creates the `ares` global command.

### Manual

```bash
pip install -r requirements.txt
```

System tools required: `nmap`, `gobuster`/`ffuf`/`feroxbuster`, `patator`, `nuclei`
Wordlists required: `seclists`, `rockyou.txt`
Root privileges recommended (SYN scan)

### Update

```bash
ares --update
```

Pulls the latest version from [GitHub](https://github.com/JavierOlmedo/ARES), updates Python dependencies, and refreshes the `/usr/local/bin/ares` wrapper automatically. No need to `cd` anywhere.

### Verify your setup

```bash
ares --check
```

## Quick Start

```bash
# Basic scan (default: nmap + fuzzing + bruteforce)
ares -t 10.10.11.100 -H target.htb

# Include nuclei vulnerability scan
ares -t 10.10.11.100 -H target.htb -m nmap,fuzzing,bruteforce,nuclei

# Network discovery (find live hosts in a range)
ares -t 10.10.10.0/24 --discover

# Quick scan — nmap + fuzzing only
ares -t 10.10.11.100 -H target.htb -m nmap,fuzzing

# Aggressive — full port range + UDP
ares -t 10.10.11.100 -H target.htb --aggressive --udp

# Route traffic through Burp Suite
ares -t 10.10.11.100 -H target.htb --proxy http://127.0.0.1:8080

# Skip brute-force and nuclei
ares -t 10.10.11.100 --no-brute --no-nuclei

# Custom wordlists and threads
ares -t 10.10.11.100 -H target.htb \
    --wordlist-web /usr/share/seclists/Discovery/Web-Content/big.txt \
    --threads 20
```

## Output Structure

```
~/.ares/target_htb/
├── nmap/
│   ├── quick_tcp.{nmap,xml,gnmap}
│   ├── detailed.{nmap,xml,gnmap}
│   └── udp.{nmap,xml,gnmap}
├── fuzzing/
│   ├── dirs_80.txt
│   ├── files_80.txt
│   └── vhosts_80.txt
├── bruteforce/
│   └── patator_ssh_22.txt
├── nuclei/
│   └── nuclei_http_target_htb.json
├── reports/
│   ├── ares_report.md
│   └── ares_report.html
├── loot/
│   └── credentials.txt
├── exploits/
├── ares_config.json
└── ares_results.json
```

## Modules

| Module       | Phase | Tools Used              | Default | Description                        |
|--------------|-------|-------------------------|---------|------------------------------------|
| `nmap`       | 0     | nmap                    | ✓       | Port scan + service enumeration    |
| `fuzzing`    | 1     | gobuster / ffuf / ferox | ✓       | Directory + file + VHost fuzzing   |
| `bruteforce` | 2     | patator                 | ✓       | Credential attacks on open services|
| `nuclei`     | 2     | nuclei                  | —       | CVE + misconfig scanning (opt-in)  |

## Adding Custom Modules

Create a new file in `modules/` inheriting from `BaseModule`:

```python
from modules.base import BaseModule
from core import logger

class MyModule(BaseModule):
    name = "mymodule"
    description = "Does something cool"
    required_tools = ["sometool"]
    phase = 1

    def run(self, context: dict) -> dict:
        # Access previous results: context["nmap"]["ports"]
        logger.info("Running my custom scan...")
        return {"findings": [...]}
```

Register it in `modules/__init__.py`:
```python
from modules.mymodule import MyModule
MODULE_REGISTRY["mymodule"] = MyModule
```

## CLI Reference

| Flag                     | Description                                              |
|--------------------------|----------------------------------------------------------|
| `-t, --target`           | Target IP or CIDR (required)                             |
| `-H, --hostname`         | Target hostname (e.g. `target.htb`)                     |
| `-o, --output`           | Custom output directory                                  |
| `--quiet`                | Minimal scan (faster, fewer checks)                      |
| `--aggressive`           | Full port range, higher rate limits                      |
| `-m, --modules`          | Comma-separated module list (default: `nmap,fuzzing,bruteforce`) |
| `--no-brute`             | Skip brute-force module                                  |
| `--no-fuzz`              | Skip fuzzing module                                      |
| `--no-nuclei`            | Skip nuclei module                                       |
| `--discover`             | Network host discovery mode (use CIDR as `-t`)           |
| `--udp`                  | Enable UDP scan                                          |
| `--threads`              | Thread count (default: `10`)                             |
| `--top-ports`            | Nmap top ports (default: `1000`)                         |
| `--extensions`           | Fuzz file extensions (default: `php,html,txt,asp,...`)   |
| `--wordlist-web`         | Wordlist for directory fuzzing                           |
| `--wordlist-web-files`   | Wordlist for file fuzzing                                |
| `--wordlist-vhost`       | Wordlist for VHost enumeration                           |
| `--wordlist-users`       | Wordlist for username brute-force                        |
| `--wordlist-passwords`   | Wordlist for password brute-force                        |
| `--proxy`                | HTTP proxy for fuzzing/brute-force (e.g. `http://127.0.0.1:8080`) |
| `--report`               | Report formats: `console,markdown,html` (default: all)  |
| `--nuclei-severity`      | Nuclei severity filter (default: `low,medium,high,critical`) |
| `--check`                | Verify dependencies and exit                             |
| `--update`               | Update to latest version from GitHub                     |
| `--version`              | Show current version                                     |

## Custom Wordlists

ARES ships with its own wordlists in `wordlists/` that are used by default. Files are auto-detected by prefix — no configuration needed:

```
wordlists/
├── users/
│   └── hackpuntes-usernames-*.txt      ← username brute-force
├── passwords/
│   └── hackpuntes-passwords-*.txt      ← password brute-force
├── web/
│   ├── raft-large-directories-*.txt    ← directory fuzzing (phase 1)
│   └── raft-large-files-*.txt          ← file fuzzing (phase 2)
└── vhost/
    └── hackpuntes-subdomains-*.txt     ← VHost enumeration
```

If no local list matches, ARES falls back to system wordlists (`seclists`, `rockyou.txt`).
You can also override any wordlist at runtime with the corresponding CLI flag.

## License

MIT — Use responsibly. For authorized testing only.

Made with ❤️ in Spain
