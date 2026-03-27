"""
ARES - Nmap Module
Port scanning, service enumeration, and script scanning.
"""
import os
import re
import xml.etree.ElementTree as ET
from modules.base import BaseModule
from core.utils import run_command
from core import logger


class NmapModule(BaseModule):
    name = "nmap"
    description = "Port scanning, service detection & NSE scripts"
    required_tools = ["nmap"]
    phase = 0

    def run(self, context: dict) -> dict:
        results = {
            "ports": [],
            "tcp_ports_csv": "",
            "services": {},
            "web_ports": [],
            "os_guess": "",
            "raw_files": [],
        }

        # ── Phase 1: Quick TCP SYN scan (top ports) ──
        logger.info("Phase 1/3: Quick TCP SYN scan...")
        tcp_ports = self._quick_tcp_scan()
        if not tcp_ports:
            logger.warning("No open TCP ports found on quick scan, trying full scan...")
            tcp_ports = self._full_tcp_scan()

        if not tcp_ports:
            logger.error("No open ports discovered. Target may be down or filtered.")
            return results

        ports_csv = ",".join(str(p) for p in tcp_ports)
        results["tcp_ports_csv"] = ports_csv
        logger.success(f"Open TCP ports: {ports_csv}")

        # ── Phase 2: Deep service + version scan on discovered ports ──
        logger.info("Phase 2/3: Service version detection & NSE scripts...")
        detailed = self._detailed_scan(ports_csv)
        results["ports"] = detailed["ports"]
        results["services"] = detailed["services"]
        results["os_guess"] = detailed.get("os_guess", "")
        results["raw_files"].extend(detailed.get("raw_files", []))

        # Identify web ports
        for p in results["ports"]:
            svc = p.get("service", "").lower()
            port = p.get("port", 0)
            if any(w in svc for w in ["http", "ssl", "https", "web"]) or port in (80, 443, 8080, 8443):
                scheme = "https" if (port == 443 or "ssl" in svc or "https" in svc) else "http"
                results["web_ports"].append({"port": port, "scheme": scheme})

        if results["web_ports"]:
            web_list = ', '.join(f"{w['scheme']}://{self.config.target_ip}:{w['port']}" for w in results["web_ports"])
            logger.success(f"Web services: {web_list}")

        logger.print_ports_table(results["ports"])

        # ── Phase 3: Optional UDP scan ──
        if self.config.run_udp:
            logger.info("Phase 3/3: UDP scan (top 50 ports)...")
            udp_results = self._udp_scan()
            results["udp_ports"] = udp_results
            if udp_results:
                logger.success(f"Open UDP ports: {', '.join(str(p['port']) for p in udp_results)}")
        else:
            logger.info("Phase 3/3: UDP scan skipped (use --udp to enable)")

        return results

    def _quick_tcp_scan(self) -> list:
        """Fast SYN scan across all 65535 TCP ports."""
        outfile = os.path.join(self.output_path, "quick_tcp")
        rate = "10000" if self.config.intensity == "aggressive" else "5000"
        cmd_str = f"nmap -sS --min-rate {rate} -Pn -p- -oA {outfile} {self.config.target_ip}"
        run_command(cmd_str, timeout=600)
        return self._extract_open_ports(f"{outfile}.xml")

    def _full_tcp_scan(self) -> list:
        """Full 65535 port scan as fallback."""
        outfile = os.path.join(self.output_path, "full_tcp")
        cmd = f"nmap -sS --min-rate 3000 -Pn -p- -oA {outfile} {self.config.target_ip}"
        run_command(cmd, timeout=600)
        return self._extract_open_ports(f"{outfile}.xml")

    def _detailed_scan(self, ports_csv: str) -> dict:
        """Version detection + default scripts on discovered ports."""
        outfile = os.path.join(self.output_path, "detailed")
        cmd = f"nmap -sCV -Pn -p {ports_csv} -oA {outfile} {self.config.target_ip}"
        if self.config.hostname:
            cmd += f" --script-args 'http.host={self.config.hostname}'"

        run_command(cmd, timeout=600)
        return self._parse_detailed_xml(f"{outfile}.xml", [f"{outfile}.nmap", f"{outfile}.xml", f"{outfile}.gnmap"])

    def _udp_scan(self) -> list:
        """Top 50 UDP port scan."""
        outfile = os.path.join(self.output_path, "udp")
        cmd = f"nmap -sU --top-ports 50 --min-rate 2000 -Pn -oA {outfile} {self.config.target_ip}"
        run_command(cmd, timeout=300)
        return self._parse_udp(f"{outfile}.xml")

    def _extract_open_ports(self, xml_file: str) -> list:
        """Extract open port numbers from nmap XML output."""
        ports = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            for port_elem in root.iter("port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    ports.append(int(port_elem.get("portid")))
        except (FileNotFoundError, ET.ParseError) as e:
            logger.warning(f"Could not parse {xml_file}: {e}")
        return sorted(ports)

    def _parse_detailed_xml(self, xml_file: str, raw_files: list) -> dict:
        """Parse detailed nmap XML for service info."""
        result = {"ports": [], "services": {}, "os_guess": "", "raw_files": raw_files}
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()

            for port_elem in root.iter("port"):
                state_elem = port_elem.find("state")
                service_elem = port_elem.find("service")

                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_num = int(port_elem.get("portid"))
                protocol = port_elem.get("protocol", "tcp")
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""
                extra = service_elem.get("extrainfo", "") if service_elem is not None else ""

                version_full = " ".join(filter(None, [product, version, extra])).strip()

                # Collect NSE script output
                scripts = {}
                for script_elem in port_elem.iter("script"):
                    scripts[script_elem.get("id")] = script_elem.get("output", "")

                port_data = {
                    "port": port_num,
                    "protocol": protocol,
                    "state": "open",
                    "service": service_name,
                    "version": version_full,
                    "scripts": scripts,
                }
                result["ports"].append(port_data)
                result["services"][port_num] = service_name

            # OS detection
            for os_match in root.iter("osmatch"):
                result["os_guess"] = f"{os_match.get('name', '')} ({os_match.get('accuracy', '')}%)"
                break

        except (FileNotFoundError, ET.ParseError) as e:
            logger.warning(f"Could not parse detailed XML: {e}")

        return result

    def _parse_udp(self, xml_file: str) -> list:
        """Parse UDP scan results."""
        ports = []
        try:
            tree = ET.parse(xml_file)
            for port_elem in tree.getroot().iter("port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") in ("open", "open|filtered"):
                    service_elem = port_elem.find("service")
                    ports.append({
                        "port": int(port_elem.get("portid")),
                        "state": state.get("state"),
                        "service": service_elem.get("name", "unknown") if service_elem is not None else "unknown",
                    })
        except (FileNotFoundError, ET.ParseError):
            pass
        return ports
