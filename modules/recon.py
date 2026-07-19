#!/usr/bin/env python3
"""
SENTINELA - Recon Module v2
Subdomain enumeration, DNS, port scanning — chains Kali tools.
"""

import socket
import concurrent.futures
import time
import re
import subprocess
import json
import tempfile
import os
from pathlib import Path

try:
    import dns.resolver
    import dns.zone
    import dns.query
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from modules.utils import log, log_finding, progress, make_finding, Colors
from modules.wordlists import WordlistManager
from modules.tool_integration import (ToolRunner, NmapRunner, GobusterRunner,
                                       DNSReconRunner, TheHarvesterRunner,
                                       MasscanRunner, SNMPRunner)

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]


class ReconModule:
    def __init__(self, config: dict):
        self.config = config
        self.target = config["target"]
        self.verbose = config.get("verbose", False)
        self.threads = config.get("threads", 20)
        self.timeout = config.get("timeout", 10)
        self.rate_limit = config.get("rate_limit", 0.1)
        self.findings = []
        self.is_ip = self._is_ip(self.target)

        self.runner = ToolRunner(config)
        self.wl = WordlistManager(verbose=self.verbose)
        self.nmap_r = NmapRunner(self.runner)
        self.gobuster = GobusterRunner(self.runner)
        self.dnsrecon_r = DNSReconRunner(self.runner)
        self.harvester_r = TheHarvesterRunner(self.runner)
        self.masscan_r = MasscanRunner(self.runner)
        self.snmp_r = SNMPRunner(self.runner)

    def run(self) -> dict:
        results = {
            "target": self.target,
            "is_ip": self.is_ip,
            "subdomains": [],
            "dns_records": {},
            "zone_transfer": {},
            "osint": {},
            "osint_passive": {},
            "open_ports": {},
            "udp_ports": {},
            "whois": {},
            "historical_urls": [],
            "findings": [],
        }

        if not self.is_ip:
            log("  → DNS record enumeration...", Colors.CYAN)
            results["dns_records"] = self._dns_enum(self.target)
            count = sum(len(v) for v in results["dns_records"].values())
            log(f"    {count} DNS records retrieved", Colors.GREEN)

            log("  → Zone transfer attempt (AXFR)...", Colors.CYAN)
            results["zone_transfer"] = self._zone_transfer(self.target)

            if not self.config.get("no_subdomains"):
                log("  → Subdomain enumeration...", Colors.CYAN)
                results["subdomains"] = self._subdomain_enum_all()
                log(f"    {len(results['subdomains'])} unique subdomains found", Colors.GREEN)

                if results["subdomains"] and self.runner.available("httpx"):
                    log("    ↳ Httpx (probe de hosts vivos + tech)...", Colors.DIM)
                    self._enriquecer_com_httpx(results["subdomains"])

            # waybackurls/gau — 100% passivo (só consulta arquivos históricos de
            # terceiros, nenhum pacote vai ao alvo), roda inclusive em --mode stealth
            if self.runner.available("waybackurls") or self.runner.available("gau"):
                log("  → URLs históricas (Wayback/Common Crawl, passivo)...", Colors.CYAN)
                results["historical_urls"] = self._urls_historicas()
                log(f"    {len(results['historical_urls'])} URLs históricas encontradas", Colors.GREEN)

            log("  → OSINT harvest...", Colors.CYAN)
            results["osint"] = self._osint_harvest()

            if self.config.get("shodan_key") or self.config.get("censys_key"):
                log("  → OSINT passivo (Shodan/Censys)...", Colors.CYAN)
                results["osint_passive"] = self._osint_passive()

            if self.runner.available("whois"):
                log("  → WHOIS lookup...", Colors.CYAN)
                results["whois"] = self._whois_lookup()

        log("  → Port scanning...", Colors.CYAN)
        scan_targets = self._build_scan_targets(results)
        results["open_ports"] = self._port_scan_all(scan_targets)
        total = sum(len(p) for p in results["open_ports"].values())
        log(f"    {total} open TCP ports across {len(results['open_ports'])} hosts", Colors.GREEN)

        if self.config.get("udp_scan") and self.runner.available("nmap"):
            log("  → UDP scan (common ports)...", Colors.CYAN)
            for t in scan_targets[:3]:
                r = self.nmap_r.udp_scan(t)
                results["udp_ports"].update(r.get("hosts", {}))

        results["findings"] = self._analyze_findings(results)
        return results

    # ── DNS ───────────────────────────────────────────────────────────────────

    def _dns_enum(self, domain: str) -> dict:
        if self.runner.available("dnsrecon"):
            r = self.dnsrecon_r.full_recon(domain, timeout=90)
            parsed = {}
            for rec in r.get("records", []):
                rtype = rec.get("type", "?")
                val = rec.get("address", rec.get("target", rec.get("strings", "")))
                parsed.setdefault(rtype, []).append(str(val))
            if parsed:
                return parsed

        if HAS_DNSPYTHON:
            return self._dnspython_enum(domain)

        return self._dig_fallback(domain)

    def _dnspython_enum(self, domain: str) -> dict:
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        for rtype in DNS_RECORD_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        return records

    def _dig_fallback(self, domain: str) -> dict:
        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                r = subprocess.run(["dig", "+short", f"-t{rtype}", domain],
                                   capture_output=True, text=True, timeout=10)
                if r.stdout.strip():
                    records[rtype] = [l.strip() for l in r.stdout.strip().split("\n") if l.strip()]
            except Exception:
                pass
        return records

    def _zone_transfer(self, domain: str) -> dict:
        result = {"attempted": [], "success": False, "records": []}
        if not HAS_DNSPYTHON:
            return result
        try:
            ns_records = dns.resolver.resolve(domain, "NS")
            nameservers = [str(ns).rstrip(".") for ns in ns_records]
        except Exception:
            return result
        for ns in nameservers:
            try:
                ns_ip = socket.gethostbyname(ns)
                result["attempted"].append(ns)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=self.timeout))
                result["success"] = True
                result["records"] = [str(n) for n in zone.nodes.keys()]
                self.findings.append(make_finding(
                    "CRITICAL", "DNS",
                    f"AXFR zone transfer succeeded via {ns}",
                    detail=f"{len(result['records'])} records exposed",
                    remediation="Restrict AXFR to authorised secondary nameservers only."))
                log_finding("CRITICAL", f"Zone transfer via {ns}", f"{len(result['records'])} records")
                break
            except Exception:
                pass
        return result

    # ── SUBDOMAINS ────────────────────────────────────────────────────────────

    def _subdomain_enum_all(self) -> list:
        all_subs = {}

        # crt.sh (certificate transparency) — 100% passivo, nenhum pacote vai ao
        # alvo, então roda sempre, inclusive em --mode stealth
        log("    ↳ crt.sh (certificate transparency, passivo)...", Colors.DIM)
        for s in self._crtsh_lookup(self.target):
            all_subs[s["subdomain"]] = s

        if self.runner.available("sublist3r"):
            log("    ↳ Sublist3r (passive OSINT)...", Colors.DIM)
            for s in self._run_sublist3r():
                all_subs[s["subdomain"]] = s

        if self.runner.available("amass"):
            log("    ↳ Amass (passive)...", Colors.DIM)
            for s in self._run_amass():
                all_subs[s["subdomain"]] = s

        if self.runner.available("subfinder"):
            log("    ↳ Subfinder (passive)...", Colors.DIM)
            for s in self._run_subfinder():
                all_subs[s["subdomain"]] = s

        if self.runner.available("assetfinder"):
            log("    ↳ Assetfinder (passive)...", Colors.DIM)
            for s in self._run_assetfinder():
                all_subs[s["subdomain"]] = s

        wl_path = self.wl.get("subdomains", "medium")
        if wl_path and self.runner.available("gobuster"):
            log(f"    ↳ Gobuster DNS ({wl_path.split('/')[-1]})...", Colors.DIM)
            for s in self.gobuster.dns_enum(self.target, wl_path, threads=self.threads):
                all_subs[s["subdomain"]] = {"subdomain": s["subdomain"], "ips": [], "source": "gobuster"}

        if not all_subs:
            log("    ↳ Python DNS brute-force...", Colors.DIM)
            for s in self._python_dns_brute():
                all_subs[s["subdomain"]] = s

        # Resolve IPs
        result = list(all_subs.values())
        for sub in result:
            if not sub.get("ips"):
                try:
                    sub["ips"] = [socket.gethostbyname(sub["subdomain"])]
                except Exception:
                    sub["ips"] = []
        return result

    def _run_sublist3r(self) -> list:
        f = tempfile.mktemp(suffix=".txt")
        self.runner.run(["sublist3r", "-d", self.target, "-o", f, "-n"], timeout=120)
        subs = []
        try:
            with open(f) as fh:
                for line in fh:
                    s = line.strip()
                    if s and "." in s:
                        subs.append({"subdomain": s, "ips": [], "source": "sublist3r"})
        except Exception:
            pass
        try: os.unlink(f)
        except Exception: pass
        return subs

    def _run_amass(self) -> list:
        f = tempfile.mktemp(suffix=".txt")
        self.runner.run(["amass", "enum", "-passive", "-d", self.target, "-o", f], timeout=180)
        subs = []
        try:
            with open(f) as fh:
                for line in fh:
                    s = line.strip()
                    if s:
                        subs.append({"subdomain": s, "ips": [], "source": "amass"})
        except Exception:
            pass
        try: os.unlink(f)
        except Exception: pass
        return subs

    def _run_subfinder(self) -> list:
        f = tempfile.mktemp(suffix=".txt")
        self.runner.run(["subfinder", "-d", self.target, "-o", f, "-silent"], timeout=120)
        subs = []
        try:
            with open(f) as fh:
                for line in fh:
                    s = line.strip()
                    if s and "." in s:
                        subs.append({"subdomain": s, "ips": [], "source": "subfinder"})
        except Exception:
            pass
        try: os.unlink(f)
        except Exception: pass
        return subs

    def _run_assetfinder(self) -> list:
        rc, stdout, _ = self.runner.run(["assetfinder", "--subs-only", self.target], timeout=90)
        subs = []
        for line in (stdout or "").splitlines():
            s = line.strip()
            if s and s.endswith(self.target):
                subs.append({"subdomain": s, "ips": [], "source": "assetfinder"})
        return subs

    def _enriquecer_com_httpx(self, subdomains: list):
        """Roda httpx sobre a lista de subdomínios pra descobrir quais estão
        vivos e enriquecer cada um com status_code/title/tech. Modifica os
        dicts de `subdomains` in-place."""
        f_in = tempfile.mktemp(suffix=".txt")
        f_out = tempfile.mktemp(suffix=".json")
        binario = self.runner.which("httpx") or "httpx"
        try:
            with open(f_in, "w") as fh:
                fh.write("\n".join(s["subdomain"] for s in subdomains))
            self.runner.run(
                [binario, "-l", f_in, "-json", "-o", f_out, "-status-code",
                 "-title", "-tech-detect", "-silent"],
                timeout=120,
            )
            vivos = {}
            with open(f_out) as fh:
                for linha in fh:
                    linha = linha.strip()
                    if not linha:
                        continue
                    try:
                        item = json.loads(linha)
                    except Exception:
                        continue
                    host = item.get("input", item.get("host", ""))
                    if host:
                        vivos[host] = item
            for sub in subdomains:
                info = vivos.get(sub["subdomain"])
                if info:
                    sub["vivo"]        = True
                    sub["status_code"] = info.get("status_code") or info.get("status-code")
                    sub["title"]       = info.get("title", "")
                    sub["tech"]        = info.get("tech", [])
                else:
                    sub["vivo"] = False
        except Exception:
            pass
        finally:
            for f in (f_in, f_out):
                try: os.unlink(f)
                except Exception: pass

    def _urls_historicas(self) -> list:
        urls = set()
        if self.runner.available("waybackurls"):
            try:
                rc, stdout, _ = self.runner.run(["waybackurls", self.target], timeout=60)
                for l in (stdout or "").splitlines():
                    if l.strip():
                        urls.add(l.strip())
            except Exception:
                pass
        if self.runner.available("gau"):
            try:
                rc, stdout, _ = self.runner.run(["gau", "--subs", self.target], timeout=60)
                for l in (stdout or "").splitlines():
                    if l.strip():
                        urls.add(l.strip())
            except Exception:
                pass
        return sorted(urls)[:2000]  # limite pra não estourar memória/relatório em domínio muito antigo

    def _python_dns_brute(self) -> list:
        wl_data, source = self.wl.get_or_builtin("subdomains", "medium")
        wordlist = []
        if source == "file":
            try:
                with open(wl_data) as fh:
                    wordlist = [l.strip() for l in fh if l.strip()][:5000]
            except Exception:
                wordlist = self.wl.get_builtin_list("subdomains")
        else:
            wordlist = wl_data

        results = []

        def check(word):
            fqdn = f"{word}.{self.target}"
            try:
                if HAS_DNSPYTHON:
                    res = dns.resolver.Resolver()
                    res.timeout = 2; res.lifetime = 2
                    ans = res.resolve(fqdn, "A")
                    ips = [str(r) for r in ans]
                else:
                    ips = [socket.gethostbyname(fqdn)]
                return {"subdomain": fqdn, "ips": ips, "source": "brute_force"}
            except Exception:
                return None

        total = len(wordlist)
        done = [0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for r in ex.map(check, wordlist):
                done[0] += 1
                if done[0] % 200 == 0:
                    progress("    DNS brute", done[0], total)
                if r:
                    results.append(r)
        progress("    DNS brute", total, total)
        return results

    def _crtsh_lookup(self, domain: str) -> list:
        """Consulta crt.sh (certificate transparency logs) por subdomínios.
        100% passivo — nenhum pacote é enviado ao alvo, só ao crt.sh."""
        if not HAS_REQUESTS:
            return []
        subs = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=max(self.timeout, 15),
            )
            if resp.status_code != 200:
                return []
            entries = resp.json()
        except Exception:
            return []

        vistos = set()
        for entry in entries:
            nome = entry.get("name_value", "")
            for linha in nome.split("\n"):
                sub = linha.strip().lower().lstrip("*.")
                if not sub or not sub.endswith(domain) or sub in vistos:
                    continue
                vistos.add(sub)
                subs.append({"subdomain": sub, "ips": [], "source": "crt.sh"})
        return subs

    def _shodan_lookup(self, target: str) -> dict:
        """Consulta o Shodan por infraestrutura/portas/serviços já indexados —
        opcional, só roda se SHODAN_API_KEY/--shodan-key estiver configurado.
        Nenhum pacote é enviado diretamente ao alvo; os dados vêm do índice do Shodan."""
        api_key = self.config.get("shodan_key")
        if not api_key or not HAS_REQUESTS:
            return {}
        resultado = {"host": None, "ports": [], "servicos": [], "erro": None}
        try:
            ip = self.target if self.is_ip else socket.gethostbyname(target)
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key}, timeout=15,
            )
            if resp.status_code != 200:
                resultado["erro"] = f"HTTP {resp.status_code}"
                return resultado
            data = resp.json()
            resultado["host"] = ip
            resultado["ports"] = data.get("ports", [])
            for item in data.get("data", []):
                resultado["servicos"].append({
                    "porta":    item.get("port"),
                    "produto":  item.get("product", ""),
                    "versao":   item.get("version", ""),
                    "banner":   (item.get("data") or "")[:200],
                })
        except Exception as e:
            resultado["erro"] = str(e)
        return resultado

    def _censys_lookup(self, target: str) -> dict:
        """Consulta o Censys por infraestrutura já indexada — opcional, só roda
        se CENSYS_API_ID + CENSYS_API_SECRET/--censys-key/--censys-secret estiverem
        configurados. Nenhum pacote é enviado diretamente ao alvo."""
        api_id = self.config.get("censys_key")
        api_secret = self.config.get("censys_secret")
        if not api_id or not api_secret or not HAS_REQUESTS:
            return {}
        resultado = {"host": None, "servicos": [], "erro": None}
        try:
            ip = self.target if self.is_ip else socket.gethostbyname(target)
            resp = requests.get(
                f"https://search.censys.io/api/v2/hosts/{ip}",
                auth=(api_id, api_secret), timeout=15,
            )
            if resp.status_code != 200:
                resultado["erro"] = f"HTTP {resp.status_code}"
                return resultado
            data = resp.json().get("result", {})
            resultado["host"] = ip
            for svc in data.get("services", []):
                resultado["servicos"].append({
                    "porta":     svc.get("port"),
                    "protocolo": svc.get("service_name", ""),
                    "software":  ", ".join(s.get("product","") for s in svc.get("software", []) if s.get("product")),
                })
        except Exception as e:
            resultado["erro"] = str(e)
        return resultado

    def _osint_passive(self) -> dict:
        """Agrega os resultados de OSINT passivo opcional (Shodan/Censys)."""
        osint = {}
        shodan_r = self._shodan_lookup(self.target)
        if shodan_r:
            osint["shodan"] = shodan_r
            if shodan_r.get("servicos"):
                log(f"    ↳ Shodan: {len(shodan_r['servicos'])} serviço(s) indexado(s)", Colors.GREEN)
        censys_r = self._censys_lookup(self.target)
        if censys_r:
            osint["censys"] = censys_r
            if censys_r.get("servicos"):
                log(f"    ↳ Censys: {len(censys_r['servicos'])} serviço(s) indexado(s)", Colors.GREEN)
        return osint

    def _osint_harvest(self) -> dict:
        if self.runner.available("theHarvester"):
            return self.harvester_r.harvest(self.target, timeout=90)
        return {"emails": [], "hosts": [], "note": "theHarvester not installed"}

    def _whois_lookup(self) -> dict:
        rc, stdout, _ = self.runner.run(["whois", self.target], timeout=30)
        data = {}
        for line in stdout.splitlines():
            if ":" in line and not line.startswith("%"):
                parts = line.split(":", 1)
                k = parts[0].strip().lower()
                v = parts[1].strip()
                if v and k not in data:
                    data[k] = v
        return data

    # ── PORT SCANNING ─────────────────────────────────────────────────────────

    def _build_scan_targets(self, results: dict) -> list:
        targets = set()
        if self.is_ip:
            targets.add(self.target)
        else:
            try:
                targets.add(socket.gethostbyname(self.target))
            except Exception:
                targets.add(self.target)
            for sub in results.get("subdomains", []):
                for ip in sub.get("ips", []):
                    targets.add(ip)
        return list(targets)

    def _port_scan_all(self, targets: list) -> dict:
        ports = self.config.get("ports",
            "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
            "1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9090,9200,27017")
        scan_type = self.config.get("port_scan_type", "connect")
        all_results = {}

        if self.runner.available("nmap"):
            for t in targets[:10]:
                log(f"    ↳ nmap {t}...", Colors.DIM)
                result = self.nmap_r.full_scan(t, ports, scan_type)
                if result.get("hosts"):
                    all_results.update(result["hosts"])
                    for host, host_ports in result["hosts"].items():
                        self._flag_dangerous_ports(host, host_ports)
                else:
                    log(f"    ↳ nmap fallback: socket scan...", Colors.DIM)
                    all_results.update(self._socket_scan([t], ports))
        else:
            log("    ↳ nmap not found — socket scan fallback", Colors.YELLOW)
            all_results = self._socket_scan(targets[:10], ports)

        return all_results

    def _socket_scan(self, targets: list, ports_str: str) -> dict:
        port_list = self._parse_ports(ports_str)
        results = {}
        for target in targets:
            open_ports = {}
            def check(port):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    if s.connect_ex((target, port)) == 0:
                        s.close()
                        return port, {"state": "open", "protocol": "tcp",
                                      "service": self._guess_service(port),
                                      "product": "", "version": "",
                                      "banner": self._grab_banner(target, port)}
                    s.close()
                except Exception:
                    pass
                return port, None

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                for port, info in ex.map(check, port_list):
                    if info:
                        open_ports[port] = info
            results[target] = open_ports
        return results

    def _flag_dangerous_ports(self, host: str, ports: dict):
        risky = {
            23:    ("HIGH",     "Telnet exposed",        "Plaintext credentials over network."),
            21:    ("MEDIUM",   "FTP exposed",            "Test for anonymous access."),
            445:   ("HIGH",     "SMB exposed",            "EternalBlue / SMB relay attack surface."),
            3389:  ("HIGH",     "RDP exposed",            "BlueKeep / brute-force risk."),
            6379:  ("CRITICAL", "Redis exposed",          "No auth by default → RCE possible."),
            9200:  ("HIGH",     "Elasticsearch exposed",  "Unauthenticated → data exfiltration."),
            27017: ("HIGH",     "MongoDB exposed",        "Often unauthenticated in default config."),
            5432:  ("MEDIUM",   "PostgreSQL exposed",     "Test default credentials."),
            3306:  ("MEDIUM",   "MySQL exposed",          "Test default/empty root credentials."),
            5900:  ("HIGH",     "VNC exposed",            "Remote desktop, commonly weak passwords."),
            1521:  ("MEDIUM",   "Oracle DB exposed",      "Test default credentials."),
        }
        for port in ports:
            p = int(port) if not isinstance(port, int) else port
            if p in risky:
                sev, title, detail = risky[p]
                self.findings.append(make_finding(sev, "Port",
                    f"{title} on {host}:{p}", detail=detail))
                log_finding(sev, f"{title} — {host}:{p}", detail)

    def _analyze_findings(self, results: dict) -> list:
        findings = self.findings.copy()
        if len(results.get("subdomains", [])) > 20:
            findings.append(make_finding("INFO", "Recon",
                f"Large attack surface: {len(results['subdomains'])} subdomains found",
                remediation="Audit all subdomains for stale services."))
        txt = results.get("dns_records", {}).get("TXT", [])
        if not any("v=spf1" in t for t in txt):
            findings.append(make_finding("MEDIUM", "DNS", "SPF record missing",
                remediation="Add SPF TXT record to prevent email spoofing."))
        if not any("DMARC1" in t for t in txt):
            findings.append(make_finding("MEDIUM", "DNS", "DMARC record missing",
                remediation="Add DMARC policy record."))
        return findings

    def _grab_banner(self, host: str, port: int) -> str:
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((host, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(512).decode("utf-8", errors="ignore").strip()
            s.close()
            return banner[:200]
        except Exception:
            return ""

    def _parse_ports(self, port_str: str) -> list:
        ports = []
        for part in str(port_str).split(","):
            part = part.strip()
            if "-" in part:
                try:
                    a, b = part.split("-", 1)
                    ports.extend(range(int(a), int(b) + 1))
                except Exception:
                    pass
            else:
                try:
                    ports.append(int(part))
                except Exception:
                    pass
        return ports

    def _guess_service(self, port: int) -> str:
        common = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",
                  110:"pop3",143:"imap",443:"https",445:"smb",3306:"mysql",
                  3389:"rdp",5432:"postgresql",6379:"redis",8080:"http-alt",
                  8443:"https-alt",9200:"elasticsearch",27017:"mongodb",5900:"vnc"}
        return common.get(port, "unknown")

    def _is_ip(self, value: str) -> bool:
        try:
            socket.inet_aton(value.split("/")[0])
            return True
        except socket.error:
            return False
