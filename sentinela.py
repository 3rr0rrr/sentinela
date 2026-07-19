#!/usr/bin/env python3
"""
SENTINELA v1.0.0 — Framework de Pentest de Nível Empresarial para Kali Linux
Criado por github.com/3rr0rrr — baseado em GhostScan (MIT License)

NOVIDADES DA SENTINELA (além do que já vinha no GhostScan original):
  - Enforcement rígido de escopo (bloqueia alvos fora de escopo + proteção SSRF)
  - Executor paralelo seguro (timeout/retry/isolamento de falha por ferramenta)
  - Motor de inteligência (correlação + ranking inteligente de alvos)
  - Workflow adaptativo (próximos passos dinâmicos com base nos achados)
  - Motor de bypass de WAF (evasão por perfil — CloudFlare, Akamai, F5 etc.)
  - Navegador headless (Playwright — DOM XSS, endpoints ocultos, análise de storage)
  - Recon paralelo (nmap + amass + sublist3r + theHarvester simultaneamente)
  - Filtro --min-severity (reduz ruído, mostra só o que importa)
  - 6 plugins novos: JWT, CORS, GraphQL introspection, subdomain takeover,
    secrets/entropy scanner, security headers avançado
  - Score CVSS v3.1 por finding, além do score próprio da ferramenta
  - Sumário executivo nos relatórios (linguagem não-técnica pra cliente/gestor)
  - Checklist automático de endpoints testados/não testados
  - Mapeamento de compliance PCI-DSS v4.0 / LGPD por finding
  - Hash SHA-256 de cadeia de custódia em cada relatório gerado
  - Recon passivo via crt.sh (sempre) + Shodan/Censys (opcional, com API key)
  - Modo --mode ghost — jitter aleatório, rotação de User-Agent, proxy rotation
  - Diagrama de kill chain (cadeia de ataque) no relatório HTML

USO AUTORIZADO APENAS — Lei 12.737/2012 (BR), 18 U.S.C § 1030 (EUA) e
Computer Misuse Act (UK) se aplicam. Obtenha autorização por escrito antes de testar.
"""

import argparse
import sys
import os
import json
import time
import signal
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.utils import banner, log, Colors, SEVERITY_COLORS
from modules.boot_animation import play_intro
from modules.wordlists import WordlistManager
from modules.tool_integration import ToolRunner
from modules.scope import ScopeEnforcer, ScopeViolation
from modules.executor import SafeExecutor
from modules.intelligence import IntelligenceEngine
from modules.workflow import WorkflowEngine


def parse_args():
    parser = argparse.ArgumentParser(
        prog="sentinela",
        description="SENTINELA v1.0.0 — Framework de Pentest de Nível Empresarial | by github.com/3rr0rrr",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
═══════════════════════════════════════════════════
  EXEMPLOS DE USO
═══════════════════════════════════════════════════
  Scan completo, relatório em PDF, modo agressivo:
    sentinela -t exemplo.com --all --intensity aggressive --report pdf

  Só recon paralelo (rápido, ferramentas simultâneas):
    sentinela -t exemplo.com --recon --parallel

  Scan web via Burp Suite + bypass de WAF:
    sentinela -t exemplo.com --web --proxy http://127.0.0.1:8080 --waf-bypass

  Teste de injeção com enforcement de escopo:
    sentinela -t exemplo.com --vuln --sqli --xss --scope exemplo.com --strict-scope

  Scan com navegador headless (DOM XSS):
    sentinela -t exemplo.com --web --browser

  Mostrar só findings HIGH+:
    sentinela -t exemplo.com --all --min-severity high

  Roteamento via Tor (requer serviço tor rodando):
    sentinela -t exemplo.com --all --tor

  Modo furtivo red-team (jitter + rotação de UA + proxies):
    sentinela -t exemplo.com --web --mode ghost --proxy-list proxies.txt

  Mostrar ferramentas instaladas:
    sentinela -t exemplo.com --tools

  Guia completo de workflow de pentest:
    sentinela -t exemplo.com --workflow

  Retomar de uma sessão salva:
    sentinela -t exemplo.com --all --resume ./sentinela_results/session_*.json

═══════════════════════════════════════════════════
  AVISO LEGAL: uso autorizado apenas.
═══════════════════════════════════════════════════
""",
    )

    # ── ALVO ─────────────────────────────────────────────────────────────────
    # Não usa required=True de propósito: --version precisa funcionar sem alvo
    # (bug corrigido em relação ao GhostScan original). A obrigatoriedade é
    # validada manualmente em main() para os demais modos.
    parser.add_argument("-t", "--target", default=None,
                        help="Domínio, IP ou CIDR (ex: 192.168.1.0/24) — obrigatório exceto com --version")

    # ── PERFIL / MODO ────────────────────────────────────────────────────────
    parser.add_argument("--mode",
        choices=["stealth", "standard", "aggressive", "ghost"],
        default=None,
        help=(
            "Perfil de scan — atalho para várias flags:\n"
            "  stealth:    Só recon passivo. Sem brute-force, sem probing ativo. Ritmo lento.\n"
            "  standard:   Scan balanceado. Todos os módulos. Ritmo normal. (padrão)\n"
            "  aggressive: Tudo habilitado. Threads no máximo. Wordlists grandes. Todas as injeções.\n"
            "  ghost:      Modo furtivo red-team — jitter aleatório entre requisições, rotação\n"
            "              de User-Agent a cada request e suporte a --proxy-list rotativo."
        ))

    # ── MÓDULOS ──────────────────────────────────────────────────────────────
    mods = parser.add_argument_group("Seleção de Módulos")
    mods.add_argument("--all",      action="store_true", help="Roda todos os módulos")
    mods.add_argument("--recon",    action="store_true", help="DNS, subdomínios, OSINT, port scan")
    mods.add_argument("--web",      action="store_true", help="Crawl web, dir brute, nikto, nuclei, wpscan")
    mods.add_argument("--vuln",     action="store_true", help="Headers, XSS, SQLi, correlação de CVE")
    mods.add_argument("--workflow", action="store_true", help="Imprime o workflow adaptativo de pentest e sai")

    # ── OPÇÕES DE ATAQUE ─────────────────────────────────────────────────────
    atk = parser.add_argument_group("Opções de Ataque")
    atk.add_argument("--xss",   action="store_true", help="Probing de XSS (payloads do SecLists)")
    atk.add_argument("--sqli",  action="store_true", help="SQLi via sqlmap")
    atk.add_argument("--brute", action="store_true", help="Brute-force online via Hydra (use com autorização explícita)")
    atk.add_argument("--udp",   action="store_true", help="Port scan UDP")
    atk.add_argument("--fast",  action="store_true", help="Descoberta full-range via masscan primeiro")
    atk.add_argument("--browser", action="store_true",
                     help="Navegador headless (Playwright) para DOM XSS + endpoints ocultos")
    atk.add_argument("--stealth",  action="store_true",
                     help="Modo furtivo — só recon passivo, sem brute-force, sem fuzzing, ritmo baixo")
    atk.add_argument("--no-subdomains", action="store_true", help="Pula enumeração de subdomínios")
    atk.add_argument("--no-cve",        action="store_true", help="Pula correlação de CVE")
    atk.add_argument("--plugins",  action="store_true", default=True,
                     help="Roda os plugins da pasta plugins/ (padrão: ligado)")
    atk.add_argument("--no-plugins", action="store_true",
                     help="Desliga o sistema de plugins")
    atk.add_argument("--screenshots", action="store_true",
                     help="Salva screenshots das páginas encontradas (requer --browser)")

    # ── VETORES DE EXPLORAÇÃO AVANÇADOS ─────────────────────────────────────
    adv = parser.add_argument_group("Vetores de Exploração Avançados")
    adv.add_argument("--race-concurrency", type=int, default=5,
                     help="Nº de requisições concorrentes no teste de race condition (padrão: 5, máx: 15)")
    adv.add_argument("--confirm-destructive", action="store_true",
                     help="Autoriza testes de lógica de negócio com efeito colateral real "
                          "(ex: reaproveitar cupom de verdade). Use só com autorização explícita.")
    adv.add_argument("--no-interactsh", action="store_true",
                     help="Desliga a detecção de vulnerabilidade cega via OOB (Interactsh) — "
                          "esse módulo faz chamada a serviço público de terceiros")
    adv.add_argument("--oob-server", default=os.environ.get("SENTINELA_OOB_SERVER"),
                     help="URL de um collaborator OOB auto-hospedado, no lugar do Interactsh público "
                          "(ou defina a env var SENTINELA_OOB_SERVER)")
    adv.add_argument("--kerberos-user", default=None, help="Usuário de domínio (Kerberoasting/BloodHound)")
    adv.add_argument("--kerberos-pass", default=None, help="Senha do usuário de domínio")
    adv.add_argument("--kerberos-domain", default=None, help="Domínio AD alvo (ex: exemplo.local)")
    adv.add_argument("--test-log4shell", action="store_true",
                     help="Teste ativo de Log4Shell (CVE-2021-44228) via callback OOB — injeção ativa, "
                          "mesma categoria de risco de --sqli/--xss")
    adv.add_argument("--mobile-app", default=None, metavar="CAMINHO",
                     help="Caminho local de um APK/IPA pra análise estática (MobSF/mobsfscan). "
                          "A SENTINELA não tenta 'achar' o app sozinha — só analisa o que for fornecido.")

    # ── AUDITORIA CLOUD (opt-in, precisa de credencial explícita) ────────────
    cloud = parser.add_argument_group("Auditoria Cloud (ScoutSuite/CloudFox — requer credencial)")
    cloud.add_argument("--aws-profile", default=None,
                       help="Perfil AWS local (~/.aws/credentials) pra auditar a CONTA cloud — "
                            "fora do escopo de 'ataque ao alvo', requer autorização do lado do cliente")
    cloud.add_argument("--azure-subscription", default=None, help="ID de subscription Azure pra auditar")
    cloud.add_argument("--gcp-project", default=None, help="ID de projeto GCP pra auditar")

    # ── PROVA DE IMPACTO / BEEF (manual, opt-in) ─────────────────────────────
    beef = parser.add_argument_group("Prova de Impacto (BeEF — instruções manuais, nunca automático)")
    beef.add_argument("--beef-hook-url", default=None,
                      help="URL do hook.js de uma instância BeEF já rodando — se informado, findings de "
                           "XSS confirmado ganham instruções manuais de payload de prova de impacto")

    # ── MÓDULO DE PHISHING (desligado por padrão, exige confirmação em runtime) ─
    phish = parser.add_argument_group("Módulo de Phishing (SET — desligado por padrão)")
    phish.add_argument("--enable-phishing-module", action="store_true",
                       help="Habilita geração de material de phishing (via SET). Pede confirmação "
                            "interativa em runtime. Phishing é tipicamente uma linha de autorização "
                            "SEPARADA no contrato — confirme isso antes de usar.")

    # ── OPENVAS/GVM (opt-in explícito, nunca automático) ─────────────────────
    ov = parser.add_argument_group("OpenVAS/GVM (opt-in — requer GVM já rodando, não instalado por esta ferramenta)")
    ov.add_argument("--openvas", action="store_true",
                    help="Conecta a uma instância GVM/OpenVAS JÁ RODANDO via gvm-cli/python-gvm e importa "
                         "os resultados. Pesado — nunca ligado por --all/--mode aggressive. A SENTINELA não "
                         "instala nem configura o GVM, só se conecta se --openvas for pedido explicitamente.")

    # ── ESCOPO ───────────────────────────────────────────────────────────────
    scope = parser.add_argument_group("Enforcement de Escopo")
    scope.add_argument("--scope", action="append", metavar="ALVO",
                       help="Adiciona alvo ao escopo (repetível). ex: --scope *.exemplo.com --scope 10.0.0.0/8")
    scope.add_argument("--scope-file", metavar="ARQUIVO",
                       help="Carrega escopo de arquivo (uma entrada por linha, prefixo ! = negar)")
    scope.add_argument("--strict-scope", action="store_true",
                       help="Bloqueia toda requisição fora de escopo (padrão: só avisa)")
    scope.add_argument("--no-ssrf-protect", action="store_true",
                       help="Desliga a proteção SSRF (use em alvos internos/laboratório de pentest)")

    # ── EVASÃO ───────────────────────────────────────────────────────────────
    evade = parser.add_argument_group("Evasão de WAF")
    evade.add_argument("--waf-bypass", action="store_true",
                       help="Ativa evasão de WAF (autodetecta o WAF e carrega o perfil de bypass)")
    evade.add_argument("--waf-profile",
                       choices=["cloudflare", "akamai", "aws-waf", "f5", "imperva",
                                "modsecurity", "wordfence", "sucuri", "generic"],
                       help="Força um perfil específico de bypass de WAF")

    # ── PERFORMANCE / FURTIVIDADE ────────────────────────────────────────────
    perf = parser.add_argument_group("Performance")
    perf.add_argument("--parallel",  action="store_true",
                      help="Roda ferramentas de recon simultaneamente (nmap+amass+sublist3r ao mesmo tempo)")
    perf.add_argument("--intensity", choices=["passive", "normal", "aggressive"],
                      default="normal",
                      help="Intensidade do scan (padrão: normal)")
    perf.add_argument("--ports",     default="21,22,23,25,53,80,110,111,135,139,143,443,445,"
                                              "993,995,1433,1521,3306,3389,5432,5900,6379,"
                                              "8080,8443,8888,9090,9200,27017",
                      help="Portas a escanear (separadas por vírgula ou range)")
    perf.add_argument("--port-scan-type", choices=["connect","syn","udp"], default="connect")
    perf.add_argument("--depth",    type=int, default=3, help="Profundidade do crawl web")
    perf.add_argument("--threads",  type=int, default=20, help="Quantidade de threads")
    perf.add_argument("--timeout",  type=int, default=10, help="Timeout de requisição (s)")
    perf.add_argument("--rate-limit", type=float, default=0.1, help="Delay entre requisições (s)")
    perf.add_argument("--tool-timeout", type=int, default=300, help="Timeout por ferramenta externa (s)")
    perf.add_argument("--proxy-list", metavar="ARQUIVO",
                      help="Lista de proxies (um por linha) para rotação — usado no --mode ghost")

    # ── SAÍDA ────────────────────────────────────────────────────────────────
    out = parser.add_argument_group("Saída & Filtragem")
    out.add_argument("--min-severity",
                     choices=["critical", "high", "medium", "low", "info"],
                     default="info",
                     help="Severidade mínima a exibir/reportar (padrão: info = mostra tudo)")
    out.add_argument("--report",
                     choices=["markdown", "html", "pdf", "json", "both", "all"],
                     default="both")
    out.add_argument("--output",  default="sentinela_results", help="Diretório de saída")
    out.add_argument("--resume",  help="Retoma de um arquivo JSON de sessão salva")
    out.add_argument("-v", "--verbose", action="store_true")

    # ── WORDLISTS ────────────────────────────────────────────────────────────
    wl = parser.add_argument_group("Wordlists")
    wl.add_argument("--wordlist-size", choices=["small","medium","large"], default="medium")
    wl.add_argument("--subdomain-wordlist")
    wl.add_argument("--dir-wordlist")
    wl.add_argument("--password-wordlist")
    wl.add_argument("--username-wordlist")

    # ── HTTP ─────────────────────────────────────────────────────────────────
    http = parser.add_argument_group("HTTP")
    http.add_argument("--proxy")
    http.add_argument("--tor",     action="store_true")
    http.add_argument("--cookies", type=json.loads)
    http.add_argument("--headers", type=json.loads)
    http.add_argument("--user-agent",
                      default="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0")

    # ── OSINT PASSIVO ────────────────────────────────────────────────────────
    osint = parser.add_argument_group("OSINT Passivo (crt.sh / Shodan / Censys)")
    osint.add_argument("--shodan-key", default=os.environ.get("SHODAN_API_KEY"),
                       help="API key do Shodan (ou defina a env var SHODAN_API_KEY)")
    osint.add_argument("--censys-key", default=os.environ.get("CENSYS_API_ID"),
                       help="Censys API ID (ou defina a env var CENSYS_API_ID)")
    osint.add_argument("--censys-secret", default=os.environ.get("CENSYS_API_SECRET"),
                       help="Censys API Secret (ou defina a env var CENSYS_API_SECRET)")

    # ── INFO ──────────────────────────────────────────────────────────────────
    info = parser.add_argument_group("Info")
    info.add_argument("--tools",     action="store_true", help="Mostra inventário de ferramentas")
    info.add_argument("--wordlists", action="store_true", help="Mostra inventário de wordlists")
    info.add_argument("--version",   action="store_true")
    info.add_argument("--no-banner", action="store_true", help="Pula a animação de abertura do banner")

    return parser.parse_args()


# ── BUILD CONFIG ──────────────────────────────────────────────────────────────

def build_config(args) -> dict:
    config = {
        "target":          args.target,
        "verbose":         args.verbose,
        "intensity":       args.intensity,
        "ports":           args.ports,
        "port_scan_type":  args.port_scan_type,
        "depth":           args.depth,
        "threads":         args.threads,
        "timeout":         args.timeout,
        "rate_limit":      args.rate_limit,
        "tool_timeout":    args.tool_timeout,
        "xss":             args.xss,
        "sqli":            args.sqli,
        "brute":           args.brute,
        "no_cve":          args.no_cve,
        "no_subdomains":   args.no_subdomains,
        "udp_scan":        args.udp,
        "stealth":         args.stealth,
        "plugins_enabled": not args.no_plugins,
        "screenshots":     args.screenshots,
        "mode":            args.mode or "standard",
        "fast_scan":       args.fast,
        "parallel":        args.parallel,
        "waf_bypass":      args.waf_bypass,
        "waf_profile":     args.waf_profile,
        "browser":         args.browser,
        "wordlist_size":   args.wordlist_size,
        "user_agent":      args.user_agent,
        "output":          args.output,
        "report":          args.report,
        "min_severity":    args.min_severity.upper(),
        "nikto_timeout":   600,
        "nuclei_timeout":  600,
        "ghost_mode":      False,
        "proxy_list_file": getattr(args, "proxy_list", None),
        "shodan_key":      getattr(args, "shodan_key", None),
        "censys_key":      getattr(args, "censys_key", None),
        "censys_secret":   getattr(args, "censys_secret", None),
        "race_concurrency":     getattr(args, "race_concurrency", 5),
        "confirm_destructive":  getattr(args, "confirm_destructive", False),
        "no_oob":               getattr(args, "no_interactsh", False),
        "oob_server":           getattr(args, "oob_server", None),
        "kerberos_user":        getattr(args, "kerberos_user", None),
        "kerberos_pass":        getattr(args, "kerberos_pass", None),
        "kerberos_domain":      getattr(args, "kerberos_domain", None),
        "username_wordlist":    getattr(args, "username_wordlist", None),
        "aws_profile":          getattr(args, "aws_profile", None),
        "azure_subscription":   getattr(args, "azure_subscription", None),
        "gcp_project":          getattr(args, "gcp_project", None),
        "beef_hook_url":        getattr(args, "beef_hook_url", None),
        "enable_phishing_module": getattr(args, "enable_phishing_module", False),
        "openvas":              getattr(args, "openvas", False),
        "test_log4shell":       getattr(args, "test_log4shell", False),
        "mobile_app":           getattr(args, "mobile_app", None),
    }

    # ── Atalhos de perfil de modo ─────────────────────────────────────────────
    if args.mode == "stealth":
        args.stealth    = True
        args.intensity  = "passive"
    elif args.mode == "standard":
        # Standard é o padrão — nenhum override necessário
        if not args.all and not any([args.recon, args.web, args.vuln]):
            args.all = True
    elif args.mode == "aggressive":
        args.all        = True
        args.intensity  = "aggressive"
        args.sqli       = True
        args.xss        = True
        args.brute      = True
        args.fast       = True
        args.parallel   = True
        args.waf_bypass = True
        config["wordlist_size"]   = "large"
        config["threads"]         = 50
        config["depth"]           = 5
        log("  MODO AGRESSIVO — todos os módulos, injeções, brute-force, wordlists grandes", Colors.BOLD_RED)
    elif args.mode == "ghost":
        config["ghost_mode"]    = True
        config["rate_limit"]    = 0.0   # jitter aleatório substitui o delay fixo — ver executor.py
        config["jitter_min"]    = 0.8
        config["jitter_max"]    = 4.5
        config["rotate_user_agent"] = True
        if not args.all and not any([args.recon, args.web, args.vuln]):
            args.all = True
        log("  MODO GHOST — jitter aleatório, rotação de User-Agent, proxy rotation ativados", Colors.MAGENTA)
        if config.get("proxy_list_file"):
            log(f"     Lista de proxies: {config['proxy_list_file']}", Colors.DIM)
        else:
            log("     Nenhum --proxy-list informado — rodando sem rotação de proxy.", Colors.DIM)

    # Overrides do modo furtivo (stealth)
    if args.stealth or args.mode == "stealth":
        config["intensity"]     = "passive"
        config["rate_limit"]    = 2.0       # 2s entre requisições
        config["threads"]       = 5         # threads bem baixas
        config["xss"]           = False     # sem probing ativo
        config["sqli"]          = False
        config["brute"]         = False
        config["no_subdomains"] = False     # mantém recon passivo
        config["fast_scan"]     = False
        log("  MODO STEALTH — só recon passivo, com rate-limit, sem probing de injeção", Colors.YELLOW)

    if args.tor:
        config["proxy"] = {"http": "socks5h://127.0.0.1:9050",
                           "https": "socks5h://127.0.0.1:9050"}
        config["tor"] = True
        log("  Roteamento via Tor ativado em socks5h://127.0.0.1:9050", Colors.YELLOW)
    elif args.proxy:
        config["proxy"] = {"http": args.proxy, "https": args.proxy}

    if args.cookies: config["cookies"] = args.cookies
    if args.headers: config["headers"] = args.headers

    for attr in ["subdomain_wordlist","dir_wordlist","password_wordlist","username_wordlist"]:
        val = getattr(args, attr, None)
        if val: config[f"custom_{attr}"] = val

    return config


# ── SCOPE SETUP ───────────────────────────────────────────────────────────────

def build_scope(args, config: dict) -> ScopeEnforcer:
    extra = args.scope or []
    enforcer = ScopeEnforcer(
        primary=args.target,
        extra_scope=extra,
        scope_file=args.scope_file if hasattr(args, "scope_file") else None,
        strict=args.strict_scope if hasattr(args, "strict_scope") else False,
        ssrf_protect=not (args.no_ssrf_protect if hasattr(args, "no_ssrf_protect") else False),
    )
    enforcer.print_scope()
    return enforcer


# ── INFO PRINTERS ─────────────────────────────────────────────────────────────

def print_tool_inventory(runner: ToolRunner):
    inv = runner.tool_inventory()
    installed = [t for t, v in inv.items() if v]
    missing   = [t for t, v in inv.items() if not v]
    log("", Colors.RESET)
    log("═"*60, Colors.BOLD_CYAN)
    log("  INVENTÁRIO DE FERRAMENTAS", Colors.BOLD_CYAN)
    log("═"*60, Colors.BOLD_CYAN)
    log(f"  Instaladas: {len(installed)}/{len(inv)}", Colors.GREEN)
    categories = {
        "Recon / OSINT":       ["nmap","dnsrecon","dnsenum","sublist3r","amass","theHarvester","masscan","fierce","whois","dig",
                                 "subfinder","assetfinder","httpx","waybackurls","gau","katana"],
        "Varredura Web":       ["nikto","whatweb","wafw00f","gobuster","ffuf","dirb","wfuzz","feroxbuster","wpscan","nuclei",
                                 "arjun","eyewitness","dalfox","wcvs"],
        "Vulnerabilidade":     ["sqlmap","xssstrike","commix","testssl","sslscan","sslyze",
                                 "searchsploit","trivy","osv-scanner","cve-bin-tool","nettacker","zap","gvm-cli",
                                 "interactsh-client"],
        "Brute-force Online":  ["hydra","medusa","ncrack","patator","crackmapexec"],
        "Quebra Offline":      ["john","hashcat","haiti"],
        "Rede/Serviços":       ["enum4linux","smbclient","smbmap","nbtscan","snmpwalk","onesixtyone"],
        "AD / Kerberos":       ["kerbrute","impacket-getuserspns","impacket-getnpusers","bloodhound-python","impacket"],
        "Cloud / Kubernetes":  ["scoutsuite","cloudfox","kube-hunter"],
        "Segredos / Mobile":   ["gitleaks","git-dumper","mobsfscan"],
    }
    for cat, tools in categories.items():
        log(f"\n  {cat}", Colors.BOLD_YELLOW)
        for t in tools:
            ok = inv.get(t, False)
            path = runner.which(t) or "" if ok else ""
            sym  = "+" if ok else "-"
            col  = Colors.GREEN if ok else Colors.DIM
            log(f"    {col}{sym}  {t:<20}{Colors.DIM}{path[:40]}{Colors.RESET}", Colors.RESET)
    if missing:
        log("\n  Instalar ferramentas faltando:", Colors.BOLD_YELLOW)
        apt_pkgs = ["nmap","gobuster","ffuf","nikto","sqlmap","hydra","john","hashcat",
                    "seclists","wordlists","dnsrecon","amass","sublist3r","theharvester",
                    "whatweb","wafw00f","sslscan","enum4linux","smbclient","nuclei","wpscan"]
        log(f"    sudo apt install -y {' '.join(apt_pkgs[:8])}", Colors.CYAN)
        log(f"    sudo apt install -y {' '.join(apt_pkgs[8:])}", Colors.CYAN)
        log("    # Navegador headless: pip install playwright && playwright install chromium", Colors.CYAN)


def print_wordlist_inventory():
    wl = WordlistManager()
    log("", Colors.RESET)
    log("═"*60, Colors.BOLD_CYAN)
    log("  INVENTÁRIO DE WORDLISTS", Colors.BOLD_CYAN)
    log("═"*60, Colors.BOLD_CYAN)
    seclists = Path("/usr/share/seclists").exists()
    wlists   = Path("/usr/share/wordlists").exists()
    log(f"\n  SecLists:  {'[+] instalado' if seclists else '[-] não encontrado → sudo apt install seclists'}", Colors.GREEN if seclists else Colors.YELLOW)
    log(f"  wordlists: {'[+] instalado' if wlists else '[-] não encontrado → sudo apt install wordlists'}", Colors.GREEN if wlists else Colors.YELLOW)
    inv = wl.inventory()
    for cat, data in inv.items():
        col = Colors.GREEN if data["available"] > 0 else Colors.DIM
        log(f"  {cat:<20} {col}{data['available']}/{data['total']} disponíveis{Colors.RESET}", Colors.RESET)
    rr = wl.rockyou_path()
    log(f"\n  rockyou.txt: {'[+] ' + rr if rr else '[-] não encontrado'}", Colors.GREEN if rr else Colors.DIM)


# ── SCAN ORCHESTRATION ────────────────────────────────────────────────────────

def run_eyewitness_fallback(urls: list, config: dict) -> list:
    """Fallback de screenshot quando Playwright não está disponível (ex:
    incompatibilidade node-playwright/Node.js do Kali). EyeWitness não faz
    análise de DOM XSS como o Playwright — só captura tela."""
    if not urls:
        return []
    outdir = os.path.join(config.get("output", "sentinela_results"), "screenshots_eyewitness")
    os.makedirs(outdir, exist_ok=True)

    urls_file = tempfile.mktemp(suffix=".txt")
    try:
        with open(urls_file, "w") as fh:
            fh.write("\n".join(urls))
        subprocess.run(
            ["eyewitness", "--web", "-f", urls_file, "-d", outdir, "--no-prompt"],
            capture_output=True, text=True, timeout=config.get("tool_timeout", 300),
        )
    except Exception:
        pass
    finally:
        try: os.unlink(urls_file)
        except Exception: pass

    if not os.path.isdir(outdir):
        return []
    return [os.path.join(outdir, f) for f in os.listdir(outdir)
            if f.lower().endswith((".png", ".jpg", ".jpeg"))]


def run_modules(config: dict, args, scope: ScopeEnforcer,
                executor: SafeExecutor, prior: dict = None) -> tuple:
    all_results  = prior or {}
    total_findings = 0

    # ── RECON (paralelo se --parallel) ────────────────────────────────────────
    if args.all or args.recon:
        log("\n", Colors.RESET)
        log("━"*62, Colors.BOLD_CYAN)
        log("  [1/3] RECONHECIMENTO", Colors.BOLD_CYAN)
        log("━"*62, Colors.BOLD_CYAN)
        t0 = time.time()

        if config.get("parallel"):
            log("  Modo paralelo — rodando todas as ferramentas de recon simultaneamente...", Colors.CYAN)
            # Run nmap + amass + sublist3r + theHarvester at the same time
            raw_parallel = executor.run_recon_parallel(config["target"], config)
            # Still run the full ReconModule to process+normalise results
            from modules.recon import ReconModule
            recon_mod = ReconModule(config)
            recon_mod._parallel_results = raw_parallel  # pass in pre-run results
            all_results["recon"] = recon_mod.run()
        else:
            from modules.recon import ReconModule
            recon_mod = ReconModule(config)
            all_results["recon"] = recon_mod.run()

        elapsed = time.time() - t0
        n = len(all_results["recon"].get("findings", []))
        total_findings += n
        log(f"\n  [+] Recon concluído em {elapsed:.1f}s — {n} findings", Colors.GREEN)

    # ── WEB ───────────────────────────────────────────────────────────────────
    if args.all or args.web:
        log("\n", Colors.RESET)
        log("━"*62, Colors.BOLD_CYAN)
        log("  [2/3] ANÁLISE WEB", Colors.BOLD_CYAN)
        log("━"*62, Colors.BOLD_CYAN)
        t0 = time.time()

        # Build WAF bypass if requested
        waf_bypass = None
        if config.get("waf_bypass") or config.get("waf_profile"):
            from modules.waf_bypass import WafBypass, build_bypass
            if config.get("waf_profile"):
                waf_bypass = WafBypass(config["waf_profile"], config["intensity"])
            # actual WAF is detected in web_analysis; bypass applied to session

        from modules.web_analysis import WebAnalysisModule
        web_mod = WebAnalysisModule(config,
                                    prior_results=all_results.get("recon", {}),
                                    waf_bypass_engine=waf_bypass)
        all_results["web"] = web_mod.run()
        elapsed = time.time() - t0
        n = len(all_results["web"].get("findings", []))
        total_findings += n
        log(f"\n  [+] Análise web concluída em {elapsed:.1f}s — {n} findings", Colors.GREEN)

        # Passo de navegador headless
        if config.get("browser"):
            from modules.browser import HeadlessBrowser
            log("  → Navegador headless (Playwright) — scan de DOM XSS...", Colors.CYAN)
            if HeadlessBrowser.available():
                hb = HeadlessBrowser(config, waf_bypass=waf_bypass)
                base_urls = all_results["web"].get("base_urls", [f"https://{config['target']}"])
                browser_results = hb.run(base_urls[:5])
                all_results["web"]["browser"] = browser_results
                # Merge browser findings into web findings
                all_results["web"]["findings"] += browser_results.get("findings", [])
                dom_xss = browser_results.get("dom_xss", [])
                if dom_xss:
                    log(f"    {len(dom_xss)} padrão(ões) de DOM XSS encontrado(s) pelo navegador headless", Colors.BOLD_RED)
            elif config.get("screenshots") and shutil.which("eyewitness"):
                log(f"    Playwright não disponível — usando EyeWitness como fallback "
                    f"(só screenshot, sem análise de DOM XSS)...", Colors.YELLOW)
                base_urls = all_results["web"].get("base_urls", [f"https://{config['target']}"])
                shots = run_eyewitness_fallback(base_urls[:5], config)
                all_results["web"].setdefault("browser", {})["screenshots"] = shots
                log(f"    {len(shots)} screenshot(s) via EyeWitness", Colors.GREEN)
            else:
                log(f"    Playwright não instalado.", Colors.YELLOW)
                log(f"    Instalar: {HeadlessBrowser.install_hint()}", Colors.DIM)
                if shutil.which("eyewitness"):
                    log(f"    EyeWitness está disponível — rode com --screenshots pra usá-lo como "
                        f"fallback (só captura tela, não analisa DOM XSS).", Colors.DIM)

    # ── VULN ──────────────────────────────────────────────────────────────────
    if args.all or args.vuln:
        log("\n", Colors.RESET)
        log("━"*62, Colors.BOLD_CYAN)
        log("  [3/3] ANÁLISE DE VULNERABILIDADES", Colors.BOLD_CYAN)
        log("━"*62, Colors.BOLD_CYAN)
        t0 = time.time()
        from modules.vuln_detection import VulnDetectionModule
        vuln_mod = VulnDetectionModule(config,
                                       prior_web=all_results.get("web", {}),
                                       prior_recon=all_results.get("recon", {}))
        all_results["vuln"] = vuln_mod.run()
        elapsed = time.time() - t0
        n = len(all_results["vuln"].get("findings", []))
        total_findings += n
        log(f"\n  [+] Análise de vulnerabilidades concluída em {elapsed:.1f}s — {n} findings", Colors.GREEN)

    # ── AUDITORIA CLOUD (opt-in — só roda se credencial foi fornecida) ──────
    if config.get("aws_profile") or config.get("azure_subscription") or config.get("gcp_project"):
        from modules.cloud_audit import rodar_auditoria_cloud
        all_results["cloud_audit"] = rodar_auditoria_cloud(config)

    # ── MÓDULO DE PHISHING (opt-in + confirmação interativa) ────────────────
    if config.get("enable_phishing_module"):
        from modules.phishing_helper import gerar_material_phishing
        all_results["phishing"] = gerar_material_phishing(config)

    # ── ANÁLISE ESTÁTICA MOBILE (opt-in — só com --mobile-app) ──────────────
    if config.get("mobile_app"):
        from modules.mobile_scan import escanear_app_mobile
        all_results["mobile"] = escanear_app_mobile(config)

    return all_results, total_findings


# ── EXECUTOR DE PLUGINS ───────────────────────────────────────────────────────

def run_plugins(config: dict, all_results: dict) -> dict:
    """Carrega e roda todos os plugins habilitados da pasta plugins/."""
    import sys, os
    from pathlib import Path

    plugin_dir = Path(os.path.dirname(os.path.abspath(__file__))) / "plugins"

    # Add project root to sys.path so plugins can import modules.*
    project_root = str(Path(os.path.dirname(os.path.abspath(__file__))))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    if not plugin_dir.exists():
        return all_results

    try:
        from plugins.base import PluginLoader
    except ImportError:
        return all_results

    log("\n", Colors.RESET)
    log("━"*62, Colors.BOLD_CYAN)
    log("  PLUGINS", Colors.BOLD_CYAN)
    log("━"*62, Colors.BOLD_CYAN)

    loader = PluginLoader(str(plugin_dir))
    stealth = config.get("stealth", False)
    completed = []
    if all_results.get("recon"):    completed.append("recon")
    if all_results.get("web"):      completed.append("web_analysis")
    if all_results.get("vuln"):     completed.append("vuln_detection")
    # bug corrigido em relação ao GhostScan original: load_all() não aceita "mode",
    # e o parâmetro correto é completed_phases (não "completed")
    plugins   = loader.load_all(stealth_only=stealth, completed_phases=completed)

    if not plugins:
        log("  Nenhum plugin encontrado na pasta plugins/", Colors.DIM)
        return all_results

    log(f"  {len(plugins)} plugin(s) carregado(s)", Colors.GREEN)

    # OOB listener (Interactsh) — instanciado UMA vez e compartilhado via
    # context, pra não pagar o custo de registro (RSA keygen + chamada de
    # rede) uma vez por plugin. Plugins de SSTI/XXE usam pra confirmar
    # vulnerabilidade cega.
    oob = None
    if not config.get("no_oob"):
        try:
            from modules.oob_listener import OOBListener
            oob = OOBListener(config)
            if oob.disponivel:
                log(f"  [OOB] Listener Interactsh ativo — vulnerabilidades cegas podem ser confirmadas", Colors.DIM)
            elif oob.erro:
                log(f"  [OOB] Indisponível ({oob.erro[:80]}) — testes cegos ficam sem confirmação por callback", Colors.DIM)
        except Exception as e:
            log(f"  [OOB] Erro ao inicializar: {e}", Colors.DIM)

    # Build context for plugins
    context = {
        **all_results.get("web", {}),
        **all_results.get("recon", {}),
        **all_results.get("vuln", {}),
        "config": config,
        "oob_listener": oob,
    }

    plugin_findings = loader.run_all(config["target"], context)

    if plugin_findings:
        log(f"  Plugins encontraram {len(plugin_findings)} finding(s) adicional(is)", Colors.GREEN)
        # Merge into web findings
        all_results.setdefault("web", {}).setdefault("findings", [])
        all_results["web"]["findings"].extend(plugin_findings)

    if oob is not None:
        oob.fechar()  # encerra o subprocesso do interactsh-client, se houver

    return all_results


# ── PÓS-PROCESSAMENTO DE INTELIGÊNCIA ────────────────────────────────────────

def run_intelligence(config: dict, all_results: dict) -> dict:
    if not all_results:
        return all_results
    log("\n", Colors.RESET)
    log("━"*62, Colors.BOLD_CYAN)
    log("  MOTOR DE INTELIGÊNCIA — Correlacionando findings...", Colors.BOLD_CYAN)
    log("━"*62, Colors.BOLD_CYAN)
    intel = IntelligenceEngine(config)
    all_results = intel.analyse(all_results)
    stats = all_results.get("intelligence", {}).get("stats", {})
    log(f"  Correlações:       {stats.get('correlations', 0)}", Colors.GREEN)
    log(f"  Alvos ranqueados:  {stats.get('attack_surface', 0)}", Colors.GREEN)
    log(f"  Após dedup:        {stats.get('after_dedup', 0)} → filtrados: {stats.get('after_filter', 0)}", Colors.GREEN)
    return all_results


# ── IMPRESSÃO DE SUMÁRIO ──────────────────────────────────────────────────────

def print_summary(config: dict, all_results: dict):
    from modules.intelligence import SEVERITY_SCORE
    min_score = SEVERITY_SCORE.get(config.get("min_severity","INFO").upper(), 0)

    # Prefer intelligence-filtered findings
    intel = all_results.get("intelligence", {})
    findings = intel.get("deduped_findings") or _collect_raw_findings(all_results)

    # Apply min_severity filter
    findings = [f for f in findings
                if SEVERITY_SCORE.get(f.get("severity","INFO").upper(), 0) >= min_score]

    counts = {}
    for f in findings:
        s = f.get("severity","INFO").upper()
        counts[s] = counts.get(s, 0) + 1

    log("\n", Colors.RESET)
    log("═"*62, Colors.BOLD_CYAN)
    log("  SUMÁRIO DO SCAN", Colors.BOLD_CYAN)
    log("═"*62, Colors.BOLD_CYAN)

    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        c = counts.get(sev, 0)
        if c:
            col = SEVERITY_COLORS.get(sev, Colors.WHITE)
            log(f"  {col}{sev:<10}{Colors.RESET}  {c}", Colors.RESET)

    log("─"*62, Colors.DIM)
    log(f"  Total (após filtro): {len(findings)}", Colors.BOLD)

    if config.get("min_severity","INFO").upper() != "INFO":
        log(f"  (Mostrando apenas {config['min_severity'].upper()}+ — use --min-severity info para ver tudo)", Colors.DIM)

    # Top findings
    from modules.reporting import SEVERITY_ORDER
    top = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 9))[:8]
    if top:
        log("\n  Principais Findings:", Colors.BOLD_YELLOW)
        for f in top:
            sev = f.get("severity","INFO")
            col = SEVERITY_COLORS.get(sev, Colors.WHITE)
            title = f.get("title","")[:58]
            log(f"  {col}[{sev}]{Colors.RESET} {title}", Colors.RESET)

    # Correlations
    corrs = intel.get("correlations", [])
    if corrs:
        log(f"\n  Correlações ({len(corrs)} riscos compostos):", Colors.BOLD_YELLOW)
        for c in sorted(corrs, key=lambda x: x.get("score",0), reverse=True)[:5]:
            sev = c.get("severity","HIGH")
            col = SEVERITY_COLORS.get(sev, Colors.WHITE)
            log(f"  {col}[{sev}]{Colors.RESET} {c.get('title','')[:58]}", Colors.RESET)
            if c.get("attack_path"):
                log(f"    {Colors.DIM}→ {c['attack_path'][:70]}{Colors.RESET}", Colors.DIM)

    log("", Colors.RESET)


# ── PRÓXIMOS PASSOS ADAPTATIVOS ───────────────────────────────────────────────

def print_next_steps(config: dict, all_results: dict):
    engine = WorkflowEngine(config)
    # Merge all relevant findings for the workflow engine
    merged = {
        **all_results.get("recon", {}),
        **all_results.get("web", {}),
        **all_results.get("vuln", {}),
    }
    # Also pass intelligence ranked targets
    intel = all_results.get("intelligence", {})
    if intel.get("ranked_targets"):
        merged["ranked_targets"] = intel["ranked_targets"]

    engine.print_adaptive_steps(merged)

    # Intelligence ranked targets
    if intel.get("ranked_targets"):
        intel_engine = IntelligenceEngine(config)
        intel_engine.print_ranked_targets(all_results)
        intel_engine.print_recommendations(all_results)


# ── HELPERS ───────────────────────────────────────────────────────────────────

def _collect_raw_findings(results: dict) -> list:
    all_f = []
    seen  = set()
    for section in ["recon","web","vuln"]:
        for f in results.get(section, {}).get("findings", []):
            key = f"{f.get('severity')}{f.get('title')}{f.get('url')}"
            if key not in seen:
                seen.add(key)
                all_f.append(f)
    return all_f


def load_session(path: str) -> dict:
    try:
        with open(path) as f:
            data = json.load(f)
        log(f"  Sessão carregada: {path}", Colors.GREEN)
        return data.get("results", {})
    except Exception as e:
        log(f"  Falha ao carregar sessão: {e}", Colors.YELLOW)
        return {}


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if args.version:
        print("SENTINELA v1.0.0 — Framework de Pentest de Nível Empresarial | by github.com/3rr0rrr (fork de GhostScan)")
        sys.exit(0)

    if not args.target:
        print("sentinela: error: o argumento -t/--target é obrigatório (exceto com --version)")
        sys.exit(2)

    if not args.no_banner:
        play_intro()
    banner()

    config  = build_config(args)
    runner  = ToolRunner(config)

    # ── MODOS DE INFO ────────────────────────────────────────────────────────
    if args.tools:
        print_tool_inventory(runner)
        sys.exit(0)

    if args.wordlists:
        print_wordlist_inventory()
        sys.exit(0)

    if args.workflow:
        engine = WorkflowEngine(config)
        engine.print_workflow()
        sys.exit(0)

    # ── VALIDAÇÃO ────────────────────────────────────────────────────────────
    if not any([args.all, args.recon, args.web, args.vuln]):
        log("Nenhum módulo selecionado. Use --all, --recon, --web, --vuln ou --workflow.", Colors.YELLOW)
        log("Rode: sentinela --help", Colors.DIM)
        sys.exit(1)

    # ── ESCOPO ───────────────────────────────────────────────────────────────
    scope    = build_scope(args, config)
    executor = SafeExecutor(config, scope)

    # Verifica o escopo do alvo principal antes de fazer qualquer coisa
    try:
        scope.check(args.target)
    except ScopeViolation as e:
        log(f"\n  ERRO DE ESCOPO: {e}", Colors.BOLD_RED)
        log("  Adicione --scope para ampliar o escopo, ou corrija --target.", Colors.YELLOW)
        sys.exit(1)

    # ── CABEÇALHO ────────────────────────────────────────────────────────────
    log("  [!]  APENAS PARA TESTES DE SEGURANÇA AUTORIZADOS", Colors.BOLD_YELLOW)
    log(f"  Alvo:        {args.target}", Colors.CYAN)
    log(f"  Intensidade: {args.intensity}  │  Threads: {args.threads}  │  Filtro de severidade: {args.min_severity.upper()}+", Colors.DIM)
    log(f"  Paralelo:    {'SIM' if config.get('parallel') else 'não'}"
        f"  │  Bypass de WAF: {'SIM' if config.get('waf_bypass') else 'não'}"
        f"  │  Navegador: {'SIM' if config.get('browser') else 'não'}"
        f"  │  Modo ghost: {'SIM' if config.get('ghost_mode') else 'não'}", Colors.DIM)
    if config.get("tor"):
        log("  Roteando via Tor", Colors.YELLOW)

    # ── HANDLER DE INTERRUPÇÃO ───────────────────────────────────────────────
    interrupted = [False]
    def _sig(sig, frame):
        log("\n  Interrompido — salvando resultados parciais...", Colors.YELLOW)
        interrupted[0] = True
        executor.cancel_all()
    signal.signal(signal.SIGINT, _sig)

    # ── RESUME ───────────────────────────────────────────────────────────────
    prior = {}
    if args.resume:
        prior = load_session(args.resume)

    # ── EXECUÇÃO ─────────────────────────────────────────────────────────────
    start = time.time()
    all_results = {}
    total       = 0

    try:
        all_results, total = run_modules(config, args, scope, executor, prior)
    except KeyboardInterrupt:
        log("\n  Interrompido.", Colors.YELLOW)
        all_results = prior
    except Exception as e:
        log(f"\n  Erro fatal: {e}", Colors.BOLD_RED)
        if args.verbose:
            import traceback; traceback.print_exc()
        all_results = prior

    elapsed = time.time() - start

    # ── PLUGINS ──────────────────────────────────────────────────────────────
    if all_results and config.get("plugins_enabled", True):
        all_results = run_plugins(config, all_results)

    # ── INTELIGÊNCIA ─────────────────────────────────────────────────────────
    if all_results:
        all_results = run_intelligence(config, all_results)

    # ── SUMÁRIO + PRÓXIMOS PASSOS ────────────────────────────────────────────
    print_summary(config, all_results)
    print_next_steps(config, all_results)
    # Imprime a tabela de scoring
    if all_results.get("intelligence"):
        from modules.intelligence import IntelligenceEngine
        ie = IntelligenceEngine(config)
        ie.print_score_table(all_results)
    log(f"  Tempo total de scan: {elapsed:.1f}s", Colors.DIM)

    # ── VIOLAÇÕES DE ESCOPO ──────────────────────────────────────────────────
    if scope.violations:
        log(f"\n  [!]  {len(scope.violations)} violação(ões) de escopo bloqueada(s):", Colors.YELLOW)
        for v in scope.violations[:5]:
            log(f"    {v}", Colors.DIM)

    # ── CHECKLIST DE ENDPOINTS ───────────────────────────────────────────────
    if all_results:
        try:
            from modules.checklist import ChecklistManager
            checklist = ChecklistManager(config, all_results)
            checklist_path = checklist.generate()
            log(f"\n  [+] Checklist de endpoints atualizado: {checklist_path}", Colors.GREEN)
        except Exception as e:
            log(f"  Falha ao gerar checklist: {e}", Colors.YELLOW)

    # ── RELATÓRIO ────────────────────────────────────────────────────────────
    if all_results:
        log("\n", Colors.RESET)
        log("━"*62, Colors.BOLD_CYAN)
        log("  GERANDO RELATÓRIOS", Colors.BOLD_CYAN)
        log("━"*62, Colors.BOLD_CYAN)
        from modules.reporting import ReportingModule
        reporter = ReportingModule(config, all_results)
        paths = reporter.generate(args.report)
        log("\n  Arquivos gerados:", Colors.BOLD_GREEN)
        for fmt, path in paths.items():
            log(f"    {fmt:<10} {path}", Colors.CYAN)
    else:
        log("  Nenhum resultado para reportar.", Colors.YELLOW)

    log("", Colors.RESET)
    log("  Rode --workflow para a referência completa passo a passo.", Colors.DIM)
    log("", Colors.RESET)


if __name__ == "__main__":
    main()
