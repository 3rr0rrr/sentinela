#!/usr/bin/env python3
"""
SENTINELA — Servidor MCP
Criado por github.com/3rr0rrr

Expõe a SENTINELA como ferramentas MCP, pra um cliente (ex: Claude Code)
poder chamar recon/web/vuln/plugins individualmente numa conversa, em vez
de só rodar via CLI com flags fixas.

Design de segurança:
- Roda a SENTINELA como subprocesso real (não reimplementa a lógica interna),
  então qualquer correção/feature nova no core da ferramenta já vale aqui
  sem duplicar código.
- Ações sensíveis (SQLi, XSS, brute-force) exigem `authorized=True`
  explícito em CADA chamada — nunca assumido, nunca "lembrado" de uma
  chamada anterior.
- Toda ação sensível é registrada em mcp_audit.log (quem pediu o quê,
  quando) — mesma filosofia de cadeia de custódia do resto da ferramenta.
- Timeout obrigatório em toda chamada — um agente não pode travar o
  servidor rodando um scan infinito sem limite.
"""

import json
import os
import subprocess
import time
import glob
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SENTINELA_PY = os.path.join(BASE_DIR, "sentinela.py")
RESULTS_DIR = os.path.join(BASE_DIR, "sentinela_results")
AUDIT_LOG = os.path.join(BASE_DIR, "mcp_audit.log")

mcp = FastMCP("sentinela")


def _audit(acao: str, detalhes: dict):
    linha = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "acao": acao,
        "detalhes": detalhes,
    }
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(linha, ensure_ascii=False) + "\n")


def _newest_session_json(since_ts: float) -> dict | None:
    """Acha o session_*.json mais recente gerado depois de `since_ts`."""
    candidatos = sorted(
        glob.glob(os.path.join(RESULTS_DIR, "session_*.json")),
        key=os.path.getmtime, reverse=True,
    )
    for c in candidatos:
        if os.path.getmtime(c) >= since_ts - 1:
            try:
                with open(c, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return None
    return None


def _run_sentinela(args: list, timeout: int = 600) -> dict:
    """Roda sentinela.py como subprocesso, captura sessão JSON gerada."""
    inicio = time.time()
    cmd = ["python3", SENTINELA_PY] + args + ["--report", "json"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=BASE_DIR,
        )
    except subprocess.TimeoutExpired:
        return {
            "erro": f"Timeout após {timeout}s — scan abortado. Tente um mode mais "
                    f"leve (stealth) ou um timeout maior.",
            "comando": " ".join(cmd),
        }

    sessao = _newest_session_json(inicio)
    saida_resumida = proc.stdout[-3000:] if proc.stdout else ""
    return {
        "comando": " ".join(cmd),
        "codigo_saida": proc.returncode,
        "stdout_final": saida_resumida,
        "stderr": proc.stderr[-1500:] if proc.stderr and proc.returncode != 0 else "",
        "sessao": sessao,
    }


@mcp.tool()
def sentinela_status() -> dict:
    """Lista quais das ferramentas externas (nmap, sqlmap, gobuster etc.) a
    SENTINELA encontrou instaladas no sistema. Não toca em nenhum alvo."""
    proc = subprocess.run(
        ["python3", SENTINELA_PY, "-t", "0.0.0.0", "--tools"],
        capture_output=True, text=True, timeout=30, cwd=BASE_DIR,
    )
    return {"saida": proc.stdout, "codigo_saida": proc.returncode}


@mcp.tool()
def sentinela_list_plugins() -> dict:
    """Lista os plugins carregados pela SENTINELA (nome, autor, descrição,
    se é stealth-safe). Não toca em nenhum alvo — só inspeciona o código."""
    script = (
        "import sys; sys.path.insert(0, '.')\n"
        "from plugins.base import PluginLoader\n"
        "import json\n"
        "loader = PluginLoader(verbose=False)\n"
        "plugins = loader.load_all(stealth_only=False, completed_phases=["
        "'recon','web_analysis','vuln_detection'])\n"
        "out = [{'name': p.name, 'version': p.version, 'author': p.author,"
        " 'description': p.description, 'stealth': p.stealth,"
        " 'severity': p.severity, 'tags': p.tags} for p in plugins]\n"
        "print(json.dumps(out, ensure_ascii=False))\n"
    )
    proc = subprocess.run(
        ["python3", "-c", script], capture_output=True, text=True,
        timeout=30, cwd=BASE_DIR,
    )
    if proc.returncode != 0:
        return {"erro": proc.stderr[-1000:]}
    try:
        return {"plugins": json.loads(proc.stdout)}
    except Exception:
        return {"erro": "Falha ao parsear lista de plugins", "saida_bruta": proc.stdout[-1000:]}


@mcp.tool()
def sentinela_recon(target: str, mode: str = "stealth", shodan_key: str = "",
                     censys_key: str = "", censys_secret: str = "") -> dict:
    """Roda o módulo de reconhecimento da SENTINELA contra um alvo (DNS,
    WHOIS, subdomínios via crt.sh/OSINT). mode='stealth' é 100% passivo
    (recomendado como primeiro passo). mode='standard' soma gobuster DNS
    brute-force. shodan_key/censys_key são opcionais — se vazios, esses
    passos são pulados automaticamente."""
    args = ["-t", target, "--recon", "--mode", mode]
    if shodan_key:
        args += ["--shodan-key", shodan_key]
    if censys_key and censys_secret:
        args += ["--censys-key", censys_key, "--censys-secret", censys_secret]
    _audit("recon", {"target": target, "mode": mode})
    return _run_sentinela(args, timeout=300)


@mcp.tool()
def sentinela_web_scan(target: str, mode: str = "stealth", waf_bypass: bool = False,
                        browser: bool = False) -> dict:
    """Roda o módulo de análise web da SENTINELA (WAF detect, crawl, e em
    mode!='stealth' também dir-brute/Nikto/Nuclei/WPScan/paths sensíveis).
    Nunca inclui SQLi/XSS — isso é só em sentinela_vuln_scan. browser=True
    soma DOM XSS via Playwright (requer playwright instalado)."""
    args = ["-t", target, "--web", "--mode", mode]
    if waf_bypass:
        args.append("--waf-bypass")
    if browser:
        args.append("--browser")
    _audit("web_scan", {"target": target, "mode": mode, "waf_bypass": waf_bypass})
    return _run_sentinela(args, timeout=600)


@mcp.tool()
def sentinela_vuln_scan(target: str, sqli: bool = False, xss: bool = False,
                         brute: bool = False, authorized: bool = False,
                         waf_bypass: bool = False) -> dict:
    """Roda o módulo de vulnerabilidades (headers, SSL, CVE, plugins).
    sqli/xss/brute SÓ rodam se authorized=True for passado explicitamente
    NESTA chamada — nunca presuma autorização de um pedido anterior.
    brute-force de credenciais é especialmente sensível: confirme com o
    operador humano antes de passar brute=True e authorized=True juntos."""
    quer_agressivo = sqli or xss or brute
    if quer_agressivo and not authorized:
        return {
            "erro": "sqli/xss/brute pedidos mas authorized=False. Confirme "
                    "explicitamente com o operador humano que ele autoriza "
                    "ESSE tipo de teste neste alvo/escopo antes de chamar "
                    "de novo com authorized=True.",
            "acao_bloqueada": {"sqli": sqli, "xss": xss, "brute": brute},
        }
    args = ["-t", target, "--vuln"]
    if sqli:
        args.append("--sqli")
    if xss:
        args.append("--xss")
    if brute:
        args.append("--brute")
    if waf_bypass:
        args.append("--waf-bypass")
    _audit("vuln_scan", {
        "target": target, "sqli": sqli, "xss": xss, "brute": brute,
        "authorized": authorized,
    })
    return _run_sentinela(args, timeout=900)


@mcp.tool()
def sentinela_full_scan(target: str, mode: str = "standard", sqli: bool = False,
                         xss: bool = False, authorized: bool = False,
                         report_format: str = "all") -> dict:
    """Roda recon+web+vuln em sequência (--all) e gera relatório completo
    (com Sumário Executivo, CVSS, compliance PCI-DSS/LGPD, hash de
    custódia). sqli/xss exigem authorized=True explícito, mesma regra de
    sentinela_vuln_scan. Use isso só depois de já ter rodado recon/web
    isolados e revisado o resultado — não é o primeiro passo recomendado."""
    if (sqli or xss) and not authorized:
        return {
            "erro": "sqli/xss pedidos mas authorized=False. Confirme com o "
                    "operador humano antes de chamar de novo com "
                    "authorized=True.",
        }
    args = ["-t", target, "--all", "--mode", mode, "--report", report_format]
    if sqli:
        args.append("--sqli")
    if xss:
        args.append("--xss")
    _audit("full_scan", {
        "target": target, "mode": mode, "sqli": sqli, "xss": xss,
        "authorized": authorized,
    })
    return _run_sentinela(args, timeout=1800)


@mcp.tool()
def sentinela_read_checklist() -> dict:
    """Lê o checklist_endpoints.txt atual (endpoints testados/não-testados
    até agora, formato usado pelo operador em todos os engajamentos)."""
    path = os.path.join(RESULTS_DIR, "checklist_endpoints.txt")
    if not os.path.exists(path):
        return {"erro": "Nenhum checklist gerado ainda — rode um scan primeiro."}
    with open(path, encoding="utf-8") as f:
        return {"conteudo": f.read()}


if __name__ == "__main__":
    mcp.run()
