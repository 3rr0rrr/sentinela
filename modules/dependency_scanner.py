#!/usr/bin/env python3
"""
SENTINELA — Scanner de Dependências (Trivy + OSV-Scanner)
Criado por github.com/3rr0rrr

Roda contra um manifest de dependência JÁ BAIXADO localmente (nunca contra
container em execução no alvo, nunca contra o alvo remotamente — só
análise estática de um arquivo que foi encontrado publicamente exposto).

Roda Trivy E OSV-Scanner sobre o MESMO arquivo baixado (sem baixar duas
vezes) e mescla os achados, deduplicando por (pacote, versão, CVE) pra não
reportar a mesma vulnerabilidade duas vezes só porque as duas ferramentas
concordam.
"""

import json
import shutil
import subprocess
import tempfile
import os


def escanear_manifest(caminho_local: str, timeout: int = 120) -> list:
    """Retorna lista de dicts {pacote, versao, cve, severidade, fonte}."""
    achados = []
    achados += _rodar_trivy(caminho_local, timeout)
    achados += _rodar_osv_scanner(caminho_local, timeout)
    return _dedup(achados)


def _rodar_trivy(caminho_local: str, timeout: int) -> list:
    if not shutil.which("trivy"):
        return []
    achados = []
    try:
        proc = subprocess.run(
            ["trivy", "fs", "--format", "json", "--quiet", os.path.dirname(caminho_local)],
            capture_output=True, text=True, timeout=timeout,
        )
        if not proc.stdout.strip():
            return []
        dados = json.loads(proc.stdout)
        for resultado in dados.get("Results", []) or []:
            for vuln in resultado.get("Vulnerabilities", []) or []:
                achados.append({
                    "pacote":     vuln.get("PkgName", "?"),
                    "versao":     vuln.get("InstalledVersion", "?"),
                    "cve":        vuln.get("VulnerabilityID", "?"),
                    "severidade": (vuln.get("Severity") or "MEDIUM").upper(),
                    "fonte":      "trivy",
                    "titulo":     vuln.get("Title", ""),
                })
    except Exception:
        pass
    return achados


def _rodar_osv_scanner(caminho_local: str, timeout: int) -> list:
    binario = shutil.which("osv-scanner")
    if not binario:
        return []
    achados = []
    try:
        proc = subprocess.run(
            [binario, "--format", "json", f"--lockfile={caminho_local}"],
            capture_output=True, text=True, timeout=timeout,
        )
        if not proc.stdout.strip():
            return []
        dados = json.loads(proc.stdout)
        for resultado in dados.get("results", []) or []:
            for pacote in resultado.get("packages", []) or []:
                info_pkg = pacote.get("package", {})
                for vuln in pacote.get("vulnerabilities", []) or []:
                    achados.append({
                        "pacote":     info_pkg.get("name", "?"),
                        "versao":     info_pkg.get("version", "?"),
                        "cve":        vuln.get("id", "?"),
                        "severidade": _severidade_osv(vuln),
                        "fonte":      "osv-scanner",
                        "titulo":     vuln.get("summary", ""),
                    })
    except Exception:
        pass
    return achados


def _severidade_osv(vuln: dict) -> str:
    for s in vuln.get("severity", []) or []:
        score = s.get("score", "")
        try:
            valor = float(score.split("/")[0]) if "/" in str(score) else float(score)
            if valor >= 9.0: return "CRITICAL"
            if valor >= 7.0: return "HIGH"
            if valor >= 4.0: return "MEDIUM"
            return "LOW"
        except Exception:
            continue
    return "MEDIUM"


def _dedup(achados: list) -> list:
    vistos = set()
    unicos = []
    for a in achados:
        chave = (a["pacote"].lower(), a["versao"], a["cve"].upper())
        if chave in vistos:
            continue
        vistos.add(chave)
        unicos.append(a)
    return unicos
