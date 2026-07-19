#!/usr/bin/env python3
"""
SENTINELA — Análise Estática Mobile (MobSF / mobsfscan)
Criado por github.com/3rr0rrr

Só ativa se o usuário fornecer um APK/IPA local via --mobile-app CAMINHO —
a SENTINELA não tenta "achar" o app sozinha, isso é fora do escopo de
recon web.

Prioriza `mobsfscan` (CLI simples, análise estática, sem precisar de
servidor) e usa o servidor MobSF completo (REST API, geralmente via Docker
na porta 8000) se estiver rodando localmente e o CLI não estiver
disponível. A SENTINELA não sobe o servidor MobSF sozinha — isso é setup
manual documentado no README.
"""

import json
import os
import shutil
import subprocess

from modules.utils import log, make_finding, Colors


def escanear_app_mobile(config: dict) -> dict:
    caminho = config.get("mobile_app")
    if not caminho:
        return {}

    if not os.path.isfile(caminho):
        log(f"  --mobile-app aponta pra um arquivo que não existe: {caminho}", Colors.YELLOW)
        return {"erro": "arquivo não encontrado"}

    resultado = {"caminho": caminho, "findings": []}

    if shutil.which("mobsfscan"):
        resultado["findings"] += _rodar_mobsfscan(caminho, config)
    else:
        log("  mobsfscan não instalado (pip install mobsfscan) — tentando servidor MobSF local...", Colors.YELLOW)
        resultado["findings"] += _rodar_mobsf_servidor(caminho, config)

    if not resultado["findings"]:
        log("  Nenhum scanner mobile disponível (mobsfscan ou servidor MobSF em localhost:8000) "
            "— análise mobile pulada", Colors.YELLOW)

    return resultado


def _rodar_mobsfscan(caminho: str, config: dict) -> list:
    log(f"  → mobsfscan (análise estática de {os.path.basename(caminho)})...", Colors.CYAN)
    achados = []
    try:
        proc = subprocess.run(
            ["mobsfscan", "--json", caminho],
            capture_output=True, text=True, timeout=config.get("tool_timeout", 300),
        )
        if not proc.stdout.strip():
            return []
        dados = json.loads(proc.stdout)
        for regra, info in (dados.get("results", {}) or {}).items():
            for meta in info.get("metadata", {}).get("files", []) if isinstance(info, dict) else []:
                achados.append({
                    "regra": regra,
                    "severidade": info.get("metadata", {}).get("severity", "MEDIUM"),
                    "descricao": info.get("metadata", {}).get("description", regra),
                    "arquivo": meta.get("file_path", "?"),
                })
        log(f"    {len(achados)} achado(s) de análise estática mobile", Colors.GREEN)
    except Exception as e:
        log(f"    Erro ao rodar mobsfscan: {e}", Colors.YELLOW)
    return achados


def _rodar_mobsf_servidor(caminho: str, config: dict) -> list:
    """Usa o servidor MobSF completo SE já estiver rodando localmente
    (geralmente via docker, porta 8000). A SENTINELA não sobe esse
    servidor sozinha — é setup manual, documentado no README."""
    try:
        import requests
    except ImportError:
        return []

    mobsf_url = config.get("mobsf_url", "http://localhost:8000")
    mobsf_key = config.get("mobsf_api_key") or os.environ.get("MOBSF_API_KEY")
    if not mobsf_key:
        log("    Servidor MobSF requer API key (env var MOBSF_API_KEY) — pulando", Colors.DIM)
        return []

    try:
        with open(caminho, "rb") as fh:
            resp = requests.post(f"{mobsf_url}/api/v1/upload",
                                  files={"file": fh},
                                  headers={"Authorization": mobsf_key}, timeout=30)
        if resp.status_code != 200:
            return []
        upload_info = resp.json()

        resp = requests.post(f"{mobsf_url}/api/v1/scan",
                              data=upload_info, headers={"Authorization": mobsf_key},
                              timeout=config.get("tool_timeout", 300))
        if resp.status_code != 200:
            return []

        resp = requests.post(f"{mobsf_url}/api/v1/report_json",
                              data={"hash": upload_info.get("hash")},
                              headers={"Authorization": mobsf_key}, timeout=60)
        if resp.status_code != 200:
            return []
        relatorio = resp.json()
        achados = []
        n_findings = len(relatorio.get("code_analysis", {}).get("findings", {}) or {})
        if n_findings:
            achados.append({"resumo": f"{n_findings} achado(s) de análise de código no relatório MobSF completo",
                             "hash": upload_info.get("hash")})
        return achados
    except Exception as e:
        log(f"    Erro ao consultar servidor MobSF: {e}", Colors.YELLOW)
        return []
