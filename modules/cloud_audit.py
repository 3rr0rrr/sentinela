#!/usr/bin/env python3
"""
SENTINELA — Auditoria de Conta Cloud (ScoutSuite + CloudFox)
Criado por github.com/3rr0rrr

[!] IMPORTANTE: isso é FORA do escopo tradicional de "ataque ao alvo web".
ScoutSuite audita a CONFIGURAÇÃO INTEIRA de uma conta AWS/Azure/GCP (IAM,
buckets, security groups, roles etc) e CloudFox mapeia caminho de ataque
em infra cloud já acessível. Os dois precisam de CREDENCIAL CLOUD VÁLIDA
fornecida explicitamente pelo usuário (--aws-profile / --azure-subscription
/ --gcp-project) — a SENTINELA nunca tenta adivinhar ou obter credencial
cloud sozinha, e este módulo só roda se uma dessas flags for passada.

Isso é auditoria de configuração da conta cloud do CLIENTE, não do "alvo"
no sentido de superfície web pública — requer autorização/acesso explícito
do lado do cliente pra essa credencial, separado da autorização de pentest
de aplicação web.
"""

import json
import os
import shutil
import subprocess

from modules.utils import log, make_finding, Colors


def rodar_auditoria_cloud(config: dict) -> dict:
    resultado = {"scoutsuite": {}, "cloudfox": {}, "findings": []}

    aws = config.get("aws_profile")
    azure = config.get("azure_subscription")
    gcp = config.get("gcp_project")

    if not (aws or azure or gcp):
        return resultado  # nenhuma credencial fornecida — silencioso, módulo simplesmente não roda

    outdir = os.path.join(config.get("output", "sentinela_results"), "cloud_audit")
    os.makedirs(outdir, exist_ok=True)

    log("\n  [!] Auditoria de CONTA cloud — requer autorização explícita do lado do cliente "
        "pra essa credencial (fora do escopo de pentest de app web tradicional).", Colors.YELLOW)

    if shutil.which("scout") or shutil.which("scoutsuite"):
        resultado["scoutsuite"] = _rodar_scoutsuite(aws, azure, gcp, outdir, config)
    else:
        log("  ScoutSuite não instalado — pulando auditoria de configuração cloud", Colors.DIM)

    if shutil.which("cloudfox"):
        resultado["cloudfox"] = _rodar_cloudfox(aws, azure, outdir, config)
    else:
        log("  CloudFox não instalado — pulando mapeamento de caminho de ataque cloud", Colors.DIM)

    return resultado


def _rodar_scoutsuite(aws, azure, gcp, outdir: str, config: dict) -> dict:
    binario = shutil.which("scout") or shutil.which("scoutsuite")
    provedor, cmd_extra = None, []
    if aws:
        provedor, cmd_extra = "aws", ["--profile", aws]
    elif azure:
        provedor, cmd_extra = "azure", ["--subscription-id", azure]
    elif gcp:
        provedor, cmd_extra = "gcp", ["--project-id", gcp]

    log(f"  → ScoutSuite ({provedor})...", Colors.CYAN)
    cmd = [binario, provedor, *cmd_extra, "--report-dir", outdir, "--no-browser"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=config.get("tool_timeout", 600))
    except Exception as e:
        log(f"    Erro ao rodar ScoutSuite: {e}", Colors.YELLOW)
        return {"erro": str(e)}

    achados = {"relatorio_dir": outdir, "provedor": provedor,
               "sucesso": proc.returncode == 0}
    if achados["sucesso"]:
        log(f"    Relatório ScoutSuite salvo em {outdir}", Colors.GREEN)
    return achados


def _rodar_cloudfox(aws, azure, outdir: str, config: dict) -> dict:
    cmd = ["cloudfox"]
    if aws:
        cmd += ["aws", "--profile", aws, "all-checks"]
    elif azure:
        cmd += ["azure", "--subscription-id", azure, "all-checks"]
    else:
        return {}

    log(f"  → CloudFox...", Colors.CYAN)
    outfile = os.path.join(outdir, "cloudfox_output.txt")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=config.get("tool_timeout", 600))
        with open(outfile, "w") as fh:
            fh.write(proc.stdout or "")
        log(f"    Saída do CloudFox salva em {outfile}", Colors.GREEN)
        return {"output_file": outfile, "sucesso": proc.returncode == 0}
    except Exception as e:
        log(f"    Erro ao rodar CloudFox: {e}", Colors.YELLOW)
        return {"erro": str(e)}
