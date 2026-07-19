#!/usr/bin/env python3
"""
SENTINELA — Auxiliar de Material de Phishing (via SET)
Criado por github.com/3rr0rrr

[!] MÓDULO DE MAIOR RISCO DA FERRAMENTA [!]

Phishing/engenharia social é TIPICAMENTE UMA LINHA DE AUTORIZAÇÃO SEPARADA
no contrato de pentest, diferente de teste técnico de aplicação web. Este
módulo:

  - Fica DESLIGADO por padrão. Só ativa com --enable-phishing-module.
  - MESMO com a flag, pede uma confirmação INTERATIVA em runtime (o
    operador precisa digitar "SIM" explicitamente).
  - NUNCA envia e-mail, mensagem ou qualquer comunicação sozinho.
  - Só AJUDA A GERAR material de template (reusando templates do SET, se
    instalado) pro operador revisar e enviar manualmente por conta própria.

Se você não tem autorização por escrito ESPECÍFICA pra teste de phishing
neste engajamento, não use este módulo.
"""

import os
import shutil
import subprocess

from modules.utils import log, Colors


def confirmar_autorizacao_interativa() -> bool:
    print()
    print("=" * 70)
    print("  [!] MÓDULO DE PHISHING — CONFIRMAÇÃO OBRIGATÓRIA")
    print("=" * 70)
    print("  Phishing/engenharia social é uma linha de autorização SEPARADA")
    print("  no contrato de pentest, diferente de teste de aplicação web.")
    print()
    print("  Confirme que você tem AUTORIZAÇÃO POR ESCRITO ESPECÍFICA pra")
    print("  teste de phishing neste engajamento.")
    print("=" * 70)
    try:
        resposta = input("  Digite SIM (maiúsculo) pra confirmar e continuar: ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    return resposta == "SIM"


def gerar_material_phishing(config: dict) -> dict:
    """Só é chamada se --enable-phishing-module foi passado. Ainda assim
    exige confirmação interativa antes de fazer qualquer coisa."""
    if not config.get("enable_phishing_module"):
        return {}

    if not confirmar_autorizacao_interativa():
        log("  Confirmação não recebida — módulo de phishing NÃO executado.", Colors.YELLOW)
        return {"executado": False, "motivo": "confirmação negada/ausente"}

    outdir = os.path.join(config.get("output", "sentinela_results"), "phishing_material")
    os.makedirs(outdir, exist_ok=True)

    if not shutil.which("setoolkit") and not shutil.which("se-toolkit"):
        log("  SET (Social-Engineer Toolkit) não instalado — nenhum template gerado. "
            "Instale manualmente: https://github.com/trustedsec/social-engineer-toolkit", Colors.YELLOW)
        aviso = (
            "SET não está instalado neste sistema. A SENTINELA não instala o SET "
            "automaticamente pelo install.sh (é uma ferramenta de risco elevado, "
            "instalação deve ser deliberada e separada)."
        )
        with open(os.path.join(outdir, "LEIA-ME.txt"), "w") as fh:
            fh.write(aviso)
        return {"executado": False, "motivo": "SET não instalado", "outdir": outdir}

    log("  [!] SET disponível — abrindo interface do SET pro operador montar o material "
        "MANUALMENTE. A SENTINELA não automatiza a criação/envio de campanha.", Colors.YELLOW)

    aviso = (
        "Este diretório é só um lembrete: a criação de material de phishing deve ser "
        "feita MANUALMENTE via SET (setoolkit), com revisão humana antes de qualquer "
        "envio. A SENTINELA nunca envia e-mail/mensagem sozinha.\n\n"
        "Rode 'sudo setoolkit' você mesmo pra montar o template."
    )
    with open(os.path.join(outdir, "LEIA-ME.txt"), "w") as fh:
        fh.write(aviso)

    return {"executado": True, "outdir": outdir,
            "nota": "material deve ser montado manualmente via setoolkit — não automatizado"}
