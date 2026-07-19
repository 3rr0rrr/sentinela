#!/usr/bin/env python3
"""
Plugin SENTINELA — Coletor BloodHound (mapeamento de caminho de ataque em AD)
Criado por github.com/3rr0rrr

Só roda se: (1) ambiente Active Directory detectado (porta 389/636 LDAP ou
88 Kerberos aberta) e (2) credenciais de domínio fornecidas (reusa as
mesmas flags do Kerberoasting: --kerberos-user/--kerberos-pass/
--kerberos-domain — não duplica flag).

Roda `bloodhound-python -c all` e salva o JSON de coleta no diretório de
resultados. Não analisa o grafo — só coleta e sinaliza que os arquivos
podem ser importados na interface do BloodHound pra visualizar caminhos
de ataque até Domain Admin.
"""

import os
import shutil
import socket
import subprocess

from plugins.base import SentinelaPlugin


class BloodhoundCollectorPlugin(SentinelaPlugin):
    name           = "Coletor BloodHound"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Coleta dados de AD via bloodhound-python pra mapeamento de caminho de ataque"
    requires       = ["recon"]
    tags           = ["ad", "bloodhound", "attack-path"]
    severity       = "info"
    enabled        = True
    stealth        = False
    min_confidence = 0.9
    max_findings   = 1
    timeout        = 300

    def run(self, target: str, context: dict) -> list:
        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive" or config.get("mode") == "stealth":
            return []

        if not self._ad_detectado(target, context):
            return []

        domain = config.get("kerberos_domain")
        user = config.get("kerberos_user")
        password = config.get("kerberos_pass")
        if not (domain and user and password):
            return []  # sem credencial, sem coleta — silencioso, Kerberoasting já avisa sobre isso

        if not shutil.which("bloodhound-python"):
            self.log("bloodhound-python não instalado", "warn")
            return []

        outdir = os.path.join(config.get("output", "sentinela_results"), "bloodhound")
        os.makedirs(outdir, exist_ok=True)
        dc_ip = target.split(":")[0].split("/")[0]

        cmd = [
            "bloodhound-python", "-u", user, "-p", password, "-d", domain,
            "-ns", dc_ip, "-c", "all", "--zip",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, cwd=outdir,
                                   timeout=config.get("tool_timeout", 300))
        except Exception as e:
            self.log(f"Erro ao rodar bloodhound-python: {e}", "error")
            return []

        arquivos = [f for f in os.listdir(outdir) if f.endswith((".json", ".zip"))]
        if not arquivos:
            self.log("bloodhound-python não gerou arquivos de saída (verifique credenciais/conectividade LDAP)", "warn")
            return []

        f = self.finding(
            severity         = "info",
            title            = f"Dados de BloodHound coletados ({len(arquivos)} arquivo(s))",
            detail           = (
                f"Coleta de AD via bloodhound-python concluída. Arquivos salvos em `{outdir}` "
                f"({', '.join(arquivos[:6])}). Importe no BloodHound (interface gráfica) pra visualizar "
                f"caminhos de ataque até Domain Admin — este plugin só coleta, não analisa o grafo."
            ),
            url              = f"ldap://{dc_ip}",
            evidence         = f"{len(arquivos)} arquivo(s) em {outdir}",
            remediation      = "Revisar caminhos de ataque encontrados no BloodHound e remover permissões/"
                                "relações desnecessárias (ex: usuários com GenericAll indevido em objetos "
                                "de alto privilégio).",
            confidence       = 0.95,
            impact           = 5.0,
            exploitability   = "requer-credencial-dominio",
            business_context = "Visualização de caminho de ataque é essencial pra priorizar remediação de "
                                "AD — nem todo finding individual é crítico, mas a combinação de relações pode ser.",
        )
        return [f] if f else []

    def _ad_detectado(self, target: str, context: dict) -> bool:
        open_ports = context.get("open_ports") or {}
        for host, portas in open_ports.items():
            if any(p in portas or str(p) in portas for p in (88, 389, 636)):
                return True

        host = target.split(":")[0].split("/")[0]
        for porta in (389, 88):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((host, porta)) == 0:
                    s.close()
                    return True
                s.close()
            except Exception:
                continue
        return False
