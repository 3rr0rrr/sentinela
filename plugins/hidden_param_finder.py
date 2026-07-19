#!/usr/bin/env python3
"""
Plugin SENTINELA — Descobridor de Parâmetro Oculto (Arjun)
Criado por github.com/3rr0rrr

Roda o Arjun em endpoints descobertos pra achar parâmetros HTTP não
documentados/ocultos (GET e POST) que podem ser vetor de ataque não óbvio
(ex: um parâmetro de debug esquecido, um campo de override interno).
Reporta como INFO/LOW — descoberta de superfície, não uma vulnerabilidade
confirmada por si só.

Não roda em --mode stealth. Limite de endpoints testados.
"""

import json
import os
import shutil
import subprocess
import tempfile

from plugins.base import SentinelaPlugin

MAX_ALVOS = 8


class HiddenParamFinderPlugin(SentinelaPlugin):
    name           = "Descobridor de Parâmetro Oculto (Arjun)"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Descobre parâmetros HTTP ocultos/não documentados via Arjun"
    requires       = ["web_analysis"]
    tags           = ["web", "params", "recon"]
    severity       = "low"
    enabled        = True
    stealth        = False
    min_confidence = 0.6
    max_findings   = 15
    timeout        = 120

    def run(self, target: str, context: dict) -> list:
        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []
        if not shutil.which("arjun"):
            return []

        findings = []
        alvos = list(context.get("base_urls") or [])[:2] + list(context.get("endpoints") or [])
        vistos = set()

        for url in alvos:
            if url in vistos:
                continue
            vistos.add(url)
            if len(vistos) > MAX_ALVOS:
                break

            params = self._rodar_arjun(url, config)
            if params:
                f = self.finding(
                    severity         = "low",
                    title            = f"{len(params)} parâmetro(s) oculto(s) encontrado(s) em {url}",
                    detail           = f"Arjun encontrou parâmetro(s) não documentado(s) que o servidor aceita "
                                        f"e processa de forma diferente da ausência dele: {', '.join(params[:15])}. "
                                        f"Vale testar manualmente cada um (IDOR, debug flag, override interno).",
                    url              = url,
                    evidence         = ", ".join(params[:15]),
                    remediation      = "Remover parâmetros de debug/desenvolvimento antes de produção. "
                                        "Documentar e validar formalmente todo parâmetro que a aplicação aceita.",
                    confidence       = 0.65,
                    impact           = 3.5,
                    exploitability   = "requer-analise-manual",
                    business_context = "Parâmetro oculto pode ser um vetor de ataque não coberto por nenhum "
                                        "outro módulo — vale investigação manual, especialmente em endpoint de API.",
                )
                if f:
                    findings.append(f)

        return findings

    def _rodar_arjun(self, url: str, config: dict) -> list:
        with tempfile.NamedTemporaryFile(mode="r", suffix=".json", delete=False) as tmp:
            outfile = tmp.name
        try:
            cmd = ["arjun", "-u", url, "-oJ", outfile, "-t", str(config.get("threads", 10))]
            subprocess.run(cmd, capture_output=True, text=True,
                            timeout=min(config.get("tool_timeout", 300), 90))
            if not os.path.exists(outfile) or os.path.getsize(outfile) == 0:
                return []
            with open(outfile) as fh:
                dados = json.load(fh)
            if isinstance(dados, dict):
                for _, info in dados.items():
                    if isinstance(info, dict) and "params" in info:
                        return list(info["params"])
            return []
        except Exception:
            return []
        finally:
            try:
                os.unlink(outfile)
            except OSError:
                pass
