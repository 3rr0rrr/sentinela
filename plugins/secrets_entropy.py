#!/usr/bin/env python3
"""
Plugin SENTINELA — Scanner de Segredos por Entropia
Criado por github.com/3rr0rrr

Além dos padrões conhecidos já cobertos pelo web_analysis (AWS, Stripe,
Google etc.), este plugin refaz o download de um número limitado de
arquivos JS já descobertos pelo scan e aplica: (1) os mesmos padrões
conhecidos, de forma independente, e (2) um scanner de entropia de Shannon
sobre strings "parecidas com token/senha" que não bateram em nenhum padrão
conhecido — captura segredos custom que uma regex fixa não pegaria.
"""

import math
import re

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


PADROES_CONHECIDOS = {
    "AWS Access Key":  r"AKIA[0-9A-Z]{16}",
    "Stripe Live Key": r"(?:r|s)k_live_[0-9a-zA-Z]{24}",
    "Google API Key":  r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":    r"ghp_[0-9a-zA-Z]{36}",
    "Slack Token":     r"xox[baprs]-[0-9a-zA-Z-]+",
}

# strings candidatas a segredo genérico: sequência alfanumérica/símbolos comuns
# de comprimento >= 20, atribuída a uma variável com nome sugestivo
CANDIDATO_GENERICO = re.compile(
    r"(?i)(?:key|token|secret|senha|password|auth|api)[a-z0-9_]{0,20}"
    r"""\s*[:=]\s*['"]([A-Za-z0-9+/_.\-]{20,100})['"]"""
)


class SecretsEntropyPlugin(SentinelaPlugin):
    name           = "Scanner de Segredos por Entropia"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Detecta segredos hardcoded via padrões conhecidos + entropia de Shannon em arquivos JS"
    requires       = ["web_analysis"]
    tags           = ["web", "secrets", "recon"]
    severity       = "high"
    enabled        = True
    stealth        = False  # refaz download de arquivos JS
    min_confidence = 0.5
    max_findings   = 25
    timeout        = 60

    MAX_ARQUIVOS = 12
    LIMIAR_ENTROPIA = 4.0  # bits/caractere — acima disso, "parece" aleatório o suficiente

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        js_files = list(context.get("js_files", []))[: self.MAX_ARQUIVOS]
        if not js_files:
            return []

        config = context.get("config", {}) or {}
        session = self._build_session(config)
        findings = []
        vistos = set()

        for js_url in js_files:
            try:
                resp = session.get(js_url, timeout=config.get("timeout", 10), verify=False)
            except Exception:
                continue
            corpo = resp.text or ""

            for nome, padrao in PADROES_CONHECIDOS.items():
                for match in re.findall(padrao, corpo):
                    chave = (nome, match[:40])
                    if chave in vistos:
                        continue
                    vistos.add(chave)
                    f = self.finding(
                        severity         = "critical",
                        title            = f"{nome} exposta em {js_url}",
                        detail           = f"Padrão conhecido de {nome} encontrado no corpo do arquivo JS.",
                        url              = js_url,
                        evidence         = match[:60] + ("..." if len(match) > 60 else ""),
                        remediation      = "Remover a chave do código client-side. Revogar e rotacionar "
                                            "a chave imediatamente — presuma que já foi comprometida.",
                        confidence       = 0.9,
                        impact           = 9.0,
                        business_context = "Chave de serviço externo exposta publicamente — uso indevido pode gerar custo direto ou vazamento de dados.",
                    )
                    if f:
                        findings.append(f)

            for match in CANDIDATO_GENERICO.finditer(corpo):
                candidato = match.group(1)
                if any(candidato in m for (_, m) in vistos):
                    continue
                entropia = self._shannon_entropy(candidato)
                if entropia < self.LIMIAR_ENTROPIA:
                    continue
                chave = ("entropy", candidato[:40])
                if chave in vistos:
                    continue
                vistos.add(chave)
                f = self.finding(
                    severity         = "medium",
                    title            = f"String de alta entropia parecida com segredo em {js_url}",
                    detail           = (
                        f"Encontrada string de {len(candidato)} caracteres com entropia de "
                        f"{entropia:.2f} bits/char (limiar: {self.LIMIAR_ENTROPIA}), atribuída a uma "
                        f"variável com nome sugestivo de segredo. Não corresponde a nenhum padrão "
                        f"conhecido — pode ser um token/chave customizado ou um falso positivo."
                    ),
                    url              = js_url,
                    evidence         = candidato[:60] + ("..." if len(candidato) > 60 else ""),
                    remediation      = "Revisar manualmente. Se for um segredo real, remover do código "
                                        "client-side e mover para variável de ambiente no backend.",
                    confidence       = 0.5,
                    impact           = 6.0,
                    business_context = "Segredo custom não coberto por regex conhecida — requer triagem manual.",
                )
                if f:
                    findings.append(f)

        return [f for f in findings if f]

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _build_session(self, config: dict):
        session = requests.Session()
        session.headers.update({
            "User-Agent": config.get("user_agent",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"),
        })
        if config.get("headers"):
            session.headers.update(config["headers"])
        if config.get("proxy"):
            session.proxies.update(config["proxy"])
        return session

    def _shannon_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((count / n) * math.log2(count / n) for count in freq.values())
