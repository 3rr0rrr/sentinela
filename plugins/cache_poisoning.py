#!/usr/bin/env python3
"""
Plugin SENTINELA — Web Cache Poisoning
Criado por github.com/3rr0rrr

Detecta web cache poisoning de duas formas:
  1. Se o binário `wcvs` (Web Cache Vulnerability Scanner, Hackmanit) estiver
     instalado, roda ele contra as base_urls e reporta os achados.
  2. Sempre, como heurística própria (funciona mesmo sem wcvs): envia
     headers não-keyed conhecidos (X-Forwarded-Host, X-Forwarded-Scheme,
     X-Original-URL) com um marcador único e verifica se a resposta muda de
     forma consistente com esse header sendo processado pelo back-end —
     indício de superfície de cache poisoning (confirmação de exploração
     real requer testar se a resposta envenenada é servida a OUTRO cliente,
     o que este plugin não faz — só sinaliza a superfície).

Não roda em --mode stealth.
"""

import shutil
import subprocess
import uuid

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

MAX_ALVOS = 5

HEADERS_NAO_KEYED = [
    ("X-Forwarded-Host", "sentinela-cache-poison-{marker}.invalid"),
    ("X-Forwarded-Scheme", "sentinela{marker}"),
    ("X-Original-URL", "/sentinela-cache-poison-{marker}"),
    ("X-Host", "sentinela-cache-poison-{marker}.invalid"),
]


class CachePoisoningPlugin(SentinelaPlugin):
    name           = "Web Cache Poisoning"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Detecta superfície de cache poisoning via headers não-keyed, com wcvs como complemento"
    requires       = ["web_analysis"]
    tags           = ["web", "cache-poisoning"]
    severity       = "high"
    enabled        = True
    stealth        = False
    min_confidence = 0.4
    max_findings   = 10
    timeout        = 90

    def run(self, target: str, context: dict) -> list:
        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        findings = []
        base_urls = list(context.get("base_urls") or [f"https://{target}"])[:MAX_ALVOS]

        if shutil.which("wcvs"):
            findings += self._rodar_wcvs(base_urls, config)

        if HAS_REQUESTS:
            findings += self._testar_headers_nao_keyed(base_urls, config)

        return findings

    def _rodar_wcvs(self, base_urls: list, config: dict) -> list:
        findings = []
        for url in base_urls:
            try:
                proc = subprocess.run(
                    ["wcvs", "-u", url],
                    capture_output=True, text=True, timeout=config.get("tool_timeout", 120),
                )
            except Exception:
                continue
            saida = (proc.stdout or "") + (proc.stderr or "")
            if "[VULNERABLE]" in saida or "vulnerable" in saida.lower():
                f = self.finding(
                    severity         = "high",
                    title            = f"Web Cache Poisoning confirmado (wcvs) em {url}",
                    detail           = "O wcvs identificou o alvo como vulnerável a cache poisoning. "
                                        "Ver saída completa da ferramenta pra detalhes do vetor exato.",
                    url              = url,
                    evidence         = saida[:500],
                    remediation      = "Configurar o cache pra normalizar/ignorar headers não confiáveis "
                                        "antes de gerar a chave de cache, ou desabilitar cache pra respostas "
                                        "que variam com esses headers.",
                    confidence       = 0.85,
                    impact           = 8.5,
                    exploitability   = "pre-auth",
                    business_context = "Cache poisoning confirmado permite servir conteúdo malicioso "
                                        "(XSS, redirect, defacement) pra TODOS os usuários que acessarem a "
                                        "página envenenada, não só o atacante.",
                )
                if f:
                    findings.append(f)
        return findings

    def _testar_headers_nao_keyed(self, base_urls: list, config: dict) -> list:
        findings = []
        session = self._build_session(config)

        for url in base_urls:
            try:
                resp_base = session.get(url, timeout=config.get("timeout", 10), verify=False)
            except Exception:
                continue

            for nome_header, valor_template in HEADERS_NAO_KEYED:
                marker = uuid.uuid4().hex[:8]
                valor = valor_template.format(marker=marker)
                try:
                    resp = session.get(url, headers={nome_header: valor},
                                        timeout=config.get("timeout", 10), verify=False)
                except Exception:
                    continue

                if marker in (resp.text or "") or marker in str(resp.headers):
                    f = self.finding(
                        severity         = "medium",
                        title            = f"Superfície de cache poisoning via {nome_header} em {url}",
                        detail           = (
                            f"O servidor processa/reflete o header não-keyed `{nome_header}` na resposta "
                            f"(marcador `{marker}` encontrado). Se esse endpoint for cacheado por um proxy/CDN "
                            f"que não inclui esse header na chave de cache, um atacante pode envenenar a "
                            f"resposta cacheada pra todos os usuários. NÃO foi confirmado que a resposta é "
                            f"de fato cacheada e reutilizada — requer validação manual (2ª requisição sem o "
                            f"header, checando se ainda reflete o marcador)."
                        ),
                        url              = url,
                        evidence         = f"header={nome_header} valor={valor}",
                        remediation      = "Configurar o cache pra normalizar ou remover headers não confiáveis "
                                            "antes de gerar a chave de cache (cache key).",
                        confidence       = 0.45,
                        impact           = 7.0,
                        exploitability   = "requer-confirmacao",
                        business_context = "Se confirmado como realmente cacheado, o impacto é amplo — afeta "
                                            "todos os visitantes da página, não só quem foi atacado diretamente.",
                    )
                    if f:
                        findings.append(f)

        return findings

    def _build_session(self, config: dict):
        session = requests.Session()
        session.headers.update({
            "User-Agent": config.get("user_agent",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"),
        })
        if config.get("proxy"):
            session.proxies.update(config["proxy"])
        return session
