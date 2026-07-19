#!/usr/bin/env python3
"""
Plugin SENTINELA — Detector de CORS Mal Configurado
Criado por github.com/3rr0rrr

Testa ativamente se o alvo reflete um Origin arbitrário (controlado pelo
atacante) de volta no header Access-Control-Allow-Origin, e se isso é
combinado com Access-Control-Allow-Credentials: true — a combinação clássica
que permite a um site malicioso ler respostas autenticadas da vítima.

Faz um número pequeno e limitado de requisições (bounded) apenas às
base_urls já conhecidas pelo scan. Não roda em --mode stealth.
"""

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


ORIGEM_TESTE = "https://sentinela-cors-check.invalid"


class CORSMisconfigPlugin(SentinelaPlugin):
    name           = "Detector de CORS Mal Configurado"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Testa reflexão de Origin arbitrário em Access-Control-Allow-Origin"
    requires       = ["web_analysis"]
    tags           = ["web", "cors", "misconfig"]
    severity       = "high"
    enabled        = True
    stealth        = False  # faz requisições ativas com Origin customizado
    min_confidence = 0.6
    max_findings   = 10
    timeout        = 30

    MAX_ALVOS = 5

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        session = self._build_session(config)

        alvos = self._coletar_alvos(target, context)
        findings = []

        for url in alvos[: self.MAX_ALVOS]:
            try:
                resp = session.get(
                    url, headers={"Origin": ORIGEM_TESTE},
                    timeout=config.get("timeout", 10), verify=False,
                    allow_redirects=True,
                )
            except Exception:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao != ORIGEM_TESTE:
                continue  # não refletiu — não é vulnerável a esse teste

            credenciais_permitidas = acac.strip().lower() == "true"
            sev = "critical" if credenciais_permitidas else "high"
            confidence = 0.95 if credenciais_permitidas else 0.85

            f = self.finding(
                severity         = sev,
                title            = "CORS reflete Origin arbitrário" + (
                                     " com credenciais habilitadas" if credenciais_permitidas else ""),
                detail           = (
                    f"O servidor respondeu com Access-Control-Allow-Origin: {acao} ao receber "
                    f"o header Origin: {ORIGEM_TESTE} (não pertence ao alvo). "
                    + (
                        "Access-Control-Allow-Credentials: true também está presente, "
                        "permitindo que um site malicioso leia respostas autenticadas da vítima "
                        "(cookies de sessão inclusos)."
                        if credenciais_permitidas else
                        "Access-Control-Allow-Credentials não está habilitado, o que limita o "
                        "impacto a endpoints que não dependem de cookies/sessão para autenticação."
                    )
                ),
                url              = url,
                evidence         = f"Origin enviado: {ORIGEM_TESTE} | ACAO recebido: {acao} | ACAC: {acac or '(ausente)'}",
                remediation      = (
                    "Nunca refletir o header Origin recebido diretamente. Usar uma allowlist "
                    "explícita de origens confiáveis no backend. Nunca combinar allowlist "
                    "dinâmica com Access-Control-Allow-Credentials: true sem validação rígida."
                ),
                confidence       = confidence,
                impact           = 8.5 if credenciais_permitidas else 6.0,
                exploitability   = "cross-origin, requer vítima acessar site controlado pelo atacante",
                business_context = "Permite roubo de dados de sessões autenticadas de outros usuários via requisição cross-origin.",
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
        if config.get("cookies"):
            session.cookies.update(config["cookies"])
        if config.get("proxy"):
            session.proxies.update(config["proxy"])
        return session

    def _coletar_alvos(self, target: str, context: dict) -> list:
        alvos = list(context.get("base_urls", [])) or [f"https://{target}"]
        # Adiciona alguns endpoints de API já descobertos, que são o alvo mais
        # típico de CORS mal configurado (endpoints de dados, não páginas HTML)
        for d in context.get("dir_brute", []):
            path = d.get("path", "")
            if d.get("status") == 200 and ("api" in path.lower() or "graphql" in path.lower()):
                base = alvos[0] if alvos else f"https://{target}"
                alvos.append(base.rstrip("/") + path)
        # dedup preservando ordem
        vistos = set()
        unicos = []
        for u in alvos:
            if u not in vistos:
                vistos.add(u)
                unicos.append(u)
        return unicos
