#!/usr/bin/env python3
"""
Plugin SENTINELA — Detector de Subdomain Takeover
Criado por github.com/3rr0rrr

Para cada subdomínio já descoberto pelo recon, resolve o CNAME e verifica se
aponta para um serviço de terceiros conhecido por permitir takeover quando o
recurso não foi reivindicado (GitHub Pages, Heroku, AWS S3, Azure, Shopify,
Fastly etc.). Quando o CNAME bate com um provedor vulnerável, faz uma única
requisição HTTP para confirmar a mensagem de erro característica de
"não reivindicado" antes de reportar.
"""

from plugins.base import SentinelaPlugin

try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# (fragmento do CNAME, nome do serviço, fingerprint de "não reivindicado" no corpo da resposta)
FINGERPRINTS = [
    ("github.io",               "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokuapp.com",           "Heroku",       "No such app"),
    ("herokudns.com",           "Heroku",       "No such app"),
    ("s3.amazonaws.com",        "AWS S3",       "NoSuchBucket"),
    ("s3-website",              "AWS S3",       "NoSuchBucket"),
    ("azurewebsites.net",       "Azure Web App","404 Web Site not found"),
    ("cloudapp.azure.com",      "Azure",        "404 Web Site not found"),
    ("myshopify.com",           "Shopify",      "Sorry, this shop is currently unavailable"),
    ("fastly.net",              "Fastly",       "Fastly error: unknown domain"),
    ("wordpress.com",           "WordPress.com","Do you want to register"),
    ("ghost.io",                "Ghost",        "The thing you were looking for is no longer here"),
    ("pantheonsite.io",         "Pantheon",     "The gods are wise"),
    ("surge.sh",                "Surge.sh",     "project not found"),
    ("bitbucket.io",            "Bitbucket",    "Repository not found"),
    ("zendesk.com",             "Zendesk",      "Help Center Closed"),
    ("unbouncepages.com",       "Unbounce",     "The requested URL was not found"),
    ("readme.io",               "ReadMe",       "Project doesnt exist"),
    ("cargocollective.com",     "Cargo",        "404 Not Found"),
    ("statuspage.io",           "Statuspage",   "You are being"),
    ("teamwork.com",            "Teamwork",     "Oops - We didn't find that team"),
]


class SubdomainTakeoverPlugin(SentinelaPlugin):
    name           = "Detector de Subdomain Takeover"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Detecta CNAMEs dangling apontando para serviços de terceiros não reivindicados"
    requires       = ["recon"]
    tags           = ["recon", "dns", "takeover"]
    severity       = "high"
    enabled        = True
    stealth        = False  # faz requisição HTTP de confirmação quando o CNAME bate
    min_confidence = 0.6
    max_findings   = 15
    timeout        = 45

    MAX_SUBDOMINIOS = 40

    def run(self, target: str, context: dict) -> list:
        if not HAS_DNSPYTHON:
            return []

        subdominios = context.get("subdomains", [])[: self.MAX_SUBDOMINIOS]
        config = context.get("config", {}) or {}
        findings = []

        for entry in subdominios:
            sub = entry.get("subdomain", "")
            if not sub:
                continue

            cname = self._resolver_cname(sub)
            if not cname:
                continue

            servico = self._identificar_servico(cname)
            if not servico:
                continue

            nome_servico, fingerprint = servico
            confirmado, evidencia = self._confirmar_takeover(sub, fingerprint, config)

            confianca = 0.9 if confirmado else 0.55
            sev = "critical" if confirmado else "medium"

            f = self.finding(
                severity         = sev,
                title            = f"Possível subdomain takeover: {sub} → {nome_servico}" + (
                                     " (confirmado)" if confirmado else " (CNAME órfão, não confirmado por HTTP)"),
                detail           = (
                    f"O subdomínio {sub} tem CNAME apontando para {cname} ({nome_servico}). "
                    + (f"A resposta HTTP confirma a mensagem característica de recurso não "
                       f"reivindicado: \"{fingerprint}\"." if confirmado else
                       "Não foi possível confirmar via HTTP (serviço pode estar indisponível ou "
                       "a mensagem de erro pode ter mudado) — verificação manual recomendada.")
                ),
                url              = f"http://{sub}",
                evidence         = evidencia or f"CNAME: {sub} → {cname}",
                remediation      = (
                    "Remover o registro CNAME órfão do DNS, ou reivindicar o recurso no serviço "
                    "de terceiros correspondente antes que um atacante o faça."
                ),
                confidence       = confianca,
                impact           = 8.0 if confirmado else 5.5,
                exploitability   = "requer apenas registrar o recurso no serviço terceiro — sem acesso prévio",
                business_context = "Permite hospedar conteúdo arbitrário (phishing, malware) sob o domínio da vítima, incluindo roubo de cookies do domínio pai.",
            )
            if f:
                findings.append(f)

        return [f for f in findings if f]

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _resolver_cname(self, subdominio: str):
        try:
            resposta = dns.resolver.resolve(subdominio, "CNAME", lifetime=5)
            return str(resposta[0].target).rstrip(".")
        except Exception:
            return None

    def _identificar_servico(self, cname: str):
        cname_low = cname.lower()
        for fragmento, servico, fingerprint in FINGERPRINTS:
            if fragmento in cname_low:
                return servico, fingerprint
        return None

    def _confirmar_takeover(self, subdominio: str, fingerprint: str, config: dict):
        if not HAS_REQUESTS:
            return False, ""
        for esquema in ("https", "http"):
            try:
                resp = requests.get(
                    f"{esquema}://{subdominio}", timeout=config.get("timeout", 8),
                    verify=False, allow_redirects=True,
                    headers={"User-Agent": config.get("user_agent", "Mozilla/5.0 SENTINELA")},
                )
                if fingerprint.lower() in resp.text.lower():
                    return True, f"GET {esquema}://{subdominio} → corpo contém \"{fingerprint}\""
            except Exception:
                continue
        return False, ""
