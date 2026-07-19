#!/usr/bin/env python3
"""
Plugin SENTINELA — Testador de SSTI (Server-Side Template Injection)
Criado por github.com/3rr0rrr

Testa parâmetros de formulários e query strings descobertos com payloads
matemáticos de detecção (ex: {{7*7}}) e verifica se o resultado calculado
(49, 7777777 etc) aparece refletido na resposta — prova de execução
server-side, não apenas reflexão de texto (o que seria XSS, não SSTI).

Não tenta RCE completo — só confirma a injeção com a menor prova possível.
Faz um número pequeno e limitado de requisições. Não roda em --mode stealth.
"""

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# (payload, resultado_esperado_se_executado, motor_provável)
PAYLOADS_SSTI = [
    ("{{7*7}}",       "49",      "Jinja2/Twig/Nunjucks"),
    ("${7*7}",        "49",      "FreeMarker/Velocity/Thymeleaf"),
    ("#{7*7}",        "49",      "Ruby ERB/JSF EL"),
    ("<%= 7*7 %>",    "49",      "ERB (Ruby)/EJS"),
    ("{{7*'7'}}",     "7777777", "Jinja2 (distingue de Twig, que dá erro nesse payload)"),
    ("*{7*7}",        "49",      "Thymeleaf"),
    ("@(7*7)",        "49",      "Razor (.NET)"),
]

MAX_ALVOS = 8


class SSTITesterPlugin(SentinelaPlugin):
    name           = "Testador de SSTI"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Detecta Server-Side Template Injection via payloads matemáticos"
    requires       = ["web_analysis"]
    tags           = ["web", "ssti", "injection"]
    severity       = "critical"
    enabled        = True
    stealth        = False  # faz requisições ativas com payload de injeção
    min_confidence = 0.7
    max_findings   = 10
    timeout        = 60

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        session = self._build_session(config)
        findings = []
        vistos = set()

        for form in (context.get("forms") or [])[:MAX_ALVOS]:
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = [i for i in form.get("inputs", []) if i.get("name") and i.get("type") not in ("submit", "button", "hidden")]
            if not action or not inputs:
                continue

            for payload, esperado, motor in PAYLOADS_SSTI:
                chave = (action, payload)
                if chave in vistos:
                    continue
                vistos.add(chave)

                dados = {i["name"]: (payload if i is inputs[0] else i.get("value", "teste"))
                         for i in inputs}
                try:
                    if method == "POST":
                        resp = session.post(action, data=dados, timeout=config.get("timeout", 10), verify=False)
                    else:
                        resp = session.get(action, params=dados, timeout=config.get("timeout", 10), verify=False)
                except Exception:
                    continue

                if esperado in (resp.text or "") and payload not in resp.text:
                    f = self.finding(
                        severity         = "critical",
                        title            = f"SSTI confirmado em {action} (motor provável: {motor})",
                        detail           = (
                            f"Payload `{payload}` foi avaliado pelo servidor e retornou `{esperado}` "
                            f"na resposta — o template está sendo interpretado, não só refletido "
                            f"(o que seria XSS). Campo testado: {inputs[0].get('name')}."
                        ),
                        url              = action,
                        evidence         = f"payload={payload} -> resposta contém {esperado}",
                        remediation      = "Nunca renderizar entrada do usuário diretamente como template. "
                                            "Usar sandboxing do motor de template (ex: Jinja2 SandboxedEnvironment) "
                                            "ou tratar entrada como dado puro, nunca como código de template.",
                        confidence       = 0.9,
                        impact           = 9.8,
                        exploitability   = "pre-auth" if method == "GET" else "auth-dependente",
                        business_context = "SSTI normalmente escala pra RCE completo — comprometimento total do servidor.",
                    )
                    if f:
                        findings.append(f)
                    break  # já confirmou nesse campo, não precisa testar os outros payloads

        return findings

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
