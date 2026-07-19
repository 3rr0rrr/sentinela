#!/usr/bin/env python3
"""
Plugin SENTINELA — Testador de Race Condition (TOCTOU)
Criado por github.com/3rr0rrr

Para endpoints de uso único (aplicação de cupom, criação de conta, resgate
de recompensa — identificados por palavra-chave no path), dispara N
requisições verdadeiramente concorrentes com o mesmo payload usando uma
barreira (threading.Barrier) pra sincronizar o disparo simultâneo, e
verifica se mais de uma teve sucesso quando deveria haver só uma.

N pequeno por padrão (--race-concurrency, default 5) — é um teste de baixo
volume, não confundir com DoS. Não roda em --mode stealth.
"""

import re
import threading

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

PALAVRAS_CHAVE_USO_UNICO = [
    "coupon", "cupom", "redeem", "resgat", "apply", "signup", "register",
    "cadastr", "voucher", "reward", "invite", "convite",
]

MAX_ALVOS = 5


class RaceConditionPlugin(SentinelaPlugin):
    name           = "Testador de Race Condition"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Dispara requisições concorrentes em endpoints de uso único pra detectar TOCTOU"
    requires       = ["web_analysis"]
    tags           = ["web", "race-condition", "toctou"]
    severity       = "high"
    enabled        = True
    stealth        = False
    min_confidence = 0.5
    max_findings   = 10
    timeout        = 60

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        n = max(2, min(int(config.get("race_concurrency", 5)), 15))
        findings = []

        alvos = self._encontrar_alvos_uso_unico(context)
        for form in alvos[:MAX_ALVOS]:
            resultado = self._disparar_concorrente(form, config, n)
            sucessos = resultado["sucessos"]
            if sucessos > 1:
                f = self.finding(
                    severity         = "high",
                    title            = f"Possível race condition em {form.get('action')}",
                    detail           = (
                        f"{sucessos} de {n} requisições concorrentes (mesmo payload, disparadas "
                        f"simultaneamente) retornaram resposta de SUCESSO em um endpoint que deveria "
                        f"processar a ação apenas uma vez. Indica ausência de lock/transação atômica "
                        f"no back-end (TOCTOU). Requer validação manual do efeito real (ex: saldo "
                        f"aplicado múltiplas vezes)."
                    ),
                    url              = form.get("action", ""),
                    evidence         = f"{sucessos}/{n} respostas de sucesso em disparo concorrente",
                    remediation      = "Usar lock otimista/pessimista ou transação atômica no back-end pra "
                                        "garantir que ações de uso único (resgate de cupom, criação de conta) "
                                        "só possam ser processadas uma vez, mesmo sob concorrência.",
                    confidence       = 0.6,
                    impact           = 7.5,
                    exploitability   = "auth-dependente",
                    business_context = "Race condition em cupom/recompensa gera prejuízo financeiro direto "
                                        "proporcional ao número de requisições concorrentes que o atacante conseguir disparar.",
                )
                if f:
                    findings.append(f)

        return findings

    def _encontrar_alvos_uso_unico(self, context: dict) -> list:
        alvos = []
        for form in (context.get("forms") or []):
            action = (form.get("action") or "").lower()
            page = (form.get("page") or "").lower()
            if any(k in action or k in page for k in PALAVRAS_CHAVE_USO_UNICO):
                alvos.append(form)
        return alvos

    def _disparar_concorrente(self, form: dict, config: dict, n: int) -> dict:
        action = form.get("action", "")
        method = form.get("method", "POST").upper()
        dados = {i["name"]: i.get("value", "teste") for i in form.get("inputs", []) if i.get("name")}

        session = self._build_session(config)
        barreira = threading.Barrier(n, timeout=10)
        resultados = []
        lock = threading.Lock()

        def worker():
            try:
                barreira.wait()
            except threading.BrokenBarrierError:
                return
            try:
                if method == "POST":
                    resp = session.post(action, data=dados, timeout=config.get("timeout", 10), verify=False)
                else:
                    resp = session.get(action, params=dados, timeout=config.get("timeout", 10), verify=False)
                sucesso = resp.status_code in (200, 201, 302) and not self._parece_erro(resp)
                with lock:
                    resultados.append(sucesso)
            except Exception:
                with lock:
                    resultados.append(False)

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=config.get("timeout", 10) + 5)

        return {"sucessos": sum(1 for r in resultados if r), "total": len(resultados)}

    def _parece_erro(self, resp) -> bool:
        corpo = (resp.text or "").lower()
        marcadores_erro = ["error", "erro", "inválido", "invalid", "já utilizado",
                            "already used", "expired", "expirado", "not found"]
        return any(m in corpo for m in marcadores_erro)

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
