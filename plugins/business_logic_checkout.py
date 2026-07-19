#!/usr/bin/env python3
"""
Plugin SENTINELA — Abuso de Lógica de Negócio (Checkout/E-commerce)
Criado por github.com/3rr0rrr

Focado em lojas de e-commerce (Nuvemshop e afins). Testa formulários/
endpoints de carrinho e checkout por manipulação de preço/quantidade e
bypass de etapa do fluxo.

IMPORTANTE — todo finding deste plugin é sinalizado como "requer validação
manual" por padrão: o plugin NUNCA afirma que uma compra foi concluída ou
que um preço foi realmente alterado no banco de dados do lojista, só que o
servidor ACEITOU um valor manipulado sem rejeitar (o que já é indício
forte, mas a confirmação final — como saldo do carrinho após reload, ou
efetivação do pedido — precisa ser feita manualmente por você antes de
reportar ao cliente como confirmado).

Por padrão o plugin é NÃO-DESTRUTIVO: monta e envia o request de teste mas
não finaliza nenhuma compra. Testes que teriam efeito colateral real
(resgate de cupom de verdade, confirmação final de pedido) só rodam com
config["confirm_destructive"] = True (flag --confirm-destructive).

Não roda em --mode stealth.
"""

import re

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

PATHS_CHECKOUT = ["/checkout", "/cart", "/carrinho", "/payment", "/pagamento", "/pix", "/boleto"]

CAMPOS_PRECO = ["price", "preco", "preço", "valor", "amount", "total", "subtotal", "unit_price"]
CAMPOS_QTD   = ["qty", "quantity", "quantidade", "qtd", "amount", "count"]
CAMPOS_CUPOM = ["coupon", "cupom", "discount_code", "promo", "voucher"]

MAX_ALVOS = 6


class BusinessLogicCheckoutPlugin(SentinelaPlugin):
    name           = "Abuso de Lógica de Negócio (Checkout)"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Testa manipulação de preço/quantidade e bypass de etapa em fluxo de checkout/e-commerce"
    requires       = ["web_analysis"]
    tags           = ["web", "business-logic", "ecommerce", "checkout"]
    severity       = "high"
    enabled        = True
    stealth        = False
    min_confidence = 0.3
    max_findings   = 12
    timeout        = 60

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        alvos = self._coletar_alvos_checkout(context)
        if not alvos:
            return []

        session = self._build_session(config)
        findings = []
        destrutivo_ok = bool(config.get("confirm_destructive", False))

        for form in alvos[:MAX_ALVOS]:
            findings += self._testar_manipulacao_preco_qtd(session, form, config)
            findings += self._testar_bypass_etapa(session, form, config)
            if destrutivo_ok:
                findings += self._testar_reuso_cupom(session, form, config)

        return findings

    # ── Descoberta ────────────────────────────────────────────────────────────

    def _coletar_alvos_checkout(self, context: dict) -> list:
        alvos = []
        for form in (context.get("forms") or []):
            action = (form.get("action") or "").lower()
            page = (form.get("page") or "").lower()
            if any(p in action or p in page for p in PATHS_CHECKOUT):
                alvos.append(form)
        return alvos

    # ── Testes ────────────────────────────────────────────────────────────────

    def _testar_manipulacao_preco_qtd(self, session, form: dict, config: dict) -> list:
        findings = []
        action = form.get("action", "")
        method = form.get("method", "POST").upper()
        inputs = form.get("inputs", [])

        campo_preco = next((i for i in inputs if any(c in (i.get("name") or "").lower() for c in CAMPOS_PRECO)), None)
        campo_qtd   = next((i for i in inputs if any(c in (i.get("name") or "").lower() for c in CAMPOS_QTD)), None)

        testes = []
        if campo_preco:
            testes.append((campo_preco["name"], "0.01", "preço alterado pra R$0,01"))
            testes.append((campo_preco["name"], "-100", "preço negativo"))
        if campo_qtd:
            testes.append((campo_qtd["name"], "-1", "quantidade negativa"))

        for campo, valor_malicioso, descricao in testes:
            dados = {i["name"]: i.get("value", "1") for i in inputs if i.get("name")}
            dados[campo] = valor_malicioso
            try:
                if method == "POST":
                    resp = session.post(action, data=dados, timeout=config.get("timeout", 10), verify=False)
                else:
                    resp = session.get(action, params=dados, timeout=config.get("timeout", 10), verify=False)
            except Exception:
                continue

            if resp.status_code in (200, 201, 302) and valor_malicioso in (resp.text or ""):
                f = self.finding(
                    severity         = "high",
                    title            = f"Servidor aceitou {descricao} sem rejeitar em {action}",
                    detail           = (
                        f"O campo `{campo}` foi enviado com valor manipulado (`{valor_malicioso}`) e o servidor "
                        f"respondeu HTTP {resp.status_code} refletindo esse valor de volta, sem sinal de validação "
                        f"server-side. NÃO CONFIRMADO como compra concluída com preço alterado — requer validação "
                        f"manual (ex: verificar total real do carrinho após esse request, ou finalizar em ambiente "
                        f"de teste controlado)."
                    ),
                    url              = action,
                    evidence         = f"campo={campo} valor={valor_malicioso} status={resp.status_code}",
                    remediation      = "Nunca confiar em preço/quantidade vindo do cliente — recalcular sempre "
                                        "com base no catálogo/banco de dados server-side antes de qualquer "
                                        "confirmação de pedido.",
                    confidence       = 0.4,
                    impact           = 8.5,
                    exploitability   = "auth-dependente",
                    business_context = "Manipulação de preço confirmada gera prejuízo financeiro direto — "
                                        "prioridade alta em loja de e-commerce.",
                )
                if f:
                    findings.append(f)

        return findings

    def _testar_bypass_etapa(self, session, form: dict, config: dict) -> list:
        findings = []
        page = form.get("page", "")
        if not any(p in page.lower() for p in ("/checkout", "/pagamento", "/payment")):
            return findings

        candidatos_confirmacao = [
            page.rstrip("/") + "/confirm", page.rstrip("/") + "/confirmacao",
            page.rstrip("/") + "/success", page.rstrip("/") + "/sucesso",
            page.rstrip("/") + "/complete", page.rstrip("/") + "/finalizar",
        ]
        for url in candidatos_confirmacao:
            try:
                resp = session.get(url, timeout=config.get("timeout", 10), verify=False, allow_redirects=False)
            except Exception:
                continue
            if resp.status_code == 200:
                f = self.finding(
                    severity         = "medium",
                    title            = f"Página de confirmação acessível diretamente: {url}",
                    detail           = (
                        "A URL de confirmação/sucesso do checkout respondeu HTTP 200 acessada diretamente, "
                        "sem passar pelas etapas anteriores do fluxo (carrinho → pagamento → confirmação). "
                        "Requer validação manual pra confirmar se isso realmente pula alguma validação de "
                        "pagamento ou é só uma página estática sem efeito colateral."
                    ),
                    url              = url,
                    evidence         = f"HTTP {resp.status_code} sem sessão de checkout prévia",
                    remediation      = "Validar server-side que o pedido está de fato em estado 'pago'/'confirmado' "
                                        "antes de renderizar a página de sucesso — nunca confiar só na navegação "
                                        "sequencial do usuário.",
                    confidence       = 0.35,
                    impact           = 6.0,
                    exploitability   = "requer-confirmacao",
                    business_context = "Se a página de sucesso também dispara alguma ação (liberar produto "
                                        "digital, confirmar frete), o bypass pode ser abusado diretamente.",
                )
                if f:
                    findings.append(f)
        return findings

    def _testar_reuso_cupom(self, session, form: dict, config: dict) -> list:
        """Só roda com --confirm-destructive — aplica um cupom encontrado no
        form duas vezes em sequência pra ver se é aceito indevidamente mais
        de uma vez. Efeito colateral real possível (consumir o cupom)."""
        findings = []
        inputs = form.get("inputs", [])
        campo_cupom = next((i for i in inputs if any(c in (i.get("name") or "").lower() for c in CAMPOS_CUPOM)), None)
        if not campo_cupom or not campo_cupom.get("value"):
            return findings

        action = form.get("action", "")
        method = form.get("method", "POST").upper()
        dados = {i["name"]: i.get("value", "") for i in inputs if i.get("name")}

        respostas = []
        for _ in range(2):
            try:
                if method == "POST":
                    r = session.post(action, data=dados, timeout=config.get("timeout", 10), verify=False)
                else:
                    r = session.get(action, params=dados, timeout=config.get("timeout", 10), verify=False)
                respostas.append(r)
            except Exception:
                continue

        if len(respostas) == 2 and respostas[0].status_code == 200 and respostas[1].status_code == 200:
            if len(respostas[0].content) > 0 and respostas[0].content == respostas[1].content:
                f = self.finding(
                    severity         = "medium",
                    title            = f"Cupom aceito repetidamente sem indicação de erro em {action}",
                    detail           = "O mesmo código de cupom foi enviado duas vezes em sequência e ambas "
                                        "retornaram HTTP 200 com resposta idêntica, sem mensagem de erro de "
                                        "'cupom já utilizado'. Requer confirmação manual do estado real do "
                                        "cupom no painel do lojista.",
                    url              = action,
                    evidence         = f"2 requisições idênticas, ambas HTTP 200",
                    remediation      = "Validar server-side, de forma atômica, se o cupom já foi utilizado pelo "
                                        "usuário/sessão antes de aplicar o desconto novamente.",
                    confidence       = 0.4,
                    impact           = 5.5,
                    exploitability   = "auth-dependente",
                    business_context = "Reuso de cupom gera prejuízo financeiro direto em desconto aplicado "
                                        "indevidamente múltiplas vezes.",
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
        if config.get("headers"):
            session.headers.update(config["headers"])
        if config.get("cookies"):
            session.cookies.update(config["cookies"])
        if config.get("proxy"):
            session.proxies.update(config["proxy"])
        return session
