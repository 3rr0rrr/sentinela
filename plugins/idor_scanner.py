#!/usr/bin/env python3
"""
Plugin SENTINELA — Scanner de IDOR/BOLA
Criado por github.com/3rr0rrr

Pega endpoints descobertos que contenham um ID numérico ou UUID no path ou
query string, gera variações (id-1, id+1, id+100) e compara resposta:
status code, tamanho do corpo, e uma amostra do conteúdo. Se uma variação
retornar 200 com conteúdo que parece um recurso VÁLIDO e DIFERENTE do
original (não um erro/404 disfarçado de 200), sinaliza IDOR pra validação
manual.

Limite de variações por endpoint pra não virar brute-force de IDs.
Não roda em --mode stealth.
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


MAX_ENDPOINTS = 15
MAX_VARIACOES_POR_ENDPOINT = 6

RE_ID_PATH = re.compile(r"/(\d{1,10})(?=/|$|\?)")
RE_UUID_PATH = re.compile(
    r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=/|$|\?)"
)


class IDORScannerPlugin(SentinelaPlugin):
    name           = "Scanner de IDOR/BOLA"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Enumera variações de ID em endpoints e compara respostas pra achar bypass de autorização"
    requires       = ["web_analysis"]
    tags           = ["web", "idor", "bola", "authz"]
    severity       = "high"
    enabled        = True
    stealth        = False
    min_confidence = 0.4
    max_findings   = 15
    timeout        = 60

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        session = self._build_session(config)
        findings = []

        candidatos = self._encontrar_candidatos(context)
        for endpoint, id_original, tipo in candidatos[:MAX_ENDPOINTS]:
            try:
                base_resp = session.get(endpoint, timeout=config.get("timeout", 10), verify=False)
            except Exception:
                continue

            variacoes = self._gerar_variacoes(endpoint, id_original, tipo)
            for url_variante, id_variante in variacoes[:MAX_VARIACOES_POR_ENDPOINT]:
                try:
                    resp = session.get(url_variante, timeout=config.get("timeout", 10), verify=False)
                except Exception:
                    continue

                if self._parece_outro_recurso_valido(base_resp, resp):
                    f = self.finding(
                        severity         = "high",
                        title            = f"Possível IDOR em {endpoint}",
                        detail           = (
                            f"Variação de ID `{id_original}` → `{id_variante}` retornou HTTP {resp.status_code} "
                            f"com conteúdo estruturalmente similar mas de tamanho diferente "
                            f"({len(base_resp.content)}b → {len(resp.content)}b), sugerindo que retornou dados "
                            f"de OUTRO recurso sem checagem de propriedade/autorização. Requer validação manual "
                            f"pra confirmar que os dados realmente pertencem a outro usuário/registro."
                        ),
                        url              = url_variante,
                        evidence         = f"original: {endpoint} ({len(base_resp.content)}b) | "
                                            f"variante: {url_variante} ({len(resp.content)}b, HTTP {resp.status_code})",
                        remediation      = "Implementar checagem de autorização a nível de objeto (verificar se o "
                                            "recurso pertence ao usuário autenticado) em todo endpoint que aceita "
                                            "ID como parâmetro, não confiar apenas em autenticação.",
                        confidence       = 0.55,
                        impact           = 7.5,
                        exploitability   = "auth-dependente",
                        business_context = "IDOR confirmado expõe dados de outros usuários/clientes — "
                                            "risco direto de vazamento de dados pessoais/pedidos/pagamentos.",
                    )
                    if f:
                        findings.append(f)

        return findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _encontrar_candidatos(self, context: dict) -> list:
        candidatos = []
        for ep in (context.get("endpoints") or []):
            m = RE_ID_PATH.search(ep)
            if m:
                candidatos.append((ep, m.group(1), "path"))
                continue
            m = RE_UUID_PATH.search(ep)
            if m:
                candidatos.append((ep, m.group(1), "path_uuid"))
                continue
            parsed = urlparse(ep)
            qs = parse_qs(parsed.query)
            for chave in ("id", "user_id", "order_id", "pedido", "uid", "account_id"):
                if chave in qs and qs[chave][0].isdigit():
                    candidatos.append((ep, qs[chave][0], f"query:{chave}"))
                    break
        return candidatos

    def _gerar_variacoes(self, endpoint: str, id_original: str, tipo: str) -> list:
        variacoes = []
        if tipo == "path_uuid":
            return []  # não dá pra "incrementar" UUID de forma útil sem enumerar de verdade
        try:
            n = int(id_original)
        except ValueError:
            return []
        for delta in (-1, 1, 10, 100, -100):
            novo_id = str(n + delta)
            if novo_id == id_original or n + delta < 0:
                continue
            if tipo == "path":
                nova_url = endpoint.replace(f"/{id_original}", f"/{novo_id}", 1)
            else:
                chave = tipo.split(":", 1)[1]
                parsed = urlparse(endpoint)
                qs = parse_qs(parsed.query)
                qs[chave] = [novo_id]
                nova_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            variacoes.append((nova_url, novo_id))
        return variacoes

    def _parece_outro_recurso_valido(self, base_resp, resp) -> bool:
        if resp.status_code != 200:
            return False
        if resp.status_code == base_resp.status_code and len(resp.content) == 0:
            return False
        tamanho_base = len(base_resp.content)
        tamanho_novo = len(resp.content)
        if tamanho_base == 0:
            return False
        # Corpo muito pequeno demais costuma ser página de erro/redirect disfarçado
        if tamanho_novo < 20:
            return False

        conteudo_identico = resp.content == base_resp.content
        if conteudo_identico:
            return False  # provável cache/redirect pro mesmo recurso, não outro registro

        # Tamanho diferente é o sinal mais forte (heurística original).
        razao = tamanho_novo / tamanho_base
        if 0.5 <= razao <= 2.0 and tamanho_novo != tamanho_base:
            return True

        # Mesmo tamanho MAS conteúdo diferente também é suspeito — dados de dois
        # registros distintos podem coincidir em tamanho (ex: JSON com mesma
        # estrutura de campos e valores de comprimento parecido). Sinaliza aqui
        # também, só que com confiança menor (ajustada no finding acima seria
        # ideal, mas por simplicidade retornamos True e deixamos o `detail`
        # explicar que precisa de validação manual — já é o texto padrão).
        if tamanho_novo == tamanho_base:
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
