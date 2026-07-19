#!/usr/bin/env python3
"""
Plugin SENTINELA — Detector de GraphQL Introspection Exposta
Criado por github.com/3rr0rrr

Testa endpoints GraphQL comuns (descobertos pelo dir_brute ou por convenção
de path) com uma query de introspection padrão. Se o schema completo vier
na resposta, a API está expondo toda a sua estrutura interna (queries,
mutations, tipos, campos) — informação valiosa para reconhecimento de
ataques subsequentes.
"""

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


INTROSPECTION_QUERY = {
    "query": (
        "query IntrospectionQuery { __schema { queryType { name } "
        "mutationType { name } types { name kind fields { name } } } }"
    )
}

CANDIDATOS_PADRAO = [
    "/graphql", "/api/graphql", "/graphql/console", "/graphiql",
    "/v1/graphql", "/api/v1/graphql", "/query", "/graphql/playground",
]


class GraphQLIntrospectionPlugin(SentinelaPlugin):
    name           = "Detector de GraphQL Introspection"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Testa se endpoints GraphQL aceitam query de introspection (__schema)"
    requires       = ["web_analysis"]
    tags           = ["web", "api", "graphql"]
    severity       = "medium"
    enabled        = True
    stealth        = False  # envia requisição POST ativa
    min_confidence = 0.7
    max_findings   = 5
    timeout        = 30

    MAX_ALVOS = 6

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        session = self._build_session(config)

        candidatos = self._coletar_candidatos(target, context)
        findings = []
        testados = set()

        for url in candidatos[: self.MAX_ALVOS]:
            if url in testados:
                continue
            testados.add(url)

            schema_info = self._testar_introspection(session, url, config)
            if not schema_info:
                continue

            n_tipos = schema_info.get("n_tipos", 0)
            f = self.finding(
                severity         = "high" if n_tipos > 20 else "medium",
                title            = f"GraphQL introspection habilitada em {url}",
                detail           = (
                    f"O endpoint aceitou a query de introspection padrão e retornou o schema "
                    f"completo — {n_tipos} tipo(s) expostos, incluindo queryType="
                    f"{schema_info.get('query_type')!r} e mutationType={schema_info.get('mutation_type')!r}."
                ),
                url              = url,
                evidence         = f"POST {{query: IntrospectionQuery}} → {n_tipos} tipos no __schema",
                remediation      = (
                    "Desabilitar introspection em produção (a maioria dos frameworks GraphQL "
                    "tem uma flag para isso, ex: `introspection: false` no Apollo Server). "
                    "Se necessário para debug, restringir a ambientes internos/autenticados."
                ),
                confidence       = 0.9,
                impact           = 6.5 if n_tipos > 20 else 4.5,
                exploitability   = "pre-auth, sem necessidade de credenciais",
                business_context = "Expõe toda a estrutura da API (mutations, campos internos) para reconhecimento de ataque.",
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
            "Content-Type": "application/json",
        })
        if config.get("headers"):
            session.headers.update(config["headers"])
        if config.get("cookies"):
            session.cookies.update(config["cookies"])
        if config.get("proxy"):
            session.proxies.update(config["proxy"])
        return session

    def _coletar_candidatos(self, target: str, context: dict) -> list:
        base_urls = context.get("base_urls") or [f"https://{target}"]
        base = base_urls[0].rstrip("/")

        candidatos = []
        for d in context.get("dir_brute", []):
            path = d.get("path", "")
            if "graphql" in path.lower() and d.get("status") in (200, 400, 405):
                candidatos.append(base + path if path.startswith("/") else base + "/" + path)

        for path in CANDIDATOS_PADRAO:
            candidatos.append(base + path)

        vistos = set()
        unicos = []
        for c in candidatos:
            if c not in vistos:
                vistos.add(c)
                unicos.append(c)
        return unicos

    def _testar_introspection(self, session, url: str, config: dict):
        try:
            resp = session.post(url, json=INTROSPECTION_QUERY,
                                 timeout=config.get("timeout", 10), verify=False)
        except Exception:
            return None

        if resp.status_code != 200:
            return None

        try:
            data = resp.json()
        except Exception:
            return None

        schema = (data or {}).get("data", {}).get("__schema") if isinstance(data, dict) else None
        if not schema:
            return None

        return {
            "n_tipos":        len(schema.get("types", []) or []),
            "query_type":     (schema.get("queryType") or {}).get("name"),
            "mutation_type":  (schema.get("mutationType") or {}).get("name"),
        }
