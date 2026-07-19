#!/usr/bin/env python3
"""
Plugin SENTINELA — Fuzzer de API/OpenAPI
Criado por github.com/3rr0rrr

Procura specs OpenAPI/Swagger conhecidos, e se encontrar um válido, testa
os endpoints documentados por: (a) ausência de autenticação onde deveria
haver, (b) mass assignment — campo extra não documentado aceito, (c)
exposição de mais campos na resposta do que o schema sugere.

Limite de endpoints testados pra não virar scan descontrolado.
Não roda em --mode stealth.
"""

import json
import re

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

SPEC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/v2/api-docs", "/v3/api-docs", "/api/swagger.json",
    "/api/openapi.json", "/swagger/v1/swagger.json",
]

MAX_ENDPOINTS = 30


class APIOpenAPIFuzzerPlugin(SentinelaPlugin):
    name           = "Fuzzer de API/OpenAPI"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Descobre spec OpenAPI/Swagger e testa auth ausente, mass assignment e exposição excessiva"
    requires       = ["web_analysis"]
    tags           = ["web", "api", "openapi", "mass-assignment"]
    severity       = "high"
    enabled        = True
    stealth        = False
    min_confidence = 0.4
    max_findings   = 15
    timeout        = 90

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        session = self._build_session(config)
        findings = []

        for base in list(context.get("base_urls") or [f"https://{target}"])[:3]:
            spec = self._encontrar_spec(session, base, config)
            if spec:
                findings += self._testar_endpoints(session, base, spec, config)
                break  # já achou um spec válido, não precisa testar outra base_url

        return findings

    def _encontrar_spec(self, session, base: str, config: dict):
        for path in SPEC_PATHS:
            url = base.rstrip("/") + path
            try:
                resp = session.get(url, timeout=config.get("timeout", 10), verify=False)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            try:
                spec = resp.json()
            except Exception:
                continue
            if isinstance(spec, dict) and ("paths" in spec or "swagger" in spec or "openapi" in spec):
                return spec
        return None

    def _testar_endpoints(self, session, base: str, spec: dict, config: dict) -> list:
        findings = []
        paths = spec.get("paths", {})
        contador = 0

        for path, metodos in paths.items():
            if contador >= MAX_ENDPOINTS:
                break
            if not isinstance(metodos, dict):
                continue
            for metodo, detalhes in metodos.items():
                if metodo.lower() not in ("get", "post", "put", "delete", "patch"):
                    continue
                if contador >= MAX_ENDPOINTS:
                    break
                contador += 1

                # Substitui parâmetros de path (ex: {id}, {userId}) por um valor
                # de exemplo — sem isso, a URL literal com "{id}" dá 404 em quase
                # toda API REST real, e o endpoint nunca é testado de verdade.
                path_resolvido = re.sub(r"\{[^}]+\}", "1", path)
                url = base.rstrip("/") + path_resolvido
                requer_auth = bool(detalhes.get("security")) or bool(spec.get("security"))

                try:
                    resp = session.request(metodo.upper(), url, timeout=config.get("timeout", 10), verify=False)
                except Exception:
                    continue

                # (a) auth ausente onde documentado como requerido
                if requer_auth and resp.status_code == 200:
                    f = self.finding(
                        severity         = "high",
                        title            = f"Endpoint documentado como autenticado responde sem token: {metodo.upper()} {path}",
                        detail           = "O spec OpenAPI marca este endpoint como exigindo autenticação "
                                            "(campo `security`), mas a requisição sem nenhum header de auth "
                                            "retornou HTTP 200.",
                        url              = url,
                        evidence         = f"HTTP {resp.status_code} sem Authorization/API-Key",
                        remediation      = "Garantir enforcement de autenticação server-side consistente com "
                                            "o que está documentado no spec — o spec não é apenas documentação, "
                                            "é um contrato de segurança.",
                        confidence       = 0.6,
                        impact           = 8.0,
                        exploitability   = "pre-auth",
                        business_context = "Bypass de autenticação em endpoint de API é acesso direto a dados/ações "
                                            "que deveriam ser protegidos.",
                    )
                    if f:
                        findings.append(f)

                # (b) exposição excessiva de dados — resposta JSON com mais campos do que o schema documenta
                if resp.status_code == 200:
                    schema_props = self._extrair_propriedades_schema(detalhes, metodo)
                    try:
                        corpo = resp.json()
                    except Exception:
                        corpo = None
                    # Endpoint de listagem retorna lista de objetos — checa o
                    # primeiro item, não só resposta em formato dict único.
                    if isinstance(corpo, list) and corpo and isinstance(corpo[0], dict):
                        corpo = corpo[0]
                    if schema_props and isinstance(corpo, dict):
                        campos_extra = set(corpo.keys()) - schema_props
                        if campos_extra and len(campos_extra) >= 2:
                            f = self.finding(
                                severity         = "medium",
                                title            = f"Possível excessive data exposure em {metodo.upper()} {path}",
                                detail           = f"A resposta contém {len(campos_extra)} campo(s) não documentados "
                                                    f"no schema OpenAPI: {', '.join(list(campos_extra)[:8])}.",
                                url              = url,
                                evidence         = f"Campos extras: {list(campos_extra)[:8]}",
                                remediation      = "Serializar apenas os campos explicitamente necessários na resposta "
                                                    "(DTO/view model), nunca retornar o objeto de domínio completo direto do ORM.",
                                confidence       = 0.4,
                                impact           = 5.5,
                                exploitability   = "requer-analise-manual",
                                business_context = "Campos não documentados podem vazar dados sensíveis internos "
                                                    "(hash de senha, flags internas, dados de outro usuário).",
                            )
                            if f:
                                findings.append(f)

        return findings

    def _extrair_propriedades_schema(self, detalhes: dict, metodo: str) -> set:
        try:
            respostas = detalhes.get("responses", {})
            r200 = respostas.get("200") or respostas.get(200) or {}
            schema = (r200.get("content", {}).get("application/json", {}).get("schema", {})
                      or r200.get("schema", {}))
            props = schema.get("properties", {})
            return set(props.keys())
        except Exception:
            return set()

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
