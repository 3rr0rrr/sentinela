#!/usr/bin/env python3
"""
Plugin SENTINELA — Analisador de JWT
Criado por github.com/3rr0rrr

Analisa tokens JWT já coletados pelo scan (em js_secrets, cookies e headers
configurados) em busca de más práticas comuns: alg:none aceito, ausência de
claim `exp`, e dados sensíveis em claro no payload. NÃO tenta quebrar ou
adivinhar o segredo de assinatura — apenas sinaliza o risco.
"""

import base64
import json
import re

from plugins.base import SentinelaPlugin


SENSITIVE_CLAIMS = {
    "password", "senha", "secret", "senha_hash", "password_hash",
    "credit_card", "cartao", "cpf", "cnpj", "ssn", "api_key", "apikey",
    "email", "e-mail", "telefone", "phone",
}

PRIVILEGE_CLAIMS = {"is_admin", "isadmin", "admin", "role", "roles", "permissions", "scope"}


class JWTAnalyzerPlugin(SentinelaPlugin):
    name           = "Analisador de JWT"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Detecta más práticas em tokens JWT: alg:none, exp ausente, dados sensíveis no payload"
    requires       = ["web_analysis"]
    tags           = ["web", "auth", "jwt"]
    severity       = "high"
    enabled        = True
    stealth        = True  # só reanalisa dados já coletados, nenhuma requisição nova
    min_confidence = 0.5
    max_findings   = 20
    timeout        = 20

    def run(self, target: str, context: dict) -> list:
        findings = []
        tokens = self._coletar_tokens(context)

        vistos = set()
        for origem, token in tokens:
            token = token.rstrip(".")  # remove reticências de truncamento residuais
            if token in vistos:
                continue
            vistos.add(token)

            header, payload = self._decodificar(token)
            if header is None:
                continue

            alg = str(header.get("alg", "")).lower()

            if alg == "none":
                f = self.finding(
                    severity         = "critical",
                    title            = f"JWT aceita alg:none — bypass de assinatura",
                    detail           = f"Token encontrado em {origem} usa alg=none no header.",
                    url              = origem if origem.startswith("http") else "",
                    evidence         = json.dumps(header),
                    remediation      = "Rejeitar explicitamente tokens com alg=none na validação do servidor. "
                                        "Usar allowlist de algoritmos esperados (ex: apenas RS256).",
                    confidence       = 0.9,
                    impact           = 9.5,
                    exploitability   = "pre-auth" ,
                    business_context = "Permite forjar tokens arbitrários sem conhecer o segredo — bypass total de autenticação/autorização.",
                )
                if f:
                    findings.append(f)

            if payload is not None and "exp" not in payload:
                f = self.finding(
                    severity         = "medium",
                    title            = "JWT sem claim de expiração (exp)",
                    detail           = f"Token em {origem} não define tempo de expiração — validade indefinida.",
                    url              = origem if origem.startswith("http") else "",
                    remediation      = "Sempre definir `exp` com um tempo de vida curto e implementar revogação de tokens.",
                    confidence       = 0.7,
                    impact           = 5.5,
                    business_context = "Um token vazado permanece válido indefinidamente.",
                )
                if f:
                    findings.append(f)

            if alg.startswith("hs"):
                f = self.finding(
                    severity         = "low",
                    title            = f"JWT assinado com algoritmo simétrico ({header.get('alg')})",
                    detail           = f"Token em {origem} usa {header.get('alg')} — a segurança depende inteiramente "
                                        f"do segredo do servidor não ser fraco/previsível/vazado. Não foi feita "
                                        f"nenhuma tentativa de adivinhar o segredo.",
                    url              = origem if origem.startswith("http") else "",
                    remediation      = "Preferir RS256/ES256 (assimétrico) quando o token precisa ser validado "
                                        "por múltiplos serviços. Se HS256 for necessário, usar um segredo "
                                        "aleatório de alta entropia (≥32 bytes) e nunca reaproveitá-lo entre ambientes.",
                    confidence       = 0.55,
                    impact           = 4.0,
                    business_context = "Risco condicional — só é explorável se o segredo for fraco ou vazar.",
                )
                if f:
                    findings.append(f)

            if payload is not None:
                claims_sensiveis = [k for k in payload if k.lower() in SENSITIVE_CLAIMS]
                if claims_sensiveis:
                    f = self.finding(
                        severity         = "high",
                        title            = f"Dados sensíveis em claro no payload do JWT: {', '.join(claims_sensiveis)}",
                        detail           = f"Token em {origem} expõe claims sensíveis sem criptografia (JWT é "
                                            f"apenas assinado/codificado em base64, não criptografado).",
                        url              = origem if origem.startswith("http") else "",
                        evidence         = ", ".join(claims_sensiveis),
                        remediation      = "Nunca colocar dados sensíveis (senha, cartão, documentos) no payload "
                                            "de um JWT. Usar apenas identificadores opacos e buscar dados sensíveis "
                                            "no backend quando necessário.",
                        confidence       = 0.85,
                        impact           = 7.5,
                        business_context = "Qualquer pessoa com o token (ex: em logs, histórico do navegador) lê esses dados.",
                    )
                    if f:
                        findings.append(f)

                claims_privilegio = [k for k in payload if k.lower() in PRIVILEGE_CLAIMS]
                if claims_privilegio and alg in ("none", "hs256", "hs384", "hs512"):
                    f = self.finding(
                        severity         = "medium",
                        title            = f"Claims de privilégio no payload: {', '.join(claims_privilegio)}",
                        detail           = f"Token em {origem} carrega papel/permissão diretamente no payload "
                                            f"({', '.join(claims_privilegio)}) com algoritmo {alg or 'desconhecido'}.",
                        url              = origem if origem.startswith("http") else "",
                        remediation      = "Validar privilégios no servidor a partir de uma fonte de verdade "
                                            "(banco de dados), não confiar cegamente no claim do token.",
                        confidence       = 0.5,
                        impact           = 6.0,
                        business_context = "Se a assinatura puder ser forjada ou o alg trocado para none, o "
                                            "atacante escala privilégios diretamente no token.",
                    )
                    if f:
                        findings.append(f)

        return [f for f in findings if f]

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _coletar_tokens(self, context: dict) -> list:
        """Retorna lista de (origem, token) a partir de dados já coletados pelo scan."""
        tokens = []

        for s in context.get("js_secrets", []):
            if s.get("type") == "JWT Token":
                tokens.append((s.get("url", "js"), s.get("match", "")))

        config = context.get("config", {}) or {}
        for nome, valor in (config.get("cookies") or {}).items():
            if self._parece_jwt(valor):
                tokens.append((f"cookie:{nome}", valor))

        for nome, valor in (config.get("headers") or {}).items():
            if nome.lower() == "authorization" and "bearer" in valor.lower():
                candidato = valor.split()[-1]
                if self._parece_jwt(candidato):
                    tokens.append((f"header:{nome}", candidato))
            elif self._parece_jwt(valor):
                tokens.append((f"header:{nome}", valor))

        return tokens

    def _parece_jwt(self, valor: str) -> bool:
        return bool(re.match(r"^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*$", valor or ""))

    def _decodificar(self, token: str):
        partes = token.split(".")
        if len(partes) < 2:
            return None, None
        header = self._b64_json(partes[0])
        payload = self._b64_json(partes[1]) if len(partes) >= 2 else None
        return header, payload

    def _b64_json(self, segmento: str):
        try:
            padded = segmento + "=" * (-len(segmento) % 4)
            raw = base64.urlsafe_b64decode(padded.encode())
            return json.loads(raw)
        except Exception:
            return None
