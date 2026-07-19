#!/usr/bin/env python3
"""
Plugin SENTINELA — Auditoria Avançada de Security Headers
Criado por github.com/3rr0rrr

Vai além da checagem básica de presença/ausência de headers (já feita pelo
módulo vuln_detection): avalia a QUALIDADE do que já foi coletado em
header_audit — CSP com unsafe-inline/unsafe-eval/wildcard em qualquer
diretiva (não só script-src), presença de Permissions-Policy,
Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, e HSTS com
max-age insuficiente. Não faz nenhuma requisição nova — reanalisa os
headers já coletados pelo scan.
"""

import re

from plugins.base import SentinelaPlugin


HSTS_MAX_AGE_MINIMO = 15552000  # 180 dias — referência comum de mercado


class SecurityHeadersProPlugin(SentinelaPlugin):
    name           = "Auditoria Avançada de Security Headers"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Avalia qualidade de CSP, Permissions-Policy, COOP/COEP e HSTS a partir dos headers já coletados"
    requires       = ["vuln_detection"]
    tags           = ["web", "headers"]
    severity       = "medium"
    enabled        = True
    stealth        = True  # só reanalisa header_audit já coletado, nenhuma requisição nova
    min_confidence = 0.6
    max_findings   = 15
    timeout        = 15

    def run(self, target: str, context: dict) -> list:
        header_audit = context.get("header_audit", {})
        presentes = header_audit.get("present", {})
        ausentes  = header_audit.get("missing", {})
        url       = header_audit.get("url", f"https://{target}")
        findings  = []

        csp = presentes.get("Content-Security-Policy", "")
        if csp:
            findings += self._auditar_csp(csp, url)

        for header, label in [
            ("Permissions-Policy",            "controla acesso a APIs sensíveis do navegador (câmera, geo, microfone)"),
            ("Cross-Origin-Opener-Policy",    "isola o contexto de navegação, mitigando ataques cross-origin como Spectre"),
            ("Cross-Origin-Embedder-Policy",  "exigido para habilitar isolamento cross-origin completo (necessário p/ recursos como SharedArrayBuffer)"),
        ]:
            if header not in presentes and header not in ausentes:
                # header nem sequer foi checado na auditoria básica — não reportar (fora do escopo coletado)
                continue
            if header not in presentes:
                f = self.finding(
                    severity         = "low",
                    title            = f"Header {header} ausente",
                    detail           = f"{header} não encontrado na resposta. Esse header {label}.",
                    url              = url,
                    remediation      = f"Adicionar o header {header} com uma política restritiva apropriada ao aplicativo.",
                    confidence       = 0.75,
                    impact           = 3.5,
                    business_context = "Endurecimento defensivo — reduz superfície de ataque de navegador.",
                )
                if f:
                    findings.append(f)

        hsts = presentes.get("Strict-Transport-Security", "")
        if hsts:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            max_age = int(m.group(1)) if m else 0
            if max_age < HSTS_MAX_AGE_MINIMO:
                f = self.finding(
                    severity         = "low" if max_age > 0 else "medium",
                    title            = f"HSTS com max-age insuficiente ({max_age}s)",
                    detail           = (
                        f"Strict-Transport-Security presente, mas com max-age={max_age}s "
                        f"(recomendado: ≥{HSTS_MAX_AGE_MINIMO}s / 180 dias). Um max-age curto "
                        f"reduz a janela de proteção contra downgrade para HTTP."
                    ),
                    url              = url,
                    evidence         = hsts,
                    remediation      = f"Definir Strict-Transport-Security: max-age={HSTS_MAX_AGE_MINIMO}; "
                                        f"includeSubDomains; preload",
                    confidence       = 0.85,
                    impact           = 4.0,
                    business_context = "Janela de proteção insuficiente contra ataques de downgrade SSL-stripping.",
                )
                if f:
                    findings.append(f)
            if "includesubdomains" not in hsts.lower():
                f = self.finding(
                    severity         = "info",
                    title            = "HSTS sem includeSubDomains",
                    detail           = "Subdomínios não estão cobertos pela política HSTS — podem ainda ser acessados via HTTP.",
                    url              = url,
                    evidence         = hsts,
                    remediation      = "Adicionar includeSubDomains à política HSTS, se todos os subdomínios suportarem HTTPS.",
                    confidence       = 0.6,
                    impact           = 2.5,
                )
                if f:
                    findings.append(f)

        return [f for f in findings if f]

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _auditar_csp(self, csp: str, url: str) -> list:
        findings = []
        diretivas = self._parsear_csp(csp)

        for diretiva, valores in diretivas.items():
            if "*" in valores and diretiva not in ("report-uri", "report-to"):
                f = self.finding(
                    severity         = "high" if diretiva in ("script-src", "default-src") else "medium",
                    title            = f"CSP com wildcard '*' em {diretiva}",
                    detail           = f"A diretiva {diretiva} aceita qualquer origem — reduz drasticamente "
                                        f"a eficácia da CSP contra XSS/injeção de recursos.",
                    url              = url,
                    evidence         = f"{diretiva}: {' '.join(valores)}",
                    remediation      = f"Restringir {diretiva} a uma allowlist explícita de origens confiáveis.",
                    confidence       = 0.85,
                    impact           = 7.0 if diretiva in ("script-src", "default-src") else 4.5,
                )
                if f:
                    findings.append(f)

            if "'unsafe-inline'" in valores and diretiva in ("script-src", "default-src"):
                f = self.finding(
                    severity         = "medium",
                    title            = f"CSP permite 'unsafe-inline' em {diretiva}",
                    detail           = "Scripts inline são permitidos, o que anula grande parte da proteção "
                                        "da CSP contra XSS refletido/armazenado.",
                    url              = url,
                    evidence         = f"{diretiva}: {' '.join(valores)}",
                    remediation      = "Remover 'unsafe-inline' e usar nonces ou hashes por requisição para scripts legítimos.",
                    confidence       = 0.8,
                    impact           = 6.0,
                )
                if f:
                    findings.append(f)

            if "'unsafe-eval'" in valores and diretiva in ("script-src", "default-src"):
                f = self.finding(
                    severity         = "medium",
                    title            = f"CSP permite 'unsafe-eval' em {diretiva}",
                    detail           = "eval() e construtores dinâmicos de função são permitidos, ampliando "
                                        "a superfície de exploração de XSS baseado em DOM.",
                    url              = url,
                    evidence         = f"{diretiva}: {' '.join(valores)}",
                    remediation      = "Remover 'unsafe-eval' — refatorar código que dependa de eval()/new Function().",
                    confidence       = 0.75,
                    impact           = 5.5,
                )
                if f:
                    findings.append(f)

        if "object-src" not in diretivas and "default-src" not in diretivas:
            f = self.finding(
                severity    = "low",
                title       = "CSP sem object-src nem default-src definidos",
                detail      = "Sem esses fallbacks, plugins legados (Flash/Java applets) e alguns vetores "
                               "de injeção não ficam cobertos pela política.",
                url         = url,
                evidence    = csp[:150],
                remediation = "Definir ao menos object-src 'none' como baseline de segurança.",
                confidence  = 0.6,
                impact      = 3.0,
            )
            if f:
                findings.append(f)

        return findings

    def _parsear_csp(self, csp: str) -> dict:
        diretivas = {}
        for parte in csp.split(";"):
            parte = parte.strip()
            if not parte:
                continue
            tokens = parte.split()
            if not tokens:
                continue
            diretivas[tokens[0].lower()] = [t.strip() for t in tokens[1:]]
        return diretivas
