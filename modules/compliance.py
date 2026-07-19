#!/usr/bin/env python3
"""
SENTINELA — Mapeamento de Compliance (PCI-DSS v4.0 / LGPD)
Criado por github.com/3rr0rrr

Associa tipos de finding comuns a requisitos do PCI-DSS v4.0 e artigos da
LGPD (Lei 13.709/2018), para dar contexto regulatório aos achados no
relatório final. Os requisitos citados são os mais plausivelmente
relacionados ao tipo de finding — não substituem uma análise de compliance
formal feita por um QSA (PCI) ou DPO (LGPD).
"""

import re


MAPA_COMPLIANCE = {
    "sqli": {
        "pci_dss": ["6.2.4 (prevenção de injeção de código)", "6.3.1 (identificação de vulnerabilidades)"],
        "lgpd": ["Art. 46 (medidas de segurança técnicas e administrativas)",
                 "Art. 48 (comunicação de incidente de segurança)"],
    },
    "xss": {
        "pci_dss": ["6.2.4 (prevenção de injeção de código)"],
        "lgpd": ["Art. 46 (medidas de segurança técnicas e administrativas)"],
    },
    "rce": {
        "pci_dss": ["6.2.4", "6.3.1", "11.4 (testes de penetração)"],
        "lgpd": ["Art. 46", "Art. 48"],
    },
    "secret_exposto": {
        "pci_dss": ["3.5 (proteção de chaves criptográficas)", "6.2.4",
                    "8.3 (autenticação forte / proteção de credenciais)"],
        "lgpd": ["Art. 46", "Art. 48"],
    },
    "headers_ausentes": {
        "pci_dss": ["6.2.4", "4.2.1 (criptografia de dados em trânsito)"],
        "lgpd": ["Art. 46"],
    },
    "cors_misconfig": {
        "pci_dss": ["6.2.4", "6.4.2 (proteção contra ataques comuns em aplicações web)"],
        "lgpd": ["Art. 46"],
    },
    "painel_admin_exposto": {
        "pci_dss": ["7.2 (restrição de acesso por necessidade de negócio)",
                    "8.3 (MFA para acesso administrativo)"],
        "lgpd": ["Art. 46"],
    },
    "banco_exposto": {
        "pci_dss": ["1.3 (restrição de conexões entre redes não confiáveis e o CDE)",
                    "3.5", "7.2"],
        "lgpd": ["Art. 46", "Art. 48"],
    },
    "jwt_alg_none": {
        "pci_dss": ["6.2.4", "8.3 (autenticação forte)"],
        "lgpd": ["Art. 46"],
    },
    "subdomain_takeover": {
        "pci_dss": ["6.4.2", "2.2 (hardening de configuração)"],
        "lgpd": ["Art. 46"],
    },
    "sem_https": {
        "pci_dss": ["4.2.1 (criptografia de dados em trânsito na rede pública)"],
        "lgpd": ["Art. 46"],
    },
    "cookie_sem_flags": {
        "pci_dss": ["6.2.4", "8.3"],
        "lgpd": ["Art. 46"],
    },
    "graphql_introspection": {
        "pci_dss": ["6.2.4", "6.4.2"],
        "lgpd": ["Art. 46"],
    },
}

_ALIASES = {
    "sqli": ["sqli", "sql_injection", "sql injection"],
    "xss": ["xss"],
    "rce": ["rce", "remote_code_execution", "command_injection", "commix"],
    "secret_exposto": ["secret", "api_key", "aws_key", "token_exposed", "entropy"],
    "headers_ausentes": ["security_headers", "missing_header", "csp", "hsts", "header"],
    "cors_misconfig": ["cors"],
    "painel_admin_exposto": ["admin_panel", "admin_finder", "exposed_admin"],
    "banco_exposto": ["database_exposed", "redis", "mongodb_exposed", "db_exposed"],
    "jwt_alg_none": ["jwt"],
    "subdomain_takeover": ["subdomain_takeover", "dangling_cname"],
    "sem_https": ["no_https", "missing_https", "http_only"],
    "cookie_sem_flags": ["cookie", "httponly", "secure_flag"],
    "graphql_introspection": ["graphql"],
}

# Paths que indicam escopo de e-commerce/checkout — dispara aviso de PCI-DSS no sumário executivo
PATHS_PCI = ["/checkout", "/cart", "/carrinho", "/payment", "/pagamento", "/pix", "/boleto"]


def compliance_para_finding(categoria_ou_tag: str) -> dict:
    """Retorna {"pci_dss": [...], "lgpd": [...]} para a categoria/tag informada, ou None."""
    if not categoria_ou_tag:
        return None
    chave = re.sub(r"[^a-z0-9]+", "_", categoria_ou_tag.strip().lower()).strip("_")

    if chave in MAPA_COMPLIANCE:
        return MAPA_COMPLIANCE[chave]

    for tipo, kws in _ALIASES.items():
        if any(kw in chave for kw in kws):
            return MAPA_COMPLIANCE[tipo]

    return None


def formatar_compliance(categoria_ou_tag: str) -> str:
    """Retorna uma linha de texto pronta pra exibir no relatório, ou string vazia."""
    c = compliance_para_finding(categoria_ou_tag)
    if not c:
        return ""
    partes = []
    if c.get("pci_dss"):
        partes.append("PCI-DSS " + "; ".join(c["pci_dss"]))
    if c.get("lgpd"):
        partes.append("LGPD " + "; ".join(c["lgpd"]))
    return " | ".join(partes)


def escopo_pci_aplicavel(urls_ou_paths) -> bool:
    """Verifica se algum path do alvo indica escopo de checkout/pagamento (PCI-DSS aplicável)."""
    for item in urls_ou_paths or []:
        low = str(item).lower()
        if any(p in low for p in PATHS_PCI):
            return True
    return False
