#!/usr/bin/env python3
"""
SENTINELA — Módulo de scoring CVSS v3.1
Criado por github.com/3rr0rrr

Implementa a fórmula oficial do CVSS v3.1 Base Score (First.org) e mantém
um dicionário de vetores sugeridos para os tipos de finding mais comuns
encontrados durante um pentest. O score CVSS é exibido nos relatórios
ADEMAIS do score próprio da SENTINELA (impact×0.6 + confidence×0.4) —
os dois têm propósitos diferentes: o score da SENTINELA prioriza o que
testar primeiro; o CVSS é o padrão de mercado usado em relatórios formais.
"""

import re


# ── PESOS OFICIAIS CVSS v3.1 ──────────────────────────────────────────────────

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def calcular_cvss_v31(vetor: str) -> dict:
    """
    Calcula o CVSS v3.1 Base Score a partir de um vetor completo.
    Formato esperado: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    Retorna: {"score": float, "severidade": str, "vetor": str}
    """
    partes = {}
    for chunk in vetor.split("/"):
        if ":" not in chunk:
            continue
        k, v = chunk.split(":", 1)
        partes[k.strip().upper()] = v.strip().upper()

    av = _AV.get(partes.get("AV", "N"), 0.85)
    ac = _AC.get(partes.get("AC", "L"), 0.77)
    ui = _UI.get(partes.get("UI", "N"), 0.85)
    scope_changed = partes.get("S", "U") == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
    pr = pr_table.get(partes.get("PR", "N"), 0.85)

    c = _CIA.get(partes.get("C", "N"), 0.0)
    i = _CIA.get(partes.get("I", "N"), 0.0)
    a = _CIA.get(partes.get("A", "N"), 0.0)

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif scope_changed:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        base_score = _roundup(min(impact + exploitability, 10))

    return {
        "score": base_score,
        "severidade": _severidade(base_score),
        "vetor": vetor,
    }


def _roundup(valor: float) -> float:
    """Arredondamento 'roundup' oficial do CVSS v3.1 (precisão de 1 casa decimal)."""
    int_valor = int(round(valor * 100000))
    if int_valor % 10000 == 0:
        return int_valor / 100000
    return (int_valor // 10000 + 1) / 10.0


def _severidade(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ── VETORES SUGERIDOS POR TIPO DE FINDING ────────────────────────────────────
# Cada entrada documenta o porquê do vetor escolhido — são vetores plausíveis
# para o cenário "típico" desse tipo de achado; ajuste conforme o contexto real.

VETORES_POR_TIPO = {
    "sqli_confirmado": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "motivo": "SQLi confirmado via sqlmap costuma permitir leitura/escrita total "
                  "do banco e, em muitos casos, RCE via funcionalidades do SGBD — "
                  "impacto total em C/I/A, scope changed pois compromete dados fora "
                  "do processo da aplicação.",
    },
    "rce": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "motivo": "Execução remota de código = controle total do servidor.",
    },
    "xss_refletido": {
        "vetor": "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "motivo": "Requer vítima clicar em link malicioso (UI:R); compromete sessão/dados "
                  "do usuário, não do servidor.",
    },
    "xss_armazenado": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
        "motivo": "Não requer interação da vítima além de visitar a página — persiste no "
                  "servidor e afeta qualquer visitante.",
    },
    "lfi": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "motivo": "Local File Inclusion tipicamente vaza arquivos sensíveis (senhas, "
                  "configs) sem afetar integridade/disponibilidade diretamente.",
    },
    "secret_exposto": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "motivo": "Chave de API/token exposta em JS ou resposta pública — confidencialidade "
                  "comprometida, impacto em I/A depende do que a chave permite fazer.",
    },
    "painel_admin_exposto": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "motivo": "Exposição do painel por si só é informativa/baixo impacto direto — "
                  "o risco real depende de credenciais fracas ou vulns adicionais no painel.",
    },
    "banco_exposto_externamente": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "motivo": "Banco de dados (Redis, MongoDB, MySQL etc.) acessível diretamente da "
                  "internet sem autenticação = comprometimento total dos dados.",
    },
    "cors_misconfig": {
        "vetor": "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "motivo": "CORS mal configurado permite leitura de respostas autenticadas via "
                  "origem maliciosa — requer vítima acessar site controlado pelo atacante.",
    },
    "jwt_alg_none": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "motivo": "Aceitar alg=none permite forjar tokens arbitrários sem assinatura — "
                  "equivale a bypass total de autenticação/autorização.",
    },
    "headers_seguranca_ausentes": {
        "vetor": "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "motivo": "Ausência de CSP/HSTS/etc. por si só não é explorável diretamente — "
                  "aumenta a superfície para outros ataques (clickjacking, XSS).",
    },
    "subdomain_takeover": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N",
        "motivo": "Permite ao atacante hospedar conteúdo arbitrário sob o domínio da "
                  "vítima — phishing, roubo de cookies de sessão do domínio pai.",
    },
    "graphql_introspection_exposta": {
        "vetor": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "motivo": "Expõe todo o schema da API (nomes de campos, mutations, tipos) — "
                  "facilita reconhecimento para ataques subsequentes.",
    },
}


def cvss_para_finding(categoria_ou_tag: str) -> dict:
    """
    Busca um vetor CVSS plausível para uma categoria/tag de finding.
    Faz correspondência aproximada (case-insensitive, por substring) contra as
    chaves de VETORES_POR_TIPO. Se não houver correspondência clara, retorna None
    — a finding fica sem CVSS no relatório em vez de exibir um valor inventado.
    """
    if not categoria_ou_tag:
        return None
    chave = re.sub(r"[^a-z0-9]+", "_", categoria_ou_tag.strip().lower()).strip("_")

    if chave in VETORES_POR_TIPO:
        entry = VETORES_POR_TIPO[chave]
        return {**calcular_cvss_v31(entry["vetor"]), "motivo": entry["motivo"]}

    # correspondência aproximada por palavras-chave
    aliases = {
        "sqli_confirmado":              ["sqli", "sql_injection", "sql injection"],
        "rce":                          ["rce", "remote_code_execution", "command_injection", "commix"],
        "xss_refletido":                ["reflected_xss", "xss_reflected", "xss (reflected)"],
        "xss_armazenado":               ["stored_xss", "xss_stored", "persistent_xss"],
        "lfi":                          ["lfi", "local_file_inclusion", "path_traversal"],
        "secret_exposto":               ["secret", "api_key", "aws_key", "token_exposed", "entropy"],
        "painel_admin_exposto":         ["admin_panel", "admin_finder", "exposed_admin"],
        "banco_exposto_externamente":   ["database_exposed", "redis", "mongodb_exposed", "db_exposed"],
        "cors_misconfig":               ["cors"],
        "jwt_alg_none":                 ["jwt"],
        "headers_seguranca_ausentes":   ["security_headers", "missing_header", "csp", "hsts"],
        "subdomain_takeover":           ["subdomain_takeover", "dangling_cname"],
        "graphql_introspection_exposta":["graphql"],
    }
    for tipo, kws in aliases.items():
        if any(kw in chave for kw in kws):
            entry = VETORES_POR_TIPO[tipo]
            return {**calcular_cvss_v31(entry["vetor"]), "motivo": entry["motivo"]}

    return None
