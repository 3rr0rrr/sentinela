"""Testes da fórmula CVSS v3.1 (modules/cvss.py) contra vetores de referência conhecidos."""

from modules.cvss import calcular_cvss_v31, cvss_para_finding


def test_vetor_critico_generico_sem_scope_change():
    # Vetor "textbook" pra RCE não autenticada — referência FIRST.org: 9.8 / Critical
    r = calcular_cvss_v31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert r["score"] == 9.8
    assert r["severidade"] == "Critical"


def test_vetor_log4shell_scope_changed():
    # Vetor oficial do CVE-2021-44228 (Log4Shell) — NVD: 10.0 / Critical
    r = calcular_cvss_v31("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert r["score"] == 10.0
    assert r["severidade"] == "Critical"


def test_vetor_sem_impacto_e_none():
    r = calcular_cvss_v31("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert r["score"] == 0.0
    assert r["severidade"] == "None"


def test_severidade_thresholds():
    from modules.cvss import _severidade
    assert _severidade(0.0)  == "None"
    assert _severidade(3.9)  == "Low"
    assert _severidade(4.0)  == "Medium"
    assert _severidade(6.9)  == "Medium"
    assert _severidade(7.0)  == "High"
    assert _severidade(8.9)  == "High"
    assert _severidade(9.0)  == "Critical"


def test_roundup_nao_arredonda_valor_exato():
    from modules.cvss import _roundup
    assert _roundup(7.0) == 7.0


def test_roundup_sempre_pra_cima():
    from modules.cvss import _roundup
    # 7.51 tem que virar 7.6, nunca 7.5 (roundup oficial do CVSS, não é round() comum)
    assert _roundup(7.51) == 7.6


def test_cvss_para_finding_match_direto():
    r = cvss_para_finding("sqli_confirmado")
    assert r is not None
    assert r["score"] > 9.0
    assert "motivo" in r


def test_cvss_para_finding_match_por_alias():
    r = cvss_para_finding("Reflected XSS")
    assert r is not None
    assert r["score"] > 0


def test_cvss_para_finding_sem_match_retorna_none():
    assert cvss_para_finding("categoria_totalmente_desconhecida_xyz") is None


def test_cvss_para_finding_string_vazia_retorna_none():
    assert cvss_para_finding("") is None
    assert cvss_para_finding(None) is None
