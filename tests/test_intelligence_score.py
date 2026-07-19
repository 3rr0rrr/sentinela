"""Testes da fórmula de score da Intelligence Engine (modules/intelligence.py),
usando os exemplos documentados no docstring de calc_score() como casos de referência."""

from modules.intelligence import calc_score, score, score_to_severity


def test_calc_score_sqli_exemplo_do_docstring():
    assert calc_score(10, 0.90) == 9.6


def test_calc_score_xss_exemplo_do_docstring():
    assert calc_score(6, 0.50) == 5.6


def test_calc_score_headers_exemplo_do_docstring():
    assert calc_score(3, 0.90) == 5.4


def test_calc_score_auth_requerido_reduz_score():
    assert calc_score(8, 0.80, exploitability=0.7) == 5.6
    assert score_to_severity(calc_score(8, 0.80, exploitability=0.7)) == "MEDIUM"


def test_calc_score_business_impact_aumenta_score_ate_o_teto():
    assert calc_score(10, 0.90, business_impact=1.5) == 10.0


def test_calc_score_nunca_ultrapassa_dez():
    assert calc_score(10, 1.0, exploitability=2.0, business_impact=2.0) == 10.0


def test_score_alias_shorthand():
    assert score(10, 9) == 9.6


def test_score_to_severity_thresholds():
    assert score_to_severity(9.0) == "CRITICAL"
    assert score_to_severity(8.99) == "HIGH"
    assert score_to_severity(7.0) == "HIGH"
    assert score_to_severity(6.99) == "MEDIUM"
    assert score_to_severity(5.0) == "MEDIUM"
    assert score_to_severity(4.99) == "LOW"
    assert score_to_severity(3.0) == "LOW"
    assert score_to_severity(2.99) == "INFO"
    assert score_to_severity(0.0) == "INFO"
