#!/usr/bin/env python3
"""
Plugin SENTINELA — Detector de HTTP Request Smuggling
Criado por github.com/3rr0rrr

Testa desync CL.TE e TE.CL enviando requisições com Content-Length e
Transfer-Encoding conflitantes via socket raw (a biblioteca requests
normaliza/corrige esses headers automaticamente, então não dá pra usar
ela aqui). Mede timing anômalo de resposta como indício de desync.

IMPORTANTE: isso é detecção HEURÍSTICA. Timing anômalo pode ter outras
causas (rede lenta, servidor sob carga). Todo finding aqui deve ser
validado manualmente antes de reportar como confirmado — a exploração
real de smuggling é sensível a race conditions e infraestrutura
intermediária (CDN/load balancer) que este teste não modela.

Não roda em --mode stealth. Volume de requisições bem limitado (2 por alvo).
"""

import socket
import ssl
import time
from urllib.parse import urlparse

from plugins.base import SentinelaPlugin

MAX_ALVOS = 4
TIMEOUT_SOCKET = 10


class HTTPSmugglingPlugin(SentinelaPlugin):
    name           = "Detector de HTTP Request Smuggling"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Testa desync CL.TE/TE.CL via requisições com headers conflitantes"
    requires       = ["web_analysis"]
    tags           = ["web", "smuggling", "desync"]
    severity       = "high"
    enabled        = True
    stealth        = False
    min_confidence = 0.4
    max_findings   = 8
    timeout        = 60

    def run(self, target: str, context: dict) -> list:
        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        findings = []
        base_urls = list(context.get("base_urls") or [f"https://{target}"])

        for base in base_urls[:MAX_ALVOS]:
            parsed = urlparse(base)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            usa_tls = parsed.scheme == "https"
            if not host:
                continue

            try:
                cl_te = self._teste_cl_te(host, port, usa_tls, config.get("timeout", 10))
                te_cl = self._teste_te_cl(host, port, usa_tls, config.get("timeout", 10))
            except Exception:
                continue

            if cl_te["suspeito"]:
                f = self.finding(
                    severity         = "high",
                    title            = f"Possível desync CL.TE em {base}",
                    detail           = (
                        f"Requisição com Content-Length e Transfer-Encoding conflitantes (variante CL.TE) "
                        f"resultou em comportamento anômalo: {cl_te['motivo']}. "
                        f"[!] Detecção heurística — requer validação manual (ex: Burp HTTP Request Smuggler) "
                        f"antes de confirmar como vulnerabilidade real."
                    ),
                    url              = base,
                    evidence         = cl_te.get("evidencia", ""),
                    remediation      = "Garantir que front-end (proxy/CDN/load balancer) e back-end concordem "
                                        "na interpretação de Content-Length vs Transfer-Encoding. Preferir HTTP/2 "
                                        "de ponta a ponta, que elimina essa classe de ambiguidade.",
                    confidence       = 0.45,
                    impact           = 8.5,
                    exploitability   = "requer-confirmacao",
                    business_context = "Request smuggling confirmado permite bypass de controles de front-end "
                                        "(WAF, autenticação) e sequestro de requisições de outros usuários.",
                )
                if f:
                    findings.append(f)

            if te_cl["suspeito"]:
                f = self.finding(
                    severity         = "high",
                    title            = f"Possível desync TE.CL em {base}",
                    detail           = (
                        f"Requisição com Content-Length e Transfer-Encoding conflitantes (variante TE.CL) "
                        f"resultou em comportamento anômalo: {te_cl['motivo']}. "
                        f"[!] Detecção heurística — requer validação manual antes de confirmar."
                    ),
                    url              = base,
                    evidence         = te_cl.get("evidencia", ""),
                    remediation      = "Mesma recomendação do CL.TE — alinhar interpretação de framing entre "
                                        "front-end e back-end, ou eliminar a camada intermediária ambígua.",
                    confidence       = 0.45,
                    impact           = 8.5,
                    exploitability   = "requer-confirmacao",
                    business_context = "Request smuggling confirmado permite bypass de controles de front-end "
                                        "e sequestro de requisições de outros usuários.",
                )
                if f:
                    findings.append(f)

        return findings

    # ── Testes raw socket ────────────────────────────────────────────────────

    def _conectar(self, host: str, port: int, usa_tls: bool, timeout: float):
        s = socket.create_connection((host, port), timeout=timeout)
        if usa_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        return s

    def _teste_cl_te(self, host: str, port: int, usa_tls: bool, timeout: float) -> dict:
        """CL.TE: front-end respeita Content-Length, back-end respeita Transfer-Encoding.
        Manda um corpo que, se o back-end seguir o TE, deixa uma requisição "presa" pendurada."""
        corpo_malicioso = "0\r\n\r\nG"
        req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: {len(corpo_malicioso) + 4}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{corpo_malicioso}\r\n\r\n"
        )
        return self._enviar_e_medir(host, port, usa_tls, req, timeout)

    def _teste_te_cl(self, host: str, port: int, usa_tls: bool, timeout: float) -> dict:
        """TE.CL: front-end respeita Transfer-Encoding, back-end respeita Content-Length."""
        chunk = "8\r\nSENTINEL\r\n0\r\n\r\n"
        req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: 4\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{chunk}"
        )
        return self._enviar_e_medir(host, port, usa_tls, req, timeout)

    def _enviar_e_medir(self, host, port, usa_tls, req, timeout) -> dict:
        t0 = time.time()
        try:
            s = self._conectar(host, port, usa_tls, timeout)
            s.settimeout(min(timeout, 8))
            s.sendall(req.encode("latin-1", errors="replace"))
            try:
                resp = s.recv(4096)
            except socket.timeout:
                resp = b""
            elapsed = time.time() - t0
            s.close()
        except Exception as e:
            return {"suspeito": False, "motivo": str(e)}

        # Timeout/hang no recv (perto do limite configurado) é o sinal clássico
        # de desync — o back-end ficou esperando mais dados que nunca vêm.
        if elapsed >= min(timeout, 8) * 0.9 and not resp:
            return {"suspeito": True, "motivo": "conexão travou esperando dados (timeout no recv)",
                     "evidencia": f"sem resposta após {elapsed:.1f}s"}

        primeira_linha = resp.split(b"\r\n", 1)[0].decode(errors="replace") if resp else ""
        if "400" in primeira_linha or "501" in primeira_linha:
            # Servidor rejeitou explicitamente — não é sinal de smuggling, é bom sinal
            return {"suspeito": False, "motivo": "servidor rejeitou corretamente"}

        return {"suspeito": False, "motivo": "sem anomalia detectada"}
