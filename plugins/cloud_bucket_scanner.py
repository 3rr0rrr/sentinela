#!/usr/bin/env python3
"""
Plugin SENTINELA — Scanner de Bucket Cloud (S3/Azure/GCS)
Criado por github.com/3rr0rrr

A partir do nome do alvo (e variações comuns) e de nomes de bucket
encontrados em JS/HTML durante o crawl, testa se o bucket existe e está
com listagem pública habilitada. Só faz requisições GET de leitura —
nunca tenta escrever/deletar nada.
"""

import re
from urllib.parse import urlparse

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

RE_BUCKET_REFS = re.compile(
    r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-][a-z0-9\-]*\.amazonaws\.com"
    r"|s3\.amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])"
    r"|([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])\.blob\.core\.windows\.net"
    r"|storage\.googleapis\.com/([a-z0-9][a-z0-9_.\-]{1,61}[a-z0-9])"
    r"|([a-z0-9][a-z0-9_.\-]{1,61}[a-z0-9])\.storage\.googleapis\.com",
    re.IGNORECASE,
)

MAX_BUCKETS = 20


class CloudBucketScannerPlugin(SentinelaPlugin):
    name           = "Scanner de Bucket Cloud"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Testa buckets S3/Azure Blob/GCS por listagem pública indevida"
    requires       = ["web_analysis"]
    tags           = ["cloud", "s3", "storage", "misconfig"]
    severity       = "critical"
    enabled        = True
    stealth        = False
    min_confidence = 0.6
    max_findings   = 15
    timeout        = 45

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        session = self._build_session(config)
        findings = []

        candidatos = self._gerar_candidatos(target, context)
        for nome, provedor, url in candidatos[:MAX_BUCKETS]:
            try:
                resp = session.get(url, timeout=config.get("timeout", 10), verify=False)
            except Exception:
                continue

            if resp.status_code == 404:
                continue  # bucket não existe com esse nome

            corpo = (resp.text or "")[:3000]
            existe = resp.status_code in (200, 403, 400)
            listagem_publica = resp.status_code == 200 and (
                "<ListBucketResult" in corpo or "<EnumerationResults" in corpo or
                '"kind": "storage#objects"' in corpo or "<Contents>" in corpo
            )

            if listagem_publica:
                f = self.finding(
                    severity         = "critical",
                    title            = f"Bucket {provedor} com listagem pública: {nome}",
                    detail           = f"O bucket `{nome}` ({provedor}) permite listagem pública de objetos — "
                                        f"qualquer pessoa pode enumerar e baixar todo o conteúdo.",
                    url              = url,
                    evidence         = corpo[:300],
                    remediation      = "Desabilitar listagem pública e acesso público de leitura no bucket. "
                                        "Restringir via IAM policy/ACL a apenas os serviços que precisam acessar.",
                    confidence       = 0.9,
                    impact           = 9.5,
                    exploitability   = "pre-auth",
                    business_context = "Bucket com listagem pública frequentemente expõe backups, dados de "
                                        "cliente, código-fonte ou credenciais — um dos vazamentos mais comuns e graves em cloud.",
                )
                if f:
                    findings.append(f)
            elif existe:
                f = self.finding(
                    severity         = "medium",
                    title            = f"Bucket {provedor} existe mas nega listagem: {nome}",
                    detail           = f"O bucket `{nome}` ({provedor}) existe (respondeu HTTP {resp.status_code}) "
                                        f"mas a listagem pública está corretamente negada. Vale checar permissões "
                                        f"de objetos individuais manualmente (pode haver objeto público específico "
                                        f"mesmo com listagem desabilitada).",
                    url              = url,
                    evidence         = f"HTTP {resp.status_code}",
                    remediation      = "Confirmar que nenhum objeto individual dentro do bucket tem ACL pública, "
                                        "mesmo com a listagem do bucket desabilitada.",
                    confidence       = 0.65,
                    impact           = 3.0,
                    exploitability   = "requer-enumeracao-adicional",
                    business_context = "Confirma existência de infraestrutura cloud associada ao alvo — "
                                        "info disclosure de baixo risco isolado, mas relevante combinado com outros achados.",
                )
                if f:
                    findings.append(f)

        return findings

    def _gerar_candidatos(self, target: str, context: dict) -> list:
        candidatos = []
        nome_base = re.sub(r"^www\.", "", target.split(":")[0]).split(".")[0].lower()
        nome_base = re.sub(r"[^a-z0-9\-]", "", nome_base)

        if nome_base:
            variacoes = [nome_base, f"{nome_base}-prod", f"{nome_base}-backup",
                         f"{nome_base}-assets", f"{nome_base}-static", f"www-{nome_base}",
                         f"{nome_base}-dev", f"{nome_base}-staging"]
            for v in variacoes:
                candidatos.append((v, "S3",    f"https://{v}.s3.amazonaws.com/?list-type=2"))
                candidatos.append((v, "Azure", f"https://{v}.blob.core.windows.net/?comp=list"))
                candidatos.append((v, "GCS",   f"https://storage.googleapis.com/{v}/"))

        # Buckets já referenciados em JS/HTML durante o crawl
        for corpo in self._coletar_corpos_js(context):
            for m in RE_BUCKET_REFS.finditer(corpo):
                nome = next((g for g in m.groups() if g), None)
                if not nome:
                    continue
                nome = nome.lower()
                if "s3" in m.group(0):
                    candidatos.append((nome, "S3", f"https://{nome}.s3.amazonaws.com/?list-type=2"))
                elif "blob.core.windows.net" in m.group(0):
                    candidatos.append((nome, "Azure", f"https://{nome}.blob.core.windows.net/?comp=list"))
                elif "storage.googleapis.com" in m.group(0):
                    candidatos.append((nome, "GCS", f"https://storage.googleapis.com/{nome}/"))

        vistos, unicos = set(), []
        for c in candidatos:
            if c[0] not in vistos:
                vistos.add(c[0])
                unicos.append(c)
        return unicos

    def _coletar_corpos_js(self, context: dict) -> list:
        # secrets_entropy/web_analysis já baixam JS — reaproveita evidências se existirem no contexto
        corpos = []
        for s in (context.get("js_secrets") or []):
            if s.get("match"):
                corpos.append(str(s["match"]))
        return corpos

    def _build_session(self, config: dict):
        session = requests.Session()
        session.headers.update({
            "User-Agent": config.get("user_agent",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"),
        })
        if config.get("proxy"):
            session.proxies.update(config["proxy"])
        return session
