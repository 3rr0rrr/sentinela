#!/usr/bin/env python3
"""
Plugin SENTINELA — Testador de Upload de Arquivo
Criado por github.com/3rr0rrr

Encontra formulários com campo de upload e testa bypass de filtro de
extensão/content-type de forma SEGURA: nunca envia um webshell funcional.
Usa um arquivo com extensão dupla suspeita (ex: teste.php.jpg) e um SVG
com payload XSS básico dentro — provam que o filtro pode ser burlado sem
deixar nenhum código executável real no servidor.

Todo finding inclui aviso explícito pra remover o arquivo de teste
enviado / reportar ao cliente pra remoção.
"""

import io
import uuid

from plugins.base import SentinelaPlugin

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

MAX_FORMS = 5

ARQUIVOS_TESTE = [
    ("teste_sentinela.php.jpg", b"SENTINELA-UPLOAD-TEST-INOFENSIVO", "image/jpeg",
     "Extensão dupla (.php.jpg) — testa se o servidor executa a extensão real (.php) "
     "em vez da aparente (.jpg)."),
    ("teste_sentinela.svg", b"<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\">"
     b"<script>/*SENTINELA-TEST-XSS-POC-INOFENSIVO*/</script></svg>", "image/svg+xml",
     "SVG com <script> embutido — testa XSS armazenado via upload de imagem "
     "(SVG é renderizado como HTML/XML pelo navegador, não como bitmap)."),
    ("teste_sentinela.phtml", b"SENTINELA-UPLOAD-TEST-INOFENSIVO", "image/jpeg",
     "Extensão alternativa (.phtml) — muitos filtros bloqueiam .php mas esquecem "
     "extensões alternativas que o Apache/PHP também executa."),
]


class FileUploadTesterPlugin(SentinelaPlugin):
    name           = "Testador de Upload de Arquivo"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Testa bypass de filtro de extensão/content-type em formulários de upload, sem enviar payload executável real"
    requires       = ["web_analysis"]
    tags           = ["web", "upload", "rce"]
    severity       = "high"
    enabled        = True
    stealth        = False
    min_confidence = 0.5
    max_findings   = 10
    timeout        = 60

    def run(self, target: str, context: dict) -> list:
        if not HAS_REQUESTS:
            return []

        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        session = self._build_session(config)
        findings = []

        forms_upload = self._encontrar_forms_upload(context)
        for form in forms_upload[:MAX_FORMS]:
            findings += self._testar_form(session, form, config)

        return findings

    def _encontrar_forms_upload(self, context: dict) -> list:
        alvos = []
        for form in (context.get("forms") or []):
            tipos = [i.get("type", "") for i in form.get("inputs", [])]
            if "file" in tipos:
                alvos.append(form)
        return alvos

    def _testar_form(self, session, form: dict, config: dict) -> list:
        findings = []
        action = form.get("action", "")
        campo_file = next((i for i in form.get("inputs", []) if i.get("type") == "file"), None)
        if not campo_file:
            return findings

        outros_campos = {i["name"]: i.get("value", "teste")
                          for i in form.get("inputs", [])
                          if i.get("name") and i.get("type") != "file"}

        for nome_arquivo, conteudo, content_type, descricao in ARQUIVOS_TESTE:
            nome_unico = f"{uuid.uuid4().hex[:8]}_{nome_arquivo}"
            try:
                resp = session.post(
                    action,
                    data=outros_campos,
                    files={campo_file["name"] or "file": (nome_unico, io.BytesIO(conteudo), content_type)},
                    timeout=config.get("timeout", 15), verify=False,
                )
            except Exception:
                continue

            if resp.status_code in (200, 201, 302):
                # Tenta achar a URL do arquivo enviado na resposta (heurística — não garante)
                url_provavel = self._extrair_url_upload(resp.text or "", nome_unico)
                f = self.finding(
                    severity         = "high",
                    title            = f"Upload aceito com {descricao.split(' — ')[0]} em {action}",
                    detail           = (
                        f"{descricao} O servidor aceitou o upload (HTTP {resp.status_code}) sem rejeitar pela "
                        f"extensão/conteúdo suspeito. Arquivo de teste é INOFENSIVO (sem código executável real), "
                        f"mas confirma que o filtro pode ser burlado. "
                        f"[!] AÇÃO NECESSÁRIA: localizar e remover o arquivo `{nome_unico}` enviado ao servidor "
                        f"durante este teste, e reportar ao cliente pra confirmação de remoção."
                    ),
                    url              = url_provavel or action,
                    evidence         = f"arquivo={nome_unico} content-type={content_type} status={resp.status_code}",
                    remediation      = "Validar extensão E conteúdo real do arquivo (magic bytes) no servidor, "
                                        "nunca confiar em extensão/Content-Type informado pelo cliente. Servir "
                                        "uploads de um domínio/bucket separado sem permissão de execução de código.",
                    confidence       = 0.55,
                    impact           = 8.5 if "svg" in nome_arquivo else 7.0,
                    exploitability   = "requer-confirmacao",
                    business_context = "Upload malicioso bem-sucedido pode escalar pra RCE completo "
                                        "(se a extensão real for executada) ou XSS armazenado (caso do SVG).",
                )
                if f:
                    findings.append(f)

        return findings

    def _extrair_url_upload(self, corpo: str, nome_arquivo: str) -> str:
        import re
        m = re.search(r'["\']([^"\']*' + re.escape(nome_arquivo) + r')["\']', corpo)
        return m.group(1) if m else ""

    def _build_session(self, config: dict):
        session = requests.Session()
        session.headers.update({
            "User-Agent": config.get("user_agent",
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"),
        })
        if config.get("cookies"):
            session.cookies.update(config["cookies"])
        if config.get("proxy"):
            session.proxies.update(config["proxy"])
        return session
