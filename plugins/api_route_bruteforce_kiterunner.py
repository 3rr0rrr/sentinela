#!/usr/bin/env python3
"""
Plugin SENTINELA — Descoberta de Rotas de API (Kiterunner)
Criado por github.com/3rr0rrr

Roda o Kiterunner (github.com/assetnote/kiterunner) contra os base_urls já
descobertos, usando o dataset apiroutes-* mantido pela assetnote (specs
Swagger coletadas de scan de internet + GitHub). Diferente de gobuster/ffuf
(fuzzing genérico de diretório), o Kiterunner manda o método HTTP, headers
e parâmetros que cada rota de API tipicamente espera — acha rotas de
Flask/Rails/Express/Django/Spring que fuzzing genérico não bate, e que só
apareceriam com um spec OpenAPI já publicado (cenário que
api_openapi_fuzzer.py já cobre quando o spec existe). Este plugin cobre o
caso oposto: quando não há spec público nem introspection liberada.

Não instala via apt — requer o binário `kr` no PATH. Baixar o release em
github.com/assetnote/kiterunner/releases (tarball linux_amd64) ou compilar
via `make build` a partir do source. Se não encontrado, o plugin não faz
nada (sem erro, sem log de aviso — mesmo padrão dos outros plugins opcionais
desta pasta, ex: hidden_param_finder.py com Arjun).

Não roda em --mode stealth. Limite de base_urls testadas.
"""

import json
import re
import shutil
import subprocess

from plugins.base import SentinelaPlugin

MAX_BASE_URLS = 3
FALLBACK_WORDLIST = "apiroutes-210328:20000"
FAIL_STATUS_CODES = "400,401,404,403,501,502,426,411"
PALAVRAS_SENSIVEIS = (
    "admin", "internal", "debug", "actuator", "management", "swagger",
    "console", "backup", "config", "secret", "private", "staff", "root",
)


class KiterunnerRoutePlugin(SentinelaPlugin):
    name           = "Descoberta de Rotas de API (Kiterunner)"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Bruteforce de rotas de API via dataset real de specs Swagger (assetnote/kiterunner)"
    requires       = ["web_analysis"]
    tags           = ["web", "api", "recon", "route-discovery"]
    severity       = "low"
    enabled        = True
    stealth        = False
    min_confidence = 0.5
    max_findings   = 20
    timeout        = 240

    def run(self, target: str, context: dict) -> list:
        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive":
            return []

        binario = shutil.which("kr") or shutil.which("kiterunner")
        if not binario:
            return []

        findings = []
        wordlist = self._melhor_wordlist_apiroutes(binario)

        alvos = list(context.get("base_urls") or [f"https://{target}"])[:MAX_BASE_URLS]
        for base_url in alvos:
            rotas = self._rodar_scan(binario, base_url, wordlist, config)
            if not rotas:
                continue

            f_geral = self.finding(
                severity         = "low",
                title            = f"{len(rotas)} rota(s) de API descoberta(s) via dataset Kiterunner em {base_url}",
                detail           = "O Kiterunner bruteforçou rotas usando um dataset de specs Swagger reais "
                                    "coletadas da internet, e não fuzzing genérico de diretório — encontrou "
                                    "rota(s) que respondem de forma consistente com uma API real: "
                                    + "; ".join(f"{r['method']} {r['path']} ({r['status_code']})" for r in rotas[:15]),
                url              = base_url,
                evidence         = "; ".join(f"{r['method']} {r['path']} [{r['status_code']}]" for r in rotas[:15]),
                remediation      = "Confirmar que toda rota de API exposta é intencional e está documentada; "
                                    "remover/desativar endpoints de debug, admin ou versões antigas não usadas.",
                confidence       = 0.6,
                impact           = 4.0,
                exploitability   = "requer-analise-manual",
                business_context = "Rota de API não documentada é superfície de ataque que nenhum outro módulo "
                                    "mapeia — pode expor funcionalidade administrativa ou dados não previstos.",
            )
            if f_geral:
                findings.append(f_geral)

            for r in rotas:
                if r["status_code"] != 200:
                    continue
                caminho_lower = r["path"].lower()
                if any(palavra in caminho_lower for palavra in PALAVRAS_SENSIVEIS):
                    f_sensivel = self.finding(
                        severity         = "medium",
                        title            = f"Rota de API sensível acessível: {r['method']} {r['path']}",
                        detail           = f"A rota {r['path']} contém termo associado a funcionalidade "
                                            f"administrativa/interna e respondeu HTTP 200 sem indício de bloqueio.",
                        url              = base_url.rstrip("/") + r["path"],
                        evidence         = f"HTTP {r['status_code']}, {r['length']} bytes",
                        remediation      = "Validar que a rota exige autenticação/autorização adequada, ou "
                                            "removê-la caso não deva estar exposta publicamente.",
                        confidence       = 0.5,
                        impact           = 6.0,
                        exploitability   = "requer-analise-manual",
                        business_context = "Rotas administrativas/internas expostas são um alvo prioritário "
                                            "de exploração manual — validar antes de qualquer outra coisa.",
                    )
                    if f_sensivel:
                        findings.append(f_sensivel)

        return findings

    def _melhor_wordlist_apiroutes(self, binario: str) -> str:
        """Descobre dinamicamente a versão mais recente do dataset apiroutes-*
        via `kr wordlist list`, em vez de depender de uma data hardcoded que
        fica desatualizada assim que a assetnote publica um dataset novo."""
        try:
            proc = subprocess.run([binario, "wordlist", "list", "-o", "json"],
                                   capture_output=True, text=True, timeout=30)
            candidatos = []
            # `kr wordlist list -o json` retorna um array JSON único (não
            # JSONL), com objetos usando a chave "Shortname" — não
            # "alias"/"ALIAS" como a tabela de texto do README antigo sugeria.
            try:
                entries = json.loads(proc.stdout)
                if isinstance(entries, dict):
                    entries = [entries]
                for entry in entries:
                    alias = str(entry.get("Shortname") or "")
                    if alias.startswith("apiroutes-"):
                        candidatos.append(alias)
            except Exception:
                pass
            if not candidatos:
                candidatos = re.findall(r"\|\s*(apiroutes-\d{6})\s*\|", proc.stdout)
            if candidatos:
                return f"{sorted(candidatos)[-1]}:20000"
        except Exception:
            pass
        return FALLBACK_WORDLIST

    def _rodar_scan(self, binario: str, base_url: str, wordlist: str, config: dict) -> list:
        cmd = [binario, "scan", base_url,
               "-A", wordlist,
               "-x", "5",       # conexoes por host — baixo de proposito (maquina fraca do usuario)
               "-j", "1",       # 1 host por vez — mesmo alvo por chamada, sem concorrencia entre hosts
               "-o", "json",
               "-q",
               "--fail-status-codes", FAIL_STATUS_CODES,
               "-t", "8s",
               ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=min(config.get("tool_timeout", 300), self.timeout))
        except Exception:
            return []
        return self._parse_jsonl(proc.stdout)

    def _parse_jsonl(self, stdout: str) -> list:
        rotas = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue
            respostas = entry.get("responses", []) or []
            final = respostas[-1] if respostas else {}
            rotas.append({
                "method":      entry.get("method", ""),
                "path":        entry.get("path", ""),
                "status_code": final.get("sc", 0),
                "length":      final.get("len", 0),
            })
        return rotas
