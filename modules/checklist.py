#!/usr/bin/env python3
"""
SENTINELA — Checklist automático de endpoints
Criado por github.com/3rr0rrr

Gera/atualiza (merge) um arquivo de texto simples com o status de cada
endpoint descoberto durante o scan: TESTADO (passou por algum módulo) ou
NÃO TESTADO (descoberto mas não chegou a ser analisado — fora de escopo,
timeout, módulo não rodado etc).

Formato por linha:
  [TESTADO] GET /endpoint - status: seguro|vulnerável - finding: <resumo ou "-">
  [NAO TESTADO] GET /endpoint - status: - - finding: -

Se já existir um checklist.txt no diretório de saída de uma execução anterior
contra o mesmo alvo, as entradas são atualizadas por merge (chave = método +
endpoint) em vez de sobrescritas — entradas antigas não tocadas nesta
execução são preservadas.
"""

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


class ChecklistManager:
    def __init__(self, config: dict, all_results: dict):
        self.config = config
        self.results = all_results
        self.target = config.get("target", "")
        raw_out = config.get("output", "sentinela_results")
        self.output_dir = Path(raw_out).expanduser().resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.output_dir / "checklist_endpoints.txt"

    # ── API PÚBLICA ──────────────────────────────────────────────────────────

    def generate(self) -> str:
        novas_entradas = self._coletar_entradas()
        existentes = self._carregar_existente()

        # merge: novas entradas sobrescrevem a mesma chave, o resto é preservado
        merged = {**existentes, **novas_entradas}

        self._escrever(merged)
        return str(self.path)

    # ── COLETA ───────────────────────────────────────────────────────────────

    def _coletar_entradas(self) -> dict:
        entradas = {}

        # Findings com URL (web + vuln) — testados, com resultado
        findings_por_url = {}
        for secao in ("web", "vuln"):
            for f in self.results.get(secao, {}).get("findings", []):
                url = f.get("url")
                if not url:
                    continue
                findings_por_url.setdefault(url, []).append(f)

        # Diretórios/arquivos testados via dir brute
        web = self.results.get("web", {})
        for d in web.get("dir_brute", []):
            path = d.get("path", "")
            if not path:
                continue
            status_http = d.get("status", 0)
            fs = findings_por_url.get(path, [])
            categoria = "Diretórios & Arquivos"
            chave = ("GET", path)
            entradas[chave] = self._linha(
                categoria=categoria, metodo="GET", endpoint=path,
                testado=True, vulneravel=self._tem_finding_relevante(fs),
                finding_resumo=self._resumo_findings(fs) or f"HTTP {status_http}",
            )

        # Nikto/Nuclei findings com url
        for tipo_lista, categoria in [("nikto_findings", "Nikto"), ("nuclei_findings", "Nuclei")]:
            for f in web.get(tipo_lista, []):
                url = f.get("url") or f.get("path") or ""
                if not url:
                    continue
                chave = ("GET", url)
                entradas[chave] = self._linha(
                    categoria=categoria, metodo="GET", endpoint=url,
                    testado=True, vulneravel=True,
                    finding_resumo=f.get("title") or f.get("description") or f.get("id", "-"),
                )

        # Findings genéricos com URL que não vieram de dir_brute (ex: plugins, sqli, xss)
        for url, fs in findings_por_url.items():
            chave = ("GET", url)
            if chave in entradas:
                continue
            entradas[chave] = self._linha(
                categoria="Findings de Vulnerabilidade", metodo="GET", endpoint=url,
                testado=True, vulneravel=self._tem_finding_relevante(fs),
                finding_resumo=self._resumo_findings(fs),
            )

        # Subdomínios descobertos no recon — testados só se também aparecem como
        # base_url analisada pelo módulo web; caso contrário ficam NÃO TESTADOS
        recon = self.results.get("recon", {})
        base_urls_testadas = set()
        for u in web.get("base_urls", []):
            host = urlparse(u).netloc or u
            base_urls_testadas.add(host.lower())

        for s in recon.get("subdomains", []):
            sub = s.get("subdomain", "")
            if not sub:
                continue
            testado = sub.lower() in base_urls_testadas
            chave = ("HOST", sub)
            entradas[chave] = self._linha(
                categoria="Subdomínios / Hosts", metodo="HOST", endpoint=sub,
                testado=testado, vulneravel=False,
                finding_resumo="-" if not testado else "recon + web analysis",
            )

        # Portas/serviços abertos no recon — sempre marcados como testados
        # (nmap já fez a varredura), sem "vulnerável" a menos que haja finding associado
        for host, portas in recon.get("open_ports", {}).items():
            for porta, info in portas.items():
                svc = info.get("service", "")
                endpoint = f"{host}:{porta}"
                chave = ("PORT", endpoint)
                entradas[chave] = self._linha(
                    categoria="Portas / Serviços", metodo="PORT", endpoint=endpoint,
                    testado=True, vulneravel=False,
                    finding_resumo=svc or "-",
                )

        return entradas

    def _tem_finding_relevante(self, findings: list) -> bool:
        for f in findings:
            if f.get("severity", "INFO").upper() in ("CRITICAL", "HIGH", "MEDIUM"):
                return True
        return False

    def _resumo_findings(self, findings: list) -> str:
        if not findings:
            return ""
        f = sorted(findings, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
                   .get(x.get("severity","INFO").upper(), 9))[0]
        return f"[{f.get('severity','INFO')}] {f.get('title','')}"[:120]

    def _linha(self, categoria, metodo, endpoint, testado, vulneravel, finding_resumo) -> dict:
        return {
            "categoria": categoria,
            "metodo": metodo,
            "endpoint": endpoint,
            "testado": testado,
            "status": ("vulnerável" if vulneravel else "seguro") if testado else "-",
            "finding": finding_resumo if finding_resumo else "-",
            "atualizado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ── PERSISTÊNCIA (MERGE) ─────────────────────────────────────────────────

    _RE_LINHA = re.compile(
        r"^\[(?P<flag>TESTADO|NAO TESTADO)\]\s+(?P<metodo>\S+)\s+(?P<endpoint>\S+)\s+-\s+"
        r"status:\s*(?P<status>[^-]*?)\s*-\s+finding:\s*(?P<finding>.*)$"
    )

    def _carregar_existente(self) -> dict:
        entradas = {}
        if not self.path.exists():
            return entradas
        categoria_atual = "Geral"
        for linha in self.path.read_text().splitlines():
            linha = linha.rstrip()
            if linha.startswith("## "):
                categoria_atual = linha[3:].strip()
                continue
            m = self._RE_LINHA.match(linha)
            if not m:
                continue
            metodo = m.group("metodo")
            endpoint = m.group("endpoint")
            chave = (metodo, endpoint)
            entradas[chave] = {
                "categoria": categoria_atual,
                "metodo": metodo,
                "endpoint": endpoint,
                "testado": m.group("flag") == "TESTADO",
                "status": m.group("status").strip(),
                "finding": m.group("finding").strip(),
                "atualizado_em": "(execução anterior)",
            }
        return entradas

    def _escrever(self, merged: dict):
        por_categoria = {}
        for (metodo, endpoint), dados in merged.items():
            por_categoria.setdefault(dados["categoria"], []).append(dados)

        linhas = [
            f"# Checklist de Endpoints — SENTINELA",
            f"# Alvo: {self.target}",
            f"# Última atualização: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Este arquivo é atualizado por merge a cada execução — entradas antigas",
            f"# de execuções anteriores são preservadas se não forem testadas de novo.",
            "",
        ]

        for categoria in sorted(por_categoria.keys()):
            linhas.append(f"## {categoria}")
            for dados in sorted(por_categoria[categoria], key=lambda d: d["endpoint"]):
                flag = "TESTADO" if dados["testado"] else "NAO TESTADO"
                linhas.append(
                    f"[{flag}] {dados['metodo']} {dados['endpoint']} - "
                    f"status: {dados['status']} - finding: {dados['finding']}"
                )
            linhas.append("")

        total = len(merged)
        testados = sum(1 for d in merged.values() if d["testado"])
        linhas.append(f"# Total: {total} endpoints — {testados} testados, {total - testados} não testados")

        self.path.write_text("\n".join(linhas))
