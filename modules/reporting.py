#!/usr/bin/env python3
"""
SENTINELA — Módulo de Relatórios v1.0.0
Criado por github.com/3rr0rrr — baseado em GhostScan (MIT License)
Saídas: Markdown, HTML, JSON, PDF (via ReportLab).
"""

import hashlib
import json
import os
import re
import html as html_mod
from datetime import datetime, timezone
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, PageBreak, HRFlowable)
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

from modules.utils import log, Colors
from modules.cvss import cvss_para_finding
from modules.compliance import compliance_para_finding, escopo_pci_aplicavel


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_LABEL_PT = {
    "CRITICAL": "CRÍTICO", "HIGH": "ALTO", "MEDIUM": "MÉDIO",
    "LOW": "BAIXO", "INFO": "INFORMATIVO",
}

SEVERITY_COLORS_HEX = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#27ae60",
    "INFO":     "#7f8c8d",
}

SEVERITY_BADGE_CSS = {
    "CRITICAL": "background:#c0392b;color:#fff",
    "HIGH":     "background:#e67e22;color:#fff",
    "MEDIUM":   "background:#f39c12;color:#fff",
    "LOW":      "background:#27ae60;color:#fff",
    "INFO":     "background:#7f8c8d;color:#fff",
}


class ReportingModule:
    def __init__(self, config: dict, all_results: dict):
        self.config = config
        self.results = all_results
        self.target = config["target"]

        # Sempre resolve o diretório de saída para um caminho absoluto
        raw_out = config.get("output", "sentinela_results")
        self.output_dir = Path(raw_out).expanduser().resolve()
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fallback para o diretório home se a permissão for negada
            self.output_dir = Path.home() / "sentinela_results"
            self.output_dir.mkdir(parents=True, exist_ok=True)
            log(f"  Permissão negada no diretório de saída — usando: {self.output_dir}", Colors.YELLOW)
        self.ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.safe_target = re.sub(r"[^\w\-.]", "_", self.target)
        self.all_findings = self._collect_all_findings()
        self._enriquecer_findings()

    # ── API PÚBLICA ──────────────────────────────────────────────────────────

    def generate(self, fmt: str = "both"):
        """fmt: markdown | html | pdf | json | both | all"""
        paths = {}
        session_path = self._save_session_json()
        paths["json"] = session_path

        if fmt in ("markdown", "both", "all", "md"):
            p = self._write_markdown()
            paths["markdown"] = p
            log(f"  Relatório Markdown: {p}", Colors.GREEN)

        if fmt in ("html", "all"):
            p = self._write_html()
            paths["html"] = p
            log(f"  Relatório HTML:     {p}", Colors.GREEN)

        if fmt in ("pdf", "both", "all"):
            if HAS_REPORTLAB:
                p = self._write_pdf()
                paths["pdf"] = p
                log(f"  Relatório PDF:      {p}", Colors.GREEN)
            else:
                # Fallback para HTML
                p = self._write_html()
                paths["html"] = p
                log(f"  PDF pulado (reportlab ausente) — HTML: {p}", Colors.YELLOW)

        return paths

    # ── ENRIQUECIMENTO (CVSS + COMPLIANCE) ───────────────────────────────────

    def _enriquecer_findings(self):
        """Anexa CVSS v3.1 e mapeamento de compliance a cada finding, quando aplicável."""
        for f in self.all_findings:
            chave = f.get("category") or f.get("title") or ""
            cvss = cvss_para_finding(chave) or cvss_para_finding(f.get("title", ""))
            if cvss:
                f["_cvss"] = cvss
            comp = compliance_para_finding(chave) or compliance_para_finding(f.get("title", ""))
            if comp:
                f["_compliance"] = comp

    # ── HASH / CADEIA DE CUSTÓDIA ────────────────────────────────────────────

    def _sha256(self, data) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def _gravar_sidecar_hash(self, path: Path):
        """Calcula o SHA-256 do arquivo final em disco e grava um .sha256 ao lado
        (cadeia de custódia — permite verificar que o relatório não foi alterado
        após a geração)."""
        try:
            conteudo = path.read_bytes()
            digest = self._sha256(conteudo)
            sidecar = Path(str(path) + ".sha256")
            sidecar.write_text(f"{digest}  {path.name}\n")
            return digest
        except Exception as e:
            log(f"  Falha ao gerar hash de integridade para {path.name}: {e}", Colors.YELLOW)
            return None

    def _rodape_custodia(self, hash_conteudo: str) -> str:
        agora_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"Documento gerado pela SENTINELA em {agora_utc}.\n"
            f"Hash SHA-256 do conteúdo do relatório (calculado antes deste rodapé): {hash_conteudo}\n"
            f"Um arquivo .sha256 do arquivo final também foi gerado ao lado deste relatório "
            f"para verificação de integridade independente. Qualquer alteração no conteúdo "
            f"após a geração invalida esses hashes."
        )

    # ── SESSÃO JSON ───────────────────────────────────────────────────────────

    def _save_session_json(self) -> str:
        path = self.output_dir / f"session_{self.ts}.json"
        payload = {
            "meta": {
                "target":            self.target,
                "timestamp":         self.ts,
                "sentinela_version": "1.0.0",
                "autor":             "github.com/3rr0rrr",
                "output_dir":        str(self.output_dir),
                "gerado_em_utc":     datetime.now(timezone.utc).isoformat(),
            },
            "results":   self.results,
            "findings":  self.all_findings,
            "summary": {
                sev: sum(1 for f in self.all_findings if f.get("severity","").upper() == sev)
                for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
            },
        }
        # Também inclui correlações de inteligência, se presentes
        if "intelligence" in self.results:
            payload["correlations"] = self.results["intelligence"].get("correlations", [])
            payload["ranked_targets"] = self.results["intelligence"].get("ranked_targets", [])

        conteudo = json.dumps(payload, indent=2, default=str)
        digest = self._sha256(conteudo)
        payload["integridade"] = {"sha256_do_conteudo_acima": digest}

        with open(path, "w") as f:
            json.dump(payload, f, indent=2, default=str)
        self._gravar_sidecar_hash(path)
        log(f"  Sessão salva → {path}", Colors.DIM)
        return str(path)

    # ── SUMÁRIO EXECUTIVO ────────────────────────────────────────────────────

    def _build_executive_summary(self) -> dict:
        summary = self._severity_summary()
        total = len(self.all_findings)
        criticas = summary.get("CRITICAL", 0)
        altas = summary.get("HIGH", 0)
        medias = summary.get("MEDIUM", 0)

        corrs = self.results.get("intelligence", {}).get("correlations", [])
        tem_correlacao_critica = any(c.get("severity","").upper() == "CRITICAL" for c in corrs)

        if criticas > 0 or tem_correlacao_critica:
            nivel = "CRÍTICO"
            narrativa = (
                f"O alvo apresenta {criticas} finding(s) de severidade CRÍTICA"
                + (" e ao menos uma cadeia de ataque correlacionada de alto impacto" if tem_correlacao_critica else "")
                + ". Recomenda-se ação de remediação imediata antes de qualquer exposição adicional do sistema."
            )
        elif altas > 0:
            nivel = "ALTO"
            narrativa = (
                f"O alvo apresenta {altas} finding(s) de severidade ALTA. Não há comprometimento "
                f"crítico confirmado no momento do teste, mas a exploração dessas vulnerabilidades "
                f"pode levar a acesso não autorizado ou vazamento de dados. Recomenda-se remediação "
                f"em curto prazo."
            )
        elif medias > 0:
            nivel = "MÉDIO"
            narrativa = (
                f"O alvo apresenta {medias} finding(s) de severidade MÉDIA. O risco imediato é "
                f"limitado, mas as fragilidades identificadas reduzem a postura de segurança geral "
                f"e devem ser corrigidas no ciclo normal de manutenção."
            )
        elif total > 0:
            nivel = "BAIXO"
            narrativa = (
                "Os achados identificados são de baixo impacto ou informativos. Nenhuma "
                "vulnerabilidade de exploração direta foi confirmada durante este teste."
            )
        else:
            nivel = "MÍNIMO"
            narrativa = (
                "Nenhum finding relevante foi identificado com o escopo e a profundidade de "
                "teste utilizados nesta execução."
            )

        top3 = sorted(self.all_findings,
                       key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 9))[:3]

        # Detecta escopo PCI-DSS (checkout/pagamento)
        urls_para_checar = [f.get("url","") for f in self.all_findings]
        urls_para_checar += self.results.get("web", {}).get("base_urls", [])
        for d in self.results.get("web", {}).get("dir_brute", []):
            urls_para_checar.append(d.get("path",""))
        pci_aplica = escopo_pci_aplicavel(urls_para_checar)

        return {
            "nivel_risco": nivel,
            "narrativa": narrativa,
            "counts": summary,
            "total": total,
            "top3": top3,
            "pci_aplica": pci_aplica,
            "data_teste": datetime.now().strftime("%Y-%m-%d"),
        }

    # ── DIAGRAMA DE KILL CHAIN (ASCII, sem dependência externa) ──────────────

    def _build_kill_chain_ascii(self) -> str:
        corrs = self.results.get("intelligence", {}).get("correlations", [])
        if not corrs:
            return ""

        blocos = []
        for c in sorted(corrs, key=lambda x: x.get("score", 0), reverse=True)[:5]:
            titulo = c.get("title", "Correlação")
            sev = c.get("severity", "HIGH")
            caminho = c.get("attack_path", "")
            if caminho:
                # Usa as etapas descritas no attack_path (separadas por → ou ->)
                partes = re.split(r"→|->", caminho)
                etapas = [p.strip() for p in partes if p.strip()]
            else:
                etapas = ["Reconhecimento", "Vulnerabilidade Encontrada", "Exploração", "Impacto"]

            linha_caixas = []
            linha_setas = []
            for i, etapa in enumerate(etapas):
                largura = max(len(etapa) + 2, 12)
                linha_caixas.append("[" + etapa.center(largura) + "]")
                if i < len(etapas) - 1:
                    linha_setas.append("─" * (largura + 2) + "▶")
            texto_fluxo = "".join(
                caixa + (seta if i < len(linha_setas) else "")
                for i, (caixa, seta) in enumerate(
                    zip(linha_caixas, linha_setas + [""] * len(linha_caixas))
                )
            )
            blocos.append(f"[{sev}] {titulo}\n{texto_fluxo}\n")

        return "\n".join(blocos)

    # ── MARKDOWN ──────────────────────────────────────────────────────────────

    def _write_markdown(self) -> str:
        path = self.output_dir / f"sentinela_{self.safe_target}_{self.ts}.md"
        corpo = "\n".join(self._build_markdown_lines())
        hash_conteudo = self._sha256(corpo)
        rodape = "\n\n---\n\n" + self._rodape_custodia(hash_conteudo).replace("\n", "  \n")
        with open(path, "w") as f:
            f.write(corpo + rodape)
        self._gravar_sidecar_hash(path)
        return str(path)

    def _build_markdown_lines(self) -> list:
        lines = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        exec_summary = self._build_executive_summary()
        summary = exec_summary["counts"]

        lines += [
            f"# Relatório de Avaliação de Segurança — SENTINELA",
            f"",
            f"| Campo         | Valor |",
            f"|---------------|-------|",
            f"| **Alvo**      | `{self.target}` |",
            f"| **Data**      | {now} |",
            f"| **Ferramenta**| SENTINELA v1.0.0 — Kali Linux Framework, by github.com/3rr0rrr |",
            f"",
            f"---",
            f"",
            f"## Sumário Executivo",
            f"",
            f"**Nível de risco geral:** `{exec_summary['nivel_risco']}`",
            f"",
            exec_summary["narrativa"],
            f"",
            f"| Severidade | Quantidade |",
            f"|------------|------------|",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = summary.get(sev, 0)
            if c:
                lines.append(f"| **{SEVERITY_LABEL_PT.get(sev,sev)}** | {c} |")
        lines += ["", f"**Total de findings:** {exec_summary['total']}", ""]

        if exec_summary["top3"]:
            lines += ["**Top 3 prioridades de remediação:**", ""]
            for i, f in enumerate(exec_summary["top3"], 1):
                lines.append(f"{i}. `[{f.get('severity','INFO')}]` {f.get('title','')}")
            lines += [""]

        if exec_summary["pci_aplica"]:
            lines += [
                "> [!] **Escopo PCI-DSS aplicável:** foram identificados paths de checkout/pagamento "
                "no alvo. As vulnerabilidades encontradas nessas áreas devem ser tratadas com "
                "prioridade sob a ótica de compliance PCI-DSS.",
                "",
            ]

        lines += [f"**Nota de escopo:** alvo `{self.target}`, teste realizado em {exec_summary['data_teste']}.",
                   "", "---", ""]

        # Tabela de findings
        lines += ["## Findings", ""]
        sorted_findings = sorted(self.all_findings,
                                  key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 9))
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "INFO")
            lines += [
                f"### [{i}] `{sev}` — {f.get('title', '')}",
                f"",
                f"| Campo | Valor |",
                f"|-------|-------|",
                f"| **Categoria** | {f.get('category', '')} |",
                f"| **Severidade** | {SEVERITY_LABEL_PT.get(sev,sev)} |",
            ]
            if f.get("url"):
                lines.append(f"| **URL** | `{f['url']}` |")
            if f.get("detail"):
                lines.append(f"| **Detalhe** | {f['detail'][:200]} |")
            if f.get("evidence"):
                lines.append(f"| **Evidência** | `{f['evidence'][:120]}` |")
            if f.get("remediation"):
                lines.append(f"| **Correção** | {f['remediation']} |")
            cvss = f.get("_cvss")
            if cvss:
                lines.append(f"| **CVSS v3.1** | {cvss['score']} ({cvss['severidade']}) — `{cvss['vetor']}` |")
            comp = f.get("_compliance")
            if comp:
                partes = []
                if comp.get("pci_dss"):
                    partes.append("PCI-DSS " + "; ".join(comp["pci_dss"]))
                if comp.get("lgpd"):
                    partes.append("LGPD " + "; ".join(comp["lgpd"]))
                lines.append(f"| **Compliance** | {' \\| '.join(partes)} |")
            lines += [""]

        # Diagrama de kill chain
        kill_chain = self._build_kill_chain_ascii()
        if kill_chain:
            lines += ["---", "", "## Cadeia de Ataque (Kill Chain)", "", "```", kill_chain, "```", ""]

        # Seção de recon
        r = self.results.get("recon", {})
        if r:
            lines += ["---", "", "## Reconhecimento", ""]
            dns = r.get("dns_records", {})
            if dns:
                lines += ["### Registros DNS", ""]
                for rtype, vals in dns.items():
                    for v in vals:
                        lines.append(f"- `{rtype}` → `{v}`")
                lines += [""]
            subs = r.get("subdomains", [])
            if subs:
                lines += [f"### Subdomínios ({len(subs)} encontrados)", ""]
                for s in subs[:50]:
                    ips = ", ".join(s.get("ips", []))
                    lines.append(f"- `{s['subdomain']}` → {ips}")
                if len(subs) > 50:
                    lines.append(f"- *...e mais {len(subs)-50}*")
                lines += [""]
            ports = r.get("open_ports", {})
            if ports:
                lines += ["### Portas Abertas", ""]
                for host, host_ports in ports.items():
                    lines.append(f"**{host}**")
                    for port, info in sorted(host_ports.items(), key=lambda x: int(x[0])):
                        svc = info.get("service", "")
                        ver = f"{info.get('product','')} {info.get('version','')}".strip()
                        lines.append(f"- `{port}/tcp` {svc} {ver}")
                lines += [""]

        # Seção web
        w = self.results.get("web", {})
        if w:
            lines += ["---", "", "## Análise Web", ""]
            waf = w.get("waf", {})
            if waf.get("waf"):
                lines.append(f"**WAF detectado:** {waf['waf']}")
            tech = w.get("technologies", {})
            if tech:
                for cat, items in tech.items():
                    if items:
                        lines.append(f"**{cat.title()}:** {', '.join(str(i) for i in items[:5])}")
            lines += [""]
            dirs = w.get("dir_brute", [])
            if dirs:
                lines += [f"### Diretórios Encontrados ({len(dirs)})", ""]
                for d in sorted(dirs, key=lambda x: x.get("status", 0)):
                    lines.append(f"- `{d.get('status')}` `{d.get('path')}` ({d.get('size',0)} bytes)")
                lines += [""]
            secrets = w.get("js_secrets", [])
            if secrets:
                lines += [f"### Segredos em JavaScript ({len(secrets)})", ""]
                for s in secrets:
                    lines.append(f"- **{s['type']}** em `{s['url']}`")
                lines += [""]

        # Seção de workflow
        lines += [
            "---", "",
            "## Referência de Workflow de Pentest",
            "",
            "> Gerado automaticamente com base nos serviços descobertos.",
            "",
        ]
        workflow_md = self._build_workflow_section()
        lines.append(workflow_md)

        lines += [
            "---",
            "",
            f"*Relatório gerado pela SENTINELA v1.0.0 (by github.com/3rr0rrr) em {now}*",
            "*Apenas para avaliações de segurança autorizadas.*",
        ]
        return lines

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _write_html(self) -> str:
        path = self.output_dir / f"sentinela_{self.safe_target}_{self.ts}.html"
        corpo_html = self._build_html()
        hash_conteudo = self._sha256(corpo_html)
        corpo_html = corpo_html.replace("{{HASH_CONTEUDO}}", hash_conteudo)
        with open(path, "w") as f:
            f.write(corpo_html)
        self._gravar_sidecar_hash(path)
        return str(path)

    def _build_html(self) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        exec_summary = self._build_executive_summary()
        summary = exec_summary["counts"]
        sorted_findings = sorted(self.all_findings,
                                  key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 9))

        finding_cards = ""
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity", "INFO")
            badge_css = SEVERITY_BADGE_CSS.get(sev, "background:#333;color:#fff")
            ev = html_mod.escape(f.get("evidence", "")[:200])
            rem = html_mod.escape(f.get("remediation", ""))
            url = html_mod.escape(f.get("url", ""))
            detail = html_mod.escape(f.get("detail", "")[:300])
            title = html_mod.escape(f.get("title", ""))
            cvss = f.get("_cvss")
            cvss_row = ""
            if cvss:
                cvss_row = (f'<tr><td>CVSS v3.1</td><td>{cvss["score"]} ({cvss["severidade"]}) '
                            f'— <code>{html_mod.escape(cvss["vetor"])}</code></td></tr>')
            comp = f.get("_compliance")
            comp_row = ""
            if comp:
                partes = []
                if comp.get("pci_dss"):
                    partes.append("PCI-DSS " + "; ".join(comp["pci_dss"]))
                if comp.get("lgpd"):
                    partes.append("LGPD " + "; ".join(comp["lgpd"]))
                comp_row = f'<tr><td>Compliance</td><td>{html_mod.escape(" | ".join(partes))}</td></tr>'
            finding_cards += f"""
            <div class="card finding-card">
              <div class="card-header">
                <span class="badge" style="{badge_css}">{SEVERITY_LABEL_PT.get(sev,sev)}</span>
                <strong>[{i}] {title}</strong>
              </div>
              <div class="card-body">
                <table class="info-table">
                  <tr><td>Categoria</td><td>{html_mod.escape(f.get('category',''))}</td></tr>
                  {'<tr><td>URL</td><td><code>' + url + '</code></td></tr>' if url else ''}
                  {'<tr><td>Detalhe</td><td>' + detail + '</td></tr>' if detail else ''}
                  {'<tr><td>Evidência</td><td><code>' + ev + '</code></td></tr>' if ev else ''}
                  {'<tr><td>Correção</td><td class="fix">' + rem + '</td></tr>' if rem else ''}
                  {cvss_row}
                  {comp_row}
                </table>
              </div>
            </div>"""

        summary_pills = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = summary.get(sev, 0)
            if c:
                col = SEVERITY_COLORS_HEX.get(sev, "#333")
                summary_pills += f'<div class="pill" style="background:{col}">{SEVERITY_LABEL_PT.get(sev,sev)} <span class="pill-count">{c}</span></div>'

        top3_html = ""
        for i, f in enumerate(exec_summary["top3"], 1):
            sev = f.get("severity", "INFO")
            col = SEVERITY_COLORS_HEX.get(sev, "#333")
            top3_html += f'<li><span class="badge" style="background:{col};color:#fff">{sev}</span> {html_mod.escape(f.get("title",""))}</li>'

        pci_banner = ""
        if exec_summary["pci_aplica"]:
            pci_banner = (
                '<div class="pci-banner">[!] <strong>Escopo PCI-DSS aplicável</strong> — '
                'foram identificados paths de checkout/pagamento no alvo. Trate os findings '
                'dessas áreas com prioridade sob a ótica de compliance.</div>'
            )

        kill_chain_ascii = self._build_kill_chain_ascii()
        kill_chain_html = ""
        if kill_chain_ascii:
            kill_chain_html = f"""
<h2>Cadeia de Ataque (Kill Chain)</h2>
<div class="section">
  <pre class="killchain">{html_mod.escape(kill_chain_ascii)}</pre>
</div>"""

        # Tabela de portas
        port_rows = ""
        for host, host_ports in self.results.get("recon", {}).get("open_ports", {}).items():
            for port, info in sorted(host_ports.items(), key=lambda x: int(x[0])):
                svc = html_mod.escape(info.get("service", ""))
                ver = html_mod.escape(f"{info.get('product','')} {info.get('version','')}".strip())
                port_rows += f"<tr><td>{host}</td><td>{port}/tcp</td><td>{svc}</td><td>{ver}</td></tr>"

        # Tabela de subdomínios
        sub_rows = ""
        for s in self.results.get("recon", {}).get("subdomains", [])[:60]:
            sd = html_mod.escape(s.get("subdomain", ""))
            ips = html_mod.escape(", ".join(s.get("ips", [])))
            src = html_mod.escape(s.get("source", ""))
            sub_rows += f"<tr><td>{sd}</td><td>{ips}</td><td>{src}</td></tr>"

        # Tabela de diretórios
        dir_rows = ""
        for d in sorted(self.results.get("web", {}).get("dir_brute", []),
                        key=lambda x: x.get("status", 0)):
            status = d.get("status", 0)
            color = "#27ae60" if status == 200 else "#e67e22" if status in [301,302] else "#7f8c8d"
            dir_rows += f'<tr><td style="color:{color};font-weight:bold">{status}</td><td><code>{html_mod.escape(d.get("path",""))}</code></td><td>{d.get("size",0)}</td></tr>'

        # Segredos JS
        js_rows = ""
        for s in self.results.get("web", {}).get("js_secrets", []):
            js_rows += f'<tr><td><span class="badge" style="background:#c0392b;color:#fff">{html_mod.escape(s.get("type",""))}</span></td><td><code>{html_mod.escape(s.get("url","")[:80])}</code></td><td><code>{html_mod.escape(s.get("match","")[:80])}</code></td></tr>'

        agora_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatório SENTINELA — {html_mod.escape(self.target)}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    --radius: 8px;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg);
         color: var(--text); line-height: 1.6; padding: 24px; }}
  h1 {{ font-size: 1.8rem; color: var(--accent); margin-bottom: 4px; }}
  h2 {{ font-size: 1.3rem; color: var(--accent); border-bottom: 1px solid var(--border);
        padding-bottom: 8px; margin: 32px 0 16px; }}
  h3 {{ font-size: 1.1rem; margin: 20px 0 8px; color: #e6edf3; }}
  .meta {{ color: var(--muted); font-size: .85rem; margin-bottom: 24px; }}
  .summary {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0 32px; }}
  .pill {{ border-radius: 20px; padding: 8px 18px; font-weight: 700; font-size: .9rem;
           display: flex; align-items: center; gap: 8px; }}
  .pill-count {{ background: rgba(0,0,0,.3); border-radius: 12px; padding: 2px 8px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border);
           border-radius: var(--radius); margin-bottom: 12px; overflow: hidden; }}
  .card-header {{ padding: 10px 16px; background: rgba(255,255,255,.03);
                  display: flex; align-items: center; gap: 10px; font-size: .95rem; }}
  .card-body {{ padding: 12px 16px; }}
  .badge {{ border-radius: 4px; padding: 2px 8px; font-size: .75rem; font-weight: 700;
            white-space: nowrap; }}
  .info-table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  .info-table td {{ padding: 5px 10px; border-bottom: 1px solid var(--border);
                    vertical-align: top; }}
  .info-table td:first-child {{ width: 120px; color: var(--muted); font-weight: 600; }}
  .fix {{ color: #58c76b; }}
  code {{ background: #1c2128; padding: 2px 6px; border-radius: 4px;
          font-family: 'Courier New', monospace; font-size: .85em; word-break: break-all; }}
  table.data-table {{ width: 100%; border-collapse: collapse; font-size: .85rem;
                      background: var(--surface); border-radius: var(--radius); overflow: hidden; }}
  table.data-table th {{ background: #21262d; padding: 8px 12px; text-align: left;
                          color: var(--muted); font-weight: 600; font-size: .8rem; }}
  table.data-table td {{ padding: 7px 12px; border-bottom: 1px solid var(--border); }}
  table.data-table tr:hover td {{ background: rgba(255,255,255,.02); }}
  .section {{ margin-bottom: 32px; }}
  .no-data {{ color: var(--muted); font-style: italic; padding: 12px; }}
  .exec-summary {{ background: var(--surface); border: 1px solid var(--border);
                    border-radius: var(--radius); padding: 20px; margin-bottom: 24px; }}
  .risk-badge {{ display: inline-block; padding: 6px 16px; border-radius: 6px;
                 font-weight: 800; font-size: 1rem; margin-bottom: 12px; }}
  .top3 {{ margin: 12px 0 0 20px; }}
  .top3 li {{ margin-bottom: 6px; }}
  .pci-banner {{ background: #3a2a00; border: 1px solid #f39c12; border-radius: var(--radius);
                 padding: 12px 16px; margin-top: 16px; font-size: .9rem; }}
  pre.killchain {{ background: var(--surface); border: 1px solid var(--border);
                    border-radius: var(--radius); padding: 16px; overflow-x: auto;
                    font-size: .8rem; white-space: pre; }}
  footer {{ margin-top: 48px; color: var(--muted); font-size: .8rem;
            border-top: 1px solid var(--border); padding-top: 16px; white-space: pre-line; }}
  @media print {{ body {{ background: #fff; color: #000; }}
                  .card {{ break-inside: avoid; }} }}
</style>
</head>
<body>

<h1>Relatório de Segurança — SENTINELA</h1>
<div class="meta">Alvo: <strong>{html_mod.escape(self.target)}</strong> &nbsp;|&nbsp;
Gerado em: {now} &nbsp;|&nbsp; SENTINELA v1.0.0 by github.com/3rr0rrr</div>

<h2>Sumário Executivo</h2>
<div class="exec-summary">
  <div class="risk-badge" style="background:{SEVERITY_COLORS_HEX.get('CRITICAL' if exec_summary['nivel_risco']=='CRÍTICO' else 'HIGH' if exec_summary['nivel_risco']=='ALTO' else 'MEDIUM' if exec_summary['nivel_risco']=='MÉDIO' else 'LOW','#333')};color:#fff">
    Risco geral: {exec_summary['nivel_risco']}
  </div>
  <p>{html_mod.escape(exec_summary['narrativa'])}</p>
  <div class="summary">{summary_pills}</div>
  {'<p><strong>Top 3 prioridades de remediação:</strong></p><ol class="top3">' + top3_html + '</ol>' if top3_html else ''}
  <p style="margin-top:12px;color:var(--muted);font-size:.85rem">Nota de escopo: alvo {html_mod.escape(self.target)}, teste realizado em {exec_summary['data_teste']}.</p>
  {pci_banner}
</div>

<h2>Findings</h2>
<div class="section">
{"<div class='no-data'>Nenhum finding registrado.</div>" if not sorted_findings else finding_cards}
</div>
{kill_chain_html}

<h2>Reconhecimento</h2>
<div class="section">
  <h3>Portas Abertas</h3>
  {"<div class='no-data'>Sem resultados de port scan.</div>" if not port_rows else f"""
  <table class="data-table">
    <thead><tr><th>Host</th><th>Porta</th><th>Serviço</th><th>Versão</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>"""}

  <h3>Subdomínios ({len(self.results.get("recon",{}).get("subdomains",[]))} encontrados)</h3>
  {"<div class='no-data'>Nenhum subdomínio encontrado.</div>" if not sub_rows else f"""
  <table class="data-table">
    <thead><tr><th>Subdomínio</th><th>IPs</th><th>Fonte</th></tr></thead>
    <tbody>{sub_rows}</tbody>
  </table>"""}
</div>

<h2>Análise Web</h2>
<div class="section">
  <h3>Diretórios / Arquivos</h3>
  {"<div class='no-data'>Sem resultados.</div>" if not dir_rows else f"""
  <table class="data-table">
    <thead><tr><th>Status</th><th>Path</th><th>Tamanho</th></tr></thead>
    <tbody>{dir_rows}</tbody>
  </table>"""}

  <h3>Segredos em JavaScript</h3>
  {"<div class='no-data'>Nenhum segredo detectado.</div>" if not js_rows else f"""
  <table class="data-table">
    <thead><tr><th>Tipo</th><th>Arquivo</th><th>Match</th></tr></thead>
    <tbody>{js_rows}</tbody>
  </table>"""}
</div>

<footer>
Gerado por <strong>SENTINELA v1.0.0</strong> — Framework de Pentest para Kali Linux, by github.com/3rr0rrr
Apenas para avaliações de segurança autorizadas. Uso não autorizado é ilegal.

Documento gerado em {agora_utc}.
Hash SHA-256 do conteúdo deste relatório (calculado antes deste rodapé): {{{{HASH_CONTEUDO}}}}
Um arquivo .sha256 do arquivo final também foi gerado ao lado deste relatório para
verificação de integridade independente. Qualquer alteração após a geração invalida os hashes.
</footer>
</body>
</html>"""

    # ── PDF ───────────────────────────────────────────────────────────────────

    def _write_pdf(self) -> str:
        path = self.output_dir / f"sentinela_{self.safe_target}_{self.ts}.pdf"
        if not HAS_REPORTLAB:
            return str(path)

        doc = SimpleDocTemplate(str(path), pagesize=A4,
                                 leftMargin=20*mm, rightMargin=20*mm,
                                 topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        story = []
        exec_summary = self._build_executive_summary()

        # Capa
        story.append(Spacer(1, 30*mm))
        story.append(Paragraph("<font size=24 color='#1a6bbf'><b>SENTINELA</b></font>", styles["Title"]))
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph("Relatório de Avaliação de Segurança", styles["Heading2"]))
        story.append(Spacer(1, 8*mm))
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"<b>Alvo:</b> {self.target}", styles["Normal"]))
        story.append(Paragraph(f"<b>Data:</b> {now}", styles["Normal"]))
        story.append(Paragraph(f"<b>Framework:</b> SENTINELA v1.0.0 — Kali Linux, by github.com/3rr0rrr", styles["Normal"]))
        story.append(PageBreak())

        # Sumário executivo
        story.append(Paragraph("<b>Sumário Executivo</b>", styles["Heading1"]))
        story.append(Spacer(1, 4*mm))
        story.append(Paragraph(f"<b>Nível de risco geral:</b> {exec_summary['nivel_risco']}", styles["Normal"]))
        story.append(Spacer(1, 2*mm))
        story.append(Paragraph(exec_summary["narrativa"], styles["Normal"]))
        story.append(Spacer(1, 4*mm))

        summary = exec_summary["counts"]
        sum_data = [["Severidade", "Quantidade"]]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = summary.get(sev, 0)
            if c:
                sum_data.append([SEVERITY_LABEL_PT.get(sev,sev), str(c)])
        if len(sum_data) > 1:
            t = Table(sum_data, colWidths=[80*mm, 40*mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), rl_colors.HexColor("#1a6bbf")),
                ("TEXTCOLOR",  (0,0), (-1,0), rl_colors.white),
                ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                ("GRID",       (0,0), (-1,-1), 0.5, rl_colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [rl_colors.HexColor("#f9f9f9"), rl_colors.white]),
            ]))
            story.append(t)
        story.append(Spacer(1, 4*mm))

        if exec_summary["top3"]:
            story.append(Paragraph("<b>Top 3 prioridades de remediação:</b>", styles["Normal"]))
            for i, f in enumerate(exec_summary["top3"], 1):
                story.append(Paragraph(f"{i}. [{f.get('severity','INFO')}] {f.get('title','')}", styles["Normal"]))
            story.append(Spacer(1, 4*mm))

        if exec_summary["pci_aplica"]:
            story.append(Paragraph(
                "<font color='#c0392b'><b>[!] Escopo PCI-DSS aplicável</b></font> — foram identificados "
                "paths de checkout/pagamento no alvo.", styles["Normal"]))
            story.append(Spacer(1, 4*mm))

        story.append(Spacer(1, 6*mm))

        # Findings
        story.append(Paragraph("<b>Findings</b>", styles["Heading1"]))
        sorted_findings = sorted(self.all_findings,
                                  key=lambda f: SEVERITY_ORDER.get(f.get("severity","INFO"), 9))
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get("severity","INFO")
            color = SEVERITY_COLORS_HEX.get(sev, "#666666")
            story.append(Spacer(1, 3*mm))
            story.append(Paragraph(
                f'<font color="{color}"><b>[{i}] [{SEVERITY_LABEL_PT.get(sev,sev)}]</b></font> {f.get("title","")}',
                styles["Heading3"]))
            rows = [["Campo", "Valor"]]
            for k, v in [("Categoria", f.get("category","")),
                         ("URL", f.get("url","")),
                         ("Detalhe", f.get("detail","")[:200]),
                         ("Evidência", f.get("evidence","")[:120]),
                         ("Correção", f.get("remediation",""))]:
                if v:
                    rows.append([k, str(v)])
            cvss = f.get("_cvss")
            if cvss:
                rows.append(["CVSS v3.1", f"{cvss['score']} ({cvss['severidade']}) — {cvss['vetor']}"])
            comp = f.get("_compliance")
            if comp:
                partes = []
                if comp.get("pci_dss"):
                    partes.append("PCI-DSS " + "; ".join(comp["pci_dss"]))
                if comp.get("lgpd"):
                    partes.append("LGPD " + "; ".join(comp["lgpd"]))
                rows.append(["Compliance", " | ".join(partes)])
            if len(rows) > 1:
                t = Table(rows, colWidths=[40*mm, 130*mm])
                t.setStyle(TableStyle([
                    ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
                    ("BACKGROUND", (0,0), (-1,0), rl_colors.HexColor("#eeeeee")),
                    ("GRID",       (0,0), (-1,-1), 0.3, rl_colors.HexColor("#cccccc")),
                    ("FONTSIZE",   (0,0), (-1,-1), 8),
                    ("VALIGN",     (0,0), (-1,-1), "TOP"),
                ]))
                story.append(t)

        # Cadeia de custódia (não pode incluir o hash do PDF final nele mesmo —
        # o hash do arquivo final fica no .sha256 gerado ao lado)
        story.append(PageBreak())
        agora_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        story.append(Paragraph("<b>Cadeia de Custódia</b>", styles["Heading2"]))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(f"Documento gerado pela SENTINELA em {agora_utc}.", styles["Normal"]))
        story.append(Paragraph(
            "Um arquivo .sha256 com o hash SHA-256 do arquivo PDF final foi gerado ao lado "
            "deste relatório para verificação de integridade independente. Qualquer alteração "
            "no arquivo após a geração invalida esse hash.", styles["Normal"]))

        doc.build(story)
        self._gravar_sidecar_hash(path)
        return str(path)

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _collect_all_findings(self) -> list:
        all_f = []
        seen = set()
        for section in ["recon", "web", "vuln"]:
            for f in self.results.get(section, {}).get("findings", []):
                key = f"{f.get('severity')}{f.get('title')}{f.get('url')}"
                if key not in seen:
                    seen.add(key)
                    all_f.append(f)
        return all_f

    def _severity_summary(self) -> dict:
        counts = {}
        for f in self.all_findings:
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _build_workflow_section(self) -> str:
        from modules.workflow import WorkflowEngine, WORKFLOW_STEPS
        try:
            engine = WorkflowEngine(self.config)
            recon_results = {
                "open_ports": self.results.get("recon", {}).get("open_ports", {}),
                "technologies": self.results.get("web", {}).get("technologies", {}),
                "subdomains": self.results.get("recon", {}).get("subdomains", []),
            }
            recommended = engine.get_contextual_steps(recon_results)
            lines = []
            seen_phases = set()
            for phase_key, step_id in recommended:
                phase_data = WORKFLOW_STEPS.get(phase_key, {})
                if phase_key not in seen_phases:
                    seen_phases.add(phase_key)
                    lines.append(f"\n### {phase_data.get('phase', phase_key)}")
                step = engine.get_step(phase_key, step_id)
                if step:
                    lines.append(f"\n#### [{step['id']}] {step['title']}")
                    lines.append(f"\nFerramentas: `{'`, `'.join(step.get('tools', []))}`\n")
                    lines.append("```bash")
                    for cmd in step.get("kali_commands", []):
                        lines.append(engine.format_command(cmd))
                    lines.append("```")
            return "\n".join(lines) if lines else "_Nenhuma recomendação de workflow — rode com --all para análise completa._"
        except Exception as e:
            return f"_Erro na geração do workflow: {e}_"
