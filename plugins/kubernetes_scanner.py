#!/usr/bin/env python3
"""
Plugin SENTINELA — Scanner de Kubernetes (kube-hunter)
Criado por github.com/3rr0rrr

Se o recon detectar sinais de API do Kubernetes exposta (porta 6443/10250
aberta, ou resposta típica de API k8s em /version, /api/v1), oferece rodar
kube-hunter em modo remoto (--remote, não precisa estar dentro do cluster).

Só roda em --mode standard ou mais (nunca stealth, é ativo). Não roda em
--mode stealth. kube-hunter só reporta — não explora nada (ele já é, por
padrão, um scanner passivo/de reconhecimento, não um framework de exploit).
"""

import json
import shutil
import subprocess

from plugins.base import SentinelaPlugin

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

PORTAS_K8S = {6443, 10250, 10255, 8443, 2379, 2380, 30000, 30001}


class KubernetesScannerPlugin(SentinelaPlugin):
    name           = "Scanner de Kubernetes (kube-hunter)"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Roda kube-hunter em modo remoto se API do Kubernetes for detectada"
    requires       = ["recon"]
    tags           = ["kubernetes", "k8s", "cloud"]
    severity       = "high"
    enabled        = True
    stealth        = False
    min_confidence = 0.6
    max_findings   = 15
    timeout        = 180

    def run(self, target: str, context: dict) -> list:
        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive" or config.get("mode") == "stealth":
            return []

        if not self._k8s_detectado(target, context):
            return []

        if not shutil.which("kube-hunter"):
            self.log("Kubernetes detectado, mas kube-hunter não instalado", "warn")
            return []

        host = target.split(":")[0].split("/")[0]
        try:
            proc = subprocess.run(
                ["kube-hunter", "--remote", host, "--report", "json"],
                capture_output=True, text=True, timeout=config.get("tool_timeout", 180),
            )
        except Exception as e:
            self.log(f"Erro ao rodar kube-hunter: {e}", "error")
            return []

        if not proc.stdout.strip():
            return []

        try:
            dados = json.loads(proc.stdout)
        except Exception:
            return []

        findings = []
        for vuln in dados.get("vulnerabilities", []) or []:
            sev_map = {"high": "high", "medium": "medium", "low": "low"}
            sev = sev_map.get((vuln.get("severity") or "medium").lower(), "medium")
            f = self.finding(
                severity         = sev,
                title            = f"Kubernetes: {vuln.get('vulnerability', 'achado desconhecido')}",
                detail           = vuln.get("description", ""),
                url              = f"k8s://{host}:{vuln.get('port', '?')}",
                evidence         = vuln.get("evidence", ""),
                remediation      = vuln.get("avd_reference", "Ver documentação do kube-hunter pra remediação específica."),
                confidence       = 0.75,
                impact           = 8.0 if sev == "high" else 5.5,
                exploitability   = "pre-auth",
                business_context = "API do Kubernetes exposta/mal configurada pode levar a controle "
                                    "total do cluster — impacto potencialmente maior que um único host comprometido.",
            )
            if f:
                findings.append(f)

        return findings

    def _k8s_detectado(self, target: str, context: dict) -> bool:
        open_ports = context.get("open_ports") or {}
        for host, portas in open_ports.items():
            if any(p in portas or str(p) in portas for p in PORTAS_K8S):
                return True

        if not HAS_REQUESTS:
            return False
        host = target.split(":")[0].split("/")[0]
        for porta in (6443, 8443, 10250):
            try:
                resp = requests.get(f"https://{host}:{porta}/version", timeout=3, verify=False)
                if resp.status_code in (200, 401, 403) and (
                        "gitVersion" in (resp.text or "") or "kubernetes" in (resp.text or "").lower()):
                    return True
            except Exception:
                continue
        return False
