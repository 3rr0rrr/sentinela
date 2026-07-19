#!/usr/bin/env python3
"""
SENTINELA — Cliente OOB (Out-of-Band) via Interactsh
Criado por github.com/3rr0rrr

Gera uma URL/subdomínio único de callback por sessão de scan usando o
binário oficial `interactsh-client` (projectdiscovery.io, open-source),
rodado como subprocesso. Plugins de SSTI/XXE/SSRF/Log4Shell podem embutir
essa URL em payloads pra detectar vulnerabilidades CEGAS (que não refletem
resultado direto na resposta) — se o alvo fizer uma requisição de volta pro
callback, é prova conclusiva de execução.

NOTA DE HISTÓRICO: a primeira versão deste módulo reimplementava o
protocolo do Interactsh à mão em Python (registro RSA + decriptação AES).
Essa reimplementação tinha um bug real — registrava com sucesso, mas o
polling nunca retornava as interações mesmo com callback HTTP/DNS confirmado
chegando ao servidor. Foi trocada por esta versão, que só invoca o binário
oficial (mesmo código usado pelo Nuclei/demais ferramentas da ProjectDiscovery)
via subprocess — mais confiável e menos código pra manter.

[!] Isso faz chamadas a um serviço público de TERCEIROS (servidor Interactsh
na internet) — não é 100% passivo/offline. Se não houver internet, o
binário não estiver instalado, ou o serviço estiver fora do ar, o módulo
degrada graciosamente: `disponivel` fica False e nenhum outro módulo quebra
por causa disso — eles simplesmente pulam a variante de payload que
dependeria de OOB.

Uso:
    oob = OOBListener(config)
    if oob.disponivel:
        url_callback = oob.gerar_payload_url("xxe-teste1")
        ...  # injeta url_callback no payload
        time.sleep(8)
        interacoes = oob.checar_interacoes()
    oob.fechar()  # encerra o subprocesso ao final do scan
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid


class OOBListener:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.disponivel = False
        self._erro = None
        self._modo_custom = False
        self._servidor = None
        self._processo = None
        self._payloads = []       # lista de hosts pré-gerados pelo cliente oficial
        self._payload_idx = 0
        self._tags = {}           # host/sub -> tag
        self._linhas_vistas = 0
        self._arquivo_saida = None
        self._arquivo_payloads = None

        servidor_custom = self.config.get("oob_server")  # self-hosted collaborator-style, opcional
        if servidor_custom:
            self._modo_custom = True
            self._servidor = servidor_custom.rstrip("/")
            self.disponivel = True
            return

        if self.config.get("no_oob"):
            self._erro = "OOB desabilitado via --no-interactsh"
            return

        binario = self._localizar_binario()
        if not binario:
            self._erro = (
                "binário interactsh-client não encontrado — instale com "
                "'go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest' "
                "(também disponível via install.sh)"
            )
            return

        try:
            self._iniciar_cliente(binario)
            self.disponivel = True
        except Exception as e:
            self._erro = str(e)
            self._encerrar_processo()
            self.disponivel = False

    # ── Setup do binário oficial ─────────────────────────────────────────────

    def _localizar_binario(self):
        caminho = shutil.which("interactsh-client")
        if caminho:
            return caminho
        candidato = os.path.expanduser("~/go/bin/interactsh-client")
        if os.path.isfile(candidato) and os.access(candidato, os.X_OK):
            return candidato
        return None

    def _iniciar_cliente(self, binario: str):
        n_payloads = int(self.config.get("oob_payload_batch", 20))
        tmpdir = tempfile.mkdtemp(prefix="sentinela_oob_")
        self._arquivo_saida = os.path.join(tmpdir, "interacoes.jsonl")
        self._arquivo_payloads = os.path.join(tmpdir, "payloads.txt")

        cmd = [
            binario,
            "-n", str(n_payloads),
            "-json",
            "-o", self._arquivo_saida,
            "-ps", "-psf", self._arquivo_payloads,
            "-pi", "5",
            "-duc",
        ]
        self._processo = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

        # Espera o arquivo de payloads ser populado — o registro é rápido
        # mas não instantâneo.
        prazo = time.time() + 15
        while time.time() < prazo:
            if self._processo.poll() is not None:
                raise RuntimeError("interactsh-client encerrou inesperadamente durante o registro")
            if os.path.isfile(self._arquivo_payloads):
                with open(self._arquivo_payloads) as f:
                    linhas = [l.strip() for l in f if l.strip()]
                if len(linhas) >= n_payloads:
                    self._payloads = linhas
                    return
            time.sleep(0.5)

        # Timeout — usa o que já tiver sido escrito, se houver algo
        if os.path.isfile(self._arquivo_payloads):
            with open(self._arquivo_payloads) as f:
                self._payloads = [l.strip() for l in f if l.strip()]
        if not self._payloads:
            raise RuntimeError("interactsh-client não gerou nenhum payload a tempo (timeout de registro)")

    # ── API pública ───────────────────────────────────────────────────────────

    def gerar_payload_url(self, tag: str = "") -> str:
        """Gera/reserva uma URL única de callback pra embutir num payload.
        `tag` é só pra você identificar depois qual payload gerou qual
        interação."""
        if not self.disponivel:
            return ""

        if self._modo_custom:
            sub = uuid.uuid4().hex[:16]
            url = f"{self._servidor}/{sub}"
            self._tags[sub] = tag
            return url

        if not self._payloads:
            return ""
        if self._payload_idx >= len(self._payloads):
            # Esgotou o lote pré-gerado — reaproveita o último em vez de
            # falhar (degradação aceitável: menos preciso, mas não quebra).
            self._payload_idx = len(self._payloads) - 1
        host = self._payloads[self._payload_idx]
        self._payload_idx += 1
        self._tags[host] = tag
        return f"http://{host}"

    def checar_interacoes(self) -> list:
        """Consulta interações recebidas desde o registro. Lista vazia =
        nada recebido ainda (ou OOB indisponível)."""
        if not self.disponivel:
            return []
        if self._modo_custom:
            return self._checar_custom()
        return self._checar_arquivo_saida()

    def fechar(self):
        """Encerra o subprocesso do interactsh-client. Chame ao final do scan."""
        self._encerrar_processo()

    # ── Leitura do output do cliente oficial ─────────────────────────────────

    def _checar_arquivo_saida(self) -> list:
        if not self._arquivo_saida or not os.path.isfile(self._arquivo_saida):
            return []

        try:
            with open(self._arquivo_saida, encoding="utf-8") as f:
                linhas = f.readlines()
        except Exception:
            return []

        interacoes = []
        for i in range(self._linhas_vistas, len(linhas)):
            linha = linhas[i].strip()
            if not linha:
                continue
            try:
                registro = json.loads(linha)
            except Exception:
                continue

            full_id = registro.get("full-id") or registro.get("unique-id") or ""
            host_usado = next((h for h in self._tags if h.split(".")[0] == full_id), None)
            interacoes.append({
                "tag":    self._tags.get(host_usado, "desconhecida"),
                "tipo":   registro.get("protocol", "?"),
                "origem": registro.get("remote-address", "?"),
                "bruto":  registro,
            })
        self._linhas_vistas = len(linhas)
        return interacoes

    # ── Modo self-hosted (servidor colaborador próprio) ──────────────────────

    def _checar_custom(self) -> list:
        try:
            import requests
            resp = requests.get(f"{self._servidor}/interacoes", timeout=10)
            if resp.status_code != 200:
                return []
            itens = resp.json()
        except Exception:
            return []

        interacoes = []
        for item in itens if isinstance(itens, list) else []:
            sub = item.get("sub", "")
            interacoes.append({
                "tag":    self._tags.get(sub, "desconhecida"),
                "tipo":   item.get("tipo", "?"),
                "origem": item.get("origem", "?"),
                "bruto":  item,
            })
        return interacoes

    # ── Helpers ───────────────────────────────────────────────────────────────

    @property
    def erro(self) -> str:
        return self._erro or ""

    def _encerrar_processo(self):
        if self._processo and self._processo.poll() is None:
            try:
                self._processo.terminate()
                self._processo.wait(timeout=5)
            except Exception:
                try:
                    self._processo.kill()
                except Exception:
                    pass

    def __del__(self):
        try:
            self._encerrar_processo()
        except Exception:
            pass
