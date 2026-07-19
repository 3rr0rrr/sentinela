<div align="center">

```
  ██████  ████████  ██      ██  ██████████  ██████  ██      ██  ████████  ██          ████
██        ██        ████    ██      ██        ██    ████    ██  ██        ██        ██    ██
  ████    ██████    ██  ██  ██      ██        ██    ██  ██  ██  ██████    ██        ████████
      ██  ██        ██    ████      ██        ██    ██    ████  ██        ██        ██    ██
██████    ████████  ██      ██      ██      ██████  ██      ██  ████████  ████████  ██    ██
```

**Framework de Pentest de Nível Empresarial para Kali Linux**

*Criado por github.com/3rr0rrr — baseado em [GhostScan](https://github.com/scf13/ghostscan) (MIT License)*

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?logo=linux)](https://kali.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tools](https://img.shields.io/badge/tools-73%20integradas-orange)](docs/sample_report.md)
[![Plugins](https://img.shields.io/badge/plugins-24%20inclu%C3%ADdos-purple)](#sistema-de-plugins)

> **[!] Apenas para testes de segurança autorizados.** Uso não autorizado é ilegal.

</div>

---

## Filosofia

A SENTINELA foi desenhada para **reduzir ruído, priorizar riscos reais e guiar o pentester por ambientes complexos** — não para substituir o julgamento humano.

A maioria dos scanners te entrega 300 findings e deixa você descobrir o que importa.
A SENTINELA entrega **10 findings que você pode agir hoje**, ranqueados por uma fórmula de score que considera impacto, confiança e contexto de negócio — e ainda traduz cada achado pra um score CVSS v3.1 padrão de mercado, um mapeamento de compliance e um checklist de cobertura, pra você não perder rastro do que já foi testado.

> *"Painel de login + SQL injection = CRÍTICO" — não dois findings MÉDIOS separados.*

**Princípios centrais:**
- **Sinal em vez de ruído** — cada finding tem score, % de confiança e contexto de negócio
- **Consciente de contexto** — findings correlacionados revelam cadeias de ataque compostas automaticamente
- **Orientação embutida** — workflow adaptativo gera os comandos exatos com base no que foi encontrado
- **Falha graciosamente** — uma ferramenta quebrada nunca para a cadeia de scan
- **Extensível** — solte um `.py` em `plugins/` para adicionar checagens customizadas
- **Rastreável** — checklist automático de endpoints testados/não testados, hash de integridade em cada relatório

---

## Novidades da SENTINELA (em relação ao GhostScan original)

| Recurso | GhostScan original | SENTINELA |
|---------|--------------------|-----------|
| Idioma | Inglês | Português do Brasil (CLI, help, relatórios) |
| Plugins inclusos | 3 (XSS, admin finder, sensitive files) | **9** — os 3 originais + JWT, CORS, GraphQL introspection, subdomain takeover, secrets/entropy, security headers avançado |
| Scoring | Score próprio (impact×0.6 + confidence×0.4) | Score próprio **+ CVSS v3.1** por finding |
| Relatório | Tabela de severidade | **Sumário executivo** em linguagem não-técnica, com nível de risco geral e top 3 prioridades |
| Compliance | — | Mapeamento **PCI-DSS v4.0 / LGPD** por finding + aviso de escopo PCI se detectar checkout/pagamento |
| Rastreabilidade de testes | — | **Checklist automático** de endpoints testados/não testados (merge entre execuções) |
| Integridade do relatório | — | Hash **SHA-256** + cadeia de custódia em cada relatório gerado |
| OSINT passivo | Sub-enum ativo | **crt.sh** sempre disponível (100% passivo) + **Shodan/Censys** opcionais |
| Furtividade | `stealth` (rate-limit) | + modo **`ghost`** — jitter aleatório, rotação de User-Agent, proxy rotation |
| Visualização de ataque | Texto de correlação | **Diagrama de kill chain** (ASCII, sem dependência externa) no relatório HTML |

---

## O que Torna a SENTINELA Diferente

| Característica | Scanner Típico | SENTINELA |
|-----------------|-----------------|-----------|
| Saída | Dump bruto, 300+ itens | Correlacionado, pontuado, ranqueado |
| Severidade | HIGH/MEDIUM/LOW estático | `score = (impacto × 0.6) + (confiança × 0.4)` + CVSS v3.1 |
| Contexto | Nenhum | Login + SQLi → CRÍTICO automaticamente |
| WAF | É bloqueado | Autodetecta + aplica perfil de evasão |
| Workflow | Comandos estáticos | Adaptativo — decisões a partir dos findings reais |
| Escopo | Sem enforcement | Bloqueio rígido — fora de escopo + proteção SSRF |
| Plugins | Nenhum | Solte `.py` em `plugins/` — carregado automaticamente + sandboxed |
| Performance | Sequencial | Paralelo com timeout + retry por ferramenta |
| Compliance | Nenhum | PCI-DSS v4.0 / LGPD mapeado por finding |
| Integridade | Nenhuma | Hash SHA-256 + cadeia de custódia |

---

## Instalação Rápida

```bash
cd ~/tools/sentinela
sudo bash install.sh
```

Verificar:
```bash
sentinela -t exemplo.com --tools
sentinela -t exemplo.com --wordlists
```

**Opcional — scan de DOM XSS:**
```bash
pip install playwright --break-system-packages
playwright install chromium
```

**Opcional — OSINT via Shodan/Censys** (recon via crt.sh já funciona sem nenhuma chave):
```bash
export SHODAN_API_KEY="sua_chave"
export CENSYS_API_ID="seu_id"
export CENSYS_API_SECRET="seu_secret"
```

---

## Perfis de Scan

```bash
sentinela -t ALVO --mode stealth      # só recon passivo, ritmo de 2s, sem probing
sentinela -t ALVO --mode standard --all --report pdf   # balanceado (padrão)
sentinela -t ALVO --mode aggressive   # todas as ferramentas, todas as injeções, threads no máximo
sentinela -t ALVO --mode ghost --proxy-list proxies.txt  # furtivo red-team, jitter + UA rotation + proxies
```

| Perfil | Ritmo | Threads | SQLi | XSS | Brute | Bypass WAF | Wordlists | Extra |
|--------|-------|---------|------|-----|-------|------------|-----------|-------|
| `stealth` | 2.0s | 5 | Não | Não | Não | Não | pequenas | — |
| `standard` | 0.1s | 20 | Sim | Sim | Não | auto | médias | — |
| `aggressive` | 0.05s | 50 | Sim | Sim | Sim | Sim | grandes | — |
| `ghost` | jitter 0.8–4.5s | 20 | Sim* | Sim* | Não | auto | médias | UA rotativo + proxy rotation |

\* No modo `ghost`, `--sqli`/`--xss` continuam opt-in via flag — o modo em si só ativa furtividade de rede.

---

## Exemplos de Uso

```bash
# Scan completo, relatório em PDF
sentinela -t exemplo.com --all --report pdf

# Bypass de WAF (autodetecta ou força perfil)
sentinela -t exemplo.com --web --waf-bypass
sentinela -t exemplo.com --web --waf-bypass --waf-profile cloudflare

# DOM XSS com screenshots
sentinela -t exemplo.com --web --browser --screenshots

# Recon paralelo (todas as ferramentas simultaneamente)
sentinela -t exemplo.com --recon --parallel

# Mostrar só findings HIGH+ — reduz ruído
sentinela -t exemplo.com --all --min-severity high --report pdf

# Scan restrito por escopo
sentinela -t exemplo.com --all --scope "*.exemplo.com" --strict-scope

# Rede interna
sentinela -t 192.168.1.0/24 --recon --no-ssrf-protect --parallel

# Via Burp Suite
sentinela -t exemplo.com --web --proxy http://127.0.0.1:8080

# Roteamento via Tor
sentinela -t exemplo.com --all --tor

# Modo furtivo red-team (jitter + rotação de UA + proxies)
sentinela -t exemplo.com --web --mode ghost --proxy-list proxies.txt

# Recon passivo com Shodan/Censys (chaves via env var ou flag)
sentinela -t exemplo.com --recon --shodan-key SUA_CHAVE

# Imprimir próximos passos adaptativos
sentinela -t exemplo.com --workflow

# Retomar scan interrompido
sentinela -t exemplo.com --all --resume ./sentinela_results/session_*.json

# 21 exemplos completos
bash usage.sh
```

---

## Sistema de Scoring

```
score_sentinela = (impacto × 0.6) + (confiança × 0.4)
```

Além do score próprio, todo finding com um tipo reconhecido (SQLi, RCE, XSS, LFI, secret exposto, CORS, JWT `alg:none`, subdomain takeover, GraphQL introspection etc.) recebe também um **score CVSS v3.1** com vetor completo — o padrão de mercado para relatórios formais de pentest.

| Finding | Impacto | Confiança | Score SENTINELA | CVSS v3.1 | Severidade |
|---------|---------|-----------|------------------|-----------|------------|
| Chave AWS em JS | 10 | 10 | **10.0** | 7.5 | CRÍTICO |
| SQLi (confirmado via sqlmap) | 10 | 9 | **9.6** | 9.8–10.0 | CRÍTICO |
| RCE via CVE | 10 | 8 | **9.2** | 9.8–10.0 | CRÍTICO |
| XSS refletido | 6 | 5 | **5.6** | 6.1 | MÉDIO |
| CSP ausente | 3 | 9 | **5.4** | 5.3 | MÉDIO |
| Versão do servidor exposta | 2 | 10 | **4.0** | — | BAIXO |

**Multiplicadores de contexto:**

| Condição | Multiplicador | Resultado |
|----------|----------------|-----------|
| Painel de login + SQLi | × 1.50 | CRÍTICO |
| API sem autenticação | × 1.40 | ALTO → CRÍTICO |
| Porta de banco exposta externamente | × 1.45 | CRÍTICO |
| Secret em JS + sem WAF | × 1.20 | CRÍTICO |
| Path de pagamento/checkout | × 1.50 | Upgrade de escopo PCI |

---

## Sumário Executivo & Compliance

Todo relatório (Markdown, HTML, PDF) começa com um **Sumário Executivo** em linguagem não-técnica, pronto pra apresentar a um cliente ou gestor:

- Nível de risco geral do alvo (`MÍNIMO` → `CRÍTICO`), com narrativa curta
- Contagem de findings por severidade
- Top 3 prioridades de remediação
- Nota de escopo e data do teste
- Aviso automático de **escopo PCI-DSS aplicável** quando o alvo tem paths de checkout/pagamento

Cada finding com tipo reconhecido também ganha uma linha de **Compliance**, mapeando pra requisitos plausíveis do **PCI-DSS v4.0** e artigos da **LGPD (Lei 13.709/2018)** — não substitui uma auditoria formal de compliance, mas dá contexto regulatório imediato no relatório técnico.

---

## Checklist Automático de Endpoints

Ao final de cada scan, a SENTINELA gera/atualiza `checklist_endpoints.txt` no diretório de saída, com uma linha por endpoint:

```
[TESTADO] GET /admin - status: vulnerável - finding: [HIGH] Painel admin exposto
[TESTADO] GET /login - status: seguro - finding: HTTP 200
[NAO TESTADO] HOST staging.exemplo.com - status: - - finding: -
```

Execuções sucessivas fazem **merge** com o checklist existente — nada é perdido entre uma rodada e outra, e você sempre sabe o que já foi coberto.

---

## Cadeia de Custódia (Hash SHA-256)

Cada relatório gerado (`.md`, `.html`, `.pdf`, `.json`) recebe:
- Um rodapé com data/hora UTC de geração e o hash SHA-256 do conteúdo
- Um arquivo `.sha256` gerado ao lado (`sentinela_exemplo.com_*.pdf.sha256`) com o hash do arquivo final, para verificação de integridade independente

Qualquer alteração no relatório após a geração invalida esses hashes — útil como evidência formal em entregáveis para clientes.

---

## Engine de Correlação + Kill Chain

A SENTINELA detecta automaticamente riscos compostos:

```
+ Painel de login em /wp-login.php (HTTP 200)
+ SQL injection em ?search= (boolean-based)
+ Content-Security-Policy ausente
= CRÍTICO [9.8] SQLi no Endpoint de Autenticação = Bypass de Auth + Dump do BD
  Ataque: admin'-- → bypass de autenticação → dump de wp_users → quebra de hashes
```

```
+ Redis na porta 6379 (aberto para a internet)
+ Sem autenticação (configuração padrão)
= CRÍTICO [9.6] Banco de Dados Exposto Externamente
  Ataque: redis-cli → CONFIG SET → RCE via cron
```

Quando há correlações, o relatório HTML inclui um **diagrama de kill chain** em ASCII (sem dependência de CDN externo, funciona 100% offline):

```
[CRITICAL] SQLi no Endpoint de Autenticação
[ Recon ]──────▶[ SQLi encontrada ]──────▶[ Bypass de autenticação ]──────▶[ Dump do banco ]
```

---

## Sistema de Plugins

Solte um `.py` em `plugins/` — ele carrega automaticamente no próximo scan.

```python
from plugins.base import SentinelaPlugin

class MeuPlugin(SentinelaPlugin):
    name           = "Minha Checagem Customizada"
    version        = "1.0.0"
    author         = "Seu Nome"
    description    = "Verifica algo customizado"
    requires       = ["web_analysis"]   # roda depois do scan web
    tags           = ["web", "auth"]
    severity       = "medium"
    stealth        = True               # seguro para modo passivo
    min_confidence = 0.5                # suprime findings de baixa confiança
    max_findings   = 20                 # limite para evitar ruído
    timeout        = 30                 # morte automática após 30s

    def run(self, target: str, context: dict) -> list:
        findings = []
        for url in context.get("endpoints", []):
            if "admin" in url:
                f = self.finding(
                    severity         = "high",
                    title            = f"Endpoint admin: {url}",
                    url              = url,
                    confidence       = 0.85,
                    impact           = 7.0,
                    exploitability   = "pre-auth",
                    business_context = "Acesso admin = controle total da aplicação",
                    remediation      = "Restringir a VPN/IPs confiáveis. Habilitar MFA.",
                )
                if f:  # None = suprimido por min_confidence
                    findings.append(f)
        return findings
```

**Plugins inclusos (9):**

| Plugin | O que detecta |
|--------|----------------|
| `xss_custom.py` | Parâmetros propensos a XSS, scoring de impacto de negócio (pagamento = CRÍTICO) |
| `admin_finder.py` | Painéis admin, Jenkins, Grafana, H2-console, phpMyAdmin com exploitabilidade |
| `sensitive_files.py` | `.env`, `.git`, dumps SQL, backups, phpinfo — 30+ padrões |
| `jwt_analyzer.py` | JWT com `alg:none` aceito, claim `exp` ausente, dados sensíveis no payload |
| `cors_misconfig.py` | CORS refletindo Origin arbitrário, `Allow-Credentials` perigoso |
| `graphql_introspection.py` | Endpoints GraphQL com introspection habilitada (`__schema` exposto) |
| `subdomain_takeover.py` | CNAMEs "dangling" apontando para serviços de terceiros não reivindicados |
| `secrets_entropy.py` | Chaves AWS/Stripe/Google e strings de alta entropia em respostas/JS |
| `security_headers_pro.py` | Qualidade do CSP, `Permissions-Policy`, `COOP`/`COEP`, `HSTS` insuficiente |

**Sandbox de segurança dos plugins:**
- Cada plugin roda em sua própria thread com kill-switch de timeout
- Um crash retorna `[]` — nunca quebra o scan principal
- Findings limitados a `max_findings` por plugin
- Confiança abaixo de `min_confidence` é suprimida automaticamente

---

## Todas as Flags

```
Módulos:     --all  --recon  --web  --vuln  --workflow
Perfil:      --mode stealth/standard/aggressive/ghost
Ataque:      --sqli  --xss  --brute  --browser  --screenshots
             --parallel  --fast  --udp
             --intensity passive/normal/aggressive
WAF:         --waf-bypass  --waf-profile cloudflare|akamai|aws-waf|f5|imperva|modsecurity|wordfence|sucuri
Escopo:      --scope ALVO  --scope-file ARQUIVO  --strict-scope  --no-ssrf-protect
Saída:       --min-severity critical/high/medium/low/info
             --report markdown/html/pdf/json/both/all
             --output DIR  --resume ARQUIVO
Plugins:     --no-plugins
HTTP:        --proxy URL  --tor  --cookies JSON  --headers JSON  --user-agent STRING
Wordlists:   --wordlist-size small/medium/large
             --subdomain-wordlist ARQUIVO  --dir-wordlist ARQUIVO
OSINT:       --shodan-key CHAVE  --censys-key ID  --censys-secret SECRET
Ghost:       --proxy-list ARQUIVO
Info:        --tools  --wordlists  --version  -v
```

---

## Perfis de Bypass de WAF

| WAF | tamper do sqlmap | Delay |
|-----|-------------------|-------|
| CloudFlare | space2comment,randomcase,charencode,between | 0.8–2.5s |
| Akamai | space2comment,charunicodeencode,randomcase,between | 1.0–3.5s |
| AWS-WAF | space2comment,randomcase,between | 0.3–1.2s |
| F5 BIG-IP | charunicodeencode,space2comment,randomcase,multiplespaces | 0.5–2.0s |
| Imperva | space2comment,charencode,randomcase,between,multiplespaces | 1.0–3.0s |
| ModSecurity | space2comment,randomcase,charencode,between,equaltolike | 0.3–1.5s |
| Wordfence | space2comment,randomcase,charencode | 0.5–2.0s |
| Sucuri | space2comment,randomcase | 1.0–3.0s |
| Genérico | space2comment,randomcase,charencode | 0.5–2.0s |

---

## Vetores de Exploração Avançados

Além dos plugins originais (JWT, CORS, GraphQL introspection, subdomain takeover,
secrets entropy, security headers), a SENTINELA inclui 15 plugins/módulos adicionais:

**Injeção/exploração web**
- **SSTI** (`ssti_tester.py`) — detecção por prova matemática ({{7*7}}), identifica o motor de template.
- **XXE** (`xxe_tester.py`) — leitura de arquivo local inofensivo + confirmação de XXE cego via OOB.
- **HTTP Request Smuggling** (`http_smuggling.py`) — desync CL.TE/TE.CL via socket raw.
- **IDOR/BOLA** (`idor_scanner.py`) — enumeração automática de variação de ID.
- **Upload de arquivo** (`file_upload_tester.py`) — bypass de extensão/content-type, sem payload executável real.
- **Web Cache Poisoning** (`cache_poisoning.py`) — headers não-keyed + wcvs.
- **Log4Shell ativo** (`log4shell_active_test.py`) — confirmação REAL via callback OOB (não só keyword), requer `--sqli` ou `--test-log4shell`.
- **Fuzzer OpenAPI** (`api_openapi_fuzzer.py`) — auth ausente, mass assignment, excessive data exposure.
- **Parâmetro oculto** (`hidden_param_finder.py`, via Arjun).

**Lógica de negócio (e-commerce)**
- **Abuso de checkout** (`business_logic_checkout.py`) — manipulação de preço/quantidade, bypass de etapa. Não-destrutivo por padrão; reuso de cupom real só com `--confirm-destructive`.
- **Race condition** (`race_condition.py`) — TOCTOU em endpoint de uso único, `--race-concurrency N`.

**Infraestrutura/cloud**
- **Bucket cloud** (`cloud_bucket_scanner.py`) — S3/Azure Blob/GCS com listagem pública.
- **Dependências expostas** (`modules/dependency_scanner.py`) — Trivy + OSV-Scanner sobre manifest público (Dockerfile, package-lock.json etc).
- **Kubernetes** (`kubernetes_scanner.py`, via kube-hunter) — API k8s exposta.
- **Auditoria de conta cloud** (`modules/cloud_audit.py`, ScoutSuite/CloudFox) — opt-in com `--aws-profile`/`--azure-subscription`/`--gcp-project`.

**Active Directory**
- **Kerberoasting/AS-REP Roasting** (`kerberos_attacks.py`) — extrai hash TGS/AS-REP, nunca quebra. `--kerberos-user/-pass/-domain`.
- **BloodHound** (`bloodhound_collector.py`) — coleta caminho de ataque em AD, requer credencial.

**Git/segredos**
- `.git` exposto agora reconstrói o repo (git-dumper) e escaneia a história completa com Gitleaks — pega segredo removido em commit posterior mas ainda na história.

**OOB (Out-of-Band)**
- `modules/oob_listener.py` — cliente Interactsh (ou collaborator próprio via `--oob-server`) pra confirmar vulnerabilidade cega (XXE, Log4Shell) com prova real de callback, não suspeita heurística. `--no-interactsh` desliga.

**Mobile / Prova de impacto / Phishing (opt-in explícito)**
- `--mobile-app CAMINHO` — análise estática de APK/IPA via mobsfscan/MobSF.
- `--beef-hook-url URL` — finding de XSS confirmado ganha instrução manual de payload BeEF (nunca injetado automaticamente).
- `--enable-phishing-module` — só gera lembrete/estrutura pro operador montar material via SET manualmente; exige confirmação interativa (digitar "SIM") além da flag. Nunca envia nada sozinho.

**CVE/DAST extras**
- OWASP Nettacker, ZAP (`install.sh --full`), OpenVAS/GVM (`--openvas`, nunca instalado automaticamente — só conecta a instância já rodando).

**Referência**
- `~/tools/references/Penetration-Testing-Tools` — clone local do repositório [mgeeky/Penetration-Testing-Tools](https://github.com/mgeeky/Penetration-Testing-Tools) (scripts/notas de red team, não integrado ao pipeline da SENTINELA, só disponível como referência).
- **Singularity** (DNS rebinding, [github.com/nccgroup/singularity](https://github.com/nccgroup/singularity)) não foi integrado — é um serviço próprio (servidor DNS + proxy HTTP de longa duração) incompatível com o modelo de scan pontual da SENTINELA. Documentado aqui só como referência pra quem precisar rodar separadamente.

---

## Ferramentas Integradas (73)

| Categoria | Ferramentas |
|-----------|-------------|
| Recon/OSINT | nmap, masscan, dnsrecon, dnsenum, amass, sublist3r, subfinder, assetfinder, theHarvester, fierce, whois, dig, crt.sh, waybackurls, gau, httpx, Shodan*, Censys* |
| Varredura Web | nikto, whatweb, wafw00f, gobuster, ffuf, dirb, wfuzz, feroxbuster, wpscan, nuclei, katana, arjun |
| Vulnerabilidade | sqlmap, xsstrike, commix, testssl, sslscan, sslyze, dalfox, searchsploit, trivy, osv-scanner, cve-bin-tool, nettacker, ZAP†, OpenVAS/GVM† |
| Cache/Smuggling | wcvs (Web Cache Vulnerability Scanner) |
| Brute-force Online | hydra, medusa, ncrack, patator, crackmapexec |
| Quebra Offline | john, hashcat, haiti |
| SMB/Windows | enum4linux, enum4linux-ng, smbclient, smbmap, nbtscan |
| Active Directory | impacket-GetUserSPNs, impacket-GetNPUsers, bloodhound-python, kerbrute |
| SNMP | snmpwalk, snmp-check, onesixtyone |
| Git/Segredos | git-dumper, gitleaks |
| Cloud (conta) | ScoutSuite‡, CloudFox‡ |
| Kubernetes | kube-hunter |
| Mobile | mobsfscan, MobSF (servidor, opcional) |
| Prova de Impacto | BeEF (manual, via `--beef-hook-url`) |
| Phishing | SET/setoolkit (desligado por padrão, `--enable-phishing-module`) |

\* Shodan/Censys são opcionais e só rodam se uma chave de API for configurada — nunca enviam pacotes diretamente ao alvo.
† ZAP só instala com `install.sh --full` (pesado, Java). OpenVAS/GVM nunca é instalado pela SENTINELA — só conecta a uma instância já rodando via `--openvas`.
‡ ScoutSuite/CloudFox auditam a CONTA cloud (IAM, buckets, etc), não o alvo web — só rodam com credencial explícita (`--aws-profile`/`--azure-subscription`/`--gcp-project`), autorização separada do pentest de aplicação.

---

## Estrutura de Saída

```
sentinela_results/
├── session_20260101_120000.json           ← Sessão completa + dados de inteligência
├── session_20260101_120000.json.sha256    ← Hash de integridade da sessão
├── sentinela_exemplo.com_*.md             ← Relatório Markdown
├── sentinela_exemplo.com_*.html           ← Relatório HTML (tema escuro + kill chain)
├── sentinela_exemplo.com_*.pdf            ← Relatório PDF profissional
├── sentinela_exemplo.com_*.pdf.sha256     ← Hash de integridade do PDF
├── checklist_endpoints.txt                ← Checklist de cobertura, atualizado por merge
└── screenshots/                           ← Screenshots de página (--browser --screenshots)
```

Veja [docs/sample_report.md](docs/sample_report.md) para um exemplo completo de relatório.

---

## Estrutura do Projeto

```
sentinela/
├── sentinela.py               # Ponto de entrada da CLI
├── install.sh                 # Instalador completo
├── usage.sh                   # 21 exemplos de uso
├── requirements.txt
├── NOTICE.md                  # Aviso de autoria (SENTINELA sobre GhostScan)
├── docs/
│   └── sample_report.md       # Exemplo de relatório de pentest
├── modules/
│   ├── scope.py                # Enforcement rígido de escopo + proteção SSRF
│   ├── executor.py              # Execução paralela (timeout/retry/isolamento)
│   ├── intelligence.py          # Motor de scoring + correlação + ranking de alvos
│   ├── normaliser.py            # Schema JSON unificado (UUID, confiança, impacto)
│   ├── waf_bypass.py            # Perfis de evasão de WAF + encoders de payload
│   ├── workflow.py               # Motor de workflow adaptativo
│   ├── browser.py                # Playwright — DOM XSS + screenshots
│   ├── recon.py                  # DNS, subdomínios, OSINT (crt.sh/Shodan/Censys), port scan
│   ├── web_analysis.py           # Crawl, dir brute, nikto, nuclei, wpscan, JS
│   ├── vuln_detection.py         # Headers, SQLi, XSS, correlação de CVE, brute
│   ├── tool_integration.py       # Wrappers para as 53 ferramentas
│   ├── wordlists.py              # SecLists + fallbacks embutidos
│   ├── reporting.py              # Relatórios Markdown, HTML, PDF, JSON + sumário executivo + hash
│   ├── cvss.py                   # Cálculo de CVSS v3.1 + vetores sugeridos por tipo
│   ├── compliance.py             # Mapeamento PCI-DSS v4.0 / LGPD por finding
│   ├── checklist.py              # Checklist automático de endpoints (merge entre execuções)
│   └── utils.py                  # Logging, cores, helpers
└── plugins/
    ├── base.py                    # Classe base de plugin + loader sandboxed
    ├── xss_custom.py               # Checagem de XSS com impacto de negócio
    ├── admin_finder.py             # Localizador de painéis admin com exploitabilidade
    ├── sensitive_files.py          # Detector de arquivos sensíveis (30+ padrões)
    ├── jwt_analyzer.py             # Análise de JWT (alg:none, exp ausente, dados sensíveis)
    ├── cors_misconfig.py           # Detector de CORS mal configurado
    ├── graphql_introspection.py    # Detector de introspection GraphQL exposta
    ├── subdomain_takeover.py       # Detector de subdomain takeover (CNAME dangling)
    ├── secrets_entropy.py          # Scanner de segredos por padrão + entropia de Shannon
    └── security_headers_pro.py     # Auditoria avançada de headers de segurança
```

---

## Aviso Legal

A SENTINELA é destinada **apenas a testes de segurança autorizados**. Uso não autorizado pode violar:
- **Brasil:** Lei 12.737/2012 (Lei Carolina Dieckmann) e o Marco Civil da Internet
- **EUA:** 18 U.S.C § 1030 (CFAA)
- **Reino Unido:** Computer Misuse Act 1990
- **UE:** Diretiva 2013/40/EU

Sempre obtenha autorização por escrito antes de testar qualquer sistema.

---

## Licença

[MIT](LICENSE) — © 2024 GhostScan (base original) · Modificações e novas funcionalidades © 2026 github.com/3rr0rrr. Ver [NOTICE.md](NOTICE.md) para detalhes de autoria.
