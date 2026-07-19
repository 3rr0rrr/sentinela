#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  SENTINELA v1.0.0 — Instalador para Kali Linux / Debian / Ubuntu
#  Criado por github.com/3rr0rrr — baseado em GhostScan (MIT License)
#  Uso: sudo bash install.sh [--full] [--no-wordlists] [--no-gpu]
# ═══════════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[1;91m'; GRN='\033[1;92m'; YLW='\033[1;93m'
CYN='\033[1;96m'; DIM='\033[2m'; RST='\033[0m'
BOLD='\033[1m'; WHT='\033[1;97m'

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FULL_INSTALL=false
SKIP_WORDLISTS=false
SKIP_GPU=false
SKIP_PYTHON=false

# ── ARGUMENT PARSING ─────────────────────────────────────────────────────────
for arg in "$@"; do
  case $arg in
    --full)          FULL_INSTALL=true ;;
    --no-wordlists)  SKIP_WORDLISTS=true ;;
    --no-gpu)        SKIP_GPU=true ;;
    --no-python-deps) SKIP_PYTHON=true ;;
    --help|-h)
      echo "Uso: sudo bash install.sh [OPÇÕES]"
      echo "  --full           Instala TODAS as ferramentas opcionais (lento)"
      echo "  --no-wordlists   Pula instalação de SecLists/wordlists"
      echo "  --no-gpu         Pula dependências de GPU do hashcat"
      echo "  --no-python-deps Pula instalações via pip"
      exit 0 ;;
  esac
done

# ── HELPERS ──────────────────────────────────────────────────────────────────
info()    { echo -e "${CYN}[*]${RST} $*"; }
success() { echo -e "${GRN}[+]${RST} $*"; }
warn()    { echo -e "${YLW}[!]${RST} $*"; }
error()   { echo -e "${RED}[-]${RST} $*" >&2; }
section() { echo -e "\n${BOLD}${CYN}══════════════════════════════════════════${RST}";
            echo -e "${BOLD}${CYN}  $*${RST}";
            echo -e "${BOLD}${CYN}══════════════════════════════════════════${RST}"; }

apt_install() {
  local pkg="$1"
  if dpkg -s "$pkg" &>/dev/null 2>&1; then
    echo -e "  ${DIM}já instalado: $pkg${RST}"
    return 0
  fi
  info "Instalando $pkg..."
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>/dev/null && \
    success "Instalado: $pkg" || warn "Falhou: $pkg (continuando)"
}

pip_install() {
  python3 -m pip install --quiet --break-system-packages "$@" 2>/dev/null || \
  python3 -m pip install --quiet "$@" 2>/dev/null || \
  warn "pip install falhou: $*"
}

# ── VERIFICAÇÃO DE ROOT ───────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  error "Rode como root: sudo bash install.sh"
  exit 1
fi

# ── DETECTA DISTRO ────────────────────────────────────────────────────────────
DISTRO="unknown"
if [[ -f /etc/os-release ]]; then
  source /etc/os-release
  DISTRO="${ID,,}"
fi

echo -e "${BOLD}${RED}"
echo -e "              uuuuuuu"
echo -e "          uu\$\$\$\$\$\$\$\$\$\$\$uu"
echo -e "       uu\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$uu"
echo -e "      u\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$u"
echo -e "      u\$\$\$\$\$\$\"   \"\$\$\$\"   \"\$\$\$\$\$\$u"
echo -e "      \"\$\$\$\$\"      u\$u       \$\$\$\$\"        ${WHT}${BOLD}SENTINELA v1.0.0${RST}${BOLD}${RED}"
echo -e "       \$\$\$u       u\$u       u\$\$\$"
echo -e "        \"\$\$\$\$uu\$\$\$   \$\$\$uu\$\$\$\$\"          ${RST}Instalador — Kali Linux / Debian / Ubuntu${BOLD}${RED}"
echo -e "          \"\$\$\$\$\$\$\$\"   \"\$\$\$\$\$\$\$\""
echo -e "             u\$\$\$\$\$\$\$u\$\$\$\$\$\$\$u"
echo -e "               \"\$\$\$\$\$\$\$\$\$\""
echo -e "${DIM}                by github.com/3rr0rrr${RST}"
echo -e "${RST}"
info "Distro detectada: $DISTRO"
info "Diretório de instalação: $INSTALL_DIR"

# ── ATUALIZA APT ──────────────────────────────────────────────────────────────
section "Atualização do Sistema"
info "Atualizando listas de pacotes..."
apt-get update -qq 2>/dev/null || warn "apt-get update falhou (continuando)"

# ── PACOTES BÁSICOS DO SISTEMA ────────────────────────────────────────────────
section "Pacotes Básicos do Sistema"
CORE_PKGS=(
  python3 python3-pip python3-venv python3-dev
  curl wget git unzip gunzip tar
  build-essential libssl-dev libffi-dev
  net-tools iputils-ping dnsutils whois
)
for pkg in "${CORE_PKGS[@]}"; do apt_install "$pkg"; done

# ── NETWORK RECON TOOLS ───────────────────────────────────────────────────────
section "Ferramentas de Reconhecimento de Rede"
RECON_PKGS=(
  nmap              # Port scanning, NSE scripts
  masscan           # Ultra-fast port scanner
  dnsrecon          # DNS enumeration
  dnsenum           # DNS zone transfer + brute
  fierce            # DNS brute-force
  sublist3r         # Subdomain enumeration (OSINT)
  amass             # Advanced subdomain enumeration
  theharvester      # OSINT email/host harvesting
  netcat-traditional # nc — banner grabbing, relay
  p0f               # Passive OS fingerprinting
  whois             # WHOIS lookups
  subfinder         # Subdomain enum passivo (ProjectDiscovery)
)
for pkg in "${RECON_PKGS[@]}"; do apt_install "$pkg"; done

# ── WEB ANALYSIS TOOLS ────────────────────────────────────────────────────────
section "Ferramentas de Análise Web & Fuzzing"
WEB_PKGS=(
  nikto             # Web vulnerability scanner
  whatweb           # Technology fingerprinting
  wafw00f           # WAF detection
  gobuster          # Dir/DNS/vhost brute-force
  dirb              # Directory brute-force
  wfuzz             # Web fuzzer
  wpscan            # WordPress scanner
  joomscan          # Joomla scanner
  sslscan           # SSL/TLS analysis
  sslyze            # SSL/TLS scanner
  testssl.sh        # SSL/TLS comprehensive check
  curl              # HTTP Swiss-army knife
  wget              # HTTP downloader
  assetfinder       # Subdomain enum passivo extra
  arjun             # Descoberta de parâmetro HTTP oculto
  eyewitness        # Screenshot (fallback do Playwright)
  trivy             # Scanner de dependência vulnerável (manifest exposto)
  httpx-toolkit     # Probe de host vivo + tech detect (ProjectDiscovery)
)
for pkg in "${WEB_PKGS[@]}"; do apt_install "$pkg"; done

# httpx — o pacote apt do Kali instala o binário como "httpx-toolkit" (nome
# colidia com outro pacote). A SENTINELA detecta ambos os nomes automaticamente.

# FFUF (not always in apt — try multiple methods)
if ! command -v ffuf &>/dev/null; then
  info "Instalando ffuf..."
  apt_install ffuf 2>/dev/null || {
    if command -v go &>/dev/null; then
      go install github.com/ffuf/ffuf/v2@latest && \
        cp ~/go/bin/ffuf /usr/local/bin/ && success "ffuf instalado via go" || warn "instalação do ffuf falhou"
    else
      warn "ffuf não encontrado no apt — instale manualmente: apt install golang && go install github.com/ffuf/ffuf/v2@latest"
    fi
  }
fi

# Feroxbuster
if ! command -v feroxbuster &>/dev/null; then
  info "Instalando feroxbuster..."
  apt_install feroxbuster 2>/dev/null || {
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
      -o /tmp/install_feroxbuster.sh 2>/dev/null && \
    bash /tmp/install_feroxbuster.sh /usr/local/bin 2>/dev/null && \
    success "feroxbuster instalado" || warn "instalação do feroxbuster falhou"
  }
fi

# Nuclei
if ! command -v nuclei &>/dev/null; then
  info "Instalando nuclei..."
  apt_install nuclei 2>/dev/null || {
    NUCLEI_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest 2>/dev/null | \
      grep -o '"browser_download_url": "[^"]*linux_amd64[^"]*\.zip"' | head -1 | cut -d'"' -f4)
    if [[ -n "$NUCLEI_URL" ]]; then
      curl -sL "$NUCLEI_URL" -o /tmp/nuclei.zip && \
        unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin && \
        mv /tmp/nuclei_bin/nuclei /usr/local/bin/ && \
        chmod +x /usr/local/bin/nuclei && \
        success "nuclei instalado" || warn "instalação do nuclei falhou"
      rm -rf /tmp/nuclei.zip /tmp/nuclei_bin
    else
      warn "nuclei não encontrado — instale manualmente em projectdiscovery.io"
    fi
  }
fi

# ── FERRAMENTAS GO EXTRAS (katana, waybackurls, gau, dalfox, kerbrute, wcvs) ──
section "Ferramentas Go Extras (crawler, XSS, cache poisoning, Kerberos)"
GO_TOOLS=(
  "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
  "waybackurls:github.com/tomnomnom/waybackurls@latest"
  "gau:github.com/lc/gau/v2/cmd/gau@latest"
  "dalfox:github.com/hahwul/dalfox/v2@latest"
  "kerbrute:github.com/ropnop/kerbrute@latest"
  "wcvs:github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest"
  "interactsh-client:github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
)
if command -v go &>/dev/null; then
  for entry in "${GO_TOOLS[@]}"; do
    bin_name="${entry%%:*}"
    mod_path="${entry#*:}"
    if command -v "$bin_name" &>/dev/null; then
      echo -e "  ${DIM}já instalado: $bin_name${RST}"
      continue
    fi
    info "Instalando $bin_name via go install..."
    go install "$mod_path" 2>/dev/null && \
      cp "$HOME/go/bin/$bin_name" /usr/local/bin/ 2>/dev/null && \
      success "$bin_name instalado" || warn "instalação de $bin_name falhou (siga manualmente: go install $mod_path)"
  done
else
  warn "Go não encontrado — pulando katana/waybackurls/gau/dalfox/kerbrute/wcvs. Instale com: apt install golang-go"
fi

# ── SQL INJECTION & EXPLOIT TOOLS ────────────────────────────────────────────
section "Ferramentas de Vulnerabilidade & Exploit"
VULN_PKGS=(
  sqlmap            # SQL injection automation
  commix            # Command injection
  beef-xss          # XSS browser exploitation (optional)
)
for pkg in "${VULN_PKGS[@]}"; do apt_install "$pkg" || true; done

# XSStrike
if ! command -v xsstrike &>/dev/null && ! python3 -c "import xsstrike" &>/dev/null 2>&1; then
  info "Instalando XSStrike..."
  pip_install xsstrike 2>/dev/null || {
    git clone --depth=1 https://github.com/s0md3v/XSStrike /opt/XSStrike 2>/dev/null && \
    ln -sf /opt/XSStrike/xsstrike.py /usr/local/bin/xsstrike && \
    chmod +x /usr/local/bin/xsstrike && success "XSStrike instalado" || warn "instalação do XSStrike falhou"
  }
fi

# ── BRUTE-FORCE TOOLS (ONLINE) ────────────────────────────────────────────────
section "Ferramentas de Brute-force Online"
BRUTE_PKGS=(
  hydra             # Multi-protocol online brute-force
  medusa            # Parallel login brute-forcer
  ncrack            # High-speed authentication cracker
  patator           # Flexible brute-forcer
  crowbar           # SSH key / OpenVPN brute-force
)
for pkg in "${BRUTE_PKGS[@]}"; do apt_install "$pkg" || true; done

# ── OFFLINE CRACKING TOOLS ────────────────────────────────────────────────────
section "Ferramentas de Quebra de Senha Offline"
CRACK_PKGS=(
  john              # John the Ripper CPU cracker
  johnny            # GUI for John (optional)
)
for pkg in "${CRACK_PKGS[@]}"; do apt_install "$pkg" || true; done

if [[ "$SKIP_GPU" == "false" ]]; then
  apt_install hashcat || true
  apt_install hashcat-utils || true
fi

# Haiti (hash identifier)
if ! command -v haiti &>/dev/null; then
  info "Instalando haiti (identificador de hash)..."
  gem install haiti-hash 2>/dev/null && success "haiti instalado" || \
    warn "instalação do haiti falhou (requer ruby-full: apt install ruby-full)"
fi

# ── SMB / WINDOWS ENUMERATION ─────────────────────────────────────────────────
section "Ferramentas de Enumeração SMB / Windows"
SMB_PKGS=(
  enum4linux        # Windows/Samba enumeration
  enum4linux-ng     # Modern enum4linux rewrite
  smbclient         # SMB client
  smbmap            # SMB share mapper
  nbtscan           # NetBIOS scanner
  rpcclient         # RPC enumeration (in samba-common)
  impacket-scripts  # GetUserSPNs/GetNPUsers — Kerberoasting/AS-REP Roasting
  bloodhound.py     # Coletor de caminho de ataque em Active Directory
)
for pkg in "${SMB_PKGS[@]}"; do apt_install "$pkg" || true; done

# Kerbrute — enumeração de usuário Kerberos (instalado no bloco Go acima
# se disponível; sem fallback apt, esse binário não está nos repositórios)

# CrackMapExec
if ! command -v crackmapexec &>/dev/null && ! command -v cme &>/dev/null; then
  info "Instalando CrackMapExec..."
  apt_install crackmapexec 2>/dev/null || \
    pip_install crackmapexec 2>/dev/null || \
    warn "instalação do CrackMapExec falhou — tente: pip install crackmapexec"
fi

# ── SNMP ──────────────────────────────────────────────────────────────────────
section "Ferramentas de Enumeração SNMP"
SNMP_PKGS=(snmp snmp-mibs-downloader onesixtyone snmpcheck)
for pkg in "${SNMP_PKGS[@]}"; do apt_install "$pkg" || true; done

# ── NETWORK TOOLS ─────────────────────────────────────────────────────────────
section "Ferramentas de Rede Adicionais"
NET_PKGS=(
  netcat-openbsd    # nc fallback
  tcpdump           # Packet capture
  ncat              # Nmap's netcat
  socat             # Socket relay
  arp-scan          # ARP network discovery
  fping             # Parallel ping
  traceroute        # Route tracing
  hping3            # TCP/IP packet crafter
)
for pkg in "${NET_PKGS[@]}"; do apt_install "$pkg" || true; done

# ── WORDLISTS ─────────────────────────────────────────────────────────────────
if [[ "$SKIP_WORDLISTS" == "false" ]]; then
  section "Wordlists & Dicionários"

  apt_install wordlists  || true
  apt_install seclists   || true
  apt_install dirbuster  || true

  # rockyou.txt
  if [[ -f /usr/share/wordlists/rockyou.txt.gz ]] && \
     [[ ! -f /usr/share/wordlists/rockyou.txt ]]; then
    info "Descompactando rockyou.txt..."
    gunzip -k /usr/share/wordlists/rockyou.txt.gz && success "rockyou.txt pronto"
  fi
  [[ -f /usr/share/wordlists/rockyou.txt ]] && \
    success "rockyou.txt: $(wc -l < /usr/share/wordlists/rockyou.txt) linhas" || \
    warn "rockyou.txt não encontrado"

  # WordPress wordlists (fix 0/3 shown in --wordlists)
  WP_DIR="/usr/share/seclists/Discovery/Web-Content/CMS/WordPress"
  mkdir -p "$WP_DIR"
  if [[ ! -f "$WP_DIR/wp-plugins.fuzz.txt" ]]; then
    info "Gerando wordlist de plugins do WordPress..."
    printf '%s\n' \
      "wp-content/plugins/akismet" "wp-content/plugins/jetpack" \
      "wp-content/plugins/contact-form-7" "wp-content/plugins/woocommerce" \
      "wp-content/plugins/yoast-seo" "wp-content/plugins/wordfence" \
      "wp-content/plugins/elementor" "wp-content/plugins/wpforms-lite" \
      "wp-content/plugins/classic-editor" "wp-content/plugins/really-simple-ssl" \
      "wp-content/plugins/wp-super-cache" "wp-content/plugins/all-in-one-seo-pack" \
      "wp-content/plugins/updraftplus" "wp-content/plugins/mailchimp-for-wp" \
      "wp-content/plugins/advanced-custom-fields" "wp-content/plugins/w3-total-cache" \
      "wp-content/plugins/wp-file-manager" "wp-content/plugins/loginizer" \
      "wp-content/plugins/revslider" "wp-content/plugins/gravityforms" \
      "wp-content/plugins/better-wp-security" "wp-content/plugins/sucuri-scanner" \
      "wp-content/plugins/limit-login-attempts-reloaded" "wp-content/plugins/wp-mail-smtp" \
      > "$WP_DIR/wp-plugins.fuzz.txt"
    success "wp-plugins.fuzz.txt criado"
  fi
  if [[ ! -f "$WP_DIR/wp-themes.fuzz.txt" ]]; then
    info "Gerando wordlist de temas do WordPress..."
    printf '%s\n' \
      "wp-content/themes/twentytwentyfour" "wp-content/themes/twentytwentythree" \
      "wp-content/themes/twentytwentytwo" "wp-content/themes/astra" \
      "wp-content/themes/divi" "wp-content/themes/avada" \
      "wp-content/themes/generatepress" "wp-content/themes/oceanwp" \
      "wp-content/themes/hello-elementor" "wp-content/themes/flatsome" \
      "wp-content/themes/storefront" "wp-content/themes/newspaper" \
      > "$WP_DIR/wp-themes.fuzz.txt"
    success "wp-themes.fuzz.txt criado"
  fi
  if [[ ! -f "$WP_DIR/wordpress-plugins.txt" ]]; then
    printf '%s\n' akismet jetpack contact-form-7 woocommerce wordpress-seo \
      wordfence elementor updraftplus revslider gravityforms sucuri-scanner \
      > "$WP_DIR/wordpress-plugins.txt"
    success "wordpress-plugins.txt criado"
  fi

  # XSS payloads
  XSS_FILE="/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt"
  mkdir -p "$(dirname $XSS_FILE)"
  if [[ ! -f "$XSS_FILE" ]]; then
    info "Gerando lista de payloads de XSS..."
    printf '%s\n' \
      '<script>alert(1)</script>' '"><script>alert(1)</script>' \
      '<img src=x onerror=alert(1)>' '<svg onload=alert(1)>' \
      "';alert(1)//" '{{7*7}}' '${7*7}' \
      '<details open ontoggle=alert(1)>' '" onmouseover="alert(1)' \
      '<iframe src="javascript:alert(1)">' '<body onload=alert(1)>' \
      '<script>alert(document.cookie)</script>' \
      > "$XSS_FILE"
    success "XSS-Jhaddix.txt criado"
  fi

  # SQLi payloads
  SQLI_FILE="/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt"
  mkdir -p "$(dirname $SQLI_FILE)"
  if [[ ! -f "$SQLI_FILE" ]]; then
    info "Gerando lista de payloads de SQLi..."
    printf '%s\n' \
      "'" "''" "' OR '1'='1" "' OR '1'='1'--" "1 OR 1=1" \
      "1' ORDER BY 1--" "' UNION SELECT NULL--" "1' AND SLEEP(5)--" \
      "admin'--" "' OR 1=1--" "' OR 1=1#" "1; DROP TABLE users--" \
      > "$SQLI_FILE"
    success "Generic-SQLi.txt criado"
  fi

  # LFI payloads
  LFI_FILE="/usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"
  mkdir -p "$(dirname $LFI_FILE)"
  if [[ ! -f "$LFI_FILE" ]]; then
    info "Gerando lista de payloads de LFI..."
    printf '%s\n' \
      "../../etc/passwd" "../../../etc/passwd" "../../../../etc/passwd" \
      "../../../../../etc/passwd" "../../etc/shadow" "../../etc/hosts" \
      "../../proc/self/environ" "/etc/passwd" "/etc/shadow" \
      "....//....//etc/passwd" "..%2F..%2Fetc%2Fpasswd" \
      > "$LFI_FILE"
    success "LFI-gracefulsecurity-linux.txt criado"
  fi

  # Parameters wordlist
  PARAMS_FILE="/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
  mkdir -p "$(dirname $PARAMS_FILE)"
  if [[ ! -f "$PARAMS_FILE" ]]; then
    info "Gerando lista de nomes de parâmetros..."
    printf '%s\n' id page search query q s url path file dir name user username \
      email pass password token key api_key apikey auth redirect return next goto \
      target dest action cmd exec command code lang locale callback jsonp format \
      type cat category view template theme style debug test mode sort order limit \
      offset start ref source > "$PARAMS_FILE"
    success "burp-parameter-names.txt criado"
  fi

  # vhosts wordlist
  VHOSTS_FILE="/usr/share/seclists/Discovery/Web-Content/vhosts.txt"
  if [[ ! -f "$VHOSTS_FILE" ]]; then
    info "Gerando wordlist de vhosts..."
    printf '%s\n' dev staging test admin api internal intranet portal dashboard \
      app beta demo preview sandbox qa uat preprod old new v2 mobile m secure \
      mail smtp ftp vpn remote git gitlab jenkins monitor logs db database backup \
      cdn assets static media docs help wiki support crm erp > "$VHOSTS_FILE"
    success "vhosts.txt criado"
  fi

  # SNMP communities
  SNMP_FILE="/usr/share/seclists/Discovery/SNMP/snmp.txt"
  mkdir -p "$(dirname $SNMP_FILE)"
  if [[ ! -f "$SNMP_FILE" ]]; then
    printf '%s\n' public private community manager admin snmp cisco default \
      internal monitor write read secret password test guest backup network \
      switch router > "$SNMP_FILE"
    success "snmp.txt criado"
  fi

  # Roda o corretor de wordlists embutido da SENTINELA para lacunas restantes
  info "Rodando corretor de lacunas de wordlist..."
  cd "$INSTALL_DIR"
  python3 -c "
import sys; sys.path.insert(0,'.')
from modules.wordlists import WordlistManager
wl = WordlistManager(verbose=True)
fixed = wl.fix_missing(verbose=True)
print(f'Corrigidas {len(fixed)} categorias faltando com fallback embutido')
" 2>/dev/null && success "Lacunas de wordlist corrigidas" || true

  # Final count
  if [[ -d /usr/share/seclists ]]; then
    SECLISTS_COUNT=$(find /usr/share/seclists -name "*.txt" | wc -l)
    success "SecLists: $SECLISTS_COUNT arquivos de wordlist"
  fi
fi

# ── PYTHON DEPENDENCIES ───────────────────────────────────────────────────────
if [[ "$SKIP_PYTHON" == "false" ]]; then
  section "Dependências Python"

  if [[ -f "$INSTALL_DIR/requirements.txt" ]]; then
    info "Instalando a partir de requirements.txt..."
    pip_install -r "$INSTALL_DIR/requirements.txt"
  else
    PYTHON_PKGS=(
      requests urllib3 dnspython beautifulsoup4
      lxml colorama tqdm tabulate
      reportlab
    )
    for pkg in "${PYTHON_PKGS[@]}"; do
      info "  pip: $pkg"
      pip_install "$pkg"
    done
  fi
  success "Dependências Python instaladas"

  info "Instalando scanners de CVE extras (cve-bin-tool, mobsfscan)..."
  pip_install cve-bin-tool
  pip_install mobsfscan

  info "Instalando kube-hunter..."
  pip_install kube-hunter
fi

# ── GIT-DUMPER + GITLEAKS (reconstrução de .git exposto + scan de segredo) ──
if ! command -v git-dumper &>/dev/null; then
  info "Instalando git-dumper..."
  pip_install git-dumper || \
    (git clone --depth=1 https://github.com/arthaud/git-dumper.git /opt/git-dumper 2>/dev/null && \
     pip_install -r /opt/git-dumper/requirements.txt 2>/dev/null && \
     ln -sf /opt/git-dumper/git_dumper.py /usr/local/bin/git-dumper && \
     chmod +x /usr/local/bin/git-dumper && success "git-dumper instalado") || \
    warn "instalação do git-dumper falhou — opcional, sem impacto no resto"
fi
apt_install gitleaks || pip_install gitleaks || warn "gitleaks não instalado — instale manualmente: https://github.com/gitleaks/gitleaks"

# ── OSV-SCANNER (Go) ────────────────────────────────────────────────────────
if command -v go &>/dev/null && ! command -v osv-scanner &>/dev/null; then
  info "Instalando osv-scanner via go install..."
  go install github.com/google/osv-scanner/cmd/osv-scanner@latest 2>/dev/null && \
    cp "$HOME/go/bin/osv-scanner" /usr/local/bin/ 2>/dev/null && \
    success "osv-scanner instalado" || warn "instalação do osv-scanner falhou"
fi

# ── OWASP NETTACKER (git clone — não tem pacote pip oficial) ─────────────────
if ! command -v nettacker &>/dev/null; then
  info "Clonando OWASP Nettacker..."
  git clone --depth=1 https://github.com/OWASP/Nettacker.git /opt/nettacker 2>/dev/null && \
    pip_install -r /opt/nettacker/requirements.txt 2>/dev/null && \
    ln -sf /opt/nettacker/nettacker.py /usr/local/bin/nettacker && \
    chmod +x /usr/local/bin/nettacker && \
    success "Nettacker instalado" || warn "instalação do Nettacker falhou — opcional, sem impacto no resto"
fi

# ── FERRAMENTAS PESADAS (só com --full) ──────────────────────────────────────
if [[ "$FULL_INSTALL" == "true" ]]; then
  section "Ferramentas pesadas (--full): OWASP ZAP"
  apt_install zaproxy || true
  warn "ZAP instalado mas é pesado (Java) — rode 'zap.sh'/'owasp-zap' na primeira vez pra aceitar EULA/baixar addons."
else
  info "Pulando OWASP ZAP (pesado, Java) — rode com --full pra instalar. Ex: sudo bash install.sh --full"
fi

# ── OPENVAS/GVM — NUNCA instalado automaticamente ────────────────────────────
section "OpenVAS/Greenbone (GVM)"
warn "A SENTINELA NÃO instala/configura o GVM automaticamente — é pesado demais (daemon + banco de"
warn "assinaturas próprio) pra rodar por padrão. Se você já tem GVM rodando em outro lugar, use"
warn "'sentinela ... --openvas' pra importar os resultados via gvm-cli. Setup do GVM:"
warn "  https://greenbone.github.io/docs/latest/22.4/kali-linux/index.html"

# ── NUCLEI TEMPLATES ──────────────────────────────────────────────────────────
if command -v nuclei &>/dev/null; then
  section "Templates do Nuclei"
  info "Atualizando templates do Nuclei..."
  nuclei -update-templates -silent 2>/dev/null && \
    success "Templates do Nuclei atualizados" || warn "Atualização dos templates do Nuclei falhou (verifique a internet)"
fi

# ── SYMLINK ───────────────────────────────────────────────────────────────────
section "Criando Symlink"
SENTINELA_BIN="$INSTALL_DIR/sentinela.py"
SYMLINK="/usr/local/bin/sentinela"

if [[ -f "$SENTINELA_BIN" ]]; then
  chmod +x "$SENTINELA_BIN"
  ln -sf "$SENTINELA_BIN" "$SYMLINK"
  success "Symlink criado: $SYMLINK → $SENTINELA_BIN"
else
  error "sentinela.py não encontrado em $SENTINELA_BIN"
  exit 1
fi

# ── VERIFY PYTHON SYNTAX ─────────────────────────────────────────────────────
section "Verificação de Sintaxe"
cd "$INSTALL_DIR"
SYNTAX_OK=true
for pyfile in sentinela.py modules/utils.py modules/recon.py modules/web_analysis.py \
              modules/vuln_detection.py modules/reporting.py modules/wordlists.py \
              modules/workflow.py modules/tool_integration.py; do
  if [[ -f "$pyfile" ]]; then
    if python3 -m py_compile "$pyfile" 2>/dev/null; then
      echo -e "  ${GRN}+${RST} $pyfile"
    else
      echo -e "  ${RED}-${RST} $pyfile"
      SYNTAX_OK=false
    fi
  fi
done

if [[ "$SYNTAX_OK" == "true" ]]; then
  success "Todas as verificações de sintaxe passaram"
else
  warn "Alguns arquivos têm erros de sintaxe — veja acima"
fi

# ── TOOL INVENTORY ────────────────────────────────────────────────────────────
section "Resumo de Ferramentas Instaladas"
TOOLS=(nmap masscan gobuster ffuf dirb wfuzz feroxbuster nikto whatweb wafw00f
       sqlmap hydra medusa john hashcat nuclei dnsrecon amass sublist3r
       theHarvester wpscan enum4linux smbclient crackmapexec snmpwalk onesixtyone
       sslscan testssl xsstrike commix
       subfinder assetfinder httpx-toolkit katana waybackurls gau dalfox wcvs
       searchsploit trivy arjun eyewitness kerbrute
       impacket-GetUserSPNs impacket-GetNPUsers bloodhound-python)

INSTALLED=(); MISSING=()
for t in "${TOOLS[@]}"; do
  if command -v "$t" &>/dev/null; then
    INSTALLED+=("$t")
  else
    MISSING+=("$t")
  fi
done

echo -e "\n  ${GRN}Instaladas (${#INSTALLED[@]}):${RST}"
printf '    %s\n' "${INSTALLED[@]}" | pr -3 -t -w 80

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo -e "\n  ${YLW}Não encontradas (${#MISSING[@]}):${RST}"
  printf '    %s\n' "${MISSING[@]}" | pr -3 -t -w 80
  echo ""
  warn "Instalar ferramentas faltando:"
  echo "    sudo apt install -y ${MISSING[*]::5}"
fi

# ── INSTRUÇÕES FINAIS ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${RED}"
echo -e "              uuuuuuu"
echo -e "          uu\$\$\$\$\$\$\$\$\$\$\$uu"
echo -e "       uu\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$uu"
echo -e "      u\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$\$u"
echo -e "      u\$\$\$\$\$\$\"   \"\$\$\$\"   \"\$\$\$\$\$\$u"
echo -e "      \"\$\$\$\$\"      u\$u       \$\$\$\$\""
echo -e "       \$\$\$u       u\$u       u\$\$\$"
echo -e "        \"\$\$\$\$uu\$\$\$   \$\$\$uu\$\$\$\$\""
echo -e "          \"\$\$\$\$\$\$\$\"   \"\$\$\$\$\$\$\$\""
echo -e "             u\$\$\$\$\$\$\$u\$\$\$\$\$\$\$u"
echo -e "               \"\$\$\$\$\$\$\$\$\$\""
echo -e "${DIM}                by github.com/3rr0rrr${RST}"
echo -e "${RST}"
echo -e "${BOLD}${RED}╔══════════════════════════════════════════════════╗${RST}"
echo -e "${BOLD}${RED}║      SENTINELA v1.0.0 — Instalação Completa!     ║${RST}"
echo -e "${BOLD}${RED}╚══════════════════════════════════════════════════╝${RST}"
echo ""
echo -e "${RED}Início Rápido:${RST}"
echo -e "  ${BOLD}sentinela -t exemplo.com --all --report pdf${RST}"
echo ""
echo -e "${RED}Ver status das ferramentas:${RST}"
echo -e "  sentinela -t exemplo.com --tools"
echo ""
echo -e "${RED}Ver wordlists:${RST}"
echo -e "  sentinela -t exemplo.com --wordlists"
echo ""
echo -e "${RED}Guia completo de workflow de pentest:${RST}"
echo -e "  sentinela -t exemplo.com --workflow"
echo ""
echo -e "${YLW}[!]  Apenas para testes de segurança autorizados.${RST}"
echo ""
