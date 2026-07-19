#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  SENTINELA v1.0.0 — Script de Exemplos de Uso
#  Criado por github.com/3rr0rrr — baseado em GhostScan (MIT License)
#  Rode qualquer exemplo passando o número: bash usage.sh 1
#  Ou apenas leia este arquivo como guia de referência.
#
#  USO AUTORIZADO APENAS — rode somente contra sistemas próprios ou com
#  autorização explícita por escrito.
# ═══════════════════════════════════════════════════════════════════════════

TARGET="${2:-exemplo.com}"   # Passe o alvo como segundo argumento, padrão exemplo.com

show_help() {
cat << 'HELP'
SENTINELA v1.0.0 — Exemplos de Uso (by github.com/3rr0rrr)

  bash usage.sh <número_do_exemplo> [alvo]

EXEMPLOS:
  1  — Scan completo (todos os módulos, relatório PDF)
  2  — Só recon (DNS, subdomínios, portas)
  3  — Só scan web
  4  — Scan de vulnerabilidades (headers, SQLi, XSS, CVEs)
  5  — Recon paralelo (todas as ferramentas simultaneamente)
  6  — Modo agressivo + todas as injeções
  7  — Modo bypass de WAF
  8  — Navegador headless (DOM XSS)
  9  — Roteamento via Tor
  10 — Scan de rede interna
  11 — Scan profundo de WordPress
  12 — Brute-force de login / serviços
  13 — Quebra de hash offline
  14 — Mostrar inventário de ferramentas
  15 — Mostrar inventário de wordlists
  16 — Guia completo de workflow de pentest
  17 — Retomar scan interrompido
  18 — Scan restrito por escopo
  19 — Via proxy Burp Suite
  20 — Filtro de severidade mínima (só HIGH+)
  21 — Modo ghost furtivo (jitter + rotação de UA + proxies)

HELP
}

run_example() {
  case $1 in

  # ── 1. SCAN COMPLETO ────────────────────────────────────────────────────
  1)
    echo "[+] Scan completo — todos os módulos, relatório PDF + Markdown"
    sentinela -t "$TARGET" \
      --all \
      --report both \
      --output ./results \
      -v
    ;;

  # ── 2. SÓ RECON ──────────────────────────────────────────────────────────
  2)
    echo "[+] Só recon — DNS, WHOIS, subdomínios, portas"
    sentinela -t "$TARGET" \
      --recon \
      --ports "21,22,25,53,80,110,143,443,445,3306,3389,8080,8443" \
      --report json \
      --output ./results
    ;;

  # ── 3. SÓ SCAN WEB ───────────────────────────────────────────────────────
  3)
    echo "[+] Scan web — crawl, dir brute, nikto, nuclei, segredos em JS"
    sentinela -t "$TARGET" \
      --web \
      --depth 4 \
      --threads 30 \
      --wordlist-size large \
      --report both \
      --output ./results
    ;;

  # ── 4. SCAN DE VULNERABILIDADES ─────────────────────────────────────────
  4)
    echo "[+] Scan de vulnerabilidades — headers, SQLi, XSS, correlação de CVE"
    sentinela -t "$TARGET" \
      --vuln \
      --sqli \
      --xss \
      --report both \
      --output ./results
    ;;

  # ── 5. RECON PARALELO (RÁPIDO) ──────────────────────────────────────────
  5)
    echo "[+] Recon paralelo — nmap + amass + sublist3r + theHarvester simultaneamente"
    sentinela -t "$TARGET" \
      --recon \
      --parallel \
      --threads 30 \
      --report json \
      --output ./results
    ;;

  # ── 6. SCAN COMPLETO AGRESSIVO ───────────────────────────────────────────
  6)
    echo "[+] Modo agressivo — todos os módulos + injeções + brute-force"
    sentinela -t "$TARGET" \
      --all \
      --intensity aggressive \
      --sqli \
      --xss \
      --brute \
      --fast \
      --wordlist-size large \
      --threads 50 \
      --report all \
      --output ./results
    ;;

  # ── 7. BYPASS DE WAF ─────────────────────────────────────────────────────
  7)
    echo "[+] Bypass de WAF — autodetecta e aplica perfil de evasão"
    sentinela -t "$TARGET" \
      --web \
      --vuln \
      --sqli \
      --xss \
      --waf-bypass \
      --intensity normal \
      --report both \
      --output ./results

    echo ""
    echo "[+] Forçar perfil específico de WAF (exemplo CloudFlare):"
    echo "    sentinela -t $TARGET --web --waf-bypass --waf-profile cloudflare"
    echo ""
    echo "[+] Perfis de WAF disponíveis:"
    echo "    cloudflare | akamai | aws-waf | f5 | imperva | modsecurity | wordfence | sucuri | generic"
    ;;

  # ── 8. NAVEGADOR HEADLESS (DOM XSS) ─────────────────────────────────────
  8)
    echo "[+] Navegador headless — DOM XSS, endpoints ocultos, storage JS"
    echo "    Requer: pip install playwright && playwright install chromium"
    sentinela -t "$TARGET" \
      --web \
      --browser \
      --depth 3 \
      --report both \
      --output ./results
    ;;

  # ── 9. ROTEAMENTO VIA TOR ────────────────────────────────────────────────
  9)
    echo "[+] Scan via Tor — requer o serviço tor rodando"
    echo "    Setup: sudo apt install tor && sudo service tor start"
    sentinela -t "$TARGET" \
      --all \
      --tor \
      --intensity passive \
      --report both \
      --output ./results
    ;;

  # ── 10. SCAN DE REDE INTERNA ─────────────────────────────────────────────
  10)
    echo "[+] Scan de rede interna — range CIDR"
    sentinela -t "192.168.1.0/24" \
      --recon \
      --no-subdomains \
      --no-ssrf-protect \
      --ports "22,80,135,139,443,445,3306,3389,5432,5900,8080,8443" \
      --fast \
      --parallel \
      --report both \
      --output ./results
    ;;

  # ── 11. SCAN PROFUNDO DE WORDPRESS ──────────────────────────────────────
  11)
    echo "[+] Scan profundo de WordPress — plugins, temas, usuários, brute-force"
    sentinela -t "$TARGET" \
      --web \
      --vuln \
      --xss \
      --sqli \
      --brute \
      --wordlist-size large \
      --intensity aggressive \
      --report both \
      --output ./results

    echo ""
    echo "[+] Comandos manuais do WPScan:"
    echo "    wpscan --url https://$TARGET --enumerate vp,vt,u,cb,dbe --plugins-detection aggressive"
    echo "    wpscan --url https://$TARGET --passwords /usr/share/wordlists/rockyou.txt"
    ;;

  # ── 12. BRUTE-FORCE ───────────────────────────────────────────────────────
  12)
    echo "[+] Brute-force online — login HTTP, SSH, FTP, SMB (use apenas com autorização explícita)"
    sentinela -t "$TARGET" \
      --vuln \
      --brute \
      --username-wordlist /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
      --password-wordlist /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
      --report both \
      --output ./results

    echo ""
    echo "[+] Exemplos manuais do Hydra:"
    echo "    # Formulário HTTP POST:"
    echo "    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt $TARGET http-post-form '/login:user=^USER^&pass=^PASS^:Invalid' -t 16 -f"
    echo "    # SSH:"
    echo "    hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://$TARGET -t 4 -f"
    echo "    # SMB:"
    echo "    crackmapexec smb $TARGET -u users.txt -p /usr/share/wordlists/rockyou.txt"
    ;;

  # ── 13. QUEBRA DE HASH OFFLINE ──────────────────────────────────────────
  13)
    echo "[+] Quebra de hash offline — John + Hashcat"
    echo ""
    echo "    John the Ripper (CPU):"
    echo "    john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt"
    echo "    john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64"
    echo "    john hashes.txt --format=ntlm --wordlist=/usr/share/wordlists/rockyou.txt"
    echo "    john --show hashes.txt"
    echo ""
    echo "    Hashcat (GPU — modos comuns):"
    echo "    hashcat -m 0    hashes.txt /usr/share/wordlists/rockyou.txt --force  # MD5"
    echo "    hashcat -m 100  hashes.txt /usr/share/wordlists/rockyou.txt --force  # SHA1"
    echo "    hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --force  # NTLM"
    echo "    hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt --force  # Net-NTLMv2"
    echo "    hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt --force  # bcrypt"
    echo "    hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt --force  # sha512crypt"
    echo ""
    echo "    Com regras:"
    echo "    hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force"
    echo ""
    echo "    Quebra de chave SSH:"
    echo "    ssh2john id_rsa > id_rsa.hash"
    echo "    john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt"
    ;;

  # ── 14. INVENTÁRIO DE FERRAMENTAS ───────────────────────────────────────
  14)
    echo "[+] Mostra todas as ferramentas instaladas"
    sentinela -t "$TARGET" --tools
    ;;

  # ── 15. INVENTÁRIO DE WORDLISTS ─────────────────────────────────────────
  15)
    echo "[+] Mostra todas as wordlists disponíveis"
    sentinela -t "$TARGET" --wordlists
    ;;

  # ── 16. GUIA DE WORKFLOW ────────────────────────────────────────────────
  16)
    echo "[+] Referência completa de workflow de pentest"
    sentinela -t "$TARGET" --workflow
    ;;

  # ── 17. RETOMAR SCAN ─────────────────────────────────────────────────────
  17)
    echo "[+] Retoma de uma sessão salva"
    LATEST=$(ls -t ./results/session_*.json 2>/dev/null | head -1)
    if [[ -z "$LATEST" ]]; then
      echo "[-] Nenhum arquivo de sessão encontrado em ./results/"
      echo "    Rode um scan primeiro, depois use --resume"
    else
      echo "[+] Retomando de: $LATEST"
      sentinela -t "$TARGET" \
        --web \
        --vuln \
        --resume "$LATEST" \
        --report both \
        --output ./results
    fi
    ;;

  # ── 18. SCAN RESTRITO POR ESCOPO ────────────────────────────────────────
  18)
    echo "[+] Scan restrito por escopo — bloqueia requisições fora de escopo"
    sentinela -t "$TARGET" \
      --all \
      --scope "*.${TARGET}" \
      --scope "${TARGET}" \
      --strict-scope \
      --report both \
      --output ./results

    echo ""
    echo "[+] Com arquivo de escopo:"
    echo "    echo '*.exemplo.com'  > scope.txt"
    echo "    echo 'exemplo.com'   >> scope.txt"
    echo "    echo '!staging.exemplo.com' >> scope.txt  # exclui staging"
    echo "    sentinela -t exemplo.com --all --scope-file scope.txt --strict-scope"
    ;;

  # ── 19. VIA BURP SUITE ───────────────────────────────────────────────────
  19)
    echo "[+] Roteia todo o tráfego pelo proxy do Burp Suite"
    echo "    Certifique-se que o Burp está rodando em 127.0.0.1:8080"
    sentinela -t "$TARGET" \
      --web \
      --vuln \
      --proxy "http://127.0.0.1:8080" \
      --report both \
      --output ./results

    echo ""
    echo "[+] Com cookie de sessão (scan pós-autenticação):"
    echo "    sentinela -t $TARGET --web --proxy http://127.0.0.1:8080 --cookies '{\"PHPSESSID\":\"abc123\"}'"
    ;;

  # ── 20. FILTRO DE SEVERIDADE ─────────────────────────────────────────────
  20)
    echo "[+] Mostra só findings HIGH e CRITICAL — reduz ruído"
    sentinela -t "$TARGET" \
      --all \
      --min-severity high \
      --report both \
      --output ./results
    ;;

  # ── 21. MODO GHOST FURTIVO ───────────────────────────────────────────────
  21)
    echo "[+] Modo ghost — jitter aleatório, rotação de User-Agent, proxy rotation"
    echo "    Crie um proxies.txt com um proxy por linha antes de rodar (opcional)"
    sentinela -t "$TARGET" \
      --web \
      --mode ghost \
      --proxy-list proxies.txt \
      --report both \
      --output ./results
    ;;

  *)
    show_help
    ;;
  esac
}

# ── PONTO DE ENTRADA ──────────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
  show_help
else
  run_example "$1"
fi
