# Aviso de Autoria

**SENTINELA** é uma versão modificada e estendida do projeto **GhostScan**
(© 2024 GhostScan, MIT License — ver [LICENSE](LICENSE)).

- **Modificações, tradução para português e novas funcionalidades:**
  © 2026 [3rr0rrr](https://github.com/3rr0rrr)
- **Base original:** GhostScan v3.0, MIT License, © 2024

Esta versão mantém o aviso de copyright e a licença MIT original, conforme
exigido pelos termos da licença. O uso, cópia, modificação e distribuição
desta ferramenta seguem as mesmas condições descritas em [LICENSE](LICENSE).

## O que foi adicionado pela SENTINELA em relação ao GhostScan original

- Tradução completa da interface, help e relatórios para português do Brasil
- 6 novos plugins: JWT, CORS misconfig, GraphQL introspection, subdomain
  takeover, secrets/entropy scanner, security headers avançado
- Score CVSS v3.1 por finding, além do score próprio da ferramenta
- Sumário executivo nos relatórios (linguagem não-técnica para cliente/gestor)
- Checklist automático de endpoints testados/não testados
- Mapeamento de compliance PCI-DSS v4.0 / LGPD por finding
- Hash SHA-256 de cadeia de custódia em cada relatório gerado
- Recon passivo via crt.sh (sempre) + Shodan/Censys (opcional, com API key)
- Modo `--mode ghost` — jitter aleatório, rotação de User-Agent, proxy rotation
- Diagrama de kill chain (cadeia de ataque) no relatório HTML

**Uso autorizado apenas.** Esta ferramenta é destinada a testes de segurança
com autorização explícita por escrito. Os autores (originais e desta versão)
não se responsabilizam por uso ilegal ou não autorizado.
