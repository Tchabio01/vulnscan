# Changelog

Toutes les modifications notables de VulnScan sont documentees ici.

## [3.3.1] - 2026-11-19

### Ajoute
- Methode ping() : teste la connectivite avant le scan
- ask_url() robuste : normalisation http/https, IP privees, IP:port
- Option --version
- Option --check
- Banniere dynamique selon l'OS

### Corrige
- Faux "Aucun finding" quand la cible est injoignable
- Indentation de main()
- Import urllib3 obsolete

## [3.3.0] - 2026-11-19

### Ajoute
- Support multiplateforme : Linux, macOS, Windows, Termux
- pyproject.toml
- install.sh, install.ps1, install-termux.sh
- Commande globale vulnscan

## [3.2.0] - 2026-09-26

### Ajoute
- Version initiale sur GitHub
- 18 techniques d'audit
- Mode interactif + CLI
- Rapports JSON + HTML
- Deep crawl
