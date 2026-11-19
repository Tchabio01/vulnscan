# Architecture

## Vue d'ensemble

VulnScan est un script unique (vulnscan.py, ~700 lignes) organise en deux classes.

## Structure

vulnscan.py
- class C              : Couleurs ANSI
- class Finding        : Un finding de securite
- class VulnScanner    : Le scanner (methodes check_*)
- BANNER / MENU        : Constantes d'affichage
- ask_url()            : Saisie URL/IP robuste
- ask_delay()          : Saisie du delai
- ask_params_url()     : Saisie URL + params
- setup_auth()         : Configuration Basic Auth / cookie / header
- run_full()           : Scan complet
- mode_interactif()    : Menu interactif
- main()               : Entree CLI

## Classe VulnScanner

### Attributs

| Attribut | Type | Description |
|---|---|---|
| base_url | str | URL cible normalisee |
| delay | float | Delai entre requetes |
| timeout | int | Timeout par requete |
| session | requests.Session | Session HTTP partagee |
| findings | list | Findings detectes |
| visited | set | URLs visitees |
| crawled_pages | set | Pages deja analysees |

### Methodes

| Methode | Role |
|---|---|
| ping() | Teste la connectivite |
| req() | Requete HTTP avec retry + delai |
| add() | Ajoute un finding (deduplique) |
| check_headers() | En-tetes de securite |
| check_files() | Fichiers sensibles exposes |
| check_html_comments() | Commentaires HTML |
| check_cookies() | Attributs cookies |
| check_methods() | Methodes HTTP |
| check_dir_listing() | Directory listing |
| check_forms() | Formulaires (CSRF) |
| check_form_vulns() | SQLi bypass sur formulaires |
| check_sqli() | SQL Injection |
| check_xss() | XSS reflechi |
| check_idor() | IDOR |
| check_lfi() | LFI |
| check_open_redirect() | Open Redirect |
| check_cors() | CORS |
| check_info_disclosure() | Erreurs exposees |
| scan_protected() | Pages protegees |
| crawl_links() | Crawl simple |
| deep_crawl() | Crawl recursif |
| report() | Genere JSON + HTML |
| _html() | Template HTML |

## Flux d'execution

main()
- parse args (argparse)
- si --check : affiche env, return
- si --version : affiche version, return
- si pas d'URL : mode_interactif()
  - ask_url()
  - setup_auth()
  - ping()
  - menu (1-7)
- sinon : mode CLI
  - ping()
  - run_full() ou check partiel
  - report()

## Flux d'un finding

check_*() detecte une vulnerabilite
- Finding(name, severity, url, evidence, description, remediation, payload, proof)
- add(finding) : deduplication (name, url, evidence)
- self.findings.append(finding)
- report() : JSON + HTML

## Dependances

| Paquet | Version | Usage |
|---|---|---|
| requests | >=2.31.0 | Requetes HTTP |
| urllib3 | >=2.0.0 | Desactivation warnings SSL |

Aucune autre dependance. Pas de framework, pas d'ORM.
