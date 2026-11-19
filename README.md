# 🛡️ VulnScan

Scanner pédagogique de vulnérabilités web — **Linux, macOS, Windows et Termux**.

## Téléchargement

**[Dernière version : v3.3.1](https://github.com/Tchabio01/vulnscan/releases/latest)**

| Plateforme | Fichier |
|---|---|
| Linux / macOS / Termux | [vulnscan-3.3.1.tar.gz](https://github.com/Tchabio01/vulnscan/releases/download/v3.3.1/vulnscan-3.3.1.tar.gz) |
| Windows | [vulnscan-3.3.1.zip](https://github.com/Tchabio01/vulnscan/releases/download/v3.3.1/vulnscan-3.3.1.zip) |
| Code source | [main.tar.gz](https://github.com/Tchabio01/vulnscan/archive/refs/heads/main.tar.gz) |

## Fonctionnalités

- 18 techniques d'audit : headers, fichiers exposés, cookies, SQLi, XSS, IDOR, LFI, CSRF, CORS, Open Redirect
- Mode interactif et CLI
- Support Basic Auth, cookie de session, headers custom
- Rapports JSON + HTML avec preuves et remédiations
- Deep crawl configurable
- Détection de redirects soft (302 avec body)

## Prérequis

- Python 3.8 ou supérieur

## Installation

### Linux / macOS

git clone https://github.com/Tchabio01/vulnscan.git
cd vulnscan
bash install.sh
source .venv/bin/activate

### Windows (PowerShell)

git clone https://github.com/Tchabio01/vulnscan.git
cd vulnscan
powershell -ExecutionPolicy Bypass -File install.ps1

### Termux

pkg install git python -y
git clone https://github.com/Tchabio01/vulnscan.git
cd vulnscan
bash install-termux.sh
source .venv/bin/activate

### Vérification

vulnscan --version
vulnscan --check

## Utilisation

### Mode interactif

vulnscan

### Mode CLI

vulnscan https://exemple.com --full --html rapport.html --json rapport.json

### Options utiles

vulnscan --help
vulnscan --version
vulnscan --check

## Avertissement l’légal

Outil éducatif uniquement. À utiliser sur des cibles autorisées (vos sites, CTF, labs).

## Auteur

Tchabio01
