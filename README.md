# 🛡️ VulnScan

Scanner pédagogique de vulnérabilités web pour Termux.

## Fonctionnalités

- 18 techniques d'audit : headers, fichiers exposés, cookies, SQLi, XSS, IDOR, LFI, CSRF, CORS, Open Redirect
- Mode interactif et CLI
- Support Basic Auth, cookie de session, headers custom
- Rapports JSON + HTML avec preuves et remédiations
- Deep crawl configurable
- Détection de redirects "soft" (302 avec body)

## Installation

pkg install python -y
pip install requests

## Utilisation

Mode interactif :
python vulnscan.py

Mode CLI :
python vulnscan.py https://exemple.com --full --html rapport.html

## Avertissement légal

Outil éducatif uniquement. À utiliser sur des cibles autorisées (tes sites, CTF, labs).

## Auteur

Tchabio01
