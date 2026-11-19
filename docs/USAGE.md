# Utilisation

## Mode interactif

vulnscan

Le menu propose :

| Choix | Action |
|---|---|
| 1 | Audit complet + deep crawl |
| 2 | Passif (headers, fichiers, cookies, comments) |
| 3 | Injections sur URL personnalisee |
| 4 | IDOR / Open Redirect / CORS |
| 5 | Deep crawl + tests |
| 6 | Formulaire (SQLi bypass / XSS) |
| 7 | Scan pages protegees (avec cookie) |
| q | Quitter |

## Mode CLI

vulnscan https://exemple.com --full --html rapport.html --json rapport.json

## Options

| Option | Description |
|---|---|
| url | URL ou IP cible |
| --full | Audit complet |
| --html FILE | Rapport HTML |
| --json FILE | Rapport JSON |
| --cookie STR | Cookie de session |
| --user USER | Basic Auth (utilisateur) |
| --password PASS | Basic Auth (mot de passe) |
| --scan-protected LIST | Chemins a scanner |
| --delay SEC | Delai entre requetes (defaut: 0.5) |
| --version | Affiche la version |
| --check | Verifie l'environnement |

## Exemples

### Scan complet avec rapport HTML

vulnscan https://scanme.nmap.org --full --html rapport.html

### Scan avec authentification Basic

vulnscan https://exemple.com --user admin --password secret --full

### Scan avec cookie de session

vulnscan https://exemple.com --cookie "PHPSESSID=abc123" --scan-protected "/admin/,/profile/"

### Scan d'une IP locale

vulnscan 192.168.1.10:8080 --full

## Sortie console

Chaque finding affiche :

  [CRITICAL] SQL Injection (error-based)
         http://cible/page?id=1
         payload : {'id': "1'"}
         preuve  : You have an error in your SQL syntax

## Rapport JSON

{
  "target": "https://exemple.com",
  "date": "2026-11-19T02:35:36",
  "findings": [
    {
      "name": "HSTS manquant",
      "severity": "MEDIUM",
      "url": "https://exemple.com",
      "evidence": "En-tete absent: Strict-Transport-Security",
      "remediation": "Ajoutez: Strict-Transport-Security: max-age=31536000"
    }
  ]
}

## Rapport HTML

Ouvrez rapport.html dans un navigateur : tableau colore par severite.
