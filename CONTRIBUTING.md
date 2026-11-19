# Contribuer a VulnScan

Merci de votre interet !

## Signaler un bug

1. Verifiez que le bug n'est pas deja signale dans les issues
2. Ouvrez une nouvelle issue avec :
   - OS et version de Python
   - Commande executee
   - Comportement attendu vs observe
   - Sortie d'erreur complete

## Proposer une fonctionnalite

1. Ouvrez une issue avec le label enhancement
2. Decrivez le cas d'usage et le benefice
3. Attendez la validation avant de coder

## Soumettre une Pull Request

1. Fork + clone le depot
2. Creer une branche : git checkout -b feature/ma-fonctionnalite
3. Installer : bash install.sh && source .venv/bin/activate
4. Coder + tester : python -m py_compile vulnscan.py && vulnscan --check
5. Commit : git commit -m "feat: description courte"
6. Push + PR

## Style de code

- Python 3.8+
- Dependances externes limitees a requests et urllib3
- Fonctions courtes, noms explicites
- Commentaires en francais

## Code de conduite

- Respect, bienveillance, inclusion
- Pas de spam, pas de scan non autorise
- Usage educatif uniquement
