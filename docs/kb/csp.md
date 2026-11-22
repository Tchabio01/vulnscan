# CSP manquant

## Description
L'en-tete `Content-Security-Policy` limite les sources de contenu.

## Correctifs

### Apache
Header set Content-Security-Policy "default-src 'self'; script-src 'self'"

### Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'" always;

## References
- MDN : https://developer.mozilla.org/fr/docs/Web/HTTP/CSP
