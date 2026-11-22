# HSTS manquant

## Description
L'en-tete `Strict-Transport-Security` force HTTPS.

## Risque
Un attaquant peut intercepter le trafic HTTP.

## Correctifs

### Apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

### Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

### Express.js
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));

### Django
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True

## References
- OWASP : https://owasp.org/www-project-secure-headers/
