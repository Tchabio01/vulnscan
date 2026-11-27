#!/usr/bin/env python3
"""VulnScan v3.3 - Audit pedagogique web - Multiplateforme
Compatible Linux, Windows, macOS, Termux.
"""
import argparse, sys, time, json, re, os, platform
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlunparse, urljoin
from datetime import datetime
from jinja2 import Template
from rich.console import Console
from rich.table import Table
from collections import Counter

if sys.version_info < (3, 8):
    sys.exit("[!] Python 3.8+ requis. Vous avez " + platform.python_version())

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Dependances manquantes. Installez avec :")
    print("    python -m pip install -r requirements.txt")
    sys.exit(1)

__version__ = "3.4.0"
OS_NAME = platform.system()  # Linux, Windows, Darwin


import socket
from requests.adapters import HTTPAdapter as _BaseAdapter


class IPv4Adapter(_BaseAdapter):
    """Force IPv4 pour eviter les echecs IPv6 en VM."""
    def init_poolmanager(self, *args, **kwargs):
        kwargs["socket_options"] = [(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)]
        return super().init_poolmanager(*args, **kwargs)

    def send(self, request, **kwargs):
        import urllib3.util.connection as urllib3_cn
        orig = urllib3_cn.allowed_gai_family
        urllib3_cn.allowed_gai_family = lambda: socket.AF_INET
        try:
            return super().send(request, **kwargs)
        finally:
            urllib3_cn.allowed_gai_family = orig


# Forcer IPv4 globalement (VM NAT : IPv6 ne repond pas)
import socket as _socket
import urllib3.util.connection as _urllib3_cn
_urllib3_cn.allowed_gai_family = lambda: _socket.AF_INET


class C:
    RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
    BLUE='\033[94m'; MAGENTA='\033[95m'; CYAN='\033[96m'
    BOLD='\033[1m'; DIM='\033[2m'; END='\033[0m'


UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


class Finding:
    SEV_ORDER = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4}
    def __init__(self, name, severity, url, evidence, description, remediation, payload=None, proof=None):
        self.name=name; self.severity=severity; self.url=url
        self.evidence=evidence; self.description=description
        self.remediation=remediation; self.payload=payload; self.proof=proof
    def to_dict(self): return self.__dict__


class VulnScanner:
    def __init__(self, base_url, delay=0.5, timeout=10, verbose=False):
        self.base_url = base_url.rstrip('/')
        self.delay = delay; self.timeout = timeout; self.verbose = verbose
        self.session = requests.Session()
        self.session.headers['User-Agent'] = UA
        self.session.mount('http://', IPv4Adapter())
        self.session.mount('https://', IPv4Adapter())
        self.session.verify = False
        self.findings = []
        self.visited = set()
        self.crawled_pages = set()

    def log(self, msg, level='info'):
        s = {'info':'[i]','ok':'[+]','warn':'[!]','err':'[-]','test':'[~]'}.get(level,'[i]')
        col = {'info':C.CYAN,'ok':C.GREEN,'warn':C.YELLOW,'err':C.RED,'test':C.MAGENTA}[level]
        print(f"{col}{s} {msg}{C.END}")

    def req(self, method, url, **kw):
        kw.setdefault('timeout', self.timeout)
        kw.setdefault('allow_redirects', True)
        time.sleep(self.delay)
        try:
            return self.session.request(method, url, **kw)
        except KeyboardInterrupt:
            raise
        except requests.exceptions.RequestException as e:
            # Toujours logguer l'erreur (pas seulement en verbose)
            msg = f"{e.__class__.__name__}: {str(e)[:120]}"
            if self.verbose:
                self.log(f"Err {url}: {msg}", 'err')
            else:
                # Garder une trace pour debug
                self._last_error = msg
            return None

    def add(self, f):
        key = (f.name, f.url, f.evidence)
        for existing in self.findings:
            if (existing.name, existing.url, existing.evidence) == key:
                return
        self.findings.append(f)
        sev_c = {'CRITICAL':C.RED+C.BOLD,'HIGH':C.RED,'MEDIUM':C.YELLOW,
                 'LOW':C.CYAN,'INFO':C.BLUE}.get(f.severity,'')
        print(f"  {sev_c}[{f.severity}]{C.END} {C.BOLD}{f.name}{C.END}")
        print(f"         {C.BLUE}{f.url}{C.END}")
        if f.payload:
            print(f"         {C.DIM}payload : {f.payload[:120]}{C.END}")
        if f.proof:
            print(f"         {C.DIM}preuve  : {f.proof.replace(chr(10),' ')[:160]}{C.END}")

    def set_basic_auth(self, user, pwd):
        self.session.auth = (user, pwd)
        r = self.req('GET', self.base_url)
        if r and r.status_code < 400:
            self.log(f"Basic Auth OK ({user})", 'ok'); return True
        self.log(f"Basic Auth echouee ({user})", 'err'); return False

    def set_cookie(self, cookie_str):
        for pair in cookie_str.split(';'):
            if '=' in pair:
                k,v = pair.strip().split('=',1)
                self.session.cookies.set(k, v)
        self.log("Cookie configure", 'ok')

    def set_header(self, name, value):
        self.session.headers[name] = value
        self.log(f"Header {name} configure", 'ok')

    def ping(self):
        """Verifie que la cible repond avant de lancer le scan."""
        print(f"\n{C.MAGENTA}[~] 0/38 Test de connectivite{C.END}")
        self._last_error = None
        r = self.req('GET', self.base_url)
        if not r:
            self.log(f"Cible injoignable : {self.base_url}", 'err')
            if self._last_error:
                self.log(f"Raison : {self._last_error}", 'warn')
            self.log("Verifiez l'URL, le reseau, ou un eventuel pare-feu.", 'warn')
            return False
        elapsed = r.elapsed.total_seconds() if hasattr(r, 'elapsed') else 0
        print(f"   HTTP {r.status_code} - {len(r.content)} octets - {elapsed:.2f}s")
        return True

    def check_ssl(self):
        """Verifie le certificat SSL/TLS et les protocoles supportes."""
        print(f"\n{C.MAGENTA}[~] 19/38 SSL/TLS{C.END}")
        import ssl
        import socket
        from urllib.parse import urlparse
        
        parsed = urlparse(self.base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        if parsed.scheme != 'https':
            print(f"   {C.DIM}Site en HTTP, pas de SSL a verifier{C.END}")
            return
        
        # 1. Verifier le certificat
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Date d'expiration
                    import datetime
                    expire = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire - datetime.datetime.now()).days
                    print(f"   Certificat valide {days_left} jours (expire: {cert['notAfter']})")
                    print(f"   Protocole: {version}, Cipher: {cipher[0]}")
                    
                    if days_left < 0:
                        self.add(Finding("Certificat SSL expire", 'CRITICAL', self.base_url,
                            f"Expire depuis {abs(days_left)} jours",
                            "Le certificat SSL est expire.",
                            "Renouvelez le certificat.",
                            proof=f"notAfter: {cert['notAfter']}"))
                    elif days_left < 30:
                        self.add(Finding("Certificat SSL bientot expire", 'MEDIUM', self.base_url,
                            f"Expire dans {days_left} jours",
                            "Le certificat SSL expire bientot.",
                            "Renouvelez le certificat.",
                            proof=f"notAfter: {cert['notAfter']}"))
                    
                    # Protocoles obsoletes
                    if version in ('TLSv1', 'TLSv1.1', 'SSLv3'):
                        self.add(Finding(f"Protocole obsolete: {version}", 'HIGH', self.base_url,
                            f"Le serveur supporte {version}",
                            "Protocole SSL/TLS obsolete et vulnerable.",
                            "Desactivez TLS 1.0/1.1, utilisez TLS 1.2+.",
                            proof=f"Version: {version}"))
        except ssl.SSLError as e:
            self.add(Finding("Erreur SSL/TLS", 'HIGH', self.base_url,
                f"Erreur: {e}", "Le certificat SSL est invalide.",
                "Verifiez le certificat SSL.", proof=str(e)[:120]))
        except Exception as e:
            if self.verbose:
                self.log(f"SSL check: {e.__class__.__name__}", 'err')

    def check_technologies(self):
        """Detecte les technologies utilisees (CMS, frameworks, serveurs)."""
        print(f"\n{C.MAGENTA}[~] 20/38 Technologies{C.END}")
        r = self.req('GET', self.base_url)
        if not r:
            return
        
        techs = []
        headers = {k.lower(): v for k, v in r.headers.items()}
        body = r.text.lower()
        
        # Serveur
        if 'server' in headers:
            techs.append(f"Serveur: {headers['server']}")
        
        # Frameworks backend
        if 'x-powered-by' in headers:
            techs.append(f"Backend: {headers['x-powered-by']}")
        
        # CMS
        cms_sigs = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'Joomla': ['/components/com_', 'joomla!'],
            'Drupal': ['/sites/default/files/', 'drupal.settings'],
            'Magento': ['/skin/frontend/', 'mage/cookies', 'magento'],
            'PrestaShop': ['/modules/ps_', 'prestashop'],
        }
        for cms, sigs in cms_sigs.items():
            if any(sig in body for sig in sigs):
                techs.append(f"CMS: {cms}")
        
        # Frameworks frontend
        js_sigs = {
            'React': ['react', '_react'],
            'Vue.js': ['vue.js', 'vue.min.js', 'v-'],
            'Angular': ['angular', 'ng-'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
        }
        for js, sigs in js_sigs.items():
            if any(sig in body for sig in sigs):
                techs.append(f"Frontend: {js}")
        
        # Langages
        if 'set-cookie' in headers:
            cookie = headers['set-cookie'].lower()
            if 'phpsessid' in cookie:
                techs.append("Langage: PHP")
            elif 'jsessionid' in cookie:
                techs.append("Langage: Java")
            elif 'asp.net' in cookie:
                techs.append("Langage: ASP.NET")
        
        if techs:
            print(f"   {C.DIM}Technologies detectees:{C.END}")
            for t in techs:
                print(f"   {C.CYAN}  - {t}{C.END}")
            self.add(Finding("Technologies detectees", 'INFO', self.base_url,
                f"{len(techs)} technologies",
                "La stack technique est visible.",
                "Masquez les signatures technologiques.",
                proof="; ".join(techs[:5])))
        else:
            print(f"   {C.DIM}Aucune technologie specifique detectee{C.END}")

    def check_waf(self):
        """Detecte la presence d'un WAF (Cloudflare, Akamai, etc.)."""
        print(f"\n{C.MAGENTA}[~] 22/38 Detection WAF{C.END}")
        r = self.req('GET', self.base_url)
        if not r: return
        headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        body = r.text.lower()
        wafs = []
        # Signatures WAF
        signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
            'Akamai': ['akamai', 'x-akamai'],
            'AWS WAF': ['x-amzn-requestid', 'awselb'],
            'Sucuri': ['x-sucuri-id', 'sucuri'],
            'Incapsula': ['x-iinfo', 'incap_ses'],
            'F5 BIG-IP': ['bigipserver', 'f5-'],
            'ModSecurity': ['mod_security', 'modsecurity'],
            'Barracuda': ['barra_counter_session'],
            'Fastly': ['x-fastly', 'fastly'],
            'Imperva': ['imperva', 'visid_incap'],
        }
        for waf, sigs in signatures.items():
            if any(sig in headers or sig in body for sig in sigs):
                wafs.append(waf)
        if wafs:
            print(f"   {C.YELLOW}WAF detecte: {', '.join(wafs)}{C.END}")
            self.add(Finding("WAF detecte", 'INFO', self.base_url,
                f"WAF: {', '.join(wafs)}", "Un WAF protege le site.",
                "Verifiez la configuration du WAF.", proof=f"WAF: {', '.join(wafs)}"))
        else:
            print(f"   {C.DIM}Aucun WAF detecte{C.END}")

    def check_ports(self):
        """Scan TCP + verification HTTP pour eviter les faux positifs."""
        print(f"\n{C.MAGENTA}[~] 23/38 Scan de ports{C.END}")
        import socket
        from urllib.parse import urlparse
        host = urlparse(self.base_url).hostname
        if not host:
            return
        ports = [80, 443, 8080, 8443, 8000, 3000, 5000, 9000, 22, 21]
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                if s.connect_ex((host, port)) == 0:
                    is_service = False
                    try:
                        if port in (443, 8443):
                            import ssl
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            ss = ctx.wrap_socket(s, server_hostname=host)
                            ss.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                            data = ss.recv(512)
                            if b"HTTP/" in data[:100]:
                                is_service = True
                        else:
                            s.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                            data = s.recv(512)
                            if b"HTTP/" in data[:100] or b"SSH-" in data[:100]:
                                is_service = True
                    except Exception:
                        pass
                    if is_service:
                        open_ports.append(port)
                        print(f"   {C.GREEN}[+] Port {port} ouvert (service detecte){C.END}")
                s.close()
            except Exception:
                pass
        if open_ports:
            self.add(Finding("Ports ouverts", 'INFO', self.base_url,
                f"Ports: {', '.join(map(str, open_ports))}",
                "Des ports sont ouverts sur le serveur.",
                "Fermez les ports non necessaires.",
                proof=f"Ports: {', '.join(map(str, open_ports))}"))
        else:
            print(f"   {C.DIM}Aucun port web supplementaire detecte{C.END}")


    def check_api_endpoints(self):
        """Cherche des endpoints API courants."""
        print(f"\n{C.MAGENTA}[~] 24/38 Endpoints API{C.END}")
        endpoints = [
            '/api/', '/api/v1/', '/api/v2/', '/api/docs', '/api/swagger',
            '/swagger.json', '/swagger-ui.html', '/openapi.json', '/api-docs',
            '/graphql', '/graphiql', '/rest', '/api/health', '/health',
            '/api/status', '/actuator', '/actuator/health', '/metrics',
        ]
        found = 0
        for ep in endpoints:
            url = f"{self.base_url}{ep}"
            r = self.req('GET', url)
            if not r or r.status_code not in (200, 201, 401, 403): continue
            if self._is_soft_404(r):
                continue
            ct = r.headers.get('Content-Type', '').lower()
            if 'text/html' in ct and 'not found' in r.text.lower()[:500]: continue
            sev = 'MEDIUM' if any(x in ep for x in ['swagger', 'graphql', 'openapi', 'api-docs']) else 'LOW'
            self.add(Finding(f"Endpoint API: {ep}", sev, url,
                f"HTTP {r.status_code} - {len(r.content)} bytes - {ct}",
                f"L'endpoint '{ep}' est accessible.",
                "Restreignez l'acces ou desactivez la doc API en prod.",
                proof=r.text[:100].replace('\n', ' ')))
            found += 1
        if found == 0:
            print(f"   {C.DIM}Aucun endpoint API expose{C.END}")

    def check_admin_panels(self):
        """Cherche des panneaux d'administration courants."""
        print(f"\n{C.MAGENTA}[~] 25/38 Panneaux admin{C.END}")
        panels = [
            '/admin', '/admin/', '/administrator', '/wp-admin', '/phpmyadmin',
            '/adminer.php', '/admin/login', '/login', '/wp-login.php',
            '/cpanel', '/webmail', '/plesk', '/directadmin',
            '/manager/html', '/admin.php', '/adminpanel', '/admin_area',
        ]
        found = 0
        for p in panels:
            url = f"{self.base_url}{p}"
            r = self.req('GET', url)
            if not r: continue
            if r.status_code in (200, 401, 403) and len(r.content) > 200:
                sev = 'HIGH' if any(x in p for x in ['phpmyadmin', 'adminer', 'manager/html']) else 'MEDIUM'
                self.add(Finding(f"Panneau admin: {p}", sev, url,
                    f"HTTP {r.status_code} - {len(r.content)} bytes",
                    f"Panneau d'administration accessible: {p}",
                    "Restreignez par IP ou desactivez en prod.",
                    proof=f"HTTP {r.status_code}"))
                found += 1
        if found == 0:
            print(f"   {C.DIM}Aucun panneau admin accessible{C.END}")

    def check_cms_paths(self):
        """Detecte le CMS et teste ses chemins specifiques."""
        print(f"\n{C.MAGENTA}[~] 26/38 CMS-specific{C.END}")
        r = self.req('GET', self.base_url)
        if not r: return
        body = r.text.lower()
        cms = None
        if 'wp-content' in body or 'wp-includes' in body:
            cms = 'WordPress'
        elif 'joomla' in body:
            cms = 'Joomla'
        elif 'drupal' in body:
            cms = 'Drupal'
        elif 'magento' in body:
            cms = 'Magento'
        elif 'prestashop' in body:
            cms = 'PrestaShop'
        if not cms:
            print(f"   {C.DIM}Aucun CMS detecte{C.END}")
            return
        print(f"   {C.YELLOW}CMS detecte: {cms}{C.END}")
        cms_paths = {
            'WordPress': ['/wp-config.php.bak', '/wp-config.php~', '/xmlrpc.php',
                         '/wp-json/wp/v2/users', '/?author=1', '/wp-content/debug.log'],
            'Joomla': ['/configuration.php.bak', '/administrator/', '/htaccess.txt'],
            'Drupal': ['/CHANGELOG.txt', '/INSTALL.txt', '/sites/default/settings.php.bak'],
            'Magento': ['/app/etc/local.xml', '/downloader/', '/admin'],
            'PrestaShop': ['/config/settings.inc.php', '/admin', '/install/'],
        }
        for path in cms_paths.get(cms, []):
            url = f"{self.base_url}{path}"
            r = self.req('GET', url)
            if r and r.status_code == 200 and len(r.content) > 50:
                self.add(Finding(f"{cms} - chemin sensible: {path}", 'HIGH', url,
                    f"HTTP 200 - {len(r.content)} bytes",
                    f"Chemin specifique {cms} accessible.",
                    f"Protegez ou supprimez {path}.",
                    proof=r.text[:100].replace('\n', ' ')))

    def check_wellknown(self):
        """Verifie les fichiers .well-known (security.txt, etc.)."""
        print(f"\n{C.MAGENTA}[~] 27/38 .well-known{C.END}")
        files = [
            '/.well-known/security.txt',
            '/security.txt',
            '/.well-known/change-password',
            '/.well-known/dnssec-trigger',
            '/humans.txt',
        ]
        for f in files:
            url = f"{self.base_url}{f}"
            r = self.req('GET', url)
            if r and r.status_code == 200 and len(r.content) > 10:
                self.add(Finding(f"Fichier .well-known: {f}", 'LOW', url,
                    f"HTTP 200 - {len(r.content)} bytes",
                    f"Fichier '{f}' accessible.",
                    "Verifiez le contenu (pas de fuite d'info).",
                    proof=r.text[:120].replace('\n', ' ')))

    def check_mixed_content(self):
        """Detecte du contenu HTTP charge sur une page HTTPS."""
        print(f"\n{C.MAGENTA}[~] 28/38 Mixed content{C.END}")
        from urllib.parse import urlparse
        parsed = urlparse(self.base_url)
        if parsed.scheme != 'https':
            print(f"   {C.DIM}Site en HTTP, mixed content non applicable{C.END}")
            return
        r = self.req('GET', self.base_url)
        if not r: return
        import re
        http_resources = re.findall(r'(?:src|href)=["\'](http://[^"\']+)["\']', r.text)
        if http_resources:
            self.add(Finding("Mixed content detecte", 'MEDIUM', self.base_url,
                f"{len(http_resources)} ressources HTTP sur page HTTPS",
                "Des ressources sont chargees en HTTP, cassant le chiffrement.",
                "Utilisez HTTPS pour toutes les ressources.",
                proof='\n'.join(http_resources[:3])))

    def check_sri(self):
        """Verifie la presence de Subresource Integrity sur les scripts externes."""
        print(f"\n{C.MAGENTA}[~] 29/38 Subresource Integrity{C.END}")
        r = self.req('GET', self.base_url)
        if not r: return
        import re
        scripts = re.findall(r'<script[^>]*src=["\'](https?://[^"\']+)["\'][^>]*>', r.text)
        external = [s for s in scripts if 'integrity=' not in s]
        # Cherche specifiquement les scripts externes sans integrity
        missing_sri = []
        for m in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', r.text):
            tag = m.group(0)
            src = m.group(1)
            if src.startswith('http') and 'integrity=' not in tag:
                missing_sri.append(src)
        if missing_sri:
            self.add(Finding("Scripts externes sans SRI", 'LOW', self.base_url,
                f"{len(missing_sri)} scripts sans integrity",
                "Les scripts externes n'ont pas de Subresource Integrity.",
                "Ajoutez integrity='sha384-...' aux scripts externes.",
                proof='\n'.join(missing_sri[:3])))

    def check_dns_security(self):
        """Verifie les enregistrements DNS de securite (SPF, DMARC, CAA)."""
        print(f"\n{C.MAGENTA}[~] 30/38 DNS security{C.END}")
        from urllib.parse import urlparse
        import socket
        parsed = urlparse(self.base_url)
        host = parsed.hostname
        if not host: return
        try:
            # CAA
            try:
                import subprocess
                result = subprocess.run(['dig', '+short', 'CAA', host],
                    capture_output=True, text=True, timeout=5)
                if not result.stdout.strip():
                    self.add(Finding("CAA manquant", 'LOW', self.base_url,
                        f"Aucun enregistrement CAA pour {host}",
                        "N'importe quelle CA peut emettre un certificat.",
                        "Ajoutez un enregistrement CAA.",
                        proof=f"dig CAA {host} -> vide"))
                else:
                    print(f"   CAA: {result.stdout.strip()[:80]}")
            except FileNotFoundError:
                print(f"   {C.DIM}dig non installe, CAA ignore{C.END}")
            # SPF (via TXT)
            try:
                result = subprocess.run(['dig', '+short', 'TXT', host],
                    capture_output=True, text=True, timeout=5)
                txt = result.stdout.lower()
                if 'v=spf1' not in txt:
                    self.add(Finding("SPF manquant", 'LOW', self.base_url,
                        f"Aucun SPF pour {host}",
                        "Pas de protection contre le spoofing email.",
                        "Ajoutez un enregistrement SPF.",
                        proof=f"dig TXT {host} -> pas de v=spf1"))
                # DMARC
                result = subprocess.run(['dig', '+short', 'TXT', f'_dmarc.{host}'],
                    capture_output=True, text=True, timeout=5)
                if 'v=dmarc1' not in result.stdout.lower():
                    self.add(Finding("DMARC manquant", 'LOW', self.base_url,
                        f"Aucun DMARC pour {host}",
                        "Pas de politique DMARC.",
                        "Ajoutez un enregistrement _dmarc.",
                        proof=f"dig TXT _dmarc.{host} -> vide"))
            except FileNotFoundError:
                pass
        except Exception as e:
            if self.verbose:
                self.log(f"DNS check: {e}", 'err')

    def check_backups(self):
        """Cherche des fichiers de backup exposes."""
        print(f"\n{C.MAGENTA}[~] 21/38 Fichiers de backup{C.END}")
        backup_files = [
            'index.php.bak', 'index.php~', 'index.php.old',
            'config.php.bak', 'config.php~', 'config.php.old',
            'wp-config.php.bak', 'wp-config.php~',
            '.env.bak', '.env~', '.env.old',
            'backup.zip', 'backup.tar.gz', 'backup.rar',
            'site.zip', 'site.tar.gz', 'www.zip',
            'database.sql', 'dump.sql', 'db.sql',
            'composer.json.bak', 'package.json.bak',
        ]
        found = 0
        for f in backup_files:
            url = f"{self.base_url}/{f}"
            r = self.req('GET', url)
            if not r or r.status_code != 200 or len(r.content) == 0:
                continue
            if self._is_soft_404(r):
                continue
            ct = r.headers.get('Content-Type', '').lower()
            if 'text/html' in ct and len(r.content) < 2000:
                continue
            # Un backup n'est jamais du text/html
            if 'text/html' in ct:
                continue
            self.add(Finding(f"Backup expose: /{f}", 'HIGH', url,
                f"HTTP 200 - {len(r.content)} bytes - {ct}",
                f"Le fichier de backup '/{f}' est accessible.",
                "Supprimez les fichiers de backup du serveur.",
                proof=r.text[:120].replace(chr(10), ' ')))
            found += 1
        if found == 0:
            print(f"   {C.DIM}Aucun backup expose{C.END}")

    def check_subdomains(self):
        """Decouverte de sous-domaines via DNS."""
        print(f"\n{C.MAGENTA}[~] 31/38 Sous-domaines{C.END}")
        import socket
        from urllib.parse import urlparse
        host = urlparse(self.base_url).hostname
        if not host: return
        domain = ".".join(host.split(".")[-2:])
        WORDLIST = ["www","api","dev","staging","admin","mail","ftp","test","blog","shop","portal","vpn","remote","git"]
        found = []
        for sub in WORDLIST:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append((fqdn, ip))
                print(f"   {C.GREEN}[+] {fqdn} -> {ip}{C.END}")
            except socket.gaierror:
                pass
        if found:
            self.add(Finding("Sous-domaines decouverts", 'INFO', self.base_url,
                f"{len(found)} sous-domaines", "Sous-domaines exposes.",
                "Verifiez leur securite.",
                proof="; ".join(f"{s}->{ip}" for s, ip in found[:5])))

    def check_dirb(self):
        """Decouverte de repertoires courants."""
        print(f"\n{C.MAGENTA}[~] 32/38 Repertoires{C.END}")
        PATHS = ["/admin","/backup","/config","/api","/.git","/.env","/test","/dev","/private","/uploads"]
        for p in PATHS:
            r = self.req('GET', self.base_url + p)
            if r and r.status_code in (200, 301, 403) and len(r.content) > 100:
                self.add(Finding(f"Repertoire expose: {p}", 'MEDIUM', self.base_url + p,
                    f"HTTP {r.status_code}", "Repertoire accessible.",
                    "Restreignez l'acces.", proof=f"HTTP {r.status_code}"))

    def check_http_methods(self):
        """Teste les methodes HTTP via OPTIONS/Allow (plus fiable)."""
        print(f"\n{C.MAGENTA}[~] 33/38 Methodes HTTP dangereuses{C.END}")
        r = self.req('OPTIONS', self.base_url)
        if not r:
            return
        allow = r.headers.get('Allow', '') or r.headers.get('allow', '')
        if not allow:
            print(f"   {C.DIM}Pas de header Allow, test ignore{C.END}")
            return
        print(f"   Allow: {allow}")
        for m in ['PUT', 'DELETE', 'TRACE', 'PATCH']:
            if m in allow.upper():
                self.add(Finding(f"Methode HTTP dangereuse: {m}", 'HIGH', self.base_url,
                    f"Allow: {allow}", f"Methode {m} listee dans Allow.",
                    f"Desactivez {m}.", proof=f"Allow: {allow}"))


    def check_ssrf(self, url, params):
        """Teste les SSRF sur les parametres."""
        print(f"{C.MAGENTA}[~] 34/38 SSRF sur {url}{C.END}")
        if not params: return
        PAYLOADS = ["http://169.254.169.254/latest/meta-data/","http://localhost:22/","file:///etc/passwd"]
        for pl in PAYLOADS:
            r = self.req('GET', url, params={k: pl for k in params})
            if r and any(x in r.text.lower() for x in ["ami-","root:","ssh-"]):
                self.add(Finding("SSRF potentielle", 'CRITICAL', url,
                    f"Payload {pl!r}", "Le serveur fait des requetes internes.",
                    "Whitelist des URLs autorisees.", payload=pl))
                return

    def check_deserialization(self):
        """Detecte les cookies serialises."""
        print(f"\n{C.MAGENTA}[~] 35/38 Deserialisation{C.END}")
        r = self.req('GET', self.base_url)
        if not r: return
        import re
        SIGS = {"Java": re.compile(r"^rO0AB"), "PHP": re.compile(r"^Tzox"), "Python": re.compile(r"^gASV")}
        for c in r.cookies:
            val = c.value or ""
            for lang, sig in SIGS.items():
                if sig.match(val):
                    self.add(Finding(f"Deserialisation {lang}", 'CRITICAL', self.base_url,
                        f"Cookie '{c.name}' serialise", "Donnees serialisees non securisees.",
                        "Utilisez JSON + signature.", proof=val[:60]))

    def check_takeover(self):
        """Detecte les subdomain takeover."""
        print(f"\n{C.MAGENTA}[~] 36/38 Subdomain takeover{C.END}")
        try:
            import dns.resolver
        except ImportError:
            print(f"   {C.DIM}dnspython non installe{C.END}")
            return
        import socket
        from urllib.parse import urlparse
        host = urlparse(self.base_url).hostname
        if not host: return
        VULN = ["herokuapp.com","s3.amazonaws.com","github.io","azurewebsites.net"]
        try:
            ans = dns.resolver.resolve(host, 'CNAME')
            for r in ans:
                target = str(r.target)
                if any(v in target for v in VULN):
                    try:
                        socket.gethostbyname(target)
                    except socket.gaierror:
                        self.add(Finding("Subdomain takeover potentiel", 'HIGH', self.base_url,
                            f"CNAME -> {target} (non resolu)", "CNAME orphelin.",
                            "Supprimez le CNAME ou reclamez le service.", proof=target))
        except Exception:
            pass

    def check_ratelimit(self):
        """Verifie l'absence de rate limiting."""
        print(f"\n{C.MAGENTA}[~] 37/38 Rate limiting{C.END}")
        codes = []
        for _ in range(30):
            r = self.req('GET', self.base_url)
            if r: codes.append(r.status_code)
        if 429 not in codes:
            self.add(Finding("Rate limiting absent", 'LOW', self.base_url,
                "30 req, aucun 429", "Pas de protection contre le brute-force.",
                "Ajoutez un rate limiting."))

    def check_leaks(self):
        """Detecte les fuites d'information."""
        print(f"\n{C.MAGENTA}[~] 38/38 Fuites d'information{C.END}")
        FILES = ["/.git/config","/.svn/entries","/.hg/requires","/.DS_Store","/Thumbs.db","/phpinfo.php","/info.php","/swagger.json","/openapi.json"]
        for f in FILES:
            r = self.req('GET', self.base_url + f)
            if r and r.status_code == 200 and len(r.content) > 50:
                self.add(Finding(f"Fuite: {f}", 'HIGH', self.base_url + f,
                    f"HTTP 200 - {len(r.content)}b", "Fichier sensible expose.",
                    "Supprimez ou protegez.", proof=r.text[:100]))

    def _baseline_fingerprint(self):
        """Retourne (len, hash) de la page d'accueil pour detecter les soft 404."""
        r = self.req('GET', self.base_url)
        if not r:
            return None
        import hashlib
        h = hashlib.sha256(r.content).hexdigest()[:16]
        return (len(r.content), h)

    def _is_soft_404(self, r):
        """Detecte un soft 404 (page identique a l'accueil)."""
        if not hasattr(self, '_baseline') or self._baseline is None:
            self._baseline = self._baseline_fingerprint()
        if not self._baseline or not r:
            return False
        import hashlib
        h = hashlib.sha256(r.content).hexdigest()[:16]
        return (len(r.content), h) == self._baseline

    def check_headers(self):
        print(f"\n{C.MAGENTA}[~] 1/38 En-tetes de securite{C.END}")
        r = self.req('GET', self.base_url)
        if not r: return
        exp = {
            'Strict-Transport-Security':('HSTS manquant','MEDIUM',"Ajoutez: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            'Content-Security-Policy':('CSP manquant','MEDIUM',"Definissez une CSP: default-src 'self'; script-src 'self'"),
            'X-Content-Type-Options':('X-Content-Type-Options manquant','LOW',"Ajoutez: X-Content-Type-Options: nosniff"),
            'X-Frame-Options':('X-Frame-Options manquant','MEDIUM',"Ajoutez: X-Frame-Options: DENY"),
            'Referrer-Policy':('Referrer-Policy manquant','LOW',"Ajoutez: Referrer-Policy: no-referrer-when-downgrade"),
            'Permissions-Policy':('Permissions-Policy manquant','LOW',"Ajoutez: Permissions-Policy: geolocation=(), camera=()"),
        }
        h_low = {k.lower():v for k,v in r.headers.items()}
        for h,(name,sev,rem) in exp.items():
            if h.lower() not in h_low:
                self.add(Finding(name, sev, self.base_url, f"En-tete absent: {h}",
                    f"L'en-tete '{h}' n'est pas present.", rem))
        for h in ['Server','X-Powered-By','X-AspNet-Version']:
            if h.lower() in h_low:
                self.add(Finding(f"Fuite version via {h}", 'LOW', self.base_url,
                    f"{h}: {h_low[h.lower()]}", "L'en-tete revele la stack technique.",
                    f"Masquez l'en-tete '{h}'.", proof=f"{h}: {h_low[h.lower()]}"))

    def check_files(self):
        print(f"\n{C.MAGENTA}[~] 2/38 Fichiers sensibles{C.END}")
        files = ['robots.txt','sitemap.xml','.git/HEAD','.git/config','.env','.env.local',
                 'config.php','config.php.bak','wp-config.php','backup.zip','backup.sql',
                 'database.sql','.htaccess','.htpasswd','.DS_Store','phpinfo.php','info.php',
                 'test.php','debug.php','admin.php','login.php','upload.php','shell.php',
                 'composer.json','package.json','README.md','Dockerfile','docker-compose.yml']
        for f in files:
            url = f"{self.base_url}/{f}"
            r = self.req('GET', url)
            if not r or r.status_code != 200 or len(r.content) == 0: continue
            ct = r.headers.get('Content-Type','').lower()
            body = r.text[:200]
            # Ignorer les soft 404 (SPA catch-all)
            if self._is_soft_404(r):
                continue
            # Un fichier sensible n'est jamais du text/html
            if 'text/html' in ct and any(x in f for x in ['.git', '.env', '.htaccess', '.htpasswd', 'backup', 'database', 'dump', '.sql', '.zip', '.bak']):
                continue
            if 'text/html' in ct and ('not found' in body.lower() or '404' in body.lower()):
                if len(r.content) < 2000: continue
            sev = ('CRITICAL' if any(x in f for x in ['.env','.git/config','.htpasswd','wp-config','backup.sql'])
                   else 'HIGH' if any(x in f for x in ['.git','backup','database','dump','config','.htaccess'])
                   else 'MEDIUM')
            self.add(Finding(f"Fichier expose: /{f}", sev, url,
                f"HTTP 200 - {len(r.content)} bytes - {ct}",
                f"Le fichier '/{f}' est accessible publiquement.",
                "Bloquez via .htaccess/nginx ou retirez le fichier.",
                proof=body.replace('\n',' ')[:150]))

    def check_html_comments(self, url=None):
        url = url or self.base_url
        if url in self.crawled_pages: return
        self.crawled_pages.add(url)
        print(f"\n{C.MAGENTA}[~] 3/38 Commentaires HTML sur {url}{C.END}")
        r = self.req('GET', url)
        if not r: return
        if r.status_code >= 400 and len(r.content) < 500: return
        IGNORE = ['contact_me.php','mail/contact_me','Bootstrap','fontawesome',
                  'fonts.googleapis','To configure the contact','Core theme',
                  'Third party plugin','Favicon','Font Awesome','Google fonts',
                  'Masthead','About Section','Icon Divider','Navigation',
                  'Footer Social','Scroll to Top','Copyright','Contact form',
                  'scroll-trigger']
        keywords = ['password','passwd','pwd','token','secret','api_key','apikey',
                    'admin_pass','db_pass','debug=','backup=','select ','insert into',
                    'update ','delete from','.env','.git','id_rsa','flag','key=']
        seen = set()
        for cm in re.findall(r'<!--(.*?)-->', r.text, re.DOTALL):
            body = cm.strip()
            if not body or len(body) < 8: continue
            if any(p.lower() in body.lower() for p in IGNORE): continue
            if body in seen: continue
            seen.add(body)
            low = body.lower()
            hits = [k for k in keywords if k in low]
            if hits:
                self.add(Finding("Commentaire HTML sensible", 'MEDIUM', url,
                    f"Mots-cles: {', '.join(hits)}",
                    "Un commentaire HTML contient des informations sensibles.",
                    "Supprimez les commentaires sensibles en prod.",
                    proof=f"<!-- {body[:200]} -->"))
            elif len(body) > 40 and not body.startswith(('[','*','/')):
                self.add(Finding("Commentaire HTML non trivial", 'LOW', url,
                    f"Contenu: {body[:80]}...", "Commentaire potentiellement sensible.",
                    "Retirez les commentaires en prod.",
                    proof=f"<!-- {body[:150]} -->"))

    def check_cookies(self, url=None):
        print(f"\n{C.MAGENTA}[~] 4/38 Cookies{C.END}")
        url = url or self.base_url
        r = self.req('GET', url)
        if not r: return
        for c in r.cookies:
            missing = []
            if not c.secure: missing.append('Secure')
            if not c.has_nonstandard_attr('HttpOnly') and not c.has_nonstandard_attr('httponly'):
                missing.append('HttpOnly')
            if not c.has_nonstandard_attr('SameSite') and not c.has_nonstandard_attr('samesite'):
                missing.append('SameSite')
            if missing:
                sev = 'HIGH' if 'HttpOnly' in missing else 'MEDIUM'
                self.add(Finding(f"Cookie '{c.name}' sans {', '.join(missing)}", sev, url,
                    f"Attributs manquants: {', '.join(missing)}",
                    "Cookie sans flags de securite.",
                    "Set-Cookie: name=val; Secure; HttpOnly; SameSite=Lax"))

    def check_methods(self):
        print(f"\n{C.MAGENTA}[~] 5/38 Methodes HTTP{C.END}")
        r = self.req('OPTIONS', self.base_url)
        if not r: return
        allow = r.headers.get('Allow','') or r.headers.get('allow','')
        dangerous = [m for m in ['PUT','DELETE','TRACE','CONNECT','PATCH'] if m in allow.upper()]
        if dangerous:
            self.add(Finding("Methodes HTTP dangereuses", 'HIGH', self.base_url,
                f"Allow: {allow}", f"Methodes {', '.join(dangerous)} actives.",
                "Desactivez TRACE. Limitez PUT/DELETE.", proof=f"Allow: {allow}"))

    def check_dir_listing(self):
        print(f"\n{C.MAGENTA}[~] 6/38 Directory listing{C.END}")
        for d in ['/','/uploads/','/files/','/backup/','/images/','/admin/']:
            url = self.base_url + d
            r = self.req('GET', url)
            if r and r.status_code == 200:
                low = r.text.lower()
                if 'index of /' in low and '<a href' in low:
                    self.add(Finding(f"Directory listing: {d}", 'MEDIUM', url,
                        "Liste des fichiers affichee", "Enumeration possible.",
                        "Options -Indexes ou autoindex off.", proof=low[:120]))

    def check_forms(self):
        print(f"\n{C.MAGENTA}[~] 7/38 Formulaires{C.END}")
        r = self.req('GET', self.base_url)
        if not r: return
        html = r.text
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL|re.IGNORECASE)
        actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
        for i, f in enumerate(forms):
            has_csrf = bool(re.search(r'csrf|_token|authenticity_token', f, re.IGNORECASE))
            has_password = bool(re.search(r'type=["\']password["\']', f, re.IGNORECASE))
            if has_password and not has_csrf:
                act = actions[i] if i < len(actions) else '?'
                self.add(Finding("Formulaire sans token CSRF", 'MEDIUM', self.base_url,
                    f"Action: {act}", "Aucun token anti-CSRF.",
                    "Ajoutez un token CSRF verifie cote serveur.",
                    proof=f"<form action='{act}' method='POST'>"))

    def check_form_vulns(self):
        print(f"\n{C.MAGENTA}[~] 7b/38 Test formulaires POST{C.END}")
        r = self.req('GET', self.base_url)
        if not r: return
        for m in re.finditer(r'<form([^>]*)>(.*?)</form>', r.text, re.DOTALL|re.I):
            attrs, body = m.group(1), m.group(2)
            act = re.search(r'action=["\']([^"\']*)["\']', attrs)
            meth = re.search(r'method=["\']([^"\']*)["\']', attrs)
            action = urljoin(self.base_url+'/', act.group(1)) if act else self.base_url
            method = (meth.group(1).upper() if meth else 'GET')
            fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', body)
            fields += re.findall(r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>', body)
            if not fields: continue
            print(f"   -> {method} {action} | champs: {fields}")
            login_field = next((f for f in fields if any(k in f.lower()
                              for k in ['login','user','email','mail','pseudo'])), fields[0])
            for pl in ["admin'-- -", "' OR '1'='1'-- -", "admin'#"]:
                params = {f:'x' for f in fields}
                params[login_field] = pl
                r2 = self.req(method, action,
                              data=params if method=='POST' else None,
                              params=params if method=='GET' else None)
                if not r2: continue
                low = r2.text.lower()
                loc_hdr = r2.headers.get('Location','').lower()
                is_bypass = ('profile.php' in low or 'profile' in loc_hdr
                    or any(w in low for w in ['dashboard','bienvenue ','deconnexion','logout']))
                if is_bypass:
                    proof_bits = []
                    if 'profile.php' in low: proof_bits.append("redirect profile.php")
                    if 'dashboard' in low: proof_bits.append("dashboard")
                    if 'deconnexion' in low or 'logout' in low: proof_bits.append("logout")
                    self.add(Finding(f"SQLi bypass sur '{login_field}'", 'CRITICAL', action,
                        f"Payload {pl!r} -> {', '.join(proof_bits) or 'profil'}",
                        "Bypass d'authentification via SQLi.",
                        "Requetes preparees PDO.",
                        payload=f"{login_field}={pl}",
                        proof=" | ".join(proof_bits) or "profil accessible"))
                    break

    def crawl_links(self, url=None):
        print(f"\n{C.MAGENTA}[~] 8/38 Crawl{C.END}")
        url = url or self.base_url
        r = self.req('GET', url)
        if not r: return []
        links = set()
        for m in re.finditer(r'(?:href|src|action)=["\']([^"\']+)["\']', r.text):
            href = m.group(1)
            if href.startswith(('#','mailto:','javascript:','tel:')): continue
            full = urljoin(self.base_url + '/', href)
            if urlparse(self.base_url).netloc in full: links.add(full)
        print(f"   {len(links)} liens")
        return list(links)[:40]

    def deep_crawl(self, depth=2, max_pages=25):
        print(f"\n{C.MAGENTA}[~] Deep crawl (d={depth}){C.END}")
        STATIC = ('.css','.js','.png','.jpg','.jpeg','.gif','.svg','.ico',
                  '.woff','.woff2','.ttf','.eot','.map','.scss')
        to_visit = [(self.base_url, 0)]; seen = set(); found = []
        while to_visit and len(seen) < max_pages:
            url, d = to_visit.pop(0)
            if url in seen or d > depth: continue
            seen.add(url)
            r = self.req('GET', url)
            if not r: continue
            if r.status_code >= 400 and len(r.content) < 500: continue
            print(f"   d={d} {C.GREEN}{r.status_code}{C.END} {url} ({len(r.content)}b)")
            found.append(url)
            for m in re.finditer(r'(?:href|action)=["\']([^"\']+)["\']', r.text):
                link = urljoin(url, m.group(1))
                if any(link.lower().endswith(ext) for ext in STATIC): continue
                if (urlparse(self.base_url).netloc == urlparse(link).netloc
                    and link not in seen and '#' not in link and len(link) < 200):
                    to_visit.append((link, d+1))
        return found

    def check_sqli(self, url, method='GET', params=None):
        print(f"{C.MAGENTA}[~] 9/38 SQLi sur {url}{C.END}")
        if not params: return
        err_sigs = ["sql syntax","mysql_fetch","mysqli","sqlite","pg_query","ora-",
                    "unclosed quotation","you have an error in your sql","syntax error",
                    "mariadb","postgresql","sqlstate"]
        base_r = self.req(method, url, params=params if method=='GET' else None,
                          data=params if method=='POST' else None)
        if not base_r: return
        base_len = len(base_r.text)
        for pl in ["'","\"","')","';"]:
            test = {k: (str(v)+pl) for k,v in params.items()}
            r = self.req(method, url, params=test if method=='GET' else None,
                         data=test if method=='POST' else None)
            if not r: continue
            for sig in err_sigs:
                if sig in r.text.lower() and sig not in base_r.text.lower():
                    m = re.search(rf".{{0,60}}{re.escape(sig)}.{{0,80}}", r.text, re.IGNORECASE)
                    self.add(Finding("SQL Injection (error-based)", 'CRITICAL', url,
                        f"Payload: {test} -> '{sig}'", "Erreur SQL visible.",
                        "Requetes preparees PDO.",
                        payload=str(test), proof=m.group(0) if m else sig)); return
        true_p  = {k: (str(v)+"' AND '1'='1") for k,v in params.items()}
        false_p = {k: (str(v)+"' AND '1'='2") for k,v in params.items()}
        rt = self.req(method, url, params=true_p if method=='GET' else None,
                      data=true_p if method=='POST' else None)
        rf = self.req(method, url, params=false_p if method=='GET' else None,
                      data=false_p if method=='POST' else None)
        if rt and rf and abs(len(rt.text)-len(rf.text)) > 30:
            self.add(Finding("SQL Injection (boolean)", 'HIGH', url,
                f"TRUE={len(rt.text)}b / FALSE={len(rf.text)}b",
                "Reponse differente selon condition SQL.",
                "Requetes preparees.", proof=f"T={len(rt.text)} vs F={len(rf.text)}"))

    def check_xss(self, url, method='GET', params=None):
        print(f"{C.MAGENTA}[~] 10/38 XSS reflechi sur {url}{C.END}")
        if not params: return
        marker = "vx" + str(int(time.time()))[-5:]
        for pl in [f"<script>alert('{marker}')</script>",
                   f"\"'><img src=x onerror=alert('{marker}')>",
                   f"'><svg onload=alert('{marker}')>"]:
            test = {k: pl for k in params}
            r = self.req(method, url, params=test if method=='GET' else None,
                         data=test if method=='POST' else None)
            if r and pl in r.text:
                self.add(Finding("XSS reflechi", 'HIGH', url, "Payload refflete brut",
                    "Sortie non echappee.", "htmlspecialchars + CSP.",
                    payload=pl, proof=pl)); return

    def check_idor(self, url, params):
        print(f"{C.MAGENTA}[~] 12/38 IDOR sur {url}{C.END}")
        if not params: return
        # Ne tester que les params dont la valeur est un ID numerique
        # ET dont le nom contient un indice d'identifiant
        id_hints = ('id', 'user', 'account', 'profile', 'order', 'invoice', 'doc', 'file')
        nums = {}
        for k, v in params.items():
            if not str(v).isdigit(): continue
            if not any(h in k.lower() for h in id_hints): continue
            nums[k] = int(v)
        if not nums:
            print(f"   {C.DIM}Aucun parametre ID numerique detecte{C.END}")
            return
        for k, v in nums.items():
            base = self.req('GET', url, params={k: v})
            if not base: continue
            base_len = len(base.text)
            base_status = base.status_code
            for tv in [v+1, v+2]:
                if tv <= 0: continue
                r = self.req('GET', url, params={k: tv})
                if not r or r.status_code != 200: continue
                # Exiger une difference significative (> 100 octets)
                # ET un contenu qui change (pas juste un article different)
                if abs(len(r.text) - base_len) > 100:
                    self.add(Finding(f"IDOR potentiel sur '{k}'", 'HIGH', url,
                        f"{k}={v} ({base_len}b) vs {k}={tv} ({len(r.text)}b)",
                        "Acces potentiel a des donnees d'autrui.",
                        "Verifiez ownership cote serveur.",
                        payload=f"{k}={tv}",
                        proof=f"{base_len}b -> {len(r.text)}b"))
                    return
        print(f"   {C.DIM}Aucun IDOR detecte{C.END}")


    def check_lfi(self, url, params):
        print(f"{C.MAGENTA}[~] 13/38 LFI sur {url}{C.END}")
        if not params:
            print(f"   {C.DIM}Aucun parametre, LFI ignore{C.END}")
            return
        # Ignorer les fichiers statiques (faux positifs)
        STATIC = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                  '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map')
        if any(url.lower().endswith(ext) for ext in STATIC):
            print(f"   {C.DIM}Fichier statique, LFI ignore{C.END}")
            return
        for pl, sig in [("../../../../etc/passwd", r"root:.*:0:0:"),
                        ("....//....//....//etc/passwd", r"root:.*:0:0:"),
                        ("/etc/passwd", r"root:.*:0:0:"),
                        ("php://filter/convert.base64-encode/resource=index.php", r"[A-Za-z0-9+/=]{50,}")]:
            r = self.req('GET', url, params={k:pl for k in params})
            if not r: continue
            m = re.search(sig, r.text)
            if m:
                # Verifier que c'est du vrai Base64 (pas un chemin CSS/HTML)
                match_text = m.group(0)
                if 'php://filter' in pl:
                    # Doit contenir 50+ chars Base64 consecutifs
                    b64_match = re.search(r'[A-Za-z0-9+/=]{50,}', r.text)
                    if not b64_match:
                        continue  # faux positif
                    match_text = b64_match.group(0)[:120]
                self.add(Finding("LFI", 'CRITICAL', url, f"Payload: {pl}",
                    "Lecture fichiers serveur.",
                    "Whitelist + basename() + realpath().",
                    payload=pl, proof=match_text)); return

    def check_open_redirect(self, url, params):
        print(f"{C.MAGENTA}[~] 14/38 Open Redirect sur {url}{C.END}")
        if not params: return
        evil = "https://evil.example.com/"
        for k in params:
            r = self.req('GET', url, params={k: evil}, allow_redirects=False)
            if r and r.status_code in (301,302,303,307,308):
                loc = r.headers.get('Location','')
                if 'evil.example.com' in loc:
                    self.add(Finding("Open Redirect", 'MEDIUM', url,
                        f"{k}={evil}", "Redirection vers domaine attaquant.",
                        "Whitelist des domaines.", proof=f"Location: {loc}"))

    def check_cors(self):
        print(f"\n{C.MAGENTA}[~] 15/38 CORS{C.END}")
        evil = "https://evil.example.com"
        r = self.req('GET', self.base_url, headers={'Origin': evil})
        if not r: return
        acao = r.headers.get('Access-Control-Allow-Origin','')
        acac = r.headers.get('Access-Control-Allow-Credentials','')
        if acao in (evil, '*') and acac.lower() == 'true':
            self.add(Finding("CORS wildcard + credentials", 'HIGH', self.base_url,
                f"ACAO: {acao}", "Donnees auth lisibles cross-origin.",
                "Whitelist stricte.", proof=f"ACAO: {acao} ACAC: {acac}"))
        elif acao == evil:
            self.add(Finding("CORS origine refletee", 'MEDIUM', self.base_url,
                f"ACAO: {acao}", "Origine refletee.",
                "Whitelist.", proof=f"ACAO: {acao}"))

    def check_info_disclosure(self):
        print(f"\n{C.MAGENTA}[~] 16/38 Info disclosure{C.END}")
        r = self.req('GET', self.base_url + '/404test-' + str(int(time.time())))
        if r and r.status_code == 404:
            low = r.text.lower()
            for sig, name in [('stack trace','stack trace'),('fatal error','erreur PHP'),
                              ('warning: ','warning PHP'),('exception','exception')]:
                if sig in low:
                    m = re.search(rf".{{0,80}}{re.escape(sig)}.{{0,120}}", r.text, re.IGNORECASE)
                    self.add(Finding(f"Erreur exposee ({name})", 'MEDIUM',
                        self.base_url + '/404test', "Info technique dans erreur.",
                        "Desactivez display_errors.",
                        proof=m.group(0) if m else sig)); break

    def scan_protected(self, paths):
        print(f"\n{C.MAGENTA}[~] 17/38 Scan pages protegees{C.END}")
        for p in paths:
            url = urljoin(self.base_url + '/', p.lstrip('/'))
            r = self.req('GET', url)
            if not r: continue
            has_body = len(r.content) > 500
            ok = (r.status_code == 200) or (r.status_code == 302 and has_body)
            print(f"   {r.status_code} {url} ({len(r.content)}b)")
            if not (ok and has_body): continue
            self.check_html_comments(url)
            for m in re.finditer(r'href=["\']([^"\']*admin[^"\']*)["\']', r.text, re.I):
                link = urljoin(url, m.group(1))
                if link not in self.visited:
                    self.add(Finding("Lien admin cache", 'LOW', link,
                        f"Trouve sur {p}", "Lien admin non liste.",
                        "Verifiez les controles d'acces.", proof=f"href={link}"))
            for cm in re.findall(r'<!--(.*?)-->', r.text, re.DOTALL):
                low = cm.lower()
                for kw in ['backup','rgpd','admin','api','private','secret','internal','debug']:
                    if kw in low:
                        m2 = re.search(r'(?:action|href|src)=["\']([^"\']+)["\']', cm, re.I)
                        target = m2.group(1) if m2 else kw
                        self.add(Finding("URL sensible dans commentaire HTML", 'HIGH', url,
                            f"Cible cachee via '{kw}': {target}",
                            "Commentaire HTML revelant une page sensible.",
                            "Retirez les commentaires. Protegez les pages sensibles.",
                            proof=cm.strip()[:200]))
                        break

    def show_findings_rich(self):
        """Affiche les findings avec rich (tableau colore)."""
        console = Console()
        table = Table(title=f"Findings - {self.base_url}")
        table.add_column("Sev", style="bold")
        table.add_column("Nom")
        table.add_column("URL", style="dim")
        for f in self.findings:
            color = {"CRITICAL":"magenta","HIGH":"red","MEDIUM":"yellow",
                     "LOW":"cyan","INFO":"blue"}.get(f.severity, "white")
            table.add_row(f"[{color}]{f.severity}[/{color}]", f.name, f.url)
        console.print(table)

    def report(self, out_json=None, out_html=None):
        # Affichage rich si disponible
        try:
            self.show_findings_rich()
        except Exception:
            pass
        print(f"\n{C.BOLD}{'='*62}")
        print(f"   RAPPORT - {self.base_url}")
        print(f"{'='*62}{C.END}")
        print(f"Date  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total : {len(self.findings)} findings\n")
        groups = {'CRITICAL':[],'HIGH':[],'MEDIUM':[],'LOW':[],'INFO':[]}
        for f in self.findings: groups[f.severity].append(f)
        for sev in ['CRITICAL','HIGH','MEDIUM','LOW','INFO']:
            if not groups[sev]: continue
            col = {'CRITICAL':C.RED+C.BOLD,'HIGH':C.RED,'MEDIUM':C.YELLOW,
                   'LOW':C.CYAN,'INFO':C.BLUE}[sev]
            print(f"{col}--- {sev} ({len(groups[sev])}) ---{C.END}")
            for f in groups[sev]:
                print(f"\n{col}[{f.severity}]{C.END} {C.BOLD}{f.name}{C.END}")
                print(f"  URL    : {f.url}")
                if f.payload: print(f"  Payload: {f.payload}")
                print(f"  Preuve : {f.evidence}")
                if f.proof: print(f"  {C.DIM}Extrait: {f.proof[:200]}{C.END}")
                print(f"  {C.GREEN}Fix    {C.END}: {f.remediation}")
            print()
        if out_json:
            with open(out_json,'w') as fp:
                json.dump({'target':self.base_url,'date':datetime.now().isoformat(),
                           'findings':[f.to_dict() for f in self.findings]},
                          fp, indent=2, ensure_ascii=False)
            print(f"{C.GREEN}[+] JSON : {out_json}{C.END}")
        if out_html:
            self._html(out_html)
            print(f"{C.GREEN}[+] HTML : {out_html}{C.END}")

    def _html(self, path):
        sev_counts = Counter(f.severity for f in self.findings)
        mod_counts = Counter(f.name.split()[0] for f in self.findings)
        tpl = """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<title>VulnScan - {{ target }}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body{font-family:system-ui;max-width:1400px;margin:auto;padding:1em;background:#f5f5f5}
.charts{display:grid;grid-template-columns:1fr 1fr;gap:1em;margin:2em 0}
canvas{background:#fff;border-radius:8px;padding:1em}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden}
th,td{padding:.6em;border-bottom:1px solid #eee}
th{background:#2c3e50;color:#fff}
tr.critical{background:#f3e5f5} tr.high{background:#ffebee}
tr.medium{background:#fff8e1} tr.low{background:#e3f2fd}
.filters{margin:1em 0}
.filters input,.filters select{padding:.4em;margin-right:.5em}
</style></head><body>
<h1>Rapport VulnScan</h1>
<p><b>Cible :</b> {{ target }}<br><b>Date :</b> {{ date }}<br>
<b>Total :</b> {{ total }} findings</p>
<div class="charts">
  <canvas id="sevChart"></canvas>
  <canvas id="modChart"></canvas>
</div>
<div class="filters">
  <input id="search" placeholder="Rechercher...">
  <select id="sevFilter">
    <option value="">Toutes severites</option>
    {% for s in ['CRITICAL','HIGH','MEDIUM','LOW','INFO'] %}
    <option>{{ s }}</option>{% endfor %}
  </select>
</div>
<table id="tbl">
<thead><tr><th>Sev</th><th>Nom</th><th>URL</th><th>Preuve</th><th>Fix</th></tr></thead>
<tbody>
{% for f in findings %}
<tr class="{{ f.severity|lower }}" data-sev="{{ f.severity }}">
  <td><b>{{ f.severity }}</b></td>
  <td>{{ f.name }}</td>
  <td><code>{{ f.url }}</code></td>
  <td><code>{{ f.payload or '' }}</code><br><small>{{ (f.proof or '')[:200] }}</small></td>
  <td><pre>{{ f.remediation }}</pre></td>
</tr>
{% endfor %}
</tbody></table>
<script>
const sevData = {{ sev_counts|tojson }};
new Chart(document.getElementById('sevChart'), {
  type:'doughnut',
  data:{labels:Object.keys(sevData),datasets:[{data:Object.values(sevData),
    backgroundColor:['#7b1fa2','#c62828','#f9a825','#0288d1','#455a64']}]},
  options:{plugins:{title:{display:true,text:'Par severite'}}}
});
const modData = {{ mod_counts|tojson }};
new Chart(document.getElementById('modChart'), {
  type:'bar',
  data:{labels:Object.keys(modData),datasets:[{label:'Findings',data:Object.values(modData),
    backgroundColor:'#2c3e50'}]},
  options:{plugins:{title:{display:true,text:'Par module'}},indexAxis:'y'}
});
document.getElementById('search').oninput = filter;
document.getElementById('sevFilter').onchange = filter;
function filter(){
  const q = document.getElementById('search').value.toLowerCase();
  const s = document.getElementById('sevFilter').value;
  document.querySelectorAll('#tbl tbody tr').forEach(tr=>{
    const match = (!q || tr.innerText.toLowerCase().includes(q))
                && (!s || tr.dataset.sev === s);
    tr.style.display = match ? '' : 'none';
  });
}
</script></body></html>"""
        html = Template(tpl).render(
            target=self.base_url,
            date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total=len(self.findings),
            findings=[f.to_dict() for f in self.findings],
            sev_counts=dict(sev_counts),
            mod_counts=dict(mod_counts),
        )
        with open(path, 'w') as f:
            f.write(html)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"


BANNER = f"""{C.BOLD}{C.CYAN}
╔═══════════════════════════════════════════════════╗
║      VulnScan v{__version__}  -  {OS_NAME:<10}     ║
║  Usage educatif / CTF autorise uniquement         ║
╚═══════════════════════════════════════════════════╝
{C.END}{C.YELLOW}[!] Cibles autorisees uniquement{C.END}
"""


MENU = f"""{C.BOLD}Que voulez-vous tester ?{C.END}
  {C.GREEN}1{C.END}. Audit complet + deep crawl
  {C.GREEN}2{C.END}. Passif (headers, fichiers, cookies, comments)
  {C.GREEN}3{C.END}. Injections sur URL personnalisee
  {C.GREEN}4{C.END}. IDOR / Open Redirect / CORS
  {C.GREEN}5{C.END}. Deep crawl + tests
  {C.GREEN}6{C.END}. Formulaire (SQLi bypass / XSS)
  {C.GREEN}7{C.END}. Scan pages protegees (avec cookie)
  {C.GREEN}q{C.END}. Quitter
"""


def validate_url(u):
    """Valide et normalise une URL. Retourne None si invalide."""
    if not u:
        return None
    try:
        if u.count('://') > 1:
            return None
        if '://' in u and not u.startswith(('http://', 'https://')):
            return None
        parsed = urlparse(u)
        if not parsed.netloc:
            return None
        if any(c in parsed.netloc for c in ' *<>"'):
            return None
        return u.rstrip('/')
    except (ValueError, AttributeError):
        return None


def ask_url():
    print(f"{C.BOLD}Entrez l'URL ou l'IP de la cible a analyser.{C.END}")
    print(f"{C.DIM}Exemples : https://exemple.com | http://192.168.1.10 | 192.168.1.10:8080{C.END}")
    while True:
        u = input(f"{C.BOLD}URL / IP cible > {C.END}").strip()
        if not u:
            print(f"{C.YELLOW}[!] Entrez une URL ou une IP.{C.END}")
            continue
        if u.lower() in ('q', 'quit', 'exit'):
            return None
        if not u.startswith(('http://', 'https://')):
            is_private = any(u.startswith(p) for p in (
                '192.168.', '10.', '172.16.', '172.17.', '172.18.',
                '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                '172.29.', '172.30.', '172.31.', '127.', 'localhost'
            ))
            http_only = ('scanme.nmap.org', 'ctf01.root-me.org', 'ctf03.root-me.org')
            is_http_only = any(u.startswith(p) for p in http_only)
            u = ('http://' if (is_private or is_http_only) else 'https://') + u
        u = validate_url(u)
        if not u:
            print(f"{C.RED}[!] URL invalide : {u}{C.END}")
            continue
        print(f"{C.GREEN}[+] Cible : {u}{C.END}")
        return u


def ask_delay():
    while True:
        d = input(f"{C.BOLD}Delai (0.5) > {C.END}").strip() or "0.5"
        try:
            v = float(d)
            if v < 0:
                print(f"{C.YELLOW}[!] Le delai doit etre positif.{C.END}")
                continue
            return v
        except ValueError:
            print(f"{C.YELLOW}[!] '{d}' n'est pas un nombre. Exemple : 0.5{C.END}")


def ask_params_url():
    u = input(f"{C.BOLD}URL avec params > {C.END}").strip()
    if not u.startswith(('http','https')): u = 'https://'+u
    pu = urlparse(u)
    return urlunparse((pu.scheme,pu.netloc,pu.path,'','','')), {k:v[0] for k,v in parse_qs(pu.query).items()}


def setup_auth(sc):
    print(f"\n{C.BOLD}Configuration d'acces{C.END}")
    r = sc.req('GET', sc.base_url)
    needs = False
    if r:
        print(f"Status initial : HTTP {r.status_code}")
        if r.status_code == 401:
            u = input(f"{C.BOLD}User Basic Auth > {C.END}").strip()
            if u:
                p = input(f"{C.BOLD}Pass > {C.END}").strip()
                sc.set_basic_auth(u, p)
        elif r.status_code < 400 and ('type="password"' in r.text.lower() or "type='password'" in r.text.lower()):
            needs = True
    if needs:
        print(f"{C.YELLOW}[!] Login detecte - fournissez le cookie PHPSESSID.{C.END}")
    ck = input(f"{C.BOLD}Cookie ou vide > {C.END}").strip()
    if ck: sc.set_cookie(ck)
    hdr = input(f"{C.BOLD}Header custom ou vide > {C.END}").strip()
    if ':' in hdr:
        k,v = hdr.split(':',1); sc.set_header(k.strip(), v.strip())


def run_full(sc):
    if not sc.ping():
        return
    sc.check_headers(); sc.check_files(); sc.check_cookies()
    sc.check_methods(); sc.check_dir_listing()
    sc.check_forms(); sc.check_form_vulns()
    sc.check_html_comments(); sc.check_cors(); sc.check_info_disclosure()
    sc.check_ssl()
    sc.check_technologies()
    sc.check_backups()
    sc.check_waf()
    sc.check_ports()
    sc.check_api_endpoints()
    sc.check_admin_panels()
    sc.check_cms_paths()
    sc.check_wellknown()
    sc.check_mixed_content()
    sc.check_sri()
    sc.check_dns_security()
    sc.check_subdomains()
    sc.check_dirb()
    sc.check_http_methods()
    sc.check_deserialization()
    sc.check_takeover()
    sc.check_ratelimit()
    sc.check_leaks()
    pages = sc.deep_crawl(depth=2, max_pages=20)
    for link in pages:
        pu = urlparse(link)
        params = {k:v[0] for k,v in parse_qs(pu.query).items()}
        base = urlunparse((pu.scheme,pu.netloc,pu.path,'','',''))
        if params:
            sc.check_sqli(base,'GET',params)
            sc.check_xss(base,'GET',params)
            sc.check_idor(base,params)
            sc.check_lfi(base,params)
            sc.check_open_redirect(base,params)
        sc.check_html_comments(link)


def mode_interactif():
    print(BANNER)
    url = ask_url()
    if not url:
        return
    sc = VulnScanner(url, delay=ask_delay())
    setup_auth(sc)
    if not sc.ping():
        print(f"{C.YELLOW}[!] Scan annule : cible injoignable.{C.END}")
        return
    print(MENU)
    ch = input(f"{C.BOLD}Choix > {C.END}").strip().lower()
    if ch == 'q': return
    try:
        if ch == '1': run_full(sc)
        elif ch == '2':
            sc.check_headers(); sc.check_files(); sc.check_cookies()
            sc.check_html_comments(); sc.check_dir_listing()
        elif ch == '3':
            base, params = ask_params_url()
            if not params: return
            print(f"Params: {params}")
            sc.check_sqli(base,'GET',params); sc.check_xss(base,'GET',params)
            sc.check_lfi(base,params); sc.check_idor(base,params)
        elif ch == '4':
            base, params = ask_params_url()
            sc.check_idor(base,params); sc.check_open_redirect(base,params); sc.check_cors()
        elif ch == '5':
            for link in sc.deep_crawl(depth=2):
                pu = urlparse(link)
                params = {k:v[0] for k,v in parse_qs(pu.query).items()}
                base = urlunparse((pu.scheme,pu.netloc,pu.path,'','',''))
                if params:
                    sc.check_sqli(base,'GET',params); sc.check_xss(base,'GET',params)
                    sc.check_idor(base,params); sc.check_lfi(base,params)
                    sc.check_open_redirect(base,params)
        elif ch == '6':
            u = input(f"{C.BOLD}URL formulaire > {C.END}").strip()
            if not u.startswith(('http','https')): u = 'https://'+u
            fields = input(f"{C.BOLD}Champs (virgule) > {C.END}").strip()
            sc.check_form_vulns()
        elif ch == '7':
            paths = input(f"{C.BOLD}Chemins (virgule) > {C.END}").strip()
            sc.scan_protected([p.strip() for p in paths.split(',')])
        else: return
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrompu.{C.END}")
    if sc.findings:
        rep = input(f"\n{C.BOLD}Rapport JSON+HTML ? (o/n) > {C.END}").strip().lower()
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        host = urlparse(sc.base_url).netloc.replace(':','_')
        if rep in ('o','oui','y'):
            sc.report(out_json=f"rapport_{host}_{ts}.json", out_html=f"rapport_{host}_{ts}.html")
        else: sc.report()
    else:
        print(f"\n{C.GREEN}Aucun finding.{C.END}")


def main():

    p = argparse.ArgumentParser(
        prog="vulnscan",
        description="VulnScan - scanner pedagogique de vulnerabilites web",
    )
    p.add_argument('url', nargs='?', help="URL ou IP cible (obligatoire en mode CLI)")
    p.add_argument('--version', action='version',
                   version=f"VulnScan {__version__} (Python {platform.python_version()})")
    p.add_argument('--check', action='store_true',
                   help="Verifie l'environnement et quitte")
    p.add_argument('--delay', type=float, default=0.5)
    p.add_argument('--full', action='store_true')
    p.add_argument('--json'); p.add_argument('--html')
    p.add_argument('--cookie'); p.add_argument('--user'); p.add_argument('--password')
    p.add_argument('--scan-protected')
    p.add_argument('--stealth', action='store_true', help='Mode furtif (UA aleatoire, delai random)')
    p.add_argument('--plugin', action='store_true', help='Charge les plugins du dossier plugins/')
    p.add_argument('--kb', help='Affiche une fiche KB (ex: hsts)')
    p.add_argument('--tutorial', help='Affiche un tutoriel (ex: 03-sqli)')
    p.add_argument('--slack', help='Webhook Slack pour notification')
    p.add_argument('--verify', metavar='BASELINE_JSON',
                   help="Verifie que les failles d'un rapport baseline sont corrigees")
    args = p.parse_args()

    if args.kb:
        path = Path(__file__).parent / "docs" / "kb" / f"{args.kb}.md"
        if path.exists():
            print(path.read_text())
        else:
            print(f"[!] KB '{args.kb}' introuvable")
            print("Disponibles :", [p.stem for p in (Path(__file__).parent / "docs" / "kb").glob("*.md")])
        return
    if args.tutorial:
        path = Path(__file__).parent / "docs" / "tutorials" / f"{args.tutorial}.md"
        if path.exists():
            print(path.read_text())
        else:
            print(f"[!] Tutoriel '{args.tutorial}' introuvable")
            print("Disponibles :", [p.stem for p in (Path(__file__).parent / "docs" / "tutorials").glob("*.md")])
        return
    if args.check:
        print(f"[i] OS         : {OS_NAME} {platform.release()}")
        print(f"[i] Python     : {platform.python_version()}")
        print(f"[i] requests   : {requests.__version__}")
        print(f"[i] urllib3    : {__import__('urllib3').__version__}")
        print("[+] Environnement OK")
        return

    if not args.url:
        # Pas d'URL fournie : on lance le mode interactif (qui demandera l'URL/IP)
        if args.full or args.json or args.html or args.scan_protected:
            print(f"{C.RED}[!] Erreur : une URL ou IP est obligatoire en mode CLI.{C.END}")
            print(f"{C.YELLOW}Usage : vulnscan <URL_ou_IP> [options]{C.END}")
            print(f"{C.DIM}Exemple : vulnscan https://exemple.com --full{C.END}")
            print(f"{C.DIM}Ou lancez le mode interactif : vulnscan{C.END}")
            sys.exit(1)
        try: mode_interactif()
        except KeyboardInterrupt: pass
        return
    print(BANNER)
    # Valider l'URL en mode CLI
    validated = validate_url(args.url)
    if not validated:
        print(f"{C.RED}[!] URL invalide : {args.url}{C.END}")
        print(f"{C.DIM}Format attendu : https://exemple.com ou http://192.168.1.10{C.END}")
        sys.exit(1)
    if args.stealth:
        from core.stealth import apply as stealth_apply
        sc = VulnScanner(validated, delay=args.delay)
        stealth_apply(sc)
    else:
        sc = VulnScanner(validated, delay=args.delay)
    if args.user and args.password: sc.set_basic_auth(args.user, args.password)
    if args.cookie: sc.set_cookie(args.cookie)
    if not sc.ping():
        sys.exit(1)
    if args.verify:
        code = verify_fixes(sc, args.verify)
        sys.exit(code)
    if args.scan_protected:
        sc.scan_protected([p.strip() for p in args.scan_protected.split(',')])
    elif args.full: run_full(sc)
    else: sc.check_headers(); sc.check_files()
    if args.plugin:
        try:
            from core.plugins import load_plugins
            for mod in load_plugins():
                print(f"{C.CYAN}[i] Plugin: {mod.__name__}{C.END}")
                mod.scan(sc)
        except Exception as e:
            print(f"{C.RED}[!] Plugins: {e}{C.END}")
    sc.report(out_json=args.json, out_html=args.html)
    if args.slack:
        try:
            from integrations.slack import notify
            notify(args.slack, sc.base_url, sc.findings)
            print(f"{C.GREEN}[+] Slack notifie{C.END}")
        except Exception as e:
            print(f"{C.RED}[!] Slack: {e}{C.END}")


if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Au revoir.{C.END}"); sys.exit(0)
