#!/usr/bin/env python3
"""VulnScan v3.3 - Audit pedagogique web - Multiplateforme
Compatible Linux, Windows, macOS, Termux.
"""
import argparse, sys, time, json, re, os, platform
from urllib.parse import urlparse, parse_qs, urlunparse, urljoin
from datetime import datetime

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

__version__ = "3.3.0"
OS_NAME = platform.system()  # Linux, Windows, Darwin


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
            if self.verbose:
                self.log(f"Err {url}: {e.__class__.__name__}", 'err')
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
        print(f"\n{C.MAGENTA}[~] 0/18 Test de connectivite{C.END}")
        r = self.req('GET', self.base_url)
        if not r:
            self.log(f"Cible injoignable : {self.base_url}", 'err')
            self.log("Verifiez l'URL, le reseau, ou un eventuel pare-feu.", 'warn')
            return False
        elapsed = r.elapsed.total_seconds() if hasattr(r, 'elapsed') else 0
        print(f"   HTTP {r.status_code} - {len(r.content)} octets - {elapsed:.2f}s")
        return True

    def check_headers(self):
        print(f"\n{C.MAGENTA}[~] 1/18 En-tetes de securite{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 2/18 Fichiers sensibles{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 3/18 Commentaires HTML sur {url}{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 4/18 Cookies{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 5/18 Methodes HTTP{C.END}")
        r = self.req('OPTIONS', self.base_url)
        if not r: return
        allow = r.headers.get('Allow','') or r.headers.get('allow','')
        dangerous = [m for m in ['PUT','DELETE','TRACE','CONNECT','PATCH'] if m in allow.upper()]
        if dangerous:
            self.add(Finding("Methodes HTTP dangereuses", 'HIGH', self.base_url,
                f"Allow: {allow}", f"Methodes {', '.join(dangerous)} actives.",
                "Desactivez TRACE. Limitez PUT/DELETE.", proof=f"Allow: {allow}"))

    def check_dir_listing(self):
        print(f"\n{C.MAGENTA}[~] 6/18 Directory listing{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 7/18 Formulaires{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 7b/18 Test formulaires POST{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 8/18 Crawl{C.END}")
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
        print(f"{C.MAGENTA}[~] 9/18 SQLi sur {url}{C.END}")
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
        print(f"{C.MAGENTA}[~] 10/18 XSS reflechi sur {url}{C.END}")
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
        print(f"{C.MAGENTA}[~] 12/18 IDOR sur {url}{C.END}")
        nums = {k:v for k,v in (params or {}).items() if str(v).isdigit()}
        for k,v in nums.items():
            v = int(v)
            base = self.req('GET', url, params={k:v})
            if not base: continue
            base_len = len(base.text)
            for tv in [v-1, v+1, v+2, 1, 100]:
                if tv < 0 or tv == v: continue
                r = self.req('GET', url, params={k:tv})
                if not r or r.status_code != 200: continue
                if abs(len(r.text) - base_len) < 50: continue
                self.add(Finding(f"IDOR sur '{k}'", 'HIGH', url,
                    f"{k}={v} ({base_len}b) vs {k}={tv} ({len(r.text)}b)",
                    "Acces donnees d'autrui.",
                    "Verif ownership cote serveur.",
                    payload=f"{k}={tv}",
                    proof=f"{base_len}b -> {len(r.text)}b")); return

    def check_lfi(self, url, params):
        print(f"{C.MAGENTA}[~] 13/18 LFI sur {url}{C.END}")
        if not params: return
        for pl, sig in [("../../../../etc/passwd", r"root:.*:0:0:"),
                        ("....//....//....//etc/passwd", r"root:.*:0:0:"),
                        ("/etc/passwd", r"root:.*:0:0:"),
                        ("php://filter/convert.base64-encode/resource=index.php", r"[A-Za-z0-9+/=]{50,}")]:
            r = self.req('GET', url, params={k:pl for k in params})
            if not r: continue
            m = re.search(sig, r.text)
            if m:
                self.add(Finding("LFI", 'CRITICAL', url, f"Payload: {pl}",
                    "Lecture fichiers serveur.",
                    "Whitelist + basename() + realpath().",
                    payload=pl, proof=m.group(0)[:120])); return

    def check_open_redirect(self, url, params):
        print(f"{C.MAGENTA}[~] 14/18 Open Redirect sur {url}{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 15/18 CORS{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 16/18 Info disclosure{C.END}")
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
        print(f"\n{C.MAGENTA}[~] 17/18 Scan pages protegees{C.END}")
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

    def report(self, out_json=None, out_html=None):
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
        sev_col = {'CRITICAL':'#7b1fa2','HIGH':'#c62828','MEDIUM':'#f9a825','LOW':'#0288d1','INFO':'#455a64'}
        rows = []
        for f in sorted(self.findings, key=lambda x: Finding.SEV_ORDER[x.severity]):
            rows.append(
              f"<tr><td style='background:{sev_col[f.severity]};color:#fff;font-weight:bold'>{f.severity}</td>"
              f"<td><b>{f.name}</b><br><small>{f.description}</small></td>"
              f"<td><code>{f.url}</code></td>"
              f"<td><code>{f.payload or ''}</code><br><small>{f.proof or ''}</small></td>"
              f"<td><pre style='white-space:pre-wrap'>{f.remediation}</pre></td></tr>")
        html = f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<title>VulnScan - {self.base_url}</title><style>
body{{font-family:sans-serif;max-width:1300px;margin:1em auto;padding:1em;background:#f5f5f5}}
table{{width:100%;border-collapse:collapse;background:#fff}}
th,td{{border:1px solid #eee;padding:8px;font-size:14px}}
th{{background:#2c3e50;color:#fff}}code{{background:#f4f4f4;padding:2px 4px;font-size:12px}}
</style></head><body><h1>Rapport VulnScan</h1>
<p><b>Cible :</b> {self.base_url}<br><b>Date :</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
<b>Total :</b> {len(self.findings)}</p>
<table><thead><tr><th>Sev</th><th>Faille</th><th>URL</th><th>Preuve</th><th>Fix</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>"""
        with open(path,'w') as fp: fp.write(html)


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
            u = ('http://' if is_private else 'https://') + u
        parsed = urlparse(u)
        if not parsed.netloc:
            print(f"{C.RED}[!] URL invalide : {u}{C.END}")
            continue
        u = u.rstrip('/')
        print(f"{C.GREEN}[+] Cible : {u}{C.END}")
        return u

def ask_delay():
    try:
        d = input(f"{C.BOLD}Delai (0.5) > {C.END}").strip() or "0.5"
        return max(0.0, float(d))
    except ValueError: return 0.5

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
    args = p.parse_args()

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
    sc = VulnScanner(args.url, delay=args.delay)
    if args.user and args.password: sc.set_basic_auth(args.user, args.password)
    if args.cookie: sc.set_cookie(args.cookie)
    if not sc.ping():
        sys.exit(1)
    if args.scan_protected:
        sc.scan_protected([p.strip() for p in args.scan_protected.split(',')])
    elif args.full: run_full(sc)
    else: sc.check_headers(); sc.check_files()
    sc.report(out_json=args.json, out_html=args.html)


if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Au revoir.{C.END}"); sys.exit(0)
