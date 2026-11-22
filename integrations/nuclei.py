import subprocess, json
from vulnscan import Finding


def scan(sc):
    try:
        r = subprocess.run(["nuclei", "-u", sc.base_url, "-json", "-silent"],
                           capture_output=True, text=True, timeout=300)
        for line in r.stdout.splitlines():
            try:
                d = json.loads(line)
                sev = d.get("info", {}).get("severity", "INFO").upper()
                sc.add(Finding(d.get("info", {}).get("name", "Nuclei"),
                               sev, d.get("matched-at", sc.base_url),
                               d.get("template-id", ""),
                               "Detecte par Nuclei", "Voir template Nuclei.",
                               proof=d.get("matcher-name", "")))
            except json.JSONDecodeError:
                pass
    except FileNotFoundError:
        print("[!] Nuclei non installe")
