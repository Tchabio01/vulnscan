import subprocess, xml.etree.ElementTree as ET
from urllib.parse import urlparse
from vulnscan import Finding


def scan(sc):
    host = urlparse(sc.base_url).hostname
    try:
        r = subprocess.run(["nmap", "-sV", "-oX", "-", host],
                           capture_output=True, text=True, timeout=120)
        root = ET.fromstring(r.stdout)
        ports = []
        for p in root.iter("port"):
            ports.append(f"{p.get('portid')}/{p.find('state').get('state')}")
        if ports:
            sc.add(Finding("Ports Nmap", 'INFO', sc.base_url,
                f"{len(ports)} ports", "Scan Nmap.", "Fermez les ports inutiles.",
                proof=", ".join(ports[:10])))
    except FileNotFoundError:
        print("[!] Nmap non installe")
