"""Plugin exemple : detecte un header custom."""
from vulnscan import Finding


def scan(sc):
    r = sc.req('GET', sc.base_url)
    if r and 'X-Custom' in r.headers:
        sc.add(Finding("Header X-Custom detecte", 'INFO', sc.base_url,
            f"X-Custom: {r.headers['X-Custom']}",
            "Header custom present.", "Verifiez son utilite."))
