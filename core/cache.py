import json, hashlib, pathlib

CACHE = pathlib.Path.home() / ".vulnscan_cache"
CACHE.mkdir(exist_ok=True)


def _key(method, url, **kw):
    return hashlib.sha256(f"{method}{url}{kw}".encode()).hexdigest()


def get(method, url, **kw):
    p = CACHE / _key(method, url, **kw)
    if p.exists():
        return json.loads(p.read_text())
    return None


def put(method, url, data, **kw):
    (CACHE / _key(method, url, **kw)).write_text(json.dumps(data))
