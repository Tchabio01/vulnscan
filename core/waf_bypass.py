import urllib.parse


def encode_payloads(p):
    return [
        p,
        urllib.parse.quote(p),
        p.replace(" ", "/**/"),
        p.replace("'", "%27"),
        p.replace("<", "%3C").replace(">", "%3E"),
    ]
