import random
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]


def apply(sc):
    sc.session.headers["User-Agent"] = random.choice(UAS)
    sc.delay = random.uniform(0.5, 2.0)
    print(f"[i] Mode furtif : UA aleatoire, delai {sc.delay:.2f}s")
