CONFIDENCE = {
    "HSTS manquant": 0.95,
    "LFI": 0.6,
    "IDOR potentiel": 0.5,
    "SQL Injection (error-based)": 0.9,
}


def is_likely_true_positive(finding):
    return CONFIDENCE.get(finding.name, 0.7) >= 0.7
