import requests


def notify(webhook, target, findings):
    if not webhook:
        return
    text = f"VulnScan - {target}\n{len(findings)} findings\n"
    for f in findings[:5]:
        text += f"[{f.severity}] {f.name}\n"
    requests.post(webhook, json={"text": text}, timeout=5)
