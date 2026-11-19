#!/usr/bin/env bash
# Installation multiplateforme VulnScan
set -e
cd "$(dirname "$0")"

PY=python3
command -v $PY >/dev/null 2>&1 || PY=python
command -v $PY >/dev/null 2>&1 || { echo "[-] Python introuvable"; exit 1; }

echo "[+] Python : $($PY --version)"
$PY -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

echo "[+] Installation terminee."
echo "[+] Activez le venv : source .venv/bin/activate"
echo "[+] Puis lancez     : vulnscan --check"
