#!/data/data/com.termux/files/usr/bin/bash
set -e
cd "$(dirname "$0")"

pkg update -y
pkg install python -y

python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

echo "[+] VulnScan pret sur Termux."
echo "[+] Activez le venv : source .venv/bin/activate"
