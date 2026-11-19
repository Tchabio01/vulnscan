# Installation

## Prerequis

- Python 3.8 ou superieur
- Git
- Connexion Internet (pour pip)

## Linux / macOS

git clone https://github.com/Tchabio01/vulnscan.git
cd vulnscan
bash install.sh
source .venv/bin/activate
vulnscan --check

## Windows (PowerShell)

git clone https://github.com/Tchabio01/vulnscan.git
cd vulnscan
powershell -ExecutionPolicy Bypass -File install.ps1
.\.venv\Scripts\Activate.ps1
vulnscan --check

## Termux (Android)

pkg install git python -y
git clone https://github.com/Tchabio01/vulnscan.git
cd vulnscan
bash install-termux.sh
source .venv/bin/activate
vulnscan --check

## Verification

vulnscan --version
vulnscan --check

Sortie attendue :

VulnScan 3.3.1 (Python 3.14.x)
[i] OS         : Linux 7.x
[i] Python     : 3.14.x
[i] requests   : 2.34.x
[i] urllib3    : 2.8.x
[+] Environnement OK

## Depannage

### error: externally-managed-environment (Kali, Debian 12+)

Solution : utiliser un venv (deja fait par install.sh).

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

### vulnscan: command not found

Le venv n'est pas active, ou l'installation a echoue.

cd vulnscan
source .venv/bin/activate
pip install -e .
which vulnscan

### ModuleNotFoundError: No module named requests

source .venv/bin/activate
pip install -r requirements.txt

### Le venv n'est pas active a chaque nouveau terminal

C'est normal. Reactivez-le :

cd ~/vulnscan
source .venv/bin/activate
