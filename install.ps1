# Installation VulnScan sous Windows
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { Write-Host "[-] Python introuvable. Installez-le depuis python.org"; exit 1 }

Write-Host "[+] Python : $(& python --version)"
& python -m venv .venv
& .\.venv\Scripts\Activate.ps1
& python -m pip install --upgrade pip
& python -m pip install -r requirements.txt
& python -m pip install -e .

Write-Host "[+] Installation terminee."
Write-Host "[+] Lancez : vulnscan --check"
