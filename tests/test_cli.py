import subprocess, sys


def test_version():
    out = subprocess.check_output([sys.executable, "vulnscan.py", "--version"], text=True)
    assert "VulnScan" in out


def test_check():
    out = subprocess.check_output([sys.executable, "vulnscan.py", "--check"], text=True)
    assert "Environnement OK" in out
