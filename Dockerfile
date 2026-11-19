# VulnScan - Image Docker/Podman
FROM python:3.12-slim

LABEL maintainer="Tchabio01"
LABEL description="Scanner pedagogique de vulnerabilites web"
LABEL version="3.3.1"

# Metadonnees
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependances systeme minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Dependances Python (cache Docker)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Code source
COPY vulnscan.py .
COPY pyproject.toml .
COPY README.md .
COPY LICENSE .

# Installation en mode editable (entry point vulnscan)
RUN pip install --no-cache-dir -e .

# Utilisateur non-root (securite)
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app
USER scanner

# Repertoire de travail pour les rapports
WORKDIR /app/reports

# Point d'entree
ENTRYPOINT ["vulnscan"]
CMD ["--help"]
