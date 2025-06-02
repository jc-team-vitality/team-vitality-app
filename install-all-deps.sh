#!/bin/bash
set -e

echo "========================================================"
echo "  TeamVitality - Installing Dependencies for All Services"
echo "========================================================"

echo -e "\n=== Installing dependencies for web-application and api-gateway (monorepo) ==="
# Use pnpm to install dependencies for both web-application and api-gateway
pnpm install

echo -e "\n=== Installing dependencies for ai-service ==="
(cd ai-service && \
    echo "Creating/refreshing virtual environment and installing Python dependencies..." && \
    python3 -m venv .venv && \
    source .venv/bin/activate && \
    pip install -r requirements.txt && \
    echo "Python dependencies installed successfully." && \
    deactivate )

echo -e "\n=== Installing dependencies for auth-service ==="
(cd auth-service && \
    echo "Creating/refreshing virtual environment and installing Python dependencies..." && \
    python3 -m venv .venv && \
    source .venv/bin/activate && \
    pip install -r requirements.txt && \
    echo "Python dependencies installed successfully." && \
    deactivate )

echo -e "\n========================================================"
echo "  All dependencies installed successfully!"
echo "========================================================"
