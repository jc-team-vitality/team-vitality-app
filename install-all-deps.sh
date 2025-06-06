#!/bin/bash
set -e

echo "========================================================"
echo "  TeamVitality - Installing Dependencies for All Services"
echo "========================================================"

echo -e "\n=== Installing dependencies for web-application and api-gateway (monorepo) ==="
# Use pnpm to install dependencies for both web-application and api-gateway
(cd web-platform && pnpm install)

echo -e "\n=== Installing dependencies for ai-service ==="
(cd ai-service && ./install-ai-deps.sh)

echo -e "\n=== Installing dependencies for auth-service ==="
(cd auth-service && ./install-auth-deps.sh)

echo -e "\n========================================================"
echo "  All dependencies installed successfully!"
echo "========================================================"
