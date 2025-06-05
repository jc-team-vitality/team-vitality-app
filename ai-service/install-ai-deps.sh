#!/bin/bash
set -e

echo "Creating/refreshing virtual environment and installing Python dependencies for ai-service..."
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
echo "Python dependencies installed successfully."
deactivate
