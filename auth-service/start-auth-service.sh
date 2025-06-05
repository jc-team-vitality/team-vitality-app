#!/bin/bash

set -e

echo "Activating virtual environment for auth-service..."
source .venv/bin/activate

echo "Starting uvicorn for auth-service..."
uvicorn app.main:app --host 0.0.0.0 --port 3002 --reload
