#!/bin/bash

set -e

echo "Activating virtual environment for ai-service..."
source .venv/bin/activate

echo "Starting uvicorn for ai-service..."
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
