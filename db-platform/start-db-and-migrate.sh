#!/bin/bash

set -e

echo "Starting local PostgreSQL database using docker-compose..."
docker-compose up -d db

# Wait for PostgreSQL to be ready
until docker exec teamvitality-postgres-local pg_isready -U admin > /dev/null 2>&1; do
  echo "Waiting for PostgreSQL to be ready..."
  sleep 2
done
echo "PostgreSQL is ready."

echo "Running Flyway migrations..."
docker run --rm --network=host -v $(pwd)/flyway/migrations:/flyway/sql flyway/flyway:latest -url=jdbc:postgresql://localhost:5432/teamvitality_dev -user=admin -password=password migrate

echo "Flyway migrations complete."
