# Database Migrations

This directory contains the database schema migrations for the TeamVitality project, managed by Flyway.

## Overview

We use Flyway to version control our database schema. Migrations are written in plain SQL and stored in the `/sql` directory. Flyway tracks which migrations have been applied in a `flyway_schema_history` table within the database.

## Naming Convention

SQL migration scripts must follow the naming convention: `V<VERSION>__<DESCRIPTION>.sql`. For example: `V1__Create_initial_tables.sql`.

## Local Development

To run migrations against your local database:

1.  Start the local PostgreSQL container:
    `docker-compose up -d db`

2.  Run the migrations using the Flyway Docker image:
    This command mounts your local SQL scripts into the Flyway container and runs the `migrate` command against the local database defined in `docker-compose.yml`.

    `docker run --rm --network=host -v $(pwd)/database-migrations/sql:/flyway/sql flyway/flyway:latest -url=jdbc:postgresql://localhost:5432/teamvitality_dev -user=admin -password=password migrate`

    Note: `--network=host` is used here for simplicity to allow the Flyway container to connect to localhost. This may vary depending on your Docker setup.

## CI/CD Deployment

Database migrations are applied automatically to the production Google Cloud SQL database via a Google Cloud Build trigger.

  - Trigger: The build is triggered by a push to the `main` branch with changes in the `database-migrations/` directory.
  - Process: The `cloudbuild.yaml` file defines the steps to securely connect to the Cloud SQL database using the Cloud SQL Auth Proxy and then run `flyway migrate`.
  - Configuration: The Cloud Build trigger must be configured with the following substitution variables: `_PROJECT_ID`, `_DB_REGION`, `_DB_INSTANCE_NAME`, `_DB_NAME`, `_DB_USER`. The database password is fetched securely from GCP Secret Manager.
