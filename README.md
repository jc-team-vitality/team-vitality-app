# TeamVitality

This repository contains the TeamVitality application, structured as a multi-service architecture deployed on Google App Engine.

## Project Structure

```
/
|-- .github/workflows/         # GitHub Actions CI/CD workflows
|-- web-application/           # Next.js frontend application
|-- api-gateway/               # NestJS API gateway service
|-- ai-service/                # FastAPI AI service
```

## Services

### Web Application (Next.js)

A Next.js application that serves as the frontend for TeamVitality.

- **Port**: 3000 (local development)
- **Service Name**: web-app (on App Engine)
- **Technology**: Next.js, TypeScript, React

### API Gateway (NestJS)

A NestJS application that serves as the API gateway for TeamVitality.

- **Port**: 3001 (local development)
- **Service Name**: api-gw (on App Engine)
- **Technology**: NestJS, TypeScript

### AI Service (FastAPI)

A FastAPI application that provides AI services for TeamVitality.

- **Port**: 8000 (local development)
- **Service Name**: ai-svc (on App Engine)
- **Technology**: FastAPI, Python

## Local Development

### Web Application

```bash
cd web-application
npm install
npm run dev
```

### API Gateway

```bash
cd api-gateway
npm install
npm run start:dev
```

### AI Service

```bash
cd ai-service
pip install -r requirements.txt
python main.py
```

## Deployment

Each service is deployed to Google App Engine using GitHub Actions workflows. The workflows are triggered when changes are pushed to the main branch in the respective service directories.

### GitHub Secrets Required for Deployment

- `GCP_WIF_PROVIDER` - Workload Identity Federation provider string
- `GCP_SERVICE_ACCOUNT` - Google Cloud service account email
- `GCP_PROJECT_ID` - Google Cloud project ID

## Production Considerations

This setup is for a demo system. For production:

1. Implement proper authentication and authorization
2. Add comprehensive error handling and logging
3. Set up monitoring and alerting
4. Configure proper scaling and resource allocation
5. Implement HTTPS with proper certificates
6. Follow security best practices (OWASP Top 10)
7. Add comprehensive testing (unit, integration, e2e)
