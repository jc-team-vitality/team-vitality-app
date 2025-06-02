# Dockerfile for api-gateway (NestJS BFF)

# ---- Base PNPM Setup ----
FROM node:20-alpine AS base
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable && corepack prepare pnpm@latest --activate
WORKDIR /app

# ---- Source & Configuration ----
# Copy all necessary configuration and source code for the entire monorepo
# This stage will be used as a base for installing dependencies and building.
FROM base AS source_with_config
# Copy PNPM workspace configurations
COPY pnpm-lock.yaml pnpm-workspace.yaml ./
# Copy root package.json
COPY package.json ./
# Copy .npmrc (if you use one for PNPM settings)
#COPY .npmrc ./
# Copy Turborepo and root TypeScript configurations
COPY turbo.json ./
#COPY tsconfig.json ./

# Copy all source code for all packages in the workspace
# Docker will use .dockerignore from the build context (monorepo root)
COPY api-gateway ./api-gateway
# Or just its package.json if its full source isn't needed for api-gateway build
COPY web-application ./web-application
COPY packages ./packages

# ---- Builder ----
# This stage installs ALL dependencies (dev included) and builds the target application
FROM source_with_config AS builder
# Install all dependencies for the entire monorepo using the copied files
# This will create the node_modules structure with symlinks within this stage
RUN pnpm install --frozen-lockfile --prod=false

# Now, run the Turborepo build for the specific application (api-gateway)
# PNPM will find typescript and other tools via the node_modules it just created.
# The '...' after api-gateway is important if you want Turborepo to also build its dependent workspace packages.
# Alternatively, if your turbo.json's build pipeline has "dependsOn": ["^build"],
# then --filter=api-gateway is enough. For explicitness: --filter=api-gateway...
RUN pnpm exec turbo run build --filter=api-gateway...

# ---- Runner ----
# Final production image: copies only necessary artifacts
FROM node:20-alpine AS runner
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable && corepack prepare pnpm@latest --activate

ENV NODE_ENV=production
ENV PORT=8080
WORKDIR /app

# Create a user for running the application for better security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory for the application context within the runner
WORKDIR /app/api-gateway

# Copy only the built application and its package.json
COPY --chown=appuser:appgroup --from=builder /app/api-gateway/dist ./dist
COPY --chown=appuser:appgroup --from=builder /app/api-gateway/package.json ./package.json

# To install production dependencies for api-gateway AND its workspace dependencies (like shared-dtos)
# correctly with PNPM in the runner, we need the lockfile and workspace config at the root context.
COPY --chown=appuser:appgroup --from=builder /app/pnpm-lock.yaml /app/pnpm-lock.yaml
COPY --chown=appuser:appgroup --from=builder /app/pnpm-workspace.yaml /app/pnpm-workspace.yaml
# Root package.json for workspace context
COPY --chown=appuser:appgroup --from=builder /app/package.json /app/package.json
# If you use .npmrc
#COPY --chown=appuser:appgroup --from=builder /app/.npmrc /app/.npmrc

# Copy the source of shared-dtos (or its dist if it has one and api-gateway depends on that)
# because api-gateway's package.json will reference it as a workspace dependency.
COPY --chown=appuser:appgroup --from=builder /app/packages/shared-dtos /app/packages/shared-dtos

# Set WORKDIR to monorepo root to run pnpm install in workspace context, 
# targeting only api-gateway for its production dependencies.
WORKDIR /app
# Install production dependencies for api-gateway and its workspace dependencies only.
# The --filter=api-gateway... should ensure only necessary prod deps are installed.
# Check PNPM docs for the best way to deploy a single package from a workspace.
# `pnpm deploy` command might also be useful here if preparing a deployment package.
RUN pnpm install --prod --frozen-lockfile --filter=api-gateway...

# Set the user to run the application
USER appuser

# Reset WORKDIR for the CMD to the application's own directory
WORKDIR /app/api-gateway

EXPOSE 8080
CMD ["node", "dist/main.js"]