# Build stage
FROM node:20-alpine AS builder
WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm ci

# Copy application code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080 

# Copy only necessary files for running the app AND installing prod dependencies
COPY --from=builder /app/dist ./dist
COPY package.json package-lock.json ./

# Install ONLY production dependencies based on the copied package.json and lockfile
RUN npm ci --omit=dev

EXPOSE 8080
CMD ["node", "dist/main.js"]