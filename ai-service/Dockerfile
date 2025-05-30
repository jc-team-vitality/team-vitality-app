# Build stage
FROM python:3.11-slim AS builder

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim AS runner

WORKDIR /app

# Copy installed packages and application code
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY . .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PIP_ROOT_USER_ACTION=ignore

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["uvicorn", "main:app", "--host", "$HOST", "--port", "$PORT"]
