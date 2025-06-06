#!/bin/bash

set -e

echo "========================================================"
echo "  TeamVitality - Starting All Services in Development Mode"
echo "========================================================"
echo "Services will run in the background."
echo "To stop all services started by this script, try 'pkill -P $$' or close this terminal."
echo "Alternatively, find PIDs with 'jobs -p' and use 'kill <PID>'."
echo "========================================================"

# Start DB and run migrations
./db-platform/start-db-and-migrate.sh

echo "========================================================"
echo -e "\nStarting web-application and api-gateway (monorepo) dev servers..."
# Use pnpm to start both dev servers in parallel
cd web-platform &&
pnpm run dev &
MONOREPO_PID=$!
echo "web-application and api-gateway dev servers started with PID: $MONOREPO_PID"
echo "Access web-application at: http://localhost:3000"
echo "Access api-gateway at: http://localhost:3001"
echo "========================================================"

# Start ai-service
# Run in a subshell in the background
(
    cd ai-service && ./start-ai-service.sh
) &
AI_PID=$!
echo "ai-service started with PID: $AI_PID"
echo "Access at: http://localhost:8000"
echo "========================================================"

# Start auth-service
# Run in a subshell in the background
(
    cd auth-service && ./start-auth-service.sh
) &
AUTH_PID=$!
echo "auth-service started with PID: $AUTH_PID"
echo "Access at: http://localhost:8001"
echo "========================================================"

# Output all running service URLs to a file
URLS_FILE="dev-service-urls.txt"
echo "web-application: http://localhost:3000" > $URLS_FILE
echo "api-gateway: http://localhost:3001" >> $URLS_FILE
echo "ai-service: http://localhost:8000" >> $URLS_FILE
echo "auth-service: http://localhost:8001" >> $URLS_FILE

echo -e "\nAll services are now running in development mode:"
echo "web-application: http://localhost:3000"
echo "api-gateway: http://localhost:3001"
echo "ai-service: http://localhost:8000"
echo "auth-service: http://localhost:8001"
echo "========================================================"
echo "Press Ctrl+C to stop this script and terminate all services."

# Store PIDs for potential cleanup by generating a cleanup script
CLEANUP_SCRIPT="cleanup-dev-services.sh"
echo "#!/bin/bash" > $CLEANUP_SCRIPT
echo "# Auto-generated script to kill dev service processes and remove itself" >> $CLEANUP_SCRIPT
echo "PIDS=($WEB_PID $API_PID $AI_PID $AUTH_PID)" >> $CLEANUP_SCRIPT
echo "for pid in \"\${PIDS[@]}\"; do" >> $CLEANUP_SCRIPT
echo "  if ps -p \$pid > /dev/null 2>&1; then" >> $CLEANUP_SCRIPT
echo "    echo Killing process \$pid..." >> $CLEANUP_SCRIPT
echo "    kill \$pid 2>/dev/null || true" >> $CLEANUP_SCRIPT
echo "  fi" >> $CLEANUP_SCRIPT
echo "done" >> $CLEANUP_SCRIPT
echo "echo All dev service processes stopped." >> $CLEANUP_SCRIPT
echo "rm -- \"\$0\"" >> $CLEANUP_SCRIPT
chmod +x $CLEANUP_SCRIPT

# Function to clean up on exit
cleanup() {
    echo -e "\nShutting down all services..."
    if [ -f $CLEANUP_SCRIPT ]; then
        ./$CLEANUP_SCRIPT
        rm -f $CLEANUP_SCRIPT
    fi
    echo "All services stopped."
    exit 0
}

# Register the cleanup function to be called on exit
trap cleanup EXIT INT TERM

# Wait for all background processes
wait
