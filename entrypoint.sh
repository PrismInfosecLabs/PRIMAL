#!/bin/bash
set -e

echo "Starting orchestrator..."

# Simple directory existence check - no permission changes
REQUIRED_DIRS=(
    "/app/uploads"
    "/app/reports" 
    "/app/rules"
    "/app/data"
    "/app/logs"
    "/app/shared-files"
)

for dir in "${REQUIRED_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "Directory $dir exists"
    else
        echo "Creating directory: $dir"
        mkdir -p "$dir" 2>/dev/null || echo "Cannot create $dir (may be normal)"
    fi
done

echo "Current user: $(whoami) (UID: $(id -u))"
echo "Starting application..."

# Execute the main command
exec "$@"