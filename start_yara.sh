#!/bin/bash
set -e

echo "Starting YARA service..."

# Check if rules directory exists and is accessible
if [ ! -d "/app/rules" ]; then
    echo "Creating rules directory..."
    mkdir -p /app/rules
fi

echo "Rules directory: $(ls -la /app/rules 2>/dev/null || echo 'empty or not accessible')"

# Set environment variables
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

# Create necessary directories
mkdir -p /app/logs

echo "Current user: $(whoami) (UID: $(id -u))"
echo "Working directory: $(pwd)"
echo "Python path: $PYTHONPATH"

# Start the YARA service
echo "Launching YARA service on port 5001..."
exec python yara_service.py