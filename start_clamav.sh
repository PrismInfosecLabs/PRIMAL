#!/bin/bash

echo "Starting ClamAV microservice..."

# REMOVED: All permission setup - done in Dockerfile now
# No more chown/chmod operations that cause "Operation not permitted"

# Check if ClamAV database exists (read-only check)
echo "Checking ClamAV database..."
if [ -f "/var/lib/clamav/main.cvd" ] || [ -f "/var/lib/clamav/main.cld" ]; then
    echo "ClamAV database found"
else
    echo "ClamAV database not found - this may cause scan failures"
    ls -la /var/lib/clamav/ 2>/dev/null || echo "Cannot access ClamAV database directory"
fi

# Start ClamAV daemon - FIXED approach
echo "Starting ClamAV daemon..."

# Method 1: Try direct start (will use User directive from config)
clamd &
CLAMD_PID=$!

# Alternative method if above fails: try with explicit config
if ! kill -0 $CLAMD_PID 2>/dev/null; then
    echo "Direct start failed, trying with explicit config..."
    clamd --config-file=/etc/clamav/clamd.conf &
    CLAMD_PID=$!
fi

# Wait for ClamAV daemon to start
echo "Waiting for ClamAV daemon to initialize..."
sleep 5

# Function to check if ClamAV is running on port 3310
check_clamav() {
    timeout 2 bash -c "</dev/tcp/localhost/3310" >/dev/null 2>&1
    return $?
}

# Function to check ClamAV with PING (without nc dependency)
ping_clamav() {
    if command -v nc >/dev/null 2>&1; then
        echo "PING" | timeout 5 nc -w 2 localhost 3310 2>/dev/null | grep -q "PONG"
    else
        # Fallback method using bash
        timeout 5 bash -c '
            exec 3<>/dev/tcp/localhost/3310
            echo "PING" >&3
            read response <&3
            exec 3<&-
            echo "$response" | grep -q "PONG"
        ' 2>/dev/null
    fi
    return $?
}

# Wait up to 60 seconds for ClamAV to be ready
WAIT_TIME=0
MAX_WAIT=60

while [ $WAIT_TIME -lt $MAX_WAIT ]; do
    if check_clamav; then
        echo "ClamAV daemon is ready on port 3310"
        
        # Test PING command
        if ping_clamav; then
            echo "ClamAV daemon responds to PING"
        else
            echo "ClamAV daemon port open but doesn't respond to PING"
        fi
        break
    fi
    
    echo "Waiting for ClamAV daemon... ($((WAIT_TIME + 5))/${MAX_WAIT}s)"
    sleep 5
    WAIT_TIME=$((WAIT_TIME + 5))
done

# Check if ClamAV started successfully
if ! check_clamav; then
    echo "ClamAV daemon failed to start within ${MAX_WAIT} seconds"
    echo "Checking ClamAV logs..."
    if [ -f "/var/log/clamav/clamd.log" ]; then
        tail -20 /var/log/clamav/clamd.log 2>/dev/null || echo "Cannot read ClamAV logs"
    else
        echo "No ClamAV logs found"
    fi
    echo "Checking ClamAV process..."
    ps aux | grep clam | grep -v grep || echo "No ClamAV processes found"
    echo "Starting Python service anyway..."
else
    echo "ClamAV daemon started successfully"
fi

# Test ClamAV with EICAR test string
echo "Testing ClamAV with EICAR test..."
EICAR_FILE="/tmp/eicar.txt"
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$EICAR_FILE"

if check_clamav && ping_clamav; then
    if command -v nc >/dev/null 2>&1; then
        TEST_RESULT=$(echo "SCAN $EICAR_FILE" | timeout 10 nc localhost 3310 2>/dev/null)
        if echo "$TEST_RESULT" | grep -q "FOUND"; then
            echo "ClamAV EICAR test successful: $TEST_RESULT"
        else
            echo "ClamAV test scan result: $TEST_RESULT"
        fi
    else
        echo "Testing with clamdscan instead of nc..."
        if command -v clamdscan >/dev/null 2>&1; then
            TEST_RESULT=$(clamdscan --no-summary "$EICAR_FILE" 2>/dev/null)
            if echo "$TEST_RESULT" | grep -q "FOUND"; then
                echo "ClamAV EICAR test successful via clamdscan"
            else
                echo "ClamAV clamdscan test result: $TEST_RESULT"
            fi
        fi
    fi
else
    echo "Cannot test ClamAV - daemon not responding properly"
fi

# Clean up test file
rm -f "$EICAR_FILE"

# Debug info before starting Python service
echo "Final system state:"
echo "Current user: $(whoami)"
echo "Current UID: $(id -u)"
echo "ClamAV processes:"
ps aux | grep clam | grep -v grep || echo "No ClamAV processes visible"
echo "Port check:"
if check_clamav; then
    echo "Port 3310 accessible"
else
    echo "Port 3310 not accessible"
fi

# Add signal handling for graceful shutdown
cleanup() {
    echo "Received shutdown signal..."
    if [ -n "${CLAMD_PID:-}" ] && kill -0 "$CLAMD_PID" 2>/dev/null; then
        echo "Stopping ClamAV daemon..."
        kill -TERM "$CLAMD_PID" 2>/dev/null || true
        wait "$CLAMD_PID" 2>/dev/null || true
    fi
    exit 0
}

trap cleanup SIGTERM SIGINT

# Start Python service
echo "Starting ClamAV microservice API..."
exec python clamav_service.py