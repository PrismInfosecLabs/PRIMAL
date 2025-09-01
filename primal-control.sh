#!/bin/bash

# PRIMAL Malware Analysis Lab Control Script
# Usage: ./primal-control.sh {start|stop|restart|status|logs|update}

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
PROJECT_NAME="malware-lab"
LOGFILE="${SCRIPT_DIR}/logs/control.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOGFILE"
    echo -e "$1"
}

# Error handling
error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

# Check dependencies
check_dependencies() {
    if ! command -v docker &> /dev/null; then
        error_exit "Docker is not installed or not in PATH"
    fi
    
    if ! command -v docker compose &> /dev/null; then
        error_exit "Docker Compose is not installed or not in PATH"
    fi
    
    if [ ! -f "$COMPOSE_FILE" ]; then
        error_exit "Docker Compose file not found: $COMPOSE_FILE"
    fi
}

# Create necessary directories
setup_directories() {
    local dirs=("logs" "data" "uploads" "reports" "rules")
    for dir in "${dirs[@]}"; do
        if [ ! -d "${SCRIPT_DIR}/${dir}" ]; then
            log "${BLUE}Creating directory: ${dir}${NC}"
            mkdir -p "${SCRIPT_DIR}/${dir}"
        fi
    done
}

# Check if services are running
check_status() {
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" ps
}

# Get service health
get_health() {
    local orchestrator_status=$(docker-compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" ps -q orchestrator | xargs docker inspect --format='{{.State.Status}}' 2>/dev/null || echo "not running")
    local clamav_status=$(docker-compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" ps -q clamav-scanner | xargs docker inspect --format='{{.State.Status}}' 2>/dev/null || echo "not running")
    local yara_status=$(docker-compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" ps -q yara-scanner | xargs docker inspect --format='{{.State.Status}}' 2>/dev/null || echo "not running")
    
    echo "Service Status:"
    echo "  Orchestrator: $orchestrator_status"
    echo "  ClamAV:       $clamav_status"
    echo "  YARA:         $yara_status"
    
    if [[ "$orchestrator_status" == "running" && "$clamav_status" == "running" && "$yara_status" == "running" ]]; then
        return 0
    else
        return 1
    fi
}

# Start services
start_services() {
    log "${BLUE}Starting PRIMAL Malware Analysis Lab...${NC}"
    
    setup_directories
    
    # Pull latest images if needed
    log "${BLUE}Pulling latest container images...${NC}"
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" pull
    
    # Start services
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d
    
    # Wait for services to be ready
    log "${BLUE}Waiting for services to start...${NC}"
    sleep 10
    
    if get_health > /dev/null; then
        log "${GREEN}All services started successfully!${NC}"
        echo ""
        echo "Access the application at: http://localhost:8080"
        echo "Container management: http://localhost:8080/containers"
        echo ""
    else
        log "${YELLOW}Some services may not be fully ready yet. Check status with: $0 status${NC}"
    fi
}

# Stop services
stop_services() {
    log "${BLUE}Stopping PRIMAL Malware Analysis Lab...${NC}"
    
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" down
    
    log "${GREEN}All services stopped.${NC}"
}

# Restart services
restart_services() {
    log "${BLUE}Restarting PRIMAL Malware Analysis Lab...${NC}"
    stop_services
    sleep 3
    start_services
}

# Show logs
show_logs() {
    local service=${2:-}
    
    if [ -n "$service" ]; then
        log "${BLUE}Showing logs for service: $service${NC}"
        docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" logs -f "$service"
    else
        log "${BLUE}Showing logs for all services (press Ctrl+C to exit)${NC}"
        docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" logs -f
    fi
}

# Update application
update_application() {
    log "${BLUE}Updating PRIMAL Malware Analysis Lab...${NC}"
    
    # Stop services
    stop_services
    
    # Pull latest images
    log "${BLUE}Pulling latest container images...${NC}"
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" pull
    
    # Remove old containers
    log "${BLUE}Removing old containers...${NC}"
    docker compose -f "$COMPOSE_FILE" -p "$PROJECT_NAME" rm -f
    
    # Start services
    start_services
    
    log "${GREEN}Update completed!${NC}"
}

# Show usage
show_usage() {
    echo "PRIMAL Malware Analysis Lab Control Script"
    echo ""
    echo "Usage: $0 {start|stop|restart|status|logs|update|health}"
    echo ""
    echo "Commands:"
    echo "  start    - Start all services"
    echo "  stop     - Stop all services"
    echo "  restart  - Restart all services"
    echo "  status   - Show service status"
    echo "  logs     - Show logs (add service name for specific service)"
    echo "  update   - Update and restart all services"
    echo "  health   - Check service health"
    echo ""
    echo "Examples:"
    echo "  $0 start"
    echo "  $0 logs orchestrator"
    echo "  $0 status"
}

# Main execution
main() {
    # Ensure log directory exists
    mkdir -p "$(dirname "$LOGFILE")"
    
    # Check dependencies
    check_dependencies
    
    case "${1:-}" in
        start)
            start_services
            ;;
        stop)
            stop_services
            ;;
        restart)
            restart_services
            ;;
        status)
            check_status
            ;;
        logs)
            show_logs "$@"
            ;;
        update)
            update_application
            ;;
        health)
            if get_health; then
                log "${GREEN}All services are healthy${NC}"
                exit 0
            else
                log "${RED}Some services are not healthy${NC}"
                exit 1
            fi
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"