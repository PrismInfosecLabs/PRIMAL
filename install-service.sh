#!/bin/bash

# PRIMAL Malware Analysis Lab Service Installer
# Usage: sudo ./install-service.sh {install|uninstall|status}

set -e

# Configuration
SERVICE_NAME="PRIMAL"
SERVICE_DESCRIPTION="PRIMAL Malware Analysis Lab"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
CONTROL_SCRIPT="${SCRIPT_DIR}/primal-control.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root (use sudo)${NC}"
        exit 1
    fi
}

# Check dependencies
check_dependencies() {
    if ! command -v systemctl &> /dev/null; then
        echo -e "${RED}systemctl not found. This system doesn't appear to use systemd.${NC}"
        exit 1
    fi
    
    if [ ! -f "$CONTROL_SCRIPT" ]; then
        echo -e "${RED}Control script not found: $CONTROL_SCRIPT${NC}"
        echo "Please ensure you're running this script from the application directory."
        exit 1
    fi
}

# Get the user who should own the service
get_service_user() {
    # If sudo was used, get the original user
    if [ -n "$SUDO_USER" ]; then
        echo "$SUDO_USER"
    else
        echo "root"
    fi
}

# Create systemd service file
create_service_file() {
    local service_user=$(get_service_user)
    local user_home=$(getent passwd "$service_user" | cut -d: -f6)
    
    echo -e "${BLUE}Creating systemd service file...${NC}"
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=$SERVICE_DESCRIPTION
Documentation=https://github.com/PrismInfosecLabs/PRIMAL
After=docker.service
Requires=docker.service
StartLimitIntervalSec=0

[Service]
Type=forking
RemainAfterExit=yes
User=$service_user
Group=$service_user
WorkingDirectory=$SCRIPT_DIR
Environment=HOME=$user_home
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Start command
ExecStart=$CONTROL_SCRIPT start

# Stop command  
ExecStop=$CONTROL_SCRIPT stop

# Reload command
ExecReload=$CONTROL_SCRIPT restart

# Health check
ExecStartPost=/bin/sleep 15
ExecStartPost=$CONTROL_SCRIPT health

# Restart policy
Restart=on-failure
RestartSec=30
StartLimitBurst=3

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$SCRIPT_DIR

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF

    echo -e "${GREEN}Service file created: $SERVICE_FILE${NC}"
}

# Install service
install_service() {
    echo -e "${BLUE}Installing $SERVICE_DESCRIPTION as a system service...${NC}"
    
    # Create service file
    create_service_file
    
    # Make control script executable
    chmod +x "$CONTROL_SCRIPT"
    
    # Set proper ownership
    local service_user=$(get_service_user)
    chown -R "$service_user:$service_user" "$SCRIPT_DIR"
    
    # Reload systemd
    echo -e "${BLUE}Reloading systemd daemon...${NC}"
    systemctl daemon-reload
    
    # Enable service
    echo -e "${BLUE}Enabling $SERVICE_NAME service...${NC}"
    systemctl enable "$SERVICE_NAME"
    
    echo -e "${GREEN}Service installed successfully!${NC}"
    echo ""
    echo "Service management commands:"
    echo "  sudo systemctl start $SERVICE_NAME     - Start the service"
    echo "  sudo systemctl stop $SERVICE_NAME      - Stop the service" 
    echo "  sudo systemctl restart $SERVICE_NAME   - Restart the service"
    echo "  sudo systemctl status $SERVICE_NAME    - Check service status"
    echo "  sudo systemctl enable $SERVICE_NAME    - Enable auto-start on boot"
    echo "  sudo systemctl disable $SERVICE_NAME   - Disable auto-start on boot"
    echo "  sudo journalctl -u $SERVICE_NAME -f    - View service logs"
    echo ""
    echo "To start the service now, run:"
    echo "  sudo systemctl start $SERVICE_NAME"
}

# Uninstall service  
uninstall_service() {
    echo -e "${BLUE}Uninstalling $SERVICE_DESCRIPTION service...${NC}"
    
    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo -e "${BLUE}Stopping $SERVICE_NAME service...${NC}"
        systemctl stop "$SERVICE_NAME"
    fi
    
    # Disable service
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        echo -e "${BLUE}Disabling $SERVICE_NAME service...${NC}"
        systemctl disable "$SERVICE_NAME"
    fi
    
    # Remove service file
    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${BLUE}Removing service file...${NC}"
        rm -f "$SERVICE_FILE"
    fi
    
    # Reload systemd
    systemctl daemon-reload
    systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
    
    echo -e "${GREEN}Service uninstalled successfully!${NC}"
}

# Show service status
show_status() {
    if [ -f "$SERVICE_FILE" ]; then
        echo -e "${BLUE}Service Status:${NC}"
        systemctl status "$SERVICE_NAME" --no-pager
        echo ""
        echo -e "${BLUE}Service Information:${NC}"
        echo "Service file: $SERVICE_FILE"
        echo "Control script: $CONTROL_SCRIPT"
        echo "Enabled: $(systemctl is-enabled $SERVICE_NAME 2>/dev/null || echo 'not installed')"
        echo "Active: $(systemctl is-active $SERVICE_NAME 2>/dev/null || echo 'inactive')"
    else
        echo -e "${YELLOW}Service is not installed.${NC}"
        echo "Run 'sudo $0 install' to install the service."
    fi
}

# Create logrotate configuration
create_logrotate() {
    local logrotate_file="/etc/logrotate.d/$SERVICE_NAME"
    
    echo -e "${BLUE}Creating logrotate configuration...${NC}"
    
    cat > "$logrotate_file" << EOF
$SCRIPT_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $(get_service_user) $(get_service_user)
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}
EOF

    echo -e "${GREEN}Logrotate configuration created: $logrotate_file${NC}"
}

# Setup firewall rules (optional)
setup_firewall() {
    if command -v ufw &> /dev/null; then
        echo -e "${BLUE}Setting up UFW firewall rules...${NC}"
        ufw allow 8080/tcp comment "PRIMAL Malware Lab"
        echo -e "${GREEN}Firewall rule added for port 8080${NC}"
    elif command -v firewall-cmd &> /dev/null; then
        echo -e "${BLUE}Setting up firewalld rules...${NC}"
        firewall-cmd --permanent --add-port=8080/tcp
        firewall-cmd --reload
        echo -e "${GREEN}Firewall rule added for port 8080${NC}"
    else
        echo -e "${YELLOW}No supported firewall found. Please manually allow port 8080 if needed.${NC}"
    fi
}

# Show usage
show_usage() {
    echo "PRIMAL Malware Analysis Lab Service Installer"
    echo ""
    echo "Usage: sudo $0 {install|uninstall|status|logs}"
    echo ""
    echo "Commands:"
    echo "  install    - Install the service and enable it"
    echo "  uninstall  - Stop and remove the service"
    echo "  status     - Show current service status"
    echo "  logs       - Show recent service logs"
    echo ""
    echo "After installation, use standard systemctl commands:"
    echo "  sudo systemctl start $SERVICE_NAME"
    echo "  sudo systemctl stop $SERVICE_NAME"
    echo "  sudo systemctl restart $SERVICE_NAME"
    echo "  sudo systemctl status $SERVICE_NAME"
    echo ""
    echo "Note: This script must be run with sudo privileges."
}

# Show recent logs
show_logs() {
    if systemctl list-units --full -all | grep -Fq "$SERVICE_NAME.service"; then
        echo -e "${BLUE}Recent logs for $SERVICE_NAME:${NC}"
        journalctl -u "$SERVICE_NAME" -n 50 --no-pager
    else
        echo -e "${YELLOW}Service is not installed or no logs available.${NC}"
    fi
}

# Main execution
main() {
    case "${1:-}" in
        install)
            check_root
            check_dependencies
            install_service
            create_logrotate
            echo ""
            read -p "Do you want to set up firewall rules for port 8080? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                setup_firewall
            fi
            echo ""
            echo -e "${GREEN}Installation complete!${NC}"
            echo "The service is installed but not started. To start it:"
            echo "  sudo systemctl start $SERVICE_NAME"
            ;;
        uninstall)
            check_root
            uninstall_service
            # Remove logrotate config
            rm -f "/etc/logrotate.d/$SERVICE_NAME"
            ;;
        status)
            check_root
            show_status
            ;;
        logs)
            check_root
            show_logs
            ;;
        *)
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
