#!/bin/bash

# Ubuntu 22.04/24.04 LTS Docker Application Setup Script
# This script addresses common issues when building Docker containers on Ubuntu 24.04

set -e

echo "?? Setting up Docker environment for Ubuntu 22.04/24.04 LTS..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root. Please run as a regular user with sudo privileges."
   exit 1
fi

# Update system packages
print_status "Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker if not already installed
if ! command -v docker &> /dev/null; then
    print_status "Installing Docker..."
    sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io
    sudo usermod -aG docker $USER
    print_warning "You may need to log out and log back in for Docker group membership to take effect"
else
    print_status "Docker is already installed"
fi

# Install Docker Compose if not already installed
if ! command -v docker-compose &> /dev/null; then
    print_status "Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
else
    print_status "Docker Compose is already installed"
fi

# Create necessary directories with proper permissions
print_status "Creating application directories..."
mkdir -p uploads reports rules data logs test-samples templates shared-files

# Set proper ownership for directories (important for Ubuntu 24.04)
print_status "Setting directory permissions..."
sudo chown -R $USER:$USER uploads reports rules data logs test-samples templates shared-files
chmod -R 755 uploads reports rules data logs test-samples templates shared-files

# Create .env file if it doesn't exist
if [[ ! -f .env ]]; then
    print_status "Creating .env file..."
    cat > .env << EOF
# API Keys (replace with your actual keys)
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
HYBRID_ANALYSIS_API_KEY=your_hybrid_analysis_api_key_here
METADEFENDER_API_KEY=your_metadefender_api_key_here

# Security
SECRET_KEY=$(openssl rand -base64 32)

# Python Environment
PIP_BREAK_SYSTEM_PACKAGES=1
PYTHONUNBUFFERED=1
PYTHONDONTWRITEBYTECODE=1
EOF
    print_warning "Don't forget to update your API keys in the .env file!"
else
    print_status ".env file already exists"
fi

# Check for Ubuntu 24.04 specific issues
print_status "Checking for Ubuntu 24.04 compatibility issues..."

# Check AppArmor status
if systemctl is-active --quiet apparmor; then
    print_warning "AppArmor is active. If you encounter permission issues, you may need to disable it temporarily or create custom profiles."
fi

# Check if user namespace remapping is enabled
if grep -q "userns-remap" /etc/docker/daemon.json 2>/dev/null; then
    print_warning "User namespace remapping is enabled in Docker. This may cause permission issues with volumes."
fi

# Create Docker daemon configuration for better compatibility
if [[ ! -f /etc/docker/daemon.json ]]; then
    print_status "Creating Docker daemon configuration..."
    sudo mkdir -p /etc/docker
    sudo cat > /etc/docker/daemon.json << EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "live-restore": true
}
EOF
    print_status "Restarting Docker service..."
    sudo systemctl restart docker
fi

# Test Docker installation
print_status "Testing Docker installation..."
if docker run --rm hello-world > /dev/null 2>&1; then
    print_status "Docker is working correctly!"
else
    print_error "Docker test failed. Please check your Docker installation."
    exit 1
fi

# Build and start the application
print_status "Building Docker containers..."
if docker-compose build; then
    print_status "Containers built successfully!"
else
    print_error "Container build failed. Check the output above for errors."
    exit 1
fi

print_status "Starting the application..."
if docker-compose up -d; then
    print_status "Application started successfully!"
    print_status "You can access the application at http://localhost:8080"
    print_status "Use 'docker-compose logs -f' to view logs"
    print_status "Use 'docker-compose down' to stop the application"
else
    print_error "Failed to start the application. Check the output above for errors."
    exit 1
fi

echo ""
print_status "? Setup complete! Your malware analysis application should now be running."
print_warning "Remember to:"
print_warning "1. Update your API keys in the .env file"
print_warning "2. Review Docker logs if you encounter any issues"
print_warning "3. Ensure your firewall allows traffic on port 8080"