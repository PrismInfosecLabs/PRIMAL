#!/bin/bash

# Docker Installation & Diagnostic Script for Ubuntu 24.04 LTS
# This script helps diagnose and fix common Docker and permission issues

echo "🐳 Docker Environment Setup & Diagnostic Tool"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

print_check() {
    echo -e "${CYAN}[CHECK]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_action() {
    echo -e "${PURPLE}[ACTION]${NC} $1"
}

# Function to install Docker Compose (standalone version)
install_docker_compose() {
    print_action "Installing Docker Compose (standalone version)..."
    
    # Get the latest version
    DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
    
    if [[ -z "$DOCKER_COMPOSE_VERSION" ]]; then
        print_warn "Could not fetch latest Docker Compose version from GitHub"
        # Use a known stable version as fallback
        DOCKER_COMPOSE_VERSION="v2.24.0"
        print_info "Using fallback version: $DOCKER_COMPOSE_VERSION"
    fi
    
    print_info "Installing standalone Docker Compose $DOCKER_COMPOSE_VERSION"
    
    # Download the standalone binary
    DOCKER_COMPOSE_URL="https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-$(uname -s)-$(uname -m)"
    
    print_info "Downloading from: $DOCKER_COMPOSE_URL"
    
    if curl -L "$DOCKER_COMPOSE_URL" -o /tmp/docker-compose; then
        # Install the binary
        sudo install /tmp/docker-compose /usr/local/bin/docker-compose
        
        # Clean up temp file
        rm /tmp/docker-compose
        
        # Verify installation
        if command -v docker-compose >/dev/null 2>&1; then
            print_pass "Docker Compose (standalone) installed successfully"
            print_info "Version: $(docker-compose --version)"
            print_info "Location: $(which docker-compose)"
            
            # Test basic functionality
            if docker-compose --version >/dev/null 2>&1; then
                print_pass "Docker Compose is working correctly"
            else
                print_warn "Docker Compose installed but may have issues"
            fi
            
            return 0
        else
            print_fail "Docker Compose installation failed - binary not found in PATH"
            print_info "You may need to add /usr/local/bin to your PATH"
            return 1
        fi
    else
        print_fail "Failed to download Docker Compose binary"
        print_info "You can manually download from: https://github.com/docker/compose/releases"
        return 1
    fi
}

# Function to install Docker
install_docker() {
    print_action "Installing Docker..."
    
    # Update package index
    sudo apt update
    
    # Install prerequisites
    sudo apt install -y ca-certificates curl gnupg lsb-release
    
    # Add Docker's official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    
    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Update package index again
    sudo apt update
    
    # Install Docker
    if sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin; then
        print_pass "Docker installed successfully"
        
        # Start and enable Docker service
        sudo systemctl start docker
        sudo systemctl enable docker
        
        return 0
    else
        print_fail "Docker installation failed"
        return 1
    fi
}

echo ""
print_check "System Information"
echo "=================="
print_info "OS: $(lsb_release -d 2>/dev/null | cut -f2 || uname -o)"
print_info "Kernel: $(uname -r)"
print_info "Architecture: $(uname -m)"
print_info "Current User: $USER (UID: $(id -u), GID: $(id -g))"
print_info "Home Directory: $HOME"
print_info "Current Directory: $(pwd)"

echo ""
print_check "User Permissions and Groups"
echo "============================"
print_info "User Groups: $(groups $USER)"

# Check if user is in sudo group
if groups "$USER" | grep -q sudo; then
    print_pass "User is in sudo group"
else
    print_fail "User is NOT in sudo group"
    print_info "To fix: sudo usermod -aG sudo $USER (requires admin privileges)"
fi

# Check if user is in docker group
if groups "$USER" | grep -q docker; then
    print_pass "User is in docker group"
    DOCKER_GROUP_OK=true
else
    print_warn "User is NOT in docker group"
    print_info "Will fix this after Docker installation/verification"
    DOCKER_GROUP_OK=false
fi

echo ""
print_check "Sudo Access Test"
echo "================"

# Test sudo access
if sudo -n true 2>/dev/null; then
    print_pass "Sudo access available (cached credentials)"
elif sudo -v 2>/dev/null; then
    print_pass "Sudo access available (after password prompt)"
else
    print_fail "Cannot access sudo"
    print_info "This could mean:"
    print_info "1. User is not in sudoers file"
    print_info "2. Wrong password"
    print_info "3. Account locked"
    exit 1
fi

echo ""
print_check "Docker Installation"
echo "==================="

DOCKER_NEEDS_INSTALL=false

# Check Docker installation
if command -v docker >/dev/null 2>&1; then
    print_pass "Docker command found"
    print_info "Version: $(docker --version 2>/dev/null || echo "Cannot determine version")"
    
    # Check Docker daemon
    if docker info >/dev/null 2>&1; then
        print_pass "Docker daemon is accessible"
    elif sudo docker info >/dev/null 2>&1; then
        print_warn "Docker daemon accessible only with sudo"
        print_info "This suggests permission issues - user may not be in docker group"
    else
        print_fail "Docker daemon is not accessible"
        print_info "Docker service may not be running"
    fi
else
    print_fail "Docker is not installed"
    DOCKER_NEEDS_INSTALL=true
fi

# Install Docker if needed
if $DOCKER_NEEDS_INSTALL; then
    read -p "Docker is not installed. Would you like to install it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_docker
    else
        print_warn "Skipping Docker installation"
    fi
fi

# Check Docker Compose (prioritize standalone version)
COMPOSE_NEEDS_INSTALL=false

if command -v docker-compose >/dev/null 2>&1; then
    print_pass "Docker Compose (standalone) found"
    print_info "Version: $(docker-compose --version 2>/dev/null || echo "Cannot determine version")"
    print_info "Location: $(which docker-compose)"
elif docker compose version >/dev/null 2>&1; then
    print_warn "Docker Compose (plugin) found, but standalone version preferred"
    print_info "Plugin Version: $(docker compose version 2>/dev/null || echo "Cannot determine version")"
    print_info "Consider installing standalone version for consistency"
else
    print_fail "Docker Compose is not installed"
    COMPOSE_NEEDS_INSTALL=true
fi

# Install Docker Compose if needed
if $COMPOSE_NEEDS_INSTALL; then
    read -p "Docker Compose (standalone) is not installed. Would you like to install it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_docker_compose
    else
        print_warn "Skipping Docker Compose installation"
    fi
fi

echo ""
print_check "Docker Service Status"
echo "====================="

if systemctl is-active --quiet docker 2>/dev/null; then
    print_pass "Docker service is running"
elif sudo systemctl is-active --quiet docker 2>/dev/null; then
    print_pass "Docker service is running (checked with sudo)"
else
    print_fail "Docker service is not running"
    print_action "Starting Docker service..."
    if sudo systemctl start docker; then
        print_pass "Docker service started successfully"
    else
        print_fail "Failed to start Docker service"
    fi
fi

if systemctl is-enabled --quiet docker 2>/dev/null; then
    print_pass "Docker service is enabled (starts on boot)"
elif sudo systemctl is-enabled --quiet docker 2>/dev/null; then
    print_pass "Docker service is enabled (checked with sudo)"
else
    print_warn "Docker service is not enabled for startup"
    print_action "Enabling Docker service for startup..."
    if sudo systemctl enable docker; then
        print_pass "Docker service enabled successfully"
    else
        print_fail "Failed to enable Docker service"
    fi
fi

# Fix Docker group membership
if ! $DOCKER_GROUP_OK && command -v docker >/dev/null 2>&1; then
    print_action "Adding user to docker group..."
    if sudo usermod -aG docker "$USER"; then
        print_pass "User added to docker group"
        print_warn "You need to log out and back in (or restart) for group changes to take effect"
        print_info "Alternatively, run: newgrp docker"
    else
        print_fail "Failed to add user to docker group"
    fi
fi

echo ""
print_check "Docker Functionality Test"
echo "=========================="

# Test Docker functionality
if docker run --rm hello-world >/dev/null 2>&1; then
    print_pass "Docker works without sudo"
elif sudo docker run --rm hello-world >/dev/null 2>&1; then
    print_warn "Docker works only with sudo"
    print_info "User needs to be added to docker group and may need to log out/in"
else
    print_fail "Docker hello-world test failed"
    print_info "Docker installation may be broken"
fi

echo ""
print_check "File System Permissions"
echo "======================="

# Check current directory permissions
if [[ -w . ]]; then
    print_pass "Current directory is writable"
else
    print_fail "Current directory is not writable"
fi

# Check for project files
if [[ -f "docker-compose.yml" ]]; then
    print_pass "docker-compose.yml found"
    if [[ -r "docker-compose.yml" ]]; then
        print_pass "docker-compose.yml is readable"
    else
        print_fail "docker-compose.yml is not readable"
    fi
else
    print_warn "docker-compose.yml not found"
    print_info "Make sure you're in the project directory"
fi

# Check required directories
REQUIRED_DIRS=("uploads" "reports" "rules" "data" "logs")
MISSING_DIRS=()

for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        if [[ -w "$dir" ]]; then
            print_pass "Directory '$dir' exists and is writable"
        else
            print_warn "Directory '$dir' exists but is not writable"
            print_action "Fixing permissions for '$dir'..."
            chmod 755 "$dir" 2>/dev/null || sudo chmod 755 "$dir"
        fi
    else
        print_warn "Directory '$dir' does not exist"
        MISSING_DIRS+=("$dir")
    fi
done

# Create missing directories
if [[ ${#MISSING_DIRS[@]} -gt 0 ]]; then
    print_action "Creating missing directories: ${MISSING_DIRS[*]}"
    if mkdir -p "${MISSING_DIRS[@]}" && chmod 755 "${MISSING_DIRS[@]}"; then
        print_pass "Created missing directories successfully"
    else
        print_fail "Failed to create some directories"
    fi
fi

echo ""
print_check "Network Connectivity"
echo "===================="

# Test internet connectivity
if ping -c 1 google.com >/dev/null 2>&1; then
    print_pass "Internet connectivity working"
elif ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    print_pass "Internet connectivity working (DNS may have issues)"
else
    print_fail "No internet connectivity"
    print_info "Check your network connection"
fi

# Test Docker Hub connectivity
if docker pull hello-world:latest >/dev/null 2>&1; then
    print_pass "Can pull images from Docker Hub"
    docker rmi hello-world:latest >/dev/null 2>&1  # Clean up
elif sudo docker pull hello-world:latest >/dev/null 2>&1; then
    print_warn "Can pull images from Docker Hub (with sudo)"
    sudo docker rmi hello-world:latest >/dev/null 2>&1  # Clean up
else
    print_fail "Cannot pull images from Docker Hub"
    print_info "This could be a network or Docker daemon issue"
fi

echo ""
print_check "Security Settings"
echo "================="

# Check AppArmor
if command -v aa-status >/dev/null 2>&1; then
    if sudo aa-status >/dev/null 2>&1; then
        APPARMOR_PROFILES=$(sudo aa-status 2>/dev/null | grep "profiles are in enforce mode" | cut -d' ' -f1)
        print_info "AppArmor is active with $APPARMOR_PROFILES profiles"
        if sudo aa-status | grep -q docker; then
            print_warn "Docker-related AppArmor profiles detected"
            print_info "This might cause permission issues in containers"
        fi
    else
        print_info "AppArmor is installed but status unknown"
    fi
else
    print_info "AppArmor is not installed"
fi

# Check SELinux (less common on Ubuntu but worth checking)
if command -v getenforce >/dev/null 2>&1; then
    SELINUX_STATUS=$(getenforce 2>/dev/null || echo "Unknown")
    print_info "SELinux status: $SELINUX_STATUS"
else
    print_info "SELinux is not installed"
fi

echo ""
echo "============================================="
print_info "Setup and diagnostic complete!"
echo "============================================="

echo ""
print_info "Summary of actions taken:"
echo ""
echo "📋 Common solutions for any remaining issues:"
echo ""
echo "• If Docker works only with sudo:"
echo "   sudo usermod -aG docker \$USER"
echo "   newgrp docker  # or log out and back in"
echo ""
echo "• If sudo doesn't work:"
echo "   sudo usermod -aG sudo \$USER  # (requires admin)"
echo "   su - \$USER  # refresh session"
echo ""
echo "• If Docker service isn't running:"
echo "   sudo systemctl start docker"
echo "   sudo systemctl enable docker"
echo ""
echo "• If you have permission issues with directories:"
echo "   chmod -R 755 uploads reports rules data logs shared-files"
echo ""
echo "• If AppArmor is causing issues:"
echo "   sudo aa-disable /etc/apparmor.d/docker  # temporary fix"
echo ""
echo "• To test your setup:"
echo "   docker run --rm hello-world"
echo "   docker-compose --version"
echo ""

print_info "🚀 Your Docker environment should now be ready to use!"
print_warn "Remember to log out and back in if you were added to the docker group."
print_info "Use 'docker-compose' command for managing multi-container applications."