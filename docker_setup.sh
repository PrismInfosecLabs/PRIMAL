#!/bin/bash

# Docker Diagnostic Script for Ubuntu 24.04 LTS
# This script helps diagnose common Docker and permission issues

echo "?? Docker Environment Diagnostic Tool"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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
else
    print_warn "User is NOT in docker group"
    print_info "To fix: sudo usermod -aG docker $USER"
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
fi

echo ""
print_check "Docker Installation"
echo "==================="

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
fi

# Check Docker Compose
if command -v docker-compose >/dev/null 2>&1; then
    print_pass "Docker Compose (standalone) found"
    print_info "Version: $(docker-compose --version 2>/dev/null || echo "Cannot determine version")"
elif docker compose version >/dev/null 2>&1; then
    print_pass "Docker Compose (plugin) found"
    print_info "Version: $(docker compose version 2>/dev/null || echo "Cannot determine version")"
else
    print_fail "Docker Compose is not installed"
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
    print_info "Try: sudo systemctl start docker"
fi

if systemctl is-enabled --quiet docker 2>/dev/null; then
    print_pass "Docker service is enabled (starts on boot)"
elif sudo systemctl is-enabled --quiet docker 2>/dev/null; then
    print_pass "Docker service is enabled (checked with sudo)"
else
    print_warn "Docker service is not enabled for startup"
    print_info "To enable: sudo systemctl enable docker"
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
REQUIRED_DIRS=("uploads" "reports" "rules" "data" "logs" "shared-files")
for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then
        if [[ -w "$dir" ]]; then
            print_pass "Directory '$dir' exists and is writable"
        else
            print_warn "Directory '$dir' exists but is not writable"
        fi
    else
        print_warn "Directory '$dir' does not exist"
        print_info "Run: mkdir -p $dir && chmod 755 $dir"
    fi
done

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
elif sudo docker pull hello-world:latest >/dev/null 2>&1; then
    print_warn "Can pull images from Docker Hub (with sudo)"
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
echo "====================================="
print_info "Diagnostic complete!"
echo "====================================="

echo ""
print_info "Common solutions for issues found:"
echo ""
echo "?? If Docker works only with sudo:"
echo "   sudo usermod -aG docker \$USER"
echo "   newgrp docker  # or log out and back in"
echo ""
echo "?? If sudo doesn't work:"
echo "   sudo usermod -aG sudo \$USER  # (requires admin)"
echo "   su - \$USER  # refresh session"
echo ""
echo "?? If Docker service isn't running:"
echo "   sudo systemctl start docker"
echo "   sudo systemctl enable docker"
echo ""
echo "?? If you have permission issues with directories:"
echo "   chmod -R 755 uploads reports rules data logs shared-files"
echo ""
echo "?? If AppArmor is causing issues:"
echo "   sudo aa-disable /etc/apparmor.d/docker  # temporary fix"
echo ""

print_info "For more help, run the troubleshooting guide or check Docker documentation."