#!/bin/bash
# File: deploy.sh
set -euo pipefail

# Configuration
SSHONEY_USER="sshoney"
SSHONEY_GROUP="sshoney"
SSHONEY_HOME="/var/lib/sshoney"
CONFIG_DIR="/etc/sshoney"
LOG_DIR="/var/log/sshoney"
REAL_SSH_PORT="${REAL_SSH_PORT:-2222}"
TARPIT_PORT="${TARPIT_PORT:-22}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot detect Linux distribution"
        exit 1
    fi
    log_info "Detected: $PRETTY_NAME"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    case $DISTRO in
        ubuntu|debian)
            apt update
            apt install -y build-essential libc6-dev libcap2-bin netcat-openbsd
        ;;
        centos|rhel|fedora|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                dnf install -y gcc glibc-devel libcap make nmap-ncat
            else
                yum install -y gcc glibc-devel libcap make nmap-ncat
            fi
        ;;
        arch|manjaro)
            pacman -Sy --noconfirm base-devel libcap netcat
        ;;
        opensuse*)
            zypper install -y gcc glibc-devel libcap-progs make netcat-openbsd
        ;;
        *)
            log_warn "Unknown distribution. Please install build tools manually."
        ;;
    esac
}

# Create system user
create_user() {
    log_info "Creating system user and directories..."
    
    if ! id "$SSHONEY_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$SSHONEY_HOME" -c "SSHoney daemon" "$SSHONEY_USER"
    fi
    
    # Create directories
    mkdir -p "$SSHONEY_HOME" "$CONFIG_DIR" "$LOG_DIR"
    chown "$SSHONEY_USER:$SSHONEY_GROUP" "$SSHONEY_HOME" "$LOG_DIR"
    chmod 750 "$SSHONEY_HOME" "$LOG_DIR"
}

# Build and install SSHoney
build_install() {
    log_info "Building and installing SSHoney..."
    
    # Build with security flags
    make clean
    make CFLAGS="-std=c99 -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE" \
    LDFLAGS="-Wl,-z,relro,-z,now -pie"
    
    # Install binary
    install -m 755 sshoney /usr/local/bin/
    
    # Set capabilities for binding to privileged ports
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/sshoney
    
    log_info "SSHoney installed successfully"
}

# Configure SSHoney
configure_sshoney() {
    log_info "Creating SSHoney configuration..."
    
    cat > "$CONFIG_DIR/config" << EOF
# SSHoney Configuration
Port $TARPIT_PORT
Delay 10000
MaxLineLength 32
MaxClients 4096
LogLevel 1
BindFamily 0
EOF
    
    chmod 644 "$CONFIG_DIR/config"
    log_info "Configuration created at $CONFIG_DIR/config"
}

# Install systemd service
install_service() {
    log_info "Installing systemd service..."
    
    # The service file should already be created via the artifact above
    if [[ -f "sshoney.service" ]]; then
        cp sshoney.service /etc/systemd/system/
    else
        log_error "Service file not found"
        exit 1
    fi
    
    systemctl daemon-reload
    systemctl enable sshoney
    log_info "Systemd service installed and enabled"
}

# Configure SSH daemon
configure_ssh() {
    log_info "Configuring SSH daemon..."
    
    # Backup original sshd_config
    if [[ ! -f /etc/ssh/sshd_config.backup ]]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        log_info "SSH config backed up to /etc/ssh/sshd_config.backup"
    fi
    
    # Check if Port is already configured
    if grep -q "^Port $REAL_SSH_PORT" /etc/ssh/sshd_config; then
        log_info "SSH already configured for port $REAL_SSH_PORT"
    else
        # Update SSH port
        sed -i "s/^#*Port 22/Port $REAL_SSH_PORT/" /etc/ssh/sshd_config
        log_info "SSH configured to use port $REAL_SSH_PORT"
        
        # Test SSH config
        if sshd -t; then
            log_info "SSH configuration is valid"
        else
            log_error "SSH configuration is invalid. Restoring backup."
            cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
            exit 1
        fi
    fi
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow "$REAL_SSH_PORT/tcp" comment "SSH"
        ufw allow "$TARPIT_PORT/tcp" comment "SSHoney"
        log_info "UFW rules added"
        elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port="$REAL_SSH_PORT/tcp"
        firewall-cmd --permanent --add-port="$TARPIT_PORT/tcp"
        firewall-cmd --reload
        log_info "Firewalld rules added"
    else
        log_warn "No supported firewall found. Please configure manually."
    fi
}

# Start services
start_services() {
    log_info "Starting services..."
    
    # Start SSHoney
    systemctl start sshoney
    
    # Restart SSH if port changed
    if ! grep -q "^Port $REAL_SSH_PORT" /etc/ssh/sshd_config.backup 2>/dev/null; then
        log_info "Restarting SSH daemon..."
        systemctl restart sshd
    fi
    
    # Check service status
    if systemctl is-active --quiet sshoney; then
        log_info "SSHoney is running"
    else
        log_error "SSHoney failed to start"
        systemctl status sshoney
        exit 1
    fi
}

# Test installation
test_installation() {
    log_info "Testing installation..."
    
    # Test SSH on new port
    if nc -z localhost "$REAL_SSH_PORT"; then
        log_info "SSH is accessible on port $REAL_SSH_PORT"
    else
        log_warn "SSH may not be accessible on port $REAL_SSH_PORT"
    fi
    
    # Test SSHoney
    if nc -z localhost "$TARPIT_PORT"; then
        log_info "SSHoney is accessible on port $TARPIT_PORT"
    else
        log_error "SSHoney is not accessible on port $TARPIT_PORT"
        exit 1
    fi
    
    log_info "Installation test completed"
}

# Print summary
print_summary() {
    log_info "Installation completed successfully!"
    echo
    echo "Summary:"
    echo "  - SSH daemon moved to port: $REAL_SSH_PORT"
    echo "  - SSHoney tarpit on port: $TARPIT_PORT"
    echo "  - Configuration: $CONFIG_DIR/config"
    echo "  - Logs: journalctl -u sshoney"
    echo
    echo "Next steps:"
    echo "  1. Test SSH access on port $REAL_SSH_PORT from another terminal"
    echo "  2. Monitor SSHoney logs: journalctl -f -u sshoney"
    echo "  3. Test the tarpit: ssh user@localhost -p $TARPIT_PORT"
    echo
    log_warn "IMPORTANT: Test SSH access before closing this session!"
}

# Main execution
main() {
    log_info "Starting SSHoney deployment..."
    
    check_root
    detect_distro
    install_dependencies
    create_user
    build_install
    configure_sshoney
    install_service
    configure_ssh
    configure_firewall
    start_services
    test_installation
    print_summary
}

# Script options
case "${1:-install}" in
    install)
        main
    ;;
    uninstall)
        log_info "Uninstalling SSHoney..."
        systemctl stop sshoney || true
        systemctl disable sshoney || true
        rm -f /etc/systemd/system/sshoney.service
        rm -f /usr/local/bin/sshoney
        rm -rf "$CONFIG_DIR" "$LOG_DIR" "$SSHONEY_HOME"
        userdel "$SSHONEY_USER" || true
        systemctl daemon-reload
        log_info "SSHoney uninstalled"
    ;;
    *)
        echo "Usage: $0 [install|uninstall]"
        exit 1
    ;;
esac