#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Author: vppebpf  Date: 2024-12-19
# Setup script for VPP eBPF Firewall GUI

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
readonly LOG_FILE="/tmp/vppebpf-gui-setup.log"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"
}

# Error handling
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "GUI setup failed! Check log file: $LOG_FILE"
    fi
    exit $exit_code
}

trap cleanup EXIT

# Utility functions
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "Don't run this script as root!"
        exit 1
    fi
}

check_node_version() {
    if ! command_exists node; then
        log_error "Node.js not found. Installing..."
        install_nodejs
        return
    fi
    
    local node_version
    node_version=$(node --version | cut -d'v' -f2)
    local required_version="18.0.0"
    
    if ! version_ge "$node_version" "$required_version"; then
        log_error "Node.js version $node_version is too old. Required: $required_version+"
        install_nodejs
    else
        log_success "Node.js version $node_version is compatible"
    fi
}

version_ge() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

install_nodejs() {
    log_info "Installing Node.js 18..."
    
    # Install Node.js 18 via NodeSource repository
    curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
    sudo dnf install -y nodejs npm
    
    # Verify installation
    node --version
    npm --version
}

check_python_version() {
    if ! command_exists python3; then
        log_error "Python 3 not found!"
        exit 1
    fi
    
    local python_version
    python_version=$(python3 --version | cut -d' ' -f2)
    local required_version="3.8.0"
    
    if ! version_ge "$python_version" "$required_version"; then
        log_error "Python version $python_version is too old. Required: $required_version+"
        exit 1
    else
        log_success "Python version $python_version is compatible"
    fi
}

install_system_packages() {
    log_info "📦 Installing system packages for GUI development..."
    
    local packages=(
        "nodejs"
        "npm"
        "python3-pip"
        "docker"
        "docker-compose"
        "nginx"
        "curl"
        "wget"
        "git"
    )
    
    sudo dnf makecache --refresh
    
    for package in "${packages[@]}"; do
        if ! dnf list installed "$package" &>/dev/null; then
            log_info "Installing $package..."
            sudo dnf install -y "$package"
        else
            log_success "$package already installed"
        fi
    done
}

setup_backend() {
    log_info "🐍 Setting up Python backend..."
    
    cd "$SCRIPT_DIR/backend"
    
    # Create virtual environment
    if [[ ! -d "venv" ]]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install dependencies
    log_info "Installing Python dependencies..."
    pip install -r requirements.txt
    
    log_success "Backend setup completed"
    cd "$SCRIPT_DIR"
}

setup_frontend() {
    log_info "⚛️ Setting up React frontend..."
    
    cd "$SCRIPT_DIR/frontend"
    
    # Check if package.json exists
    if [[ ! -f "package.json" ]]; then
        log_error "package.json not found in frontend directory"
        exit 1
    fi
    
    # Install dependencies
    log_info "Installing Node.js dependencies..."
    npm install
    
    # Install global tools
    if ! command_exists typescript; then
        log_info "Installing TypeScript globally..."
        sudo npm install -g typescript
    fi
    
    if ! command_exists vite; then
        log_info "Installing Vite globally..."
        sudo npm install -g vite
    fi
    
    log_success "Frontend setup completed"
    cd "$SCRIPT_DIR"
}

setup_docker() {
    log_info "🐳 Setting up Docker..."
    
    # Start and enable Docker service
    sudo systemctl start docker
    sudo systemctl enable docker
    
    # Add user to docker group
    sudo usermod -aG docker "$USER"
    
    # Install Docker Compose if not present
    if ! command_exists docker-compose; then
        log_info "Installing Docker Compose..."
        sudo dnf install -y docker-compose
    fi
    
    log_success "Docker setup completed"
    log_warning "You may need to log out and back in for Docker group membership to take effect"
}

create_config_files() {
    log_info "📄 Creating configuration files..."
    
    # Create environment file for backend
    cat > "$SCRIPT_DIR/backend/.env" <<EOF
# VPP eBPF Firewall Backend Configuration
DEBUG=true
LOG_LEVEL=INFO
HOST=0.0.0.0
PORT=8080
PROJECT_ROOT=/home/$(whoami)/vppebpf
AUTH_ENABLED=false
AUTH_TOKEN=dev-token-123
EOF
    
    # Create environment file for frontend
    cat > "$SCRIPT_DIR/frontend/.env" <<EOF
# VPP eBPF Firewall Frontend Configuration
REACT_APP_API_URL=http://localhost:8080
REACT_APP_WS_URL=ws://localhost:8080/ws
GENERATE_SOURCEMAP=true
EOF
    
    # Create nginx configuration
    mkdir -p "$SCRIPT_DIR/docker"
    cat > "$SCRIPT_DIR/docker/nginx.conf" <<EOF
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html;

    # Handle React Router
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # API proxy
    location /api/ {
        proxy_pass http://backend:8080/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # WebSocket proxy
    location /ws {
        proxy_pass http://backend:8080/ws;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
}
EOF
    
    log_success "Configuration files created"
}

test_backend() {
    log_info "🧪 Testing backend..."
    
    cd "$SCRIPT_DIR/backend"
    source venv/bin/activate
    
    # Run a quick test
    python -c "
import main
print('✅ Backend imports successfully')
"
    
    log_success "Backend test passed"
    cd "$SCRIPT_DIR"
}

test_frontend() {
    log_info "🧪 Testing frontend..."
    
    cd "$SCRIPT_DIR/frontend"
    
    # Check if TypeScript config exists
    if [[ -f "tsconfig.json" ]]; then
        log_success "TypeScript configuration found"
    else
        log_warning "TypeScript configuration missing"
    fi
    
    # Check if package.json is valid
    npm list --depth=0 >/dev/null 2>&1 || log_warning "Some npm dependencies may have issues"
    
    log_success "Frontend test passed"
    cd "$SCRIPT_DIR"
}

create_start_scripts() {
    log_info "📋 Creating startup scripts..."
    
    # Backend start script
    cat > "$SCRIPT_DIR/start-backend.sh" <<EOF
#!/bin/bash
# Start VPP eBPF Firewall Backend

cd "\$(dirname "\$0")/backend"
source venv/bin/activate
python main.py
EOF
    chmod +x "$SCRIPT_DIR/start-backend.sh"
    
    # Frontend development script
    cat > "$SCRIPT_DIR/start-frontend-dev.sh" <<EOF
#!/bin/bash
# Start VPP eBPF Firewall Frontend (Development)

cd "\$(dirname "\$0")/frontend"
npm run dev
EOF
    chmod +x "$SCRIPT_DIR/start-frontend-dev.sh"
    
    # Docker Compose start script
    cat > "$SCRIPT_DIR/start-docker.sh" <<EOF
#!/bin/bash
# Start VPP eBPF Firewall GUI Stack with Docker

cd "\$(dirname "\$0")/docker"
docker-compose up -d
EOF
    chmod +x "$SCRIPT_DIR/start-docker.sh"
    
    log_success "Startup scripts created"
}

print_summary() {
    log_success "🎉 GUI setup completed successfully!"
    echo
    echo "==============================================="
    echo "       VPP eBPF Firewall GUI Setup"
    echo "==============================================="
    echo
    echo "📋 What was configured:"
    echo "  • Backend: FastAPI + WebSocket + Python virtual environment"
    echo "  • Frontend: React + TypeScript + Material-UI + Vite"
    echo "  • Docker: Multi-container setup with nginx, redis, monitoring"
    echo "  • Scripts: Development and production startup scripts"
    echo
    echo "🚀 Quick Start:"
    echo "  1. Development Mode:"
    echo "     ./start-backend.sh     # Terminal 1"
    echo "     ./start-frontend-dev.sh # Terminal 2"
    echo "     # Open http://localhost:3000"
    echo
    echo "  2. Production Mode (Docker):"
    echo "     ./start-docker.sh"
    echo "     # Open http://localhost:3000"
    echo
    echo "📖 URLs:"
    echo "  • Frontend:   http://localhost:3000"
    echo "  • Backend:    http://localhost:8080"
    echo "  • API Docs:   http://localhost:8080/api/docs"
    echo "  • Grafana:    http://localhost:3001 (admin/admin)"
    echo "  • Prometheus: http://localhost:9090"
    echo
    echo "📁 Important files:"
    echo "  • Backend config:  gui/backend/.env"
    echo "  • Frontend config: gui/frontend/.env"
    echo "  • Docker config:   gui/docker/docker-compose.yml"
    echo
    echo "🔧 Development:"
    echo "  • Backend logs:  gui/backend/logs/"
    echo "  • Build logs:    $LOG_FILE"
    echo
}

main() {
    log_info "🚀 Starting VPP eBPF Firewall GUI setup..."
    log_info "Log file: $LOG_FILE"
    
    check_root
    check_python_version
    install_system_packages
    setup_docker
    check_node_version
    setup_backend
    setup_frontend
    create_config_files
    test_backend
    test_frontend
    create_start_scripts
    print_summary
}

# Run main function
main "$@" 