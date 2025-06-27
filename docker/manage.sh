#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Docker Management Script
# Author: funcybot@gmail.com  Date: 2025-06-27

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Environment selection
ENVIRONMENT="production"
COMPOSE_FILE=""
ENV_FILE=""

# Command configuration
COMMAND=""
SERVICES=""
FOLLOW_LOGS=false
FORCE_RECREATE=false
BUILD_IMAGES=false

# Show usage
show_usage() {
    cat << 'EOF'
Cerberus-V Docker Management Script

Usage: ./manage.sh [OPTIONS] COMMAND [SERVICES...]

Environments:
  production    Full production stack with monitoring
  development   Development stack with hot reload
  monitoring    Only monitoring services (Prometheus, Grafana)

Commands:
  up            Start services
  down          Stop services
  restart       Restart services
  logs          Show service logs
  status        Show service status
  build         Build custom images
  pull          Pull latest images
  clean         Clean up containers and volumes
  backup        Backup persistent data
  restore       Restore from backup
  shell         Open shell in service container

Options:
  -e, --env ENV         Environment (production|development|monitoring)
  -f, --follow          Follow log output
  -r, --recreate        Force recreate containers
  -b, --build           Build images before starting
  --help                Show this help

Examples:
  ./manage.sh up                          # Start production stack
  ./manage.sh -e development up           # Start development stack
  ./manage.sh logs -f cerberus-ctrl       # Follow control plane logs
  ./manage.sh -e development restart      # Restart dev services
  ./manage.sh shell cerberus-ctrl         # Open shell in control plane
  ./manage.sh clean                       # Clean up everything

Services (production):
  cerberus-ctrl, cerberus-dataplane, cerberus-gui
  prometheus, grafana, elasticsearch, kibana, logstash
  traefik, redis, postgres

Services (development):
  cerberus-ctrl-dev, cerberus-gui-dev, cerberus-backend-dev
  postgres-dev, redis-dev, prometheus-dev, grafana-dev
  test-runner, file-watcher

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            -f|--follow)
                FOLLOW_LOGS=true
                shift
                ;;
            -r|--recreate)
                FORCE_RECREATE=true
                shift
                ;;
            -b|--build)
                BUILD_IMAGES=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            up|down|restart|logs|status|build|pull|clean|backup|restore|shell)
                COMMAND="$1"
                shift
                SERVICES="$*"
                break
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    if [[ -z "$COMMAND" ]]; then
        log_error "No command specified"
        show_usage
        exit 1
    fi
}

# Set environment configuration
setup_environment() {
    case "$ENVIRONMENT" in
        production)
            COMPOSE_FILE="$SCRIPT_DIR/production/docker-compose.yml"
            ENV_FILE="$SCRIPT_DIR/production/cerberus.env"
            ;;
        development)
            COMPOSE_FILE="$SCRIPT_DIR/development/docker-compose.dev.yml"
            ENV_FILE="$SCRIPT_DIR/development/dev.env"
            ;;
        monitoring)
            COMPOSE_FILE="$SCRIPT_DIR/monitoring/docker-compose.monitoring.yml"
            ENV_FILE="$SCRIPT_DIR/monitoring/monitoring.env"
            ;;
        *)
            log_error "Unknown environment: $ENVIRONMENT"
            exit 1
            ;;
    esac

    if [[ ! -f "$COMPOSE_FILE" ]]; then
        log_error "Compose file not found: $COMPOSE_FILE"
        exit 1
    fi

    log_info "Using environment: $ENVIRONMENT"
    log_info "Compose file: $(basename "$COMPOSE_FILE")"
}

# Check prerequisites
check_prerequisites() {
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker is not installed"
        exit 1
    fi

    if ! command -v docker-compose >/dev/null 2>&1 && ! docker compose version >/dev/null 2>&1; then
        log_error "Docker Compose is not installed"
        exit 1
    fi

    # Check if Docker daemon is running
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        exit 1
    fi
}

# Build Docker Compose command
build_compose_cmd() {
    local cmd="docker compose"
    
    # Use legacy docker-compose if available
    if command -v docker-compose >/dev/null 2>&1; then
        cmd="docker-compose"
    fi

    cmd="$cmd -f $COMPOSE_FILE"
    
    if [[ -f "$ENV_FILE" ]]; then
        cmd="$cmd --env-file $ENV_FILE"
    fi

    echo "$cmd"
}

# Execute Docker commands
execute_command() {
    local compose_cmd
    compose_cmd=$(build_compose_cmd)

    case "$COMMAND" in
        up)
            log_info "Starting Cerberus-V ($ENVIRONMENT)..."
            
            local up_args="up -d"
            
            if [[ "$FORCE_RECREATE" == "true" ]]; then
                up_args="$up_args --force-recreate"
            fi
            
            if [[ "$BUILD_IMAGES" == "true" ]]; then
                up_args="$up_args --build"
            fi
            
            eval "$compose_cmd $up_args $SERVICES"
            
            log_success "Cerberus-V started successfully!"
            show_access_info
            ;;
            
        down)
            log_info "Stopping Cerberus-V ($ENVIRONMENT)..."
            eval "$compose_cmd down $SERVICES"
            log_success "Cerberus-V stopped"
            ;;
            
        restart)
            log_info "Restarting Cerberus-V ($ENVIRONMENT)..."
            eval "$compose_cmd restart $SERVICES"
            log_success "Cerberus-V restarted"
            ;;
            
        logs)
            local log_args="logs"
            if [[ "$FOLLOW_LOGS" == "true" ]]; then
                log_args="$log_args -f"
            fi
            eval "$compose_cmd $log_args $SERVICES"
            ;;
            
        status)
            log_info "Cerberus-V status ($ENVIRONMENT):"
            eval "$compose_cmd ps"
            ;;
            
        build)
            log_info "Building Cerberus-V images..."
            eval "$compose_cmd build $SERVICES"
            log_success "Images built successfully"
            ;;
            
        pull)
            log_info "Pulling latest images..."
            eval "$compose_cmd pull $SERVICES"
            log_success "Images updated"
            ;;
            
        shell)
            if [[ -z "$SERVICES" ]]; then
                log_error "Service name required for shell command"
                exit 1
            fi
            local service=$(echo "$SERVICES" | awk '{print $1}')
            log_info "Opening shell in $service..."
            eval "$compose_cmd exec $service /bin/bash || $compose_cmd exec $service /bin/sh"
            ;;
            
        clean)
            cleanup_system
            ;;
            
        backup)
            backup_data
            ;;
            
        restore)
            restore_data
            ;;
            
        *)
            log_error "Unknown command: $COMMAND"
            exit 1
            ;;
    esac
}

# Show access information
show_access_info() {
    log_info "🌐 Access Information:"
    
    case "$ENVIRONMENT" in
        production)
            echo "  • Main GUI:      http://localhost:3000"
            echo "  • API:           http://localhost:50052"
            echo "  • Prometheus:    http://localhost:9090"
            echo "  • Grafana:       http://localhost:3001 (admin/cerberus123)"
            echo "  • Kibana:        http://localhost:5601"
            echo "  • Traefik:       http://localhost:8080"
            ;;
        development)
            echo "  • Dev GUI:       http://localhost:3000"
            echo "  • Dev API:       http://localhost:50052"
            echo "  • Backend API:   http://localhost:8000"
            echo "  • Prometheus:    http://localhost:9091"
            echo "  • Grafana:       http://localhost:3002 (admin/dev123)"
            ;;
    esac
    
    echo "  • Control Plane: gRPC localhost:50051"
    echo "  • Metrics:       http://localhost:8080/metrics"
}

# Clean up system
cleanup_system() {
    log_info "🧹 Cleaning up Cerberus-V Docker resources..."
    
    local compose_cmd
    compose_cmd=$(build_compose_cmd)
    
    # Stop and remove containers
    eval "$compose_cmd down --volumes --remove-orphans" 2>/dev/null || true
    
    # Remove custom images
    docker images --filter "reference=cerberus-v/*" -q | xargs -r docker rmi -f 2>/dev/null || true
    
    # Remove dangling volumes
    docker volume ls --filter "name=cerberus" -q | xargs -r docker volume rm 2>/dev/null || true
    
    # Clean up networks
    docker network ls --filter "name=cerberus" -q | xargs -r docker network rm 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Backup persistent data
backup_data() {
    log_info "📦 Creating backup of Cerberus-V data..."
    
    local backup_dir="$SCRIPT_DIR/backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup volumes
    local volumes=(
        "cerberus-config"
        "cerberus-rules" 
        "cerberus-data"
        "prometheus-data"
        "grafana-data"
        "postgres-data"
    )
    
    for volume in "${volumes[@]}"; do
        if docker volume inspect "$volume" >/dev/null 2>&1; then
            log_info "Backing up volume: $volume"
            docker run --rm \
                -v "$volume:/data:ro" \
                -v "$backup_dir:/backup" \
                alpine:latest \
                tar czf "/backup/$volume.tar.gz" -C /data .
        fi
    done
    
    log_success "Backup created: $backup_dir"
}

# Restore from backup
restore_data() {
    log_info "📦 Restoring Cerberus-V data from backup..."
    
    local backup_dir="$SCRIPT_DIR/backups"
    if [[ ! -d "$backup_dir" ]]; then
        log_error "No backups found"
        exit 1
    fi
    
    local latest_backup
    latest_backup=$(find "$backup_dir" -type d -name "20*" | sort | tail -1)
    
    if [[ -z "$latest_backup" ]]; then
        log_error "No backup directories found"
        exit 1
    fi
    
    log_info "Restoring from: $latest_backup"
    
    # Stop services first
    local compose_cmd
    compose_cmd=$(build_compose_cmd)
    eval "$compose_cmd down"
    
    # Restore volumes
    for backup_file in "$latest_backup"/*.tar.gz; do
        if [[ -f "$backup_file" ]]; then
            local volume_name
            volume_name=$(basename "$backup_file" .tar.gz)
            
            log_info "Restoring volume: $volume_name"
            
            # Create volume if it doesn't exist
            docker volume create "$volume_name" >/dev/null 2>&1 || true
            
            # Restore data
            docker run --rm \
                -v "$volume_name:/data" \
                -v "$backup_file:/backup.tar.gz:ro" \
                alpine:latest \
                tar xzf /backup.tar.gz -C /data
        fi
    done
    
    log_success "Restore completed from: $latest_backup"
}

# Main execution
main() {
    log_info "🛡️ Cerberus-V Docker Manager"
    log_info "=============================="
    
    parse_args "$@"
    check_prerequisites
    setup_environment
    execute_command
}

# Execute main function
main "$@" 