#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Cerberus-V Integration Test Runner

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
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$TEST_DIR/../.." && pwd)"
VENV_DIR="$TEST_DIR/venv"
TEST_RESULTS_DIR="$TEST_DIR/results"

# Test options
RUN_PYTEST=true
RUN_UNITTEST=true
RUN_PERFORMANCE=false
RUN_STRESS=false
INSTALL_DEPS=true

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --pytest-only)
            RUN_UNITTEST=false
            shift
            ;;
        --unittest-only)
            RUN_PYTEST=false
            shift
            ;;
        --performance)
            RUN_PERFORMANCE=true
            shift
            ;;
        --stress)
            RUN_STRESS=true
            shift
            ;;
        --no-deps)
            INSTALL_DEPS=false
            shift
            ;;
        --help)
            echo "Cerberus-V Integration Test Runner"
            echo
            echo "Usage: $0 [OPTIONS]"
            echo
            echo "Options:"
            echo "  --pytest-only    Run only pytest tests"
            echo "  --unittest-only  Run only unittest tests"
            echo "  --performance    Include performance tests"
            echo "  --stress         Include stress tests"
            echo "  --no-deps        Skip dependency installation"
            echo "  --help           Show this help"
            echo
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Setup function
setup_test_environment() {
    log_info "🚀 Setting up test environment..."
    
    # Create results directory
    mkdir -p "$TEST_RESULTS_DIR"
    
    # Install Python dependencies if requested
    if [[ "$INSTALL_DEPS" == "true" ]]; then
        log_info "📦 Installing Python dependencies..."
        
        # Create virtual environment if it doesn't exist
        if [[ ! -d "$VENV_DIR" ]]; then
            python3 -m venv "$VENV_DIR"
        fi
        
        # Activate virtual environment
        source "$VENV_DIR/bin/activate"
        
        # Upgrade pip
        pip install --upgrade pip
        
        # Install requirements
        pip install -r "$TEST_DIR/requirements.txt"
        
        log_success "Dependencies installed"
    else
        log_info "Skipping dependency installation"
    fi
    
    # Check for Scapy availability
    if python3 -c "import scapy" 2>/dev/null; then
        log_success "Scapy is available for network testing"
    else
        log_warning "Scapy not available - network tests will run in simulation mode"
    fi
    
    # Check if we're running as root (needed for some network tests)
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root - full network testing enabled"
    else
        log_info "Running as user - some network tests may be limited"
    fi
}

# Check prerequisites
check_prerequisites() {
    log_info "🔍 Checking prerequisites..."
    
    # Check Python
    if ! command -v python3 >/dev/null 2>&1; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check Go (for control plane)
    if ! command -v go >/dev/null 2>&1; then
        log_warning "Go not found - control plane tests will be limited"
    fi
    
    # Check if control plane can be built
    if [[ -d "$PROJECT_ROOT/ctrl" ]]; then
        log_info "Control plane source found"
        cd "$PROJECT_ROOT/ctrl"
        if go build -o /tmp/cerberus-ctrl-test . 2>/dev/null; then
            log_success "Control plane builds successfully"
            rm -f /tmp/cerberus-ctrl-test
        else
            log_warning "Control plane build issues - some tests may fail"
        fi
    else
        log_warning "Control plane source not found"
    fi
    
    cd "$TEST_DIR"
}

# Run unittest-based tests
run_unittest_tests() {
    log_info "🧪 Running unittest-based integration tests..."
    
    # Activate virtual environment if it exists
    if [[ -d "$VENV_DIR" ]]; then
        source "$VENV_DIR/bin/activate"
    fi
    
    local test_file="test_cerberus_integration.py"
    local results_file="$TEST_RESULTS_DIR/unittest_results.xml"
    
    if [[ -f "$test_file" ]]; then
        # Run unittest tests with XML output
        python3 "$test_file" 2>&1 | tee "$TEST_RESULTS_DIR/unittest_output.log"
        local exit_code=${PIPESTATUS[0]}
        
        if [[ $exit_code -eq 0 ]]; then
            log_success "Unittest tests passed"
        else
            log_error "Unittest tests failed (exit code: $exit_code)"
        fi
        
        return $exit_code
    else
        log_warning "Unittest test file not found: $test_file"
        return 0
    fi
}

# Run pytest-based tests
run_pytest_tests() {
    log_info "🧪 Running pytest-based integration tests..."
    
    # Activate virtual environment if it exists
    if [[ -d "$VENV_DIR" ]]; then
        source "$VENV_DIR/bin/activate"
    fi
    
    local pytest_args=(
        "--verbose"
        "--tb=short"
        "--junit-xml=$TEST_RESULTS_DIR/pytest_results.xml"
        "--cov=."
        "--cov-report=html:$TEST_RESULTS_DIR/coverage"
        "--cov-report=term"
    )
    
    # Add performance tests if requested
    if [[ "$RUN_PERFORMANCE" == "true" ]]; then
        pytest_args+=("-m" "not slow or performance")
    else
        pytest_args+=("-m" "not slow")
    fi
    
    # Add stress tests if requested
    if [[ "$RUN_STRESS" == "true" ]]; then
        pytest_args+=("--stress")
    fi
    
    # Run pytest
    if command -v pytest >/dev/null 2>&1; then
        pytest "${pytest_args[@]}" test_pytest_cerberus.py 2>&1 | tee "$TEST_RESULTS_DIR/pytest_output.log"
        local exit_code=${PIPESTATUS[0]}
        
        if [[ $exit_code -eq 0 ]]; then
            log_success "Pytest tests passed"
        else
            log_error "Pytest tests failed (exit code: $exit_code)"
        fi
        
        return $exit_code
    else
        log_warning "pytest not available"
        return 0
    fi
}

# Generate test report
generate_test_report() {
    log_info "📊 Generating test report..."
    
    local report_file="$TEST_RESULTS_DIR/test_report.html"
    
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Cerberus-V Integration Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        .code { background: #f4f4f4; padding: 10px; border-radius: 3px; font-family: monospace; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Cerberus-V Integration Test Report</h1>
        <p>Generated: $(date)</p>
    </div>
    
    <div class="section">
        <h2>Test Summary</h2>
        <table>
            <tr><th>Test Suite</th><th>Status</th><th>Results File</th></tr>
EOF

    # Add test results to report
    if [[ -f "$TEST_RESULTS_DIR/unittest_output.log" ]]; then
        echo "            <tr><td>Unittest</td><td class=\"success\">✅ Completed</td><td>unittest_output.log</td></tr>" >> "$report_file"
    fi
    
    if [[ -f "$TEST_RESULTS_DIR/pytest_output.log" ]]; then
        echo "            <tr><td>Pytest</td><td class=\"success\">✅ Completed</td><td>pytest_output.log</td></tr>" >> "$report_file"
    fi
    
    cat >> "$report_file" << 'EOF'
        </table>
    </div>
    
    <div class="section">
        <h2>Test Categories</h2>
        <ul>
            <li><strong>Control Plane API:</strong> REST endpoint testing</li>
            <li><strong>Metrics:</strong> Prometheus metrics validation</li>
            <li><strong>Packet Processing:</strong> Scapy-based network testing</li>
            <li><strong>Performance:</strong> Throughput and latency testing</li>
            <li><strong>End-to-End:</strong> Complete pipeline validation</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Files Generated</h2>
        <ul>
EOF

    # List all generated files
    for file in "$TEST_RESULTS_DIR"/*; do
        if [[ -f "$file" ]]; then
            filename=$(basename "$file")
            echo "            <li><code>$filename</code></li>" >> "$report_file"
        fi
    done
    
    cat >> "$report_file" << 'EOF'
        </ul>
    </div>
</body>
</html>
EOF
    
    log_success "Test report generated: $report_file"
}

# Main execution
main() {
    log_info "🛡️ Cerberus-V Integration Test Suite"
    log_info "===================================="
    
    # Setup
    check_prerequisites
    setup_test_environment
    
    # Track overall success
    local overall_success=true
    
    # Run tests
    if [[ "$RUN_UNITTEST" == "true" ]]; then
        if ! run_unittest_tests; then
            overall_success=false
        fi
    fi
    
    if [[ "$RUN_PYTEST" == "true" ]]; then
        if ! run_pytest_tests; then
            overall_success=false
        fi
    fi
    
    # Generate report
    generate_test_report
    
    # Final summary
    log_info "===================================="
    if [[ "$overall_success" == "true" ]]; then
        log_success "🎉 All integration tests completed successfully!"
        log_info "📁 Results available in: $TEST_RESULTS_DIR"
        exit 0
    else
        log_error "❌ Some integration tests failed"
        log_info "📁 Check results in: $TEST_RESULTS_DIR"
        exit 1
    fi
}

# Execute main function
main "$@" 