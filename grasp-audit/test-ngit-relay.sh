#!/bin/bash
set -e

# Change to script's directory so `cargo run`/`cargo test` select the
# grasp-audit package within the workspace (cargo resolves the workspace
# root automatically). This allows the script to be run from any directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# =============================================================================
# Script: test-ngit-relay.sh
# Purpose: Test ngit-relay against GRASP specifications
#
# This script automates the process of:
# 1. Starting a fresh ngit-relay instance in Docker
# 2. Running either grasp-audit CLI or cargo test suite
# 3. Cleaning up all resources on exit (via EXIT trap)
#
# Features:
# - Automatic cleanup via EXIT trap (runs even on failure)
# - Random port selection (20000-30000) to avoid conflicts
# - Unique temporary directories per run
# - Support for both audit and test execution modes
# =============================================================================

# -----------------------------------------------------------------------------
# Help Function
# -----------------------------------------------------------------------------
show_help() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Test ngit-relay against GRASP specifications

OPTIONS:
    --mode <audit|test>    Execution mode (default: audit)
                           audit: Run grasp-audit CLI tool
                           test: Run cargo test suite
    --spec <spec>          Specification to test (default: all)
                           Available specs: nip01-smoke, nip11, event-acceptance,
                           cors, git-clone, push-auth, repo-creation, all
                           Only used in audit mode
    --help                 Show this help message

EXAMPLES:
    # Run audit with all tests (default)
    ./test-ngit-relay.sh

    # Run cargo tests instead
    ./test-ngit-relay.sh --mode test

    # Run audit with specific spec
    ./test-ngit-relay.sh --mode audit --spec nip01-smoke
    ./test-ngit-relay.sh --mode audit --spec nip11
    ./test-ngit-relay.sh --mode audit --spec event-acceptance
    ./test-ngit-relay.sh --mode audit --spec cors
    ./test-ngit-relay.sh --mode audit --spec git-clone
    ./test-ngit-relay.sh --mode audit --spec push-auth
    ./test-ngit-relay.sh --mode audit --spec repo-creation

EOF
    exit 0
}

# -----------------------------------------------------------------------------
# Argument Parsing
# -----------------------------------------------------------------------------
# Default: run audit mode with all specs
MODE="audit"
SPEC="all"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --spec)
            SPEC="$2"
            shift 2
            ;;
        --help)
            show_help
            ;;
        *)
            echo "❌ Unknown option: $1"
            echo "Run with --help for usage information"
            exit 1
            ;;
    esac
done

# Validate mode parameter
if [ "$MODE" != "audit" ] && [ "$MODE" != "test" ]; then
    echo "❌ Invalid mode: $MODE"
    echo "Mode must be 'audit' or 'test'"
    exit 1
fi

# -----------------------------------------------------------------------------
# Environment Setup
# -----------------------------------------------------------------------------
# Create temporary directory with random name
# This ensures each test run is isolated and doesn't interfere with others
TEST_DIR=$(mktemp -d -t grasp-audit-run-XXXXXXXXXX)

# Pick a random port in the range 20000-30000 to avoid conflicts
PORT=$((20000 + RANDOM % 10000))

# Generate a unique container name suffix for parallel runs
CONTAINER_SUFFIX=$RANDOM

echo "🧹 Using temporary directory: $TEST_DIR"
echo "🔌 Using port: $PORT"
echo "🎯 Mode: $MODE $([ "$MODE" = "audit" ] && echo "(spec: $SPEC)" || echo "")"

# -----------------------------------------------------------------------------
# Cleanup Function
# -----------------------------------------------------------------------------
# This function is called automatically on script exit via trap
# The '|| true' pattern ensures cleanup continues even if individual steps fail
cleanup() {
    echo ""
    echo "🛑 Stopping relay..."
    # Stop container gracefully, ignore errors if already stopped
    docker stop "grasp-audit-run-$CONTAINER_SUFFIX" 2>/dev/null || true
    
    echo "🧹 Cleaning up temporary directory..."
    # Use alpine container to clean Docker-created files (may have different ownership)
    docker run --rm -v "$TEST_DIR:/data" alpine sh -c "rm -rf /data/*" 2>/dev/null || true
    # Remove the temporary directory itself
    rm -rf "$TEST_DIR"
}

# Set trap to run cleanup on ANY exit (success, failure, or interrupt)
# This ensures resources are always cleaned up
trap cleanup EXIT

# -----------------------------------------------------------------------------
# Docker Setup
# -----------------------------------------------------------------------------
echo "📁 Creating data directories..."
# Create all required directories for ngit-relay in one command
mkdir -p "$TEST_DIR"/{repos,blossom,relay-db,logs}

echo "🚀 Starting ngit-relay..."
# Remove any existing container with this name (defensive cleanup)
CONTAINER_NAME="grasp-audit-run-$CONTAINER_SUFFIX"
docker rm -f "$CONTAINER_NAME" 2>/dev/null || true

# Start ngit-relay in detached mode with all required configuration
# - Port mapping: expose internal 8081 on our random port
# - Volume mounts: persist data in temp directory
# - Proactive sync disabled: we control event submission via tests
docker run --rm -d \
  --name "$CONTAINER_NAME" \
  -p "$PORT:8081" \
  -e NGIT_DOMAIN=localhost \
  -e NGIT_RELAY_NAME="ngit-relay test instance" \
  -e NGIT_RELAY_DESCRIPTION="Test instance for grasp-audit" \
  -e NGIT_OWNER_NPUB="npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr" \
  -e NGIT_PROACTIVE_SYNC_GIT=false \
  -e NGIT_PROACTIVE_SYNC_BLOSSOM=false \
  -e NGIT_PROACTIVE_SYNC_NOSTR=false \
  -e NGIT_LOG_LEVEL=INFO \
  -v "$TEST_DIR/repos:/srv/ngit-relay/repos" \
  -v "$TEST_DIR/blossom:/srv/ngit-relay/blossom" \
  -v "$TEST_DIR/relay-db:/srv/ngit-relay/relay-db" \
  -v "$TEST_DIR/logs:/var/log/ngit-relay" \
  ghcr.io/danconwaydev/ngit-relay:latest

echo "⏳ Waiting for relay to start..."
# Give the relay time to initialize before running tests
sleep 3

# -----------------------------------------------------------------------------
# Test Execution
# -----------------------------------------------------------------------------
# Execute tests based on selected mode
# The EXIT trap ensures cleanup happens regardless of test outcome

if [ "$MODE" = "audit" ]; then
    echo "🧪 Running audit mode (spec: $SPEC)..."
    echo ""
    echo "Note: ngit-relay only accepts Git-related events (NIP-34)."
    echo "Some NIP-01 smoke tests will fail (expected behavior)."
    echo "Validation tests should pass."
    echo ""
    
    # Run grasp-audit CLI tool
    # - RELAY_URL: Environment variable used by audit tool
    # - --relay: Command-line parameter for relay address
    # - --mode ci: Continuous integration mode (structured output)
    # - --spec: Which specification to test
    # - --git-data-dir: Path to git data directory (for git-clone, push-auth, repo-creation)
    # The '|| { }' block provides user-friendly messaging on failure
    RELAY_URL="ws://localhost:$PORT" cargo run -- audit \
        --relay "ws://localhost:$PORT" \
        --mode ci \
        --spec "$SPEC" \
        --git-data-dir "$TEST_DIR/repos" || {
        echo "⚠️  Some tests failed (expected for ngit-relay)"
        echo "    Validation tests should have passed"
    }
    
elif [ "$MODE" = "test" ]; then
    echo "🧪 Running cargo test mode..."
    echo ""
    
    # Run cargo test suite
    # - RELAY_URL: Environment variable tests use to connect
    # - --lib: Only library tests (not integration tests in tests/)
    # - --ignored: Run tests marked with #[ignore] (these need relay)
    # - --nocapture: Show println! output from tests
    # This runs all library tests marked with #[ignore], including:
    #   - test_grasp01_nostr_relay_against_relay (GRASP-01 relay tests)
    #   - Any other integration tests requiring a relay
    RELAY_URL="ws://localhost:$PORT" cargo test \
        --lib -- --ignored --nocapture || {
        echo "⚠️  Some tests failed"
        echo "    Review output above for details"
    }
fi

echo ""
echo "✅ Done!"
