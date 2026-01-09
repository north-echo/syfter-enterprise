#!/bin/bash
# query.sh - Convenience wrapper for querying the SBOM database
#
# Usage: query.sh [package|file] <pattern> [product] [version]
#
# Examples:
#   ./scripts/query.sh package "kernel%"
#   ./scripts/query.sh file "%/bin/bash"
#   ./scripts/query.sh package "openssl%" rhel 10.0

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: $0 <type> <pattern> [product] [version]"
    echo ""
    echo "Types:"
    echo "  package    Search by package name"
    echo "  file       Search by file path"
    echo ""
    echo "Pattern:"
    echo "  Use % as wildcard (SQL LIKE pattern)"
    echo ""
    echo "Examples:"
    echo "  $0 package 'kernel%'"
    echo "  $0 file '%/bin/bash'"
    echo "  $0 package 'openssl%' rhel 10.0"
    echo ""
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

TYPE="$1"
PATTERN="$2"
PRODUCT="${3:-}"
VERSION="${4:-}"

# Check if rh-syfter is available
if ! command -v rh-syfter &> /dev/null; then
    if python -c "import syfter" 2>/dev/null; then
        SYFTER_CMD="python -m syfter.cli"
    else
        echo -e "${RED}Error: rh-syfter not found. Install with: pip install -e .${NC}"
        exit 1
    fi
else
    SYFTER_CMD="rh-syfter"
fi

# Build command based on type
case "$TYPE" in
    package|pkg|p)
        CMD="$SYFTER_CMD query -n '$PATTERN'"
        ;;
    file|f)
        CMD="$SYFTER_CMD query -f '$PATTERN'"
        ;;
    *)
        echo -e "${RED}Unknown type: $TYPE${NC}"
        usage
        ;;
esac

# Add product filter if specified
if [[ -n "$PRODUCT" ]]; then
    CMD="$CMD -p '$PRODUCT'"
fi

if [[ -n "$VERSION" ]]; then
    CMD="$CMD -v '$VERSION'"
fi

# Run the query
eval $CMD
