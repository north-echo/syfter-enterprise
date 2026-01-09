#!/bin/bash
# batch-scan.sh - Scan multiple products from a configuration file
#
# Usage: batch-scan.sh <config-file>
#
# Config file format (YAML-like):
#   # One product per line: target product version [description]
#   /path/to/rhel10/rpms rhel 10.0 "Red Hat Enterprise Linux 10.0"
#   /path/to/rhel9/rpms rhel 9.4 "RHEL 9.4"
#   registry.redhat.io/ubi9:latest ubi 9.0 "Universal Base Image 9"

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: $0 <config-file>"
    echo ""
    echo "Config file format (one product per line):"
    echo "  target product version [description]"
    echo ""
    echo "Example config file:"
    echo "  /path/to/rhel10 rhel 10.0 \"RHEL 10.0\""
    echo "  /path/to/rhel9 rhel 9.4 \"RHEL 9.4\""
    echo "  registry.redhat.io/ubi9:latest ubi 9.0 \"UBI 9\""
    echo ""
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

CONFIG_FILE="$1"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}Config file not found: $CONFIG_FILE${NC}"
    exit 1
fi

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

# Count lines (excluding comments and empty lines)
TOTAL=$(grep -v '^#' "$CONFIG_FILE" | grep -v '^$' | wc -l | tr -d ' ')
COUNT=0
FAILED=0

echo -e "${GREEN}Processing $TOTAL products from $CONFIG_FILE${NC}"
echo ""

# Read and process each line
while IFS= read -r line || [[ -n "$line" ]]; do
    # Skip comments and empty lines
    [[ "$line" =~ ^#.*$ ]] && continue
    [[ -z "${line// }" ]] && continue

    ((COUNT++))

    # Parse line - handle quoted description
    if [[ "$line" =~ ^([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+\"(.*)\"$ ]]; then
        TARGET="${BASH_REMATCH[1]}"
        PRODUCT="${BASH_REMATCH[2]}"
        VERSION="${BASH_REMATCH[3]}"
        DESCRIPTION="${BASH_REMATCH[4]}"
    elif [[ "$line" =~ ^([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)$ ]]; then
        TARGET="${BASH_REMATCH[1]}"
        PRODUCT="${BASH_REMATCH[2]}"
        VERSION="${BASH_REMATCH[3]}"
        DESCRIPTION=""
    else
        echo -e "${YELLOW}Skipping invalid line: $line${NC}"
        continue
    fi

    echo -e "${GREEN}[$COUNT/$TOTAL] Scanning $PRODUCT-$VERSION from $TARGET${NC}"

    # Build command
    CMD="$SYFTER_CMD scan '$TARGET' -p '$PRODUCT' -v '$VERSION'"
    if [[ -n "$DESCRIPTION" ]]; then
        CMD="$CMD --description '$DESCRIPTION'"
    fi

    # Run scan
    if eval $CMD; then
        echo -e "${GREEN}✓ $PRODUCT-$VERSION completed${NC}"
    else
        echo -e "${RED}✗ $PRODUCT-$VERSION failed${NC}"
        ((FAILED++))
    fi

    echo ""

done < "$CONFIG_FILE"

echo -e "${GREEN}Completed: $((COUNT - FAILED))/$COUNT successful${NC}"
if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}Failed: $FAILED${NC}"
    exit 1
fi
