#!/bin/bash
# scan-product.sh - Convenience wrapper for scanning a product
#
# Usage: scan-product.sh <target> <product-name> <product-version> [options]
#
# Example:
#   ./scripts/scan-product.sh /path/to/rpms rhel 10.0
#   ./scripts/scan-product.sh registry.redhat.io/rhel9:latest rhel 9.0

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <target> <product-name> <product-version> [rh-syfter options]"
    echo ""
    echo "Arguments:"
    echo "  target           Directory, container image, or syft-supported target"
    echo "  product-name     Product name (e.g., 'rhel', 'openshift')"
    echo "  product-version  Product version (e.g., '10.0', '4.14')"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/rpms rhel 10.0"
    echo "  $0 registry.redhat.io/rhel9:latest rhel 9.0"
    echo "  $0 ./packages openshift 4.14 --description 'OCP 4.14'"
    echo ""
    exit 1
}

if [[ $# -lt 3 ]]; then
    usage
fi

TARGET="$1"
PRODUCT="$2"
VERSION="$3"
shift 3

# Check if rh-syfter is available
if ! command -v rh-syfter &> /dev/null; then
    # Try running via python module
    if python -c "import syfter" 2>/dev/null; then
        SYFTER_CMD="python -m syfter.cli"
    else
        echo -e "${RED}Error: rh-syfter not found. Install with: pip install -e .${NC}"
        exit 1
    fi
else
    SYFTER_CMD="rh-syfter"
fi

echo -e "${GREEN}Scanning ${TARGET} for ${PRODUCT}-${VERSION}...${NC}"

# Run the scan with any additional arguments
$SYFTER_CMD scan "$TARGET" -p "$PRODUCT" -v "$VERSION" "$@"

echo -e "${GREEN}Done!${NC}"
