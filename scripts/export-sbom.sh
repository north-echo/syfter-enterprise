#!/bin/bash
# export-sbom.sh - Export product SBOMs to various formats
#
# Usage: export-sbom.sh <product> <version> <format> [output]
#
# Examples:
#   ./scripts/export-sbom.sh rhel 10.0 spdx-json rhel-10.spdx.json
#   ./scripts/export-sbom.sh rhel 10.0 all ./sboms/
#   ./scripts/export-sbom.sh openshift 4.14 cyclonedx-json

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    echo "Usage: $0 <product> <version> <format> [output]"
    echo ""
    echo "Formats:"
    echo "  syft-json       Native Syft JSON format"
    echo "  spdx-json       SPDX 2.3 JSON format"
    echo "  spdx-tv         SPDX Tag-Value format"
    echo "  cyclonedx-json  CycloneDX JSON format"
    echo "  cyclonedx-xml   CycloneDX XML format"
    echo "  all             Export to all formats (output must be directory)"
    echo ""
    echo "Examples:"
    echo "  $0 rhel 10.0 spdx-json rhel-10.spdx.json"
    echo "  $0 rhel 10.0 all ./sboms/"
    echo "  $0 openshift 4.14 cyclonedx-json  # outputs to stdout"
    echo ""
    exit 1
}

if [[ $# -lt 3 ]]; then
    usage
fi

PRODUCT="$1"
VERSION="$2"
FORMAT="$3"
OUTPUT="${4:-}"

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

# Build and run command
CMD="$SYFTER_CMD export -p '$PRODUCT' -v '$VERSION' -f '$FORMAT'"

if [[ -n "$OUTPUT" ]]; then
    CMD="$CMD -o '$OUTPUT'"
fi

eval $CMD
