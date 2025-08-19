#!/bin/bash
# File: terraform/scripts/deploy.sh
# Terraform deployment script with safety checks

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT="${1:-production}"
ACTION="${2:-plan}"
SCRIPT_DIR