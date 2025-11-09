#!/bin/sh
# Installation script for sysrebase

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo "${BLUE}=== Sysrebase - Installation Script ===${NC}"

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "${RED}Error: Installation requires root privileges${NC}"
    echo "Please run: sudo $0"
    exit 1
fi

# Installation directories
BIN_DIR="/usr/local/bin"
ETC_DIR="/usr/local/etc"
LOG_DIR="/var/log"

echo "${BLUE}Installing sysrebase components...${NC}"

# Install main script
echo "Installing main script to ${BIN_DIR}/sysrebase"
cp sysrebase.py ${BIN_DIR}/sysrebase
chmod +x ${BIN_DIR}/sysrebase

# Install wrapper script
echo "Installing wrapper to ${BIN_DIR}/sysrebase-cli"
cp sysrebase_wrapper.sh ${BIN_DIR}/sysrebase-cli
chmod +x ${BIN_DIR}/sysrebase-cli

# Install test script
echo "Installing test suite to ${BIN_DIR}/sysrebase-test"
cp test_sysrebase.py ${BIN_DIR}/sysrebase-test
chmod +x ${BIN_DIR}/sysrebase-test

# Install configuration example
if [ ! -f ${ETC_DIR}/sysrebase.conf ]; then
    echo "Installing configuration template to ${ETC_DIR}/sysrebase.conf"
    cp sysrebase.conf.example ${ETC_DIR}/sysrebase.conf
else
    echo "${BLUE}Configuration already exists at ${ETC_DIR}/sysrebase.conf${NC}"
    echo "New template saved as ${ETC_DIR}/sysrebase.conf.example"
    cp sysrebase.conf.example ${ETC_DIR}/sysrebase.conf.example
fi

# Create log directory
echo "Creating log directory at ${LOG_DIR}"
mkdir -p ${LOG_DIR}

# Install documentation
DOC_DIR="/usr/local/share/doc/sysrebase"
echo "Installing documentation to ${DOC_DIR}"
mkdir -p ${DOC_DIR}
cp README_IMPROVED.md ${DOC_DIR}/README.md
cp IMPROVEMENTS_SUMMARY.md ${DOC_DIR}/IMPROVEMENTS.md

echo ""
echo "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "Installed components:"
echo "  • Main script: ${BIN_DIR}/sysrebase"
echo "  • CLI wrapper: ${BIN_DIR}/sysrebase-cli"
echo "  • Test suite: ${BIN_DIR}/sysrebase-test"
echo "  • Configuration: ${ETC_DIR}/sysrebase.conf"
echo "  • Documentation: ${DOC_DIR}/"
echo ""
echo "Usage examples:"
echo "  ${BLUE}sysrebase --to 25.02 --dry-run${NC}     # Test rebase"
echo "  ${BLUE}sysrebase-cli status${NC}               # Show system status"
echo "  ${BLUE}sysrebase-cli rebase 25.02${NC}         # Perform rebase"
echo "  ${BLUE}sysrebase-test${NC}                     # Run validation tests"
echo ""
echo "Run ${BLUE}sysrebase-cli help${NC} for more information"
