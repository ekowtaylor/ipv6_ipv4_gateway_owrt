#!/bin/bash
# Comprehensive Test Runner for IPv4/IPv6 Gateway
# Runs all tests and generates a detailed report

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "======================================================================"
echo "IPv4/IPv6 Gateway - Comprehensive Test Suite"
echo "======================================================================"
echo ""

# Check Python version
echo -e "${BLUE}Checking Python version...${NC}"
python3 --version
echo ""

# Check dependencies
echo -e "${BLUE}Checking test dependencies...${NC}"
python3 -c "import unittest; import unittest.mock; print('✓ unittest available')"
echo ""

# Run unit tests
echo "======================================================================"
echo -e "${YELLOW}Running Unit Tests${NC}"
echo "======================================================================"
echo ""

if python3 test_gateway.py; then
    UNIT_TESTS_PASSED=true
    echo -e "${GREEN}✅ Unit tests PASSED${NC}"
else
    UNIT_TESTS_PASSED=false
    echo -e "${RED}❌ Unit tests FAILED${NC}"
fi

echo ""
echo ""

# Run integration tests
echo "======================================================================"
echo -e "${YELLOW}Running Integration Tests${NC}"
echo "======================================================================"
echo ""

if python3 integration_test.py; then
    INTEGRATION_TESTS_PASSED=true
    echo -e "${GREEN}✅ Integration tests PASSED${NC}"
else
    INTEGRATION_TESTS_PASSED=false
    echo -e "${RED}❌ Integration tests FAILED${NC}"
fi

echo ""
echo ""

# Final summary
echo "======================================================================"
echo "FINAL TEST SUMMARY"
echo "======================================================================"
echo ""

if [ "$UNIT_TESTS_PASSED" = true ]; then
    echo -e "Unit Tests:        ${GREEN}✅ PASSED${NC}"
else
    echo -e "Unit Tests:        ${RED}❌ FAILED${NC}"
fi

if [ "$INTEGRATION_TESTS_PASSED" = true ]; then
    echo -e "Integration Tests: ${GREEN}✅ PASSED${NC}"
else
    echo -e "Integration Tests: ${RED}❌ FAILED${NC}"
fi

echo ""

if [ "$UNIT_TESTS_PASSED" = true ] && [ "$INTEGRATION_TESTS_PASSED" = true ]; then
    echo "======================================================================"
    echo -e "${GREEN}🎉 ALL TESTS PASSED! 🎉${NC}"
    echo "======================================================================"
    echo ""
    echo "Your IPv4/IPv6 gateway code is ready for deployment!"
    echo ""
    echo "Next steps:"
    echo "  1. Deploy to OpenWrt router"
    echo "  2. Run: ./install.sh --full-auto"
    echo "  3. Check logs: tail -f /var/log/ipv4-ipv6-gateway.log"
    echo "  4. Test connectivity to your RF attenuator"
    echo ""
    exit 0
else
    echo "======================================================================"
    echo -e "${RED}❌ SOME TESTS FAILED${NC}"
    echo "======================================================================"
    echo ""
    echo "Please review the test output above and fix the issues."
    echo ""
    exit 1
fi
