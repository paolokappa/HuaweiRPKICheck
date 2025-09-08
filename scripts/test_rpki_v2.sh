#!/bin/bash
# Test script for HuaweiRPKICheck v2

echo "=========================================="
echo "RPKI Check v2 - Test Suite"
echo "=========================================="
echo ""

SCRIPT_DIR="/opt/HuaweiRPKICheck"
cd $SCRIPT_DIR

echo "1. Testing configuration decryption..."
python3 HuaweiRPKICheck_v2.py --test --verbose 2>&1 | head -20
echo ""

echo "2. Running in test mode (no changes, verbose output)..."
echo "   This will show what would happen without making changes"
echo ""
python3 HuaweiRPKICheck_v2.py --test --verbose

echo ""
echo "3. Checking log file creation..."
if [ -d "/var/log/huawei_rpki" ]; then
    echo "   ✓ Log directory exists"
    ls -la /var/log/huawei_rpki/ 2>/dev/null | head -5
else
    echo "   ✗ Log directory not found"
fi

echo ""
echo "4. Comparing with production script..."
echo "   Production script: HuaweiRPKICheck.py"
echo "   New script: HuaweiRPKICheck_v2.py"
echo ""

echo "Test complete!"
echo ""
echo "To run the new script in production mode:"
echo "  python3 $SCRIPT_DIR/HuaweiRPKICheck_v2.py"
echo ""
echo "To see all options:"
echo "  python3 $SCRIPT_DIR/HuaweiRPKICheck_v2.py --help"