#!/bin/bash
# Script to compare v1 and v2 behavior side by side

echo "=========================================="
echo "Comparing RPKI Check v1 vs v2"
echo "=========================================="
echo ""

cd /opt/HuaweiRPKICheck

echo "Running v1 (current production)..."
echo "-----------------------------------"
timeout 10 python3 HuaweiRPKICheck.py 2>&1 | head -20 || echo "v1 completed/timeout"

echo ""
echo "Running v2 in test mode..."
echo "-----------------------------------"
timeout 10 python3 HuaweiRPKICheck_v2.py --test 2>&1 | grep -v "DEBUG" | head -30

echo ""
echo "Log comparison:"
echo "-----------------------------------"
echo "v2 logs location: /var/log/huawei_rpki/"
tail -5 /var/log/huawei_rpki/rpki_check_*.log 2>/dev/null

echo ""
echo "Feature comparison:"
echo "==================="
echo "v1 Features:"
echo "  - Basic SSH connection"
echo "  - Email alerts on issues"
echo "  - Auto-reset sessions"
echo ""
echo "v2 New Features:"
echo "  - Comprehensive logging to /var/log/huawei_rpki/"
echo "  - Test mode (--test) for safe testing"
echo "  - Retry logic with exponential backoff"
echo "  - Proper SSH timeout handling"
echo "  - State tracking (consecutive failures)"
echo "  - Alert suppression (1 hour cooldown)"
echo "  - Better error messages and debugging"
echo "  - Command-line arguments support"
echo "  - Validates configuration on startup"
echo ""
echo "To switch to v2 in production:"
echo "  1. Test thoroughly: python3 HuaweiRPKICheck_v2.py --test"
echo "  2. Update crontab to use HuaweiRPKICheck_v2.py"
echo "  3. Keep v1 as backup (HuaweiRPKICheck.py.backup)"