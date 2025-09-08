#!/bin/bash
# Analyze Routinator tuning issues
# Check configuration and performance on remote servers

echo "=========================================="
echo "Routinator Tuning Analysis"
echo "Date: $(date)"
echo "=========================================="

SERVERS="lg.goline.ch time.goline.ch"
ROUTER_IP="185.54.81.25"

for SERVER in $SERVERS; do
    echo ""
    echo "Checking $SERVER..."
    echo "------------------------------------------"
    
    # Test SSH connectivity
    echo -n "SSH connectivity: "
    if ssh -o ConnectTimeout=5 -o BatchMode=yes root@$SERVER "echo OK" 2>/dev/null; then
        echo "✓ OK"
        
        # Get Routinator configuration
        echo ""
        echo "Routinator Configuration:"
        ssh root@$SERVER "cat /etc/routinator/routinator.conf 2>/dev/null || cat /usr/local/etc/routinator/routinator.conf 2>/dev/null" 2>/dev/null | grep -E "^[^#]" | head -20
        
        # Check RTR listen settings
        echo ""
        echo "RTR Listen Settings:"
        ssh root@$SERVER "grep -E 'rtr-listen|http-listen' /etc/routinator/routinator.conf 2>/dev/null || grep -E 'rtr-listen|http-listen' /usr/local/etc/routinator/routinator.conf 2>/dev/null" 2>/dev/null
        
        # Check timing parameters
        echo ""
        echo "Timing Parameters (may affect stability):"
        ssh root@$SERVER "grep -E 'refresh|retry|expire|timeout' /etc/routinator/routinator.conf 2>/dev/null || grep -E 'refresh|retry|expire|timeout' /usr/local/etc/routinator/routinator.conf 2>/dev/null" 2>/dev/null
        
        # Check memory and thread settings
        echo ""
        echo "Performance Settings:"
        ssh root@$SERVER "grep -E 'validation-threads|history-size|max-object-size' /etc/routinator/routinator.conf 2>/dev/null" 2>/dev/null
        
        # Check if Routinator is running
        echo ""
        echo "Service Status:"
        ssh root@$SERVER "systemctl is-active routinator 2>/dev/null || service routinator status 2>/dev/null | head -1" 2>/dev/null
        
        # Get memory usage
        echo ""
        echo "Memory Usage:"
        ssh root@$SERVER "ps aux | grep -E '^[^ ]*[ ]+[0-9]+.*routinator' | grep -v grep | awk '{print \"PID: \"\$2\" CPU: \"\$3\"%\" MEM: \"\$4\"%\" VSZ: \"\$5\" RSS: \"\$6}'" 2>/dev/null
        
        # Check recent errors in logs
        echo ""
        echo "Recent Errors (last 24 hours):"
        ssh root@$SERVER "journalctl -u routinator --since '24 hours ago' 2>/dev/null | grep -iE 'error|warning|fail|timeout|disconnect|reset|$ROUTER_IP' | tail -10" 2>/dev/null
        
        # Check RTR connections
        echo ""
        echo "Current RTR Connections:"
        ssh root@$SERVER "netstat -an | grep :3323 | grep -c ESTABLISHED" 2>/dev/null | while read count; do
            echo "  Established connections: $count"
        done
        ssh root@$SERVER "netstat -an | grep :3323 | grep $ROUTER_IP" 2>/dev/null | while read line; do
            echo "  Our router: $line"
        done
        
        # Check for connection drops in kernel
        echo ""
        echo "Network Statistics:"
        ssh root@$SERVER "netstat -s | grep -iE 'drop|timeout|reset|fail' | head -10" 2>/dev/null
        
        # Check systemd restart count
        echo ""
        echo "Service Restart History:"
        ssh root@$SERVER "systemctl show routinator -p NRestarts -p ActiveEnterTimestamp 2>/dev/null" 2>/dev/null
        
    else
        echo "✗ FAILED"
        echo "  Cannot connect to $SERVER via SSH"
        echo "  Please check SSH keys and connectivity"
    fi
    
    echo ""
done

echo "=========================================="
echo "Analysis Complete"
echo "=========================================="

# Recommendations based on common issues
echo ""
echo "RECOMMENDATIONS:"
echo "----------------"
echo "If you see disconnections, check these common issues:"
echo ""
echo "1. Memory exhaustion:"
echo "   - Reduce history-size in configuration"
echo "   - Lower max-object-size"
echo "   - Monitor RSS memory usage"
echo ""
echo "2. Timeout issues:"
echo "   - Default refresh=3600, retry=600, expire=7200"
echo "   - If reduced too much, can cause instability"
echo "   - Consider setting: refresh=1800, retry=300, expire=3600"
echo ""
echo "3. Thread contention:"
echo "   - validation-threads should match CPU cores"
echo "   - Too many threads can cause lock contention"
echo ""
echo "4. Network buffer issues:"
echo "   - Check for 'Connection reset by peer' errors"
echo "   - May need to tune TCP keepalive settings"
echo ""
echo "5. RTR protocol issues:"
echo "   - Check if dirty flag is set (forces cache flush)"
echo "   - Monitor for frequent cache resets"
echo ""

# Save report
REPORT_FILE="/var/log/huawei_rpki/routinator_tuning_$(date +%Y%m%d_%H%M%S).log"
echo "Report saved to: $REPORT_FILE"