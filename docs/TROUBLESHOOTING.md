# Troubleshooting Guide

## Common Issues and Solutions

### 1. Sessions Stuck in "Negotiation" State

**Symptoms:**
- Log shows: `Session X.X.X.X stuck in Negotiation for Xm`
- Sessions never reach "Established" state
- Repeated reset attempts

**Cause:**
RTR protocol packet format error. Routinator expects specific packet structure.

**Solution:**
```python
# Correct RTR Reset Query format
struct.pack('!BBHI', 1, 2, 0, 8)
# Format: Version(1) + Type(1) + Reserved(2) + Length(4) = 8 bytes total
```

**Test:**
```bash
python3 /opt/HuaweiRPKICheck/scripts/test_rtr_connection.py
```

### 2. "No Sessions Retrieved" Error

**Symptoms:**
- Script connects but returns no session data
- Log shows: `ERROR - No sessions retrieved`

**Possible Causes:**
1. SSH connection issues
2. Command output format changed
3. Parsing pattern mismatch

**Debugging Steps:**
```bash
# Test SSH connection
python3 /opt/HuaweiRPKICheck/scripts/test_ssh_direct.py

# Test authentication
python3 /opt/HuaweiRPKICheck/scripts/debug_auth.py

# Test parsing
python3 /opt/HuaweiRPKICheck/scripts/debug_parsing.py
```

### 3. RTR Connection Failed

**Symptoms:**
- Cannot connect to Routinator servers
- RTR protocol errors

**Check:**
```bash
# Test RTR connectivity
python3 /opt/HuaweiRPKICheck/scripts/test_rtr_connection.py

# Check if Routinator is running
telnet lg.goline.ch 3323
telnet time.goline.ch 3323

# Test with correct packet format
python3 /opt/HuaweiRPKICheck/scripts/fix_rtr_protocol.py
```

### 4. Configuration File Issues

**Symptoms:**
- `KeyError: 'hostname'`
- Cannot decrypt configuration

**Solution:**
```bash
# Verify files exist
ls -la /opt/HuaweiRPKICheck/config/HuaweiRPKICheck.conf
ls -la /opt/HuaweiRPKICheck/secret.key

# Test decryption
python3 /opt/HuaweiRPKICheck/scripts/debug_auth.py
```

### 5. SSH Connection Timeout

**Symptoms:**
- Connection attempts timeout
- SSH session drops unexpectedly

**Solutions:**
1. Check network connectivity:
```bash
ping ROUTER_IP
nc -zv ROUTER_IP 22
```

2. Verify keepalive is working:
```python
# Check if keepalive thread is running
ps aux | grep HuaweiRPKICheck
```

3. Adjust timeout settings in script:
```python
CONNECTION_TIMEOUT = 30  # Increase if needed
COMMAND_TIMEOUT = 20     # Increase for slow responses
```

### 6. Monitoring Not Working

**Symptoms:**
- No automatic monitoring
- Cron job not running

**Check:**
```bash
# Check if monitor is running
ps aux | grep monitor_routinator

# Check cron job
crontab -l | grep HuaweiRPKICheck

# Start manual monitoring
python3 /opt/HuaweiRPKICheck/scripts/monitor_routinator_complete.py --once

# Check logs
tail -f /var/log/huawei_rpki/rpki_check_*.log
```

### 7. Email Alerts Not Sending

**Symptoms:**
- No email notifications
- SMTP errors in logs

**Debug:**
```python
# Test email configuration
import smtplib
from email.mime.text import MIMEText

# Load config and test SMTP connection
# Check firewall rules for SMTP port
```

## Log Files Location

- Main logs: `/var/log/huawei_rpki/rpki_check_YYYYMM.log`
- Monitor logs: `/var/log/huawei_rpki/monitor_continuous.log`
- Routinator monitor: `/var/log/huawei_rpki/routinator_monitor.log`
- State file: `/opt/HuaweiRPKICheck/rpki_state.json`

## Emergency Recovery

If everything fails:

1. **Restore from backup:**
```bash
cd /opt
tar -xzf HuaweiRPKICheck_backup_*.tar.gz
```

2. **Reset state:**
```bash
rm /opt/HuaweiRPKICheck/rpki_state.json
```

3. **Test with old version:**
```bash
python3 /opt/HuaweiRPKICheck/backups/HuaweiRPKICheck.py.backup_* --test
```

4. **Manual session reset on router:**
```
ssh router
display rpki session
reset rpki session X.X.X.X
```

## Performance Tuning

### Timeout Adjustments
Edit `/opt/HuaweiRPKICheck/src/HuaweiRPKICheck.py`:
```python
CONNECTION_TIMEOUT = 30           # SSH connection timeout
COMMAND_TIMEOUT = 20              # Command execution timeout  
NEGOTIATION_TIMEOUT_MINUTES = 3   # Max time in negotiation
ESTABLISHED_STUCK_MINUTES = 30    # Max time without records
MAX_RETRIES = 3                   # Connection retry attempts
```

### Monitoring Frequency
Edit crontab:
```bash
# Every 5 minutes (default)
*/5 * * * * /usr/bin/python3 /opt/HuaweiRPKICheck/HuaweiRPKICheck.py

# Every 10 minutes (reduced load)
*/10 * * * * /usr/bin/python3 /opt/HuaweiRPKICheck/HuaweiRPKICheck.py
```

## Contact Support

For issues not covered here:
1. Check GitHub Issues: https://github.com/paolokappa/HuaweiRPKICheck/issues
2. Review recent commits for changes
3. Enable verbose logging: `--verbose` flag
4. Collect diagnostic information:
   - Log files
   - `display rpki session` output
   - Routinator status