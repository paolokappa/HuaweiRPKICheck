# Claude AI Assistant Instructions

## Project Overview
HuaweiRPKICheck is a monitoring tool for RPKI sessions on Huawei routers with Routinator integration. It monitors session states, detects issues, and automatically recovers stuck sessions.

## Important Guidelines

### Security
- **NEVER** commit sensitive data (passwords, keys, real IPs) to GitHub
- Always use the encrypted configuration file system
- The `secret.key` file must remain local and secure
- Use example values in documentation

### Code Standards
- Maintain Python 3.6+ compatibility
- Follow existing code patterns and style
- Test changes in both test mode (`--test`) and production
- Preserve backward compatibility with cron jobs

### File Structure
```
/opt/HuaweiRPKICheck/
├── src/              # Main source code
├── config/           # Configuration files (encrypted)
├── scripts/          # Utility and monitoring scripts
├── tests/            # Test scripts
├── docs/             # Documentation
└── backups/          # Automatic backups
```

### Working with Encrypted Configs
The configuration is stored encrypted. To decrypt:
```python
from cryptography.fernet import Fernet

with open('secret.key', 'rb') as f:
    key = f.read()
    
with open('HuaweiRPKICheck.conf', 'rb') as f:
    encrypted = f.read()
    
fernet = Fernet(key)
decrypted = fernet.decrypt(encrypted).decode()
```

### RTR Protocol Notes
- Use correct packet format: `struct.pack('!BBHI', version, type, reserved, length)`
- Length field must be 8 for Reset Query
- Support both RTR v0 and v1
- Default RTR port: 3323

### Monitoring Best Practices
- Check sessions every 5 minutes via cron
- Reset stuck sessions automatically
- Log all actions for audit trail
- Send alerts only when necessary (avoid spam)

### Testing Checklist
Before committing changes:
1. Test SSH connectivity: `python3 scripts/test_ssh_direct.py`
2. Test RTR protocol: `python3 scripts/test_rtr_connection.py`
3. Test main script: `python3 src/HuaweiRPKICheck.py --test`
4. Check parsing: `python3 scripts/debug_parsing.py`
5. Verify no sensitive data in commits

### Common Issues and Solutions

#### Sessions Stuck in Negotiation
- Check RTR packet format
- Verify Routinator is responding
- Check network connectivity
- Review timeout settings

#### No Sessions Retrieved
- Verify SSH credentials
- Check command output format
- Test with `display rpki session`
- Verify parsing patterns match

#### RTR Connection Errors
- Test with `scripts/test_rtr_connection.py`
- Check Routinator logs
- Verify firewall rules
- Check RTR port (3323) is open

### Deployment Steps
1. Backup current installation
2. Update scripts in `/opt/HuaweiRPKICheck/`
3. Maintain symlinks for backward compatibility
4. Test with `--test` flag
5. Monitor logs for 24 hours
6. Update cron if needed

### Environment Variables
- `BASE_DIR`: `/opt/HuaweiRPKICheck`
- `LOG_DIR`: `/var/log/huawei_rpki`
- `STATE_FILE`: `rpki_state.json`

### Contact with Routinator Servers
- lg.goline.ch (185.54.81.23)
- time.goline.ch (185.54.81.25)
- Both should be monitored continuously

## Remember
- Keep it simple and maintainable
- Document significant changes
- Test thoroughly before production
- Monitor after deployment