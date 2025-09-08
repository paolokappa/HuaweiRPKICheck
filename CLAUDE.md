# Claude AI Assistant Instructions - v3.2

## Project Information
**Project**: HuaweiRPKICheck  
**Version**: 3.2 (September 8, 2025)
**Developer**: Paolo Caparrelli  
**Company**: GOLINE SA  
**Address**: Via Croce Campagna, 2 - 6855 Stabio - Switzerland  
**Website**: https://www.goline.ch  
**Support Email**: soc@goline.ch  
**GitHub**: https://github.com/paolokappa/HuaweiRPKICheck

## Project Overview
HuaweiRPKICheck is a monitoring tool for RPKI sessions on Huawei routers with Routinator integration. It monitors session states, detects issues, automatically recovers stuck sessions, and sends email alerts.

## Current System Status (v3.2)
- **Script Version**: 3.2 - Combined v2.0 email functionality with v3.1 timeout improvements
- **Email System**: ✅ Working (sends to soc@goline.ch)
- **Cron Exit Code**: ✅ Fixed (returns 0 except for fatal errors)
- **Timeout Settings**: 
  - Negotiation: 3 minutes (reduced from 30)
  - Connection: 30 seconds
  - Command: 20 seconds
- **Class Name**: RPKIChecker (unified)
- **No wrapper script needed** - exit codes handled in Python

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
- Always return exit code 0 except for fatal errors

### File Structure
```
/opt/HuaweiRPKICheck/
├── src/                      # Main source code
│   └── HuaweiRPKICheck.py   # Main script (v3.2)
├── config/                   # Configuration files (encrypted)
├── scripts/                  # Utility and monitoring scripts
├── tests/                    # Test scripts
├── docs/                     # Documentation
├── GitHub_Repo/             # Local GitHub repository
├── backups/                 # Automatic backups
│   ├── 20250908_190450/    # Working backup with emails
│   └── v3.2_20250908_*/    # Latest v3.2 backup
├── rpki_state.json          # State tracking file
└── HuaweiRPKICheck.py      # Symlink to src/HuaweiRPKICheck.py
```

### Cron Configuration
```bash
# Current working configuration (no wrapper needed)
*/15 * * * * /usr/bin/python3 /opt/HuaweiRPKICheck/HuaweiRPKICheck.py >> /var/log/huawei_rpki/cron.log 2>&1
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

### Email System
- **SMTP Server**: Configured in encrypted config
- **Recipient**: soc@goline.ch
- **Anti-spam**: Won't send duplicate alerts within 1 hour
- **Recovery alerts**: Sends when sessions recover
- **HTML emails**: Professional formatting with GOLINE branding

### Monitoring Best Practices
- Check sessions every 15 minutes via cron
- Reset stuck sessions automatically after 3 minutes
- Log all actions for audit trail
- Send alerts only when necessary (anti-spam)
- Track state in rpki_state.json

### Testing Checklist
Before committing changes:
1. Test main script: `python3 src/HuaweiRPKICheck.py --test`
2. Test production: `python3 src/HuaweiRPKICheck.py` (check exit code)
3. Verify email sending works
4. Check cron doesn't generate errors
5. Verify no sensitive data in commits

### Common Issues and Solutions

#### Sessions Stuck in Negotiation
- Now resets after 3 minutes (improved in v3.2)
- Check Routinator connectivity
- Verify network path

#### No Email Received
- Check rpki_state.json for last_alert timestamp
- Verify SMTP configuration
- Check logs in /var/log/huawei_rpki/

#### Cron Errors
- Fixed in v3.2 - script returns 0 for warnings
- Only returns non-zero for fatal errors

### Version History
- **v2.0**: Added email functionality, improved error handling
- **v3.1**: Enhanced timeout management  
- **v3.2**: Combined best of v2.0 and v3.1, fixed exit codes

### Deployment Steps
1. Backup current installation: `/opt/HuaweiRPKICheck/backups/`
2. Update script: `cp GitHub_Repo/HuaweiRPKICheck.py src/`
3. Test with `--test` flag
4. Monitor logs for 24 hours
5. No cron update needed (same filename)

### Environment Variables
- `BASE_DIR`: `/opt/HuaweiRPKICheck`
- `LOG_DIR`: `/var/log/huawei_rpki`
- `STATE_FILE`: `rpki_state.json`
- `CONFIG_FILE`: `HuaweiRPKICheck.conf`

### Monitored Routinator Servers
- lg.goline.ch (185.54.81.23)
- time.goline.ch (185.54.81.25)
- Both monitored continuously every 15 minutes

### Key Improvements in v3.2
1. **Faster recovery**: 3-minute timeout vs 30 minutes
2. **No wrapper needed**: Exit codes handled properly
3. **Unified codebase**: Best of both versions
4. **Maintained compatibility**: Same filename for cron
5. **Email system intact**: All notifications working

## Remember
- Keep it simple and maintainable
- Document significant changes
- Test thoroughly before production
- Monitor after deployment
- GitHub repo: https://github.com/paolokappa/HuaweiRPKICheck

## Last Update
- Date: September 8, 2025
- Version: 3.2
- Status: Production ready, fully tested
- Email: Working
- Cron: No errors