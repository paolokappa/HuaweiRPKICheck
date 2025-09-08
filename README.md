# HuaweiRPKICheck

[![Version](https://img.shields.io/badge/version-3.1.0-blue.svg)](https://github.com/paolokappa/HuaweiRPKICheck)
[![Python](https://img.shields.io/badge/python-3.6%2B-green.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)

Automated RPKI session monitoring and management system for Huawei routers with Routinator integration.

## 🎯 Overview

HuaweiRPKICheck is a comprehensive monitoring solution that:
- Monitors RPKI sessions between Huawei routers and Routinator validators
- Automatically detects and recovers stuck sessions
- Provides real-time alerts and detailed logging
- Supports encrypted credential storage
- Includes extensive debugging and troubleshooting tools

## 🚀 Features

- **Automatic Session Recovery**: Detects and resets stuck sessions (Negotiation, Idle, Syn states)
- **Enhanced Stability**: Keepalive threads, retry logic with exponential backoff
- **RTR Protocol Support**: Compatible with RTR v0 and v1, proper packet formatting
- **Secure Configuration**: Encrypted credential storage using Fernet
- **Comprehensive Monitoring**: Multiple monitoring scripts for different aspects
- **Email Alerts**: HTML-formatted notifications with session details
- **Extensive Logging**: Rotating logs with configurable verbosity

## 📋 Requirements

- Python 3.6+
- Huawei router with RPKI support
- Routinator RPKI validator
- Network access to router (SSH) and Routinator (RTR port 3323)

### Python Dependencies

```bash
pip3 install -r requirements.txt
```

Dependencies:
- paramiko>=2.7.2
- cryptography>=3.4.8

## 🔧 Installation

1. **Clone the repository:**
```bash
cd /opt
git clone https://github.com/paolokappa/HuaweiRPKICheck.git
cd HuaweiRPKICheck
```

2. **Install dependencies:**
```bash
pip3 install -r requirements.txt
```

3. **Create configuration:**
```bash
cp HuaweiRPKICheck.conf.example HuaweiRPKICheck.conf
# Edit with your settings
nano HuaweiRPKICheck.conf
```

4. **Encrypt configuration:**
```bash
python3 HuaweiRPKI_credgen.py
```

5. **Set up cron job:**
```bash
crontab -e
# Add this line for checks every 5 minutes:
*/5 * * * * /usr/bin/python3 /opt/HuaweiRPKICheck/HuaweiRPKICheck.py
```

## 📁 Project Structure

```
/opt/HuaweiRPKICheck/
├── src/
│   └── HuaweiRPKICheck.py          # Main monitoring script
├── config/
│   ├── HuaweiRPKICheck.conf        # Encrypted configuration
│   └── HuaweiRPKICheck.conf.example # Configuration template
├── scripts/
│   ├── monitor_routinator_complete.py  # Complete monitoring solution
│   ├── test_rtr_connection.py         # RTR protocol tester
│   ├── test_ssh_direct.py             # SSH connectivity tester
│   ├── debug_auth.py                  # Authentication debugger
│   └── debug_parsing.py               # Output parsing debugger
├── docs/
│   ├── TROUBLESHOOTING.md            # Troubleshooting guide
│   └── CLAUDE.md                     # AI assistant instructions
├── tests/                             # Test scripts
├── backups/                           # Automatic backups
├── secret.key                         # Encryption key (DO NOT SHARE)
└── rpki_state.json                   # Session state tracking
```

## 🔐 Configuration

### Example Configuration File

```ini
# Network settings
hostname=192.168.1.1        # Router IP address
username=admin              # SSH username
password=your_password      # SSH password

# Email settings (optional)
smtp_server=mail.example.com
smtp_port=587
smtp_username=rpki@example.com
smtp_password=smtp_password
email_sender=rpki@example.com
email_receiver=noc@example.com
```

### Security Notes

- Configuration file is encrypted using Fernet symmetric encryption
- `secret.key` file must be kept secure and never shared
- Use strong, unique passwords
- Consider implementing SSH key-based authentication (future enhancement)

## 💻 Usage

### Manual Testing

```bash
# Test mode (no changes made)
python3 /opt/HuaweiRPKICheck/src/HuaweiRPKICheck.py --test

# Verbose output
python3 /opt/HuaweiRPKICheck/src/HuaweiRPKICheck.py --test --verbose

# Production run
python3 /opt/HuaweiRPKICheck/src/HuaweiRPKICheck.py
```

### Monitoring Scripts

```bash
# Complete monitoring with RTR testing
python3 scripts/monitor_routinator_complete.py --once

# Continuous monitoring (every 60 seconds)
python3 scripts/monitor_routinator_complete.py --interval 60

# Test RTR connectivity
python3 scripts/test_rtr_connection.py

# Debug SSH connection
python3 scripts/test_ssh_direct.py

# Debug authentication
python3 scripts/debug_auth.py
```

## 🔍 Troubleshooting

### Common Issues

1. **Sessions stuck in "Negotiation"**
   - Usually caused by RTR protocol issues
   - Run: `python3 scripts/test_rtr_connection.py`

2. **"No sessions retrieved" error**
   - Check SSH connectivity: `python3 scripts/test_ssh_direct.py`
   - Verify parsing: `python3 scripts/debug_parsing.py`

3. **Authentication failures**
   - Test credentials: `python3 scripts/debug_auth.py`
   - Verify encrypted config is readable

See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for detailed solutions.

## 📊 Session States

The script monitors and manages these RPKI session states:

- **Established**: Normal operating state with active record exchange
- **Idle**: Session is down, needs investigation
- **Negotiation**: Session establishing, should be temporary
- **Syn/Sync**: Synchronizing, should resolve quickly

### Automatic Recovery

Sessions are automatically reset if:
- Stuck in Negotiation > 3 minutes
- Stuck in Syn > 2 minutes  
- Established but no records > 30 minutes
- Any Idle state detected

## 📈 Monitoring Output Example

```
RPKI Session Status:
  Total sessions: 2
  Established: 2
  Idle: 0
  Negotiating: 0
  Need reset: 0
  Healthy: True

Session Details:
  routinator1.example.com - Established - 588576 IPv4 records
  routinator2.example.com - Established - 588552 IPv4 records
```

## 🐛 Recent Fixes (v3.1.0)

### RTR Protocol Fix
The main issue causing disconnections was an incorrect RTR packet format:

```python
# OLD (incorrect) - caused "invalid length" errors
struct.pack('!BBHHI', 1, 2, 0, 0, 8)

# NEW (correct) - proper RTR format
struct.pack('!BBHI', 1, 2, 0, 8)
```

This fix resolved sessions getting stuck in "Negotiation" state with Routinator.

## 📝 Logs

Log files are stored in `/var/log/huawei_rpki/`:
- `rpki_check_YYYYMM.log` - Main monitoring log
- `routinator_monitor.log` - Routinator connectivity log
- `monitor_continuous.log` - Continuous monitoring output

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Support

For issues or questions:
- Open an issue on [GitHub](https://github.com/paolokappa/HuaweiRPKICheck/issues)
- Check the [Troubleshooting Guide](docs/TROUBLESHOOTING.md)
- Review the [Changelog](CHANGELOG.md) for recent changes

## 🙏 Acknowledgments

- Huawei for router platform
- NLnet Labs for Routinator
- Contributors and testers

---

**Security Notice**: Never commit sensitive data (passwords, keys, real IPs) to version control. Always use the encrypted configuration system.