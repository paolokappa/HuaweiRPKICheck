# HuaweiRPKICheck v2.0

This project provides an automated monitoring and recovery system for Huawei NetEngine RPKI sessions. The main purpose is to address a known issue with Huawei NetEngine routers where RPKI sessions fail to automatically reset when the RPKI server becomes available after an outage.

## 🆕 What's New in v2.0

### Major Enhancements
- **🔄 Automatic Recovery Detection**: Now sends notifications when sessions recover from problematic states
- **⏰ Smart Timeout Management**: Automatically resets sessions stuck in Negotiation for more than 30 minutes
- **📧 Improved Email Templates**: Professional HTML emails with consistent styling and better readability
- **📊 Enhanced State Tracking**: Persistent state management to track session history and prevent duplicate alerts
- **🎨 Visual Status Indicators**: Color-coded session states with emoji indicators for quick status identification

### Key Improvements
- Recovery notifications with green success indicators
- Configurable timeout thresholds for session resets
- Better error handling and logging
- Reduced false positives through intelligent state comparison

## Purpose of the Project

Huawei NetEngine routers have a bug where RPKI sessions do not automatically reset when the RPKI server becomes available after an outage. This can lead to routing issues that affect network security. This project automates the process of monitoring the status of RPKI sessions, automatically resetting problematic sessions, and notifying administrators of both issues and recoveries.

## How It Works

The monitoring system follows this workflow:

1. **Connection**: Establishes SSH connection to the Huawei router
2. **Monitoring**: Executes `display rpki session` command every 15 minutes (via cron)
3. **Analysis**: Evaluates session states:
   - ✅ **Established**: Session is healthy with active prefixes
   - ⚠️ **Idle**: Session is inactive (triggers reset if 0 prefixes)
   - 🔄 **Negotiation**: Session is connecting (triggers reset if >30 minutes)
   - 🔶 **Syn**: Session in synchronization phase
4. **Action**: Automatically resets problematic sessions
5. **Notification**: Sends appropriate email alerts:
   - 🔴 **Problem Alert**: Blue header with red border, sent when issues detected
   - ✅ **Recovery Alert**: Blue header with green border, sent when sessions recover

## Project Structure

This project consists of two main scripts:

1. **Credential Encryption Script** (`HuaweiRPKI_credgen.py`):  
   Used to securely generate and store encrypted credentials (such as SSH, SMTP, and email credentials) in a configuration file.
   
2. **RPKI Session Monitor and Reset Script** (`HuaweiRPKICheck.py`):  
   Monitors the RPKI sessions on a Huawei NetEngine router, identifies problematic sessions, automatically resets them, and sends notifications for both problems and recoveries.

---

## Installation and Setup

### Prerequisites
- Python 3.6 or higher
- SSH access to Huawei NetEngine router
- SMTP server for email notifications

### Step 1: Install Dependencies

```bash
pip install paramiko cryptography
```

### Step 2: Configure Credentials

1. Create a configuration file from the example:
```bash
cp HuaweiRPKICheck.conf.example HuaweiRPKICheck.conf
```

2. Edit the configuration with your settings:
```ini
hostname=192.168.1.1          # Your router IP
username=admin                # SSH username
password=your_password        # SSH password
smtp_server=mail.example.com  # SMTP server
smtp_port=587                 # SMTP port
smtp_username=user@example.com # SMTP username
smtp_password=smtp_pass       # SMTP password
email_sender=rpki@example.com # From address
email_receiver=noc@example.com # To address (can be comma-separated for multiple)
```

3. Encrypt the credentials:
```bash
python3 HuaweiRPKI_credgen.py
```

This generates:
- `secret.key`: Encryption key (keep this secure!)
- `HuaweiRPKICheck.conf`: Encrypted configuration

### Step 3: Test the Script

Run in test mode to verify configuration without making changes:
```bash
python3 HuaweiRPKICheck.py --test
```

### Step 4: Schedule with Cron

Add to crontab for automatic monitoring every 15 minutes:
```bash
crontab -e
```

Add this line:
```bash
*/15 * * * * /usr/bin/python3 /opt/HuaweiRPKICheck/HuaweiRPKICheck.py >/dev/null 2>&1
```

---

## Email Notification Templates

### Problem Alert Email
Sent when sessions have issues (Idle, Negotiation >30min, Syn):

- **Header**: Blue background (#1e3c72) with red bottom border
- **Status**: Shows issue count and severity
- **Table**: Session details with color-coded states
  - 🟢 Green: Established sessions
  - ⚠️ Yellow: Idle/Negotiation sessions
  - 🔴 Red: Error states
- **Actions**: Automated reset notification and recommended manual checks

### Recovery Notification Email
Sent when sessions recover to Established state:

- **Header**: Blue background (#1e3c72) with green bottom border
- **Status**: "✅ SESSIONS RECOVERED" indicator
- **Table**: Current healthy session status
- **Summary**: Lists recovered sessions and confirms operational status

Both emails include:
- Professional GOLINE SA branding
- Responsive HTML design
- Clear visual indicators
- Detailed session information table
- Timestamp and device information

---

## Command Line Options

```bash
python3 HuaweiRPKICheck.py [options]
```

Options:
- `--test`: Run in test mode (no changes, no emails)
- `--verbose`: Enable verbose logging
- `--config PATH`: Specify custom config file path
- `--key PATH`: Specify custom key file path

---

## Troubleshooting

### Sessions Not Resetting
- Verify SSH credentials and connectivity
- Check user permissions for `reset rpki session` command
- Review logs in `/var/log/huawei_rpki/`

### Emails Not Received
- Check spam/junk folder
- Verify SMTP settings and firewall rules
- Test SMTP connectivity: `telnet smtp_server port`
- Check logs for SMTP errors

### False Positives
- Adjust the Negotiation timeout threshold in the code (default: 30 minutes)
- Verify network connectivity between router and RPKI servers

---

## File Structure

```
/opt/HuaweiRPKICheck/
├── HuaweiRPKICheck.py        # Main monitoring script
├── HuaweiRPKI_credgen.py     # Credential encryption utility
├── HuaweiRPKICheck.conf      # Encrypted configuration
├── secret.key                # Encryption key (protect this!)
├── rpki_state.json           # State tracking file
└── /var/log/huawei_rpki/     # Log directory
    └── rpki_check_YYYYMM.log # Monthly rotating logs
```

---

## Security Considerations

1. **Never commit** `secret.key` or unencrypted configuration files to version control
2. Set restrictive permissions on sensitive files:
   ```bash
   chmod 600 secret.key HuaweiRPKICheck.conf
   chmod 700 HuaweiRPKICheck.py
   ```
3. Use strong, unique passwords for router and SMTP access
4. Consider implementing SSH key-based authentication (future enhancement)
5. Regularly rotate credentials and encryption keys

---

## Version History

### v2.0 (2024-09)
- Added automatic recovery detection and notifications
- Implemented smart timeout for stuck Negotiation sessions
- Redesigned email templates with consistent styling
- Added persistent state management
- Improved error handling and logging
- Enhanced session analysis logic

### v1.0 (2024)
- Initial release
- Basic RPKI session monitoring
- Automatic session reset for problematic states
- Email alerts for session issues

---

## Known Issues and Limitations

- Huawei NetEngine bug: RPKI sessions don't automatically recover after server outage (this project works around this issue)
- Maximum email frequency: Problem alerts once per hour, recovery alerts once per 30 minutes
- SSH password authentication only (key-based auth planned for future)

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request with clear description

---

## License

MIT License - See LICENSE file for details

---

## Author

Paolo Kappa - [GitHub](https://github.com/paolokappa)

---

## Support

For issues, questions, or suggestions:
- Open an issue on [GitHub](https://github.com/paolokappa/HuaweiRPKICheck/issues)
- Check the logs in `/var/log/huawei_rpki/` for debugging

---

## Acknowledgments

- Thanks to the network engineering community for identifying and documenting the Huawei RPKI session bug
- GOLINE SA for supporting the development and testing of this solution