# Changelog

All notable changes to HuaweiRPKICheck project will be documented in this file.

## [3.1.0] - 2025-09-08

### Fixed
- **Critical**: Fixed RTR protocol packet format causing "invalid length" errors
  - Changed from `struct.pack('!BBHHI', ...)` to `struct.pack('!BBHI', ...)`
  - This was causing sessions to get stuck in "Negotiation" state
- Fixed parsing of Huawei RPKI session output format
- Corrected error in session analysis (type error with total count)
- Fixed encrypted configuration file loading

### Added
- Thread-based keepalive mechanism for SSH connections
- Retry logic with exponential backoff (max 3 attempts)
- Comprehensive monitoring scripts suite:
  - `monitor_routinator_complete.py`: Full monitoring with RTR protocol testing
  - `test_rtr_connection.py`: RTR protocol connectivity tester
  - `decode_rtr_error.py`: RTR error decoder
  - `test_ssh_direct.py`: Direct SSH connection tester
  - `debug_auth.py`: Authentication debugger
  - `debug_parsing.py`: Output parsing debugger
- Enhanced error handling and recovery
- Support for both RTR protocol versions (0 and 1)
- Automatic session reset for stuck connections

### Changed
- **Reduced timeout values for faster recovery:**
  - NEGOTIATION_TIMEOUT: 5 minutes → 3 minutes
  - ESTABLISHED_STUCK: 60 minutes → 30 minutes
- Improved SSH connection management with connection pooling
- Enhanced logging with more detailed error messages
- Better handling of encrypted configuration files
- Reorganized project structure with dedicated directories

### Project Structure
```
/opt/HuaweiRPKICheck/
├── src/              # Source code
├── config/           # Configuration files
├── scripts/          # Utility scripts
├── tests/            # Test scripts
├── docs/             # Documentation
└── backups/          # Backup files
```

## [3.0.0] - 2025-09-04

### Added
- Interactive SSH shell support for better command execution
- Enhanced session state tracking
- Improved email notifications with HTML formatting

### Changed
- Refactored SSH connection handling
- Updated command execution method

## [2.0.0] - 2025-08-23

### Added
- Encryption support for configuration files
- State persistence between runs
- Automatic recovery detection
- Enhanced logging with rotation

### Security
- Credentials now stored encrypted
- Added secret key management

## [1.0.0] - 2024-09-16

### Initial Release
- Basic RPKI session monitoring
- SSH connection to Huawei routers
- Email alerts for issues
- Simple session state checking