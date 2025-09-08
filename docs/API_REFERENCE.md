# API Reference Documentation

## Table of Contents
- [Core Classes](#core-classes)
- [SSH Management](#ssh-management)
- [RTR Protocol](#rtr-protocol)
- [Monitoring Functions](#monitoring-functions)
- [Utility Functions](#utility-functions)
- [Configuration API](#configuration-api)
- [REST API Endpoints](#rest-api-endpoints)

---

## Core Classes

### HuaweiRPKIChecker

Main monitoring engine that orchestrates all RPKI checking operations.

```python
class HuaweiRPKIChecker:
    """
    Main RPKI monitoring class for Huawei routers.
    
    Attributes:
        config (dict): Encrypted configuration parameters
        ssh_client (EnhancedInteractiveSSH): SSH connection manager
        logger (Logger): Logging instance
        state (dict): Current monitoring state
    """
```

#### Methods

##### `__init__(config_file='HuaweiRPKICheck.conf', test_mode=False)`

Initialize the RPKI checker instance.

**Parameters:**
- `config_file` (str): Path to encrypted configuration file
- `test_mode` (bool): Enable test mode for dry-run operations

**Returns:**
- None

**Raises:**
- `FileNotFoundError`: If configuration file doesn't exist
- `CryptoError`: If decryption fails

**Example:**
```python
checker = HuaweiRPKIChecker(
    config_file='/opt/HuaweiRPKICheck/HuaweiRPKICheck.conf',
    test_mode=True
)
```

##### `get_rpki_sessions()`

Retrieve current RPKI sessions from Huawei router.

**Parameters:**
- None

**Returns:**
- `list[dict]`: List of session dictionaries containing:
  - `validator_ip` (str): IP address of validator
  - `state` (str): Session state (Established/Idle/Negotiation/Syn)
  - `last_update` (str): Time since last update
  - `ipv4_records` (int): Number of IPv4 ROA records
  - `ipv6_records` (int): Number of IPv6 ROA records

**Raises:**
- `SSHException`: If SSH connection fails
- `ParseError`: If output parsing fails

**Example:**
```python
sessions = checker.get_rpki_sessions()
for session in sessions:
    print(f"Validator: {session['validator_ip']}")
    print(f"State: {session['state']}")
    print(f"IPv4 Records: {session['ipv4_records']}")
```

##### `analyze_sessions(sessions)`

Analyze session health and identify issues.

**Parameters:**
- `sessions` (list[dict]): List of session dictionaries

**Returns:**
- `dict`: Analysis results containing:
  - `total` (int): Total number of sessions
  - `established` (int): Number of established sessions
  - `idle` (int): Number of idle sessions
  - `negotiating` (int): Number of negotiating sessions
  - `syncing` (int): Number of syncing sessions
  - `issues` (list): List of identified issues
  - `need_reset` (list): Sessions requiring reset

**Example:**
```python
analysis = checker.analyze_sessions(sessions)
if analysis['issues']:
    for issue in analysis['issues']:
        print(f"Issue detected: {issue}")
```

##### `reset_session(validator_ip)`

Reset a stuck RPKI session.

**Parameters:**
- `validator_ip` (str): IP address of validator to reset

**Returns:**
- `bool`: True if reset successful, False otherwise

**Raises:**
- `SSHException`: If SSH command fails
- `TimeoutError`: If reset times out

**Example:**
```python
success = checker.reset_session('185.54.81.23')
if success:
    print("Session reset successfully")
```

---

## SSH Management

### EnhancedInteractiveSSH

Enhanced SSH client with interactive shell support and keepalive functionality.

```python
class EnhancedInteractiveSSH:
    """
    Enhanced SSH client for Huawei router management.
    
    Features:
    - Interactive shell support
    - Automatic keepalive threads
    - Connection pooling
    - Retry logic with exponential backoff
    """
```

#### Methods

##### `connect(hostname, username, password, port=22, timeout=30)`

Establish SSH connection to router.

**Parameters:**
- `hostname` (str): Router hostname or IP
- `username` (str): SSH username
- `password` (str): SSH password
- `port` (int): SSH port (default: 22)
- `timeout` (int): Connection timeout in seconds

**Returns:**
- `bool`: True if connection successful

**Raises:**
- `AuthenticationException`: If authentication fails
- `SSHException`: If connection fails

**Example:**
```python
ssh = EnhancedInteractiveSSH()
connected = ssh.connect(
    hostname='192.168.1.1',
    username='admin',
    password='encrypted_pass',
    timeout=30
)
```

##### `execute_command(command, timeout=60)`

Execute command on router via interactive shell.

**Parameters:**
- `command` (str): Command to execute
- `timeout` (int): Command timeout in seconds

**Returns:**
- `str`: Command output

**Raises:**
- `TimeoutError`: If command times out
- `SSHException`: If execution fails

**Example:**
```python
output = ssh.execute_command('display rpki session')
print(output)
```

##### `start_keepalive(interval=30)`

Start keepalive thread to maintain connection.

**Parameters:**
- `interval` (int): Keepalive interval in seconds

**Returns:**
- `Thread`: Keepalive thread instance

**Example:**
```python
keepalive_thread = ssh.start_keepalive(interval=30)
```

---

## RTR Protocol

### RTRProtocolHandler

Implementation of RPKI-to-Router protocol (RFC 8210).

```python
class RTRProtocolHandler:
    """
    RTR protocol handler for RPKI validation.
    
    Implements:
    - RTR v0 and v1 support
    - Packet encoding/decoding
    - Session management
    - Error recovery
    """
```

#### Methods

##### `connect(host, port=3323, timeout=30)`

Connect to RTR server (Routinator).

**Parameters:**
- `host` (str): Routinator host
- `port` (int): RTR port (default: 3323)
- `timeout` (int): Connection timeout

**Returns:**
- `socket`: Connected socket object

**Raises:**
- `ConnectionError`: If connection fails
- `TimeoutError`: If connection times out

##### `send_reset_query(version=1)`

Send RTR Reset Query packet.

**Parameters:**
- `version` (int): RTR protocol version (0 or 1)

**Returns:**
- `bytes`: Response packet

**Raises:**
- `ProtocolError`: If invalid response received

**Example:**
```python
rtr = RTRProtocolHandler()
rtr.connect('routinator.example.com')
response = rtr.send_reset_query(version=1)
```

##### `parse_packet(data)`

Parse RTR protocol packet.

**Parameters:**
- `data` (bytes): Raw packet data

**Returns:**
- `dict`: Parsed packet containing:
  - `version` (int): Protocol version
  - `type` (int): PDU type
  - `session_id` (int): Session identifier
  - `length` (int): Packet length
  - `payload` (bytes): Packet payload

**Example:**
```python
packet = rtr.parse_packet(response_data)
print(f"PDU Type: {packet['type']}")
print(f"Session ID: {packet['session_id']}")
```

---

## Monitoring Functions

### Session Monitoring

##### `monitor_session_health(session, thresholds=None)`

Monitor individual session health metrics.

**Parameters:**
- `session` (dict): Session dictionary
- `thresholds` (dict): Custom thresholds (optional)

**Returns:**
- `dict`: Health metrics including:
  - `status` (str): Health status (healthy/warning/critical)
  - `metrics` (dict): Performance metrics
  - `recommendations` (list): Suggested actions

**Default Thresholds:**
```python
DEFAULT_THRESHOLDS = {
    'negotiation_timeout': 180,  # 3 minutes
    'established_stuck': 1800,   # 30 minutes
    'syn_timeout': 120,          # 2 minutes
    'min_ipv4_records': 100000,  # Minimum expected records
    'max_idle_time': 300         # 5 minutes
}
```

### Performance Monitoring

##### `collect_performance_metrics()`

Collect system performance metrics.

**Returns:**
- `dict`: Performance metrics:
  - `cpu_usage` (float): CPU utilization percentage
  - `memory_usage` (float): Memory usage in MB
  - `network_latency` (dict): Latency to validators
  - `session_recovery_time` (float): Average recovery time
  - `uptime` (float): System uptime in hours

**Example:**
```python
metrics = collect_performance_metrics()
print(f"CPU Usage: {metrics['cpu_usage']}%")
print(f"Memory: {metrics['memory_usage']}MB")
```

---

## Utility Functions

### Encryption Utilities

##### `encrypt_config(plaintext_config, key_file='secret.key')`

Encrypt configuration data using Fernet.

**Parameters:**
- `plaintext_config` (str): Plain text configuration
- `key_file` (str): Path to encryption key file

**Returns:**
- `bytes`: Encrypted configuration

**Example:**
```python
encrypted = encrypt_config(config_text)
with open('HuaweiRPKICheck.conf', 'wb') as f:
    f.write(encrypted)
```

##### `decrypt_config(encrypted_config, key_file='secret.key')`

Decrypt configuration data.

**Parameters:**
- `encrypted_config` (bytes): Encrypted configuration
- `key_file` (str): Path to encryption key file

**Returns:**
- `str`: Decrypted configuration

**Example:**
```python
with open('HuaweiRPKICheck.conf', 'rb') as f:
    encrypted = f.read()
config = decrypt_config(encrypted)
```

### Parsing Utilities

##### `parse_huawei_output(output, pattern=None)`

Parse Huawei command output.

**Parameters:**
- `output` (str): Raw command output
- `pattern` (str): Custom regex pattern (optional)

**Returns:**
- `list[dict]`: Parsed data

**Default Pattern:**
```python
DEFAULT_PATTERN = (
    r'(\d+\.\d+\.\d+\.\d+)\s+'
    r'(Established|Idle|Negotiation|Syn)\s+'
    r'(\S+)\s+(\d+)/(\d+)'
)
```

### Logging Utilities

##### `setup_logger(name, level='INFO', log_file=None)`

Configure logger instance.

**Parameters:**
- `name` (str): Logger name
- `level` (str): Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)
- `log_file` (str): Optional log file path

**Returns:**
- `Logger`: Configured logger instance

**Example:**
```python
logger = setup_logger(
    'rpki_monitor',
    level='DEBUG',
    log_file='/var/log/rpki_monitor.log'
)
```

---

## Configuration API

### ConfigManager

##### `load_config(config_file)`

Load and decrypt configuration.

**Parameters:**
- `config_file` (str): Path to configuration file

**Returns:**
- `dict`: Configuration dictionary

**Configuration Structure:**
```python
{
    'router': {
        'hostname': '192.168.1.1',
        'username': 'admin',
        'password': 'encrypted_password',
        'port': 22
    },
    'validators': [
        {
            'name': 'lg.goline.ch',
            'ip': '185.54.81.23',
            'port': 3323
        },
        {
            'name': 'time.goline.ch',
            'ip': '185.54.81.25',
            'port': 3323
        }
    ],
    'monitoring': {
        'check_interval': 300,
        'timeout': 30,
        'max_retries': 3
    },
    'alerting': {
        'smtp_server': 'mail.example.com',
        'smtp_port': 587,
        'from_email': 'rpki@example.com',
        'to_emails': ['noc@example.com']
    }
}
```

### Environment Variables

```python
# Supported environment variables
RPKI_CONFIG_FILE = os.getenv('RPKI_CONFIG_FILE', '/opt/HuaweiRPKICheck/HuaweiRPKICheck.conf')
RPKI_LOG_LEVEL = os.getenv('RPKI_LOG_LEVEL', 'INFO')
RPKI_LOG_DIR = os.getenv('RPKI_LOG_DIR', '/var/log/huawei_rpki')
RPKI_STATE_FILE = os.getenv('RPKI_STATE_FILE', 'rpki_state.json')
RPKI_CHECK_INTERVAL = os.getenv('RPKI_CHECK_INTERVAL', '300')
RPKI_MAX_RETRIES = os.getenv('RPKI_MAX_RETRIES', '3')
```

---

## REST API Endpoints

### Optional REST API Server

##### `GET /api/v1/status`

Get current system status.

**Response:**
```json
{
    "status": "healthy",
    "timestamp": "2025-01-08T10:30:45Z",
    "sessions": {
        "total": 2,
        "established": 2,
        "idle": 0,
        "negotiating": 0
    },
    "uptime_hours": 168.5
}
```

##### `GET /api/v1/sessions`

Get all RPKI sessions.

**Response:**
```json
{
    "sessions": [
        {
            "validator_ip": "185.54.81.23",
            "state": "Established",
            "ipv4_records": 588576,
            "ipv6_records": 123456,
            "last_update": "00:05:23",
            "health": "healthy"
        }
    ]
}
```

##### `POST /api/v1/sessions/{validator_ip}/reset`

Reset specific session.

**Parameters:**
- `validator_ip` (str): Validator IP address

**Request Body:**
```json
{
    "force": false,
    "reason": "Manual reset requested"
}
```

**Response:**
```json
{
    "success": true,
    "message": "Session reset initiated",
    "timestamp": "2025-01-08T10:35:00Z"
}
```

##### `GET /api/v1/metrics`

Get Prometheus-compatible metrics.

**Response:**
```
# HELP rpki_sessions_total Total number of RPKI sessions
# TYPE rpki_sessions_total gauge
rpki_sessions_total 2

# HELP rpki_sessions_established Number of established sessions
# TYPE rpki_sessions_established gauge
rpki_sessions_established 2

# HELP rpki_ipv4_records_total Total IPv4 ROA records
# TYPE rpki_ipv4_records_total gauge
rpki_ipv4_records_total 1177152

# HELP rpki_reset_operations_total Total reset operations performed
# TYPE rpki_reset_operations_total counter
rpki_reset_operations_total 5
```

##### `GET /api/v1/alerts`

Get active alerts.

**Response:**
```json
{
    "alerts": [
        {
            "id": "alert-001",
            "severity": "warning",
            "timestamp": "2025-01-08T10:20:00Z",
            "message": "Session to 185.54.81.25 in negotiation for 2 minutes",
            "validator_ip": "185.54.81.25",
            "acknowledged": false
        }
    ]
}
```

##### `PUT /api/v1/alerts/{alert_id}/acknowledge`

Acknowledge an alert.

**Parameters:**
- `alert_id` (str): Alert identifier

**Request Body:**
```json
{
    "acknowledged_by": "admin",
    "notes": "Investigating issue"
}
```

---

## Error Codes

### SSH Errors
- `SSH001`: Authentication failed
- `SSH002`: Connection timeout
- `SSH003`: Command execution failed
- `SSH004`: Keepalive failed

### RTR Protocol Errors
- `RTR001`: Invalid packet format
- `RTR002`: Unsupported protocol version
- `RTR003`: Session negotiation failed
- `RTR004`: Connection reset by peer

### Configuration Errors
- `CFG001`: Configuration file not found
- `CFG002`: Decryption failed
- `CFG003`: Invalid configuration format
- `CFG004`: Missing required parameter

### Monitoring Errors
- `MON001`: Session parse error
- `MON002`: Analysis failed
- `MON003`: Reset operation failed
- `MON004`: State persistence error

---

## Code Examples

### Complete Monitoring Cycle

```python
#!/usr/bin/env python3
"""
Example: Complete monitoring cycle implementation
"""

import sys
import logging
from HuaweiRPKICheck import HuaweiRPKIChecker

def main():
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Initialize checker
        checker = HuaweiRPKIChecker(
            config_file='/opt/HuaweiRPKICheck/HuaweiRPKICheck.conf'
        )
        
        # Get sessions
        sessions = checker.get_rpki_sessions()
        
        # Analyze
        analysis = checker.analyze_sessions(sessions)
        
        # Handle issues
        if analysis['need_reset']:
            for session in analysis['need_reset']:
                success = checker.reset_session(session['validator_ip'])
                if success:
                    logging.info(f"Reset successful: {session['validator_ip']}")
                else:
                    logging.error(f"Reset failed: {session['validator_ip']}")
        
        # Report status
        print(f"Total sessions: {analysis['total']}")
        print(f"Established: {analysis['established']}")
        print(f"Issues found: {len(analysis['issues'])}")
        
    except Exception as e:
        logging.error(f"Monitoring failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
```

### Custom Alert Handler

```python
class CustomAlertHandler:
    """
    Custom alert handler with multiple notification channels
    """
    
    def __init__(self, config):
        self.config = config
        self.channels = self._setup_channels()
    
    def _setup_channels(self):
        channels = []
        
        if self.config.get('email'):
            channels.append(EmailChannel(self.config['email']))
        
        if self.config.get('slack'):
            channels.append(SlackChannel(self.config['slack']))
        
        if self.config.get('webhook'):
            channels.append(WebhookChannel(self.config['webhook']))
        
        return channels
    
    def send_alert(self, alert):
        """Send alert through all configured channels"""
        for channel in self.channels:
            try:
                channel.send(alert)
            except Exception as e:
                logging.error(f"Channel {channel} failed: {e}")
```

---

**© 2024-2025 GOLINE SA - Switzerland**  
**Author:** Paolo Caparrelli  
**Website:** https://www.goline.ch  
**Support:** soc@goline.ch