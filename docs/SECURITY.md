# Security Hardening Guide

## Table of Contents
- [Security Overview](#security-overview)
- [Threat Model](#threat-model)
- [Security Controls](#security-controls)
- [Hardening Checklist](#hardening-checklist)
- [Credential Management](#credential-management)
- [Network Security](#network-security)
- [Audit and Compliance](#audit-and-compliance)
- [Incident Response](#incident-response)

---

## Security Overview

HuaweiRPKICheck implements defense-in-depth security architecture to protect critical BGP infrastructure from various threat vectors.

### Security Principles

1. **Least Privilege**: Minimal permissions required for operation
2. **Defense in Depth**: Multiple security layers
3. **Zero Trust**: Verify everything, trust nothing
4. **Encryption Everywhere**: All sensitive data encrypted
5. **Audit Everything**: Complete audit trail

### Security Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Security Perimeter                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Application Layer                    │  │
│  │  ┌────────────────────────────────────────────┐ │  │
│  │  │   Input Validation | Output Encoding        │ │  │
│  │  │   Authentication   | Authorization          │ │  │
│  │  │   Session Mgmt     | Error Handling         │ │  │
│  │  └────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Data Protection Layer                │  │
│  │  ┌────────────────────────────────────────────┐ │  │
│  │  │   Encryption at Rest  | Key Management      │ │  │
│  │  │   Encryption in Transit| Data Sanitization  │ │  │
│  │  └────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Network Layer                        │  │
│  │  ┌────────────────────────────────────────────┐ │  │
│  │  │   Firewall Rules    | Network Segmentation  │ │  │
│  │  │   IDS/IPS           | VPN/IPSec            │ │  │
│  │  └────────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────────┘  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## Threat Model

### Threat Actors

| Actor | Motivation | Capability | Mitigation |
|-------|-----------|------------|------------|
| **External Attacker** | Disruption, Data theft | High | Firewall, Encryption, Authentication |
| **Insider Threat** | Sabotage, Data leak | Medium | Audit logging, Least privilege |
| **Compromised System** | Lateral movement | High | Network segmentation, Monitoring |
| **Supply Chain** | Backdoor, Malware | Low | Code review, Dependency scanning |

### Attack Vectors

#### 1. SSH Compromise
**Risk**: High  
**Attack**: Credential theft, brute force, man-in-the-middle  
**Mitigation**:
```python
# Implement key-based authentication
ssh_config = {
    'auth_method': 'key',
    'private_key_file': '/secure/path/id_rsa',
    'passphrase': encrypted_passphrase,
    'allowed_ciphers': ['aes256-gcm', 'chacha20-poly1305'],
    'kex_algorithms': ['curve25519-sha256', 'ecdh-sha2-nistp256']
}
```

#### 2. Configuration Tampering
**Risk**: Medium  
**Attack**: Modify encrypted config, inject malicious settings  
**Mitigation**:
```python
# Implement configuration integrity checking
import hashlib
import hmac

def verify_config_integrity(config_file, signature_file):
    """Verify configuration hasn't been tampered"""
    with open(config_file, 'rb') as f:
        config_data = f.read()
    
    with open(signature_file, 'rb') as f:
        expected_signature = f.read()
    
    key = get_hmac_key()  # Securely retrieve HMAC key
    actual_signature = hmac.new(key, config_data, hashlib.sha256).digest()
    
    return hmac.compare_digest(actual_signature, expected_signature)
```

#### 3. RTR Protocol Attacks
**Risk**: Medium  
**Attack**: Packet injection, session hijacking  
**Mitigation**:
```python
# Implement RTR security extensions
class SecureRTRHandler:
    def __init__(self):
        self.session_keys = {}
        self.nonce_cache = set()
    
    def validate_packet(self, packet):
        """Validate RTR packet authenticity"""
        # Check nonce to prevent replay
        if packet.nonce in self.nonce_cache:
            raise SecurityError("Replay attack detected")
        
        # Verify signature
        if not self.verify_signature(packet):
            raise SecurityError("Invalid packet signature")
        
        self.nonce_cache.add(packet.nonce)
        return True
```

---

## Security Controls

### Authentication & Authorization

#### Multi-Factor Authentication
```python
class MFAAuthenticator:
    """
    Implement TOTP-based MFA for administrative access
    """
    def __init__(self):
        self.totp_secret = self.load_secret()
    
    def verify_token(self, token):
        """Verify TOTP token"""
        import pyotp
        
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)
    
    def authenticate(self, username, password, mfa_token):
        """Full authentication flow"""
        # Step 1: Verify credentials
        if not self.verify_credentials(username, password):
            return False
        
        # Step 2: Verify MFA token
        if not self.verify_token(mfa_token):
            return False
        
        # Step 3: Create secure session
        return self.create_session(username)
```

#### Role-Based Access Control
```python
RBAC_PERMISSIONS = {
    'admin': ['read', 'write', 'reset', 'configure'],
    'operator': ['read', 'reset'],
    'viewer': ['read']
}

def check_permission(user_role, action):
    """Check if role has permission for action"""
    return action in RBAC_PERMISSIONS.get(user_role, [])
```

### Encryption Implementation

#### Key Management
```python
class KeyManager:
    """
    Secure key management system
    """
    def __init__(self):
        self.key_store = '/secure/keystore'
        self.master_key = self.derive_master_key()
    
    def derive_master_key(self):
        """Derive master key from hardware security module"""
        # In production, use HSM or TPM
        import os
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        salt = os.urandom(32)
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        password = self.get_secure_password()  # From secure source
        return kdf.derive(password.encode())
    
    def rotate_keys(self):
        """Periodic key rotation"""
        old_key = self.master_key
        new_key = self.derive_master_key()
        
        # Re-encrypt all data with new key
        self.reencrypt_data(old_key, new_key)
        self.master_key = new_key
        
        # Securely destroy old key
        self.secure_delete(old_key)
```

#### Data Encryption
```python
def encrypt_sensitive_data(data, key):
    """
    Encrypt sensitive data using AES-256-GCM
    """
    from cryptography.hazmat.primitives.ciphers import (
        Cipher, algorithms, modes
    )
    import os
    
    # Generate nonce
    nonce = os.urandom(12)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce)
    )
    
    # Encrypt
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    return nonce + encryptor.tag + ciphertext
```

---

## Hardening Checklist

### System Hardening

- [ ] **Operating System**
  ```bash
  # Disable unnecessary services
  systemctl disable bluetooth
  systemctl disable cups
  
  # Kernel hardening
  echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf
  echo "kernel.kptr_restrict = 2" >> /etc/sysctl.conf
  echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf
  
  # File system hardening
  mount -o remount,hidepid=2 /proc
  chmod 700 /opt/HuaweiRPKICheck
  ```

- [ ] **File Permissions**
  ```bash
  # Set strict permissions
  chmod 600 /opt/HuaweiRPKICheck/HuaweiRPKICheck.conf
  chmod 600 /opt/HuaweiRPKICheck/secret.key
  chmod 755 /opt/HuaweiRPKICheck/*.py
  
  # Set ownership
  chown rpki:rpki /opt/HuaweiRPKICheck -R
  ```

- [ ] **Network Configuration**
  ```bash
  # Firewall rules
  iptables -A INPUT -p tcp --dport 22 -s trusted_network -j ACCEPT
  iptables -A INPUT -p tcp --dport 3323 -s validator_ips -j ACCEPT
  iptables -A INPUT -j DROP
  
  # Disable IPv6 if not used
  echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
  ```

### Application Hardening

- [ ] **Input Validation**
  ```python
  import re
  
  def validate_ip_address(ip):
      """Strict IP address validation"""
      pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
      if not re.match(pattern, ip):
          raise ValueError(f"Invalid IP address: {ip}")
      
      # Additional check for private/reserved ranges
      octets = [int(x) for x in ip.split('.')]
      if octets[0] in [0, 10, 127, 169, 172, 192, 224, 240]:
          raise ValueError(f"Reserved IP address: {ip}")
      
      return ip
  ```

- [ ] **Secure Coding Practices**
  ```python
  # Use parameterized queries
  def get_session_history(validator_ip):
      query = "SELECT * FROM sessions WHERE validator_ip = %s"
      return db.execute(query, (validator_ip,))
  
  # Sanitize log output
  def secure_log(message):
      # Remove sensitive patterns
      sanitized = re.sub(r'password=\S+', 'password=***', message)
      sanitized = re.sub(r'key=\S+', 'key=***', sanitized)
      logger.info(sanitized)
  ```

- [ ] **Error Handling**
  ```python
  def secure_error_handler(error):
      """Handle errors without information disclosure"""
      # Log full error internally
      logger.error(f"Internal error: {error}", exc_info=True)
      
      # Return generic error to user
      if isinstance(error, AuthenticationError):
          return "Authentication failed"
      elif isinstance(error, ValidationError):
          return "Invalid input"
      else:
          return "An error occurred"
  ```

---

## Credential Management

### Secure Storage

```python
class SecureCredentialStore:
    """
    Secure credential storage with hardware security module support
    """
    def __init__(self, use_hsm=True):
        self.use_hsm = use_hsm
        if use_hsm:
            self.hsm = self.init_hsm()
        else:
            self.key = self.load_local_key()
    
    def store_credential(self, name, credential):
        """Store credential securely"""
        # Encrypt credential
        encrypted = self.encrypt(credential)
        
        # Store with integrity check
        integrity = self.calculate_mac(encrypted)
        
        storage = {
            'data': encrypted,
            'mac': integrity,
            'timestamp': time.time(),
            'version': 1
        }
        
        # Save to secure storage
        self.save_secure(name, storage)
    
    def retrieve_credential(self, name):
        """Retrieve and verify credential"""
        storage = self.load_secure(name)
        
        # Verify integrity
        if not self.verify_mac(storage['data'], storage['mac']):
            raise SecurityError("Credential integrity check failed")
        
        # Check age
        age = time.time() - storage['timestamp']
        if age > 86400 * 30:  # 30 days
            raise SecurityError("Credential expired")
        
        # Decrypt
        return self.decrypt(storage['data'])
```

### Password Policy

```python
class PasswordPolicy:
    """
    Enforce strong password policy
    """
    MIN_LENGTH = 16
    REQUIRE_UPPER = True
    REQUIRE_LOWER = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True
    
    @classmethod
    def validate(cls, password):
        """Validate password against policy"""
        errors = []
        
        if len(password) < cls.MIN_LENGTH:
            errors.append(f"Minimum length {cls.MIN_LENGTH}")
        
        if cls.REQUIRE_UPPER and not any(c.isupper() for c in password):
            errors.append("Must contain uppercase")
        
        if cls.REQUIRE_LOWER and not any(c.islower() for c in password):
            errors.append("Must contain lowercase")
        
        if cls.REQUIRE_DIGIT and not any(c.isdigit() for c in password):
            errors.append("Must contain digit")
        
        if cls.REQUIRE_SPECIAL and not any(c in '!@#$%^&*()' for c in password):
            errors.append("Must contain special character")
        
        if errors:
            raise ValueError(f"Password policy violations: {', '.join(errors)}")
        
        return True
```

---

## Network Security

### Firewall Configuration

```bash
#!/bin/bash
# Comprehensive firewall setup

# Flush existing rules
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH from management network only
iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/24 -j ACCEPT

# RTR from validators only
iptables -A INPUT -p tcp --dport 3323 -s 185.54.81.23 -j ACCEPT
iptables -A INPUT -p tcp --dport 3323 -s 185.54.81.25 -j ACCEPT

# Rate limiting
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT

# Log dropped packets
iptables -A INPUT -j LOG --log-prefix "DROPPED: "

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Network Segmentation

```yaml
# Network architecture
networks:
  management:
    subnet: 10.0.0.0/24
    vlan: 100
    description: Management and monitoring
    
  production:
    subnet: 10.1.0.0/24
    vlan: 200
    description: Production routers
    
  validation:
    subnet: 10.2.0.0/24
    vlan: 300
    description: RPKI validators
    
  dmz:
    subnet: 10.3.0.0/24
    vlan: 400
    description: External facing services

# Access control
access_rules:
  - from: management
    to: production
    protocol: ssh
    port: 22
    
  - from: production
    to: validation
    protocol: tcp
    port: 3323
    
  - from: validation
    to: internet
    protocol: https
    port: 443
```

---

## Audit and Compliance

### Audit Logging

```python
class AuditLogger:
    """
    Comprehensive audit logging system
    """
    def __init__(self):
        self.logger = self.setup_secure_logger()
        
    def setup_secure_logger(self):
        """Configure tamper-proof logging"""
        logger = logging.getLogger('audit')
        
        # Syslog handler for remote logging
        syslog = SysLogHandler(
            address=('syslog.example.com', 514),
            facility=SysLogHandler.LOG_AUTH
        )
        
        # Format with all required fields
        formatter = logging.Formatter(
            '%(asctime)s|%(hostname)s|%(user)s|%(action)s|'
            '%(resource)s|%(result)s|%(details)s'
        )
        
        syslog.setFormatter(formatter)
        logger.addHandler(syslog)
        
        return logger
    
    def log_event(self, event_type, **kwargs):
        """Log security event"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user': self.get_current_user(),
            'source_ip': self.get_source_ip(),
            'session_id': self.get_session_id(),
            **kwargs
        }
        
        # Sign event for integrity
        event['signature'] = self.sign_event(event)
        
        # Log to multiple destinations
        self.logger.info(json.dumps(event))
        self.store_in_database(event)
        
        # Alert on critical events
        if event_type in ['authentication_failure', 'unauthorized_access']:
            self.send_security_alert(event)
```

### Compliance Reporting

```python
def generate_compliance_report():
    """
    Generate compliance report for auditors
    """
    report = {
        'generated_at': datetime.utcnow().isoformat(),
        'period': 'last_30_days',
        'compliance_frameworks': ['ISO27001', 'PCI-DSS', 'SOC2'],
        'controls': {}
    }
    
    # Access control compliance
    report['controls']['access_control'] = {
        'password_policy': check_password_policy_compliance(),
        'mfa_enabled': check_mfa_compliance(),
        'privileged_access': audit_privileged_access(),
        'access_reviews': get_access_review_status()
    }
    
    # Data protection compliance
    report['controls']['data_protection'] = {
        'encryption_at_rest': verify_encryption_at_rest(),
        'encryption_in_transit': verify_encryption_in_transit(),
        'key_rotation': check_key_rotation_compliance(),
        'data_retention': check_data_retention_compliance()
    }
    
    # Monitoring compliance
    report['controls']['monitoring'] = {
        'log_retention': check_log_retention(),
        'alert_response_time': calculate_alert_response_metrics(),
        'incident_resolution': get_incident_metrics(),
        'vulnerability_management': check_vulnerability_scanning()
    }
    
    return report
```

---

## Incident Response

### Incident Response Plan

```python
class IncidentResponsePlan:
    """
    Automated incident response system
    """
    
    SEVERITY_LEVELS = {
        'CRITICAL': 1,  # Immediate response required
        'HIGH': 2,      # Response within 1 hour
        'MEDIUM': 3,    # Response within 4 hours
        'LOW': 4        # Response within 24 hours
    }
    
    def detect_incident(self, event):
        """Detect potential security incident"""
        indicators = [
            self.check_authentication_anomalies(event),
            self.check_traffic_patterns(event),
            self.check_file_integrity(event),
            self.check_configuration_changes(event)
        ]
        
        if any(indicators):
            return self.create_incident(event, indicators)
        
        return None
    
    def respond_to_incident(self, incident):
        """Execute incident response playbook"""
        severity = self.assess_severity(incident)
        
        # Immediate actions
        if severity <= 2:  # CRITICAL or HIGH
            self.isolate_affected_systems(incident)
            self.preserve_evidence(incident)
            self.notify_security_team(incident)
        
        # Investigation
        investigation = self.investigate_incident(incident)
        
        # Containment
        self.contain_threat(incident, investigation)
        
        # Recovery
        self.recover_systems(incident)
        
        # Lessons learned
        self.document_incident(incident, investigation)
```

### Security Monitoring

```python
class SecurityMonitor:
    """
    Real-time security monitoring
    """
    
    def __init__(self):
        self.rules = self.load_detection_rules()
        self.baseline = self.establish_baseline()
        
    def monitor_authentication(self):
        """Monitor authentication events"""
        events = self.get_auth_events()
        
        for event in events:
            # Check for brute force
            if self.detect_brute_force(event):
                self.alert("Brute force attempt detected", event)
            
            # Check for credential stuffing
            if self.detect_credential_stuffing(event):
                self.alert("Credential stuffing detected", event)
            
            # Check for impossible travel
            if self.detect_impossible_travel(event):
                self.alert("Impossible travel detected", event)
    
    def monitor_network_traffic(self):
        """Monitor network anomalies"""
        traffic = self.capture_traffic()
        
        # Check for data exfiltration
        if self.detect_exfiltration(traffic):
            self.alert("Possible data exfiltration", traffic)
        
        # Check for command and control
        if self.detect_c2_traffic(traffic):
            self.alert("C2 traffic detected", traffic)
```

---

## Security Tools Integration

### SIEM Integration

```python
def send_to_siem(event):
    """
    Send security events to SIEM
    """
    siem_format = {
        'event_id': str(uuid.uuid4()),
        'timestamp': event['timestamp'],
        'source': 'HuaweiRPKICheck',
        'severity': event['severity'],
        'category': 'RPKI_Security',
        'description': event['description'],
        'details': event
    }
    
    # Send via syslog
    syslog.send(json.dumps(siem_format))
    
    # Send via API
    requests.post(
        'https://siem.example.com/api/events',
        json=siem_format,
        headers={'Authorization': f'Bearer {api_token}'}
    )
```

### Vulnerability Scanning

```bash
#!/bin/bash
# Automated vulnerability scanning

# Dependency scanning
pip-audit --desc

# Static code analysis
bandit -r /opt/HuaweiRPKICheck/

# Secret scanning
trufflehog filesystem /opt/HuaweiRPKICheck/

# OWASP dependency check
dependency-check --scan /opt/HuaweiRPKICheck/ --format JSON
```

---

## Security Best Practices

### Development Security

1. **Secure Development Lifecycle**
   - Code review for all changes
   - Security testing in CI/CD
   - Dependency scanning
   - Static analysis

2. **Secret Management**
   - Never commit secrets
   - Use environment variables
   - Rotate regularly
   - Audit access

3. **Security Testing**
   ```python
   # Security test suite
   class SecurityTests(unittest.TestCase):
       def test_sql_injection(self):
           """Test SQL injection prevention"""
           malicious_input = "'; DROP TABLE sessions; --"
           result = process_input(malicious_input)
           self.assertNotIn("DROP", result)
       
       def test_xss_prevention(self):
           """Test XSS prevention"""
           xss_payload = "<script>alert('XSS')</script>"
           output = render_output(xss_payload)
           self.assertNotIn("<script>", output)
       
       def test_authentication_bypass(self):
           """Test authentication cannot be bypassed"""
           with self.assertRaises(AuthenticationError):
               authenticate("admin", "' OR '1'='1")
   ```

### Operational Security

1. **Change Management**
   - Review all configuration changes
   - Test in staging environment
   - Maintain rollback capability
   - Document changes

2. **Access Management**
   - Regular access reviews
   - Immediate revocation on termination
   - Principle of least privilege
   - Audit all privileged access

3. **Monitoring and Response**
   - 24/7 security monitoring
   - Defined escalation procedures
   - Regular incident drills
   - Post-incident reviews

---

**© 2024-2025 GOLINE SA - Switzerland**  
**Author:** Paolo Caparrelli  
**Website:** https://www.goline.ch  
**Support:** soc@goline.ch