#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Huawei RPKI Check v3.1 - Improved timeout and reconnection handling
Enhanced for better stability with Routinator connections
"""

import paramiko
import time
import logging
import sys
import os
import json
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import socket
from pathlib import Path
import threading
import select

# Configuration
BASE_DIR = Path("/opt/HuaweiRPKICheck")
LOG_DIR = Path("/var/log/huawei_rpki")
LOG_FILE = LOG_DIR / f"rpki_check_{datetime.now().strftime('%Y%m')}.log"
STATE_FILE = BASE_DIR / "rpki_state.json"
SECRET_KEY_FILE = BASE_DIR / "secret.key"
CONFIG_FILE = BASE_DIR / "HuaweiRPKICheck.conf"

# Create log directory if it doesn't exist
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Enhanced timeout settings
CONNECTION_TIMEOUT = 30  # Initial connection timeout
COMMAND_TIMEOUT = 20     # Command execution timeout
NEGOTIATION_TIMEOUT_MINUTES = 3  # Reduced from 5 to 3 minutes
ESTABLISHED_STUCK_MINUTES = 30   # Reduced from 60 to 30 minutes
MAX_RETRIES = 3          # Maximum reconnection attempts

# Configure logging
def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    import logging.handlers
    
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create logger
    logger = logging.getLogger('HuaweiRPKICheck')
    logger.setLevel(log_level)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setLevel(log_level)
    
    # Console handler for test mode
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.WARNING)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

class EnhancedInteractiveSSH:
    """Enhanced Interactive SSH session handler with better timeout management"""
    
    def __init__(self, hostname: str, username: str, password: str):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.client = None
        self.channel = None
        self.prompt_pattern = r'[<\[].*?[>\]]'
        self.last_activity = time.time()
        self.connection_attempts = 0
        self.lock = threading.Lock()
        
    def connect(self, timeout: int = CONNECTION_TIMEOUT) -> bool:
        """Establish interactive SSH connection with retry logic"""
        with self.lock:
            for attempt in range(MAX_RETRIES):
                try:
                    # Close any existing connection
                    self.disconnect()
                    
                    # Create new SSH client
                    self.client = paramiko.SSHClient()
                    
                    # Load known hosts if available
                    known_hosts_file = Path.home() / '.ssh' / 'known_hosts'
                    if known_hosts_file.exists():
                        self.client.load_host_keys(str(known_hosts_file))
                        self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
                    else:
                        logger.warning("No known_hosts file found, using AutoAddPolicy")
                        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    
                    # Connect with timeout
                    logger.info(f"Connecting to {self.hostname} (attempt {attempt + 1}/{MAX_RETRIES})")
                    self.client.connect(
                        hostname=self.hostname,
                        username=self.username,
                        password=self.password,
                        timeout=timeout,
                        banner_timeout=timeout,
                        auth_timeout=timeout,
                        look_for_keys=False,
                        allow_agent=False
                    )
                    
                    # Open interactive shell channel
                    self.channel = self.client.invoke_shell(
                        width=256,
                        height=24,
                        term='vt100'
                    )
                    
                    # Set channel timeout
                    self.channel.settimeout(5.0)
                    
                    # Wait for initial prompt
                    time.sleep(2)
                    initial_output = self._read_until_prompt(timeout=10)
                    logger.debug(f"Initial prompt received: {initial_output[-100:] if initial_output else 'None'}")
                    
                    # Disable paging
                    self._send_command_raw("screen-length 0 temporary", wait_for_prompt=True)
                    
                    self.last_activity = time.time()
                    self.connection_attempts = 0
                    logger.info(f"Successfully connected to {self.hostname}")
                    return True
                    
                except socket.timeout:
                    logger.warning(f"Connection timeout on attempt {attempt + 1}")
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(5 * (attempt + 1))  # Exponential backoff
                    
                except Exception as e:
                    logger.error(f"Connection failed on attempt {attempt + 1}: {e}")
                    if attempt < MAX_RETRIES - 1:
                        time.sleep(5 * (attempt + 1))
            
            self.connection_attempts += 1
            logger.error(f"Failed to connect after {MAX_RETRIES} attempts")
            return False
    
    def disconnect(self):
        """Close SSH connection"""
        try:
            if self.channel:
                self.channel.close()
                self.channel = None
            if self.client:
                self.client.close()
                self.client = None
            logger.debug("SSH connection closed")
        except:
            pass
    
    def _read_until_prompt(self, timeout: int = 10) -> str:
        """Read output until prompt is detected with improved timeout handling"""
        output = ""
        start_time = time.time()
        no_data_counter = 0
        
        while time.time() - start_time < timeout:
            try:
                if self.channel.recv_ready():
                    chunk = self.channel.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    no_data_counter = 0
                    
                    # Check if we've received a prompt
                    if re.search(self.prompt_pattern, output.split('\n')[-1]):
                        break
                else:
                    no_data_counter += 1
                    if no_data_counter > 50:  # 5 seconds without data
                        logger.warning("No data received for 5 seconds")
                        break
                    time.sleep(0.1)
                    
            except socket.timeout:
                logger.debug("Socket timeout while reading")
                break
            except Exception as e:
                logger.error(f"Error reading channel: {e}")
                break
        
        return output
    
    def _send_command_raw(self, command: str, wait_for_prompt: bool = True) -> str:
        """Send command with improved error handling"""
        if not self.channel:
            logger.error("No active channel for command execution")
            return ""
        
        try:
            # Clear any pending data
            while self.channel.recv_ready():
                self.channel.recv(4096)
            
            # Send command
            self.channel.send(command + '\n')
            logger.debug(f"Sent command: {command}")
            self.last_activity = time.time()
            
            if wait_for_prompt:
                # Read response until prompt
                output = self._read_until_prompt(timeout=COMMAND_TIMEOUT)
                
                # Remove the command echo and prompt from output
                lines = output.split('\n')
                if len(lines) > 1:
                    cleaned_lines = lines[1:-1]
                    return '\n'.join(cleaned_lines)
                
                return output
            
            return ""
            
        except Exception as e:
            logger.error(f"Failed to send command '{command}': {e}")
            return ""
    
    def execute_command(self, command: str, timeout: int = COMMAND_TIMEOUT) -> Optional[str]:
        """Execute command with automatic reconnection on failure"""
        # Check connection staleness
        if time.time() - self.last_activity > 300:  # 5 minutes
            logger.info("Connection may be stale, verifying...")
            if not self.is_active():
                logger.warning("Connection stale, reconnecting...")
                if not self.connect():
                    return None
        
        if not self.is_active():
            logger.warning("SSH session not active, reconnecting...")
            if not self.connect():
                return None
        
        try:
            output = self._send_command_raw(command, wait_for_prompt=True)
            logger.debug(f"Command '{command}' output length: {len(output) if output else 0}")
            return output
            
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            # Try to reconnect once
            logger.info("Attempting to reconnect...")
            if self.connect():
                try:
                    output = self._send_command_raw(command, wait_for_prompt=True)
                    return output
                except Exception as e2:
                    logger.error(f"Failed again after reconnect: {e2}")
            
            return None
    
    def is_active(self) -> bool:
        """Enhanced connection activity check"""
        if not self.client or not self.channel:
            return False
        
        try:
            transport = self.client.get_transport()
            if transport and transport.is_active() and not self.channel.closed:
                # Send keepalive to verify connection
                transport.send_ignore()
                return True
        except:
            pass
        
        return False
    
    def keep_alive(self):
        """Send periodic keepalive to maintain connection"""
        while self.is_active():
            try:
                time.sleep(30)
                if self.client and self.client.get_transport():
                    self.client.get_transport().send_ignore()
                    logger.debug("Keepalive sent")
            except:
                break

class HuaweiRPKIChecker:
    """Enhanced RPKI checker with improved session management"""
    
    def __init__(self, config: Dict[str, str]):
        self.config = config
        self.ssh = EnhancedInteractiveSSH(
            hostname=config['hostname'],
            username=config['username'],
            password=self.decrypt_password(config['password'])
        )
        self.state = self.load_state()
        
        # Start keepalive thread
        self.keepalive_thread = threading.Thread(target=self.ssh.keep_alive, daemon=True)
        
    def check_rpki_sessions(self) -> List[Dict]:
        """Get RPKI session information with enhanced error handling"""
        if not self.ssh.connect():
            logger.error("Failed to establish SSH connection")
            return []
        
        # Start keepalive thread after connection
        if not self.keepalive_thread.is_alive():
            self.keepalive_thread = threading.Thread(target=self.ssh.keep_alive, daemon=True)
            self.keepalive_thread.start()
        
        try:
            # Get RPKI session information
            output = self.ssh.execute_command("display rpki session")
            if not output:
                logger.error("Failed to get RPKI session output")
                return []
            
            sessions = self.parse_rpki_sessions(output)
            
            # Get RPKI statistics for additional info
            stats_output = self.ssh.execute_command("display rpki statistics")
            if stats_output:
                self.enhance_session_info(sessions, stats_output)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Error checking RPKI sessions: {e}")
            return []
    
    def parse_rpki_sessions(self, output: str) -> List[Dict]:
        """Parse RPKI session output with improved pattern matching"""
        sessions = []
        
        # Enhanced patterns for different session states
        session_patterns = [
            # Pattern for Huawei display rpki session format
            r'(\d+\.\d+\.\d+\.\d+)\s+(Established|Idle|Negotiation|Syn)\s+(\S+)\s+(\d+)/(\d+)',
            # Alternative patterns
            r'(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+\d+\s+\d+\s+(\w+)',
            r'(\d+\.\d+\.\d+\.\d+)\s+(\w+)\s+(\d+)\s+Records'
        ]
        
        for line in output.split('\n'):
            for pattern in session_patterns:
                match = re.search(pattern, line)
                if match:
                    # Handle different pattern matches
                    if pattern == session_patterns[0]:  # Huawei format
                        ip = match.group(1)
                        state = match.group(2)
                        age = match.group(3)
                        records = int(match.group(4))  # IPv4 records
                    else:
                        ip = match.group(1)
                        
                        # Determine state and records from line content
                        if 'establish' in line.lower():
                            state = 'Established'
                            # Extract record count
                            record_match = re.search(r'(\d+)/\d+', line)
                            records = int(record_match.group(1)) if record_match else 0
                        elif 'idle' in line.lower():
                            state = 'Idle'
                            records = 0
                        elif 'negot' in line.lower():
                            state = 'Negotiation'
                            records = 0
                        elif 'syn' in line.lower() or 'sync' in line.lower():
                            state = 'Syn'
                            records = 0
                        else:
                            state = 'Unknown'
                            records = 0
                        
                        # Extract age information
                        age_match = re.search(r'(\d+[dhms]+\d*[hms]*\d*[ms]*)', line)
                        age = age_match.group(1) if age_match else 'Unknown'
                    
                    session = {
                        'ip': ip,
                        'state': state,
                        'records': records,
                        'age': age,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    sessions.append(session)
                    logger.debug(f"Parsed session: {session}")
                    break
        
        return sessions
    
    def enhance_session_info(self, sessions: List[Dict], stats_output: str):
        """Add statistics information to sessions"""
        try:
            # Parse statistics for additional context
            for line in stats_output.split('\n'):
                if 'Total records' in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        total_records = int(match.group(1))
                        logger.info(f"Total RPKI records: {total_records}")
                        
        except Exception as e:
            logger.error(f"Error enhancing session info: {e}")
    
    def analyze_sessions(self, sessions: List[Dict]) -> Dict:
        """Analyze sessions with adjusted timeout thresholds"""
        analysis = {
            'total': len(sessions),
            'established': [],
            'idle': [],
            'negotiation': [],
            'syn': [],
            'need_reset': [],
            'healthy': True,
            'issues': []
        }
        
        for session in sessions:
            state = session['state'].lower()
            age = session.get('age', 'Unknown')
            
            # Parse age to minutes
            age_minutes = 0
            if age != 'Unknown':
                if 'h' in age:
                    hours = int(re.search(r'(\d+)h', age).group(1))
                    age_minutes += hours * 60
                if 'm' in age:
                    minutes_match = re.search(r'(\d+)m', age)
                    if minutes_match:
                        age_minutes += int(minutes_match.group(1))
            
            # Categorize sessions
            if state == 'established':
                if session['records'] > 0:
                    analysis['established'].append(session['ip'])
                else:
                    # Established but no records - check if stuck
                    if age_minutes > ESTABLISHED_STUCK_MINUTES:
                        analysis['need_reset'].append(session['ip'])
                        logger.warning(f"Session {session['ip']} established but no records for {age_minutes} minutes")
                    else:
                        analysis['established'].append(session['ip'])
                        
            elif state == 'idle':
                analysis['idle'].append(session['ip'])
                analysis['need_reset'].append(session['ip'])
                
            elif state == 'negotiation':
                analysis['negotiation'].append(session['ip'])
                # Reset if stuck in negotiation
                if age_minutes > NEGOTIATION_TIMEOUT_MINUTES:
                    analysis['need_reset'].append(session['ip'])
                    logger.warning(f"Session {session['ip']} stuck in Negotiation for {age} ({age_minutes} minutes)")
                    
            elif state in ['syn', 'sync']:
                analysis['syn'].append(session['ip'])
                # Usually syn state resolves quickly
                if age_minutes > 2:
                    analysis['need_reset'].append(session['ip'])
                    logger.warning(f"Session {session['ip']} stuck in Syn for {age_minutes} minutes")
        
        # Determine health status
        if analysis['idle'] or analysis['negotiation'] or analysis['syn'] or analysis['need_reset']:
            analysis['healthy'] = False
            
            if analysis['idle']:
                analysis['issues'].append(f"{len(analysis['idle'])} idle sessions")
            if analysis['negotiation']:
                analysis['issues'].append(f"{len(analysis['negotiation'])} negotiating sessions")
            if analysis['syn']:
                analysis['issues'].append(f"{len(analysis['syn'])} syn sessions")
            if analysis['need_reset']:
                analysis['issues'].append(f"{len(analysis['need_reset'])} sessions need reset")
        
        return analysis
    
    def reset_session(self, session_ip: str) -> bool:
        """Reset RPKI session with improved confirmation handling"""
        logger.info(f"Attempting to reset RPKI session: {session_ip}")
        
        try:
            command = f"reset rpki session {session_ip}"
            
            # Send reset command
            self.ssh.channel.send(command + '\n')
            time.sleep(1)
            
            # Read response
            output = ""
            start_time = time.time()
            confirmed = False
            
            while time.time() - start_time < 10:
                if self.ssh.channel.recv_ready():
                    chunk = self.ssh.channel.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    
                    # Check for confirmation prompt
                    if re.search(r'Continue\?.*\[Y/N\]', output, re.IGNORECASE):
                        logger.debug("Confirmation prompt detected, sending 'y'")
                        self.ssh.channel.send('y\n')
                        confirmed = True
                        time.sleep(2)
                        
                        # Read confirmation response
                        if self.ssh.channel.recv_ready():
                            confirm_output = self.ssh.channel.recv(4096).decode('utf-8', errors='ignore')
                            logger.debug(f"Confirmation response: {confirm_output[:200]}")
                        break
                    
                    # Check if command completed without confirmation
                    if re.search(self.ssh.prompt_pattern, output.split('\n')[-1]):
                        break
                        
                time.sleep(0.1)
            
            if confirmed or 'reset' in output.lower():
                logger.info(f"Session {session_ip} reset successfully")
                return True
            else:
                logger.warning(f"Session reset may have failed for {session_ip}")
                return False
                
        except Exception as e:
            logger.error(f"Error resetting session {session_ip}: {e}")
            return False
    
    def load_state(self) -> Dict:
        """Load saved state"""
        if STATE_FILE.exists():
            try:
                with open(STATE_FILE, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}
    
    def save_state(self, data: Dict):
        """Save state to file"""
        try:
            with open(STATE_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving state: {e}")
    
    def decrypt_password(self, encrypted_password: str) -> str:
        """Decrypt password"""
        try:
            if SECRET_KEY_FILE.exists():
                with open(SECRET_KEY_FILE, 'rb') as f:
                    key = f.read()
                cipher = Fernet(key)
                return cipher.decrypt(encrypted_password.encode()).decode()
            else:
                # Assume plain text if no key file
                return encrypted_password
        except:
            return encrypted_password
    
    def run_check(self, test_mode: bool = False) -> bool:
        """Run RPKI check with enhanced error recovery"""
        try:
            logger.info("Starting RPKI session check")
            
            # Get current sessions
            sessions = self.check_rpki_sessions()
            if not sessions:
                logger.error("No sessions retrieved")
                return False
            
            # Analyze sessions
            analysis = self.analyze_sessions(sessions)
            
            logger.info(f"Session status: {analysis['total']} total, "
                       f"{len(analysis['established'])} established, "
                       f"{len(analysis['idle'])} idle, "
                       f"{len(analysis['negotiation'])} negotiating")
            
            # Reset sessions if needed
            if analysis['need_reset'] and not test_mode:
                logger.warning(f"Sessions need reset: {analysis['need_reset']}")
                for session_ip in analysis['need_reset']:
                    if self.reset_session(session_ip):
                        logger.info(f"Reset session: {session_ip}")
                        time.sleep(2)  # Wait between resets
            
            # Save state
            self.state['last_check'] = datetime.now().isoformat()
            self.state['last_analysis'] = analysis
            self.save_state(self.state)
            
            # Print summary for test mode
            if test_mode:
                print("\nRPKI Session Status:")
                print(f"  Total sessions: {analysis['total']}")
                print(f"  Established: {len(analysis['established'])}")
                print(f"  Idle: {len(analysis['idle'])}")
                print(f"  Negotiating: {len(analysis['negotiation'])}")
                print(f"  Need reset: {len(analysis['need_reset'])}")
                print(f"  Healthy: {analysis['healthy']}")
                if analysis['issues']:
                    print(f"  Issues: {', '.join(analysis['issues'])}")
            
            return analysis['healthy']
            
        except Exception as e:
            logger.error(f"Error during check: {e}", exc_info=True)
            return False
        finally:
            # Ensure connection is closed properly
            if not test_mode:
                self.ssh.disconnect()

def load_config(config_file: Path) -> Dict[str, str]:
    """Load configuration from file (handles encrypted files)"""
    config = {}
    try:
        with open(config_file, 'rb') as f:
            data = f.read()
        
        # Check if file is encrypted
        try:
            # Try to decode as text first
            text_data = data.decode('utf-8')
            if text_data.startswith('gAAAAA'):  # Fernet encrypted data marker
                # File is encrypted, decrypt it
                if SECRET_KEY_FILE.exists():
                    with open(SECRET_KEY_FILE, 'rb') as kf:
                        key = kf.read()
                    cipher = Fernet(key)
                    decrypted = cipher.decrypt(data).decode('utf-8')
                    text_data = decrypted
                else:
                    logger.error("Config file is encrypted but no secret key found")
                    sys.exit(1)
        except UnicodeDecodeError:
            # Binary file, try to decrypt directly
            if SECRET_KEY_FILE.exists():
                with open(SECRET_KEY_FILE, 'rb') as kf:
                    key = kf.read()
                cipher = Fernet(key)
                text_data = cipher.decrypt(data).decode('utf-8')
            else:
                logger.error("Cannot read config file - appears to be encrypted")
                sys.exit(1)
        
        # Parse configuration
        for line in text_data.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
        
        return config
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Huawei RPKI Session Checker')
    parser.add_argument('--test', action='store_true', help='Run in test mode')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--config', type=str, default=str(CONFIG_FILE), help='Config file path')
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Load configuration
    config = load_config(Path(args.config))
    
    # Create checker instance
    checker = HuaweiRPKIChecker(config)
    
    # Run check
    success = checker.run_check(test_mode=args.test)
    
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()