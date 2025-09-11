#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Huawei RPKI Check v3.6 - Added Routinator issue detection and partial prefix monitoring
Combines v2.0 email functionality with v3.1 timeout improvements

Author: Paolo Caparrelli
Company: GOLINE SA - Switzerland
Website: https://www.goline.ch
Support: soc@goline.ch
License: MIT
Copyright (c) 2024-2025 GOLINE SA
"""

import paramiko
import time
import logging
import sys
import os
import json
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re
import socket
from pathlib import Path

# Enhanced timeout settings from v3.1
CONNECTION_TIMEOUT = 30  # Initial connection timeout
COMMAND_TIMEOUT = 20     # Command execution timeout  
NEGOTIATION_TIMEOUT_MINUTES = 3  # Reduced from 30 to 3 minutes for faster recovery
ESTABLISHED_STUCK_MINUTES = 30   # Check if established sessions are stuck
MAX_RETRIES = 3          # Maximum reconnection attempts

# Configuration
BASE_DIR = Path("/opt/HuaweiRPKICheck")
LOG_DIR = Path("/var/log/huawei_rpki")
LOG_FILE = LOG_DIR / f"rpki_check_{datetime.now().strftime('%Y%m')}.log"
STATE_FILE = BASE_DIR / "rpki_state.json"
SECRET_KEY_FILE = BASE_DIR / "secret.key"
CONFIG_FILE = BASE_DIR / "HuaweiRPKICheck.conf"

# Create log directory if it doesn't exist
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Configure logging
def setup_logging(verbose: bool = False) -> logging.Logger:
    """Setup logging configuration"""
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

# Import logging module for handlers
import logging.handlers

logger = setup_logging()

class RPKIChecker:
    """Main class for RPKI session checking with improved error handling"""
    
    def __init__(self, config: Dict[str, str], test_mode: bool = False):
        self.config = config
        self.test_mode = test_mode
        self.ssh_client = None
        self.state = self.load_state()
        self.session_history = []
        
    def load_state(self) -> Dict:
        """Load previous state from file"""
        try:
            if STATE_FILE.exists():
                with open(STATE_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load state file: {e}")
        return {
            "last_check": None, 
            "consecutive_failures": 0, 
            "last_alert": None,
            "previous_analysis": None,
            "last_recovery_alert": None
        }
    
    def save_state(self):
        """Save current state to file"""
        try:
            self.state["last_check"] = datetime.now().isoformat()
            with open(STATE_FILE, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save state file: {e}")
    
    def decrypt_config(self, key_path: Path, config_path: Path) -> Dict[str, str]:
        """Decrypt configuration file with error handling"""
        try:
            with open(key_path, "rb") as key_file:
                key = key_file.read()
            
            fernet = Fernet(key)
            
            with open(config_path, "rb") as enc_file:
                encrypted_data = enc_file.read()
            
            decrypted_data = fernet.decrypt(encrypted_data).decode()
            
            config = {}
            for line in decrypted_data.strip().split("\n"):
                if '=' in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
            
            # Validate required fields
            required_fields = ['hostname', 'username', 'password', 
                             'smtp_server', 'email_sender', 'email_receiver']
            missing = [f for f in required_fields if f not in config]
            if missing:
                raise ValueError(f"Missing required config fields: {missing}")
            
            logger.info("Configuration decrypted successfully")
            return config
            
        except Exception as e:
            logger.error(f"Failed to decrypt configuration: {e}")
            raise
    
    def test_connectivity(self) -> bool:
        """Test SSH connectivity to target host"""
        try:
            sock = socket.create_connection(
                (self.config['hostname'], 22), timeout=10
            )
            sock.close()
            logger.info(f"SSH port reachable on {self.config['hostname']}")
            return True
        except Exception as e:
            logger.error(f"Cannot reach SSH on {self.config['hostname']}: {e}")
            return False
    
    def ssh_connect(self, max_retries: int = 3) -> Optional[paramiko.SSHClient]:
        """Establish SSH connection with retry logic"""
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.info(f"Retry {attempt}/{max_retries} after {wait_time}s")
                    time.sleep(wait_time)
                
                client = paramiko.SSHClient()
                
                # Load known hosts if available
                known_hosts_file = Path.home() / '.ssh' / 'known_hosts'
                if known_hosts_file.exists():
                    client.load_host_keys(str(known_hosts_file))
                    client.set_missing_host_key_policy(paramiko.RejectPolicy())
                else:
                    # Fall back to AutoAddPolicy but log warning
                    logger.warning("No known_hosts file found, using AutoAddPolicy")
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                client.connect(
                    self.config['hostname'],
                    username=self.config['username'],
                    password=self.config['password'],
                    timeout=30,
                    banner_timeout=30,
                    auth_timeout=30
                )
                
                logger.info(f"SSH connection established to {self.config['hostname']}")
                self.ssh_client = client
                return client
                
            except paramiko.AuthenticationException as e:
                logger.error(f"Authentication failed: {e}")
                break  # Don't retry auth failures
            except Exception as e:
                logger.warning(f"Connection attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    logger.error(f"Failed to connect after {max_retries} attempts")
                    
        return None
    
    def execute_command_shell(self, command: str, timeout: int = 10) -> Optional[str]:
        """Execute command via interactive shell in USER mode for Huawei devices"""
        if not self.ssh_client:
            logger.error("No SSH connection available")
            return None
        
        shell = None
        try:
            # Always create a fresh shell for reset commands to avoid state issues
            logger.debug("Creating fresh interactive shell session in USER mode")
            shell = self.ssh_client.invoke_shell()
            time.sleep(2)  # Increased wait for shell initialization
            
            # Clear any initial output (banner, etc.)
            while shell.recv_ready():
                initial_output = shell.recv(4096).decode('utf-8', errors='ignore')
                logger.debug(f"Initial output: {initial_output[:200]}...")
                time.sleep(0.5)
            
            # Send the command
            logger.info(f"Sending command via shell: {command}")
            shell.send(command + "\n")
            
            # Wait for output - special handling for reset commands
            time.sleep(2)  # Give command time to execute
            output = ""
            received_prompt = False
            start_time = time.time()
            
            # Try to get output for a shorter time for reset commands
            max_wait = 5 if "reset" in command else timeout
            
            while time.time() - start_time < max_wait:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    logger.debug(f"Received chunk: {chunk[:200]}...")
                    
                    # Check for confirmation prompts
                    if "confirm" in chunk.lower() or "[y/n]" in chunk.lower() or "Continue?" in chunk:
                        logger.info("Confirmation prompt detected, sending 'y'")
                        shell.send("y\n")
                        time.sleep(1)
                        if shell.recv_ready():
                            confirm_output = shell.recv(4096).decode('utf-8', errors='ignore')
                            output += confirm_output
                    
                    # Check for common prompts indicating command completion
                    if any(prompt in chunk for prompt in ['<netengine', '>', '#', ']']):
                        received_prompt = True
                        logger.debug(f"Prompt detected, command likely completed")
                        break
                else:
                    # For reset commands, consider success if we sent the command
                    if "reset" in command and time.time() - start_time > 3:
                        logger.info("Reset command sent, assuming success")
                        output = "Reset command sent successfully"
                        break
                    time.sleep(0.5)
            
            # For reset commands, success is indicated by no error messages
            if "reset" in command:
                if "Error" not in output and "Invalid" not in output and "Unrecognized" not in output:
                    logger.info(f"Reset command executed successfully for: {command}")
                    return "Reset command executed successfully"
                else:
                    logger.error(f"Reset command failed with output: {output}")
                    return None
            
            logger.debug(f"Shell command output: {output[:500]}...")
            return output if output else "Command executed"
            
        except Exception as e:
            logger.error(f"Failed to execute shell command '{command}': {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None
        finally:
            # Always close the shell after use
            if shell:
                try:
                    shell.close()
                except:
                    pass
    
    def execute_command(self, command: str, timeout: int = 30) -> Optional[str]:
        """Execute command via SSH with proper output handling"""
        if not self.ssh_client:
            logger.error("No SSH connection available")
            return None
            
        try:
            logger.debug(f"Executing command: {command}")
            
            # For display commands, exec_command works fine in USER mode
            # For reset commands, we need special handling (see reset_sessions method)
            stdin, stdout, stderr = self.ssh_client.exec_command(
                command, timeout=timeout
            )
            
            # Wait for command to complete
            exit_status = stdout.channel.recv_exit_status()
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            # Huawei returns -1 for many commands but still provides output
            if exit_status != 0 and output:
                logger.debug(f"Command returned exit status {exit_status} but has output")
            elif exit_status != 0:
                logger.warning(f"Command '{command}' returned non-zero exit status {exit_status}")
                if error:
                    logger.warning(f"Error output: {error}")
            
            logger.debug(f"Command output: {output[:200]}..." if len(output) > 200 else f"Command output: {output}")
            
            return output
            
        except Exception as e:
            logger.error(f"Failed to execute command '{command}': {e}")
            return None
    
    def parse_rpki_output(self, output: str) -> Tuple[List[Dict], str]:
        """Parse RPKI session output with improved error handling"""
        sessions = []
        
        if not output:
            logger.error("No output to parse")
            return sessions, "<p>No data received from device</p>"
        
        lines = output.splitlines()
        
        # Find session data lines (containing IP addresses)
        for line in lines:
            # Match lines with IP addresses
            if re.search(r'\d+\.\d+\.\d+\.\d+', line):
                # Remove "Session:" prefix if present (NetEngine format)
                line = re.sub(r'^Session:\s*', '', line.strip())
                
                # Try multiple parsing patterns
                # Pattern 1: Standard format with multiple spaces
                parts = re.split(r'\s{2,}', line.strip())
                
                if len(parts) >= 4:
                    try:
                        session = {
                            'ip': parts[0],
                            'state': parts[1],
                            'age': parts[2] if len(parts) > 2 else 'N/A',
                            'records': parts[3] if len(parts) > 3 else '0/0'
                        }
                        
                        # Parse IPv4/IPv6 records
                        if '/' in session['records']:
                            ipv4, ipv6 = session['records'].split('/')
                            session['ipv4_count'] = int(ipv4)
                            session['ipv6_count'] = int(ipv6)
                        else:
                            session['ipv4_count'] = 0
                            session['ipv6_count'] = 0
                        
                        sessions.append(session)
                        logger.debug(f"Parsed session: {session}")
                        
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Failed to parse line: {line} - Error: {e}")
        
        # Generate HTML table
        html = self.generate_html_table(sessions)
        
        return sessions, html
    
    def generate_html_table(self, sessions: List[Dict]) -> str:
        """Generate HTML table with session status"""
        if not sessions:
            return "<p>No RPKI sessions found</p>"
        
        html = """
        <style>
            table { 
                border-collapse: collapse; 
                width: 100%; 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin: 0;
            }
            th, td { 
                border: 1px solid #e1e8f0; 
                padding: 10px 12px; 
                text-align: left;
                font-size: 13px;
            }
            th { 
                background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                color: white; 
                font-weight: 600;
                text-transform: uppercase;
                font-size: 12px;
                letter-spacing: 0.5px;
            }
            tr:nth-child(even) { background-color: #f8f9fb; }
            .established { 
                background-color: #e6f4ea; 
                color: #1e7e34;
                font-weight: 500;
            }
            .idle { 
                background-color: #fff3cd; 
                color: #856404;
                font-weight: 500;
            }
            .negotiation { 
                background-color: #fff3cd; 
                color: #856404;
                font-weight: 500;
            }
            .syn { 
                background-color: #ffeaa7; 
                color: #d63031;
                font-weight: 500;
            }
            .error { 
                background-color: #ffe0e0; 
                color: #dc3545;
                font-weight: 500;
            }
        </style>
        <table>
            <thead>
                <tr>
                    <th>Session IP</th>
                    <th>State</th>
                    <th>Age</th>
                    <th>IPv4/IPv6 Records</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for session in sessions:
            state_class = session['state'].lower()
            state_emoji = ''
            
            if state_class == 'established' and session['ipv4_count'] > 0:
                state_class = 'established'
                state_emoji = '🟢'
            elif state_class == 'idle':
                state_emoji = '⚠️'
            elif state_class == 'negotiation':
                state_class = 'negotiation'
                state_emoji = '🔄'
            elif state_class == 'syn':
                state_class = 'syn'
                state_emoji = '🟠'
            else:
                state_class = 'error'
                state_emoji = '🔴'
            
            html += f"""
                <tr class="{state_class}">
                    <td>{state_emoji} {session['ip']}</td>
                    <td>{session['state']}</td>
                    <td>{session['age']}</td>
                    <td>{session['records']}</td>
                </tr>
            """
        
        html += """
            </tbody>
        </table>
        """
        
        return html
    
    def parse_age_to_minutes(self, age_str: str) -> int:
        """Parse age string (e.g., '01h14m46s', '6d02h12m51s') to minutes"""
        try:
            total_minutes = 0
            
            # Parse days
            if 'd' in age_str:
                days_part = age_str.split('d')[0]
                total_minutes += int(days_part) * 24 * 60
                age_str = age_str.split('d')[1]
            
            # Parse hours
            if 'h' in age_str:
                hours_part = age_str.split('h')[0]
                total_minutes += int(hours_part) * 60
                age_str = age_str.split('h')[1]
            
            # Parse minutes
            if 'm' in age_str:
                minutes_part = age_str.split('m')[0]
                total_minutes += int(minutes_part)
            
            return total_minutes
            
        except Exception as e:
            logger.warning(f"Could not parse age string '{age_str}': {e}")
            return 0
    
    def analyze_sessions(self, sessions: List[Dict]) -> Dict:
        """Analyze session status and determine if action is needed"""
        analysis = {
            'total': len(sessions),
            'established': [],
            'partial': [],  # Sessions with missing IPv4 or IPv6 prefixes
            'idle': [],
            'negotiation': [],
            'syn': [],
            'need_reset': [],
            'healthy': True,
            'issues': [],
            'routinator_issues': []  # Track potential Routinator problems
        }
        
        # Use the global timeout setting
        negotiation_timeout = NEGOTIATION_TIMEOUT_MINUTES
        syn_timeout = 2  # Reset SYN sessions stuck for more than 2 minutes
        
        for session in sessions:
            state = session['state'].lower()
            
            if state == 'established':
                # Check if session has both IPv4 and IPv6 prefixes
                if session['ipv4_count'] > 0 and session['ipv6_count'] > 0:
                    analysis['established'].append(session['ip'])
                elif session['ipv4_count'] == 0 and session['ipv6_count'] > 0:
                    # Missing IPv4 prefixes - likely Routinator issue
                    analysis['partial'].append(session['ip'])
                    analysis['routinator_issues'].append(f"{session['ip']}: Missing IPv4 prefixes (0/{session['ipv6_count']})")
                    logger.warning(f"Session {session['ip']} established but missing IPv4 prefixes - Routinator issue?")
                elif session['ipv4_count'] > 0 and session['ipv6_count'] == 0:
                    # Missing IPv6 prefixes
                    analysis['partial'].append(session['ip'])
                    analysis['routinator_issues'].append(f"{session['ip']}: Missing IPv6 prefixes ({session['ipv4_count']}/0)")
                    logger.warning(f"Session {session['ip']} established but missing IPv6 prefixes")
                else:
                    # No prefixes at all despite being established
                    analysis['idle'].append(session['ip'])
                    analysis['need_reset'].append(session['ip'])
                    
            elif state == 'idle':
                analysis['idle'].append(session['ip'])
                if session['ipv4_count'] == 0 and session['ipv6_count'] == 0:
                    analysis['need_reset'].append(session['ip'])
                    
            elif state == 'negotiation':
                analysis['negotiation'].append(session['ip'])
                
                # Check how long it's been in negotiation
                age_minutes = self.parse_age_to_minutes(session.get('age', '0'))
                
                # Reset if: no records OR stuck in negotiation for too long
                if (session['ipv4_count'] == 0 and session['ipv6_count'] == 0) or \
                   (age_minutes > negotiation_timeout):
                    analysis['need_reset'].append(session['ip'])
                    logger.warning(f"Session {session['ip']} stuck in Negotiation for {session.get('age')} ({age_minutes} minutes) - will reset")
                    
            elif state == 'syn':
                analysis['syn'].append(session['ip'])
                
                # Check how long it's been in SYN state
                age_minutes = self.parse_age_to_minutes(session.get('age', '0'))
                
                # Reset if stuck in SYN for too long
                if age_minutes > syn_timeout:
                    analysis['need_reset'].append(session['ip'])
                    logger.warning(f"Session {session['ip']} stuck in SYN for {session.get('age')} ({age_minutes} minutes) - will reset")
                    
                    # If repeatedly stuck in SYN, likely a Routinator issue
                    if session['ip'] in self.state.get('reset_sessions', []):
                        analysis['routinator_issues'].append(f"{session['ip']}: Repeatedly stuck in SYN - check Routinator")
        
        # Determine health status
        if analysis['idle'] or analysis['negotiation'] or analysis['syn'] or analysis['partial']:
            analysis['healthy'] = False
            
            if analysis['idle']:
                analysis['issues'].append(f"{len(analysis['idle'])} idle sessions")
            if analysis['negotiation']:
                analysis['issues'].append(f"{len(analysis['negotiation'])} negotiating sessions")
            if analysis['syn']:
                analysis['issues'].append(f"{len(analysis['syn'])} syn sessions")
            if analysis['partial']:
                analysis['issues'].append(f"{len(analysis['partial'])} partial sessions (missing prefixes)")
        
        return analysis
    
    def reset_sessions(self, sessions_to_reset: List[str]) -> bool:
        """Reset specified RPKI sessions - MUST reconnect SSH for each reset on Huawei"""
        if self.test_mode:
            logger.info(f"TEST MODE: Would reset sessions: {sessions_to_reset}")
            return True
        
        success = True
        reset_results = {}
        
        for session_ip in sessions_to_reset:
            logger.info(f"Attempting to reset session: {session_ip}")
            
            # Store the age before reset to verify later
            before_age = None
            check_output = self.execute_command("display rpki session", timeout=10)
            if check_output and session_ip in check_output:
                for line in check_output.split('\n'):
                    if session_ip in line:
                        parts = re.split(r'\s+', line.strip())
                        if len(parts) >= 3:
                            before_age = parts[2]
                            logger.info(f"Session {session_ip} age before reset: {before_age}")
                            break
            
            # For Huawei, we need to reconnect for reset commands
            # Save current connection state
            old_client = self.ssh_client
            
            try:
                # Create new connection for reset
                logger.info(f"Creating new SSH connection for reset command")
                reset_client = paramiko.SSHClient()
                reset_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                reset_client.connect(
                    self.config['hostname'],
                    username=self.config['username'],
                    password=self.config['password'],
                    timeout=30
                )
                
                # Use shell on new connection
                shell = reset_client.invoke_shell()
                time.sleep(2)
                
                # Clear initial output
                while shell.recv_ready():
                    shell.recv(4096)
                    time.sleep(0.2)
                
                # IMPORTANT: Reset command must be sent in USER mode, NOT system-view
                # The shell starts in USER mode by default on Huawei
                reset_cmd = f"reset rpki session {session_ip}"
                logger.info(f"Sending reset command in USER mode: {reset_cmd}")
                shell.send(reset_cmd + "\n")
                
                # Wait for command to process
                time.sleep(3)
                
                # Try to get any output
                output = ""
                attempts = 0
                while attempts < 5:
                    if shell.recv_ready():
                        chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                        output += chunk
                        # Check for confirmation
                        if any(word in chunk.lower() for word in ['confirm', 'continue', '[y/n]']):
                            logger.info("Confirmation prompt detected, sending 'y'")
                            shell.send("y\n")
                            time.sleep(1)
                    attempts += 1
                    time.sleep(0.5)
                
                shell.close()
                reset_client.close()
                
                # Log that reset command was sent
                logger.info(f"Reset command sent for {session_ip}")
                reset_results[session_ip] = "reset_sent"
                
                # Wait for reset to take effect
                logger.info(f"Waiting 10 seconds for reset to take effect...")
                time.sleep(10)
                
                # Always reconnect after reset as Huawei may close the connection
                logger.info("Reconnecting main SSH client after reset")
                if old_client:
                    try:
                        old_client.close()
                    except:
                        pass
                
                # Reconnect for verification
                if not self.ssh_connect():
                    logger.error("Failed to reconnect after reset")
                    # Try one more time
                    time.sleep(2)
                    self.ssh_connect()
                
                # Verify the reset by checking session status
                verify_output = self.execute_command("display rpki session", timeout=10)
                if verify_output and session_ip in verify_output:
                    for line in verify_output.split('\n'):
                        if session_ip in line:
                            parts = re.split(r'\s+', line.strip())
                            if len(parts) >= 3:
                                new_state = parts[1]
                                new_age = parts[2]
                                logger.info(f"Post-reset: {session_ip} is {new_state} with age {new_age}")
                                
                                # Check if age indicates recent reset (seconds only)
                                if 's' in new_age and ('m' not in new_age or '00m' in new_age):
                                    logger.info(f"✅ Reset successful! {session_ip} age shows recent reset: {new_age}")
                                    reset_results[session_ip] = f"success -> {new_state} ({new_age})"
                                elif before_age and before_age != new_age:
                                    logger.info(f"Age changed from {before_age} to {new_age}")
                                    reset_results[session_ip] = f"age_changed -> {new_state}"
                                else:
                                    logger.warning(f"Reset may have failed, age unchanged: {new_age}")
                                    reset_results[session_ip] = "uncertain"
                                break
                
            except Exception as e:
                logger.error(f"Failed to reset {session_ip}: {e}")
                reset_results[session_ip] = "failed"
                success = False
                
                # Try to restore connection
                if old_client:
                    self.ssh_client = old_client
                    if not self.ssh_client.get_transport() or not self.ssh_client.get_transport().is_active():
                        self.ssh_connect()
        
        # Log summary of reset operations
        logger.info(f"Reset operation summary: {reset_results}")
        
        # Add recovery monitoring info to state
        if reset_results:
            self.state['last_reset'] = datetime.now().isoformat()
            self.state['reset_sessions'] = list(reset_results.keys())
        
        return success
    
    def send_alert_email(self, subject: str, body: str) -> bool:
        """Send alert email with improved error handling"""
        if self.test_mode:
            logger.info(f"TEST MODE: Would send email with subject: {subject}")
            print(f"\n--- Email Preview ---\nSubject: {subject}\nBody:\n{body[:500]}...")
            return True
        
        try:
            msg = MIMEMultipart("alternative")
            msg['From'] = self.config['email_sender']
            msg['To'] = self.config['email_receiver']
            msg['Subject'] = subject
            msg['Date'] = email.utils.formatdate(localtime=True)
            
            # Add both plain text and HTML parts
            text_part = MIMEText(re.sub('<[^<]+?>', '', body), 'plain')
            html_part = MIMEText(body, 'html')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Connect to SMTP server
            smtp_port = int(self.config.get('smtp_port', 587))
            
            with smtplib.SMTP(self.config['smtp_server'], smtp_port, timeout=30) as server:
                server.set_debuglevel(0)  # Set to 1 for SMTP debug output
                
                # Start TLS if not using port 25
                if smtp_port != 25:
                    server.starttls()
                
                # Authenticate if credentials provided
                if self.config.get('smtp_username') and self.config.get('smtp_password'):
                    server.login(self.config['smtp_username'], self.config['smtp_password'])
                
                # Send email
                server.send_message(msg)
                
            logger.info(f"Alert email sent successfully to {self.config['email_receiver']}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed: {e}")
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error occurred: {e}")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
        
        return False
    
    def should_send_alert(self, analysis: Dict) -> bool:
        """Determine if an alert should be sent based on state and history"""
        if analysis['healthy']:
            return False
        
        # Always alert in test mode
        if self.test_mode:
            return True
        
        # Check if we've already alerted recently (within 1 hour)
        if self.state.get('last_alert'):
            try:
                last_alert = datetime.fromisoformat(self.state['last_alert'])
                if (datetime.now() - last_alert).total_seconds() < 3600:
                    logger.info("Alert suppressed (sent within last hour)")
                    return False
            except:
                pass
        
        return True
    
    def check_for_recovery(self, current_analysis: Dict) -> bool:
        """Check if sessions have recovered from previous issues"""
        if not self.state.get('previous_analysis'):
            return False
        
        prev = self.state['previous_analysis']
        
        # Check if we had issues before but not now
        if not prev.get('healthy', True) and current_analysis['healthy']:
            return True
        
        # Check if specific sessions recovered
        prev_issues = set(prev.get('idle', [])) | set(prev.get('negotiation', [])) | set(prev.get('syn', []))
        curr_established = set(current_analysis.get('established', []))
        
        # Sessions that were problematic but are now established
        recovered = prev_issues & curr_established
        
        return len(recovered) > 0
    
    def should_send_recovery_alert(self) -> bool:
        """Check if we should send a recovery alert"""
        # Always send in test mode
        if self.test_mode:
            return True
        
        # Don't send recovery alerts too frequently (wait at least 30 minutes)
        if self.state.get('last_recovery_alert'):
            try:
                last_recovery = datetime.fromisoformat(self.state['last_recovery_alert'])
                if (datetime.now() - last_recovery).total_seconds() < 1800:
                    logger.info("Recovery alert suppressed (sent within last 30 minutes)")
                    return False
            except:
                pass
        
        return True
    
    def run_check(self) -> bool:
        """Main check routine"""
        logger.info("="*50)
        logger.info(f"Starting RPKI check at {datetime.now()}")
        
        try:
            # Test connectivity first
            if not self.test_connectivity():
                self.state['consecutive_failures'] += 1
                self.save_state()
                return False
            
            # Connect via SSH
            if not self.ssh_connect():
                self.state['consecutive_failures'] += 1
                self.save_state()
                return False
            
            # Execute RPKI command
            output = self.execute_command("display rpki session")
            if not output:
                logger.error("No output received from RPKI command")
                self.state['consecutive_failures'] += 1
                self.save_state()
                return False
            
            # Parse output
            sessions, html_table = self.parse_rpki_output(output)
            
            # Analyze sessions
            analysis = self.analyze_sessions(sessions)
            
            logger.info(f"Analysis: {analysis['total']} total sessions, "
                       f"{len(analysis['established'])} established, "
                       f"{len(analysis['idle'])} idle, "
                       f"{len(analysis['negotiation'])} negotiating")
            
            # Reset sessions if needed
            if analysis['need_reset']:
                logger.warning(f"Sessions need reset: {analysis['need_reset']}")
                self.reset_sessions(analysis['need_reset'])
            
            # Check for recovery and send recovery notification
            if self.check_for_recovery(analysis) and self.should_send_recovery_alert():
                # Get recovered sessions
                prev = self.state.get('previous_analysis', {})
                prev_issues = set(prev.get('idle', [])) | set(prev.get('negotiation', [])) | set(prev.get('syn', []))
                curr_established = set(analysis.get('established', []))
                recovered_sessions = prev_issues & curr_established
                
                subject = f"[RPKI Monitor] ✅ Recovery: Sessions Restored"
                
                # Create recovery email
                body = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body {{
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            line-height: 1.3;
                            color: #333;
                            background-color: #f5f7fa;
                            margin: 0;
                            padding: 0;
                        }}
                        .container {{
                            max-width: 800px;
                            margin: 0 auto;
                            background: white;
                            box-shadow: 0 0 10px rgba(0,0,0,0.1);
                        }}
                        .header-block {{
                            background: #1e3c72;
                            color: white;
                            padding: 15px 20px;
                            border-bottom: 3px solid #28a745;
                        }}
                        .header-block h1 {{
                            margin: 0;
                            font-size: 20px;
                            font-weight: 400;
                        }}
                        .header-block .subtitle {{
                            font-size: 12px;
                            color: #b8d4f1;
                            margin: 0;
                        }}
                        .recovery-text {{
                            color: #90ee90;
                            font-weight: bold;
                            font-size: 13px;
                        }}
                        .content {{
                            padding: 15px 20px;
                        }}
                        .info-grid {{
                            display: grid;
                            grid-template-columns: 1fr 1fr;
                            gap: 10px;
                            margin: 10px 0;
                            padding: 10px;
                            background: #f8f9fb;
                            border-radius: 4px;
                            font-size: 13px;
                        }}
                        .info-item {{
                            display: flex;
                            align-items: center;
                        }}
                        .info-label {{
                            font-weight: 600;
                            color: #1e3c72;
                            margin-right: 6px;
                        }}
                        .section-title {{
                            color: #1e3c72;
                            border-bottom: 1px solid #e1e8f0;
                            padding-bottom: 2px;
                            margin: 10px 0 0 0;
                            font-size: 14px;
                        }}
                        .footer {{
                            background: #1e3c72;
                            color: #b8d4f1;
                            padding: 10px;
                            text-align: center;
                            font-size: 11px;
                        }}
                        .footer a {{
                            color: #fff;
                            text-decoration: none;
                        }}
                        .success-box {{
                            background: #d4edda;
                            border-left: 3px solid #28a745;
                            padding: 8px 10px;
                            margin: 10px 0;
                            border-radius: 3px;
                            font-size: 13px;
                        }}
                        ul {{
                            margin: 5px 0;
                            padding-left: 20px;
                        }}
                        li {{
                            margin: 3px 0;
                        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header-block">
                            <div style="line-height: 1.2;">
                                <h1 style="margin: 0;">HUAWEI RPKI MONITOR v2.0</h1>
                                <div class="subtitle">Session Monitoring System</div>
                                <div class="recovery-text">✅ SESSIONS RECOVERED</div>
                            </div>
                        </div>
                        
                        <div class="content">
                            <div class="info-grid">
                                <div class="info-item">
                                    <span class="info-label">🕐 Time:</span>
                                    <span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} CET</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">🖥 Device:</span>
                                    <span>{self.config['hostname']}</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">✅ Status:</span>
                                    <span style="color: #28a745; font-weight: bold;">ALL SESSIONS HEALTHY</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">🔄 Recovered:</span>
                                    <span style="color: #28a745; font-weight: bold;">{len(recovered_sessions)} sessions</span>
                                </div>
                            </div>
                            
                            <div style="background: #f0f4f8; padding: 8px; border-radius: 4px; margin: 10px 0; font-size: 13px; text-align: center;">
                                <strong style="color: #28a745;">Current Status:</strong>
                                &nbsp;&nbsp;Total: <strong>{analysis['total']}</strong>
                                &nbsp;&nbsp;|&nbsp;&nbsp;
                                <span style="color: #28a745;">✓ Established: <strong>{len(analysis['established'])}</strong></span>
                                &nbsp;&nbsp;|&nbsp;&nbsp;
                                <span style="color: #6c757d;">Idle: <strong>{len(analysis['idle'])}</strong></span>
                                &nbsp;&nbsp;|&nbsp;&nbsp;
                                <span style="color: #6c757d;">Negotiating: <strong>{len(analysis['negotiation'])}</strong></span>
                            </div>
                            
                            <h2 class="section-title">📊 Session Details</h2>
                            {html_table}
                            
                            <div class="success-box">
                                <strong>✅ Recovery Details:</strong>
                                <ul>
                                    {''.join([f'<li>Session {ip} is now established and operational</li>' for ip in recovered_sessions])}
                                </ul>
                            </div>
                            
                            <div class="success-box">
                                <strong>📝 Summary:</strong>
                                <ul>
                                    <li>RPKI sessions have been successfully restored</li>
                                    <li>All BGP prefixes are now being validated</li>
                                    <li>No further action required</li>
                                </ul>
                            </div>
                        </div>
                        
                        <div class="footer">
                            <strong>GOLINE SA</strong> | Via Croce Campagna 2, 6855 Stabio, Switzerland | 📧 <a href="mailto:noc@goline.ch">noc@goline.ch</a><br>
                            <span style="opacity: 0.8;">Automated recovery notification from HuaweiRPKICheck_v2.py</span>
                        </div>
                    </div>
                </body>
                </html>
                """
                
                if self.send_alert_email(subject, body):
                    self.state['last_recovery_alert'] = datetime.now().isoformat()
                    logger.info(f"Recovery notification sent for {len(recovered_sessions)} sessions")
            
            # Send alert if needed
            elif not analysis['healthy'] and self.should_send_alert(analysis):
                # Check if this is a Routinator issue
                if analysis.get('routinator_issues'):
                    subject = f"[RPKI Monitor] ⚠️ ROUTINATOR ISSUE: {', '.join(analysis['routinator_issues'][:1])}"
                else:
                    subject = f"[RPKI Monitor] Alert: {', '.join(analysis['issues'])}"
                
                # Create professional HTML email with GOLINE branding
                body = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                    <style>
                        body {{
                            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                            line-height: 1.3;
                            color: #333;
                            background-color: #f5f7fa;
                            margin: 0;
                            padding: 0;
                        }}
                        .container {{
                            max-width: 800px;
                            margin: 0 auto;
                            background: white;
                            box-shadow: 0 0 10px rgba(0,0,0,0.1);
                        }}
                        .header-block {{
                            background: #1e3c72;
                            color: white;
                            padding: 15px 20px;
                            border-bottom: 3px solid #dc3545;
                        }}
                        .header-block h1 {{
                            margin: 0;
                            font-size: 20px;
                            font-weight: 400;
                        }}
                        .header-block .subtitle {{
                            font-size: 12px;
                            color: #b8d4f1;
                            margin: 0;
                        }}
                        .alert-text {{
                            color: #ffeb3b;
                            font-weight: bold;
                            font-size: 13px;
                        }}
                        .content {{
                            padding: 15px 20px;
                        }}
                        .info-grid {{
                            display: grid;
                            grid-template-columns: 1fr 1fr;
                            gap: 10px;
                            margin: 10px 0;
                            padding: 10px;
                            background: #f8f9fb;
                            border-radius: 4px;
                            font-size: 13px;
                        }}
                        .info-item {{
                            display: flex;
                            align-items: center;
                        }}
                        .info-label {{
                            font-weight: 600;
                            color: #1e3c72;
                            margin-right: 6px;
                        }}
                        .section-title {{
                            color: #1e3c72;
                            border-bottom: 1px solid #e1e8f0;
                            padding-bottom: 2px;
                            margin: 10px 0 0 0;
                            font-size: 14px;
                        }}
                        .footer {{
                            background: #1e3c72;
                            color: #b8d4f1;
                            padding: 10px;
                            text-align: center;
                            font-size: 11px;
                        }}
                        .footer a {{
                            color: #fff;
                            text-decoration: none;
                        }}
                        .warning-box {{
                            background: #fff3cd;
                            border-left: 3px solid #ffc107;
                            padding: 8px 10px;
                            margin: 10px 0;
                            border-radius: 3px;
                            font-size: 13px;
                        }}
                        .success-box {{
                            background: #d4edda;
                            border-left: 3px solid #28a745;
                            padding: 8px 10px;
                            margin: 10px 0;
                            border-radius: 3px;
                            font-size: 13px;
                        }}
                        ul {{
                            margin: 5px 0;
                            padding-left: 20px;
                        }}
                        li {{
                            margin: 3px 0;
                        }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header-block">
                            <div style="line-height: 1.2;">
                                <h1 style="margin: 0;">HUAWEI RPKI MONITOR v2.0</h1>
                                <div class="subtitle">Session Monitoring System</div>
                                <div class="alert-text">⚠ ANOMALY DETECTED</div>
                            </div>
                        </div>
                        
                        <div class="content">
                            <div class="info-grid">
                                <div class="info-item">
                                    <span class="info-label">🕐 Time:</span>
                                    <span>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} CET</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">🖥 Device:</span>
                                    <span>{self.config['hostname']}</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">⚠ Issues:</span>
                                    <span style="color: #dc3545; font-weight: bold;">{', '.join(analysis['issues'])}</span>
                                </div>
                                <div class="info-item">
                                    <span class="info-label">🔴 Severity:</span>
                                    <span style="color: #dc3545; font-weight: bold;">HIGH</span>
                                </div>
                            </div>
                            
                            <div style="background: #f0f4f8; padding: 8px; border-radius: 4px; margin: 10px 0; font-size: 13px; text-align: center;">
                                <strong style="color: #1e3c72;">Sessions:</strong>
                                &nbsp;&nbsp;Total: <strong>{analysis['total']}</strong>
                                &nbsp;&nbsp;|&nbsp;&nbsp;
                                <span style="color: #28a745;">✓ OK: <strong>{len(analysis['established'])}</strong></span>
                                &nbsp;&nbsp;|&nbsp;&nbsp;
                                <span style="color: #ffc107;">⚠ Idle: <strong>{len(analysis['idle'])}</strong></span>
                                &nbsp;&nbsp;|&nbsp;&nbsp;
                                <span style="color: #fd7e14;">🔄 Negotiating: <strong>{len(analysis['negotiation'])}</strong></span>
                                &nbsp;&nbsp;|&nbsp;&nbsp;
                                <span style="color: #dc3545;">🔶 SYN: <strong>{len(analysis['syn'])}</strong></span>
                            </div>
                            
                            <h2 class="section-title">📊 Session Details</h2>
                            {html_table}
                            
                            {'<div class="success-box"><strong>✓ Automatic Recovery:</strong> Sessions reset: ' + ', '.join(analysis['need_reset']) + '</div>' if analysis['need_reset'] else ''}
                            
                            {'<div class="warning-box" style="background: #f8d7da; border-left-color: #dc3545;"><strong>🚨 Routinator Server Issues Detected:</strong><ul>' + ''.join([f'<li>{issue}</li>' for issue in analysis.get('routinator_issues', [])]) + '</ul><strong>Action Required:</strong> Check Routinator service on affected servers</div>' if analysis.get('routinator_issues') else ''}
                            
                            <div class="warning-box">
                                <strong>💡 Recommended Actions:</strong>
                                <ul>
                                    {'<li><strong>URGENT:</strong> Check Routinator services on affected servers</li><li>Restart Routinator: systemctl restart routinator</li><li>Check logs: journalctl -u routinator -n 100</li>' if analysis.get('routinator_issues') else ''}
                                    <li>Review RPKI server connectivity</li>
                                    <li>Check BGP peering status</li>
                                    <li>Verify network path to RPKI validators</li>
                                    <li>Monitor for recurring issues</li>
                                </ul>
                            </div>
                        </div>
                        
                        <div class="footer">
                            <strong>GOLINE SA</strong> | Via Croce Campagna 2, 6855 Stabio, Switzerland | 📧 <a href="mailto:noc@goline.ch">noc@goline.ch</a><br>
                            <span style="opacity: 0.8;">Automated alert from HuaweiRPKICheck_v2.py</span>
                        </div>
                    </div>
                </body>
                </html>
                """
                
                if self.send_alert_email(subject, body):
                    self.state['last_alert'] = datetime.now().isoformat()
            
            # Update state with current analysis for next comparison
            self.state['consecutive_failures'] = 0
            self.state['previous_analysis'] = {
                'healthy': analysis['healthy'],
                'established': analysis['established'],
                'idle': analysis['idle'],
                'negotiation': analysis['negotiation'],
                'syn': analysis['syn'],
                'total': analysis['total']
            }
            self.save_state()
            
            logger.info("RPKI check completed successfully")
            return True
            
        except Exception as e:
            logger.exception(f"Unexpected error during check: {e}")
            self.state['consecutive_failures'] += 1
            self.save_state()
            return False
            
        finally:
            # Clean up SSH connection
            if self.ssh_client:
                try:
                    self.ssh_client.close()
                except:
                    pass

# Import email.utils for email date formatting
import email.utils

def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(description='Huawei RPKI Session Checker v3.6')
    parser.add_argument('--test', action='store_true', help='Run in test mode (no changes, no emails)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--config', type=str, default=str(CONFIG_FILE), help='Path to config file')
    parser.add_argument('--key', type=str, default=str(SECRET_KEY_FILE), help='Path to key file')
    
    args = parser.parse_args()
    
    # Setup logging
    global logger
    logger = setup_logging(verbose=args.verbose)
    
    if args.test:
        logger.info("Running in TEST MODE - no changes will be made")
    
    try:
        # Create checker instance
        checker = RPKIChecker({}, test_mode=args.test)
        
        # Load and decrypt configuration
        config = checker.decrypt_config(Path(args.key), Path(args.config))
        checker.config = config
        
        # Run the check
        success = checker.run_check()
        
        sys.exit(0 if success else 1)
        
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()