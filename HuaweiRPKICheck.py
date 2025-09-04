#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Huawei RPKI Check v3.0 - Enhanced version with interactive SSH shell support
Improved connection stability and command execution for Huawei devices
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

class InteractiveSSH:
    """Interactive SSH session handler for Huawei devices"""
    
    def __init__(self, hostname: str, username: str, password: str):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.client = None
        self.channel = None
        self.prompt_pattern = r'[<\[].*?[>\]]'  # Matches Huawei prompts like <hostname> or [hostname]
        
    def connect(self, timeout: int = 30) -> bool:
        """Establish interactive SSH connection"""
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
            
            # Connect to the device
            logger.info(f"Connecting to {self.hostname}...")
            self.client.connect(
                self.hostname,
                username=self.username,
                password=self.password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                look_for_keys=False,
                allow_agent=False
            )
            
            # Get transport and set keepalive
            transport = self.client.get_transport()
            transport.set_keepalive(15)  # Send keepalive every 15 seconds
            
            # Open interactive shell channel
            self.channel = self.client.invoke_shell(
                width=200,
                height=100
            )
            
            # Set channel timeout
            self.channel.settimeout(5.0)
            
            # Wait for initial prompt
            time.sleep(2)
            initial_output = self._read_until_prompt(timeout=10)
            logger.debug(f"Initial prompt received: {initial_output[-100:] if initial_output else 'None'}")
            
            # Disable paging to get full output
            self._send_command_raw("screen-length 0 temporary", wait_for_prompt=True)
            
            logger.info(f"Interactive SSH session established to {self.hostname}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to establish interactive SSH connection: {e}")
            self.disconnect()
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
        """Read output until prompt is detected"""
        output = ""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if self.channel.recv_ready():
                chunk = self.channel.recv(4096).decode('utf-8', errors='ignore')
                output += chunk
                
                # Check if we've received a prompt
                if re.search(self.prompt_pattern, output.split('\n')[-1]):
                    break
            else:
                time.sleep(0.1)
        
        return output
    
    def _send_command_raw(self, command: str, wait_for_prompt: bool = True) -> str:
        """Send command and optionally wait for response"""
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
            
            if wait_for_prompt:
                # Read response until prompt
                output = self._read_until_prompt()
                
                # Remove the command echo and prompt from output
                lines = output.split('\n')
                if len(lines) > 1:
                    # Remove first line (command echo) and last line (prompt)
                    cleaned_lines = lines[1:-1]
                    return '\n'.join(cleaned_lines)
                
                return output
            
            return ""
            
        except Exception as e:
            logger.error(f"Failed to send command '{command}': {e}")
            return ""
    
    def execute_command(self, command: str, timeout: int = 30) -> Optional[str]:
        """Execute command and return output"""
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
        """Check if SSH connection is active"""
        if not self.client or not self.channel:
            return False
        
        try:
            transport = self.client.get_transport()
            if transport and transport.is_active() and not self.channel.closed:
                # Send a small test to verify channel is responsive
                transport.send_ignore()
                return True
        except:
            pass
        
        return False


class RPKIChecker:
    """Main class for RPKI session checking with interactive SSH"""
    
    def __init__(self, config: Dict[str, str], test_mode: bool = False):
        self.config = config
        self.test_mode = test_mode
        self.ssh = None
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
    
    def parse_rpki_output(self, output: str) -> Tuple[List[Dict], str]:
        """Parse RPKI session output with improved error handling"""
        sessions = []
        
        if not output:
            logger.error("No output to parse")
            return sessions, "<p>No data received from device</p>"
        
        lines = output.splitlines()
        
        # Debug: log first few lines to understand format
        logger.debug(f"First 5 lines of output: {lines[:5] if len(lines) >= 5 else lines}")
        
        # Find session data lines (containing IP addresses)
        for line in lines:
            # Skip empty lines and headers
            if not line.strip() or 'Session' in line and 'State' in line:
                continue
                
            # Match lines with IP addresses
            if re.search(r'\d+\.\d+\.\d+\.\d+', line):
                # Remove "Session:" prefix if present
                line = re.sub(r'^Session:\s*', '', line.strip())
                
                # Try multiple parsing patterns
                # Pattern 1: Standard format with multiple spaces
                parts = re.split(r'\s{2,}', line.strip())
                
                # Also try single space split if double space fails
                if len(parts) < 4:
                    parts = line.split()
                
                if len(parts) >= 4:
                    try:
                        session = {
                            'ip': parts[0],
                            'state': parts[1],
                            'age': parts[2] if len(parts) > 2 else 'N/A',
                            'records': parts[3] if len(parts) > 3 else '0/0'
                        }
                        
                        # Normalize state names
                        state_lower = session['state'].lower()
                        if 'estab' in state_lower:
                            session['state'] = 'Established'
                        elif 'idle' in state_lower:
                            session['state'] = 'Idle'
                        elif 'negot' in state_lower:
                            session['state'] = 'Negotiation'
                        elif 'syn' in state_lower or 'sync' in state_lower:
                            session['state'] = 'Syn'
                        
                        # Parse IPv4/IPv6 records
                        if '/' in session['records']:
                            ipv4, ipv6 = session['records'].split('/')
                            # Remove any non-numeric characters
                            ipv4 = re.sub(r'[^\d]', '', ipv4)
                            ipv6 = re.sub(r'[^\d]', '', ipv6)
                            session['ipv4_count'] = int(ipv4) if ipv4 else 0
                            session['ipv6_count'] = int(ipv6) if ipv6 else 0
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
            state = session['state'].lower()
            state_class = state
            
            if state == 'established' and session['ipv4_count'] > 0:
                state_class = 'established'
            elif state == 'idle':
                state_class = 'idle'
            elif state == 'negotiation':
                state_class = 'negotiation'
            elif state in ['syn', 'sync']:
                state_class = 'syn'
            else:
                state_class = 'error'
            
            html += f"""
                <tr class="{state_class}">
                    <td>{session['ip']}</td>
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
            'idle': [],
            'negotiation': [],
            'syn': [],
            'need_reset': [],
            'healthy': True,
            'issues': []
        }
        
        NEGOTIATION_TIMEOUT_MINUTES = 5  # Reset if in negotiation for more than 5 minutes
        ESTABLISHED_STUCK_MINUTES = 60  # Consider stuck if established but no records for 60 minutes
        
        for session in sessions:
            state = session['state'].lower()
            age_minutes = self.parse_age_to_minutes(session.get('age', '0'))
            
            if state == 'established':
                if session['ipv4_count'] > 0 or session['ipv6_count'] > 0:
                    analysis['established'].append(session['ip'])
                else:
                    # Established but no records - check if stuck
                    if age_minutes > ESTABLISHED_STUCK_MINUTES:
                        analysis['need_reset'].append(session['ip'])
                        logger.warning(f"Session {session['ip']} established but no records for {session.get('age')} - will reset")
                    else:
                        logger.info(f"Session {session['ip']} established but waiting for records ({session.get('age')})")
                        
            elif state == 'idle':
                analysis['idle'].append(session['ip'])
                analysis['need_reset'].append(session['ip'])
                
            elif state == 'negotiation':
                analysis['negotiation'].append(session['ip'])
                # Reset if stuck in negotiation
                if age_minutes > NEGOTIATION_TIMEOUT_MINUTES:
                    analysis['need_reset'].append(session['ip'])
                    logger.warning(f"Session {session['ip']} stuck in Negotiation for {session.get('age')} ({age_minutes} minutes) - will reset")
                    
            elif state in ['syn', 'sync']:
                analysis['syn'].append(session['ip'])
                # Usually syn state resolves quickly, reset if stuck
                if age_minutes > 2:
                    analysis['need_reset'].append(session['ip'])
        
        # Determine health status
        if analysis['idle'] or analysis['negotiation'] or analysis['syn'] or analysis['need_reset']:
            analysis['healthy'] = False
            
            if analysis['idle']:
                analysis['issues'].append(f"{len(analysis['idle'])} idle sessions")
            if analysis['negotiation']:
                analysis['issues'].append(f"{len(analysis['negotiation'])} negotiating sessions")
            if analysis['syn']:
                analysis['issues'].append(f"{len(analysis['syn'])} syn sessions")
        
        return analysis
    
    def reset_sessions(self, sessions_to_reset: List[str]) -> bool:
        """Reset specified RPKI sessions using interactive SSH"""
        if self.test_mode:
            logger.info(f"TEST MODE: Would reset sessions: {sessions_to_reset}")
            return True
        
        if not self.ssh:
            logger.error("No SSH connection available")
            return False
        
        success = True
        
        for i, session_ip in enumerate(sessions_to_reset):
            logger.info(f"Resetting RPKI session {i+1}/{len(sessions_to_reset)}: {session_ip}")
            
            # Execute reset command
            command = f"reset rpki session {session_ip}"
            result = self.ssh.execute_command(command, timeout=15)
            
            if result is not None:
                # Check for error messages
                if any(error in result.lower() for error in ["error", "unrecognized", "invalid", "wrong", "failed"]):
                    logger.error(f"Reset command failed for {session_ip}: {result[:200]}")
                    success = False
                else:
                    # For Huawei, might need to confirm
                    if "confirm" in result.lower() or "[y/n]" in result.lower():
                        # Send confirmation
                        confirm_result = self.ssh.execute_command("y", timeout=5)
                        logger.info(f"Confirmed reset for session {session_ip}")
                    else:
                        logger.info(f"Session {session_ip} reset command executed")
            else:
                logger.warning(f"No response for reset of {session_ip}")
            
            # Wait a bit between resets
            if i < len(sessions_to_reset) - 1:
                time.sleep(2)
        
        # Wait and then verify the reset worked
        if sessions_to_reset:
            logger.info("Waiting 10 seconds for sessions to re-establish...")
            time.sleep(10)
            
            # Check status again
            output = self.ssh.execute_command("display rpki session")
            if output:
                sessions, _ = self.parse_rpki_output(output)
                for session in sessions:
                    if session['ip'] in sessions_to_reset:
                        logger.info(f"Session {session['ip']} is now in state: {session['state']}")
        
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
                server.set_debuglevel(0)
                
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
        
        # Check alert frequency based on severity
        if self.state.get('last_alert'):
            try:
                last_alert = datetime.fromisoformat(self.state['last_alert'])
                time_since_alert = (datetime.now() - last_alert).total_seconds()
                
                # CRITICAL: Both sessions down - alert every 30 minutes
                if len(analysis['established']) == 0:
                    if time_since_alert < 1800:  # 30 minutes
                        logger.info(f"Critical alert suppressed (sent {int(time_since_alert/60)} minutes ago, waiting for 30)")
                        return False
                    logger.warning("CRITICAL: All RPKI sessions are down - sending alert")
                # WARNING: At least one session has issues - alert every hour
                else:
                    if time_since_alert < 3600:  # 60 minutes
                        logger.info(f"Warning alert suppressed (sent {int(time_since_alert/60)} minutes ago, waiting for 60)")
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
    
    def _generate_alert_email(self, analysis: Dict, html_table: str, severity: str) -> str:
        """Generate alert email HTML with professional GOLINE branding"""
        is_critical = "CRITICAL" in severity
        border_color = "#dc3545" if is_critical else "#ffc107"
        severity_color = "#dc3545" if is_critical else "#856404"
        severity_bg = "#f8d7da" if is_critical else "#fff3cd"
        
        return f"""
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
                    border-bottom: 3px solid {border_color};
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
                    color: {"#ff6b6b" if is_critical else "#ffeb3b"};
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
                .alert-box {{
                    background: {severity_bg};
                    border-left: 3px solid {border_color};
                    padding: 8px 10px;
                    margin: 10px 0;
                    border-radius: 3px;
                    font-size: 13px;
                    color: {severity_color};
                    font-weight: bold;
                }}
                .status-summary {{
                    background: #f0f4f8;
                    padding: 8px;
                    border-radius: 4px;
                    margin: 10px 0;
                    font-size: 13px;
                    text-align: center;
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
                        <h1 style="margin: 0;">HUAWEI RPKI MONITOR v3.0</h1>
                        <div class="subtitle">Session Monitoring System</div>
                        <div class="alert-text">{severity}</div>
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
                            <span class="info-label">{"🔴" if is_critical else "⚠️"} Status:</span>
                            <span style="color: {severity_color}; font-weight: bold;">
                                {"CRITICAL - ALL DOWN" if is_critical else "WARNING - ISSUES DETECTED"}
                            </span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">📊 Sessions:</span>
                            <span>{analysis['total']} total, {len(analysis['established'])} working</span>
                        </div>
                    </div>
                    
                    <div class="alert-box">
                        {"⚠️ CRITICAL ALERT: All RPKI sessions are down! No BGP prefix validation is currently active. This is a severe security risk." if is_critical else "⚠️ WARNING: Some RPKI sessions are experiencing issues. BGP validation may be degraded."}
                    </div>
                    
                    <div class="status-summary">
                        <strong style="color: #1e3c72;">Current Status:</strong>
                        &nbsp;&nbsp;Total: <strong>{analysis['total']}</strong>
                        &nbsp;&nbsp;|&nbsp;&nbsp;
                        <span style="color: {"#dc3545" if len(analysis['established']) == 0 else "#28a745"};">
                            ✓ Established: <strong>{len(analysis['established'])}</strong>
                        </span>
                        &nbsp;&nbsp;|&nbsp;&nbsp;
                        <span style="color: #856404;">Idle: <strong>{len(analysis['idle'])}</strong></span>
                        &nbsp;&nbsp;|&nbsp;&nbsp;
                        <span style="color: #856404;">Negotiating: <strong>{len(analysis['negotiation'])}</strong></span>
                        &nbsp;&nbsp;|&nbsp;&nbsp;
                        <span style="color: #dc3545;">Syn: <strong>{len(analysis['syn'])}</strong></span>
                    </div>
                    
                    <h2 class="section-title">📊 Session Details</h2>
                    {html_table}
                    
                    {'<div class="alert-box" style="background: #f8d7da; margin-top: 15px;"><strong>🚨 CRITICAL SEVERITY:</strong> Immediate action required! No RPKI validation is active. All BGP prefixes are currently unvalidated.</div>' if is_critical else ''}
                    
                    <div style="background: #fff3cd; border-left: 3px solid #ffc107; padding: 8px 10px; margin: 10px 0; border-radius: 3px; font-size: 13px;">
                        <strong>💡 Recommended Actions:</strong>
                        <ul style="margin: 5px 0; padding-left: 20px;">
                            <li>Check RPKI server connectivity (185.54.81.25 and 185.54.81.23)</li>
                            <li>Verify network path to RPKI validators</li>
                            <li>Review BGP peering status</li>
                            <li>Check if RPKI servers are operational</li>
                            {"<li style='color: #dc3545; font-weight: bold;'>⚠️ BGP validation is currently NOT active!</li>" if is_critical else ""}
                        </ul>
                    </div>
                    
                    <div style="margin-top: 15px; padding: 8px; background: #f8f9fb; border-radius: 4px; font-size: 12px;">
                        <strong>Alert Frequency:</strong> {"This CRITICAL alert will repeat every 30 minutes until resolved." if is_critical else "This WARNING alert will repeat every 60 minutes until resolved."}
                    </div>
                </div>
                
                <div class="footer">
                    <strong>GOLINE SA</strong> | Via Croce Campagna 2, 6855 Stabio, Switzerland | 📧 <a href="mailto:noc@goline.ch">noc@goline.ch</a><br>
                    <span style="opacity: 0.8;">Automated {"critical" if is_critical else "warning"} alert from HuaweiRPKICheck v3.0</span>
                </div>
            </div>
        </body>
        </html>
        """
    
    def _generate_recovery_email(self, analysis: Dict, html_table: str) -> str:
        """Generate recovery email HTML with professional GOLINE branding"""
        # Calculate recovered sessions
        prev = self.state.get('previous_analysis', {})
        prev_issues = set(prev.get('idle', [])) | set(prev.get('negotiation', [])) | set(prev.get('syn', []))
        curr_established = set(analysis.get('established', []))
        recovered_sessions = prev_issues & curr_established
        
        return f"""
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
                .status-summary {{
                    background: #f0f4f8;
                    padding: 8px;
                    border-radius: 4px;
                    margin: 10px 0;
                    font-size: 13px;
                    text-align: center;
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
                        <h1 style="margin: 0;">HUAWEI RPKI MONITOR v3.0</h1>
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
                    
                    <div class="status-summary">
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
                            {''.join([f'<li>Session {ip} is now established and operational</li>' for ip in recovered_sessions]) if recovered_sessions else '<li>All sessions are now operational</li>'}
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
                    <span style="opacity: 0.8;">Automated recovery notification from HuaweiRPKICheck v3.0</span>
                </div>
            </div>
        </body>
        </html>
        """
    
    def run_check(self) -> bool:
        """Main check routine using interactive SSH"""
        logger.info("="*50)
        logger.info(f"Starting RPKI check at {datetime.now()}")
        
        try:
            # Test connectivity first
            if not self.test_connectivity():
                self.state['consecutive_failures'] += 1
                self.save_state()
                return False
            
            # Create interactive SSH session
            self.ssh = InteractiveSSH(
                self.config['hostname'],
                self.config['username'],
                self.config['password']
            )
            
            # Connect
            if not self.ssh.connect():
                logger.error("Failed to establish interactive SSH session")
                self.state['consecutive_failures'] += 1
                self.save_state()
                return False
            
            # Execute RPKI command
            output = self.ssh.execute_command("display rpki session")
            if not output:
                logger.error("No output received from RPKI command")
                self.state['consecutive_failures'] += 1
                self.save_state()
                return False
            
            # Parse output
            sessions, html_table = self.parse_rpki_output(output)
            
            if not sessions:
                logger.warning("No sessions found in output")
                logger.debug(f"Raw output: {output[:500]}")
            
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
                subject = f"[RPKI Monitor] ✅ Recovery: Sessions Restored"
                body = self._generate_recovery_email(analysis, html_table)
                if self.send_alert_email(subject, body):
                    self.state['last_recovery_alert'] = datetime.now().isoformat()
                    logger.info(f"Recovery notification sent")
            
            # Send alert if needed
            elif not analysis['healthy'] and self.should_send_alert(analysis):
                # Determine severity
                if len(analysis['established']) == 0:
                    severity = "🔴 CRITICAL"
                    severity_text = "ALL SESSIONS DOWN"
                else:
                    severity = "⚠️ WARNING"
                    severity_text = ', '.join(analysis['issues'])
                
                subject = f"[RPKI Monitor] {severity}: {severity_text}"
                body = self._generate_alert_email(analysis, html_table, severity)
                
                if self.send_alert_email(subject, body):
                    self.state['last_alert'] = datetime.now().isoformat()
            
            # Update state
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
            if self.ssh:
                self.ssh.disconnect()

# Import email.utils for email date formatting
import email.utils

def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(description='Huawei RPKI Session Checker v3.0')
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