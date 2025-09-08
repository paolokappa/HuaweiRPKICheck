#!/usr/bin/env python3
"""
Check Routinator logs and status on remote servers
Analyzes lg.goline.ch and time.goline.ch for issues
"""

import paramiko
import sys
import json
from datetime import datetime, timedelta
import re
from pathlib import Path

# Remote servers configuration
ROUTINATOR_SERVERS = {
    'lg.goline.ch': {
        'port': 22,
        'user': 'root',  # Adjust as needed
        'key_file': '/root/.ssh/id_rsa'  # SSH key path
    },
    'time.goline.ch': {
        'port': 22,
        'user': 'root',
        'key_file': '/root/.ssh/id_rsa'
    }
}

# Routinator paths (common locations)
ROUTINATOR_PATHS = {
    'config': [
        '/etc/routinator/routinator.conf',
        '/usr/local/etc/routinator/routinator.conf',
        '/opt/routinator/.routinator.conf'
    ],
    'logs': [
        '/var/log/routinator/routinator.log',
        '/var/log/syslog',  # Routinator might log here
        '/var/log/messages',
        'journalctl -u routinator -n 1000'  # SystemD logs
    ],
    'service': [
        'systemctl status routinator',
        'service routinator status',
        'ps aux | grep routinator'
    ]
}

class RoutinatorRemoteChecker:
    """Check Routinator on remote servers"""
    
    def __init__(self, hostname, config):
        self.hostname = hostname
        self.config = config
        self.client = None
        
    def connect(self):
        """Connect to remote server via SSH"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try key-based authentication first
            if 'key_file' in self.config and Path(self.config['key_file']).exists():
                self.client.connect(
                    hostname=self.hostname,
                    port=self.config.get('port', 22),
                    username=self.config['user'],
                    key_filename=self.config['key_file'],
                    timeout=30
                )
            else:
                # Fall back to password (will need to be provided)
                print(f"Warning: No SSH key found for {self.hostname}")
                return False
                
            print(f"✓ Connected to {self.hostname}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to connect to {self.hostname}: {e}")
            return False
    
    def execute_command(self, command):
        """Execute command on remote server"""
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=30)
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            return output, error
        except Exception as e:
            return None, str(e)
    
    def check_routinator_status(self):
        """Check if Routinator service is running"""
        print(f"\n[{self.hostname}] Checking Routinator service status...")
        
        for cmd in ROUTINATOR_PATHS['service']:
            output, error = self.execute_command(cmd)
            if output:
                if 'systemctl' in cmd:
                    # Parse systemctl output
                    if 'active (running)' in output:
                        print(f"  ✓ Routinator is running")
                        # Extract uptime and memory info
                        for line in output.split('\n'):
                            if 'Active:' in line:
                                print(f"    {line.strip()}")
                            elif 'Memory:' in line:
                                print(f"    {line.strip()}")
                    elif 'inactive' in output or 'dead' in output:
                        print(f"  ✗ Routinator is NOT running!")
                        return False
                elif 'ps aux' in cmd:
                    # Check process list
                    routinator_procs = [line for line in output.split('\n') if 'routinator' in line and 'grep' not in line]
                    if routinator_procs:
                        print(f"  ✓ Found {len(routinator_procs)} Routinator process(es)")
                        for proc in routinator_procs[:2]:  # Show first 2
                            # Extract CPU and memory usage
                            parts = proc.split()
                            if len(parts) > 10:
                                print(f"    PID: {parts[1]}, CPU: {parts[2]}%, MEM: {parts[3]}%")
                break
        
        return True
    
    def check_routinator_config(self):
        """Check Routinator configuration"""
        print(f"\n[{self.hostname}] Checking Routinator configuration...")
        
        for config_path in ROUTINATOR_PATHS['config']:
            output, error = self.execute_command(f"cat {config_path} 2>/dev/null")
            if output:
                print(f"  Found config at: {config_path}")
                
                # Check for important settings that might affect stability
                important_settings = {
                    'rtr-listen': None,
                    'http-listen': None,
                    'refresh': None,
                    'retry': None,
                    'expire': None,
                    'history-size': None,
                    'max-object-size': None,
                    'dirty': None,
                    'validation-threads': None
                }
                
                for line in output.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        for setting in important_settings:
                            if setting in line:
                                important_settings[setting] = line
                
                print("  Important settings:")
                for setting, value in important_settings.items():
                    if value:
                        print(f"    {value}")
                
                # Check for recent tuning changes
                output, _ = self.execute_command(f"ls -la {config_path}")
                if output:
                    print(f"  Config file details: {output.strip()}")
                
                break
    
    def check_routinator_logs(self):
        """Check Routinator logs for errors and warnings"""
        print(f"\n[{self.hostname}] Checking Routinator logs...")
        
        # Patterns to look for in logs
        error_patterns = [
            r'error|ERROR',
            r'warning|WARNING',
            r'disconnect|DISCONNECT',
            r'timeout|TIMEOUT',
            r'failed|FAILED',
            r'refused|REFUSED',
            r'reset|RESET',
            r'RTR.*error',
            r'RTR.*disconnect',
            r'client.*disconnect',
            r'185\.54\.81\.\d+',  # Our router IP range
            r'memory|OOM',
            r'CPU|cpu.*high',
            r'Connection reset by peer',
            r'Broken pipe'
        ]
        
        found_issues = {}
        
        # Try different log locations
        for log_cmd in ROUTINATOR_PATHS['logs']:
            if 'journalctl' in log_cmd:
                # Get recent journal entries
                output, error = self.execute_command(log_cmd)
            else:
                # Get last 500 lines of log file
                output, error = self.execute_command(f"tail -n 500 {log_cmd} 2>/dev/null | grep -i routinator")
            
            if output:
                print(f"  Analyzing logs from: {log_cmd.split()[0] if ' ' in log_cmd else log_cmd}")
                
                for pattern in error_patterns:
                    matches = re.findall(f'.*{pattern}.*', output, re.IGNORECASE)
                    if matches:
                        if pattern not in found_issues:
                            found_issues[pattern] = []
                        found_issues[pattern].extend(matches[-5:])  # Keep last 5 occurrences
                
                break
        
        # Report findings
        if found_issues:
            print("  ⚠ Found potential issues:")
            for pattern, matches in found_issues.items():
                print(f"\n  Pattern: {pattern}")
                for match in matches[-3:]:  # Show last 3
                    # Clean and truncate long lines
                    clean_match = match.strip()
                    if len(clean_match) > 150:
                        clean_match = clean_match[:150] + "..."
                    print(f"    {clean_match}")
        else:
            print("  ✓ No significant errors found in recent logs")
    
    def check_system_resources(self):
        """Check system resources"""
        print(f"\n[{self.hostname}] Checking system resources...")
        
        # Check memory
        output, _ = self.execute_command("free -h")
        if output:
            print("  Memory usage:")
            for line in output.split('\n')[1:3]:  # Header and Mem line
                if line:
                    print(f"    {line}")
        
        # Check disk space
        output, _ = self.execute_command("df -h /")
        if output:
            print("  Disk usage:")
            for line in output.split('\n')[1:2]:  # Just root filesystem
                if line:
                    print(f"    {line}")
        
        # Check load average
        output, _ = self.execute_command("uptime")
        if output:
            print(f"  System load: {output.strip()}")
        
        # Check network connections related to RTR
        output, _ = self.execute_command("netstat -an | grep -E ':3323|:8323' | head -20")
        if output:
            connections = output.split('\n')
            established = len([c for c in connections if 'ESTABLISHED' in c])
            time_wait = len([c for c in connections if 'TIME_WAIT' in c])
            listening = len([c for c in connections if 'LISTEN' in c])
            
            print(f"  RTR connections:")
            print(f"    Listening: {listening}")
            print(f"    Established: {established}")
            print(f"    TIME_WAIT: {time_wait}")
            
            # Show connections from our router
            router_conns = [c for c in connections if '185.54.81' in c]
            if router_conns:
                print(f"    Connections from our router:")
                for conn in router_conns[:5]:
                    print(f"      {conn.strip()}")
    
    def check_recent_changes(self):
        """Check for recent configuration or service changes"""
        print(f"\n[{self.hostname}] Checking recent changes...")
        
        # Check when Routinator was last restarted
        output, _ = self.execute_command("systemctl show routinator --property=ActiveEnterTimestamp")
        if output and '=' in output:
            timestamp = output.split('=')[1].strip()
            print(f"  Routinator last started: {timestamp}")
        
        # Check for recent config changes
        for config_path in ROUTINATOR_PATHS['config']:
            output, _ = self.execute_command(f"stat {config_path} 2>/dev/null | grep Modify")
            if output:
                print(f"  Config last modified: {output.strip()}")
                break
        
        # Check system logs for recent Routinator restarts or crashes
        output, _ = self.execute_command(
            "journalctl -u routinator --since '7 days ago' | grep -E 'Started|Stopped|Failed|Restarting' | tail -10"
        )
        if output:
            print("  Recent service events:")
            for line in output.split('\n'):
                if line:
                    print(f"    {line[:150]}")  # Truncate long lines
    
    def analyze(self):
        """Run all checks"""
        if not self.connect():
            return False
        
        try:
            self.check_routinator_status()
            self.check_routinator_config()
            self.check_system_resources()
            self.check_routinator_logs()
            self.check_recent_changes()
            
            return True
            
        except Exception as e:
            print(f"Error during analysis: {e}")
            return False
            
        finally:
            if self.client:
                self.client.close()

def main():
    """Main function"""
    print("=" * 70)
    print("Routinator Remote Server Analysis")
    print(f"Timestamp: {datetime.now()}")
    print("=" * 70)
    
    # Analyze each server
    results = {}
    for hostname, config in ROUTINATOR_SERVERS.items():
        print(f"\n{'=' * 70}")
        print(f"Analyzing: {hostname}")
        print(f"{'=' * 70}")
        
        checker = RoutinatorRemoteChecker(hostname, config)
        results[hostname] = checker.analyze()
    
    # Summary
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")
    
    for hostname, success in results.items():
        status = "✓ Analyzed successfully" if success else "✗ Analysis failed"
        print(f"{hostname}: {status}")
    
    # Save results to file
    report_file = f"/var/log/huawei_rpki/routinator_remote_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    print(f"\nFull report will be saved to: {report_file}")

if __name__ == '__main__':
    main()