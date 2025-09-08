#!/usr/bin/env python3
"""
Monitor Routinator connections and RPKI sessions
Helps debug disconnection issues with lg.goline.ch and time.goline.ch
"""

import subprocess
import time
import json
from datetime import datetime
import socket
import sys

ROUTINATOR_HOSTS = ['lg.goline.ch', 'time.goline.ch']
ROUTER_IP = '185.54.81.25'  # IP from logs showing issues

def check_routinator_connectivity():
    """Check if Routinator hosts are reachable"""
    results = {}
    for host in ROUTINATOR_HOSTS:
        try:
            # Try to resolve hostname
            ip = socket.gethostbyname(host)
            # Try to connect to RTR port (typically 3323)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, 3323))
            sock.close()
            
            if result == 0:
                results[host] = {'status': 'OK', 'ip': ip, 'port_open': True}
            else:
                results[host] = {'status': 'PORT_CLOSED', 'ip': ip, 'port_open': False}
        except socket.gaierror:
            results[host] = {'status': 'DNS_FAIL', 'ip': None, 'port_open': False}
        except Exception as e:
            results[host] = {'status': f'ERROR: {str(e)}', 'ip': None, 'port_open': False}
    
    return results

def check_rpki_sessions():
    """Check RPKI session status on router"""
    try:
        # Read config
        with open('/opt/HuaweiRPKICheck/config/HuaweiRPKICheck.conf', 'r') as f:
            config = {}
            for line in f:
                if '=' in line and not line.strip().startswith('#'):
                    key, value = line.strip().split('=', 1)
                    config[key.strip()] = value.strip()
        
        # Run the check script
        result = subprocess.run(
            ['python3', '/opt/HuaweiRPKICheck/src/HuaweiRPKICheck.py', '--test'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Parse output for session info
        output = result.stdout
        sessions = []
        for line in output.split('\n'):
            if ROUTER_IP in line or 'Negotiation' in line or 'Established' in line:
                sessions.append(line.strip())
        
        return sessions
    except Exception as e:
        return [f"Error checking sessions: {str(e)}"]

def check_network_stats():
    """Check network statistics for dropped packets"""
    try:
        result = subprocess.run(['netstat', '-s'], capture_output=True, text=True)
        stats = {}
        
        for line in result.stdout.split('\n'):
            if 'dropped' in line.lower() or 'timeout' in line.lower():
                stats[line.strip()] = True
        
        return stats
    except Exception as e:
        return {'error': str(e)}

def main():
    """Main monitoring loop"""
    print(f"Starting Routinator Connection Monitor - {datetime.now()}")
    print("=" * 60)
    
    while True:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Check Routinator connectivity
        print(f"\n[{timestamp}] Checking Routinator hosts...")
        routinator_status = check_routinator_connectivity()
        for host, status in routinator_status.items():
            print(f"  {host}: {status}")
        
        # Check RPKI sessions
        print(f"\n[{timestamp}] Checking RPKI sessions...")
        sessions = check_rpki_sessions()
        for session in sessions[:5]:  # Show first 5 lines
            print(f"  {session}")
        
        # Check for network issues
        print(f"\n[{timestamp}] Network statistics:")
        net_stats = check_network_stats()
        for stat in list(net_stats.keys())[:5]:  # Show first 5 stats
            print(f"  {stat}")
        
        # Log to file
        log_entry = {
            'timestamp': timestamp,
            'routinator': routinator_status,
            'sessions': sessions[:5],
            'network': list(net_stats.keys())[:5]
        }
        
        with open('/var/log/huawei_rpki/routinator_monitor.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
        
        print("\n" + "-" * 60)
        print("Sleeping for 60 seconds...")
        time.sleep(60)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        sys.exit(0)