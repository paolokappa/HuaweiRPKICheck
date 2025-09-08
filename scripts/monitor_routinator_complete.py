#!/usr/bin/env python3
"""
Complete Routinator and RPKI Session Monitor
Includes fixed RTR protocol implementation
"""

import socket
import struct
import time
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Configuration
ROUTINATOR_SERVERS = ['lg.goline.ch', 'time.goline.ch']
ROUTER_IP = 'YOUR_ROUTER_IP'  # Replace with your router IP
RTR_PORT = 3323
HTTP_PORT = 8323
LOG_FILE = Path("/var/log/huawei_rpki/routinator_monitor_complete.log")

class RoutinatorMonitor:
    """Complete monitoring for Routinator and RPKI sessions"""
    
    def __init__(self):
        self.results = {}
        self.session_history = {}
        
    def test_rtr_connection(self, hostname):
        """Test RTR connection with correct protocol format"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            # Connect to RTR port
            start_time = time.time()
            sock.connect((hostname, RTR_PORT))
            connect_time = (time.time() - start_time) * 1000
            
            # Send correct Reset Query format
            # Format: Version(1) + Type(1) + Reserved(2) + Length(4)
            reset_query = struct.pack('!BBHI',
                1,  # Protocol version 1
                2,  # PDU Type (Reset Query)
                0,  # Reserved (2 bytes)
                8   # Length (total packet size)
            )
            
            sock.send(reset_query)
            
            # Receive response
            response = sock.recv(1024)
            
            if response:
                version, pdu_type = struct.unpack('!BB', response[:2])
                
                if pdu_type == 3:  # Cache Response
                    session_id = struct.unpack('!H', response[2:4])[0]
                    sock.close()
                    return {
                        'status': 'OK',
                        'latency_ms': connect_time,
                        'session_id': session_id,
                        'protocol_version': version
                    }
                elif pdu_type == 10:  # Error Report
                    error_code = struct.unpack('!H', response[2:4])[0]
                    sock.close()
                    return {
                        'status': 'ERROR',
                        'error_code': error_code,
                        'latency_ms': connect_time
                    }
                else:
                    sock.close()
                    return {
                        'status': 'UNKNOWN',
                        'pdu_type': pdu_type,
                        'latency_ms': connect_time
                    }
            
            sock.close()
            return {'status': 'NO_RESPONSE'}
            
        except socket.timeout:
            return {'status': 'TIMEOUT'}
        except Exception as e:
            return {'status': 'CONNECTION_FAILED', 'error': str(e)}
    
    def get_http_metrics(self, hostname):
        """Get Routinator metrics via HTTP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((hostname, HTTP_PORT))
            
            # Request metrics
            request = f"GET /metrics HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())
            
            # Read response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 50000:
                    break
            
            sock.close()
            
            # Parse metrics
            metrics = {}
            response_text = response.decode('utf-8', errors='ignore')
            
            if 'HTTP/1.1 200' in response_text:
                # Extract key metrics
                import re
                
                # Current RTR connections
                match = re.search(r'routinator_rtr_current_connections (\d+)', response_text)
                if match:
                    metrics['rtr_connections'] = int(match.group(1))
                
                # Total VRPs
                match = re.search(r'routinator_vrps_total (\d+)', response_text)
                if match:
                    metrics['vrps_total'] = int(match.group(1))
                
                # RTR bytes written
                match = re.search(r'routinator_rtr_bytes_written_total (\d+)', response_text)
                if match:
                    metrics['bytes_written'] = int(match.group(1))
                
                return metrics
            
            return None
            
        except Exception as e:
            return None
    
    def check_rpki_sessions(self):
        """Check RPKI sessions on router"""
        try:
            # Run the main check script
            result = subprocess.run(
                ['python3', '/opt/HuaweiRPKICheck/src/HuaweiRPKICheck.py', '--test'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse output
            output = result.stdout
            sessions = {
                'total': 0,
                'established': 0,
                'negotiating': 0,
                'idle': 0,
                'issues': []
            }
            
            for line in output.split('\n'):
                if 'Total sessions:' in line:
                    sessions['total'] = int(line.split(':')[1].strip())
                elif 'Established:' in line:
                    sessions['established'] = int(line.split(':')[1].strip())
                elif 'Negotiating:' in line:
                    sessions['negotiating'] = int(line.split(':')[1].strip())
                elif 'Idle:' in line:
                    sessions['idle'] = int(line.split(':')[1].strip())
                elif 'Issues:' in line:
                    issues = line.split(':')[1].strip()
                    if issues and issues != 'None':
                        sessions['issues'] = issues.split(',')
            
            return sessions
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_stability(self):
        """Analyze connection stability over time"""
        analysis = {
            'stable': True,
            'issues': [],
            'recommendations': []
        }
        
        # Check RTR connectivity
        for server in ROUTINATOR_SERVERS:
            if server in self.results:
                result = self.results[server]['rtr']
                if result['status'] != 'OK':
                    analysis['stable'] = False
                    analysis['issues'].append(f"{server}: RTR {result['status']}")
                elif result.get('latency_ms', 0) > 100:
                    analysis['issues'].append(f"{server}: High latency ({result['latency_ms']:.1f}ms)")
        
        # Check RPKI sessions
        if 'rpki_sessions' in self.results:
            sessions = self.results['rpki_sessions']
            if sessions.get('negotiating', 0) > 0:
                analysis['stable'] = False
                analysis['issues'].append(f"{sessions['negotiating']} sessions stuck in negotiation")
                analysis['recommendations'].append("Reset stuck sessions")
            
            if sessions.get('idle', 0) > 0:
                analysis['stable'] = False
                analysis['issues'].append(f"{sessions['idle']} idle sessions")
                analysis['recommendations'].append("Check router configuration")
        
        # Check metrics trends
        for server in ROUTINATOR_SERVERS:
            if server in self.results and 'metrics' in self.results[server]:
                metrics = self.results[server]['metrics']
                if metrics and metrics.get('vrps_total', 0) == 0:
                    analysis['issues'].append(f"{server}: No VRPs loaded")
                    analysis['recommendations'].append(f"Check Routinator initialization on {server}")
        
        return analysis
    
    def run_monitoring_cycle(self):
        """Run one complete monitoring cycle"""
        timestamp = datetime.now()
        self.results = {
            'timestamp': timestamp.isoformat(),
            'rpki_sessions': None
        }
        
        print(f"\n{'='*60}")
        print(f"Monitoring Cycle: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")
        
        # Check each Routinator server
        for server in ROUTINATOR_SERVERS:
            print(f"\n[{server}]")
            
            # Test RTR connection
            print(f"  Testing RTR connection...")
            rtr_result = self.test_rtr_connection(server)
            
            if rtr_result['status'] == 'OK':
                print(f"  ✓ RTR OK (Session: {rtr_result['session_id']}, "
                      f"Latency: {rtr_result['latency_ms']:.1f}ms)")
            else:
                print(f"  ✗ RTR Failed: {rtr_result['status']}")
            
            # Get HTTP metrics
            print(f"  Getting metrics...")
            metrics = self.get_http_metrics(server)
            
            if metrics:
                print(f"  ✓ Metrics: {metrics.get('rtr_connections', 0)} connections, "
                      f"{metrics.get('vrps_total', 0)} VRPs")
            else:
                print(f"  ✗ Metrics unavailable")
            
            self.results[server] = {
                'rtr': rtr_result,
                'metrics': metrics
            }
        
        # Check RPKI sessions on router
        print(f"\n[Router RPKI Sessions]")
        sessions = self.check_rpki_sessions()
        
        if 'error' not in sessions:
            print(f"  Total: {sessions.get('total', 0)}")
            print(f"  Established: {sessions.get('established', 0)}")
            print(f"  Negotiating: {sessions.get('negotiating', 0)}")
            print(f"  Idle: {sessions.get('idle', 0)}")
            if sessions.get('issues'):
                print(f"  Issues: {', '.join(sessions['issues'])}")
        else:
            print(f"  Error: {sessions['error']}")
        
        self.results['rpki_sessions'] = sessions
        
        # Analyze stability
        print(f"\n[Stability Analysis]")
        analysis = self.analyze_stability()
        
        if analysis['stable']:
            print("  ✓ System appears stable")
        else:
            print("  ⚠ Stability issues detected:")
            for issue in analysis['issues']:
                print(f"    - {issue}")
        
        if analysis['recommendations']:
            print("  Recommendations:")
            for rec in analysis['recommendations']:
                print(f"    → {rec}")
        
        self.results['analysis'] = analysis
        
        # Save to log
        self.save_results()
        
        return analysis['stable']
    
    def save_results(self):
        """Save monitoring results to log file"""
        try:
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(self.results) + '\n')
                
        except Exception as e:
            print(f"Failed to save log: {e}")
    
    def continuous_monitor(self, interval=60):
        """Run continuous monitoring"""
        print("Starting continuous monitoring...")
        print(f"Check interval: {interval} seconds")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                stable = self.run_monitoring_cycle()
                
                if not stable:
                    print("\n⚠ ALERT: Stability issues detected!")
                    # Could trigger alerts here
                
                print(f"\nNext check in {interval} seconds...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped.")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Routinator and RPKI Monitor')
    parser.add_argument('--once', action='store_true', 
                       help='Run once and exit')
    parser.add_argument('--interval', type=int, default=60,
                       help='Check interval in seconds (default: 60)')
    
    args = parser.parse_args()
    
    monitor = RoutinatorMonitor()
    
    if args.once:
        monitor.run_monitoring_cycle()
    else:
        monitor.continuous_monitor(interval=args.interval)

if __name__ == '__main__':
    main()