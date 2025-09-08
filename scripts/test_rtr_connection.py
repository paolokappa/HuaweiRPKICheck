#!/usr/bin/env python3
"""
Test RTR protocol connectivity to Routinator servers
Checks if RTR ports are accessible and responsive
"""

import socket
import struct
import time
import sys
from datetime import datetime

# RTR Protocol constants
RTR_PORT = 3323
HTTP_PORT = 8323

# Servers to check
ROUTINATOR_SERVERS = [
    'lg.goline.ch',
    'time.goline.ch'
]

class RTRTester:
    """Test RTR protocol connectivity"""
    
    def __init__(self, hostname, port=RTR_PORT):
        self.hostname = hostname
        self.port = port
        self.socket = None
        
    def test_tcp_connection(self):
        """Test basic TCP connectivity"""
        try:
            print(f"Testing TCP connection to {self.hostname}:{self.port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            start_time = time.time()
            self.socket.connect((self.hostname, self.port))
            connect_time = (time.time() - start_time) * 1000
            
            print(f"  ✓ Connected successfully (latency: {connect_time:.2f}ms)")
            return True
            
        except socket.timeout:
            print(f"  ✗ Connection timeout")
            return False
        except socket.error as e:
            print(f"  ✗ Connection failed: {e}")
            return False
    
    def test_rtr_handshake(self):
        """Test RTR protocol handshake"""
        if not self.socket:
            return False
            
        try:
            print(f"Testing RTR protocol handshake...")
            
            # RTR Reset Query (version 1)
            # Protocol version = 1
            # PDU Type = 2 (Reset Query)
            # Session ID = 0 (request new session)
            # Length = 8
            reset_query = struct.pack('!BBHHI', 
                1,  # Protocol version
                2,  # PDU Type (Reset Query)
                0,  # Session ID (high)
                0,  # Session ID (low)  
                8   # Length
            )
            
            # Send Reset Query
            self.socket.send(reset_query)
            print("  → Sent RTR Reset Query")
            
            # Wait for response
            self.socket.settimeout(5)
            response = self.socket.recv(1024)
            
            if response:
                print(f"  ← Received response: {len(response)} bytes")
                
                # Parse response header
                if len(response) >= 8:
                    version, pdu_type = struct.unpack('!BB', response[:2])
                    print(f"    Protocol version: {version}")
                    print(f"    PDU Type: {pdu_type}")
                    
                    # PDU Type 3 = Cache Response
                    # PDU Type 10 = Error Report
                    if pdu_type == 3:
                        print("  ✓ Received Cache Response - RTR protocol working")
                        return True
                    elif pdu_type == 10:
                        print("  ⚠ Received Error Report from server")
                        return False
                    else:
                        print(f"  ⚠ Unexpected PDU type: {pdu_type}")
                        return False
            else:
                print("  ✗ No response received")
                return False
                
        except socket.timeout:
            print("  ✗ Response timeout")
            return False
        except Exception as e:
            print(f"  ✗ RTR handshake failed: {e}")
            return False
    
    def test_http_metrics(self):
        """Test HTTP metrics endpoint"""
        try:
            print(f"\nTesting HTTP metrics on {self.hostname}:{HTTP_PORT}...")
            
            http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            http_socket.settimeout(10)
            http_socket.connect((self.hostname, HTTP_PORT))
            
            # Send HTTP request for metrics
            request = b"GET /metrics HTTP/1.1\r\nHost: " + self.hostname.encode() + b"\r\nConnection: close\r\n\r\n"
            http_socket.send(request)
            
            # Read response
            response = b""
            while True:
                chunk = http_socket.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 10000:  # Limit response size
                    break
            
            http_socket.close()
            
            response_text = response.decode('utf-8', errors='ignore')
            
            if 'HTTP/1.1 200' in response_text:
                print("  ✓ HTTP metrics endpoint accessible")
                
                # Extract some metrics
                lines = response_text.split('\n')
                for line in lines:
                    if 'routinator_rtr_current_connections' in line:
                        print(f"    {line.strip()}")
                    elif 'routinator_rtr_bytes_written' in line:
                        print(f"    {line.strip()}")
                    elif 'routinator_vrps_total' in line:
                        print(f"    {line.strip()}")
                
                return True
            else:
                print("  ✗ HTTP metrics not accessible")
                return False
                
        except Exception as e:
            print(f"  ✗ HTTP test failed: {e}")
            return False
    
    def close(self):
        """Close connections"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
    
    def run_tests(self):
        """Run all connectivity tests"""
        print(f"\n{'='*50}")
        print(f"Testing: {self.hostname}")
        print(f"{'='*50}")
        
        results = {
            'tcp': False,
            'rtr': False,
            'http': False
        }
        
        # Test TCP connection
        results['tcp'] = self.test_tcp_connection()
        
        if results['tcp']:
            # Test RTR protocol
            results['rtr'] = self.test_rtr_handshake()
        
        # Test HTTP metrics (independent of RTR)
        results['http'] = self.test_http_metrics()
        
        self.close()
        
        # Summary
        print(f"\nSummary for {self.hostname}:")
        print(f"  TCP connectivity: {'✓' if results['tcp'] else '✗'}")
        print(f"  RTR protocol: {'✓' if results['rtr'] else '✗'}")
        print(f"  HTTP metrics: {'✓' if results['http'] else '✗'}")
        
        return results

def test_dns_resolution():
    """Test DNS resolution for Routinator servers"""
    print("Testing DNS resolution...")
    print("-" * 40)
    
    for server in ROUTINATOR_SERVERS:
        try:
            ip = socket.gethostbyname(server)
            print(f"  {server}: {ip} ✓")
        except socket.gaierror as e:
            print(f"  {server}: DNS resolution failed ✗")
            print(f"    Error: {e}")

def main():
    """Main test function"""
    print("="*60)
    print("RTR Protocol Connectivity Test")
    print(f"Timestamp: {datetime.now()}")
    print("="*60)
    
    # Test DNS first
    test_dns_resolution()
    
    # Test each server
    all_results = {}
    for server in ROUTINATOR_SERVERS:
        tester = RTRTester(server)
        results = tester.run_tests()
        all_results[server] = results
    
    # Overall summary
    print(f"\n{'='*60}")
    print("OVERALL SUMMARY")
    print("="*60)
    
    all_ok = True
    for server, results in all_results.items():
        status = "✓ OK" if all(results.values()) else "⚠ Issues detected"
        print(f"{server}: {status}")
        if not all(results.values()):
            all_ok = False
            failed = [k for k, v in results.items() if not v]
            print(f"  Failed: {', '.join(failed)}")
    
    print("\nRECOMMENDATIONS:")
    print("-" * 40)
    
    if not all_ok:
        print("⚠ Some connectivity issues detected:")
        print("")
        print("1. If TCP fails:")
        print("   - Check firewall rules (port 3323 for RTR)")
        print("   - Verify Routinator is running on the server")
        print("   - Check network connectivity to the server")
        print("")
        print("2. If RTR protocol fails but TCP works:")
        print("   - Routinator may be overloaded")
        print("   - Check Routinator logs for errors")
        print("   - Possible protocol version mismatch")
        print("")
        print("3. If HTTP metrics fail:")
        print("   - Check if HTTP listener is enabled (port 8323)")
        print("   - Verify Routinator configuration")
    else:
        print("✓ All connectivity tests passed!")
        print("  Routinator servers appear to be accessible.")
        print("  If you're still experiencing disconnections, check:")
        print("  - Routinator server logs for memory/CPU issues")
        print("  - Network stability between router and Routinator")
        print("  - RTR session timeout settings")
    
    return 0 if all_ok else 1

if __name__ == '__main__':
    sys.exit(main())