#!/usr/bin/env python3
"""
Decode RTR protocol errors from Routinator
"""

import socket
import struct
import time

SERVERS = ['lg.goline.ch', 'time.goline.ch']
RTR_PORT = 3323

# RTR Error Codes
ERROR_CODES = {
    0: "Corrupt Data",
    1: "Internal Error", 
    2: "No Data Available",
    3: "Invalid Request",
    4: "Unsupported Protocol Version",
    5: "Unsupported PDU Type",
    6: "Withdrawal of Unknown Record",
    7: "Duplicate Announcement Received",
    8: "Unexpected Protocol Version"
}

def decode_rtr_error(hostname):
    """Connect and decode RTR error response"""
    print(f"\n{'='*50}")
    print(f"Decoding RTR Error from {hostname}")
    print(f"{'='*50}")
    
    try:
        # Connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((hostname, RTR_PORT))
        
        # Send Reset Query with version 1
        reset_query = struct.pack('!BBHHI', 
            1,  # Protocol version 1
            2,  # PDU Type (Reset Query)
            0,  # Session ID high
            0,  # Session ID low
            8   # Length
        )
        
        sock.send(reset_query)
        print(f"Sent RTR Reset Query (Protocol v1)")
        
        # Receive response
        response = sock.recv(1024)
        
        if len(response) >= 16:
            # Parse Error Report PDU
            version, pdu_type = struct.unpack('!BB', response[:2])
            
            if pdu_type == 10:  # Error Report
                # Error Report format:
                # Version (1 byte)
                # Type = 10 (1 byte)  
                # Error Code (2 bytes)
                # Length (4 bytes)
                # Encapsulated PDU (variable)
                # Error Text (variable)
                
                error_code = struct.unpack('!H', response[2:4])[0]
                length = struct.unpack('!I', response[4:8])[0]
                
                print(f"\n✗ Error Report Received:")
                print(f"  Protocol Version: {version}")
                print(f"  Error Code: {error_code}")
                print(f"  Error Type: {ERROR_CODES.get(error_code, 'Unknown')}")
                print(f"  PDU Length: {length}")
                
                # Extract error text if present
                if length > 16:
                    # Skip encapsulated PDU (8 bytes) 
                    error_text_start = 16
                    error_text = response[error_text_start:length].decode('utf-8', errors='ignore')
                    if error_text:
                        print(f"  Error Message: {error_text}")
                
                # Try with version 0
                print(f"\nTrying with Protocol Version 0...")
                sock.close()
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((hostname, RTR_PORT))
                
                reset_query_v0 = struct.pack('!BBHHI',
                    0,  # Protocol version 0
                    2,  # PDU Type (Reset Query)
                    0,  # Reserved
                    0,  # Reserved
                    8   # Length
                )
                
                sock.send(reset_query_v0)
                response_v0 = sock.recv(1024)
                
                if response_v0:
                    version_v0, pdu_type_v0 = struct.unpack('!BB', response_v0[:2])
                    
                    if pdu_type_v0 == 3:  # Cache Response
                        print(f"✓ Success with Protocol Version 0!")
                        print(f"  Received Cache Response")
                        session_id = struct.unpack('!H', response_v0[2:4])[0]
                        print(f"  Session ID: {session_id}")
                    elif pdu_type_v0 == 10:
                        error_code_v0 = struct.unpack('!H', response_v0[2:4])[0]
                        print(f"✗ Still getting error with v0:")
                        print(f"  Error Code: {error_code_v0}")
                        print(f"  Error Type: {ERROR_CODES.get(error_code_v0, 'Unknown')}")
                    else:
                        print(f"  PDU Type: {pdu_type_v0}")
                        
            elif pdu_type == 3:  # Cache Response
                print(f"✓ Received Cache Response - RTR working!")
                session_id = struct.unpack('!H', response[2:4])[0]
                print(f"  Session ID: {session_id}")
            else:
                print(f"Received PDU Type: {pdu_type}")
                
        sock.close()
        
    except Exception as e:
        print(f"Error: {e}")

def check_http_status(hostname):
    """Check HTTP endpoint for more info"""
    print(f"\nChecking HTTP status endpoint...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((hostname, 8323))
        
        # Get status
        request = f"GET /status HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if len(response) > 50000:
                break
        
        sock.close()
        
        response_text = response.decode('utf-8', errors='ignore')
        
        # Parse JSON status if available
        if '"version"' in response_text:
            print("Status information available:")
            # Extract key info
            import re
            version_match = re.search(r'"version":\s*"([^"]+)"', response_text)
            if version_match:
                print(f"  Routinator version: {version_match.group(1)}")
            
            # Check for RTR info
            if '"rtr"' in response_text:
                print("  RTR service information found")
                
    except Exception as e:
        print(f"  HTTP status check failed: {e}")

def main():
    print("="*60)
    print("RTR Protocol Error Decoder")
    print("="*60)
    
    for server in SERVERS:
        decode_rtr_error(server)
        check_http_status(server)
    
    print(f"\n{'='*60}")
    print("ANALYSIS")
    print("="*60)
    
    print("\nPossible causes for RTR errors:")
    print("\n1. Protocol Version Mismatch:")
    print("   - Routinator may be configured to only accept specific RTR versions")
    print("   - Try configuring router to use RTR version 0 instead of 1")
    print("\n2. 'No Data Available' error:")
    print("   - Routinator cache may be empty or still initializing")
    print("   - Check if Routinator has finished downloading RPKI data")
    print("\n3. Internal Error:")
    print("   - Routinator may be experiencing memory or resource issues")
    print("   - Check Routinator logs and system resources")
    print("\n4. Configuration Issues:")
    print("   - Check if 'dirty' flag is set in Routinator config")
    print("   - Verify RTR listener is properly configured")

if __name__ == '__main__':
    main()