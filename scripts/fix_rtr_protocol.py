#!/usr/bin/env python3
"""
Test correct RTR protocol format for Routinator
"""

import socket
import struct
import time

SERVERS = ['lg.goline.ch', 'time.goline.ch']
RTR_PORT = 3323

def test_rtr_formats(hostname):
    """Test different RTR packet formats"""
    print(f"\n{'='*50}")
    print(f"Testing RTR formats for {hostname}")
    print(f"{'='*50}")
    
    # Format 1: Standard Reset Query (8 bytes total)
    print("\n1. Testing standard Reset Query (8 bytes)...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((hostname, RTR_PORT))
        
        # Correct format: Version(1) + Type(1) + Reserved(2) + Length(4)
        reset_query = struct.pack('!BBHI',
            1,  # Protocol version
            2,  # PDU Type (Reset Query)
            0,  # Reserved (2 bytes)
            8   # Length (includes header)
        )
        
        print(f"   Sending: {reset_query.hex()}")
        sock.send(reset_query)
        
        response = sock.recv(1024)
        if response:
            version, pdu_type = struct.unpack('!BB', response[:2])
            print(f"   Response: Version={version}, PDU Type={pdu_type}")
            if pdu_type == 3:
                print("   ✓ Success! Got Cache Response")
            elif pdu_type == 10:
                error_code = struct.unpack('!H', response[2:4])[0]
                print(f"   ✗ Error code: {error_code}")
                if len(response) > 16:
                    error_msg = response[16:].decode('utf-8', errors='ignore').strip()
                    print(f"   Error message: {error_msg}")
        
        sock.close()
    except Exception as e:
        print(f"   Failed: {e}")
    
    # Format 2: Serial Query (12 bytes)
    print("\n2. Testing Serial Query (12 bytes)...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((hostname, RTR_PORT))
        
        # Serial Query: Version(1) + Type(1) + SessionID(2) + Length(4) + Serial(4)
        serial_query = struct.pack('!BBHII',
            1,  # Protocol version
            1,  # PDU Type (Serial Query)
            0,  # Session ID
            12, # Length
            0   # Serial Number
        )
        
        print(f"   Sending: {serial_query.hex()}")
        sock.send(serial_query)
        
        response = sock.recv(1024)
        if response:
            version, pdu_type = struct.unpack('!BB', response[:2])
            print(f"   Response: Version={version}, PDU Type={pdu_type}")
            if pdu_type == 3:
                print("   ✓ Success! Got Cache Response")
            elif pdu_type == 10:
                error_code = struct.unpack('!H', response[2:4])[0]
                print(f"   ✗ Error code: {error_code}")
        
        sock.close()
    except Exception as e:
        print(f"   Failed: {e}")
    
    # Format 3: Version 0 Reset Query
    print("\n3. Testing Version 0 Reset Query...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((hostname, RTR_PORT))
        
        reset_v0 = struct.pack('!BBHI',
            0,  # Protocol version 0
            2,  # PDU Type (Reset Query)
            0,  # Reserved
            8   # Length
        )
        
        print(f"   Sending: {reset_v0.hex()}")
        sock.send(reset_v0)
        
        response = sock.recv(1024)
        if response:
            version, pdu_type = struct.unpack('!BB', response[:2])
            print(f"   Response: Version={version}, PDU Type={pdu_type}")
            if pdu_type == 3:
                print("   ✓ Success! Got Cache Response")
                # Parse Cache Response
                session_id = struct.unpack('!H', response[2:4])[0]
                length = struct.unpack('!I', response[4:8])[0]
                print(f"   Session ID: {session_id}, Length: {length}")
            elif pdu_type == 10:
                error_code = struct.unpack('!H', response[2:4])[0]
                print(f"   ✗ Error code: {error_code}")
        
        sock.close()
    except Exception as e:
        print(f"   Failed: {e}")

def main():
    print("="*60)
    print("RTR Protocol Format Tester")
    print("="*60)
    
    for server in SERVERS:
        test_rtr_formats(server)
    
    print(f"\n{'='*60}")
    print("RECOMMENDATIONS")
    print("="*60)
    
    print("\nBased on the error 'invalid length', the issue appears to be:")
    print("1. The Reset Query packet structure was incorrect")
    print("2. Should use format: Version(1) + Type(1) + Reserved(2) + Length(4)")
    print("3. The Length field should be 8 (total packet size)")
    print("\nTo fix in HuaweiRPKICheck.py:")
    print("- Update the RTR packet format in the monitoring code")
    print("- Ensure proper struct packing with correct field sizes")

if __name__ == '__main__':
    main()