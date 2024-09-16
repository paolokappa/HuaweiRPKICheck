# HuaweiRPKICheck

This project provides two scripts to manage Huawei NetEngine RPKI sessions. The main purpose of these scripts is to address a known issue with Huawei NetEngine, where it fails to reset RPKI sessions even when the RPKI server becomes active again.

## Purpose of the Project

Huawei NetEngine routers have a bug where RPKI sessions do not automatically reset when the RPKI server becomes available after an outage. This can lead to routing issues that affect network security. This project automates the process of monitoring the status of RPKI sessions and resetting them when necessary.

## Project Structure

This project consists of two scripts:

1. **Credential Encryption Script** (`HuaweiRPKI_credgen.py`):  
   Used to securely generate and store encrypted credentials (such as SSH, SMTP, and email credentials) in a configuration file.
   
2. **RPKI Session Monitor and Reset Script** (`HuaweiRPKICheck.py`):  
   Monitors the RPKI sessions on a Huawei NetEngine router, identifies any problematic sessions, and resets them if needed. This script is intended to run periodically as a cron job.

---

## 1. Credential Encryption Script (`HuaweiRPKI_credgen.py`)

### Purpose

This script is used to generate a secure key for encrypting credentials, such as SSH and email settings, which are necessary for the session reset script. It then encrypts these credentials and saves them in a configuration file (`HuaweiRPKICheck.conf`), which the monitoring script will read.

### Usage

1. **Run the script**:  
   Execute the script to generate a new encryption key and store the encrypted credentials in `HuaweiRPKICheck.conf`.

2. **Configuration Variables**:  
   The script encrypts the following information:
   - **hostname**: IP address of the Huawei NetEngine device.
   - **username**: SSH username to access the Huawei NetEngine device.
   - **password**: SSH password for authentication.
   - **smtp_server**: SMTP server address for sending status emails.
   - **smtp_username**: Username for the SMTP server.
   - **smtp_password**: Password for the SMTP server.
   - **email_sender**: The email address used as the sender.
   - **email_receiver**: The recipient email address for receiving notifications about the session status.

3. **Output**:  
   - `secret.key`: Contains the generated encryption key.
   - `HuaweiRPKICheck.conf`: Contains the encrypted credentials.

### Example Code

```python
from cryptography.fernet import Fernet

# Generate a key to encrypt the data
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the encryption key
def load_key():
    return open("secret.key", "rb").read()

# Encrypt and write the data to the configuration file
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    with open("HuaweiRPKICheck.conf", "wb") as config_file:
        config_file.write(encrypted_data)

# Data to encrypt and store
config_data = """
hostname=192.168.1.1
username=rpki_sessions
password=YourPassword123
smtp_server=smtp.example.com
smtp_username=your-email@example.com
smtp_password=YourSMTPPassword
email_sender=noreply@example.com
email_receiver=admin@example.com
"""

# Generate a new key
generate_key()

# Load the key and encrypt the data
key = load_key()
encrypt_data(config_data, key)
print("Encrypted configuration file successfully created!")
```

### How to Run
1. Update the `config_data` variable with your own details (hostname, username, passwords, etc.).
2. Run the script:
   ```bash
   python3 HuaweiRPKI_credgen.py
   ```
   This will create `secret.key` and `HuaweiRPKICheck.conf`.

---

## 2. RPKI Session Monitor and Reset Script (`HuaweiRPKICheck.py`)

### Purpose

This script monitors the status of the RPKI sessions on the Huawei NetEngine device. If any session is found to be non-operational (in "Idle" or "Negotiation" states, or with `IPv4/IPv6 record = 0`), it will attempt to reset the session. Additionally, it sends a notification email when a session is reset or when an issue is detected.

### Usage

1. **Run the script**:  
   The script can be scheduled to run periodically (e.g., via a cron job) to continuously monitor RPKI sessions.

2. **Monitored States**:
   - **Established**: Operational sessions with valid IPv4/IPv6 records.
   - **Idle**: Sessions that are not operational and need to be reset.
   - **Negotiation**: Sessions in the negotiation state, which should also be reset if `IPv4/IPv6 record = 0`.
   - **Syn**: A session that is attempting to synchronize, but needs to be monitored.

3. **Output**:  
   An email is sent only if a session is not operational or is reset. The email includes a summary of the sessions and any actions taken.

### Example Code

```python
# -*- coding: utf-8 -*-
import paramiko
import time
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import re

# Function to decrypt data
def decrypt_data(key, file_path):
    fernet = Fernet(key)
    with open(file_path, "rb") as enc_file:
        encrypted_data = enc_file.read()
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    config = {}
    for line in decrypted_data.strip().split("\n"):
        k, v = line.split("=")
        config[k.strip()] = v.strip()
    return config

# Function to monitor and reset RPKI sessions
def check_rpki_session(hostname, username, password):
    # Logic to connect to the device and monitor RPKI sessions...
    # Send an email only if there are problematic sessions.
    pass

# Function to send email notifications
def send_email(smtp_server, smtp_username, smtp_password, sender_email, receiver_email, subject, body):
    msg = MIMEMultipart("alternative")
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP(smtp_server, 587) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
    except Exception as e:
        pass  # Handle error silently

# Main script
if __name__ == "__main__":
    key = open("secret.key", "rb").read()
    config = decrypt_data(key, "HuaweiRPKICheck.conf")

    hostname = config["hostname"]
    username = config["username"]
    password = config["password"]
    smtp_server = config["smtp_server"]
    smtp_username = config["smtp_username"]
    smtp_password = config["smtp_password"]
    email_sender = config["email_sender"]
    email_receiver = config["email_receiver"]

    log = check_rpki_session(hostname, username, password)

    if log:
        send_email(smtp_server, smtp_username, smtp_password, email_sender, email_receiver, "RPKI Session Alert", log)
```

### How to Run
1. Make sure to schedule this script using a cron job for continuous monitoring.
2. Run the script manually to test it:
   ```bash
   python3 HuaweiRPKICheck.py
   ```

---

## Conclusion

This project provides a simple and effective solution for managing Huawei NetEngine's RPKI session bug by automatically resetting sessions when necessary. By running the monitor script at regular intervals, you can ensure that RPKI sessions remain operational, improving the security and stability of your network.

Feel free to contribute, report issues, or suggest improvements!

