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

# Function to connect via SSH and execute commands
def ssh_connect_and_execute(hostname, username, password, commands):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username, password=password)
        ssh = client.invoke_shell()

        for command in commands:
            ssh.send(command + '\n')
            time.sleep(2)

        output = ssh.recv(65535).decode('utf-8')
        return output
    finally:
        client.close()

# Function to generate the RPKI sessions HTML table with highlights for "Idle", "Negotiation", "Established" and "Syn" states
def generate_rpki_table(output):
    session_lines = output.splitlines()
    rows = []
    for line in session_lines:
        if re.search(r"\d+\.\d+\.\d+\.\d+", line):  # Find lines with IP
            rows.append(line.strip())

    table_html = """
    <table border="1" cellpadding="5" cellspacing="0">
        <thead>
            <tr>
                <th>Session</th>
                <th>State</th>
                <th>Age</th>
                <th>IPv4/IPv6 record</th>
            </tr>
        </thead>
        <tbody>
    """
    
    established_sessions = []
    idle_sessions = []
    negotiation_sessions = []
    syn_sessions = []
    sessions_to_reset = []

    for row in rows:
        parts = re.split(r"\s{2,}", row)  # Split row based on multiple spaces
        if len(parts) >= 4:  # Ensure at least 4 elements exist
            session_ip = parts[0]
            state = parts[1]
            record = parts[3]
            # Extract IPv4/IPv6 record numbers
            ipv4v6_record = list(map(int, record.split('/')))
            if state == "Idle" or state == "Negotiation":
                if state == "Idle":
                    idle_sessions.append(session_ip)
                if state == "Negotiation":
                    negotiation_sessions.append(session_ip)
                
                # Highlight Idle or Negotiation sessions with yellow background
                table_html += f"<tr><td>{parts[0]}</td><td style='background-color:yellow;'>{parts[1]}</td><td>{parts[2]}</td><td>{parts[3]}</td></tr>"
                
                # If IPv4/IPv6 record is 0/0, the session should be reset
                if ipv4v6_record[0] == 0 and ipv4v6_record[1] == 0:
                    sessions_to_reset.append(session_ip)

            elif state == "Established" and ipv4v6_record[0] > 0 and ipv4v6_record[1] > 0:
                established_sessions.append(session_ip)
                # Highlight Established sessions with green background
                table_html += f"<tr><td>{parts[0]}</td><td style='background-color:lightgreen;'>{parts[1]}</td><td>{parts[2]}</td><td>{parts[3]}</td></tr>"

            elif state == "Syn":
                syn_sessions.append(session_ip)
                # Highlight Syn sessions with orange background
                table_html += f"<tr><td>{parts[0]}</td><td style='background-color:orange;'>{parts[1]}</td><td>{parts[2]}</td><td>{parts[3]}</td></tr>"
            else:
                table_html += f"<tr><td>{parts[0]}</td><td>{parts[1]}</td><td>{parts[2]}</td><td>{parts[3]}</td></tr>"
    
    table_html += "</tbody></table>"
    return table_html, established_sessions, idle_sessions, negotiation_sessions, syn_sessions, sessions_to_reset

# Function to check RPKI session status and reset sessions if necessary
def check_rpki_session(hostname, username, password):
    command = "display rpki session"
    output = ssh_connect_and_execute(hostname, username, password, [command])

    # Generate the HTML table and retrieve Established, Idle, Negotiation, Syn sessions, and those to reset
    table_html, established_sessions, idle_sessions, negotiation_sessions, syn_sessions, sessions_to_reset = generate_rpki_table(output)

    log = f"<b>RPKI session status</b>:<br><br>{table_html}<br>"

    # Reset "Idle" or "Negotiation" sessions with IPv4/IPv6 record = 0
    if sessions_to_reset:
        log += f"<b>The following 'Idle' or 'Negotiation' sessions with IPv4/IPv6 record = 0 were reset</b>: {', '.join(sessions_to_reset)}<br>"
        reset_sessions(hostname, username, password, sessions_to_reset)
    
    if idle_sessions or negotiation_sessions or syn_sessions:
        log += f"<br><b>Warning</b>: There are 'Idle', 'Negotiation', or 'Syn' sessions, possible malfunction.<br>"

    if established_sessions and not (idle_sessions or negotiation_sessions or syn_sessions):
        # No issues found, so we return None to avoid sending an email
        return None

    return log

# Function to reset RPKI sessions
def reset_sessions(hostname, username, password, sessions_to_reset):
    for session in sessions_to_reset:
        command = f"reset rpki session {session}"
        ssh_connect_and_execute(hostname, username, password, [command])

# Function to send email
def send_email(smtp_server, smtp_username, smtp_password, sender_email, receiver_email, subject, body):
    msg = MIMEMultipart("alternative")
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    # Convert body to HTML
    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP(smtp_server, 587) as server:  # Assuming use of TLS
            server.starttls()
            server.login(smtp_username, smtp_password)  # SMTP Authentication
            server.sendmail(sender_email, receiver_email, msg.as_string())
    except Exception as e:
        pass  # Optionally handle the error without printing it

# Main script
if __name__ == "__main__":
    # Load the key and decrypt the configuration file
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

    # Check RPKI session status and generate log
    log = check_rpki_session(hostname, username, password)

    # Only send the email if there are issues
    if log:
        # Email subject and body
        subject = "RPKI Session Status Report"
        body = log

        # Send the email
        send_email(smtp_server, smtp_username, smtp_password, email_sender, email_receiver, subject, body)
