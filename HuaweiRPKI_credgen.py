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
username=rpki_user
password=mypassword
smtp_server=exchange.mail.com
smtp_username=mymailusername
smtp_password=mymailpassword
email_sender=huaweirpki@mail.com
email_receiver=soc@mail.com
"""

# Generate a new key
generate_key()

# Load the key and encrypt the data
key = load_key()
encrypt_data(config_data, key)
print("Encrypted configuration file successfully created!")
