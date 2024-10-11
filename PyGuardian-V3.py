import base64
import getpass
import logging
from math import e

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# ANSI escape codes for colors
GREEN = '\033[92m'  # Green color for success messages
BLUE = '\033[94m'   # Blue color for decrypted data
RED = '\033[91m'    # Red color for error messages
RESET = '\033[0m'   # Reset to default color


# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
SALT_SIZE = 32
NONCE_SIZE = 12  # GCM nonce size
KEY_SIZE = 32
TAG_SIZE = 16  # GCM tag size
VERSION = b'\x02'  # Updated version for GCM
MIN_PASSWORD_LENGTH = 8
ITERATION_COUNT = 1_000_000

class EncryptionError(Exception):
    """Custom exception for encryption-related errors."""
    pass

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key using PBKDF2 with the provided salt."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATION_COUNT, hmac_hash_module=SHA256)

def encrypt_data(data: str, password: str) -> str:
    """Encrypt data with a password using AES-GCM."""
    try:
        # Generate a random salt
        salt = get_random_bytes(SALT_SIZE)
        
        # Derive the key from the password and salt
        key = derive_key(password, salt)
        
        # Generate a nonce
        nonce = get_random_bytes(NONCE_SIZE)
        
        # Create cipher and encrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
        
        # Combine version, salt, nonce, ciphertext, and tag
        combined = VERSION + salt + nonce + ciphertext + tag
        
        # Encode as base64
        encoded = base64.b64encode(combined).decode('utf-8')
        
        logger.info("Data encrypted successfully using AES-GCM.")
        return encoded
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise EncryptionError("Encryption failed due to an unexpected error.") from e

def decrypt_data(encrypted_data: str, password: str) -> str:
    """Decrypt data with a password using AES-GCM."""
    try:
        # Decode from base64
        decoded = base64.b64decode(encrypted_data)
        
        # Extract components
        version = decoded[0:1]
        salt = decoded[1:SALT_SIZE+1]
        nonce = decoded[SALT_SIZE+1:SALT_SIZE+NONCE_SIZE+1]
        ciphertext = decoded[SALT_SIZE+NONCE_SIZE+1:-TAG_SIZE]
        tag = decoded[-TAG_SIZE:]
        
        # Check version
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        # Derive the key
        key = derive_key(password, salt)
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        
        logger.info("Data decrypted successfully using AES-GCM.")
        return decrypted_data.decode('utf-8')
    except ValueError as e:
        logger.error(f"{RED}Decryption failed: {str(e)}{RESET}")
        raise EncryptionError("Decryption failed. The data may be corrupted or the password may be incorrect.") from e
    except Exception as e:
        logger.error(f"{RED}Decryption failed: {str(e)}{RESET}")
        raise EncryptionError("Decryption failed due to an unexpected error.") from e

def validate_password(password: str) -> bool:
    """Validate the password meets minimum requirements."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    # Add more complexity requirements as needed
    return True

def get_valid_password(prompt: str) -> str:
    """Get a valid password from the user."""
    while True:
        #password = input(prompt) #Remove or Comment this parameter For invisible password
        password = getpass.getpass(prompt) #Uncomment to enable visible password
        if validate_password(password):
            return password
        print(f"{RED}Password must be at least {MIN_PASSWORD_LENGTH} characters long.{RESET}")

def main():
    print("AES-GCM Encryption/Decryption Tool (Ver.3)")
    
    while True:
        action = input("Choose action (e: encrypt / d: decrypt / q: quit): ").lower()

        if action == 'q':
            print("Session ended.")
            break

        if action not in ['e', 'd']:
            print(f"{RED}Invalid action. Please choose 'e', 'd', or 'q'.{RESET}")
            continue

        try:
            if action == 'e':
                while True:
                    data = input("Enter the data to encrypt (or type 'ex' to go back): ")
                    if data.lower() == 'ex':
                        break
                    password = get_valid_password("Enter your password: ")
                    result = encrypt_data(data, password)
                    print(f"{GREEN}Encrypted data:{result}{RESET}")

            elif action == 'd':
                while True:
                    data = input("Enter the base64-encoded data to decrypt (or type 'ex' to go back): ")
                    if data.lower() == 'ex':
                        break
                    password = get_valid_password("Enter your password: ")
                    result = decrypt_data(data, password)
                    print(f"{BLUE}Decrypted data:{result}{RESET}")

        except EncryptionError as e:
            print(f"Operation failed: {str(e)}")
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()