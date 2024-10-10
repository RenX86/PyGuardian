import base64
import getpass
import logging

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
SALT_SIZE = 32
IV_SIZE = 16
KEY_SIZE = 32
VERSION = b'\x01'  # Version 1 of our encryption scheme
MIN_PASSWORD_LENGTH = 8
ITERATION_COUNT = 1_000_000  # Increased from the original script

class EncryptionError(Exception):
    """Custom exception for encryption-related errors."""
    pass

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key using PBKDF2 with the provided salt."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATION_COUNT, hmac_hash_module=SHA256)

def encrypt_data(data: str, password: str) -> str:
    """Encrypt data with a password."""
    try:
        # Generate a random salt
        salt = get_random_bytes(SALT_SIZE)
        
        # Derive the key from the password and salt
        key = derive_key(password, salt)
        
        # Generate a random IV
        iv = get_random_bytes(IV_SIZE)
        
        # Create cipher and encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        # Combine version, salt, IV, and encrypted data
        combined = VERSION + salt + iv + encrypted_data
        
        # Encode as base64
        encoded = base64.b64encode(combined).decode('utf-8').replace("/", "-")
        
        logger.info("Data encrypted successfully.")
        return encoded
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise EncryptionError("Encryption failed due to an unexpected error.") from e

def decrypt_data(encrypted_data: str, password: str) -> str:
    """Decrypt data with a password."""
    try:
        # Decode from base64
        decoded = base64.b64decode(encrypted_data)
        
        # Extract components
        version = decoded[0:1]
        salt = decoded[1:SALT_SIZE+1]
        iv = decoded[SALT_SIZE+1:SALT_SIZE+IV_SIZE+1]
        ciphertext = decoded[SALT_SIZE+IV_SIZE+1:]
        
        # Check version
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")
        
        # Derive the key
        key = derive_key(password, salt)
        
        # Create cipher and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        
        logger.info("Data decrypted successfully.")
        return unpadded_data.decode('utf-8')
    except ValueError as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise EncryptionError("Decryption failed. The data may be corrupted or the password may be incorrect.") from e
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
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
        password = getpass.getpass(prompt)
        if validate_password(password):
            return password
        print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")

def main():
    print("AES Encryption/Decryption Tool (Ver. 2.1)")
    
    while True:
        action = input("Choose action (e: encrypt / d: decrypt / q: quit): ").lower()

        if action == 'q':
            print("Session ended.")
            break

        if action not in ['e', 'd']:
            print("Invalid action. Please choose 'e', 'd', or 'q'.")
            continue

        try:
            if action == 'e':
                data = input("Enter the data to encrypt (Unicode supported):")
                password = get_valid_password("Enter your password:")
                result = encrypt_data(data, password)
                print(f"Encrypted data:{result}")

            elif action == 'd':
                data = input("Enter the base64-encoded data to decrypt:")
                password = get_valid_password("Enter your password:")
                result = decrypt_data(data, password)
                print(f"Decrypted data:{result}")

        except EncryptionError as e:
            print(f"Operation failed: {str(e)}")
        except Exception as e:
            print(f"An unexpected error occurred: {str(e)}")

if __name__ == "__main__":
    main()