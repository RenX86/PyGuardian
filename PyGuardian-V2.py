from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import hashlib

# Derive a salt deterministically from the password (e.g., using SHA-256)
def derive_salt_from_password(password):
    return hashlib.sha256(password.encode()).digest()  # 32-byte deterministic salt

# Derive a key using PBKDF2 with the deterministic salt
def derive_key(password):
    salt = derive_salt_from_password(password)
    return PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)

# Encrypt data with automatic IV generation
def encrypt_data(data, key):
    iv = get_random_bytes(16)  # Generate random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(iv + encrypted_data).decode('utf-8')  # Prepend IV to ciphertext

# Decrypt data, extracting the IV
def decrypt_data(encrypted_data, key):
    try:
        decoded_data = base64.b64decode(encrypted_data)
        iv = decoded_data[:16]  # Extract the IV from the first 16 bytes
        encrypted_data = decoded_data[16:]  # The rest is the actual encrypted data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        return unpadded_data.decode('utf-8')
    except ValueError as e:
        if "Padding is incorrect" in str(e):
            raise ValueError("Decryption failed: Incorrect padding. This could be due to corrupted data.")
        else:
            raise

def main():
    print("AES Encryption/Decryption Tool with Password-Derived Key and Automatic IV Generation (Ver.2)")

    password = input("Enter your password: ").strip()

    # Derive the key from the password (same key will be generated each session for the same password)
    key = derive_key(password)
    print("Key derived successfully from the password.")

    while True:
        action = input("Choose action (e: encrypt / d: decrypt / q: quit): ").lower()

        if action == 'q':
            print("Session ended.")
            break

        if action not in ['e', 'd']:
            print("Invalid action. Please choose 'e', 'd', or 'q'.")
            continue

        if action == 'e':
            data = input("Enter the data to encrypt (Unicode supported): ")
            try:
                result = encrypt_data(data, key)
                print(f"Encrypted data: {result}")
            except Exception as e:
                print(f"Encryption error: {str(e)}")

        elif action == 'd':
            data = input("Enter the base64-encoded data to decrypt: ")
            try:
                result = decrypt_data(data, key)
                print(f"Decrypted data: {result}")
            except Exception as e:
                print(f"Decryption error: {str(e)}")

if __name__ == "__main__":
    main()