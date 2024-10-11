from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# ANSI escape codes for colors
GREEN = '\033[92m'  # Green color for success messages
BLUE = '\033[94m'   # Blue color for decrypted data
RED = '\033[91m'    # Red color for error messages
RESET = '\033[0m'   # Reset to default color

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def encrypt_data(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Encode the data as UTF-8 before padding and encryption
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data, key, iv):
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decoded_data = base64.b64decode(encrypted_data)
        decrypted_data = cipher.decrypt(decoded_data)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        # Decode the decrypted data from UTF-8
        return unpadded_data.decode('utf-8')
    except ValueError as e:
        if "Padding is incorrect" in str(e):
            raise ValueError(f"{RED}Decryption failed: Incorrect padding. This could be due to corrupted data.{RESET}")
        else:
            raise

def main():
    print("AES Encryption/Decryption Tool (Ver.1)")
    print("You will need to provide a 32-byte key and 16-byte IV in hexadecimal format to start the session.")
    
    # Ask for the session-specific key and IV at the beginning
    key_hex = input("Enter 32-byte key (hexadecimal):").strip()
    iv_hex = input("Enter 16-byte IV (hexadecimal):").strip()

    try:
        key = hex_to_bytes(key_hex)
        iv = hex_to_bytes(iv_hex)
        if len(key) != 32 or len(iv) != 16:
            raise ValueError("Invalid key or IV length. Key must be 32 bytes and IV must be 16 bytes.")
    except Exception as e:
        print(f"{RED}Error: {str(e)}{RESET}")
        return
    
    print("Session started. Use the key and IV for encryption and decryption.")
    
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
                    result = encrypt_data(data, key, iv)
                    print(f"{GREEN}Encrypted data:{result}{RESET}")

            elif action == 'd':
                while True:
                    data = input("Enter the base64-encoded data to decrypt: ")
                    if data.lower() == 'ex':
                        break
                    result = decrypt_data(data, key, iv)
                    print(f"{BLUE}Decrypted data:{result}{RESET}") 
                           
        except Exception as e:
            print(f"{RED}Operation failed: {str(e)}{RESET}")
        except Exception as e:
            print(f"{RED}An unexpected error occurred: {str(e)}{RESET}")

if __name__ == "__main__":
    main()
