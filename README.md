# AES Encryption/Decryption Tool

This project provides several Python scripts that implement AES encryption and decryption using different modes and techniques. The scripts support password-based key derivation, padding, and both AES-CBC and AES-GCM encryption modes.

## Version Overview

1. **AES-CBC with Manual Key and IV (`PyGuardian-V1.py`)**  
   This version requires the user to manually input a 32-byte key and a 16-byte IV (Initialization Vector) in hexadecimal format. It uses AES in CBC mode, with data padding and base64 encoding of the encrypted output.

2. **AES-CBC with Password-Derived Key and Auto IV (`PyGuardian-V2.py`)**  
   This version improves upon V1 by deriving the encryption key from a user-provided password using PBKDF2. The IV is generated automatically, and encryption/decryption is handled through AES in CBC mode.

3. **AES-CBC with Salted Password-Derived Key and Auto IV (Improved) (`PyGuardian-V2.1.py`)**  
   Building on V2, this version adds password validation (e.g., length check), better error handling, and logging for easier troubleshooting. It uses salted password derivation for key generation and automatic IV generation, still using AES-CBC.

4. **AES-GCM with Salted Password-Derived Key and Integrity Check (`PyGuardian-V3.py`)**  
   This is the most secure version, using AES-GCM for encryption. AES-GCM provides both confidentiality and integrity verification through a tag. Like the previous versions, it derives the key from the password using PBKDF2 and adds logging for enhanced error tracing.

## Features
- AES encryption in CBC or GCM modes.
- Password-based key derivation using PBKDF2.
- Automatic generation of Initialization Vectors (IV).
- Support for Unicode data encryption.
- Data integrity checks (in AES-GCM mode).
- Logging and detailed error handling for troubleshooting.

## Prerequisites

- Python 3.6 or higher
- `pycryptodome` library (to install, run `pip install pycryptodome`)

## Installation

1. Clone this repository to your local machine.
   ```bash
   git clone https://github.com/RenX86/PyGuardian.git
   ```

2. Install the necessary dependencies.
   ```bash
   pip install pycryptodome
   ```

## Usage

### 1. AES-CBC with Manual Key and IV (`PyGuardian-V1.py`)

This version requires you to provide a 32-byte key and a 16-byte IV in hexadecimal format.  
**Steps**:
- Run the script:
   ```bash
   PyGuardian-V1.py
   ```
   or Run the .bat file
   ```
   PyGuardian.bat
   ```


- Enter a 32-byte key and 16-byte IV in hexadecimal format.
- Choose to either encrypt or decrypt data.

Example:
```bash
$ python PyGuardian-V1.py
Enter 32-byte key (hexadecimal): a0b1c2d3e4f5678910abcdef1234567890abcdef1234567890abcdef12345678
Enter 16-byte IV (hexadecimal): 1234567890abcdef12345678
Choose action (e: encrypt / d: decrypt / q: quit): e
Enter the data to encrypt (Unicode supported): Hello, World!
Encrypted data: XXXXXXXXXXXXXXXXXXXXXXX
```

### 2. AES-CBC with Password-Derived Key and Auto IV (`PyGuardian-V2.py`)

In this version, the key is derived from a password, and the IV is automatically generated.  
**Steps**:
- Run the script:
   ```bash
   PyGuardian-V2.py
   ```
   or Run the .bat file
   ```
   PyGuardian.bat
   ```
- Enter a password to derive the encryption key.
- Choose to either encrypt or decrypt data.

Example:
```bash
$ python PyGuardian-V2.py
Enter your password: ********
Key derived successfully from the password.
Choose action (e: encrypt / d: decrypt / q: quit): e
Enter the data to encrypt (Unicode supported): Hello, World!
Encrypted data: XXXXXXXXXXXXXXXXXXXXXXX
```

### 3. AES-CBC with Salted Password-Derived Key and Auto IV (Improved) (`PyGuardian-V2.1.py`)

This version includes improvements like password validation and logging.  
**Steps**:
- Run the script:
   ```bash
   PyGuardian-V2.1.py
   ```
   or Run the .bat file
   ```
   PyGuardian.bat
   ```
- Follow the same steps as in `V2.py`.

### 4. AES-GCM with Salted Password-Derived Key and Integrity Check (`PyGuardian-V3.py`)

This version uses AES-GCM, which provides both encryption and integrity verification.  
**Steps**:
- Run the script:
   ```bash
   PyGuardian-V3.py
   ```
   or Run the .bat file
   ```
   PyGuardian.bat
   ```
- Enter a password to derive the encryption key.
- Choose to either encrypt or decrypt data.

Example:
```bash
$ python PyGuardian-V3.py
Enter your password: ********
Key derived successfully from the password.
Choose action (e: encrypt / d: decrypt / q: quit): e
Enter the data to encrypt (Unicode supported): Hello, World!
Encrypted data: XXXXXXXXXXXXXXXXXXXXXXX
```

## Notes

- Ensure that the same password and method are used for both encryption and decryption.
- In AES-GCM (V3), any change in the encrypted data will result in decryption failure due to the integrity check.
