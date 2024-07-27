# PINNACLE_LABS-Text_Encryption
The following repository documents the Text Encryption task assigned during a Cybersecurity Internship at Pinnacle Labs

# Objective
Create a cybersecurity project that encrypts text using different algorithms like AES, DES and RSA for secure data protection.

# Features
- **AES Encryption**: Supports AES encryption with key sizes of 16, 24, or 32 bytes.
- **DES Encryption**: Supports DES encryption with a key size of 8 bytes.
- **RSA Encryption**: Supports RSA encryption with key generation, encryption, and decryption functionalities.
- **Menu-driven Interface**: Provides a user-friendly interface for selecting encryption algorithms and operations.

# Requirements
- Python 3.x
- `pycryptodome` library

# Installation
1. Clone the repository:
   ```text
   git clone https://github.com/your-username/text-encryption-tool.git
   cd text-encryption-tool
   ```
2. Install the required library:
   ```text
   pip install pycryptodome
   ```

# Usage
## Running the Tool
To start the tool, run the main.py file:
```text
python main.py
```

## Main Menu
After running the tool, you will be presented with the main menu where you can choose the desired encryption algorithm:
```text
Choose algorithm (AES/DES/RSA/quit): 
```

## AES Encryption
1. Select `AES` from the main menu.
2. Choose the operation (`encrypt` or `decrypt`):
   ```text
   Choose operation for AES (encrypt/decrypt/quit):
   ```
3. Enter the AES key (16/24/32 bytes):
   ```text
   Enter AES key (16/24/32 bytes):
   ```
4. For encryption, enter the plaintext to be encrypted.
5. For decryption, enter the ciphertext to be decrypted.

## DES Encryption
1. Select `DES` from the main menu.
2. Choose the operation (`encrypt` or `decrypt`):
   ```text
   Choose operation for DES (encrypt/decrypt/quit):
   ```
3. Enter the DES key (8 bytes):
   ```text
   Enter DES key (8 bytes):
   ```
4. For encryption, enter the plaintext to be encrypted.
5. For decryption, enter the ciphertext to be decrypted.

## RSA Encryption
1. Select `RSA` from the main menu
2. Choose the operation (`generate_keys`, `encrypt` or `decrypt`):
   ```bash
   Choose operation for RSA (generate_keys/encrypt/decrypt/quit):
   ```
3. For key generation, the keys will be saved to `rsa_private_key.pem` and `rsa_public_key.pem`.
For encryption, ensure the public key file (`rsa_public_key.pem`) is present and enter the plaintext to be encrypted.
For decryption, ensure the private key file (`rsa_private_key.pem`) is present and enter the ciphertext to be decrypted.

# Example
## AES Encryption Example
```text
Choose algorithm (AES/DES/RSA/quit): AES
Choose operation for AES (encrypt/decrypt/quit): encrypt
Enter AES key (16/24/32 bytes): thisisaverysecretkey!
Enter plaintext for AES encryption: Hello, World!
Encrypted: 4bSyWctuHrZl1GoSyVIdWUNL9/RQcspe
```

## DES Encryption Example
```text
Choose algorithm (AES/DES/RSA/quit): DES
Choose operation for DES (encrypt/decrypt/quit): encrypt
Enter DES key (8 bytes): deskey12
Enter plaintext for DES encryption: Hello, World!
Encrypted: Zx8cDsdVqe5dKWeFby4YXtI=
```

## RSA Encryption Example
```text
Choose algorithm (AES/DES/RSA/quit): RSA
Choose operation for RSA (generate_keys/encrypt/decrypt/quit): generate_keys
Keys have been saved to 'rsa_private_key.pem' and 'rsa_public_key.pem'
Choose operation for RSA (generate_keys/encrypt/decrypt/quit): encrypt
Enter plaintext for RSA encryption: Hello, World!
Encrypted: QWxLcDh8ZGZ...
```
