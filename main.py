from AES import encrypt as aes_encrypt, decrypt as aes_decrypt
from DES import encrypt as des_encrypt, decrypt as des_decrypt
from RSA import generate_keys, encrypt as rsa_encrypt, decrypt as rsa_decrypt
from base64 import b64encode, b64decode

def main():
    algorithm = input("Choose algorithm (AES/DES/RSA): ").strip().upper()
    operation = input("Choose operation (encrypt/decrypt): ").strip().lower()
    
    if algorithm == "AES":
        key = input("Enter AES key (16/24/32 bytes): ").encode()
        if operation == "encrypt":
            plaintext = input("Enter plaintext for AES encryption: ")
            ciphertext = aes_encrypt(key, plaintext)
            print("AES Encrypted:", b64encode(ciphertext).decode())
        elif operation == "decrypt":
            encrypted_text = b64decode(input("Enter ciphertext for AES decryption: "))
            decrypted_text = aes_decrypt(key, encrypted_text)
            print("AES Decrypted:", decrypted_text)
        else:
            print("Invalid operation")
    
    elif algorithm == "DES":
        key = input("Enter DES key (8 bytes): ").encode()
        if operation == "encrypt":
            plaintext = input("Enter plaintext for DES encryption: ")
            ciphertext = des_encrypt(key, plaintext)
            print("DES Encrypted:", b64encode(ciphertext).decode())
        elif operation == "decrypt":
            encrypted_text = b64decode(input("Enter ciphertext for DES decryption: "))
            decrypted_text = des_decrypt(key, encrypted_text)
            print("DES Decrypted:", decrypted_text)
        else:
            print("Invalid operation")
    
    elif algorithm == "RSA":
        if operation == "generate_keys":
            private_key, public_key = generate_keys()
            print("Public Key:")
            print(public_key.decode())
            print("\nPrivate Key:")
            print(private_key.decode())
        elif operation == "encrypt":
            public_key = input("Enter RSA public key: ").encode()
            plaintext = input("Enter plaintext for RSA encryption: ")
            ciphertext = rsa_encrypt(public_key, plaintext)
            print("RSA Encrypted:", ciphertext)
        elif operation == "decrypt":
            private_key = input("Enter RSA private key: ").encode()
            encrypted_text = input("Enter ciphertext for RSA decryption: ")
            decrypted_text = rsa_decrypt(private_key, encrypted_text)
            print("RSA Decrypted:", decrypted_text)
        else:
            print("Invalid operation")
    else:
        print("Invalid algorithm")

if __name__ == "__main__":
    main()
