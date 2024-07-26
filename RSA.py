from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

def generate_keys():
    try:
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key
    except Exception as e:
        print(f"Error generating keys: {e}")
        return None, None

def encrypt(public_key, plaintext):
    try:
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        ciphertext = cipher.encrypt(plaintext.encode())
        return b64encode(ciphertext).decode()
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

def decrypt(private_key, ciphertext):
    try:
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_data = cipher.decrypt(b64decode(ciphertext))
        return decrypted_data.decode()
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

def rsa_menu():
    while True:
        choice = input("Choose operation for RSA (generate_keys/encrypt/decrypt/quit): ").strip().lower()
        if choice == "quit":
            break
        if choice == "generate_keys":
            private_key, public_key = generate_keys()
            if private_key and public_key:
                print("Public Key:")
                print(public_key.decode())
                print("\nPrivate Key:")
                print(private_key.decode())
        elif choice == "encrypt":
            public_key = input("Enter RSA public key: ").encode()
            plaintext = input("Enter plaintext for RSA encryption: ")
            ciphertext = encrypt(public_key, plaintext)
            if ciphertext:
                print("Encrypted:", ciphertext)
        elif choice == "decrypt":
            private_key = input("Enter RSA private key: ").encode()
            encrypted_text = input("Enter ciphertext for RSA decryption: ")
            decrypted_text = decrypt(private_key, encrypted_text)
            if decrypted_text:
                print("Decrypted:", decrypted_text)
        else:
            print("Invalid choice")

