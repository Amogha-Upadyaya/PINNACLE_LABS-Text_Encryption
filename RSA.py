from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

def generate_keys():
    try:
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        with open("rsa_private_key.pem", "wb") as prv_file:
            prv_file.write(private_key)
        with open("rsa_public_key.pem", "wb") as pub_file:
            pub_file.write(public_key)
        print("\nKeys have been saved to 'rsa_private_key.pem' and 'rsa_public_key.pem'")
        return private_key, public_key
    except Exception as e:
        print(f"\nError generating keys: {e}")
        return None, None

def read_key_from_file(file_path):
    try:
        with open(file_path, "rb") as key_file:
            return key_file.read()
    except Exception as e:
        print(f"\nError reading key from file: {e}")
        return None

def encrypt(public_key, plaintext):
    try:
        rsa_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        ciphertext = cipher.encrypt(plaintext.encode())
        return b64encode(ciphertext).decode()
    except Exception as e:
        print(f"\nError during encryption: {e}")
        return None

def decrypt(private_key, ciphertext):
    try:
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        decrypted_data = cipher.decrypt(b64decode(ciphertext))
        return decrypted_data.decode()
    except Exception as e:
        print(f"\nError during decryption: {e}")
        return None

def rsa_menu():
    while True:
        choice = input("\nChoose operation for RSA (generate_keys/encrypt/decrypt/quit): ").strip().lower()
        if choice == "quit":
            break
        if choice == "generate_keys":
            generate_keys()
        elif choice == "encrypt":
            public_key = read_key_from_file("rsa_public_key.pem")
            if public_key:
                plaintext = input("\nEnter plaintext for RSA encryption: ")
                ciphertext = encrypt(public_key, plaintext)
                if ciphertext:
                    print("\nEncrypted:", ciphertext)
        elif choice == "decrypt":
            private_key = read_key_from_file("rsa_private_key.pem")
            if private_key:
                encrypted_text = input("\nEnter ciphertext for RSA decryption: ")
                decrypted_text = decrypt(private_key, encrypted_text)
                if decrypted_text:
                    print("\nDecrypted:", decrypted_text)
        else:
            print("\nInvalid choice")
