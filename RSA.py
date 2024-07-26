from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt(public_key, plaintext):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher.encrypt(plaintext.encode())
    return b64encode(ciphertext).decode()

def decrypt(private_key, ciphertext):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_data = cipher.decrypt(b64decode(ciphertext))
    return decrypted_data.decode()

# Example usage:
if __name__ == "__main__":
    private_key, public_key = generate_keys()
    
    print("Public Key:")
    print(public_key.decode())
    print("\nPrivate Key:")
    print(private_key.decode())
    
    plaintext = "Hello, RSA encryption and decryption!"
    print("\nPlaintext:", plaintext)
    
    ciphertext = encrypt(public_key, plaintext)
    print("Encrypted:", ciphertext)
    
    decrypted_text = decrypt(private_key, ciphertext)
    print("Decrypted:", decrypted_text)
