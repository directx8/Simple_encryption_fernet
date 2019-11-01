import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC    
from cryptography.fernet import Fernet


def GenerateKey():
    key = Fernet.generate_key()
    file = open('key.key', 'wb')
    file.write(key)
    file.close()


def MessageEcrypt(message):
    # Get key from file
    file = open('key.key', 'rb')
    key = file.read()
    file.close()

    # Encode the message
    encoded = message.encode()

    # Encrypt the message
    f = Fernet(key)
    encrypted = f.encrypt(encoded)
    
    print(encrypted)
    
    return encrypted
    

def MessageDecrypt(encMess):
    # Get key from file
    file = open('key.key', 'rb')
    key = file.read()
    file.close()
    
    # Decrypt the encrypted message
    f2 = Fernet(key)
    decrypted = f2.decrypt(encMess)

    # Decode the message
    original_message = decrypted.decode()
    print (original_message)


def FileEncrypt():
    # Get key from file
    file = open('key.key', 'rb')
    key = file.read()
    file.close()
    
    # Open the file to encrypt
    with open('encrypt_this.txt', 'rb') as f:
        data = f.read()
    
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    
    # Write the encrypted file
    with open('encrypt_this.encrypted', 'wb') as f:
        f.write(encrypted)

        
def FileDecrypt():
    # Get key from file
    file = open('key.key', 'rb')
    key = file.read()
    file.close()
    
    # Open the file to decrypt
    with open('encrypt_this.encrypted', 'rb') as f:
        data = f.read()
    
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    
    # Write the encrypted file
    with open('encrypt_this_decrypted.txt', 'wb') as f:
        f.write(decrypted)


# Real way to generate a key with password
def VarKeyGen(PassW):
    password = PassW.encode()
    
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    print(key)


VarKeyGen(input())