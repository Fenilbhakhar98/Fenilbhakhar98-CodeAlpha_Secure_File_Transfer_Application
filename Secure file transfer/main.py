import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key
def encrypt_file(file_path, password, salt):
    key = generate_key(password, salt)
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path + '.encrypted', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
def decrypt_file(file_path, password, salt):
    key = generate_key(password, salt)
    fernet = Fernet(key)
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path[:-9], 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)
password = 'my_secret_password'
salt = os.urandom(16)
file_path = 'example.txt'
encrypt_file(file_path, password, salt)
decrypt_file(file_path + '.encrypted', password, salt)