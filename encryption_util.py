from Crypto.Cipher import AES
import base64

SECRET_KEY = "ThisIsASecretKey"

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

def encrypt(plain_text):
    plain_text = pad(plain_text)
    cipher = AES.new(SECRET_KEY.encode('utf8'), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(plain_text.encode('utf8'))).decode('utf-8')

def decrypt(cipher_text):
    cipher = AES.new(SECRET_KEY.encode('utf8'), AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(cipher_text))
    return unpad(decrypted_text.decode('utf-8'))