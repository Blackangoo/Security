from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    cipher_text = cipher.encrypt(padded_data)
    return cipher_text

def decrypt_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)

def encrypt_cbc(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_data = pad(data, AES.block_size)
    cipher_text = cipher.encrypt(padded_data)
    return (iv, cipher_text)

def decrypt_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)

def encrypt_gcm(data, key, nonce):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher_text, tag = cipher.encrypt_and_digest(data)
    return (tag, cipher_text)

def decrypt_gcm(data, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(data, tag)
    return (decrypted_data)

'''
plaintext = b'/space.jpg'
cipher_text = encrypt_cbc(plaintext, key)
print(cipher_text)
plain_text = decrypt_cbc(cipher_text[1],key,cipher_text[0])
print(plain_text.decode())
'''
'''
plaintext = b"test secret message"
cipher_text = encrypt_gcm(plaintext, key, nonce)
print(cipher_text)
plain_text =  decrypt_gcm(cipher_text[1], key, nonce, cipher_text[0])
print(plain_text)
'''
'''
with open('test.txt', 'rb') as file:
    plaintext = file.read()

ciphertext = encrypt_ecb(plaintext, key)

with open('encrypted.txt', 'wb') as file:
    file.write(ciphertext)

with open('encrypted.txt', 'rb') as file:
    ciphertext = file.read()

plaintext = decrypt_ecb(ciphertext, key)

with open('decrypted.txt', 'wb') as file:
    file.write(plaintext)'''