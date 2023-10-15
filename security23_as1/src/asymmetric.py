from Crypto.Random import get_random_bytes
from src import symmetric

def convert_key(key):
    key = key.strip('()').replace(' ', '')
    a_str, b_str = key.split(',')
    a = int(a_str)
    b = int(b_str)
    return a, b

def encrypt_rsa(plaintext, public_key_file):
    public = open(public_key_file, "r")
    public_key_str = public.read()
    public_key = convert_key(public_key_str)

    e, n = public_key
    plaintext_int = int.from_bytes(plaintext, byteorder='big')
    plaintext_int = int(plaintext.hex(),16)
    ciphertext_int = pow(plaintext_int, e, n)
    ciphertext = ciphertext_int.to_bytes((ciphertext_int.bit_length() + 7) // 8, byteorder='big')
    return ciphertext

def decrypt_rsa(ciphertext, private_key_file):
    private = open(private_key_file, "r")
    private_key_str = private.read()
    private_key =  convert_key(private_key_str)

    d, n = private_key
    ciphertext_int = int.from_bytes(ciphertext, byteorder='big')
    plaintext_int = pow(ciphertext_int, d, n)
    plaintext = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, byteorder='big')
    return plaintext

def asymmetric_encryption(public_key_file, input_file, output_file):
    symmetric_key = get_random_bytes(16)
    nonce = get_random_bytes(12)

    with open(input_file, 'rb') as file:
        plaintext = file.read()

    tag, ciphertext = symmetric.encrypt_gcm(plaintext, symmetric_key, nonce)

    encrypted_symmetric_key = encrypt_rsa(symmetric_key, public_key_file)

    with open(output_file, 'wb') as file:
        file.write(tag)
        file.write(nonce)
        file.write(encrypted_symmetric_key)
        file.write(ciphertext)

def asymmetric_decryption(private_key_file, input_file, output_file):
    with open(input_file, 'rb') as file:
        tag = file.read(16)
        nonce = file.read(12)
        encrypted_symmetric_key = file.read(375)
        ciphertext = file.read()
    
    symmetric_key = decrypt_rsa(encrypted_symmetric_key, private_key_file)

    plaintext = symmetric.decrypt_gcm(ciphertext, symmetric_key, nonce, tag)

    with open(output_file, 'wb') as file:
        file.write(plaintext)
