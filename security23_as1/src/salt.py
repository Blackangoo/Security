from Crypto.Random import get_random_bytes
'''
salt = get_random_bytes(16)
nonce = get_random_bytes(12)

with open('utils/salt.txt', 'wb') as file:
    file.write(salt)

with open('utils/nonce.txt', 'wb') as file:
    file.write(nonce)
'''
def get_salt():
    with open('utils/salt.txt', 'rb') as file:
        salt = file.read()
    return salt

def get_nonce():
    with open('utils/nonce.txt', 'rb') as file:
        nonce = file.read()
    return nonce