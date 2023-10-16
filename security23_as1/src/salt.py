from Crypto.Random import get_random_bytes

'''
# Run this if you need to reset the nonce and the salt 

salt = get_random_bytes(16)
nonce = get_random_bytes(12)

with open('utils/salt.txt', 'wb') as file:
    file.write(salt)

with open('utils/nonce.txt', 'wb') as file:
    file.write(nonce)
'''

def get_salt():
    """
    Reads and returns the salt value stored in a file.
    
    Returns:
        bytes: The salt value as bytes.
    """
    with open('utils/salt.txt', 'rb') as file:
        salt = file.read()
    return salt

def get_nonce():
    """
    Reads and returns the nonce value stored in a file.
    
    Returns:
        bytes: The nonce value as bytes.
    """
    with open('utils/nonce.txt', 'rb') as file:
        nonce = file.read()
    return nonce