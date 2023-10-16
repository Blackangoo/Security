from Crypto.Util.number import getPrime

def generate_keys():
    """
    Generates RSA key pairs and saves them to 'private.txt' and 'public.txt' files (Using textbook RSA).
    
    """
    p = getPrime(1500)
    q = getPrime(1500)

    n = p * q
    phiN = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phiN)

    with open("keys/private.txt", "w") as private_file, open("keys/public.txt", "w") as public_file:
        # Write the private key (d, n) to the private key file
        private_file.write(str((d, n)))
        
        # Write the public key (e, n) to the public key file
        public_file.write(str((e, n)))
