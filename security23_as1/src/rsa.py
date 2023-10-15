from Crypto.Util.number import getPrime

def generate_keys():
    p = getPrime(1500)
    q = getPrime(1500)
    n = p * q
    phiN = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phiN)
    private = open("private.txt", "w")
    public = open("public.txt", "w")
    private.write(str((d, n)))
    public.write(str((e,n)))
