# Private Chat - Writeup
The QR codes provide three Shamir secret sharing points over the prime field p. The shared secret is the constant term of the polynomial, which is recovered by Lagrange interpolation at x=0.

## Reconstructing the Secret

Given shares:

- (1, 41588560628171152593688072686229718387)
- (2, 102367892015091791145384104860017242567)
- (3, 137046074329932719059328595132049831898)

with p = 170141183460469231731687303715884105727, compute:

    secret = f(0)

Using Lagrange interpolation modulo p, the secret is:

    124849263629640035135927802326571365085

## Decrypting the Flag

The `encrypt.py` script uses AES-128-ECB with PKCS7 padding, where the key is:

    key = secret.to_bytes(16, "big")

Which yields the AES key (hex):

    5ded17f1f80815655d3f1d61dead32dd

Decrypting `flag.enc` with AES-128-ECB and removing PKCS7 padding gives:

    CRYPTO_CTF{too_many_shares_leaked}

### Final Flag: `CRYPTO_CTF{too_many_shares_leaked}`
