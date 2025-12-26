key = #REDACTED
RNG_Nonce = np.random.default_rng()

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def bit_xor(ba1, ba2):
    return "".join([str(int(_a) ^ int(_b)) for _a, _b in zip(ba1, ba2)])

def split_blocks(msg, block_size):
    return [msg[i:i+block_size] for i in range(0, len(msg), block_size)]

@app.route('/', methods = ['GET', 'POST'])
async def index():
    if request.method == 'GET':
        return "Please POST the plaintext in JSON to obtain its encryption. JSON format is {'plaintext':base64plaintext}"
    if request.method == 'POST':
        data = request.json['plaintext']
        plaintext = b64decode(data)
        ciphertext = encrypt_decrypt(plaintext, key)
        ct_b64 = b64encode(ciphertext)
        return ct_b64

def encrypt_decrypt(msg :bytes, key:bytes):

    Nonce = RNG_Nonce.integers(0, np.iinfo(np.int_).max, endpoint=False)
    NonceExpansion = np.random.default_rng(seed=Nonce)

    cipher = AES.new(key, AES.MODE_ECB)
    msg_blocks = split_blocks(msg, 16)
    c = []
    for i, msg_block in enumerate(msg_blocks):
        NonceCtr, hashval = NonceExpansion.integers(256, size=(2, 16), dtype=np.ubyte)
        mixer = NonceCtr[-4:].copy()
        NonceCtr[-4:] = [x for x in i.to_bytes(4, 'big')]
        NonceCtr = bytes(NonceCtr)
        pad = cipher.encrypt(NonceCtr)
        hashval = "".join("{0:b}".format(x).rjust(8, '0') for x in hashval)
        mixer = "".join("{0:b}".format(x).rjust(8, '0') for x in mixer)
        hl = len(hashval) // 2
        hashval = bit_xor(hashval[:hl], hashval[hl:])
        for _ in range(3):
            hl = len(mixer) // 2
            mixer = bit_xor(mixer[:hl], mixer[hl:])
            hl = len(hashval) // 2
            hashval = bit_xor(hashval[:hl], hashval[hl:])
        hl = len(hashval) // 2
        hashval = bit_xor(hashval[:hl], hashval[hl:])
        hashval = int(hashval, 2)
        hashval = byte_xor(key[:hashval] + pad[hashval:hashval+1] + key[hashval+1:], key)
        mixer = int(mixer) // 1111
        hashval = bytes([x*mixer for x in hashval])
        pad = byte_xor(pad, hashval)

        c.append(byte_xor(pad, msg_block))
    return b''.join(c)