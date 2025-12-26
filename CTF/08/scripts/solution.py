from pwn import *
from Crypto.Util.number import long_to_bytes

# Connection details from the image
HOST = '141.85.224.115'
PORT = 7205

r = remote(HOST, PORT)

# 1. Get the flag data
r.sendlineafter(b"Choose an option: ", b"3")
r.recvuntil(b"Ciphertext: ")
ct = int(r.recvline().strip())
r.recvuntil(b"Value: ")
value = int(r.recvline().strip())

# 2. Calculate the original ciphertext
# ct = (c_flag + value) * 1337
c_flag = (ct // 1337) - value

# 3. Send the ciphertext to the Decrypt option
r.sendlineafter(b"Choose an option: ", b"2")
r.sendlineafter(b"Enter data to decrypt (integer ciphertext): ", str(c_flag).encode())

# 4. Extract the decrypted integer
r.recvuntil(b"Decrypted data: ")
flag_int = int(r.recvline().strip())

# 5. Convert integer to bytes
print(f"Flag: {long_to_bytes(flag_int).decode()}")

r.close()