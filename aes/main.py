import aes, os
# key = os.urandom(16)
# iv = os.urandom(16)
# print("key: ")
# print(key.encode('utf-8'))
# print("iv: ")
# print(iv)
# encrypted = vaes.AES(key).encrypt_ctr(b'Attack at dawn', iv)
# print("encrypted: ")
# print(encrypted)
# print("decrypted: ")
# print(vaes.AES(key).decrypt_ctr(encrypted, iv))
# b'Attack at dawn'

#key =  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
#plaintext = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

#key =  bytes('0000000000000000', 'utf-8')
#plaintext = bytes('0000000000000000', 'utf-8')

key =  bytes('SOME 128 BIT KEY', 'utf-8')
plaintext = bytes('ATTACK AT DAWN!\x01', 'utf-8')

print('key: '+str(key.hex()))
print('plaintext: '+str(plaintext.hex()))

encrypted_block = aes.AES(key).encrypt_block(plaintext)
print("encrypted: ")
print(encrypted_block.hex())

decrypted_block = aes.AES(key).decrypt_block(encrypted_block)

print('key: '+str(key.hex()))
print("encrypted: ")
print(encrypted_block.hex())
print("decrypted: ")
print(decrypted_block.hex())
