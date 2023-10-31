# -*- coding: utf-8 -*-
# @Time : 2023/10/30 9:52
# @Author : hungry_xd
# @File : 4_3
# @Project : SAES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def triple_encrypt(plaintext, keys):
    ciphertext = plaintext
    for key in keys:
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(pad(ciphertext, AES.block_size))
    return ciphertext

def triple_decrypt(ciphertext, keys):
    plaintext = ciphertext
    for key in reversed(keys):
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(plaintext), AES.block_size)
    return plaintext

# 示例使用的密钥列表
keys = [b'K1'*8, b'K2'*8, b'K3'*8]

# 待加密的明文
plaintext = '测试信息'.encode('utf-8')


# 加密
ciphertext = triple_encrypt(plaintext, keys)
print('加密后的密文:', ciphertext)

# 解密
decrypted_text = triple_decrypt(ciphertext, keys)
print('解密后的明文:', decrypted_text.decode())
