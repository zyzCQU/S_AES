# -*- coding: utf-8 -*-
# @Time : 2023/10/30 9:25
# @Author : hungry_xd
# @File : 4_1
# @Project : SAES
from Crypto.Cipher import AES


def encrypt(string, key1, iv1, key2, iv2):
    cipher1 = AES.new(key1, AES.MODE_CBC, iv1)
    x = AES.block_size - (len(string) % AES.block_size)
    if x != 0:
        string = string + chr(x) * x
    msg1 = cipher1.encrypt(string.encode('utf-8'))

    cipher2 = AES.new(key2, AES.MODE_CBC, iv2)
    x2 = AES.block_size - (len(msg1) % AES.block_size)
    if x2 != 0:
        msg1 = msg1 + bytes([x2]) * x2
    msg2 = cipher2.encrypt(msg1)

    return msg2


def decrypt(en_str, key2, iv2, key1, iv1):
    cipher2 = AES.new(key2, AES.MODE_CBC, iv2)
    msg1 = cipher2.decrypt(en_str)

    padding_len = msg1[-1]
    msg1 = msg1[:-padding_len]

    cipher1 = AES.new(key1, AES.MODE_CBC, iv1)
    msg = cipher1.decrypt(msg1)

    return msg


if __name__ == "__main__":
    import secrets

    infor = secrets.token_hex(16)  # 生成一个随机的 16 字节字符串
    key1 = secrets.token_bytes(32)  # 生成一个随机的 32 字节密钥
    iv1 = secrets.token_bytes(16)  # 生成一个随机的 16 字节初始化向量
    key2 = secrets.token_bytes(32)  # 生成一个随机的 32 字节密钥
    iv2 = secrets.token_bytes(16)  # 生成一个随机的 16 字节初始化向量
    print("随机生成的输入数据:")
    print("string:", infor)
    print("key1:", key1)
    print("iv1:", iv1)
    print("key2:", key2)
    print("iv2:", iv2)

    print("="*30)


    res = encrypt(infor, key1, iv1, key2, iv2)
    print('双重加密结果为：')
    print(res)
    print("双重解密结果为：")
    print(decrypt(res, key2, iv2, key1, iv1))
