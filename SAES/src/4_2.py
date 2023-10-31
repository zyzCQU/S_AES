# -*- coding: utf-8 -*-
# @Time : 2023/10/30 9:25
# @Author : hungry_xd
# @File : 4_2
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


def perform_meet_in_the_middle_attack(ciphertexts, plaintexts):
    # 尝试所有可能的密钥组合
    for key1 in range(2 ** 32):
        for key2 in range(2 ** 32):
            # 尝试解密并加密以获取中间值
            intermediate_values = []
            for ciphertext in ciphertexts:
                intermediate = decrypt(ciphertext, key2.to_bytes(16, 'big'), b'\x00' * 16, key1.to_bytes(16, 'big'), b'\x00' * 16)
                intermediate_values.append(intermediate)

            # 尝试加密并解密以获取密钥
            for plaintext in plaintexts:
                for intermediate in intermediate_values:
                    key = encrypt(plaintext, key1.to_bytes(16, 'big'), b'\x00' * 16, key2.to_bytes(16, 'big'), b'\x00' * 16)
                    if key == intermediate:
                        return key1.to_bytes(16, 'big') + key2.to_bytes(16, 'big')

    return None


if __name__ == "__main__":
    import secrets

    plaintexts = [b"plaintext1", b"plaintext2"]  # 明文列表
    ciphertexts = []  # 密文列表

    # 生成随机的密钥和初始化向量，并进行加密
    for plaintext in plaintexts:
        key1 = secrets.randbits(128).to_bytes(16, 'big')
        iv1 = b'\x00' * 16
        key2 = secrets.randbits(128).to_bytes(16, 'big')
        iv2 = b'\x00' * 16
        ciphertext = encrypt(plaintext.decode('utf-8'), key1, iv1, key2, iv2)
        ciphertexts.append(ciphertext)

    print("中间相遇攻击中...")
    recovered_key = perform_meet_in_the_middle_attack(ciphertexts, plaintexts)

    if recovered_key is not None:
        print("成功找到正确的密钥:", recovered_key)
    else:
        print("未找到正确的密钥")
