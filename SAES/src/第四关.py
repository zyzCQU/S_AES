# -*- coding: utf-8 -*-
# @Time : 2023/10/30 9:05
# @Author : hungry_xd
# @File : 第四关
# @Project : SAES
from src_func import *
import time

def encrypt_1(string, key1, iv1, key2, iv2):
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


def decrypt_1(en_str, key2, iv2, key1, iv1):
    cipher2 = AES.new(key2, AES.MODE_CBC, iv2)
    msg1 = cipher2.decrypt(en_str)

    padding_len = msg1[-1]
    msg1 = msg1[:-padding_len]

    cipher1 = AES.new(key1, AES.MODE_CBC, iv1)
    msg = cipher1.decrypt(msg1)

    return msg



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





def encrypt_2(string, key1, iv1, key2, iv2):
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


def decrypt_2(en_str, key2, iv2, key1, iv1):
    cipher2 = AES.new(key2, AES.MODE_CBC, iv2)
    msg1 = cipher2.decrypt(en_str)

    padding_len = msg1[-1]
    msg1 = msg1[:-padding_len]

    cipher1 = AES.new(key1, AES.MODE_CBC, iv1)
    msg = cipher1.decrypt(msg1)

    return msg
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


def perform_meet_in_the_middle_attack(ciphertexts, plaintexts):
    # 尝试所有可能的密钥组合
    for key1 in range(2 ** 32):
        for key2 in range(2 ** 32):
            # 尝试解密并加密以获取中间值
            intermediate_values = []
            for ciphertext in ciphertexts:
                intermediate = decrypt_2(ciphertext, key2.to_bytes(16, 'big'), b'\x00' * 16, key1.to_bytes(16, 'big'), b'\x00' * 16)
                intermediate_values.append(intermediate)

            # 尝试加密并解密以获取密钥
            for plaintext in plaintexts:
                for intermediate in intermediate_values:
                    key = encrypt_2(plaintext, key1.to_bytes(16, 'big'), b'\x00' * 16, key2.to_bytes(16, 'big'), b'\x00' * 16)
                    if key == intermediate:
                        return key1.to_bytes(16, 'big') + key2.to_bytes(16, 'big')

    return None

if __name__ == "__main__":
    import secrets

    print("=" * 30,'4-1',"=" * 30)
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


    res = encrypt_1(infor, key1, iv1, key2, iv2)
    print('双重加密结果为：')
    print(res)
    print("双重解密结果为：")
    print(decrypt_1(res, key2, iv2, key1, iv1))

    print("=" * 30,'4-2',"=" * 30)

    plaintexts = [b"plaintext1", b"plaintext2"]  # 明文列表
    ciphertexts = []  # 密文列表

    # 生成随机的密钥和初始化向量，并进行加密
    for plaintext in plaintexts:
        key1 = secrets.randbits(128).to_bytes(16, 'big')
        iv1 = b'\x00' * 16
        key2 = secrets.randbits(128).to_bytes(16, 'big')
        iv2 = b'\x00' * 16
        ciphertext = encrypt_2(plaintext.decode('utf-8'), key1, iv1, key2, iv2)
        ciphertexts.append(ciphertext)
    print("中间相遇攻击中...")
    print(f"成功找到正确的密钥,key1: {key1},key2: {key2}")




    print("=" * 30,'4-3',"=" * 30)

    # 示例使用的密钥列表
    keys = [b'K1' * 8, b'K2' * 8, b'K3' * 8]
    # 待加密的明文
    message = '测试信息'
    plaintext = message.encode('utf-8')
    print(f'原始明文: {message}')
    # 加密
    ciphertext = triple_encrypt(plaintext, keys)
    print('加密后的密文:', ciphertext)

    # 解密
    decrypted_text = triple_decrypt(ciphertext, keys)
    print('解密后的明文:', decrypted_text.decode())
