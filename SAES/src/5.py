import base64
from Crypto.Cipher import AES


# 原始密文和密钥
original_ciphertext = "RK4joPmZKoa8JPz+hQbVJQ=="
key = "1110011111100111"
iv = "1110011111100111"


# 解密原始密文
def decrypt_cbc(ciphertext, key, iv):
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv.encode("utf-8"))
    plaintext = cipher.decrypt(base64.b64decode(ciphertext))
    return plaintext
# 输出原始密文的解密结果
original_plaintext = decrypt_cbc(original_ciphertext, key, iv)
print("原始密文:", original_plaintext)
#将第一个密文分组的第一个字节更改为0xFF
tampered_ciphertext = base64.b64decode(original_ciphertext)
tampered_ciphertext = bytearray(tampered_ciphertext)
tampered_ciphertext[0] = 0xFF
# 解密篡改后的密文
tampered_ciphertext = base64.b64encode(tampered_ciphertext).decode("utf-8")
tampered_plaintext = decrypt_cbc(tampered_ciphertext, key, iv)
print("修改分组后密文:", tampered_plaintext)
