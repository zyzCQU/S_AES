# -*- coding: utf-8 -*-
# @Time : 2023/10/30 8:27
# @Author : hungry_xd
# @File : gui
# @Project : SAES
# -*- coding: utf-8 -*-

import base64
from Crypto.Cipher import AES
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QComboBox

class MyApp(QWidget):
    def __init__(self):
        super().__init__()

        self.iv = ''  # 偏移量
        self.key = ''  # 密钥

        self.input_type = QComboBox()
        self.input_type.addItem("二进制")
        self.input_type.addItem("ASCII")

        self.iv_entry = QLineEdit()
        self.key_entry = QLineEdit()
        self.encrypt_text = QLineEdit()
        self.decrypt_text = QLineEdit()
        self.result_box = QTextEdit()

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("输入类型:"))
        layout.addWidget(self.input_type)

        layout.addWidget(QLabel("偏移量:"))
        layout.addWidget(self.iv_entry)

        layout.addWidget(QLabel("密钥:"))
        layout.addWidget(self.key_entry)

        layout.addWidget(QLabel("加密信息:"))
        layout.addWidget(self.encrypt_text)
        encrypt_button = QPushButton("加密")
        encrypt_button.clicked.connect(self.encrypt_callback)
        layout.addWidget(encrypt_button)

        layout.addWidget(QLabel("解密信息:"))
        layout.addWidget(self.decrypt_text)
        decrypt_button = QPushButton('解密')
        decrypt_button.clicked.connect(self.decrypt_callback)
        layout.addWidget(decrypt_button)

        layout.addWidget(QLabel("结果:"))
        layout.addWidget(self.result_box)

        self.setLayout(layout)
        self.setWindowTitle('S-AES 加密/解密')
        self.show()

    def pad(self, value):
        BLOCK_SIZE = 16  # 设定字节长度
        count = len(value)
        if count % BLOCK_SIZE != 0:
            add = BLOCK_SIZE - (count % BLOCK_SIZE)
        else:
            add = 0
        text = value + ("\0".encode() * add)  # 这里的"\0"必须编码成bytes，不然无法和text拼接
        return text

    def AES_en(self, data):
        data = self.pad(data.encode())
        AES_obj = AES.new(self.key.encode("utf-8"), AES.MODE_CBC, self.iv.encode("utf-8"))
        AES_en_str = AES_obj.encrypt(data)
        AES_en_str = base64.b64encode(AES_en_str)
        AES_en_str = AES_en_str.decode("utf-8")
        return AES_en_str

    def AES_de(self, data):
        data = data.encode("utf-8")
        data = base64.decodebytes(data)
        AES_de_obj = AES.new(self.key.encode("utf-8"), AES.MODE_CBC, self.iv.encode("utf-8"))
        AES_de_str = AES_de_obj.decrypt(data)
        AES_de_str = AES_de_str.strip()
        AES_de_str = AES_de_str.decode("utf-8")
        return AES_de_str.strip(b'\x00'.decode())

    def encrypt_callback(self):
        self.key = self.key_entry.text()
        self.iv = self.iv_entry.text()
        plaintext = self.encrypt_text.text()
        if self.key and self.iv and plaintext:
            encrypted_text = self.AES_en(plaintext)
            self.result_box.clear()
            self.result_box.insertPlainText(f"加密为：{encrypted_text}")

    def decrypt_callback(self):
        self.key = self.key_entry.text()
        self.iv = self.iv_entry.text()
        ciphertext = self.decrypt_text.text()
        if self.key and self.iv and ciphertext:
            decrypted_text = self.AES_de(ciphertext)
            self.result_box.clear()
            self.result_box.insertPlainText(f"解密为：{decrypted_text}")


if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    ex = MyApp()
    sys.exit(app.exec_())
