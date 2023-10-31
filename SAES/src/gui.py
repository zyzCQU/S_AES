# -*- coding: utf-8 -*-
# @Time : 2023/10/30 8:38
# @Author : hungry_xd
# @File : gui2
# @Project : SAES

from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit, QLabel, QComboBox
from src_func import *
class MyApp(QWidget):
    def __init__(self):
        super().__init__()

        self.input_type = QComboBox()
        self.input_type.addItem("二进制")
        self.input_type.addItem("ASCII")

        self.encrypt_text = QLineEdit()
        self.encrypt_key = QLineEdit()
        self.decrypt_text = QLineEdit()
        self.decrypt_key = QLineEdit()
        self.result_box = QTextEdit()

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        layout.addWidget(QLabel("输入类型:"))
        layout.addWidget(self.input_type)

        layout.addWidget(QLabel("加密信息:"))
        layout.addWidget(self.encrypt_text)
        layout.addWidget(QLabel("密钥:"))
        layout.addWidget(self.encrypt_key)
        encrypt_button = QPushButton("加密")
        encrypt_button.clicked.connect(self.encrypt)
        layout.addWidget(encrypt_button)

        layout.addWidget(QLabel("解密信息:"))
        layout.addWidget(self.decrypt_text)
        layout.addWidget(QLabel("密钥:"))
        layout.addWidget(self.decrypt_key)
        decrypt_button = QPushButton('解密')
        decrypt_button.clicked.connect(self.decrypt)
        layout.addWidget(decrypt_button)

        layout.addWidget(QLabel("结果:"))
        layout.addWidget(self.result_box)

        self.setLayout(layout)
        self.setWindowTitle('S-AES 加密/解密')
        self.show()

    def encrypt(self):
        plaintext = self.encrypt_text.text()
        key = self.encrypt_key.text()

        aes = AES128(key)
        ciphertext = aes.encrypto(plaintext)
        self.result_box.setText(ciphertext)

    def decrypt(self):
        ciphertext = self.decrypt_text.text()
        key = self.decrypt_key.text()

        aes = AES128(key)
        plaintext = aes.decrypto(ciphertext)
        self.result_box.setText(plaintext.decode('utf-8'))


if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    ex = MyApp()
    sys.exit(app.exec_())
