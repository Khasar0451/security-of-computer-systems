import sys
from PyQt6 import QtCore

import signer
from signer import *

from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout, QVBoxLayout,
    QMainWindow,
    QPushButton,
    QWidget, QFileDialog, QMessageBox, QInputDialog, QLabel
)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Safety first")
        sign_file_button = QPushButton("Sign file")
        verify_button = QPushButton("Verify signature")
        encryption_button = QPushButton("Encryption")
        decryption_button = QPushButton("Decryption")
        key_button = QPushButton("Generate key")
        sign_file_button.clicked.connect(self.sign_file)
        verify_button.clicked.connect(self.verify)
        encryption_button.clicked.connect(self.encryption)
        decryption_button.clicked.connect(self.decryption)
        key_button.clicked.connect(self.key_generation)

        self.status_label = QLabel("Witaj")
        self.status_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("background-color: qlineargradient(x1: 0, x2: 1, stop: 0 lightcoral, stop: 1 lightgreen)")

        hbox = QHBoxLayout()
        vbox = QVBoxLayout()
        hbox.addWidget(sign_file_button)
        hbox.addWidget(verify_button)
        hbox.addWidget(encryption_button)
        hbox.addWidget(decryption_button)
        hbox.addWidget(key_button)

        vbox.addLayout(hbox)
        vbox.addWidget(self.status_label)

        centralWidget = QWidget()
        centralWidget.setLayout(vbox)
        self.setCentralWidget(centralWidget)

    def display_success(self, text):
        self.status_label.setText(text)
        self.status_label.setStyleSheet("background-color: lightgreen")

    def get_file(self):
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Choose a file")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)  # max one file
        file_dialog.setNameFilter("Files (*.pdf *.cpp)")
        if file_dialog.exec() == QFileDialog.DialogCode.Rejected:
            self.show_error("Error when choosing file")
            raise Exception
        return file_dialog.selectedFiles()[0]

    def get_xml_file(self):
        file_dialog = QFileDialog()
        file_dialog.setWindowTitle("Choose an XML file")
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)  # max one file
        file_dialog.setNameFilter("File (*.xml)")
        if file_dialog.exec() == QFileDialog.DialogCode.Rejected:
            self.show_error("Error when choosing XML file")
            raise Exception
        return file_dialog.selectedFiles()[0]

    def get_file_with_key(self):
        key_file_dialog = QFileDialog()
        key_file_dialog.setWindowTitle("Choose a file with key")
        key_file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        key_file_dialog.setNameFilter("RSA files (*.pem)")
        if key_file_dialog.exec() == QFileDialog.DialogCode.Rejected:
            self.show_error("Error when choosing key")
            raise Exception
        return key_file_dialog.selectedFiles()[0]

    def choose_directory(self):
        directory_dialog = QFileDialog()
        directory_dialog.setWindowTitle("Choose a directory to save key")
        directory_dialog.setFileMode(QFileDialog.FileMode.Directory)
        if directory_dialog.exec():
            return directory_dialog.selectedFiles()[0]
        else:
            self.show_error("Error when choosing directory")
            raise Exception

    def sign_file(self):
        try:
            file = self.get_file()
            key_file = self.get_file_with_key()
            pin = self.insert_pin()
            private_key = load_private_key_from_file(key_file, pin)
        except Exception:
            return
        signer.create_xml(file, private_key)
        self.display_success("File signed")

    def verify(self):
        try:
            file = self.get_file()
            xml_file = self.get_xml_file()
            key_file = self.get_file_with_key()
            public_key = load_public_key_from_file(key_file)
        except Exception:
            return
        if verify_xml(xml_file, public_key, file):
            self.display_success("Signatures are identical")
        else:
            self.display_success("Signatures are different")

    def encryption(self):
        try:
            key_file = self.get_file_with_key()
            public_key = load_public_key_from_file(key_file)
            file = self.get_file()
        except Exception:
            return
        with open(file, "rb") as f:
            data = f.read()
            buffer = data

        with open(file, "wb") as f:
            f.write(encrypt_data(buffer, public_key))
        self.display_success("Encryption successful")

    def decryption(self):
        try:
            key_file = self.get_file_with_key()
        except Exception:
            return

        try:
            pin = self.insert_pin()
            private_key = load_private_key_from_file(key_file, pin)
            file = self.get_file()
            with open(file, "rb") as f:
                data = f.read()
                buffer = data

            with open(file, "wb") as f:
                f.write(decrypt_data(buffer, private_key))
            self.display_success("Decryption successful")
        except Exception as e:
            self.show_error("Invalid PIN")

    def key_generation(self):
        try:
            directory = self.choose_directory()
        except Exception:
            return
        pin = self.insert_pin()
        save_keys(path=directory, file_name="key", private_key=generate_rsa(), pin=pin)
        self.display_success("Key generated in " + directory)


    def show_error(self, text):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setText(text)
        msg.setWindowTitle("Error")
        msg.adjustSize()
        self.status_label.setText("Error occured!")
        self.status_label.setStyleSheet("background-color: lightcoral")
        msg.exec()

    def insert_pin(self):
        pin, ok = QInputDialog.getText(self, 'Hold!', 'Insert PIN')
        if ok:
            return pin
        else:
            raise Exception()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()

