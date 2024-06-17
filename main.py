import sys
import PyQt6.QtCore as Qt
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

        status_label = QLabel("Kowalki analiza")

        hbox = QHBoxLayout()
        vbox = QVBoxLayout()
        hbox.addWidget(sign_file_button)
        hbox.addWidget(verify_button)
        hbox.addWidget(encryption_button)
        hbox.addWidget(decryption_button)
        hbox.addWidget(key_button)

        vbox.addLayout(hbox)
        vbox.addWidget(status_label)

        centralWidget = QWidget()
        centralWidget.setLayout(vbox)
        self.setCentralWidget(centralWidget)

    def get_file(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)  # max one file
        file_dialog.setNameFilter("Files (*.pdf *.cpp *.xml)")
        if file_dialog.exec() == QFileDialog.DialogCode.Rejected:
            self.show_error("Error when choosing file")
            return
        return file_dialog.selectedFiles()[0]

    def get_file_with_key(self):
        key_file_dialog = QFileDialog()
        key_file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        key_file_dialog.setNameFilter("RSA files (*.rsa)")
        if key_file_dialog.exec() == QFileDialog.DialogCode.Rejected:
            self.show_error("Error when choosing key")
            return
        return key_file_dialog.selectedFiles()[0]

    def choose_directory(self):
        directory_dialog = QFileDialog()
        directory_dialog.setFileMode(QFileDialog.FileMode.Directory)
        if directory_dialog.exec():
            return directory_dialog.selectedFiles()[0]
        else:
            self.show_error("Error when choosing directory")

    def sign_file(self):
        file = self.get_file()
        key = self.get_file_with_key()

        print(file.title())
        print(key.title())

    def verify(self):
        file = self.get_file()
        xml_file = self.get_file()
        key = self.get_file_with_key()

    def encryption(self):
        file = self.get_file()
        try:
            pin = self.insert_pin()
        except Exception as e:
            self.show_error("Invalid PIN")

    def decryption(self):
        file = self.get_file()
        try:
            pin = self.insert_pin()
        except Exception as e:
            self.show_error("Invalid PIN")

    def key_generation(self):
        directory = self.choose_directory()

    def show_error(self, text):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setText(text)
        msg.setWindowTitle("Error")
        msg.adjustSize()
        msg.exec()

    def insert_pin(self):
        pin, ok = QInputDialog.getText(self, '"Encryption/decryption', 'Insert PIN?')
        # TODO validate PIN
        if ok:
            return pin
        else:
            raise Exception()


app = QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec()
