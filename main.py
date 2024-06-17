import sys

from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QPushButton,
    QWidget, QFileDialog, QMessageBox, QInputDialog,
)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Safety first")
        sign_file_button = QPushButton("Sign file")
        verify_button = QPushButton("Verify signature")
        cryptic_button = QPushButton("Encryption/decryption")
        key_button = QPushButton("Generate key")
        sign_file_button.clicked.connect(self.sign_file)
        verify_button.clicked.connect(self.verify)
        cryptic_button.clicked.connect(self.cryption)
        key_button.clicked.connect(self.key_generation)

        hbox = QHBoxLayout()
        hbox.addWidget(sign_file_button)
        hbox.addWidget(verify_button)
        hbox.addWidget(cryptic_button)
        hbox.addWidget(key_button)

        centralWidget = QWidget()
        centralWidget.setLayout(hbox)
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

    def sign_file(self):
        file = self.get_file()
        key = self.get_file_with_key()

        print(file.title())
        print(key.title())

    def verify(self):
        file = self.get_file()
        key = self.get_file_with_key()


    def cryption(self):
        try:
            pin = self.insert_pin()
        except Exception as e:
            self.show_error("Invalid PIN")

    def key_generation(self):
        directory_dialog = QFileDialog()
        directory_dialog.setFileMode(QFileDialog.FileMode.Directory)
        if directory_dialog.exec():
            directory = directory_dialog.selectedFiles()[0]
            print(directory)
        else:
            self.show_error("Machine spirit is not satisfied with your lack of cooperation")

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
