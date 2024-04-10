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
        cryptic_button = QPushButton("Encryption/decryption ")
        sign_file_button.clicked.connect(self.sign_file)
        verify_button.clicked.connect(self.verify)
        cryptic_button.clicked.connect(self.cryption)

        hbox = QHBoxLayout()
        hbox.addWidget(sign_file_button)
        hbox.addWidget(verify_button)
        hbox.addWidget(cryptic_button)

        centralWidget = QWidget()
        centralWidget.setLayout(hbox)
        self.setCentralWidget(centralWidget)

    def sign_file(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)  # max one file
        file_dialog.setNameFilter("RSA files (*.rsa)")
        file_dialog.exec()

        if file_dialog.exec() == QFileDialog.DialogCode.Rejected:
            self.show_error("Error when choosing key")
            return
        print(file_dialog.selectedFiles()[0].title())

    def verify(self):

        pass

    def cryption(self):
        try:
            pin = self.insert_pin()
        except Exception as e:
            self.show_error("Invalid PIN")

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
