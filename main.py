import sys

from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QPushButton,
    QWidget, QFileDialog,
)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Safety first")
        sign_file_button = QPushButton("Sign file")
        sign_file_button.clicked.connect(self.sign_file)
        verify_button = QPushButton("Verify signature")
        cryptic_button = QPushButton("Encryption/decryption ")

        hbox = QHBoxLayout()
        hbox.addWidget(sign_file_button)
        hbox.addWidget(verify_button)
        hbox.addWidget(cryptic_button)

        centralWidget = QWidget()
        centralWidget.setLayout(hbox)
        self.setCentralWidget(centralWidget)

    def sign_file(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)      #max one file
        file_dialog.setNameFilter("RSA files (*.rsa)")
        file_dialog.exec()


app = QApplication(sys.argv)

window = MainWindow()
window.show()

app.exec()