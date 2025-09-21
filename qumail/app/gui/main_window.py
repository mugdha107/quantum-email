from PyQt5 import QtWidgets, QtCore
from typing import List, Tuple
import base64

from ..services.email_service import EmailService
from ..services.km_client import KMClient
from ..services import crypto_service
from .compose_dialog import ComposeDialog
from .settings_dialog import SettingsDialog


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setWindowTitle("QuMail")
        self.resize(900, 600)

        self.email_service: EmailService = app.email_service
        self.km: KMClient = app.km_client

        # UI
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)

        # Intrusion banner (hidden by default)
        self.banner = QtWidgets.QLabel("Possible Intrusion Detected: Key integrity mismatch")
        self.banner.setStyleSheet("background-color:#b00020; color:white; padding:6px; font-weight:bold;")
        self.banner.setVisible(False)
        layout.addWidget(self.banner)

        # Toolbar
        toolbar = QtWidgets.QToolBar()
        self.addToolBar(toolbar)
        btn_compose = QtWidgets.QAction("Compose", self)
        btn_refresh = QtWidgets.QAction("Refresh", self)
        btn_settings = QtWidgets.QAction("Settings", self)
        toolbar.addAction(btn_compose)
        toolbar.addAction(btn_refresh)
        toolbar.addAction(btn_settings)

        btn_compose.triggered.connect(self.open_compose)
        btn_refresh.triggered.connect(self.refresh_inbox)
        btn_settings.triggered.connect(self.open_settings)

        # Inbox list
        self.inbox_list = QtWidgets.QListWidget()
        self.inbox_list.itemDoubleClicked.connect(self.open_message)
        layout.addWidget(self.inbox_list)

        self.statusBar().showMessage("Ready")

        self.refresh_inbox()

    def open_settings(self):
        dlg = SettingsDialog(self.app)
        dlg.exec_()

    def refresh_inbox(self):
        self.inbox_list.clear()
        try:
            items = self.email_service.list_inbox(limit=50)
            for uid, subject in items:
                item = QtWidgets.QListWidgetItem(f"{uid} | {subject}")
                item.setData(QtCore.Qt.UserRole, uid)
                self.inbox_list.addItem(item)
            self.statusBar().showMessage(f"Loaded {len(items)} messages")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Inbox Error", str(e))

    def open_compose(self):
        dlg = ComposeDialog(self.app)
        if dlg.exec_() == QtWidgets.QDialog.Accepted:
            self.statusBar().showMessage("Email sent")

    def open_message(self, item: QtWidgets.QListWidgetItem):
        uid = item.data(QtCore.Qt.UserRole)
        msg = self.email_service.fetch_message(uid)
        if not msg:
            return

        # Attempt decryption: request some key material based on policy
        level_str = msg.get('X-QuMail-Level', '4')
        try:
            level = int(level_str)
        except Exception:
            level = 4

        qkd_bytes = None
        tampered_detected = False

        key_id = msg.get('X-QuMail-KeyId')
        key_bytes_hdr = msg.get('X-QuMail-KeyBytes')
        key_offset_hdr = msg.get('X-QuMail-KeyOffset')
        km_tampered_hdr = msg.get('X-QuMail-KMTampered')
        if km_tampered_hdr == 'true':
            tampered_detected = True

        try:
            if level == 1:
                # Try to consume exact slice if key_id and bytes are present
                if key_id and key_bytes_hdr:
                    need = int(key_bytes_hdr)
                    offset, slice_b, t = self.km.consume_with_verify(key_id, need)
                    qkd_bytes = slice_b
                    tampered_detected = tampered_detected or t
                # Fallback if still None
                if qkd_bytes is None:
                    # Request a fresh large key
                    kid, kb, t = self.km.request_key_with_verify(length=65536)
                    qkd_bytes = kb
                    tampered_detected = tampered_detected or t
            elif level in (2, 3):
                # Derive small AES key
                kid, kb, t = self.km.request_key_with_verify(length=64)
                qkd_bytes = kb
                tampered_detected = tampered_detected or t
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "KM Error", str(e))
            return

        try:
            body, attachments = self.email_service.decrypt_message(msg, qkd_bytes)
            text = (
                f"Subject: {msg.get('Subject','')}\n"
                f"From: {msg.get('From','')}\n"
                f"To: {msg.get('To','')}\n\n"
                f"{body}\n\n"
                f"Attachments: {', '.join([a[0] for a in attachments])}"
            )
            dlg = QtWidgets.QMessageBox(self)
            dlg.setWindowTitle("Message")
            dlg.setText(text)
            dlg.exec_()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Decrypt Error", str(e))
            tampered_detected = tampered_detected or False

        # Show banner if tampering detected
        self.banner.setVisible(bool(tampered_detected))
