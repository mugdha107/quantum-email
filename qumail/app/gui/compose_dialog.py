from PyQt5 import QtWidgets, QtCore
from typing import List, Tuple, Optional
import os
import base64

from ..services.email_service import EmailService
from ..services.km_client import KMClient
from ..services import crypto_service


class ComposeDialog(QtWidgets.QDialog):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.email_service: EmailService = app.email_service
        self.km: KMClient = app.km_client
        self.setWindowTitle("Compose Email")
        self.resize(700, 500)

        layout = QtWidgets.QVBoxLayout(self)

        form = QtWidgets.QFormLayout()
        self.txt_from = QtWidgets.QLineEdit(self.app.config.smtp.username)
        self.txt_to = QtWidgets.QLineEdit()
        self.txt_subject = QtWidgets.QLineEdit()
        self.cmb_level = QtWidgets.QComboBox()
        self.cmb_level.addItems([
            "4 - No Quantum Security",
            "3 - Placeholder (AES-GCM)",
            "2 - Quantum-aided AES-GCM",
            "1 - Quantum Secure OTP",
        ])
        # Default to level 2
        self.cmb_level.setCurrentIndex(2)

        form.addRow("From:", self.txt_from)
        form.addRow("To (comma-separated):", self.txt_to)
        form.addRow("Subject:", self.txt_subject)
        form.addRow("Security Level:", self.cmb_level)

        layout.addLayout(form)

        self.txt_body = QtWidgets.QPlainTextEdit()
        self.txt_body.setPlaceholderText("Write your message...")
        layout.addWidget(self.txt_body)

        # Attachments
        attach_layout = QtWidgets.QHBoxLayout()
        self.lst_attachments = QtWidgets.QListWidget()
        btn_add = QtWidgets.QPushButton("Add Attachment")
        btn_remove = QtWidgets.QPushButton("Remove Selected")
        attach_layout.addWidget(self.lst_attachments)
        v = QtWidgets.QVBoxLayout()
        v.addWidget(btn_add)
        v.addWidget(btn_remove)
        v.addStretch()
        attach_layout.addLayout(v)
        layout.addLayout(attach_layout)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        layout.addWidget(btns)

        btn_add.clicked.connect(self.add_attachment)
        btn_remove.clicked.connect(self.remove_attachment)
        btns.accepted.connect(self.on_send)
        btns.rejected.connect(self.reject)

        self._attachments: List[Tuple[str, bytes]] = []

    def add_attachment(self):
        paths, _ = QtWidgets.QFileDialog.getOpenFileNames(self, "Select files")
        for p in paths:
            try:
                with open(p, 'rb') as f:
                    data = f.read()
                fname = os.path.basename(p)
                self._attachments.append((fname, data))
                self.lst_attachments.addItem(f"{fname} ({len(data)} bytes)")
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "Attachment Error", str(e))

    def remove_attachment(self):
        row = self.lst_attachments.currentRow()
        if row >= 0:
            self.lst_attachments.takeItem(row)
            del self._attachments[row]

    def _level_value(self) -> int:
        # Map combobox index to level
        idx = self.cmb_level.currentIndex()
        mapping = {0: 4, 1: 3, 2: 2, 3: 1}
        return mapping.get(idx, 4)

    def on_send(self):
        sender = self.txt_from.text().strip()
        recipients = [x.strip() for x in self.txt_to.text().split(',') if x.strip()]
        subject = self.txt_subject.text().strip()
        body_text = self.txt_body.toPlainText()
        level = self._level_value()

        if not sender or not recipients:
            QtWidgets.QMessageBox.warning(self, "Validation", "Sender and at least one recipient required")
            return

        qkd_bytes: Optional[bytes] = None
        key_id: Optional[str] = None
        tampered: Optional[bool] = None
        key_offset: Optional[int] = 0
        key_bytes: Optional[int] = None
        try:
            # Determine required key length
            if level == 1:
                total_len = len(body_text.encode('utf-8')) + sum(len(d) for _, d in self._attachments)
                key_id, qkd_bytes, tampered = self.km.request_key_with_verify(length=max(total_len, self.app.config.km.default_key_length))
                key_bytes = total_len
            elif level in (2, 3):
                key_id, qkd_bytes, tampered = self.km.request_key_with_verify(length=64)
                key_bytes = 64
        except Exception as e:
            if level != 4:
                QtWidgets.QMessageBox.warning(self, "KM Error", f"Failed to get key: {e}")
                return

        try:
            # Audit: key requested
            if key_id:
                try:
                    self.app.db.log_audit(
                        op="requested",
                        key_id=key_id,
                        level=level,
                        client_id=self.app.config.km.client_id,
                        peer_id=self.app.config.km.peer_id,
                        message_id=None,
                        account_id=None,
                        tampered=bool(tampered),
                        notes="compose dialog",
                    )
                except Exception:
                    pass

            self.email_service.send_email(
                sender=sender,
                recipients=recipients,
                subject=subject,
                body=body_text.encode('utf-8'),
                attachments=self._attachments,
                level=level,
                qkd_key_material=qkd_bytes,
                key_id=key_id,
                key_offset=key_offset,
                key_bytes=key_bytes,
                tampered=tampered,
            )
            # Audit: encrypt message
            try:
                self.app.db.upsert_message(
                    external_id=None,
                    account_id=None,
                    subject=subject,
                    from_addr=sender,
                    to_addrs=recipients,
                    level=level,
                    direction='outgoing',
                    when=None,
                )
                if key_id:
                    self.app.db.log_audit(
                        op="encrypt",
                        key_id=key_id,
                        level=level,
                        client_id=self.app.config.km.client_id,
                        peer_id=self.app.config.km.peer_id,
                        message_id=None,
                        account_id=None,
                        tampered=bool(tampered),
                        notes="email sent",
                    )
            except Exception:
                pass
            if tampered:
                QtWidgets.QMessageBox.warning(self, "Intrusion Warning", "KM reported integrity mismatch (tampering simulated). The sent message used potentially tampered key material.")
            QtWidgets.QMessageBox.information(self, "Success", "Email sent")
            self.accept()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Send Error", str(e))
