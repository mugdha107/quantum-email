from PyQt5 import QtWidgets
from ..services.config import load_config


class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, app):
        super().__init__()
        self.app = app
        self.setWindowTitle("Settings")
        self.resize(500, 400)

        cfg = self.app.config

        layout = QtWidgets.QVBoxLayout(self)
        form = QtWidgets.QFormLayout()

        # KM
        self.km_base = QtWidgets.QLineEdit(cfg.km.base_url)
        self.km_client = QtWidgets.QLineEdit(cfg.km.client_id)
        self.km_peer = QtWidgets.QLineEdit(cfg.km.peer_id)
        self.km_len = QtWidgets.QSpinBox()
        self.km_len.setRange(256, 10_000_000)
        self.km_len.setValue(cfg.km.default_key_length)

        form.addRow("KM Base URL:", self.km_base)
        form.addRow("KM Client ID:", self.km_client)
        form.addRow("KM Peer ID:", self.km_peer)
        form.addRow("KM Default Length:", self.km_len)

        # SMTP
        self.smtp_host = QtWidgets.QLineEdit(cfg.smtp.host)
        self.smtp_port = QtWidgets.QSpinBox()
        self.smtp_port.setRange(1, 65535)
        self.smtp_port.setValue(cfg.smtp.port)
        self.smtp_user = QtWidgets.QLineEdit(cfg.smtp.username)
        self.smtp_pass = QtWidgets.QLineEdit(cfg.smtp.password)
        self.smtp_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        self.smtp_tls = QtWidgets.QCheckBox()
        self.smtp_tls.setChecked(cfg.smtp.use_starttls)

        form.addRow("SMTP Host:", self.smtp_host)
        form.addRow("SMTP Port:", self.smtp_port)
        form.addRow("SMTP Username:", self.smtp_user)
        form.addRow("SMTP Password:", self.smtp_pass)
        form.addRow("SMTP STARTTLS:", self.smtp_tls)

        # IMAP
        self.imap_host = QtWidgets.QLineEdit(cfg.imap.host)
        self.imap_port = QtWidgets.QSpinBox()
        self.imap_port.setRange(1, 65535)
        self.imap_port.setValue(cfg.imap.port)
        self.imap_user = QtWidgets.QLineEdit(cfg.imap.username)
        self.imap_pass = QtWidgets.QLineEdit(cfg.imap.password)
        self.imap_pass.setEchoMode(QtWidgets.QLineEdit.Password)
        self.imap_ssl = QtWidgets.QCheckBox()
        self.imap_ssl.setChecked(cfg.imap.use_ssl)

        form.addRow("IMAP Host:", self.imap_host)
        form.addRow("IMAP Port:", self.imap_port)
        form.addRow("IMAP Username:", self.imap_user)
        form.addRow("IMAP Password:", self.imap_pass)
        form.addRow("IMAP SSL:", self.imap_ssl)

        layout.addLayout(form)

        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        layout.addWidget(btns)
        btns.accepted.connect(self.apply)
        btns.rejected.connect(self.reject)

    def apply(self):
        # Update runtime config in memory for current session
        cfg = self.app.config
        cfg.km.base_url = self.km_base.text().strip()
        cfg.km.client_id = self.km_client.text().strip()
        cfg.km.peer_id = self.km_peer.text().strip()
        cfg.km.default_key_length = int(self.km_len.value())

        cfg.smtp.host = self.smtp_host.text().strip()
        cfg.smtp.port = int(self.smtp_port.value())
        cfg.smtp.username = self.smtp_user.text().strip()
        cfg.smtp.password = self.smtp_pass.text()
        cfg.smtp.use_starttls = self.smtp_tls.isChecked()

        cfg.imap.host = self.imap_host.text().strip()
        cfg.imap.port = int(self.imap_port.value())
        cfg.imap.username = self.imap_user.text().strip()
        cfg.imap.password = self.imap_pass.text()
        cfg.imap.use_ssl = self.imap_ssl.isChecked()

        self.accept()
