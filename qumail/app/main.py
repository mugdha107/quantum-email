import sys
import base64
from typing import Optional

from PyQt5 import QtWidgets

from .services.config import load_config
from .services.logger import setup_logger
from .services.km_client import KMClient
from .services.email_service import EmailService
from .services.db import Database, DBConfig
from .gui.main_window import MainWindow
from .gui.settings_dialog import SettingsDialog


class QuMailApp(QtWidgets.QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName("QuMail")
        self.config = load_config()
        self.logger = setup_logger(self.config.log_level)
        self.km_client = KMClient(self.config.km)
        self.email_service = EmailService(self.config.smtp, self.config.imap)
        self.db = Database(DBConfig(self.config.db_path))


def run():
    app = QuMailApp(sys.argv)

    # Simple startup checks
    if app.km_client.status():
        app.logger.info("KM Simulator reachable.")
    else:
        app.logger.warning("KM Simulator not reachable. Start it via run_km_simulator.py")

    win = MainWindow(app)
    win.show()
    # If no credentials configured, prompt Settings so user can log in at runtime
    if not app.config.smtp.username or not app.config.imap.username:
        dlg = SettingsDialog(app)
        dlg.exec_()
    sys.exit(app.exec_())
