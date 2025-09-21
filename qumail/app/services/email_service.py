import base64
import ast
import mimetypes
import smtplib
import ssl
import imaplib
import email
from email.message import EmailMessage
from email import policy
from typing import List, Tuple, Optional

from .config import SMTPConfig, IMAPConfig
from . import crypto_service


class EmailService:
    def __init__(self, smtp_cfg: SMTPConfig, imap_cfg: IMAPConfig):
        self.smtp_cfg = smtp_cfg
        self.imap_cfg = imap_cfg

    def send_email(
        self,
        sender: str,
        recipients: List[str],
        subject: str,
        body: bytes,
        attachments: List[Tuple[str, bytes]] | None,
        level: crypto_service.SecurityLevel,
        qkd_key_material: Optional[bytes],
        key_id: Optional[str] = None,
        key_offset: Optional[int] = None,
        key_bytes: Optional[int] = None,
        tampered: Optional[bool] = None,
    ) -> None:
        # Encrypt application payload (body) and each attachment
        enc = crypto_service.encrypt(level, body, qkd_key_material)

        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg["Subject"] = subject
        msg["X-QuMail-Level"] = str(level)
        msg["X-QuMail-Algo"] = enc.algo
        if enc.metadata:
            msg["X-QuMail-Meta"] = base64.b64encode(str(enc.metadata).encode()).decode()
        if key_id is not None:
            msg["X-QuMail-KeyId"] = key_id
        if key_offset is not None:
            msg["X-QuMail-KeyOffset"] = str(int(key_offset))
        if key_bytes is not None:
            msg["X-QuMail-KeyBytes"] = str(int(key_bytes))
        if tampered is not None:
            msg["X-QuMail-KMTampered"] = "true" if tampered else "false"

        # Add encrypted body as base64 payload
        msg.set_content("QuMail encrypted content. Use QuMail to decrypt.")
        msg.add_attachment(
            enc.ciphertext,
            maintype="application",
            subtype="octet-stream",
            filename="body.enc",
        )

        # Attach files (encrypt each)
        attachments = attachments or []
        for fname, data in attachments:
            aenc = crypto_service.encrypt(level, data, qkd_key_material)
            maintype, subtype = (mimetypes.guess_type(fname)[0] or "application/octet-stream").split("/")
            # Store encrypted attachment with per-part metadata header
            part_headers = []
            if aenc.metadata:
                part_headers.append(("X-QuMail-Meta", base64.b64encode(str(aenc.metadata).encode()).decode()))
            msg.add_attachment(
                aenc.ciphertext,
                maintype=maintype,
                subtype=subtype,
                filename=fname + ".enc",
                headers=part_headers or None,
            )

        # Send via SMTP
        if self.smtp_cfg.use_starttls:
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_cfg.host, self.smtp_cfg.port) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(self.smtp_cfg.username, self.smtp_cfg.password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(self.smtp_cfg.host, self.smtp_cfg.port) as server:
                server.login(self.smtp_cfg.username, self.smtp_cfg.password)
                server.send_message(msg)

    def list_inbox(self, mailbox: str = "INBOX", limit: int = 20) -> List[Tuple[str, str]]:
        """Return list of (uid, subject)."""
        items: List[Tuple[str, str]] = []
        if self.imap_cfg.use_ssl:
            M = imaplib.IMAP4_SSL(self.imap_cfg.host, self.imap_cfg.port)
        else:
            M = imaplib.IMAP4(self.imap_cfg.host, self.imap_cfg.port)
        try:
            M.login(self.imap_cfg.username, self.imap_cfg.password)
            M.select(mailbox)
            typ, data = M.search(None, 'ALL')
            if typ != 'OK':
                return items
            uids = data[0].split()
            for uid in reversed(uids[-limit:]):
                typ, msg_data = M.fetch(uid, '(RFC822)')
                if typ != 'OK':
                    continue
                eml = email.message_from_bytes(msg_data[0][1])
                items.append((uid.decode(), eml.get('Subject', '(no subject)')))
        finally:
            try:
                M.logout()
            except Exception:
                pass
        return items

    def fetch_message(self, uid: str, mailbox: str = "INBOX") -> EmailMessage | None:
        if self.imap_cfg.use_ssl:
            M = imaplib.IMAP4_SSL(self.imap_cfg.host, self.imap_cfg.port)
        else:
            M = imaplib.IMAP4(self.imap_cfg.host, self.imap_cfg.port)
        try:
            M.login(self.imap_cfg.username, self.imap_cfg.password)
            M.select(mailbox)
            typ, msg_data = M.fetch(uid, '(RFC822)')
            if typ != 'OK':
                return None
            # Use modern policy so we get EmailMessage with iter_attachments()
            return email.message_from_bytes(msg_data[0][1], policy=policy.default)
        finally:
            try:
                M.logout()
            except Exception:
                pass

    def decrypt_message(
        self,
        msg: EmailMessage,
        qkd_key_material: Optional[bytes],
    ) -> Tuple[str, List[Tuple[str, bytes]]]:
        """Return (decrypted_body_text, attachments list)."""
        level_str = msg.get('X-QuMail-Level', '4')
        try:
            level = int(level_str)
        except Exception:
            level = 4
        algo = msg.get('X-QuMail-Algo', '')

        # Find encrypted body attachment
        dec_body = ""
        dec_attachments: List[Tuple[str, bytes]] = []
        for part in msg.iter_attachments():
            filename = part.get_filename() or "attachment.bin"
            payload = part.get_payload(decode=True)
            if filename == 'body.enc':
                # Metadata for AES-GCM
                meta_b64 = msg.get('X-QuMail-Meta')
                meta = {}
                if meta_b64:
                    try:
                        meta = ast.literal_eval(base64.b64decode(meta_b64).decode())
                    except Exception:
                        meta = {}
                pt = crypto_service.decrypt(level, payload, qkd_key_material, metadata=meta)
                try:
                    dec_body = pt.decode('utf-8', errors='replace')
                except Exception:
                    dec_body = "<binary body>"
            else:
                # Decrypt attachment assuming same level; prefer per-part metadata
                meta_b64 = part.get('X-QuMail-Meta') or msg.get('X-QuMail-Meta')
                meta = {}
                if meta_b64:
                    try:
                        meta = ast.literal_eval(base64.b64decode(meta_b64).decode())
                    except Exception:
                        meta = {}
                pt = crypto_service.decrypt(level, payload, qkd_key_material, metadata=meta)
                # Remove .enc suffix if present
                if filename.endswith('.enc'):
                    filename = filename[:-4]
                dec_attachments.append((filename, pt))

        return dec_body, dec_attachments
