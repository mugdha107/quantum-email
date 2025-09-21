import base64
import os
from dataclasses import dataclass
from typing import Optional, List, Tuple

from flask import Flask, render_template, request, redirect, url_for, session, flash

from ..app.services.config import KMConfig, SMTPConfig, IMAPConfig
from ..app.services.km_client import KMClient
from ..app.services.email_service import EmailService
from ..app.services import crypto_service


@dataclass
class UserContext:
    smtp: SMTPConfig
    imap: IMAPConfig


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("WEB_APP_SECRET", "change-this-secret")

    # Global KM client (can still be changed via settings if needed)
    km = KMClient(KMConfig(
        base_url=os.getenv("KM_BASE_URL", "http://127.0.0.1:5001"),
        client_id=os.getenv("KM_CLIENT_ID", "Alice"),
        peer_id=os.getenv("KM_PEER_ID", "Bob"),
        default_key_length=int(os.getenv("KM_DEFAULT_KEY_LENGTH", "4096")),
        integrity_secret=os.getenv("KM_INTEGRITY_SECRET", "change_this_demo_secret"),
    ))

    def get_ctx() -> Optional[UserContext]:
        if "smtp" in session and "imap" in session:
            s = session["smtp"]
            i = session["imap"]
            return UserContext(
                smtp=SMTPConfig(
                    host=s["host"], port=int(s["port"]), username=s["username"], password=s["password"], use_starttls=bool(s["use_starttls"]),
                ),
                imap=IMAPConfig(
                    host=i["host"], port=int(i["port"]), username=i["username"], password=i["password"], use_ssl=bool(i["use_ssl"]),
                ),
            )
        return None

    @app.route("/")
    def index():
        if not get_ctx():
            return redirect(url_for("login"))
        return redirect(url_for("inbox"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            mode = request.form.get("mode", "simple")

            # Provider presets
            provider = request.form.get("provider", "gmail")
            email_addr = request.form.get("email", "").strip()
            password = request.form.get("password", "").strip()

            presets = {
                "gmail": {
                    "smtp_host": "smtp.gmail.com", "smtp_port": 587, "smtp_tls": True,
                    "imap_host": "imap.gmail.com", "imap_port": 993, "imap_ssl": True,
                },
                "yahoo": {
                    "smtp_host": "smtp.mail.yahoo.com", "smtp_port": 587, "smtp_tls": True,
                    "imap_host": "imap.mail.yahoo.com", "imap_port": 993, "imap_ssl": True,
                },
                "outlook": {
                    "smtp_host": "smtp.office365.com", "smtp_port": 587, "smtp_tls": True,
                    "imap_host": "outlook.office365.com", "imap_port": 993, "imap_ssl": True,
                },
            }

            if mode == "simple":
                if not email_addr or not password:
                    flash("Please provide email and password (App Password if required)", "danger")
                    return render_template("login.html")
                preset = presets.get(provider, presets["gmail"])
                session["smtp"] = {
                    "host": preset["smtp_host"],
                    "port": preset["smtp_port"],
                    "username": email_addr,
                    "password": password,
                    "use_starttls": preset["smtp_tls"],
                }
                session["imap"] = {
                    "host": preset["imap_host"],
                    "port": preset["imap_port"],
                    "username": email_addr,
                    "password": password,
                    "use_ssl": preset["imap_ssl"],
                }
            else:
                # Advanced mode
                smtp_host = request.form.get("smtp_host", "").strip()
                smtp_port = int(request.form.get("smtp_port", "587").strip() or 587)
                smtp_user = request.form.get("smtp_user", "").strip()
                smtp_pass = request.form.get("smtp_pass", "").strip()
                smtp_tls = request.form.get("smtp_tls") == "on"

                imap_host = request.form.get("imap_host", "").strip()
                imap_port = int(request.form.get("imap_port", "993").strip() or 993)
                imap_user = request.form.get("imap_user", "").strip()
                imap_pass = request.form.get("imap_pass", "").strip()
                imap_ssl = request.form.get("imap_ssl") == "on"

                if not smtp_user or not imap_user:
                    flash("Please provide SMTP/IMAP usernames", "danger")
                    return render_template("login.html")

                session["smtp"] = {
                    "host": smtp_host or "smtp.gmail.com",
                    "port": smtp_port,
                    "username": smtp_user,
                    "password": smtp_pass,
                    "use_starttls": smtp_tls,
                }
                session["imap"] = {
                    "host": imap_host or "imap.gmail.com",
                    "port": imap_port,
                    "username": imap_user,
                    "password": imap_pass,
                    "use_ssl": imap_ssl,
                }

            flash("Logged in.", "success")
            return redirect(url_for("inbox"))

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out.", "info")
        return redirect(url_for("login"))

    @app.route("/inbox")
    def inbox():
        ctx = get_ctx()
        if not ctx:
            return redirect(url_for("login"))
        es = EmailService(ctx.smtp, ctx.imap)
        try:
            items = es.list_inbox(limit=50)
        except Exception as e:
            flash(f"Inbox error: {e}", "danger")
            items = []
        return render_template("inbox.html", items=items)

    @app.route("/compose", methods=["GET", "POST"])
    def compose():
        ctx = get_ctx()
        if not ctx:
            return redirect(url_for("login"))
        if request.method == "POST":
            sender = (request.form.get("from", "").strip() or ctx.smtp.username).strip()
            to_raw = request.form.get("to", "").strip()
            subject = request.form.get("subject", "").strip()
            level = int(request.form.get("level", "2"))
            body = request.form.get("body", "").encode("utf-8")
            files = request.files.getlist("attachments")
            attachments: List[Tuple[str, bytes]] = []
            for f in files:
                if not f or not f.filename:
                    continue
                attachments.append((f.filename, f.read()))

            # Prepare key material
            qkd_bytes = None
            key_id: Optional[str] = None
            tampered: Optional[bool] = None
            key_offset: Optional[int] = 0
            key_bytes: Optional[int] = None

            try:
                if level == 1:
                    total_len = len(body) + sum(len(d) for _, d in attachments)
                    key_id, qkd_bytes, tampered = km.request_key_with_verify(length=max(total_len, km.cfg.default_key_length))
                    key_bytes = total_len
                elif level in (2, 3):
                    key_id, qkd_bytes, tampered = km.request_key_with_verify(length=64)
                    key_bytes = 64
            except Exception as e:
                if level != 4:
                    flash(f"KM error: {e}", "danger")
                    return render_template("compose.html")

            try:
                es = EmailService(ctx.smtp, ctx.imap)
                # Allow single or multiple recipients; split only if commas exist
                recipients = [to_raw.strip()] if "," not in to_raw else [x.strip() for x in to_raw.split(',') if x.strip()]
                es.send_email(
                    sender=sender,
                    recipients=recipients,
                    subject=subject,
                    body=body,
                    attachments=attachments,
                    level=level,
                    qkd_key_material=qkd_bytes,
                    key_id=key_id,
                    key_offset=key_offset,
                    key_bytes=key_bytes,
                    tampered=tampered,
                )
                if tampered:
                    flash("Warning: KM integrity mismatch detected (intrusion simulation).", "warning")
                flash("Email sent.", "success")
                return redirect(url_for("inbox"))
            except Exception as e:
                flash(f"Send error: {e}", "danger")
                return render_template("compose.html")

        return render_template("compose.html")

    @app.route("/message/<uid>")
    def message(uid: str):
        ctx = get_ctx()
        if not ctx:
            return redirect(url_for("login"))
        es = EmailService(ctx.smtp, ctx.imap)
        msg = es.fetch_message(uid)
        if not msg:
            flash("Message not found.", "warning")
            return redirect(url_for("inbox"))

        level_str = msg.get('X-QuMail-Level', '4')
        try:
            level = int(level_str)
        except Exception:
            level = 4

        qkd_bytes = None
        tampered_detected = False
        key_id = msg.get('X-QuMail-KeyId')
        key_bytes_hdr = msg.get('X-QuMail-KeyBytes')
        km_tampered_hdr = msg.get('X-QuMail-KMTampered')
        if km_tampered_hdr == 'true':
            tampered_detected = True

        try:
            if level == 1:
                if key_id and key_bytes_hdr:
                    need = int(key_bytes_hdr)
                    offset, slice_b, t = km.consume_with_verify(key_id, need)
                    qkd_bytes = slice_b
                    tampered_detected = tampered_detected or t
                if qkd_bytes is None:
                    kid, kb, t = km.request_key_with_verify(length=65536)
                    qkd_bytes = kb
                    tampered_detected = tampered_detected or t
            elif level in (2, 3):
                kid, kb, t = km.request_key_with_verify(length=64)
                qkd_bytes = kb
                tampered_detected = tampered_detected or t
        except Exception as e:
            flash(f"KM error: {e}", "danger")
            return redirect(url_for("inbox"))

        body, attachments = es.decrypt_message(msg, qkd_bytes)
        if tampered_detected:
            flash("Possible Intrusion Detected: Key integrity mismatch", "danger")
        return render_template("message.html", msg=msg, body=body, attachments=attachments)

    return app
