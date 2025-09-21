from flask import Flask, jsonify, request, Response, render_template_string, redirect
from .storage import store
import base64
import os
import hmac
import hashlib
import random


def create_app() -> Flask:
    app = Flask(__name__)
    INTEGRITY_SECRET = os.getenv("KM_INTEGRITY_SECRET", "change_this_demo_secret").encode()
    app.config["INTRUSION_ON"] = False
    # Persist KM store across restarts (prevents 404 on consume after restart)
    try:
        from .storage import store
        store_path = os.getenv("KM_STORE_PATH", ".km_store.json")
        store.set_path(store_path)
        store.load()
    except Exception:
        pass

    def _hmac_hex(data: bytes) -> str:
        return hmac.new(INTEGRITY_SECRET, data, hashlib.sha256).hexdigest()

    def _maybe_tamper(data: bytes) -> bytes:
        if not app.config.get("INTRUSION_ON", False):
            return data
        if not data:
            return data
        # Flip a few random bits
        b = bytearray(data)
        for _ in range(max(1, len(b)//64)):
            i = random.randrange(0, len(b))
            b[i] ^= 0x01
        return bytes(b)

    @app.get("/")
    def index():
        status = {"status": "ok", "intrusion": app.config.get("INTRUSION_ON", False)}
        html = (
            "<h2>QuMail KM Simulator</h2>"
            f"<p>Status: {status['status']}, Intrusion: {str(status['intrusion']).lower()}</p>"
            '<p>Useful links: '
            '<a href="/api/v1/status">/api/v1/status</a> | '
            '<a href="/admin">/admin</a></p>'
        )
        return Response(html, mimetype="text/html")

    @app.get("/api/v1/status")
    def status():
        return jsonify({"status": "ok", "intrusion": app.config.get("INTRUSION_ON", False)})

    @app.post("/api/v1/keys")
    def create_key():
        data = request.get_json(force=True, silent=True) or {}
        client_id = data.get("client_id", "client")
        peer_id = data.get("peer_id", "peer")
        length = int(data.get("length", 4096))
        expires_in = data.get("expires_in")
        max_uses = data.get("max_uses")
        expires_at = None
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            import time as _t
            expires_at = _t.time() + float(expires_in)
        item = store.create_key(client_id, peer_id, length, expires_at=expires_at, max_uses=int(max_uses) if max_uses is not None else None)
        original = item.key_bytes
        resp_bytes = _maybe_tamper(original)
        return jsonify({
            "key_id": item.key_id,
            "client_id": item.client_id,
            "peer_id": item.peer_id,
            "length": len(item.key_bytes),
            "key_b64": base64.b64encode(resp_bytes).decode(),
            "key_hmac": _hmac_hex(original),
            "created_at": item.created_at,
            "consumed": item.consumed,
            "expires_at": item.expires_at,
            "max_uses": item.max_uses,
            "uses": item.uses,
        })

    @app.get("/api/v1/keys/new")
    def create_key_get():
        # Fallback endpoint for environments blocking POST
        client_id = request.args.get("client_id", "client")
        peer_id = request.args.get("peer_id", "peer")
        try:
            length = int(request.args.get("length", "4096"))
        except Exception:
            length = 4096
        expires_in = request.args.get("expires_in")
        max_uses = request.args.get("max_uses")
        expires_at = None
        if expires_in:
            try:
                import time as _t
                val = float(expires_in)
                if val > 0:
                    expires_at = _t.time() + val
            except Exception:
                expires_at = None
        item = store.create_key(client_id, peer_id, length, expires_at=expires_at, max_uses=int(max_uses) if max_uses else None)
        original = item.key_bytes
        resp_bytes = _maybe_tamper(original)
        return jsonify({
            "key_id": item.key_id,
            "client_id": item.client_id,
            "peer_id": item.peer_id,
            "length": len(item.key_bytes),
            "key_b64": base64.b64encode(resp_bytes).decode(),
            "key_hmac": _hmac_hex(original),
            "created_at": item.created_at,
            "consumed": item.consumed,
            "expires_at": item.expires_at,
            "max_uses": item.max_uses,
            "uses": item.uses,
        })

    @app.get("/api/v1/keys/<key_id>")
    def get_key(key_id: str):
        item = store.get_key(key_id)
        if not item:
            return jsonify({"error": "not found"}), 404
        return jsonify({
            "key_id": item.key_id,
            "client_id": item.client_id,
            "peer_id": item.peer_id,
            "length": len(item.key_bytes),
            "created_at": item.created_at,
            "consumed": item.consumed,
            "expires_at": item.expires_at,
            "max_uses": item.max_uses,
            "uses": item.uses,
        })

    @app.post("/api/v1/consume/<key_id>")
    @app.post("/api/v1/consume/<key_id>/")
    def consume(key_id: str):
        data = request.get_json(force=True, silent=True) or {}
        nbytes = int(data.get("bytes", 0))
        if nbytes <= 0:
            return jsonify({"error": "invalid bytes"}), 400
        try:
            offset, slice_bytes = store.consume(key_id, nbytes)
            original = slice_bytes
            resp_bytes = _maybe_tamper(original)
            return jsonify({
                "offset": offset,
                "bytes": nbytes,
                "slice_b64": base64.b64encode(resp_bytes).decode(),
                "slice_hmac": _hmac_hex(original),
            })
        except KeyError:
            return jsonify({"error": "not found"}), 404
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    @app.get("/api/v1/material/<key_id>")
    def material(key_id: str):
        try:
            from .storage import store
            item = store.get_key(key_id)
            if not item:
                return jsonify({"error": "not found"}), 404
            # Non-consuming slice
            try:
                offset = int(request.args.get('offset', '0'))
                nbytes = int(request.args.get('bytes', '0'))
            except Exception:
                return jsonify({"error": "invalid params"}), 400
            if nbytes <= 0 or offset < 0 or (offset + nbytes) > len(item.key_bytes):
                return jsonify({"error": "range out of bounds"}), 400
            sl = item.key_bytes[offset:offset+nbytes]
            resp_bytes = _maybe_tamper(sl)
            return jsonify({
                "offset": offset,
                "bytes": nbytes,
                "slice_b64": base64.b64encode(resp_bytes).decode(),
                "slice_hmac": _hmac_hex(sl),
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # Admin toggle endpoints
    @app.get("/api/v1/admin/intrusion")
    def get_intrusion():
        return jsonify({"intrusion": app.config.get("INTRUSION_ON", False)})

    @app.post("/api/v1/admin/intrusion")
    def set_intrusion():
        data = request.get_json(force=True, silent=True) or {}
        val = bool(data.get("enabled", False))
        app.config["INTRUSION_ON"] = val
        return jsonify({"intrusion": app.config["INTRUSION_ON"]})

    # Minimal admin page
    ADMIN_HTML = """
    <html><head><title>KM Admin</title></head>
    <body>
    <h2>Key Manager Admin</h2>
    <p>Intrusion Simulation: <b>{{ 'ON' if intrusion else 'OFF' }}</b></p>
    <form method="post" action="/admin/toggle">
      <button type="submit">Toggle</button>
    </form>
    </body></html>
    """

    @app.get("/admin")
    def admin_page():
        return render_template_string(ADMIN_HTML, intrusion=app.config.get("INTRUSION_ON", False))

    @app.post("/admin/toggle")
    def admin_toggle():
        app.config["INTRUSION_ON"] = not app.config.get("INTRUSION_ON", False)
        return redirect("/admin")

    return app
