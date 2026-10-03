import base64
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
from urllib.parse import urlencode, urlsplit

from flask import Flask, g, jsonify, make_response, redirect, request, send_from_directory
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from .provider import (MAGIC, MAX_FILE_BYTES, ProviderConflict, ProviderError,
                       ProviderPending, ProviderUnauthorized, YandexProvider, digest_matches, valid_name)
from .state import MemoryState, StateFull


COOKIE = "__Host-vault-session"
VERSION_SUFFIX = re.compile(r"\.\d{8}T\d{12}Z\.[a-f0-9]{16}\Z")


def version_name(name):
    stem = VERSION_SUFFIX.sub("", name[:-5])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    suffix = "." + stamp + "." + secrets.token_hex(8) + ".kdbx"
    # Bound UTF-8 length without splitting a Unicode code point.
    while len((stem + suffix).encode("utf-8")) > 240 or len(stem + suffix) > 180:
        stem = stem[:-1]
    return stem + suffix


def create_app(config=None, provider=None):
    app = Flask(__name__, static_folder=None)
    app.config.from_mapping(
        PUBLIC_ORIGIN=os.environ.get("PUBLIC_ORIGIN", "https://secret.zenlog.pro"),
        YANDEX_CLIENT_ID=os.environ.get("YANDEX_CLIENT_ID", ""),
        YANDEX_CLIENT_SECRET=os.environ.get("YANDEX_CLIENT_SECRET", ""),
        MAX_CONTENT_LENGTH=MAX_FILE_BYTES,
        SESSION_TTL=28800,
        MAX_SESSIONS=4096,
        TRUST_PROXY=os.environ.get("TRUST_PROXY", "0") == "1",
        FRONTEND_DIR=str(Path(__file__).resolve().parent.parent / "dist"),
    )
    if config:
        app.config.update(config)
    origin = app.config["PUBLIC_ORIGIN"].rstrip("/")
    parts = urlsplit(origin)
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None
            or parts.password is not None or parts.path or parts.query or parts.fragment):
        raise ValueError("PUBLIC_ORIGIN must be an HTTPS origin")
    app.config["PUBLIC_ORIGIN"] = origin
    if app.config["TRUST_PROXY"]:
        # Only deploy behind the documented loopback-only nginx proxy.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)
    state = MemoryState(app.config["SESSION_TTL"], app.config["MAX_SESSIONS"])
    disk = provider or YandexProvider(app.config["YANDEX_CLIENT_ID"], app.config["YANDEX_CLIENT_SECRET"])
    app.extensions["vault_state"] = state
    app.extensions["vault_provider"] = disk

    def error(code, status, **values):
        return jsonify(error=code, **values), status

    def session(create=False):
        if not hasattr(g, "session"):
            g.sid = request.cookies.get(COOKIE)
            g.session = state.get(g.sid)
        if g.session is None and create:
            if not state.allowed(("session", request.remote_addr), 30, 60):
                return None
            g.sid, g.session = state.new()
            g.set_cookie = True
        return g.session

    def authenticated():
        current = session()
        return current if current is not None and current.token and current.user else None

    def csrf_valid(current):
        if (request.headers.get("Origin") != origin
                or request.headers.get("Sec-Fetch-Site") not in (None, "same-origin")):
            return False
        supplied = request.headers.get("X-CSRF-Token", "")
        return bool(supplied and hmac.compare_digest(supplied.encode(), current.csrf.encode()))

    def name_argument():
        names = request.args.getlist("name")
        return names[0] if len(names) == 1 and valid_name(names[0]) else None

    @app.before_request
    def guard_request():
        # Do not accept a Host supplied by another origin to construct redirects.
        if request.host.lower() != parts.netloc.lower():
            return error("invalid_host", 400)
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            current = session()
            if current is None or not csrf_valid(current):
                return error("csrf", 403)
        if request.path.startswith("/api/") and request.path != "/api/session":
            if not authenticated():
                return error("authentication_required", 401)
        # APIs are same-origin. OAuth callback remains a top-level cross-site GET.
        if request.path.startswith("/api/") and request.headers.get("Sec-Fetch-Site") == "cross-site":
            return error("cross_site_request", 403)

    @app.after_request
    def secure_response(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; worker-src 'self'; "
            "object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if getattr(g, "set_cookie", False):
            response.set_cookie(COOKIE, g.sid, secure=True, httponly=True, samesite="Lax",
                                path="/", max_age=app.config["SESSION_TTL"])
        if getattr(g, "delete_cookie", False):
            response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="Lax", path="/")
        return response

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return error("request_too_large" if exc.code == 413 else "invalid_request", exc.code or 500)

    @app.errorhandler(StateFull)
    def state_full(_):
        return error("temporarily_unavailable", 503)

    @app.errorhandler(ProviderUnauthorized)
    def provider_unauthorized(_):
        state.delete(getattr(g, "sid", None))
        g.delete_cookie = True
        return error("authentication_required", 401)

    @app.errorhandler(ProviderConflict)
    def provider_conflict(_):
        return error("conflict", 409)

    @app.errorhandler(ProviderError)
    def provider_error(_):
        return error("storage_unavailable", 502)

    @app.get("/healthz")
    def health():
        return jsonify(status="ok", configured=bool(app.config["YANDEX_CLIENT_ID"]))

    @app.get("/api/session")
    def get_session():
        current = session(create=True)
        if current is None:
            return error("rate_limited", 429)
        return jsonify(authenticated=bool(current.token and current.user),
                       configured=bool(app.config["YANDEX_CLIENT_ID"]), csrfToken=current.csrf,
                       user=current.user, limits={"maxFileBytes": app.config["MAX_CONTENT_LENGTH"]})

    @app.get("/auth/login")
    def login():
        if not app.config["YANDEX_CLIENT_ID"]:
            return error("oauth_not_configured", 503)
        if not state.allowed(("login", request.remote_addr), 10, 60):
            return error("rate_limited", 429)
        current = session(create=True)
        if current is None:
            return error("rate_limited", 429)
        verifier = secrets.token_urlsafe(48)
        oauth_state = secrets.token_urlsafe(32)
        with state.lock:
            current.oauth = {"state": oauth_state, "verifier": verifier, "expires": state.clock() + 600}
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        parameters = {
            "response_type": "code", "client_id": app.config["YANDEX_CLIENT_ID"],
            "redirect_uri": origin + "/auth/callback", "state": oauth_state,
            "code_challenge": challenge, "code_challenge_method": "S256",
            "scope": "cloud_api:disk.read cloud_api:disk.write",
        }
        return redirect("https://oauth.yandex.ru/authorize?" + urlencode(parameters), code=302)

    @app.get("/auth/callback")
    def callback():
        current = session()
        with state.lock:
            oauth = current.oauth if current is not None else None
            if current is not None:
                current.oauth = None  # One use, including denial and failed exchange.
        received_state = request.args.get("state", "")
        code = request.args.get("code", "")
        if (not oauth or oauth["expires"] <= state.clock() or not received_state
                or not hmac.compare_digest(received_state.encode(), oauth["state"].encode())
                or not code or len(code) > 4096 or request.args.get("error")
                or len(request.args.getlist("state")) != 1 or len(request.args.getlist("code")) != 1):
            return redirect("/?auth=failed", code=303)
        try:
            token = disk.exchange(code, oauth["verifier"], origin + "/auth/callback")
            user = disk.identity(token)
        except ProviderError:
            return redirect("/?auth=failed", code=303)
        old_sid = g.sid
        g.sid, g.session = state.new()
        g.session.token, g.session.user = token, user
        state.delete(old_sid)
        g.set_cookie = True
        return redirect("/", code=303)

    @app.post("/auth/logout")
    def logout():
        state.delete(getattr(g, "sid", None))
        g.delete_cookie = True
        return jsonify(ok=True)

    @app.get("/api/vaults")
    def vaults():
        current = authenticated()
        return jsonify(files=disk.list(current.token))

    @app.route("/api/vault", methods=["GET", "PUT"])
    def vault():
        name = name_argument()
        if name is None:
            return error("invalid_name", 400)
        current = authenticated()
        maximum = app.config["MAX_CONTENT_LENGTH"]
        with state.for_user(current.user["id"]):
            metadata = disk.stat(current.token, name)
            if request.method == "GET":
                if metadata is None:
                    return error("not_found", 404)
                if metadata["size"] > maximum:
                    return error("file_too_large", 413)
                data = disk.download(current.token, name, maximum)
                if len(data) > maximum:
                    return error("file_too_large", 413)
                if not digest_matches(data, metadata["revision"]):
                    return error("conflict", 409)
                if not data.startswith(MAGIC):
                    return error("invalid_kdbx", 422)
                response = make_response(data)
                response.headers["Content-Type"] = "application/octet-stream"
                response.headers["X-Vault-Revision"] = metadata["revision"]
                return response
            if request.mimetype != "application/octet-stream":
                return error("unsupported_content_type", 415)
            data = request.get_data(cache=False)
            if len(data) > maximum:
                return error("file_too_large", 413)
            if not data.startswith(MAGIC):
                return error("invalid_kdbx", 422)
            match = request.headers.get("If-Match")
            absent = request.headers.get("If-None-Match")
            if (match is None) == (absent is None):
                return error("precondition_required", 428)
            if absent is not None:
                if absent != "*":
                    return error("invalid_precondition", 400)
                if metadata is not None:
                    return error("conflict", 409, revision=metadata["revision"])
                target = name
            else:
                if metadata is None or match != metadata["revision"]:
                    return error("conflict", 409, revision=metadata["revision"] if metadata else None)
                target = version_name(name)
            # Append-only: the selected base can change in another client during
            # this request, but neither their bytes nor this save are overwritten.
            try:
                saved = disk.upload_new(current.token, target, data)
            except ProviderPending:
                return error("save_unconfirmed", 503, name=target, sourceName=name)
            return jsonify(name=saved["name"], revision=saved["revision"], sourceName=name), 201

    @app.get("/")
    def index():
        return send_from_directory(app.config["FRONTEND_DIR"], "index.html")

    @app.get("/<path:path>")
    def frontend(path):
        license_files = {"third-party-licenses.txt", "vault-worker.js.LEGAL.txt", "app.js.LEGAL.txt"}
        if (any(part.startswith(".") for part in path.split("/"))
                or (path not in license_files and Path(path).suffix.lower()
                    not in (".js", ".css", ".wasm", ".svg", ".png", ".ico"))):
            return error("not_found", 404)
        return send_from_directory(app.config["FRONTEND_DIR"], path)

    return app
