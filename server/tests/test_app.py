import base64
import hashlib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from server.app import COOKIE, create_app, version_name
from server.provider import MAGIC, ProviderConflict, ProviderError, ProviderPending
from server.state import MemoryState, StateFull


ORIGIN = "https://vault.zenlog.pro"
DATA = MAGIC + b"encrypted fixture, not a parsed database"


def revision(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeProvider:
    def __init__(self):
        self.files = {"token-one": {"main.kdbx": DATA}, "token-two": {"other.kdbx": DATA + b"other"}}
        self.writes = []
        self.exchanges = []
        self.fail = False
        self.change_on_download = False

    def exchange(self, code, verifier, redirect_uri):
        self.exchanges.append((code, verifier, redirect_uri))
        if self.fail:
            raise ProviderError("SECRET SHOULD NOT REACH CLIENT")
        return "token-two" if code == "two" else "token-one"

    def identity(self, token):
        return {"id": token.removeprefix("token-"), "login": "user-" + token.removeprefix("token-")}

    def stat(self, token, name):
        if self.fail:
            raise ProviderError("SECRET SIGNED URL SHOULD NOT REACH CLIENT")
        data = self.files[token].get(name)
        return None if data is None else {"name": name, "size": len(data), "modified": "2026-10-03", "revision": revision(data)}

    def list(self, token):
        return [self.stat(token, name) for name in self.files[token]]

    def download(self, token, name, maximum):
        data = self.files[token][name]
        return data + b"concurrent edit" if self.change_on_download else data

    def upload_new(self, token, name, data):
        if name in self.files[token]:
            raise ProviderConflict()
        self.files[token][name] = data
        self.writes.append((token, name, data))
        return self.stat(token, name)


@pytest.fixture
def setup(tmp_path):
    provider = FakeProvider()
    (tmp_path / "index.html").write_text("<!doctype html><h1>Vault</h1>")
    (tmp_path / "main.js").write_text("console.log('no secrets');")
    app = create_app({"TESTING": True, "YANDEX_CLIENT_ID": "client-public-id", "FRONTEND_DIR": str(tmp_path)}, provider)
    return app, app.test_client(), provider


def call(client, path, method="GET", **kwargs):
    return client.open(path, method=method, base_url=ORIGIN, **kwargs)


def login(client, code="one"):
    result = call(client, "/auth/login")
    parameters = parse_qs(urlsplit(result.location).query)
    result = call(client, "/auth/callback", query_string={"state": parameters["state"][0], "code": code})
    assert result.status_code == 303
    assert result.location == "/"
    return call(client, "/api/session").json


def mutation_headers(session, **extra):
    return {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": session["csrfToken"], **extra}


def save(client, session, name="main.kdbx", data=DATA + b"new", **headers):
    return call(client, "/api/vault", method="PUT", query_string={"name": name}, data=data,
                content_type="application/octet-stream", headers=mutation_headers(session, **headers))


def test_session_cookie_no_secrets_and_security_headers(setup):
    _, client, _ = setup
    response = call(client, "/api/session")
    assert response.json == {"authenticated": False, "configured": True, "csrfToken": response.json["csrfToken"],
                             "user": None, "limits": {"maxFileBytes": 64 * 1024 * 1024}}
    cookie = response.headers["Set-Cookie"]
    assert cookie.startswith(COOKIE + "=")
    assert all(flag in cookie for flag in ("Secure", "HttpOnly", "SameSite=Lax", "Path=/"))
    assert "Domain=" not in cookie
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "wasm-unsafe-eval" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_oauth_pkce_state_rotation_replay_and_separation(setup):
    app, client, provider = setup
    response = call(client, "/auth/login")
    old_cookie = client.get_cookie(COOKIE, domain="vault.zenlog.pro").value
    params = parse_qs(urlsplit(response.location).query)
    oauth = app.extensions["vault_state"].get(old_cookie).oauth
    expected = base64.urlsafe_b64encode(hashlib.sha256(oauth["verifier"].encode()).digest()).decode().rstrip("=")
    assert params["code_challenge"] == [expected]
    assert params["code_challenge_method"] == ["S256"]
    assert params["scope"] == ["cloud_api:disk.read cloud_api:disk.write"]
    assert params["redirect_uri"] == [ORIGIN + "/auth/callback"]
    query = {"state": params["state"][0], "code": "one"}
    response = call(client, "/auth/callback", query_string=query)
    assert response.location == "/"
    assert client.get_cookie(COOKIE, domain="vault.zenlog.pro").value != old_cookie
    assert app.extensions["vault_state"].get(old_cookie) is None
    assert provider.exchanges == [("one", oauth["verifier"], ORIGIN + "/auth/callback")]
    assert call(client, "/auth/callback", query_string=query).location == "/?auth=failed"
    assert len(provider.exchanges) == 1
    session = call(client, "/api/session").json
    assert session["user"] == {"id": "one", "login": "user-one"}
    assert b"token-one" not in call(client, "/api/session").data


@pytest.mark.parametrize("bad", ["wrong", "", "другой"])
def test_bad_state_cannot_exchange(setup, bad):
    _, client, provider = setup
    call(client, "/auth/login")
    assert call(client, "/auth/callback", query_string={"state": bad, "code": "one"}).location == "/?auth=failed"
    assert provider.exchanges == []


def test_expired_state_and_denial(setup):
    app, client, provider = setup
    response = call(client, "/auth/login")
    query = parse_qs(urlsplit(response.location).query)
    sid = client.get_cookie(COOKIE, domain="vault.zenlog.pro").value
    app.extensions["vault_state"].get(sid).oauth["expires"] = 0
    assert call(client, "/auth/callback", query_string={"state": query["state"][0], "code": "one"}).location == "/?auth=failed"
    assert provider.exchanges == []


def test_auth_failure_redacts_upstream(setup):
    _, client, provider = setup
    provider.fail = True
    response = call(client, "/auth/login")
    state = parse_qs(urlsplit(response.location).query)["state"][0]
    response = call(client, "/auth/callback", query_string={"state": state, "code": "private-code"})
    assert response.location == "/?auth=failed"
    assert b"SECRET" not in response.data and b"private-code" not in response.data


def test_auth_required_and_no_cross_site_reads(setup):
    _, client, _ = setup
    assert call(client, "/api/vaults").status_code == 401
    login(client)
    assert call(client, "/api/vaults", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.get("/api/session", base_url="https://evil.example").status_code == 400


@pytest.mark.parametrize("overrides", [
    {"Origin": "https://evil.example"}, {"Origin": "null"}, {"Origin": ""},
    {"Sec-Fetch-Site": "same-site"}, {"Sec-Fetch-Site": "cross-site"},
    {"X-CSRF-Token": "wrong"}, {"X-CSRF-Token": "другой"},
])
def test_csrf_rejects_bad_mutation(setup, overrides):
    _, client, provider = setup
    session = login(client)
    response = call(client, "/api/vault?name=main.kdbx", method="PUT", data=DATA,
                    content_type="application/octet-stream", headers=mutation_headers(session, **overrides))
    assert response.status_code == 403
    assert provider.writes == []


@pytest.mark.parametrize("name", ["../main.kdbx", "dir/main.kdbx", "dir\\main.kdbx", "%2f.kdbx", "..kdbx",
                                  ".hidden.kdbx", "other.txt", "main.kdbx\n", " main.kdbx", "a\x00.kdbx",
                                  "a\u202e.kdbx", "a" * 181 + ".kdbx"])
def test_invalid_names_do_not_reach_disk(setup, name):
    _, client, provider = setup
    login(client)
    assert call(client, "/api/vault", query_string={"name": name}).status_code == 400
    assert provider.writes == []


def test_opaque_download_append_only_save_and_roundtrip(setup):
    _, client, provider = setup
    session = login(client)
    response = call(client, "/api/vault?name=main.kdbx")
    assert response.data == DATA and response.headers["X-Vault-Revision"] == revision(DATA)
    data = MAGIC + bytes(range(256))
    saved = save(client, session, data=data, **{"If-Match": revision(DATA)})
    assert saved.status_code == 201
    assert saved.json["sourceName"] == "main.kdbx"
    assert saved.json["name"] != "main.kdbx"
    assert saved.json["revision"] == revision(data)
    assert provider.files["token-one"]["main.kdbx"] == DATA
    downloaded = call(client, "/api/vault", query_string={"name": saved.json["name"]})
    assert downloaded.data == data
    assert len(call(client, "/api/vaults").json["files"]) == 2


def test_create_conflict_and_missing_preconditions(setup):
    _, client, provider = setup
    session = login(client)
    assert save(client, session).status_code == 428
    assert save(client, session, **{"If-Match": "stale"}).status_code == 409
    assert save(client, session, **{"If-None-Match": "*"}).status_code == 409
    assert save(client, session, **{"If-Match": revision(DATA), "If-None-Match": "*"}).status_code == 428
    assert provider.writes == []
    result = save(client, session, name="Пароли.kdbx", **{"If-None-Match": "*"})
    assert result.status_code == 201 and result.json["name"] == "Пароли.kdbx"
    assert save(client, session, name="Пароли.kdbx", **{"If-None-Match": "*"}).status_code == 409


def test_same_base_parallel_saves_preserve_both_versions(setup):
    _, client, provider = setup
    session = login(client)
    first = save(client, session, data=DATA + b"first", **{"If-Match": revision(DATA)})
    second = save(client, session, data=DATA + b"second", **{"If-Match": revision(DATA)})
    assert first.status_code == second.status_code == 201
    assert first.json["name"] != second.json["name"]
    assert provider.files["token-one"]["main.kdbx"] == DATA
    assert provider.files["token-one"][first.json["name"]] == DATA + b"first"
    assert provider.files["token-one"][second.json["name"]] == DATA + b"second"


def test_unknown_save_returns_actual_target_for_reconciliation(setup):
    _, client, provider = setup
    session = login(client)
    def pending(*_):
        raise ProviderPending()
    provider.upload_new = pending
    response = save(client, session, **{"If-Match": revision(DATA)})
    assert response.status_code == 503
    assert response.json["error"] == "save_unconfirmed"
    assert response.json["sourceName"] == "main.kdbx"
    assert response.json["name"].startswith("main.") and response.json["name"] != "main.kdbx"


def test_accounts_are_isolated(setup):
    app, client, provider = setup
    first = login(client)
    other = app.test_client()
    second = login(other, "two")
    assert [f["name"] for f in call(client, "/api/vaults").json["files"]] == ["main.kdbx"]
    assert [f["name"] for f in call(other, "/api/vaults").json["files"]] == ["other.kdbx"]
    assert call(other, "/api/vault?name=main.kdbx").status_code == 404
    response = call(other, "/api/vault?name=other.kdbx", method="PUT", data=DATA,
                    content_type="application/octet-stream", headers=mutation_headers(first))
    assert response.status_code == 403
    assert provider.writes == []


def test_logout_and_expiration(setup):
    app, client, _ = setup
    session = login(client)
    assert call(client, "/auth/logout", method="POST", headers=mutation_headers(session)).status_code == 200
    assert call(client, "/api/vaults").status_code == 401
    assert client.get_cookie(COOKIE, domain="vault.zenlog.pro") is None
    login(client)
    sid = client.get_cookie(COOKIE, domain="vault.zenlog.pro").value
    app.extensions["vault_state"].get(sid).expires = 0
    assert call(client, "/api/vaults").status_code == 401


def test_size_magic_download_race_and_provider_errors(setup):
    app, client, provider = setup
    session = login(client)
    assert save(client, session, data=b"master password plaintext", **{"If-Match": revision(DATA)}).status_code == 422
    app.config["MAX_CONTENT_LENGTH"] = 32
    assert save(client, session, data=MAGIC + b"x" * 33, **{"If-Match": revision(DATA)}).status_code == 413
    assert call(client, "/api/vault?name=main.kdbx").status_code == 413
    app.config["MAX_CONTENT_LENGTH"] = 65536
    provider.change_on_download = True
    assert call(client, "/api/vault?name=main.kdbx").status_code == 409
    provider.fail = True
    response = call(client, "/api/vault?name=main.kdbx")
    assert response.status_code == 502 and response.json == {"error": "storage_unavailable"}
    assert b"SECRET" not in response.data


def test_static_files_no_traversal_or_source(setup):
    _, client, _ = setup
    assert call(client, "/").status_code == 200
    assert call(client, "/main.js").status_code == 200
    for path in ("/.env", "/server/app.py", "/../requirements.txt", "/.git/config", "/main.js.map"):
        assert call(client, path).status_code == 404
    assert call(client, "/api/vault?name=main.kdbx", method="DELETE").status_code == 403


def test_unconfigured_app_fails_closed():
    app = create_app({"TESTING": True, "YANDEX_CLIENT_ID": ""})
    client = app.test_client()
    assert call(client, "/api/session").json["configured"] is False
    assert call(client, "/auth/login").status_code == 503
    assert call(client, "/healthz").json == {"configured": False, "status": "ok"}


def test_version_name_bounds_and_suffix_stripping():
    first = version_name("main.kdbx")
    second = version_name(first)
    assert second.startswith("main.") and len(first) == len(second)
    assert first not in second and first != second
    long = version_name("я" * 115 + ".kdbx")
    assert len(long.encode()) <= 240 and len(long) <= 180


def test_bounded_state_and_rate_expiration():
    clock = [0]
    state = MemoryState(ttl=10, maximum=2, clock=lambda: clock[0])
    sid, session = state.new()
    state.new()
    with pytest.raises(StateFull):
        state.new()
    assert state.allowed("key", 1, 5)
    assert not state.allowed("key", 1, 5)
    clock[0] = 6
    assert state.allowed("key", 1, 5)
    clock[0] = 11
    assert state.get(sid) is None
    state.new()
