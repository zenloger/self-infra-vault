import hashlib

import pytest
import requests

from server.provider import (API, MAGIC, ROOT, ProviderConflict, ProviderError,
                             ProviderPending, ProviderUnauthorized, YandexProvider, transfer_url, valid_name)


DATA = MAGIC + b"encrypted bytes"


class Response:
    def __init__(self, status=200, data=None, headers=None, body=b""):
        self.status_code = status
        self.data = data
        self.headers = headers or {}
        self.body = body
        self.closed = False

    def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data

    def close(self):
        self.closed = True

    def iter_content(self, size):
        for offset in range(0, len(self.body), size):
            yield self.body[offset:offset + size]


def queued(*responses):
    calls = []

    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        response = responses[len(calls) - 1]
        if isinstance(response, Exception):
            raise response
        return response

    return YandexProvider("client-id", request=request, sleep=lambda _: None), calls


def resource(name="main.kdbx", data=DATA):
    return {"name": name, "path": ROOT + "/" + name, "type": "file", "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "modified": "2026-10-03T12:00:00Z"}


@pytest.mark.parametrize("url", [
    "http://downloader.disk.yandex.ru/disk/file", "https://downloader.disk.yandex.ru.evil.test/file",
    "https://downloader.disk.yandex.ru@evil.test/file", "https://user:pass@downloader.disk.yandex.ru/file",
    "https://127.0.0.1/", "https://169.254.169.254/", "https://[::1]/", "https://evil.test/",
    "https://downloader.disk.yandex.ru:444/file", "//downloader.disk.yandex.ru/file",
    "https://downloader.disk.yandex.ru/file#fragment", "https://downloader.disk.yandex.ru/\nfile",
])
def test_transfer_rejects_unsafe_urls(url):
    with pytest.raises(ProviderError):
        transfer_url(url, "download")


def test_transfer_allows_only_documented_families():
    assert transfer_url("https://downloader.dst.yandex.ru/disk/a", "download")
    assert transfer_url("https://uploader1d.dst.yandex.net:443/upload-target/a", "upload")
    assert transfer_url("https://sas3-001.storage.yandex.net/rdisk/a", "storage")
    for url in ("https://storage.yandex.net.evil.test/", "https://notstorage.yandex.net/", "https://yandex.net/"):
        with pytest.raises(ProviderError):
            transfer_url(url, "storage")


def test_download_redirect_drops_oauth_and_limits_bytes():
    provider, calls = queued(
        Response(data={"href": "https://downloader.disk.yandex.ru/disk/file"}),
        Response(302, headers={"Location": "https://sas3-001.storage.yandex.net/file"}),
        Response(body=DATA),
    )
    assert provider.download("secret-token", "main.kdbx") == DATA
    assert calls[0][2]["headers"]["Authorization"] == "OAuth secret-token"
    assert calls[1][2]["headers"]["Authorization"] == "OAuth secret-token"
    assert "Authorization" not in calls[2][2]["headers"]
    assert all(call[2]["allow_redirects"] is False for call in calls)


def test_redirect_to_arbitrary_host_is_never_requested():
    provider, calls = queued(Response(data={"href": "https://downloader.disk.yandex.ru/disk/file"}),
                             Response(302, headers={"Location": "https://evil.test/steal"}))
    with pytest.raises(ProviderError):
        provider.download("secret-token", "main.kdbx")
    assert len(calls) == 2


@pytest.mark.parametrize("headers", [{}, {"Content-Length": "99999"}])
def test_download_size_limit_even_without_content_length(headers):
    provider, _ = queued(Response(data={"href": "https://downloader.disk.yandex.ru/disk/file"}),
                          Response(headers=headers, body=DATA * 100))
    with pytest.raises(ProviderError):
        provider.download("token", "main.kdbx", maximum=32)


def test_upload_never_overwrites_or_sends_token_to_uploader():
    provider, calls = queued(
        Response(409),
        Response(data={"href": "https://uploader1d.dst.yandex.net:443/upload-target/x"}),
        Response(201),
        Response(data=resource()),
    )
    saved = provider.upload_new("secret-token", "main.kdbx", DATA)
    assert saved["name"] == "main.kdbx"
    assert calls[1][2]["params"] == {"path": ROOT + "/main.kdbx", "overwrite": "false"}
    assert "Authorization" not in calls[2][2]["headers"]
    assert calls[2][2]["data"] == DATA


def test_upload_conflict_is_not_retried_with_overwrite():
    provider, calls = queued(Response(409), Response(409))
    with pytest.raises(ProviderConflict):
        provider.upload_new("token", "main.kdbx", DATA)
    assert len(calls) == 2 and calls[1][2]["params"]["overwrite"] == "false"


def test_upload_external_redirect_is_not_followed():
    provider, calls = queued(Response(409), Response(data={"href": "https://uploader1d.dst.yandex.net/x"}),
                             Response(307, headers={"Location": "https://evil.test/"}))
    with pytest.raises(ProviderError):
        provider.upload_new("token", "main.kdbx", DATA)
    assert len(calls) == 3


def test_upload_202_polls_fixed_api_and_verifies_digest():
    provider, calls = queued(Response(409),
        Response(data={"href": "https://uploader1d.dst.yandex.net/x", "operation_id": "op-id"}),
        Response(202), Response(data={"status": "in-progress"}), Response(data={"status": "success"}),
        Response(data=resource()))
    assert provider.upload_new("token", "main.kdbx", DATA)["name"] == "main.kdbx"
    assert calls[3][1] == calls[4][1] == API + "/operations/op-id"


def test_upload_unknown_status_is_not_reported_success():
    provider, calls = queued(Response(409),
        Response(data={"href": "https://uploader1d.dst.yandex.net/x", "operation_id": "op-id"}),
        Response(202), *[Response(data={"status": "in-progress"}) for _ in range(3)])
    with pytest.raises(ProviderPending):
        provider.upload_new("token", "main.kdbx", DATA)
    assert len(calls) == 6


def test_upload_timeout_is_an_unknown_outcome():
    provider, _ = queued(Response(409), Response(data={"href": "https://uploader1d.dst.yandex.net/x"}),
                          requests.Timeout("signed-url-must-not-leak"))
    with pytest.raises(ProviderPending) as exc:
        provider.upload_new("token", "main.kdbx", DATA)
    assert str(exc.value) == ""


def test_list_filters_immediate_kdbx_and_handles_pagination():
    first = [resource(), {"name": "folder.kdbx", "type": "dir"}, {"name": "notes.txt", "type": "file"}]
    provider, calls = queued(Response(data={"_embedded": {"items": first, "total": 101}}),
                             Response(data={"_embedded": {"items": [resource("second.kdbx")], "total": 101}}))
    assert [item["name"] for item in provider.list("token")] == ["second.kdbx", "main.kdbx"]
    assert calls[1][2]["params"]["offset"] == 100


def test_list_rejects_path_outside_root():
    bad = resource()
    bad["path"] = "disk:/elsewhere/main.kdbx"
    provider, _ = queued(Response(data={"_embedded": {"items": [bad], "total": 1}}))
    with pytest.raises(ProviderError):
        provider.list("token")


def test_missing_root_returns_empty():
    provider, _ = queued(Response(404))
    assert provider.list("token") == []


@pytest.mark.parametrize("status", [301, 403, 429, 500])
def test_api_failure_is_redacted_and_not_redirected(status):
    provider, calls = queued(Response(status, {"error_description": "SECRET"}))
    with pytest.raises(ProviderError) as exc:
        provider.stat("secret-token", "main.kdbx")
    assert "SECRET" not in str(exc.value) and "secret-token" not in str(exc.value)
    assert len(calls) == 1


def test_network_error_is_redacted():
    provider, _ = queued(requests.ConnectionError("signed-secret-url"))
    with pytest.raises(ProviderError) as exc:
        provider.stat("secret-token", "main.kdbx")
    assert "secret" not in str(exc.value)


def test_token_exchange_pkce_and_identity():
    provider, calls = queued(Response(data={"access_token": "token"}),
                             Response(data={"id": "123", "login": "zenlog", "client_id": "client-id"}))
    assert provider.exchange("private-code", "verifier", "https://secret.zenlog.pro/auth/callback") == "token"
    assert calls[0][1] == "https://oauth.yandex.ru/token"
    assert calls[0][2]["data"]["code_verifier"] == "verifier"
    assert "client_secret" not in calls[0][2]["data"]
    assert provider.identity("token") == {"id": "123", "login": "zenlog"}


def test_identity_is_bound_to_client():
    provider, _ = queued(Response(data={"id": "123", "login": "zenlog", "client_id": "different-app"}))
    with pytest.raises(ProviderError):
        provider.identity("token")


def test_missing_hash_is_not_a_revision():
    item = resource()
    item.pop("sha256")
    provider, _ = queued(Response(data=item))
    with pytest.raises(ProviderError):
        provider.stat("token", "main.kdbx")
