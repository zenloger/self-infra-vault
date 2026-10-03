"""Narrow Yandex adapter. Transfer hosts are checked before every request.

Disk does not document conditional replacement (CAS). This adapter deliberately
never asks for overwrite=true: every save is a new cloud object.
"""

import hashlib
import re
import time
import unicodedata
from urllib.parse import quote, urlsplit

import requests


API = "https://cloud-api.yandex.net/v1/disk"
ROOT = "disk:/secret"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAGIC = bytes.fromhex("03d9a29a67fb4bb5")
DOWNLOAD_HOSTS = {"downloader.disk.yandex.ru", "downloader.dst.yandex.ru"}
UPLOAD_HOST = re.compile(r"uploader[a-z0-9-]*\.(?:dst|disk)\.yandex\.net\Z")
STORAGE_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+storage\.yandex\.net\Z")


class ProviderError(Exception):
    """Never include upstream bodies, OAuth tokens or signed URLs in errors."""


class ProviderUnauthorized(ProviderError):
    pass


class ProviderConflict(ProviderError):
    pass


class ProviderPending(ProviderError):
    """The ciphertext might already be stored; relist before retrying."""


def valid_name(name):
    return (isinstance(name, str) and 5 <= len(name) <= 180
            and not any(unicodedata.category(c).startswith("C") for c in name)
            and len(name.encode("utf-8")) <= 240
            and name.lower().endswith(".kdbx")
            and not name.startswith(".") and ".." not in name
            and not any(c in name for c in "/\\%")
            and name == name.strip())


def resource_revision(item):
    for kind, length in (("sha256", 64), ("md5", 32)):
        value = item.get(kind)
        if isinstance(value, str) and re.fullmatch(r"[a-fA-F0-9]{%d}" % length, value):
            return kind + ":" + value.lower()
    raise ProviderError()


def digest_matches(data, revision):
    algorithm, _, wanted = revision.partition(":")
    if algorithm not in ("sha256", "md5"):
        return False
    return hashlib.new(algorithm, data).hexdigest() == wanted


def transfer_url(url, kind):
    if not isinstance(url, str) or len(url) > 16384 or any(ord(c) < 33 for c in url):
        raise ProviderError()
    try:
        parts = urlsplit(url)
        if (parts.scheme != "https" or parts.username is not None or parts.password is not None
                or parts.port not in (None, 443) or parts.fragment):
            raise ProviderError()
    except ValueError:
        raise ProviderError() from None
    host = parts.hostname or ""
    allowed = (host in DOWNLOAD_HOSTS if kind == "download" else
               bool(UPLOAD_HOST.fullmatch(host)) if kind == "upload" else
               bool(STORAGE_HOST.fullmatch(host)))
    if not allowed:
        raise ProviderError()
    return url


class YandexProvider:
    def __init__(self, client_id, client_secret=None, request=requests.request, sleep=time.sleep):
        self.client_id = client_id
        self.client_secret = client_secret
        self.request = request
        self.sleep = sleep

    def _request(self, method, url, **kwargs):
        try:
            return self.request(method, url, allow_redirects=False, timeout=(5, 30), **kwargs)
        except requests.RequestException:
            raise ProviderError() from None

    @staticmethod
    def _json(response):
        try:
            value = response.json()
            if not isinstance(value, dict):
                raise ProviderError()
            return value
        except (ValueError, TypeError):
            raise ProviderError() from None
        finally:
            response.close()

    def _api(self, token, method, endpoint, params=None, missing=False):
        response = self._request(method, API + endpoint,
                                 headers={"Authorization": "OAuth " + token}, params=params)
        if response.status_code == 401:
            response.close()
            raise ProviderUnauthorized()
        if response.status_code == 404 and missing:
            response.close()
            return None
        if response.status_code == 409:
            response.close()
            raise ProviderConflict()
        if not 200 <= response.status_code < 300:
            response.close()
            raise ProviderError()
        return self._json(response)

    def exchange(self, code, verifier, redirect_uri):
        form = {"grant_type": "authorization_code", "code": code,
                "client_id": self.client_id, "code_verifier": verifier,
                "redirect_uri": redirect_uri}
        if self.client_secret:
            form["client_secret"] = self.client_secret
        response = self._request("POST", "https://oauth.yandex.ru/token", data=form)
        if response.status_code != 200:
            response.close()
            raise ProviderError()
        data = self._json(response)
        token = data.get("access_token")
        if not isinstance(token, str) or not token or len(token) > 8192:
            raise ProviderError()
        return token

    def identity(self, token):
        response = self._request("GET", "https://login.yandex.ru/info",
                                 headers={"Authorization": "OAuth " + token}, params={"format": "json"})
        if response.status_code != 200:
            response.close()
            raise ProviderError()
        data = self._json(response)
        if (not isinstance(data.get("id"), str) or not data["id"]
                or not isinstance(data.get("login"), str)
                or data.get("client_id") != self.client_id):
            raise ProviderError()
        return {"id": data["id"], "login": data["login"]}

    @staticmethod
    def _resource(data, name):
        if (not isinstance(data, dict) or data.get("type") != "file"
                or data.get("path") != ROOT + "/" + name
                or not isinstance(data.get("size"), int) or data["size"] < 0):
            raise ProviderError()
        return {"name": name, "size": data["size"],
                "modified": data.get("modified", ""), "revision": resource_revision(data)}

    def stat(self, token, name):
        data = self._api(token, "GET", "/resources", {"path": ROOT + "/" + name}, missing=True)
        return None if data is None else self._resource(data, name)

    def list(self, token):
        files = []
        for offset in range(0, 10000, 100):
            data = self._api(token, "GET", "/resources",
                             {"path": ROOT, "limit": 100, "offset": offset}, missing=True)
            if data is None:
                return []
            embedded = data.get("_embedded", {})
            items = embedded.get("items")
            total = embedded.get("total")
            if not isinstance(items, list) or not isinstance(total, int):
                raise ProviderError()
            for item in items:
                name = item.get("name") if isinstance(item, dict) else None
                if valid_name(name) and item.get("type") == "file":
                    files.append(self._resource(item, name))
            if offset + len(items) >= total:
                return sorted(files, key=lambda item: (item["modified"], item["name"]), reverse=True)
            if not items:
                raise ProviderError()
        raise ProviderError()

    def download(self, token, name, maximum=MAX_FILE_BYTES):
        link = self._api(token, "GET", "/resources/download", {"path": ROOT + "/" + name})
        url = transfer_url(link.get("href"), "download")
        # Yandex's documented download endpoint requires OAuth; signed storage
        # redirects never receive the token, even after another redirect.
        for hop in range(5):
            headers = {"Authorization": "OAuth " + token} if hop == 0 else {}
            response = self._request("GET", url, headers=headers, stream=True)
            if response.status_code in (301, 302, 303, 307, 308):
                target = response.headers.get("Location")
                response.close()
                url = transfer_url(target, "storage")
                continue
            if response.status_code != 200:
                response.close()
                raise ProviderError()
            try:
                size = response.headers.get("Content-Length")
                if size is not None and (not size.isdigit() or int(size) > maximum):
                    raise ProviderError()
                chunks, count = [], 0
                for chunk in response.iter_content(65536):
                    count += len(chunk)
                    if count > maximum:
                        raise ProviderError()
                    chunks.append(chunk)
                return b"".join(chunks)
            except requests.RequestException:
                raise ProviderError() from None
            finally:
                response.close()
        raise ProviderError()

    def upload_new(self, token, name, data):
        try:
            self._api(token, "PUT", "/resources", {"path": ROOT})
        except ProviderConflict:
            pass  # The folder usually already exists.
        link = self._api(token, "GET", "/resources/upload",
                         {"path": ROOT + "/" + name, "overwrite": "false"})
        url = transfer_url(link.get("href"), "upload")
        try:
            response = self._request("PUT", url, data=data,
                                     headers={"Content-Type": "application/octet-stream"})
        except ProviderError:
            raise ProviderPending() from None
        status = response.status_code
        response.close()
        if status == 409:
            raise ProviderConflict()
        if status == 202:
            operation = link.get("operation_id")
            if (not isinstance(operation, str) or not 1 <= len(operation) <= 1024
                    or operation in (".", "..") or any(ord(c) < 32 for c in operation)):
                raise ProviderPending()
            try:
                for attempt in range(3):
                    if attempt:
                        self.sleep(1)
                    result = self._api(token, "GET", "/operations/" + quote(operation, safe=""))
                    if result.get("status") == "success":
                        break
                    if result.get("status") != "in-progress":
                        raise ProviderPending()
                else:
                    raise ProviderPending()
            except ProviderError:
                raise ProviderPending() from None
        elif status != 201:
            raise ProviderPending()
        try:
            actual = self.stat(token, name)
        except ProviderError:
            raise ProviderPending() from None
        if actual is None or not digest_matches(data, actual["revision"]):
            raise ProviderPending()
        return actual
