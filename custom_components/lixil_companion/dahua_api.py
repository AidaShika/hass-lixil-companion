"""Minimal Dahua HTTP API helpers (Digest auth), stdlib only.

Used by the config flow *after* the user pastes the QR text: with
admin + security code we can read the device serial via magicBox and
cross-check it against the QR's SN before driving the ha-dahua flow.

The transport is injectable so the digest handshake can be unit tested
without a camera.  Never log the password or the computed response.
"""

from __future__ import annotations

import hashlib
import http.client
import re
from typing import Callable

try:  # package import (inside Home Assistant)
    from .discovery import parse_magicbox
except ImportError:  # top-level import (unit tests)
    from discovery import parse_magicbox  # type: ignore

Transport = Callable[[str, str, dict[str, str]], "tuple[int, dict[str, str], str]"]

SERIAL_PATH = "/cgi-bin/magicBox.cgi?action=getSerialNo"
DEVICE_TYPE_PATH = "/cgi-bin/magicBox.cgi?action=getDeviceType"


class DahuaError(Exception):
    """Base error with a stable machine-readable key."""

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


class DahuaAuthError(DahuaError):
    def __init__(self) -> None:
        super().__init__("auth_failed")


class DahuaUnreachableError(DahuaError):
    def __init__(self) -> None:
        super().__init__("device_unreachable")


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


_AUTH_PARAM_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^,\s]+))')


def parse_www_authenticate(header: str) -> dict[str, str]:
    """Parse a ``WWW-Authenticate: Digest ...`` header into a dict."""
    out: dict[str, str] = {}
    if not header:
        return out
    for m in _AUTH_PARAM_RE.finditer(header):
        out[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


def build_digest_header(
    *,
    method: str,
    uri: str,
    username: str,
    password: str,
    challenge: dict[str, str],
    nc: str = "00000001",
    cnonce: str = "lixilcompanion",
) -> str:
    """Build an ``Authorization: Digest ...`` header value (RFC 7616, MD5)."""
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    qop_offered = challenge.get("qop", "")
    algorithm = challenge.get("algorithm", "MD5")

    ha1 = _md5(f"{username}:{realm}:{password}")
    if algorithm.upper() == "MD5-SESS":
        ha1 = _md5(f"{ha1}:{nonce}:{cnonce}")
    ha2 = _md5(f"{method}:{uri}")

    if "auth" in qop_offered:
        qop = "auth"
        response = _md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
        extra = f', qop={qop}, nc={nc}, cnonce="{cnonce}"'
    else:
        response = _md5(f"{ha1}:{nonce}:{ha2}")
        extra = ""

    return (
        f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
        f'uri="{uri}", response="{response}", algorithm={algorithm}{extra}'
    )


def _default_transport(ip: str, timeout: float) -> Transport:
    def _request(method: str, path: str, headers: dict[str, str]):
        conn = http.client.HTTPConnection(ip, 80, timeout=timeout)
        try:
            conn.request(method, path, headers=headers)
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="ignore")
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hdrs, body
        finally:
            conn.close()

    return _request


def fetch_device_info(
    ip: str,
    username: str,
    password: str,
    *,
    transport: Transport | None = None,
    timeout: float = 5.0,
) -> dict[str, str]:
    """Read serial (+ device type when available) using Digest auth.

    Returns e.g. ``{"serial": "...", "device_type": "..."}``.
    Raises :class:`DahuaAuthError` / :class:`DahuaUnreachableError` /
    :class:`DahuaError` with stable keys.
    """
    if transport is None:
        transport = _default_transport(ip, timeout)

    def authed_get(path: str) -> str:
        try:
            status, headers, body = transport("GET", path, {})
        except Exception as err:  # connection refused, timeout, DNS...
            raise DahuaUnreachableError() from err
        if status == 401:
            challenge = parse_www_authenticate(headers.get("www-authenticate", ""))
            if not challenge:
                raise DahuaAuthError()
            auth = build_digest_header(
                method="GET",
                uri=path,
                username=username,
                password=password,
                challenge=challenge,
            )
            try:
                status, headers, body = transport(
                    "GET", path, {"Authorization": auth}
                )
            except Exception as err:
                raise DahuaUnreachableError() from err
            if status == 401:
                raise DahuaAuthError()
        if status != 200:
            raise DahuaError(f"http_{status}")
        return body

    info: dict[str, str] = {}
    serial_body = authed_get(SERIAL_PATH)
    serial = parse_magicbox(serial_body).get("sn")
    if serial:
        info["serial"] = serial
    try:
        type_body = authed_get(DEVICE_TYPE_PATH)
        dtype = parse_magicbox(type_body).get("type")
        if dtype:
            info["device_type"] = dtype
    except DahuaError:
        pass  # device type is a bonus; serial is what matters
    if "serial" not in info:
        raise DahuaError("serial_missing")
    return info
