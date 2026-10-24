"""Parser for LIXIL camera QR code payloads.

The QR code printed in the camera manual decodes to a payload like::

    {SN:ABC123..., SC:Ab12Cd34, PID:12345}

- ``SN``  serial number of the camera
- ``SC``  security code == the camera's admin password
- ``PID`` product id

MVP input method (decided 2026-10-24): the user scans the QR code with
their phone, then pastes the decoded text into the config flow.  This
module turns that pasted text into structured data.  It is deliberately
free of Home Assistant imports so it can be unit tested anywhere.

Accepted inputs:
- the full ``{SN:…, SC:…, PID:…}`` payload (also JSON-style with quotes)
- the payload embedded in surrounding noise text
- a bare security code on its own (``partial=True``; SN check is skipped
  by the caller in that case, per SPEC)

Never log or persist the returned ``sc`` value outside the flow.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["QrData", "QrParseError", "parse_qr_text", "sn_matches"]


class QrParseError(ValueError):
    """Raised when pasted text cannot yield a security code.

    ``key`` is a stable machine-readable reason, mapped to a translated
    error string by the config flow.
    """

    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


@dataclass(frozen=True)
class QrData:
    """Structured result of parsing a QR payload."""

    sc: str
    sn: str | None = None
    pid: str | None = None
    partial: bool = False
    warnings: tuple[str, ...] = field(default_factory=tuple)


_BLOCK_RE = re.compile(r"\{[^{}]*\}")
_PAIR_RE = re.compile(
    r'"?(SN|SC|PID)"?\s*[:=]\s*"?(?P<value>[^",}\s]+)"?', re.IGNORECASE
)
_BARE_SC_RE = re.compile(r"^[A-Za-z0-9!@#$%^&*._~+\-]{6,16}$")


def _looks_like_bare_sc(token: str) -> bool:
    """Heuristic for a bare security code pasted on its own.

    Real SCs are short mixed tokens (the verified LS279 one is 8 chars
    with letters and digits).  Requiring a letter+digit mix and a short
    length keeps ordinary sentences from being mistaken for a code;
    anyone whose code does not fit can paste the full QR payload
    instead, which is parsed structurally.
    """
    if not _BARE_SC_RE.match(token):
        return False
    return bool(re.search(r"[A-Za-z]", token) and re.search(r"[0-9]", token))


def _parse_block(block: str) -> QrData:
    fields: dict[str, str] = {}
    for match in _PAIR_RE.finditer(block):
        fields[match.group(1).upper()] = match.group("value").strip()

    sc = fields.get("SC")
    if not sc:
        raise QrParseError("qr_missing_sc")

    warnings: list[str] = []
    sn = fields.get("SN")
    if not sn:
        warnings.append("qr_missing_sn")
    pid = fields.get("PID")
    if not pid:
        warnings.append("qr_missing_pid")

    return QrData(
        sc=sc,
        sn=sn,
        pid=pid,
        partial=bool(warnings),
        warnings=tuple(warnings),
    )


def parse_qr_text(text: str) -> QrData:
    """Parse pasted QR text into :class:`QrData`.

    Raises :class:`QrParseError` with key ``qr_empty``, ``qr_missing_sc``
    or ``qr_unrecognized`` when no security code can be extracted.
    """
    if text is None:
        raise QrParseError("qr_empty")
    cleaned = text.strip()
    if not cleaned:
        raise QrParseError("qr_empty")

    block = _BLOCK_RE.search(cleaned)
    if block:
        return _parse_block(block.group(0))

    # No {...} block: accept a single bare token as the security code.
    token = re.sub(r"\s+", "", cleaned)
    if _looks_like_bare_sc(token):
        return QrData(sc=token, partial=True, warnings=("qr_bare_sc",))

    raise QrParseError("qr_unrecognized")


def sn_matches(qr: QrData, device_sn: str | None) -> bool | None:
    """Cross-check the QR serial number against a discovered device.

    Returns ``True``/``False`` when both sides have a serial number,
    ``None`` when the check cannot be performed (caller decides whether
    to warn or block).
    """
    if not qr.sn or not device_sn:
        return None
    return qr.sn.strip().upper() == device_sn.strip().upper()
