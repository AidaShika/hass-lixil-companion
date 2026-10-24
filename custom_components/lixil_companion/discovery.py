"""LAN discovery and Dahua-OEM fingerprinting.

Strategy (SPEC F1): a LIXIL camera does not announce itself, so we scan
the local /24, then score each live host on Dahua traits:

- TCP 554 (RTSP) open                       -> weak signal
- TCP 37777 (Dahua private protocol) open   -> strong signal
- HTTP management page with Dahua markers   -> strong signal
- MAC OUI seen on verified units            -> weak signal

The serial number is intentionally *not* required at this stage: Dahua
CGI endpoints need auth, so the serial cross-check happens later in the
flow, once the user has pasted the QR text (the integration then logs in
with admin/SC and reads the serial via magicBox).  When ONVIF discovery
data is available, its scopes are parsed for a serial as a bonus.

Everything except the ``probe_*`` network helpers is pure/stdlib so the
scoring and parsing can be unit tested without Home Assistant.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

# --- fingerprint knowledge -------------------------------------------------

DAHUA_PRIVATE_PORT = 37777
RTSP_PORT = 554
HTTP_PORTS = (80, 8080)
PROBE_PORTS = (RTSP_PORT, DAHUA_PRIVATE_PORT, *HTTP_PORTS)

# MAC OUIs (first 3 octets, lowercase, colon form).
# "1c:4d:89" is verified on the author's LS279 (2026-10-24, live ARP).
# Others are widely used Dahua OUIs; treat OUI as a weak signal only.
DAHUA_OUIS = {
    "1c:4d:89",  # verified: LS279 author's unit
    "3c:ef:8c",
    "e0:50:8b",
    "bc:32:5f",
    "a0:bd:1d",
    "f4:b8:a1",
}

_HTTP_MARKERS = (
    "dahua",
    "dhua",  # some firmware misspell/abbreviate
    "/cgi-bin/magicbox.cgi",
    "web service",  # Dahua web UI title on several firmware lines
)
# NOTE (verified 2026-10-24, LS279 fw 2.800.1E8C000.0.R): the root page
# is a bare "404 Not Found" with no Server header and no Dahua markers,
# so this signal does NOT fire for LS279.  Its fingerprint there is
# 37777 + 554 + MAC OUI = 70, comfortably above threshold.  The HTTP
# marker remains useful for other Dahua firmware lines.

# Score needed to call a host a likely Dahua OEM camera.
LIKELY_THRESHOLD = 50


@dataclass(frozen=True)
class Fingerprint:
    """What we believe about one host on the LAN."""

    ip: str
    mac: str | None = None
    open_ports: tuple[int, ...] = ()
    http_server: str | None = None
    http_title: str | None = None
    serial: str | None = None
    score: int = 0
    reasons: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_likely_dahua(self) -> bool:
        return self.score >= LIKELY_THRESHOLD


def mac_oui(mac: str | None) -> str | None:
    if not mac:
        return None
    parts = re.split(r"[:\-]", mac.strip().lower())
    if len(parts) < 3:
        return None
    return ":".join(p.zfill(2) for p in parts[:3])


def classify(
    ip: str,
    *,
    mac: str | None = None,
    open_ports: tuple[int, ...] = (),
    http_server: str | None = None,
    http_body: str | None = None,
    serial: str | None = None,
) -> Fingerprint:
    """Score one host's traits. Pure function - this is the testable core."""
    score = 0
    reasons: list[str] = []

    ports = set(open_ports)
    if DAHUA_PRIVATE_PORT in ports:
        score += 45
        reasons.append("dahua_private_port")
    if RTSP_PORT in ports:
        score += 15
        reasons.append("rtsp_open")

    haystack = " ".join(
        x for x in (http_server, _extract_title(http_body), http_body) if x
    ).lower()
    if any(marker in haystack for marker in _HTTP_MARKERS):
        score += 35
        reasons.append("dahua_http_marker")

    if mac_oui(mac) in DAHUA_OUIS:
        score += 10
        reasons.append("dahua_mac_oui")

    if serial:
        score += 10
        reasons.append("serial_known")

    return Fingerprint(
        ip=ip,
        mac=mac,
        open_ports=tuple(sorted(ports)),
        http_server=http_server,
        http_title=_extract_title(http_body),
        serial=serial,
        score=min(score, 100),
        reasons=tuple(reasons),
    )


_TITLE_RE = re.compile(r"<title[^>]*>([^<]*)</title>", re.IGNORECASE)


def _extract_title(html: str | None) -> str | None:
    if not html:
        return None
    m = _TITLE_RE.search(html)
    return m.group(1).strip() if m else None


# --- response parsers --------------------------------------------------------

_KV_RE = re.compile(r"^([A-Za-z0-9_.]+)=(.*)$")


def parse_magicbox(text: str) -> dict[str, str]:
    """Parse Dahua magicBox CGI ``key=value`` responses.

    Examples: ``sn=ABC123`` from getSerialNo, ``type=ABC123`` from
    getDeviceType.  Unknown lines are ignored.
    """
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        m = _KV_RE.match(line.strip())
        if m:
            out[m.group(1).lower()] = m.group(2).strip()
    return out


_SCOPE_SERIAL_RE = re.compile(r"(?:serial|hardware/)\S*?([A-Za-z0-9]{8,})", re.IGNORECASE)
_XADDR_RE = re.compile(r"<[^>]*XAddrs[^>]*>([^<]+)</", re.IGNORECASE)
_SCOPES_RE = re.compile(r"<[^>]*Scopes[^>]*>([^<]+)</", re.IGNORECASE)


def parse_onvif_probe_matches(xml: str) -> list[dict[str, str | None]]:
    """Extract endpoints (+ serial when present) from WS-Discovery replies."""
    results: list[dict[str, str | None]] = []
    if not xml:
        return results
    xaddrs = _XADDR_RE.findall(xml)
    scopes_blocks = _SCOPES_RE.findall(xml)
    for idx, xaddr in enumerate(xaddrs):
        serial = None
        if idx < len(scopes_blocks):
            m = _SCOPE_SERIAL_RE.search(scopes_blocks[idx])
            if m:
                serial = m.group(1)
        first = xaddr.split()[0] if xaddr.split() else xaddr
        host = re.sub(r"^https?://", "", first).split("/")[0].split(":")[0]
        results.append({"ip": host or None, "xaddr": first, "serial": serial})
    return results


_ARP_BSD_RE = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]{11,17})", re.IGNORECASE)
_ARP_LINUX_RE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-f:]{17})", re.IGNORECASE | re.MULTILINE
)
# /proc/net/arp (what HA Core on Linux can read directly):
# IP address  HW type  Flags  HW address         Mask  Device
_PROC_ARP_RE = re.compile(
    r"^(\d+\.\d+\.\d+\.\d+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+([0-9a-f:]{17})\s",
    re.IGNORECASE | re.MULTILINE,
)


def arp_pairs(arp_text: str) -> dict[str, str]:
    """Parse any supported ARP dump into ``{ip: mac}`` (mac lowercase)."""
    pairs: dict[str, str] = {}
    for regex in (_ARP_BSD_RE, _ARP_LINUX_RE, _PROC_ARP_RE):
        for m in regex.finditer(arp_text or ""):
            pairs[m.group(1)] = m.group(2).lower()
    return pairs


def _norm_mac(mac: str) -> str:
    parts = re.split(r"[:\-]", mac.strip().lower())
    return ":".join(p.zfill(2) for p in parts)


def normalize_mac(raw: str | None) -> str | None:
    """Normalize a MAC in any common spelling to ``aa:bb:cc:dd:ee:ff``.

    Accepts colon/dash separated forms and the separator-free form that
    Home Assistant's DHCP discovery hands out (``1c4d895d25a0``).
    """
    if not raw:
        return None
    text = raw.strip().lower()
    hexonly = re.sub(r"[^0-9a-f]", "", text)
    if len(hexonly) == 12 and set(text) <= set("0123456789abcdef:-"):
        return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))
    parts = re.split(r"[:\-]", text)
    if len(parts) == 6 and all(
        1 <= len(p) <= 2 and all(c in "0123456789abcdef" for c in p)
        for p in parts
    ):
        return ":".join(p.zfill(2) for p in parts)
    return None


def mac_from_arp_table(arp_text: str, ip: str) -> str | None:
    """Find a MAC for ``ip`` in an ARP dump (arp -a / ip neigh / /proc)."""
    return arp_pairs(arp_text).get(ip)


def ip_from_arp_table(arp_text: str, mac: str) -> str | None:
    """Reverse lookup: current IP for a known MAC (the guardian's core)."""
    target = _norm_mac(mac)
    for ip, found in arp_pairs(arp_text).items():
        if _norm_mac(found) == target:
            return ip
    return None


def read_proc_arp() -> str:
    """Read /proc/net/arp when available (Linux / HA Core); '' otherwise."""
    try:
        with open("/proc/net/arp", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


_IP_NEIGH_RE = re.compile(
    r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})",
    re.IGNORECASE,
)


def mac_for_ip(ip: str) -> str | None:
    """Best-effort MAC lookup for one IP from local ARP sources.

    Tries /proc/net/arp, then ``ip neigh``, then ``arp -a``.  Blocking
    (file/subprocess) - call it from an executor.  Works best right
    after traffic to the host (a probe or a login warms the ARP cache).
    """
    mac = mac_from_arp_table(read_proc_arp(), ip)
    if mac:
        return mac
    import subprocess

    for cmd in (["ip", "neigh", "show", ip], ["arp", "-a"]):
        try:
            out = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        mac = mac_from_arp_table(out, ip)
        if mac:
            return mac
        m = _IP_NEIGH_RE.search(out or "")
        if m and m.group(1) == ip:
            return m.group(2).lower()
    return None


def subnet_hosts(subnet_ip: str) -> list[str]:
    """All host addresses of the /24 containing ``subnet_ip`` (excl. .0/.255)."""
    parts = subnet_ip.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"not an IPv4 address: {subnet_ip!r}")
    base = ".".join(parts[:3])
    return [f"{base}.{i}" for i in range(1, 255)]


# --- network probers (thin, stdlib asyncio) ----------------------------------


async def probe_port(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        return True
    except Exception:
        return False


async def fetch_http(ip: str, port: int = 80, timeout: float = 1.5) -> tuple[str | None, str]:
    """Minimal HTTP/1.0 GET; returns (Server header, body text)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.write(
            f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: lixil-companion\r\n\r\n".encode()
        )
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(16384), timeout=timeout)
        writer.close()
    except Exception:
        return None, ""
    text = raw.decode("utf-8", errors="ignore")
    server = None
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            break
    body = text.split("\r\n\r\n", 1)[-1]
    return server, body


# --- scan orchestration -------------------------------------------------------


async def probe_host(
    ip: str,
    *,
    mac: str | None = None,
    port_timeout: float = 0.8,
) -> Fingerprint:
    results = await asyncio.gather(
        *(probe_port(ip, p, port_timeout) for p in PROBE_PORTS)
    )
    open_ports = tuple(p for p, ok in zip(PROBE_PORTS, results) if ok)
    server, body = (None, "")
    for hp in HTTP_PORTS:
        if hp in open_ports:
            server, body = await fetch_http(ip, hp)
            break
    return classify(
        ip, mac=mac, open_ports=open_ports, http_server=server, http_body=body
    )


async def scan_subnet(
    subnet_ip: str,
    *,
    arp_text: str = "",
    max_concurrent: int = 48,
) -> list[Fingerprint]:
    """Probe a whole /24; return likely cameras, strongest first.

    Two phases: a fast TCP sweep for every host, then the (slower) HTTP
    fingerprint fetch only for hosts whose port profile could be a
    Dahua camera.  A naive full probe of a busy /24 took ~46 s from a
    Home Assistant VM; this keeps a scan in the ~10-20 s range.
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _ports(ip: str) -> tuple[int, ...]:
        async with semaphore:
            results = await asyncio.gather(
                *(probe_port(ip, p) for p in PROBE_PORTS)
            )
        return tuple(p for p, ok in zip(PROBE_PORTS, results) if ok)

    async def _full(ip: str, open_ports: tuple[int, ...]) -> Fingerprint:
        async with semaphore:
            server, body = (None, "")
            for hp in HTTP_PORTS:
                if hp in open_ports:
                    server, body = await fetch_http(ip, hp)
                    break
            return classify(
                ip,
                mac=mac_from_arp_table(arp_text, ip),
                open_ports=open_ports,
                http_server=server,
                http_body=body,
            )

    hosts = subnet_hosts(subnet_ip)
    port_sets = await asyncio.gather(*(_ports(ip) for ip in hosts))
    prints: list[Fingerprint] = []
    for ip, open_ports in zip(hosts, port_sets):
        if DAHUA_PRIVATE_PORT in open_ports or (
            RTSP_PORT in open_ports
            and any(hp in open_ports for hp in HTTP_PORTS)
        ):
            prints.append(await _full(ip, open_ports))
        else:
            prints.append(
                classify(
                    ip,
                    mac=mac_from_arp_table(arp_text, ip),
                    open_ports=open_ports,
                )
            )
    likely = [fp for fp in prints if fp.is_likely_dahua]
    return sorted(likely, key=lambda fp: fp.score, reverse=True)


def candidate_label(fp: Fingerprint) -> str:
    """Human-readable one-liner for a scan candidate (setup picker)."""
    parts = [fp.ip]
    if fp.mac:
        parts.append(f"MAC {fp.mac}")
    parts.append(f"score {fp.score}")
    return " — ".join(parts)


def candidate_options(prints: list[Fingerprint]) -> dict[str, str]:
    """Map ip -> picker label for likely cameras, strongest first."""
    likely = sorted(
        (fp for fp in prints if fp.is_likely_dahua),
        key=lambda fp: fp.score,
        reverse=True,
    )
    return {fp.ip: candidate_label(fp) for fp in likely}
