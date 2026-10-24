"""Config flow for LIXIL Companion.

Steps (SPEC F1/F2):
1. ``user``    - enter the camera IP (automatic discovery lands here too
                 once F1 ships; manual entry is the fallback).  The host
                 is fingerprinted before moving on.
2. ``qr``      - paste the decoded QR text; the parser extracts the
                 security code (SC).
3. ``confirm`` - read the device serial with admin/SC (digest auth) and
                 cross-check it against the QR's SN, then hand off to
                 ha-dahua by programmatically driving its config flow,
                 and finally verify the new camera can snapshot.

The security code lives only in this flow's memory.  It is passed to the
ha-dahua flow (which owns credential storage) and is never written into
this integration's own config entry.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_NAME
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import entity_registry as er

from .const import (
    CONF_ADDRESS,
    CONF_DAHUA_ENTRY_ID,
    CONF_MAC,
    CONF_PID,
    CONF_SERIAL,
    DEFAULT_DAHUA_CHANNEL,
    DEFAULT_DAHUA_USERNAME,
    DOMAIN,
)
from .dahua_api import DahuaError, fetch_device_info
from .discovery import Fingerprint, probe_host
from .qr import QrData, QrParseError, parse_qr_text, sn_matches

_LOGGER = logging.getLogger(__name__)

DAHUA_DOMAIN = "dahua"
_DRIVE_POLL_SECONDS = 2.0
_DRIVE_MAX_POLLS = 45  # ~90s worst case for dahua discovery
_MANUAL_CHOICE = "__manual__"


def _local_ip() -> str | None:
    """This host's primary LAN IP (routing decision only, no traffic)."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


class LixilCompanionConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a LIXIL Companion config flow."""

    VERSION = 1

    def __init__(self) -> None:
        self._address: str | None = None
        self._mac: str | None = None
        self._device_sn: str | None = None
        self._device_type: str | None = None
        self._fingerprint: Fingerprint | None = None
        self._qr: QrData | None = None
        self._candidates: dict[str, Fingerprint] = {}

    # -- step 1: pick a discovered camera (or fall back to manual) -------

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if user_input is not None:
            choice = user_input.get("device")
            if choice == _MANUAL_CHOICE:
                return await self.async_step_manual()
            fp = self._candidates.get(choice or "")
            if fp is not None:
                await self._adopt_fingerprint(fp)
                return await self.async_step_qr()

        candidates = await self._async_scan()
        self._candidates = {fp.ip: fp for fp in candidates}
        if not candidates:
            return await self.async_step_manual(no_devices=True)

        from .discovery import candidate_options

        options = candidate_options(candidates)
        options[_MANUAL_CHOICE] = "Enter an IP address manually"
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required("device"): vol.In(options)}
            ),
        )

    async def _adopt_fingerprint(self, fp: Fingerprint) -> None:
        self._address = fp.ip
        self._fingerprint = fp
        self._device_sn = fp.serial
        self._mac = fp.mac
        if not self._mac:
            from .discovery import mac_for_ip

            self._mac = await self.hass.async_add_executor_job(
                mac_for_ip, fp.ip
            )

    async def _async_scan(self) -> list[Fingerprint]:
        """Scan HA's own /24 (plus subnets of existing entries)."""
        from .discovery import read_proc_arp, scan_subnet

        bases: list[str] = []
        local_ip = await self.hass.async_add_executor_job(_local_ip)
        if local_ip:
            bases.append(local_ip)
        for domain in (DOMAIN, DAHUA_DOMAIN):
            for entry in self.hass.config_entries.async_entries(domain):
                addr = (entry.data or {}).get(CONF_ADDRESS)
                if addr and addr not in bases:
                    bases.append(addr)
        arp_text = await self.hass.async_add_executor_job(read_proc_arp)
        found: list[Fingerprint] = []
        seen: set[str] = set()
        scanned_subnets: set[str] = set()
        for base in bases:
            subnet_key = ".".join(base.split(".")[:3])
            if subnet_key in scanned_subnets:
                continue  # same /24 via another base address
            scanned_subnets.add(subnet_key)
            for fp in await scan_subnet(base, arp_text=arp_text):
                if fp.ip not in seen:
                    seen.add(fp.ip)
                    found.append(fp)
        return found

    # -- step 1b: manual address entry ------------------------------------

    async def async_step_manual(
        self,
        user_input: dict[str, Any] | None = None,
        *,
        no_devices: bool = False,
    ) -> FlowResult:
        errors: dict[str, str] = {}
        if no_devices and user_input is None:
            errors["base"] = "no_devices_found"
        if user_input is not None:
            self._address = (user_input.get(CONF_ADDRESS) or "").strip()
            if not self._address:
                errors[CONF_ADDRESS] = "address_required"
            else:
                # Fingerprint the host (ports + HTTP markers + MAC).
                # Unreachable -> hard error.  Reachable but not scored
                # as Dahua -> continue anyway; the SN check in the
                # confirm step and ha-dahua's own discovery are the
                # real gates, this score only informs.
                self._fingerprint = await probe_host(self._address)
                if not self._fingerprint.open_ports:
                    errors[CONF_ADDRESS] = "device_unreachable"
                    self._fingerprint = None
                else:
                    self._device_sn = self._fingerprint.serial
                    # Capture the MAC now (the probe just warmed the
                    # ARP cache).  The guardian needs it to follow the
                    # camera across IP changes; confirm retries once
                    # more after the authenticated device read.
                    from .discovery import mac_for_ip

                    self._mac = await self.hass.async_add_executor_job(
                        mac_for_ip, self._address
                    )
                    return await self.async_step_qr()

        return self.async_show_form(
            step_id="manual",
            data_schema=vol.Schema({vol.Required(CONF_ADDRESS): str}),
            errors=errors,
        )

    # -- discovery via DHCP ----------------------------------------------

    async def async_step_dhcp(self, discovery_info: Any) -> FlowResult:
        """A device with a Dahua OUI got a DHCP lease: offer setup.

        HA matches MAC prefixes from the manifest.  We fingerprint the
        device before bothering the user - other Dahua gear (NVRs,
        intercoms) shares the same OUIs and must not trigger this flow.
        """
        from .discovery import normalize_mac

        ip = getattr(discovery_info, "ip", None)
        mac = normalize_mac(getattr(discovery_info, "macaddress", None))
        if not ip:
            return self.async_abort(reason="not_dahua_camera")
        for entry in self._async_current_entries():
            if normalize_mac((entry.data or {}).get(CONF_MAC)) == mac and mac:
                return self.async_abort(reason="already_configured")
        await self.async_set_unique_id(mac or ip)
        self._abort_if_unique_id_configured()
        fp = await probe_host(ip)
        if not fp.is_likely_dahua:
            return self.async_abort(reason="not_dahua_camera")
        if mac and not fp.mac:
            import dataclasses

            fp = dataclasses.replace(fp, mac=mac)
        self.context["title_placeholders"] = {"name": f"LIXIL camera ({ip})"}
        await self._adopt_fingerprint(fp)
        return await self.async_step_qr()

    # -- step 2: QR paste -------------------------------------------------

    async def async_step_qr(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            raw = user_input.get("qr_text") or ""
            try:
                self._qr = parse_qr_text(raw)
            except QrParseError as err:
                errors["qr_text"] = err.key
            else:
                match = sn_matches(self._qr, self._device_sn)
                if match is False:
                    errors["qr_text"] = "sn_mismatch"
                else:
                    return await self.async_step_confirm()

        return self.async_show_form(
            step_id="qr",
            data_schema=vol.Schema({vol.Required("qr_text"): str}),
            errors=errors,
            description_placeholders={"address": self._address or ""},
        )

    # -- step 3: verify + drive ha-dahua ----------------------------------

    async def async_step_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        assert self._qr is not None and self._address is not None
        errors: dict[str, str] = {}
        default_name = self._default_name()

        if user_input is not None:
            name = (user_input.get(CONF_NAME) or default_name).strip() or default_name

            # 1) Read the real serial from the device with admin/SC and
            #    cross-check the QR's SN.  This is the authoritative
            #    check (discovery cannot read a serial without auth).
            try:
                info = await self.hass.async_add_executor_job(
                    fetch_device_info,
                    self._address,
                    DEFAULT_DAHUA_USERNAME,
                    self._qr.sc,
                )
            except DahuaError as err:
                errors["base"] = err.key
            else:
                self._device_sn = info.get("serial") or self._device_sn
                self._device_type = info.get("device_type") or self._device_type
                if self._qr.sn and self._device_sn and not sn_matches(
                    self._qr, self._device_sn
                ):
                    errors["base"] = "sn_mismatch"
                if not self._mac:
                    # The authenticated read just talked to the device,
                    # so its ARP entry is warm - best moment to capture.
                    from .discovery import mac_for_ip

                    self._mac = await self.hass.async_add_executor_job(
                        mac_for_ip, self._address
                    )

            # 2) Reuse an existing ha-dahua entry for this address when
            #    there is one (e.g. retrying after a partial failure, or
            #    the user added the camera manually first); otherwise
            #    drive the ha-dahua flow to create its entry.
            dahua_entry_id: str | None = None
            if not errors:
                dahua_entry_id = self._find_existing_dahua_entry()
            if not errors and not dahua_entry_id:
                try:
                    dahua_entry_id = await self._drive_dahua_flow(name)
                except _DriveError as err:
                    if err.key == "dahua_not_installed":
                        return self.async_abort(reason="dahua_not_installed")
                    errors["base"] = err.key

            # 3) Verify the new camera actually snapshots (best effort:
            #    a failure here does not roll back the dahua entry, it is
            #    recorded on our entry for the guardian to watch).
            verified = False
            if not errors and dahua_entry_id:
                verified = await self._verify_snapshot(dahua_entry_id)

            if not errors:
                await self.async_set_unique_id(self._device_sn or self._address)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=name,
                    data={
                        CONF_ADDRESS: self._address,
                        CONF_SERIAL: self._device_sn,
                        CONF_PID: self._qr.pid,
                        CONF_MAC: self._mac
                        or (self._fingerprint.mac if self._fingerprint else None),
                        CONF_DAHUA_ENTRY_ID: dahua_entry_id,
                        "device_type": self._device_type,
                        "verified": verified,
                    },
                )

        return self.async_show_form(
            step_id="confirm",
            data_schema=vol.Schema(
                {vol.Optional(CONF_NAME, default=default_name): str}
            ),
            errors=errors,
            description_placeholders={"address": self._address},
        )

    # -- helpers ------------------------------------------------------------

    def _default_name(self) -> str:
        if self._device_type:
            return f"LIXIL {self._device_type}"
        return "LIXIL Camera"

    async def _drive_dahua_flow(self, name: str) -> str:
        """Create a ha-dahua entry by driving its config flow in-process.

        Raises _DriveError with a stable key on failure.  Proven against
        the real integration on 2026-10-24 via the REST flow API, which
        exercises the same flow manager used here.
        """
        assert self._qr is not None and self._address is not None
        flow_manager = self.hass.config_entries.flow
        try:
            result = await flow_manager.async_init(
                DAHUA_DOMAIN,
                context={"source": config_entries.SOURCE_USER},
                data={
                    "username": DEFAULT_DAHUA_USERNAME,
                    "password": self._qr.sc,
                    "address": self._address,
                    "channel": DEFAULT_DAHUA_CHANNEL,
                },
            )
        except Exception as err:  # UnknownHandler etc.
            _LOGGER.warning("dahua flow init failed: %s", err)
            raise _DriveError("dahua_not_installed") from err

        flow_id = result.get("flow_id")
        for _ in range(_DRIVE_MAX_POLLS):
            rtype = result.get("type")
            if rtype == "create_entry":
                # In-process, FlowResult["result"] is the ConfigEntry
                # object itself (the REST layer serializes it to a dict
                # with entry_id).  Handle both shapes.
                entry = result.get("result")
                if entry is None:
                    return ""
                if isinstance(entry, dict):
                    return entry.get("entry_id") or ""
                return getattr(entry, "entry_id", "") or ""
            if rtype == "abort":
                reason = result.get("reason") or "drive_failed"
                raise _DriveError(
                    "dahua_already_configured"
                    if reason == "already_configured"
                    else "drive_failed"
                )
            if rtype == "form":
                if result.get("step_id") == "name":
                    result = await flow_manager.async_configure(
                        flow_id, {"name": name}
                    )
                    continue
                raise _DriveError("drive_failed")
            # "progress" (dahua is discovering the device): wait, then
            # re-configure with no input to advance the flow.
            await asyncio.sleep(_DRIVE_POLL_SECONDS)
            result = await flow_manager.async_configure(flow_id)
        raise _DriveError("drive_timeout")

    def _find_existing_dahua_entry(self) -> str | None:
        """Entry id of a loaded ha-dahua entry for our address, if any."""
        for entry in self.hass.config_entries.async_entries(DAHUA_DOMAIN):
            if (entry.data or {}).get(CONF_ADDRESS) == self._address:
                return entry.entry_id
        return None

    async def _verify_snapshot(self, dahua_entry_id: str) -> bool:
        """Best-effort: fetch one image from the new entry's camera.

        The entity registry can lag a few seconds behind entry creation,
        so poll briefly for the camera entity before giving up.
        """
        try:
            registry = er.async_get(self.hass)
            camera_id = None
            for _ in range(8):
                entries = er.async_entries_for_config_entry(
                    registry, dahua_entry_id
                )
                camera_id = next(
                    (e.entity_id for e in entries if e.domain == "camera"),
                    None,
                )
                if camera_id:
                    break
                await asyncio.sleep(2)
            if not camera_id:
                return False
            from homeassistant.components.camera import async_get_image

            image = await async_get_image(self.hass, camera_id, timeout=10)
            return bool(image and image.content)
        except Exception as err:  # best effort only, never fatal
            _LOGGER.debug("snapshot verify failed: %s", err)
            return False


class _DriveError(Exception):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key
