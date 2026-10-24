"""IP guardian: watches for camera IP drift and heals the dahua entry.

SPEC F3.  The motivation is measured, not hypothetical: the author's
LS279 moved 192.168.11.26 -> 192.168.11.15 within four days, and a
ha-dahua entry stores a fixed address with no auto-follow.

Design:
- :class:`GuardianTracker` is a pure decision maker (unit tested): feed
  it what each check found, it tells you whether to do nothing, update
  the address, or notify the user (only after repeated failures, and
  only once until recovery).
- :class:`IpGuardian` is the thin Home Assistant shell: periodic timer,
  locate the device by MAC (ARP after an active subnet probe), update
  the ha-dahua entry's ``address`` via the config-entries manager and
  reload it, then verify the camera entity recovers.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

try:  # package import (inside Home Assistant)
    from .const import (
        CONF_ADDRESS,
        CONF_DAHUA_ENTRY_ID,
        CONF_MAC,
        GUARDIAN_NOTIFY_AFTER_FAILURES,
        GUARDIAN_SCAN_INTERVAL_MINUTES,
    )
except ImportError:  # top-level import (unit tests)
    from const import (  # type: ignore
        CONF_ADDRESS,
        CONF_DAHUA_ENTRY_ID,
        CONF_MAC,
        GUARDIAN_NOTIFY_AFTER_FAILURES,
        GUARDIAN_SCAN_INTERVAL_MINUTES,
    )

if TYPE_CHECKING:  # pragma: no cover - typing only
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


# --- pure decision core ------------------------------------------------------


@dataclass(frozen=True)
class GuardianDecision:
    action: str  # "none" | "update" | "notify"
    new_ip: str | None = None


class GuardianTracker:
    """Stateful decider across guardian checks."""

    def __init__(self, notify_after: int = GUARDIAN_NOTIFY_AFTER_FAILURES) -> None:
        self._notify_after = max(1, notify_after)
        self._misses = 0
        self._notified = False

    def found(self, current_ip: str, found_ip: str) -> GuardianDecision:
        """The device was located at ``found_ip``."""
        self._misses = 0
        self._notified = False
        if found_ip != current_ip:
            return GuardianDecision("update", new_ip=found_ip)
        return GuardianDecision("none")

    def not_found(self) -> GuardianDecision:
        """The device could not be located this round."""
        self._misses += 1
        if self._misses >= self._notify_after and not self._notified:
            self._notified = True
            return GuardianDecision("notify")
        return GuardianDecision("none")

    def update_failed(self) -> GuardianDecision:
        """Locating worked but applying the new address did not."""
        return self.not_found()


# --- Home Assistant shell ------------------------------------------------------


class IpGuardian:
    """Periodic checker bound to one companion config entry."""

    def __init__(self, hass: "HomeAssistant", entry: "ConfigEntry") -> None:
        self.hass = hass
        self.entry = entry
        self.tracker = GuardianTracker()
        self._unsub_timer = None
        self._unsub_initial = None

    async def async_start(self) -> None:
        from homeassistant.helpers.event import (
            async_call_later,
            async_track_time_interval,
        )

        # One early check shortly after start: catches drift that happened
        # while HA was down, and makes the guardian observable/testable
        # without waiting a full interval.
        self._unsub_initial = async_call_later(
            self.hass, 60, self._async_check
        )
        self._unsub_timer = async_track_time_interval(
            self.hass,
            self._async_check,
            timedelta(minutes=GUARDIAN_SCAN_INTERVAL_MINUTES),
        )
        _LOGGER.debug(
            "guardian started for %s every %s min",
            self.entry.title,
            GUARDIAN_SCAN_INTERVAL_MINUTES,
        )

    async def async_stop(self) -> None:
        if self._unsub_timer is not None:
            self._unsub_timer()
            self._unsub_timer = None
        unsub_initial = getattr(self, "_unsub_initial", None)
        if unsub_initial is not None:
            unsub_initial()
            self._unsub_initial = None

    # -- internals ---------------------------------------------------------

    async def _locate_ip(self) -> str | None:
        """Find the camera's current IP.

        Primary: by stored MAC (probe the /24 to warm the ARP cache,
        then reverse-lookup the MAC).  Fallback when no MAC was stored
        (older entries): fingerprint scan - if exactly one host on the
        subnet answers on the Dahua control port (37777), treat it as
        the camera and backfill its MAC into our entry so later checks
        take the primary path.
        """
        from .discovery import (
            ip_from_arp_table,
            mac_for_ip,
            probe_host,
            read_proc_arp,
            subnet_hosts,
        )

        data = self.entry.data
        mac = data.get(CONF_MAC)
        address = data.get(CONF_ADDRESS)
        if not address:
            return None

        # Probe the /24 so the kernel ARP cache learns the camera's MAC
        # (same mechanism scan_subnet uses; ~seconds on a home LAN).
        prints = await asyncio.gather(
            *(probe_host(ip) for ip in subnet_hosts(address)),
            return_exceptions=True,
        )
        if mac:
            return ip_from_arp_table(read_proc_arp(), mac)

        candidates = [
            fp.ip
            for fp in prints
            if not isinstance(fp, Exception) and 37777 in fp.open_ports
        ]
        if len(candidates) != 1:
            _LOGGER.warning(
                "guardian: no MAC stored and %d Dahua-port candidates "
                "on the subnet - cannot locate safely",
                len(candidates),
            )
            return None
        found = candidates[0]
        backfill = await self.hass.async_add_executor_job(mac_for_ip, found)
        if backfill:
            self.hass.config_entries.async_update_entry(
                self.entry, data={**self.entry.data, CONF_MAC: backfill}
            )
            _LOGGER.info(
                "guardian: backfilled missing MAC %s for %s",
                backfill,
                self.entry.title,
            )
        return found

    async def _async_check(self, _now=None) -> None:
        from homeassistant.helpers import entity_registry as er

        data = self.entry.data
        dahua_entry_id = data.get(CONF_DAHUA_ENTRY_ID)
        current_ip = data.get(CONF_ADDRESS)
        # Breadcrumb while the integration is young: one line per check
        # so a silent no-op can be told apart from "never ran".
        _LOGGER.info(
            "guardian check: title=%s stored_address=%s mac=%s dahua_entry=%s",
            self.entry.title,
            current_ip,
            data.get(CONF_MAC),
            dahua_entry_id,
        )
        if not dahua_entry_id or not current_ip:
            return

        found_ip = await self._locate_ip()
        _LOGGER.info(
            "guardian check: located=%s (stored %s)", found_ip, current_ip
        )
        if found_ip is None:
            decision = self.tracker.not_found()
            if decision.action == "notify":
                await self._notify(
                    "LIXIL camera not found",
                    f"「{self.entry.title}」could not be located on the "
                    "network after several checks. It may be offline or "
                    "on a different subnet.",
                )
            return

        decision = self.tracker.found(current_ip, found_ip)
        if decision.action != "update" or not decision.new_ip:
            return

        # Heal: update the ha-dahua entry address, then reload it.
        dahua_entry = self.hass.config_entries.async_get_entry(dahua_entry_id)
        if dahua_entry is None:
            _LOGGER.warning("guardian: dahua entry %s gone", dahua_entry_id)
            return
        new_data = {**dahua_entry.data, CONF_ADDRESS: decision.new_ip}
        changed = self.hass.config_entries.async_update_entry(
            dahua_entry, data=new_data
        )
        if changed:
            await self.hass.config_entries.async_reload(dahua_entry_id)
        # Mirror the new address into our own entry.
        self.hass.config_entries.async_update_entry(
            self.entry, data={**data, CONF_ADDRESS: decision.new_ip}
        )
        _LOGGER.info(
            "guardian: %s address %s -> %s (entry reloaded)",
            self.entry.title,
            current_ip,
            decision.new_ip,
        )

        # Verify recovery: the entry's camera should leave 'unavailable'.
        registry = er.async_get(self.hass)
        cams = [
            e.entity_id
            for e in er.async_entries_for_config_entry(registry, dahua_entry_id)
            if e.domain == "camera"
        ]
        recovered = False
        for _ in range(6):
            await asyncio.sleep(5)
            if cams:
                state = self.hass.states.get(cams[0])
                if state is not None and state.state not in (
                    "unavailable",
                    "unknown",
                ):
                    recovered = True
                    break
        if not recovered:
            await self._notify(
                "LIXIL camera address updated",
                f"「{self.entry.title}」moved to {decision.new_ip} and its "
                "ha-dahua entry was updated, but the camera has not "
                "recovered yet. Please check it in Home Assistant.",
            )

    async def _notify(self, title: str, message: str) -> None:
        await self.hass.services.async_call(
            "persistent_notification",
            "create",
            {"title": title, "message": message},
            blocking=False,
        )
