"""LIXIL Companion integration.

A thin companion for ha-dahua: it discovers LIXIL (Dahua OEM) cameras on
the LAN, walks the user through adding them via the ha-dahua config flow
(QR-code paste fills the password), and then watches for IP changes so
the ha-dahua entry can be updated and reloaded automatically.

See SPEC.md in the repository root for the full design.
"""

from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .guardian import IpGuardian

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up a managed camera entry and start its IP guardian."""
    guardian = IpGuardian(hass, entry)
    await guardian.async_start()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = guardian
    entry.async_on_unload(guardian.async_stop)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a managed camera entry (guardian stops via on_unload)."""
    hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    return True
