"""A 'rescan now' button that runs the guardian check on demand."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .sensor import _device_info, _guardian


class RescanButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_icon = "mdi:radar"
    _attr_translation_key = "rescan"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self._hass = hass
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}:rescan"
        self._attr_device_info = _device_info(entry)

    @property
    def available(self) -> bool:
        return _guardian(self._hass, self._entry) is not None

    async def async_press(self) -> None:
        guardian = _guardian(self._hass, self._entry)
        if guardian is not None:
            await guardian.async_check_now()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    async_add_entities([RescanButton(hass, entry)])
