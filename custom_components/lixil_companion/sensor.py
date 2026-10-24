"""Diagnostic sensors that make the IP guardian visible.

The guardian's whole value used to live in the log file.  These entities
surface it on the camera's device page instead: where the camera is now,
when the guardian last checked, and how many IP changes it has repaired.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_ADDRESS, CONF_SERIAL, DOMAIN


def _guardian(hass: HomeAssistant, entry: ConfigEntry):
    return hass.data.get(DOMAIN, {}).get(entry.entry_id)


def _device_info(entry: ConfigEntry) -> DeviceInfo:
    data = entry.data
    return DeviceInfo(
        identifiers={(DOMAIN, data.get(CONF_SERIAL) or entry.entry_id)},
        name=entry.title,
        manufacturer="LIXIL",
        model=data.get("device_type") or "Dahua OEM camera",
        serial_number=data.get(CONF_SERIAL),
        configuration_url=f"http://{data.get(CONF_ADDRESS)}"
        if data.get(CONF_ADDRESS)
        else None,
    )


class _GuardianSensor(SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, kind: str) -> None:
        self._hass = hass
        self._entry = entry
        self._kind = kind
        self._attr_unique_id = f"{entry.entry_id}:{kind}"
        self._attr_device_info = _device_info(entry)
        self._attr_translation_key = kind

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        guardian = _guardian(self._hass, self._entry)
        if guardian is not None:
            guardian.add_listener(self.async_write_ha_state)
            self.async_on_remove(
                lambda: guardian.remove_listener(self.async_write_ha_state)
            )

    @property
    def _status(self) -> dict[str, Any]:
        guardian = _guardian(self._hass, self._entry)
        return guardian.status if guardian is not None else {}

    @property
    def available(self) -> bool:
        return _guardian(self._hass, self._entry) is not None


class CurrentIpSensor(_GuardianSensor):
    _attr_icon = "mdi:ip-network"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(hass, entry, "current_ip")

    @property
    def native_value(self) -> str | None:
        return self._status.get("last_found_ip") or self._entry.data.get(
            CONF_ADDRESS
        )


class LastCheckSensor(_GuardianSensor):
    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(hass, entry, "last_check")

    @property
    def native_value(self) -> datetime | None:
        raw = self._status.get("last_check")
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None


class DriftCountSensor(_GuardianSensor):
    _attr_icon = "mdi:bandage"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(hass, entry, "drift_count")

    @property
    def native_value(self) -> int:
        return int(self._status.get("drift_events") or 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        drift = self._status.get("last_drift") or {}
        if not drift:
            return {}
        return {
            "last_from": drift.get("from"),
            "last_to": drift.get("to"),
            "last_at": drift.get("at"),
        }


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    async_add_entities(
        [
            CurrentIpSensor(hass, entry),
            LastCheckSensor(hass, entry),
            DriftCountSensor(hass, entry),
        ]
    )
