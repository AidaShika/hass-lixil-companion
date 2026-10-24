"""Constants for the LIXIL Companion integration."""

DOMAIN = "lixil_companion"

# Config entry data keys (note: the security code / password is NEVER
# stored in the companion entry; it only transits the config flow and is
# handed to the ha-dahua flow, which owns credential storage).
CONF_ADDRESS = "address"
CONF_SERIAL = "serial"
CONF_PID = "pid"
CONF_MAC = "mac"
CONF_DAHUA_ENTRY_ID = "dahua_entry_id"

DEFAULT_DAHUA_USERNAME = "admin"
DEFAULT_DAHUA_CHANNEL = 0

# Models verified against real hardware (see SPEC / guide compat table).
VERIFIED_MODELS = {
    # PID -> human readable model name; filled as PID mapping is confirmed.
}

# How often the guardian re-checks device IPs (F3, SPEC).
GUARDIAN_SCAN_INTERVAL_MINUTES = 60
GUARDIAN_NOTIFY_AFTER_FAILURES = 3
