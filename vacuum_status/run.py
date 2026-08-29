#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["requests", "paho-mqtt", "pycryptodome"]
# ///

"""Report the current state of the Dreame vacuum in one cloud round trip."""

import datetime
import json
import pathlib
import sys

# The shared root module owns config loading, login, the session cache and the
# MIoT plumbing, so every tool in this plugin talks to the cloud the same way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import _dreame

# Fetched as one batch, in one round trip. SELF_WASH_BASE_STATUS and
# DUST_COLLECTION are presence probes for mop-pad-lifting detection, which
# decides how the packed cleaning-mode property is decoded; they are never
# reported. STATUS backs up TASK_STATUS when that single read fails.
PROPERTY_NAMES = (
    "STATE",
    "ERROR",
    "BATTERY_LEVEL",
    "CHARGING_STATUS",
    "STATUS",
    "TASK_STATUS",
    "CLEANING_TIME",
    "CLEANED_AREA",
    "SUCTION_LEVEL",
    "WATER_TANK",
    "CLEANING_MODE",
    "CLEANING_PROGRESS",
    "SELF_WASH_BASE_STATUS",
    "DUST_COLLECTION",
)

# Statuses that mean a cleaning job exists, used only when TASK_STATUS is
# unreadable. Returning to the dock is not a job, so it is deliberately absent.
ACTIVE_STATUS_NAMES = (
    "PAUSED",
    "CLEANING",
    "PARTIAL_CLEANING",
    "SEGMENT_CLEANING",
    "ZONE_CLEANING",
    "SPOT_CLEANING",
    "FAST_MAPPING",
)

OFFLINE_NOTE = (
    "The Dreame cloud reports this vacuum as offline, so these readings are cached from "
    "the last time it was in contact and are not live. Commands are relayed through the "
    "cloud, so nothing can be delivered until the robot reconnects to WiFi."
)


def last_contact(record):
    """Format the record's last-contact stamp, or None when it has none."""
    raw = record.get("updateTime")
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        if not text.isdigit():
            return text
        raw = int(text)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None

    # The cloud reports epoch milliseconds; a seconds value would land in 1970.
    seconds = raw / 1000 if raw > 1e11 else raw
    try:
        stamp = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None
    return stamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def job_in_progress(task_status, status, types):
    """True when a cleaning job exists, so its partial totals are meaningful."""
    if task_status is not None:
        return task_status not in (
            types.DreameVacuumTaskStatus.COMPLETED,
            types.DreameVacuumTaskStatus.UNKNOWN,
        )
    if status is None:
        return False
    return status in tuple(types.DreameVacuumStatus[name] for name in ACTIVE_STATUS_NAMES)


def main() -> None:
    """Read the vacuum's state and print it as one JSON object."""
    # This tool takes no parameters. Drain stdin so the runner's write always
    # completes, and ignore whatever it contains.
    sys.stdin.read()

    limit = _dreame.deadline()
    types = _dreame.types
    enum = _dreame.DreameVacuumProperty
    mapping = _dreame.DreameVacuumPropertyMapping

    # refresh_identity re-reads the device list, which is what makes the
    # cloud's own reachability flag available and keeps the identity cache
    # warm for the action tools.
    cloud, record = _dreame.connect(limit, refresh_identity=True)
    record = record if isinstance(record, dict) else {}

    properties = _dreame.get_props(
        cloud, [mapping[enum[name]] for name in PROPERTY_NAMES], limit
    )

    def value(name):
        return _dreame.read_property(properties, mapping[enum[name]])

    def whole_number(name):
        return _dreame.read_whole_number(properties, mapping[enum[name]])

    result = {}
    name = _dreame._device_name(record, None)
    if name is not None:
        result["name"] = name
    model = record.get("model")
    if isinstance(model, str) and model.strip():
        result["model"] = model.strip()

    online = record.get("online") is not False
    result["online"] = online

    # A property the cloud refused cannot be decoded into a name, and a raw
    # placeholder would be worse than its absence, so such fields are omitted.
    state = value("STATE")
    if state is not None:
        result["state"] = _dreame.decode(types.DreameVacuumState, state)

    battery = whole_number("BATTERY_LEVEL")
    if battery is not None:
        result["battery_percent"] = battery

    charging_status = value("CHARGING_STATUS")
    if charging_status is not None:
        result["charging_status"] = _dreame.decode(
            types.DreameVacuumChargingStatus, charging_status
        )

    water_tank = value("WATER_TANK")
    if water_tank is not None:
        result["water_tank"] = _dreame.decode(types.DreameVacuumWaterTank, water_tank)

    # Both lifting probes have to have been answered, whatever they answered:
    # without them the packed value could mean sweep or sweep_and_mop with no
    # way to tell, and a swapped mode is worse than a missing field.
    cleaning_mode = whole_number("CLEANING_MODE")
    if cleaning_mode is not None and _dreame.lifting_probes_present(properties):
        result["cleaning_mode"] = _dreame.decode_cleaning_mode(
            cleaning_mode, _dreame.detect_mop_pad_lifting(properties)
        )

    suction_level = value("SUCTION_LEVEL")
    if suction_level is not None:
        result["suction_level"] = _dreame.decode(
            types.DreameVacuumSuctionLevel, suction_level
        )

    error = value("ERROR")
    if error is not None and error != types.DreameVacuumErrorCode.NO_ERROR:
        result["error"] = _dreame.decode(types.DreameVacuumErrorCode, error)

    # Elapsed time, area and progress only mean something while a job is on.
    if job_in_progress(value("TASK_STATUS"), value("STATUS"), types):
        cleaning_time = whole_number("CLEANING_TIME")
        if cleaning_time is not None:
            result["cleaning_time_minutes"] = cleaning_time
        cleaned_area = whole_number("CLEANED_AREA")
        if cleaned_area is not None:
            result["cleaned_area_sqm"] = cleaned_area
        progress = whole_number("CLEANING_PROGRESS")
        if progress is not None:
            result["cleaning_progress_percent"] = progress

    if not online:
        result["note"] = OFFLINE_NOTE
        stamp = last_contact(record)
        if stamp is not None:
            result["last_contact"] = stamp

    json.dump(result, sys.stdout)


if __name__ == "__main__":
    _dreame.main_guard(main)
