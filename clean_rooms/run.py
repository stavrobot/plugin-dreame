#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["requests", "paho-mqtt", "pycryptodome"]
# ///

"""Start a cleaning job for one or more rooms on the Dreame vacuum's saved map."""

import json
import pathlib
import sys

# The shared root module owns config loading, login, the session cache and the
# MIoT plumbing, so every tool in this plugin talks to the cloud the same way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import _dreame

# Same shape as start_cleaning's note: the cloud accepting the action is not
# proof that the robot has started, because it acts on commands a moment later.
NOTE = (
    "The Dreame cloud accepted the room cleaning command. The robot acts on it a moment later "
    "and may take a few seconds to leave the dock, so this is not confirmation that it is "
    "already cleaning. Run vacuum_status to see what it is actually doing."
)

# CleanGenius overrides the manual cleaning mode, so a room clean started while
# it is on uses the robot's own choice of mode. The tool never changes it.
CLEAN_GENIUS_NOTE = (
    " CleanGenius is on, so the robot will choose its own cleaning mode for these rooms "
    "instead of using the current mode setting. Run set_cleaning_mode first to force a "
    "specific mode."
)

UNREADABLE_SETTINGS_MESSAGE = (
    "The Dreame cloud could not read the vacuum's suction level or water volume. Cleaning "
    "without them would mean guessing settings, so nothing was sent. Try again shortly."
)

# One batch, in one round trip. The cleaning mode is deliberately absent: the
# robot uses its current mode, and forcing one would need a separate mode write
# before the action, which adds a fourth cloud call and does not fit the budget.
PROPERTY_NAMES = (
    "SUCTION_LEVEL",
    "WATER_VOLUME",
    "CUSTOMIZED_CLEANING",
    "AUTO_SWITCH_SETTINGS",
)


def requested_rooms():
    """Return the validated room IDs from stdin, failing before any cloud call."""
    try:
        parameters = json.load(sys.stdin)
    except (UnicodeDecodeError, ValueError):
        raise _dreame.ToolError("This tool expects a JSON object on stdin.") from None
    return _dreame.parse_room_ids(parameters)


def main() -> None:
    """Read the current settings, then start a room clean in three cloud calls."""
    room_ids = requested_rooms()

    limit = _dreame.deadline()
    enum = _dreame.DreameVacuumProperty
    mapping = _dreame.DreameVacuumPropertyMapping

    # The identity cache is warm from list_rooms, and the action needs no
    # device list, so this stays login plus one read plus the action.
    cloud, _ = _dreame.connect(limit)

    properties = _dreame.get_props(
        cloud, [mapping[enum[name]] for name in PROPERTY_NAMES], limit
    )

    suction = _dreame.read_whole_number(properties, mapping[enum.SUCTION_LEVEL])
    water = _dreame.read_whole_number(properties, mapping[enum.WATER_VOLUME])
    if suction is None or water is None:
        raise _dreame.ToolError(UNREADABLE_SETTINGS_MESSAGE)

    # When customized cleaning is supported and readable, upstream uses order 1
    # for every room; any other value breaks newer models. On a robot without
    # it, the 1-based position is what the older firmware expects.
    customized = (
        _dreame.read_property(properties, mapping[enum.CUSTOMIZED_CLEANING])
        is not None
    )
    inputs = _dreame.clean_rooms_inputs(room_ids, suction, water, customized)

    _dreame.run_action(
        cloud,
        _dreame.DreameVacuumActionMapping[_dreame.DreameVacuumAction.START_CUSTOM],
        limit,
        inputs,
    )

    clean_genius = _dreame.clean_genius_on(
        _dreame.read_property(properties, mapping[enum.AUTO_SWITCH_SETTINGS])
    )
    json.dump(
        {
            "rooms": room_ids,
            "accepted": True,
            "note": NOTE + (CLEAN_GENIUS_NOTE if clean_genius else ""),
        },
        sys.stdout,
    )


if __name__ == "__main__":
    _dreame.main_guard(main)
