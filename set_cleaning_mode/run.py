#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["requests", "paho-mqtt", "pycryptodome"]
# ///

"""Change the Dreame vacuum's cleaning mode without starting a clean."""

import json
import pathlib
import sys

# The shared root module owns config loading, login, the session cache and the
# MIoT plumbing, so every tool in this plugin talks to the cloud the same way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import _dreame

# Fetched as one batch, in one round trip. CLEANING_MODE carries the packed
# value this tool rewrites, and it must be read first: bits 8-15 hold the
# self-clean value and bits 16-17 the water level, so a blind write of a bare
# mode number would wipe them. SELF_WASH_BASE_STATUS and DUST_COLLECTION are
# presence probes for mop-pad-lifting detection, which decides whether the
# sweep and sweep-and-mop wire values are swapped.
PROPERTY_NAMES = ("CLEANING_MODE", "SELF_WASH_BASE_STATUS", "DUST_COLLECTION")

MODE_NAMES_MESSAGE = "Choose one of: sweep, mop, sweep_and_mop, mop_after_sweep."

CHANGED_NOTE = (
    "This changed the cleaning mode setting only; the vacuum was not sent out to clean. "
    "Use start_cleaning to begin a job with this mode."
)

# Only bits 0-1 can differ, so an equal packed value means the robot is already
# in the requested mode. Saying "set" would imply a change that did not happen.
UNCHANGED_NOTE = (
    "The vacuum was already in this mode, so nothing was changed. The mode setting is all "
    "this tool touches; use start_cleaning to begin a job with it."
)

UNREADABLE_MODE_MESSAGE = (
    "The Dreame cloud could not read the vacuum's current cleaning mode. Setting a new mode "
    "without it would wipe the water level and self-clean settings, so nothing was changed. "
    "Try again shortly."
)


def requested_mode():
    """Return the mode parameter from stdin, failing cleanly if it is unusable."""
    try:
        parameters = json.load(sys.stdin)
    except (UnicodeDecodeError, ValueError):
        raise _dreame.ToolError("This tool expects a JSON object on stdin.") from None
    if not isinstance(parameters, dict):
        raise _dreame.ToolError("This tool expects a JSON object on stdin.")

    mode = parameters.get("mode")
    if not isinstance(mode, str) or not mode.strip():
        raise _dreame.ToolError(f"A cleaning mode is required. {MODE_NAMES_MESSAGE}")
    return mode.strip().lower()


def main() -> None:
    """Set the cleaning mode in one login, one read and at most one write."""
    mode = requested_mode()

    # Reject an unknown mode before spending a login on it. encode_cleaning_mode
    # owns both the mode table and this message, so probe it with a throwaway
    # packed value rather than keeping a second copy of either here.
    _dreame.encode_cleaning_mode(0, mode, False)

    limit = _dreame.deadline()
    enum = _dreame.DreameVacuumProperty
    mapping = _dreame.DreameVacuumPropertyMapping
    cleaning_mode = mapping[enum.CLEANING_MODE]

    # The identity cache is warm from vacuum_status, and rewriting one property
    # needs no device list, so this login stays a single round trip.
    cloud, _ = _dreame.connect(limit)

    properties = _dreame.get_props(
        cloud, [mapping[enum[name]] for name in PROPERTY_NAMES], limit
    )

    packed = _dreame.read_whole_number(properties, cleaning_mode)
    if packed is None:
        raise _dreame.ToolError(UNREADABLE_MODE_MESSAGE)

    # Both lifting probes have to have been answered, whatever they answered:
    # with one absent, sweep and sweep_and_mop cannot be told apart on the
    # wire, so writing either of them would be a coin toss on the robot.
    if not _dreame.lifting_probes_present(properties):
        raise _dreame.ToolError(UNREADABLE_MODE_MESSAGE)

    lifting = _dreame.detect_mop_pad_lifting(properties)
    new_packed = _dreame.encode_cleaning_mode(packed, mode, lifting)

    # An identical value would be a provable no-op on the robot, so that write
    # is skipped rather than spent: it is the third of three round trips.
    changed = new_packed != packed
    if changed:
        _dreame.set_prop(cloud, cleaning_mode, new_packed, limit)

    json.dump(
        {
            "mode": mode,
            "changed": changed,
            "note": CHANGED_NOTE if changed else UNCHANGED_NOTE,
        },
        sys.stdout,
    )


if __name__ == "__main__":
    _dreame.main_guard(main)
