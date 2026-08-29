#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["requests", "paho-mqtt", "pycryptodome"]
# ///

"""Ask the Dreame vacuum to start or resume cleaning."""

import json
import pathlib
import sys

# The shared root module owns config loading, login, the session cache and the
# MIoT plumbing, so every tool in this plugin talks to the cloud the same way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import _dreame

# Deliberately no cleaning-mode parameter. Setting the mode means reading the
# packed 4/23 property before rewriting it, so mode plus start would be four
# round trips, which does not fit the 30-second tool budget. Mode belongs to
# set_cleaning_mode; do not merge the two tools.
NOTE = (
    "The Dreame cloud accepted the start command. The robot acts on it a moment later and "
    "may take a few seconds to leave the dock, so this is not confirmation that it is "
    "already cleaning. Run vacuum_status to see what it is actually doing."
)


def main() -> None:
    """Run the START action and print one JSON object."""
    # This tool takes no parameters. Drain stdin so the runner's write always
    # completes, and ignore whatever it contains.
    sys.stdin.read()

    limit = _dreame.deadline()

    # refresh_identity left False: the cached device identity is enough to
    # address the robot, which keeps this to login plus the action.
    cloud, _ = _dreame.connect(limit)
    _dreame.run_action(
        cloud, _dreame.DreameVacuumActionMapping[_dreame.DreameVacuumAction.START], limit
    )

    json.dump({"requested": "start cleaning", "accepted": True, "note": NOTE}, sys.stdout)


if __name__ == "__main__":
    _dreame.main_guard(main)
