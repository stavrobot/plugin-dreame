#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["requests", "paho-mqtt", "pycryptodome"]
# ///

"""Ask the Dreame vacuum to announce where it is."""

import json
import pathlib
import sys

# The shared root module owns config loading, login, the session cache and the
# MIoT plumbing, so every tool in this plugin talks to the cloud the same way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import _dreame

NOTE = (
    "The Dreame cloud accepted the locate command. The robot should speak up shortly; a moment "
    "of silence does not yet mean it failed, and nothing here proves the sound was played. If "
    "the robot stays silent, run vacuum_status to check whether it is online at all."
)


def main() -> None:
    """Run the LOCATE action and print one JSON object."""
    # This tool takes no parameters. Drain stdin so the runner's write always
    # completes, and ignore whatever it contains.
    sys.stdin.read()

    limit = _dreame.deadline()

    # refresh_identity left False: the cached device identity is enough to
    # address the robot, which keeps this to login plus the action.
    cloud, _ = _dreame.connect(limit)

    # LOCATE (7/1) makes the robot announce its own position. PLAY_SOUND (7/2)
    # is the generic sound-test action and is not what this tool is for.
    _dreame.run_action(
        cloud, _dreame.DreameVacuumActionMapping[_dreame.DreameVacuumAction.LOCATE], limit
    )

    json.dump({"requested": "locate vacuum", "accepted": True, "note": NOTE}, sys.stdout)


if __name__ == "__main__":
    _dreame.main_guard(main)
