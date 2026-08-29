#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["requests", "paho-mqtt", "pycryptodome"]
# ///

"""Ask the Dreame vacuum to return to its dock and charge."""

import json
import pathlib
import sys

# The shared root module owns config loading, login, the session cache and the
# MIoT plumbing, so every tool in this plugin talks to the cloud the same way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import _dreame

NOTE = (
    "The Dreame cloud accepted the return-to-dock command. The robot then drives home on its "
    "own, which takes as long as the trip takes, so this is not confirmation that it has "
    "arrived or is charging. Run vacuum_status to see where it is."
)


def main() -> None:
    """Run the CHARGE action and print one JSON object."""
    # This tool takes no parameters. Drain stdin so the runner's write always
    # completes, and ignore whatever it contains.
    sys.stdin.read()

    limit = _dreame.deadline()

    # refresh_identity left False: the cached device identity is enough to
    # address the robot, which keeps this to login plus the action.
    cloud, _ = _dreame.connect(limit)
    _dreame.run_action(
        cloud, _dreame.DreameVacuumActionMapping[_dreame.DreameVacuumAction.CHARGE], limit
    )

    json.dump({"requested": "return to dock", "accepted": True, "note": NOTE}, sys.stdout)


if __name__ == "__main__":
    _dreame.main_guard(main)
