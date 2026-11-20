#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["requests", "paho-mqtt", "pycryptodome"]
# ///

"""List the rooms on the Dreame vacuum's saved map, with their IDs."""

import json
import pathlib
import sys

# The shared root module owns config loading, login, the session cache and the
# MIoT plumbing, so every tool in this plugin talks to the cloud the same way.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import _dreame


def main() -> None:
    """Fetch the saved map and print its rooms as one JSON object."""
    # This tool takes no parameters. Drain stdin so the runner's write always
    # completes, and ignore whatever it contains.
    sys.stdin.read()

    limit = _dreame.deadline()

    # refresh_identity left False: the cached device identity is enough to
    # address the robot, which keeps the map fetch to its minimum four calls.
    cloud, _ = _dreame.connect(limit)
    rooms = _dreame.fetch_rooms(cloud, limit)

    json.dump({"rooms": rooms}, sys.stdout)


if __name__ == "__main__":
    _dreame.main_guard(main)
