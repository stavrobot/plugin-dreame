#!/usr/bin/env -S uv run --script
# This dependency block must stay byte-identical to the one in every tool's
# run.py: running it here is what warms the uv cache the tools then reuse, so
# trimming it to what setup alone needs would move that download into a tool's
# 30-second window.
# /// script
# dependencies = ["requests", "paho-mqtt", "pycryptodome"]
# ///

"""Fetch the pinned Dreame cloud protocol used by this plugin."""

from __future__ import annotations

from pathlib import Path
import sys
import types

import requests


# Bumping this SHA is the fix when Dreame rotates API endpoints: protocol.py
# has those endpoint constants baked into it.
UPSTREAM_SHA = "3720223e11353aba622f8da34c9041586865aa48"
UPSTREAM_REPOSITORY = "https://github.com/Tasshack/dreame-vacuum"
UPSTREAM_BASE_URL = (
    "https://raw.githubusercontent.com/Tasshack/dreame-vacuum/"
    f"{UPSTREAM_SHA}/custom_components/dreame_vacuum/dreame"
)
UPSTREAM_FILES = ("protocol.py", "exceptions.py", "types.py")

ROOT = Path(__file__).resolve().parent
UPSTREAM_DIR = ROOT / "upstream"
PACKAGE_INIT = 'VERSION = "stavrobot-plugin-dreame"\n'
NOTICE = f"""Dreame vacuum upstream files

Source: {UPSTREAM_REPOSITORY}
Pinned commit: {UPSTREAM_SHA}

MIT License

Copyright (c) 2022 Tasshack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


def download_file(filename: str) -> bytes:
    """Return one pinned upstream source file, failing for any HTTP error."""
    response = requests.get(f"{UPSTREAM_BASE_URL}/{filename}", timeout=30)
    response.raise_for_status()
    return response.content


def install_miio_stub() -> None:
    """Provide the LAN-only python-miio base class required at import time."""
    # protocol.py imports MiIOProtocol at line 18 solely as the base class of
    # DreameVacuumDeviceProtocol at line 39. That local-LAN class is never used
    # here, so this stub avoids python-miio and its netifaces C build dependency.
    miioprotocol = types.ModuleType("miio.miioprotocol")

    class MiIOProtocol:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

    miioprotocol.MiIOProtocol = MiIOProtocol
    miio = types.ModuleType("miio")
    miio.__path__ = []
    miio.miioprotocol = miioprotocol
    sys.modules["miio"] = miio
    sys.modules["miio.miioprotocol"] = miioprotocol


def verify_imports() -> None:
    """Ensure the two upstream imports required by plugin tools are usable."""
    root = str(ROOT)
    if not sys.path or sys.path[0] != root:
        sys.path.insert(0, root)

    # Import through the package parent only. Never add upstream/ itself to
    # sys.path: its types.py would shadow stdlib types deep inside enum/typing.
    install_miio_stub()
    from upstream.protocol import DreameVacuumDreameHomeCloudProtocol
    from upstream.types import DreameVacuumPropertyMapping

    if DreameVacuumDreameHomeCloudProtocol is None or DreameVacuumPropertyMapping is None:
        raise ImportError("Pinned Dreame upstream symbols are unavailable")


def main() -> None:
    """Refresh the pinned upstream source and validate its imports."""
    UPSTREAM_DIR.mkdir(exist_ok=True)
    downloads = {filename: download_file(filename) for filename in UPSTREAM_FILES}

    # On an update, upstream/__init__.py already exists from last time, and a
    # tool importing mid-rewrite would otherwise see a half-written package as
    # a hard error. A torn rewrite must read as an unfinished setup instead, so
    # drop the file the tools test for; it is rewritten last, which keeps the
    # whole window looking incomplete.
    (UPSTREAM_DIR / "__init__.py").unlink(missing_ok=True)

    for filename, contents in downloads.items():
        (UPSTREAM_DIR / filename).write_bytes(contents)
    (UPSTREAM_DIR / "__init__.py").write_text(PACKAGE_INIT, encoding="utf-8")
    (UPSTREAM_DIR / "NOTICE").write_text(NOTICE, encoding="utf-8")

    verify_imports()

    sizes = ", ".join(f"{filename} ({len(contents)} bytes)" for filename, contents in downloads.items())
    print(f"Downloaded {sizes} from Dreame upstream at {UPSTREAM_SHA}.")
    print("Dreame cloud protocol setup succeeded.")


if __name__ == "__main__":
    main()
