# plugin-dreame

Control a Dreame robot vacuum through the Dreame cloud.

## Tools

- **vacuum_status** — Show the vacuum's current status.
- **start_cleaning** — Start a cleaning run of the whole house.
- **list_rooms** — List the rooms on the vacuum's saved map, with their IDs.
- **clean_rooms** — Start a cleaning run of chosen rooms.
- **pause_cleaning** — Pause the current cleaning run.
- **return_to_dock** — Send the vacuum back to its charging dock.
- **locate_vacuum** — Make the vacuum announce its location.
- **set_cleaning_mode** — Change the vacuum's cleaning mode. Turns CleanGenius off.

## Cleaning chosen rooms

"Mop the kitchen" takes three tools: `list_rooms` to find the kitchen's ID, `set_cleaning_mode` to choose mopping, and `clean_rooms` with that ID. A room clean uses the mode, suction and water settings the vacuum has at that moment.

CleanGenius is the vacuum's automatic mode. While it is on, the vacuum picks the cleaning mode itself and ignores the one you set. `set_cleaning_mode` therefore turns CleanGenius off, and says so when it does. It stays off until you turn it back on in the app. `clean_rooms` never changes it: without a `set_cleaning_mode` call first, a room clean with CleanGenius on is a CleanGenius clean of those rooms, and the tool's output says so.

## Installation

Tell Stavrobot to install `https://github.com/stavrobot/plugin-dreame`.

## Configuration

Fill in `username` and `password`; set `account_type` to the app you registered the vacuum in and `country` to the region the ACCOUNT was created in, not where you live. A wrong region looks like a wrong password, or gives an empty device list.

- **account_type** — Which phone app your vacuum is registered in: `dreame`, `mova`, or `trouver`. Region support differs by brand: dreame supports eu, us, cn, sg, ru, kr; mova supports eu, us, cn, sg; trouver supports eu, us, ru, sg.
- **username** — The email address you log into that app with.
- **password** — The password for that account.
- **country** — The region your account was created in: eu, us, cn, sg, ru, or kr.

Press a button on the robot to wake it before the first command. A sleeping vacuum drops its WiFi link and the cloud then rejects commands with error 80001.

The plugin handles one vacuum per account. Setup runs in the background for up to a minute after install. Tools report that setup is still running until it finishes.

## Attribution

The cloud protocol code is downloaded at install time from <https://github.com/Tasshack/dreame-vacuum> (MIT, Copyright (c) 2022 Tasshack), pinned to the commit in `UPSTREAM_SHA` in `init.py`. This plugin does not vendor or redistribute that code. The one exception is `MAP_AES_IVS` in `_dreame.py`: 13 short constants copied from upstream `const.py` at the same commit, which are needed to decrypt map files.

The pin also freezes Dreame API endpoint constants, so if login starts failing across the board the fix is to bump `UPSTREAM_SHA` in `init.py`, which is the only place the commit is recorded.

## Limitations

- One vacuum per account.
- No zone cleaning, map images, or schedules.
- Rooms come from the map the vacuum is currently on. Other floors' maps are not listed.
- `clean_rooms` does not check room IDs against the map, and takes no per-room suction, water or repeat settings.
- Encrypted map files are decrypted with constants copied from upstream. A model newer than the pinned commit may need a constant this plugin does not have; `list_rooms` then reports that no usable map was returned.
- Cloud-only: the robot must be awake and online.
- Cleaning-mode detection assumes a self-wash plus auto-empty base; on other mop-lifting models `sweep` and `sweep_and_mop` may be exchanged, both when set and when reported.
