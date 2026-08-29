# plugin-dreame

Control a Dreame robot vacuum through the Dreame cloud.

## Tools

- **vacuum_status** — Show the vacuum's current status.
- **start_cleaning** — Start a cleaning run.
- **pause_cleaning** — Pause the current cleaning run.
- **return_to_dock** — Send the vacuum back to its charging dock.
- **locate_vacuum** — Make the vacuum announce its location.
- **set_cleaning_mode** — Change the vacuum's cleaning mode.

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

The cloud protocol code is downloaded at install time from <https://github.com/Tasshack/dreame-vacuum> (MIT, Copyright (c) 2022 Tasshack), pinned to the commit in `UPSTREAM_SHA` in `init.py`. This plugin does not vendor or redistribute it.

The pin also freezes Dreame API endpoint constants, so if login starts failing across the board the fix is to bump `UPSTREAM_SHA` in `init.py`, which is the only place the commit is recorded.

## Limitations

- One vacuum per account.
- No room or zone cleaning, map images, or schedules.
- Cloud-only: the robot must be awake and online.
- Cleaning-mode detection assumes a self-wash plus auto-empty base; on other mop-lifting models `sweep` and `sweep_and_mop` may be exchanged, both when set and when reported.
