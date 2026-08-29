#!/usr/bin/env -S uv run --script
# /// script
# dependencies = ["requests", "paho-mqtt", "pycryptodome"]
# ///
"""Offline checks for the pure logic in _dreame.py.

Nothing here talks to the Dreame cloud and nothing here needs credentials:
every check works on values the cloud would have returned. The two dangerous
side effects are guarded rather than trusted -- an audit hook makes any read of
the real ../config.json or the real $HOME session cache an immediate hard
failure, so a future edit cannot quietly start reading the owner's account.

Config tests run inside a temporary plugin tree because load_config() reads the
relative path ../config.json from a tool working directory. Session-cache tests
run under a temporary HOME because the cache location follows it.

Run with: uv run tests/test_pure_logic.py
"""
import json
import os
import pathlib
import stat
import sys
import tempfile
import time
from contextlib import contextmanager

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import _dreame
from _dreame import ToolError

FAILURES = []
CHECKS = 0


def check(name, cond, detail=""):
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"PASS: {name}")
    else:
        print(f"FAIL: {name} {detail}")
        FAILURES.append(name)


# ---------------------------------------------------------------------------
# Guard rail: the owner's real config.json holds live credentials and the real
# session cache holds a live auth key. Neither may be opened, not even
# read-only, so make the attempt crash instead of succeeding silently.
# ---------------------------------------------------------------------------
REAL_HOME = pathlib.Path.home()
REAL_CONFIG = os.path.realpath(ROOT.parent / "config.json")
REAL_CACHE_DIRECTORY = os.path.realpath(
    REAL_HOME.joinpath(*_dreame.CACHE_DIRECTORY)
) + os.sep


def _forbid_real_secrets(event, arguments):
    if event != "open":
        return
    target = arguments[0]
    if not isinstance(target, (str, bytes, os.PathLike)):
        return
    resolved = os.path.realpath(os.fsdecode(target))
    if resolved == REAL_CONFIG or resolved.startswith(REAL_CACHE_DIRECTORY):
        raise RuntimeError(f"a test tried to open the real {resolved}")


sys.addaudithook(_forbid_real_secrets)


@contextmanager
def temporary_home():
    """Point HOME at a scratch directory so the real session cache is untouched."""
    original_home = os.environ.get("HOME")
    with tempfile.TemporaryDirectory(prefix="dreame-home-") as home:
        os.environ["HOME"] = home
        try:
            yield pathlib.Path(home)
        finally:
            if original_home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = original_home


@contextmanager
def temporary_tool_directory(config_text):
    """Emulate a tool's cwd inside a scratch plugin tree holding config_text.

    config_text of None means the configuration file does not exist at all.
    """
    original_cwd = os.getcwd()
    with tempfile.TemporaryDirectory(prefix="dreame-plugin-") as plugin_root:
        tool_directory = pathlib.Path(plugin_root, "fake_tool")
        tool_directory.mkdir()
        if config_text is not None:
            pathlib.Path(plugin_root, "config.json").write_text(
                config_text, encoding="utf-8"
            )
        os.chdir(tool_directory)
        try:
            yield
        finally:
            os.chdir(original_cwd)


# Fake, obviously-invalid stand-ins. No real credential appears in this file
# and no check ever compares against one.
FAKE_USERNAME = "nobody@example.invalid"
FAKE_PASSWORD = "  not-a-real-password  "


KEEP_OUT = object()  # Sentinel meaning "omit this key entirely".


def config_text(**overrides):
    config = {"username": FAKE_USERNAME, "password": FAKE_PASSWORD}
    config.update(overrides)
    return json.dumps({key: value for key, value in config.items() if value is not KEEP_OUT})


def load_config_error(config_text_value):
    """Return the ToolError message load_config() raises, or None if it did not."""
    with temporary_tool_directory(config_text_value):
        try:
            _dreame.load_config()
        except ToolError as err:
            return str(err)
    return None


def load_config_result(config_text_value):
    with temporary_tool_directory(config_text_value):
        return _dreame.load_config()


# ---------------------------------------------------------------------------
# 1. Cleaning mode encode/decode.
#
# The packed 4/23 property carries unrelated fields in the upper bits. The
# probe value has recognisable upper bytes and non-zero bits 2-7 so that any
# mask that clears more than bits 0-1 shows up immediately.
# ---------------------------------------------------------------------------
PACKED = 0x2A1F5
MODES = ("sweep", "mop", "sweep_and_mop", "mop_after_sweep")
WIRE_WITHOUT_LIFTING = {"sweep": 0, "mop": 1, "sweep_and_mop": 2, "mop_after_sweep": 3}
WIRE_WITH_LIFTING = {"sweep": 2, "mop": 1, "sweep_and_mop": 0, "mop_after_sweep": 3}

for mode in MODES:
    encoded = _dreame.encode_cleaning_mode(PACKED, mode, False)
    check(
        f"1a: {mode} without lifting encodes to {WIRE_WITHOUT_LIFTING[mode]}",
        encoded & 0x03 == WIRE_WITHOUT_LIFTING[mode],
        detail=hex(encoded),
    )
    encoded_lifting = _dreame.encode_cleaning_mode(PACKED, mode, True)
    check(
        f"1b: {mode} with lifting encodes to {WIRE_WITH_LIFTING[mode]}",
        encoded_lifting & 0x03 == WIRE_WITH_LIFTING[mode],
        detail=hex(encoded_lifting),
    )

# The 0/2 swap is the whole point of the lifting flag: with a lifting mop pad
# the wire meanings of sweep and sweep-and-mop are exchanged. mop and
# mop-after-sweep are identical in both worlds.
check(
    "1c: lifting swaps only sweep and sweep_and_mop",
    _dreame.encode_cleaning_mode(PACKED, "sweep", True) & 0x03
    == _dreame.encode_cleaning_mode(PACKED, "sweep_and_mop", False) & 0x03
    and _dreame.encode_cleaning_mode(PACKED, "sweep_and_mop", True) & 0x03
    == _dreame.encode_cleaning_mode(PACKED, "sweep", False) & 0x03
    and _dreame.encode_cleaning_mode(PACKED, "mop", True) & 0x03
    == _dreame.encode_cleaning_mode(PACKED, "mop", False) & 0x03
    and _dreame.encode_cleaning_mode(PACKED, "mop_after_sweep", True) & 0x03
    == _dreame.encode_cleaning_mode(PACKED, "mop_after_sweep", False) & 0x03,
)

# Bit preservation. Upstream's combine_group_value/split_group_value pair
# rebuilds the word from (V & 0x30000) | (V & 0xFF00) | (V & 0x03) and so
# drops bits 2-7 and 18+. This plugin masks with ~0x03 on purpose. These
# checks exist so that "fixing" it back to upstream's masks fails loudly.
for lifting in (False, True):
    for mode in MODES:
        encoded = _dreame.encode_cleaning_mode(PACKED, mode, lifting)
        check(
            f"1d: bits 2-7 survive {mode} (lifting={lifting})",
            (encoded >> 2) & 0x3F == (PACKED >> 2) & 0x3F,
            detail=f"{hex(encoded)} from {hex(PACKED)}",
        )
        check(
            f"1e: bits 8-17 survive {mode} (lifting={lifting})",
            (encoded >> 8) & 0x3FF == (PACKED >> 8) & 0x3FF,
            detail=f"{hex(encoded)} from {hex(PACKED)}",
        )
        check(
            f"1f: everything but bits 0-1 survives {mode} (lifting={lifting})",
            encoded & ~0x03 == PACKED & ~0x03,
            detail=f"{hex(encoded)} from {hex(PACKED)}",
        )

# The ticket's own example value: recognisable upper bytes, zero low byte.
for lifting in (False, True):
    for mode in MODES:
        encoded = _dreame.encode_cleaning_mode(0x2A100, mode, lifting)
        check(
            f"1g: upper bytes of 0x2A100 survive {mode} (lifting={lifting})",
            encoded & ~0xFF == 0x2A100,
            detail=hex(encoded),
        )

# decode_cleaning_mode is the exact inverse for every mode and both flags.
for lifting in (False, True):
    for mode in MODES:
        encoded = _dreame.encode_cleaning_mode(PACKED, mode, lifting)
        decoded = _dreame.decode_cleaning_mode(encoded, lifting)
        check(
            f"1h: {mode} round-trips (lifting={lifting})",
            decoded == mode,
            detail=f"got {decoded!r} from {hex(encoded)}",
        )

# Decoding with the wrong flag must give the swapped answer, not the same one:
# proof that decode consults the flag rather than ignoring it.
check(
    "1i: decoding with the wrong lifting flag swaps sweep and sweep_and_mop",
    _dreame.decode_cleaning_mode(_dreame.encode_cleaning_mode(PACKED, "sweep", True), False)
    == "sweep_and_mop"
    and _dreame.decode_cleaning_mode(
        _dreame.encode_cleaning_mode(PACKED, "sweep_and_mop", True), False
    )
    == "sweep",
)

# Unknown mode names are a user error with a listing message, never a KeyError.
for bad_mode, label in ((" sweep", "leading space"), ("SWEEP", "wrong case"), ("scrub", "unknown name")):
    try:
        _dreame.encode_cleaning_mode(PACKED, bad_mode, False)
        check(f"1j: {label} is rejected", False)
    except ToolError as err:
        check(
            f"1j: {label} is rejected",
            "sweep_and_mop" in str(err),
            detail=str(err),
        )

try:
    _dreame.encode_cleaning_mode(PACKED, ["sweep"], False)
    check("1k: an unhashable mode is rejected as a ToolError", False)
except ToolError:
    check("1k: an unhashable mode is rejected as a ToolError", True)

# ---------------------------------------------------------------------------
# 2. detect_mop_pad_lifting: successful presence of both probes, nothing else.
# ---------------------------------------------------------------------------
SELF_WASH_KEY = (
    _dreame.DreameVacuumPropertyMapping[
        _dreame.DreameVacuumProperty.SELF_WASH_BASE_STATUS
    ]["siid"],
    _dreame.DreameVacuumPropertyMapping[
        _dreame.DreameVacuumProperty.SELF_WASH_BASE_STATUS
    ]["piid"],
)
DUST_KEY = (
    _dreame.DreameVacuumPropertyMapping[_dreame.DreameVacuumProperty.DUST_COLLECTION]["siid"],
    _dreame.DreameVacuumPropertyMapping[_dreame.DreameVacuumProperty.DUST_COLLECTION]["piid"],
)
NEVER = _dreame.types.DreameVacuumDustCollection.NEVER.value

check(
    "2a: the two probes have distinct addresses",
    SELF_WASH_KEY != DUST_KEY,
    detail=f"{SELF_WASH_KEY} vs {DUST_KEY}",
)

check(
    "2b: both probes successful means lifting",
    _dreame.detect_mop_pad_lifting(
        {SELF_WASH_KEY: {"code": 0, "value": 0}, DUST_KEY: {"code": 0, "value": 1}}
    ),
)

# The guard against copying upstream. Upstream clears its auto-empty flag when
# DUST_COLLECTION reads NEVER; that flag governs auto-empty features, not the
# cleaning-mode wire encoding. Adopting it here would silently exchange sweep
# and sweep-and-mop for every user who set auto-empty to Never.
check(
    "2c: DUST_COLLECTION reading NEVER still means lifting",
    _dreame.detect_mop_pad_lifting(
        {SELF_WASH_KEY: {"code": 0, "value": 0}, DUST_KEY: {"code": 0, "value": NEVER}}
    ),
    detail=f"NEVER={NEVER}",
)

check(
    "2d: a successful probe with a null value still counts as present",
    _dreame.detect_mop_pad_lifting(
        {SELF_WASH_KEY: {"code": 0, "value": None}, DUST_KEY: {"code": 0, "value": None}}
    ),
)

check(
    "2e: unrelated properties do not affect the answer",
    _dreame.detect_mop_pad_lifting(
        {
            SELF_WASH_KEY: {"code": 0, "value": 0},
            DUST_KEY: {"code": 0, "value": 1},
            (2, 1): {"code": 0, "value": 99},
        }
    ),
)

check("2f: no probes at all is not lifting", not _dreame.detect_mop_pad_lifting({}))
check(
    "2g: a missing self-wash probe is not lifting",
    not _dreame.detect_mop_pad_lifting({DUST_KEY: {"code": 0, "value": 1}}),
)
check(
    "2h: a missing dust-collection probe is not lifting",
    not _dreame.detect_mop_pad_lifting({SELF_WASH_KEY: {"code": 0, "value": 0}}),
)
check(
    "2i: an unsupported self-wash probe is not lifting",
    not _dreame.detect_mop_pad_lifting(
        {SELF_WASH_KEY: {"code": -4004}, DUST_KEY: {"code": 0, "value": 1}}
    ),
)
check(
    "2j: an unsupported dust-collection probe is not lifting",
    not _dreame.detect_mop_pad_lifting(
        {SELF_WASH_KEY: {"code": 0, "value": 0}, DUST_KEY: {"code": -4004}}
    ),
)
check(
    "2k: a probe without a code is not lifting",
    not _dreame.detect_mop_pad_lifting(
        {SELF_WASH_KEY: {"value": 0}, DUST_KEY: {"code": 0, "value": 1}}
    ),
)
check(
    "2l: a non-mapping probe entry is not lifting",
    not _dreame.detect_mop_pad_lifting(
        {SELF_WASH_KEY: [0], DUST_KEY: {"code": 0, "value": 1}}
    ),
)
check(
    "2m: a probe present as None is not lifting",
    not _dreame.detect_mop_pad_lifting(
        {SELF_WASH_KEY: None, DUST_KEY: {"code": 0, "value": 1}}
    ),
)

# The detection feeds the encoder, so pin the end-to-end consequence too.
LIFTING_PROPS = {SELF_WASH_KEY: {"code": 0, "value": 0}, DUST_KEY: {"code": 0, "value": NEVER}}
check(
    "2n: NEVER-plus-lifting still encodes sweep as 2",
    _dreame.encode_cleaning_mode(
        PACKED, "sweep", _dreame.detect_mop_pad_lifting(LIFTING_PROPS)
    )
    & 0x03
    == 2,
)

# ---------------------------------------------------------------------------
# 3. Config validation. Every rejection is a ToolError with a message safe to
#    print, and no message may echo a configuration value back to the user.
# ---------------------------------------------------------------------------
message = load_config_error(None)
check("3a: a missing config.json is a ToolError", message is not None, detail=repr(message))
check("3b: the missing message names the file", message and "config.json is missing" in message, detail=repr(message))

message = load_config_error('{"username": "a", "password":')
check(
    "3c: an unparseable config.json is a ToolError",
    message is not None and "could not be read" in message,
    detail=repr(message),
)

message = load_config_error("not json at all")
check(
    "3d: a non-JSON config.json is a ToolError",
    message is not None and "could not be read" in message,
    detail=repr(message),
)

message = load_config_error('["username", "password"]')
check(
    "3e: a non-object config.json is a ToolError",
    message is not None and "must contain a JSON object" in message,
    detail=repr(message),
)

REJECTED_CONFIGS = (
    ("3f: an empty username", config_text(username=""), "username is missing"),
    ("3g: a whitespace-only username", config_text(username="   "), "username is missing"),
    ("3h: an absent username", config_text(username=KEEP_OUT), "username is missing"),
    ("3i: a non-string username", json.dumps({"username": 42, "password": FAKE_PASSWORD}), "username is missing"),
    ("3j: an empty password", config_text(password=""), "password is missing"),
    ("3k: a whitespace-only password", config_text(password="  \t "), "password is missing"),
    ("3l: an absent password", config_text(password=KEEP_OUT), "password is missing"),
    ("3m: a non-string password", json.dumps({"username": FAKE_USERNAME, "password": 42}), "password is missing"),
    ("3n: an unknown account_type", config_text(account_type="roomba"), "account_type must be one of"),
    ("3o: kr is not a valid mova country", config_text(account_type="mova", country="kr"), "for a mova account"),
    ("3p: kr is not a valid trouver country", config_text(account_type="trouver", country="kr"), "for a trouver account"),
    ("3q: an unknown country", config_text(country="mars"), "for a dreame account"),
)

for label, text, expected in REJECTED_CONFIGS:
    message = load_config_error(text)
    check(f"{label} is rejected", message is not None and expected in message, detail=repr(message))
    # A configuration value must never travel into a message that is printed
    # to stderr; config.json holds the account password.
    check(
        f"{label} leaks nothing",
        message is not None
        and FAKE_USERNAME not in message
        and FAKE_PASSWORD.strip() not in message,
        detail=repr(message),
    )

config = load_config_result(config_text())
check(
    "3r: the defaults path accepts a bare username and password",
    config["account_type"] == "dreame" and config["country"] == "eu",
    detail=repr({key: config.get(key) for key in ("account_type", "country")}),
)
check(
    "3s: the password is preserved byte for byte",
    config["password"] == FAKE_PASSWORD,
)
config = load_config_result(config_text(username=f"  {FAKE_USERNAME}  "))
check("3t: the username is stripped", config["username"] == FAKE_USERNAME)

config = load_config_result(config_text(account_type="  DREAME  ", country="  KR  "))
check(
    "3u: account_type and country are normalised, and kr is valid for dreame",
    config["account_type"] == "dreame" and config["country"] == "kr",
    detail=repr({key: config.get(key) for key in ("account_type", "country")}),
)

config = load_config_result(config_text(account_type="mova", country="sg"))
check(
    "3v: sg is valid for mova",
    config["account_type"] == "mova" and config["country"] == "sg",
)

config = load_config_result(config_text(account_type=None, country=None))
check(
    "3w: explicit nulls fall back to the defaults",
    config["account_type"] == "dreame" and config["country"] == "eu",
)

# ---------------------------------------------------------------------------
# 4. decode(): stable lowercase names, and a fallback instead of an exception.
#    Upstream keeps adding state values, so an unknown number reaching a tool
#    must degrade to text rather than crash the command.
# ---------------------------------------------------------------------------
STATE = _dreame.types.DreameVacuumState


def decoded(enum_cls, value):
    """Decode, reporting an escaped exception as a value so the check fails."""
    try:
        return _dreame.decode(enum_cls, value)
    except Exception as err:  # noqa: BLE001 - decode() must never raise.
        return f"raised {type(err).__name__}"


check(
    "4a: a known value becomes a lowercase spaced name",
    decoded(STATE, STATE.CHARGING_COMPLETED.value) == "charging completed",
    detail=repr(decoded(STATE, STATE.CHARGING_COMPLETED.value)),
)
check(
    "4b: a single-word value decodes without change",
    decoded(STATE, STATE.CHARGING.value) == "charging",
    detail=repr(decoded(STATE, STATE.CHARGING.value)),
)
check(
    "4c: an enum member decodes like its value",
    decoded(STATE, STATE.MOPPING) == "mopping",
    detail=repr(decoded(STATE, STATE.MOPPING)),
)
check(
    "4d: another table decodes too",
    decoded(_dreame.types.DreameVacuumDustCollection, NEVER) == "never",
    detail=repr(decoded(_dreame.types.DreameVacuumDustCollection, NEVER)),
)

# Deliberately not asserting the full enum contents: upstream grows them. This
# only needs one integer that is genuinely absent right now.
ABSENT_VALUE = 424242
check(
    "4e: the probe value really is absent from the upstream table",
    ABSENT_VALUE not in {member.value for member in STATE},
)
check(
    "4f: an unknown value degrades to 'unknown (N)'",
    decoded(STATE, ABSENT_VALUE) == f"unknown ({ABSENT_VALUE})",
    detail=repr(decoded(STATE, ABSENT_VALUE)),
)
check(
    "4g: a missing property value degrades instead of raising",
    decoded(STATE, None) == "unknown (None)",
    detail=repr(decoded(STATE, None)),
)
check(
    "4h: a non-numeric value degrades instead of raising",
    decoded(STATE, "banana") == "unknown (banana)",
    detail=repr(decoded(STATE, "banana")),
)

# ---------------------------------------------------------------------------
# 5. Session cache round trip, under a temporary HOME throughout.
# ---------------------------------------------------------------------------
CACHE = {
    "auth_key": "fake-auth-key",
    "did": "1234567890",
    "host": "example.invalid",
    "model": "dreame.vacuum.fake",
    "name": "Test Vacuum",
}

with temporary_home() as home:
    cache_path = home.joinpath(*_dreame.CACHE_DIRECTORY, _dreame.CACHE_FILENAME)
    check(
        "5a: the cache path follows HOME",
        _dreame._session_cache_path() == cache_path,
        detail=str(_dreame._session_cache_path()),
    )
    check("5b: an absent cache reads as absent", _dreame._load_session_cache() is None)

    _dreame._write_session_cache(CACHE)
    check("5c: writing creates the cache file", cache_path.is_file())
    check(
        "5d: the cache file is mode 0600",
        stat.S_IMODE(cache_path.stat().st_mode) == 0o600,
        detail=oct(stat.S_IMODE(cache_path.stat().st_mode)),
    )
    check(
        "5e: the round trip returns the same fields",
        _dreame._load_session_cache() == CACHE,
        detail=repr(_dreame._load_session_cache()),
    )
    check(
        "5f: writing leaves no temporary files behind",
        sorted(entry.name for entry in cache_path.parent.iterdir())
        == [_dreame.CACHE_FILENAME],
        detail=repr(sorted(entry.name for entry in cache_path.parent.iterdir())),
    )

    # Only the fixed schema is persisted: a caller's extra keys are not.
    _dreame._write_session_cache(dict(CACHE, password="must-not-be-stored"))
    stored = json.loads(cache_path.read_text(encoding="utf-8"))
    check(
        "5g: only the fixed cache fields are written",
        sorted(stored) == sorted(_dreame.CACHE_FIELDS),
        detail=repr(sorted(stored)),
    )

    # A second write replaces the first and keeps the mode.
    _dreame._write_session_cache(dict(CACHE, name="Renamed"))
    check(
        "5h: rewriting replaces the cache and keeps mode 0600",
        _dreame._load_session_cache()["name"] == "Renamed"
        and stat.S_IMODE(cache_path.stat().st_mode) == 0o600,
    )

    _dreame._write_session_cache({field: None for field in _dreame.CACHE_FIELDS})
    check(
        "5i: null fields round-trip as nulls",
        _dreame._load_session_cache() == {field: None for field in _dreame.CACHE_FIELDS},
        detail=repr(_dreame._load_session_cache()),
    )

    # A damaged cache is equivalent to no cache: the tool must log in again
    # rather than fail.
    DAMAGED = (
        ("5j: a truncated file", '{"auth_key": "fake-auth-key", "did'),
        ("5k: an empty file", ""),
        ("5l: non-JSON contents", "not json at all"),
        ("5m: a JSON array", '["fake-auth-key"]'),
        ("5n: a JSON string", '"fake-auth-key"'),
        ("5o: a missing field", json.dumps({key: value for key, value in CACHE.items() if key != "name"})),
        ("5p: a non-string field", json.dumps(dict(CACHE, did=1234567890))),
    )
    for label, contents in DAMAGED:
        cache_path.write_text(contents, encoding="utf-8")
        loaded = _dreame._load_session_cache()
        check(f"{label} reads as absent", loaded is None, detail=repr(loaded))

    # Unknown extra keys in an otherwise valid file are ignored, not fatal:
    # an older or newer plugin version must not invalidate the session.
    cache_path.write_text(json.dumps(dict(CACHE, future_field="ignored")), encoding="utf-8")
    check(
        "5q: extra keys are ignored on read",
        _dreame._load_session_cache() == CACHE,
        detail=repr(_dreame._load_session_cache()),
    )

    # A cache directory that cannot be created must not abort a command.
    unusable_home = home / "unusable"
    unusable_home.write_text("", encoding="utf-8")
    os.environ["HOME"] = str(unusable_home)
    try:
        _dreame._write_session_cache(CACHE)
        check("5r: an unusable HOME does not break the write path", True)
    except Exception as err:  # noqa: BLE001 - the point is that nothing escapes.
        check("5r: an unusable HOME does not break the write path", False, detail=repr(err))
    check("5s: an unusable HOME reads as absent", _dreame._load_session_cache() is None)
    os.environ["HOME"] = str(home)

check(
    "5t: HOME is restored after the cache checks",
    pathlib.Path.home() == REAL_HOME,
    detail=str(pathlib.Path.home()),
)

# ---------------------------------------------------------------------------
# 6. get_props response pairing, against a stub cloud. This is the most
#    cloud-exposed logic in the plugin: every caller looks a property up by its
#    (siid, piid) address, and the cloud is free to answer in a different
#    order, to leave an entry out, or to stringify the numbers. Pairing by
#    position instead of by address would silently report one property's value
#    as another's, which no later check could catch.
# ---------------------------------------------------------------------------
PROPERTY_MAPPING = _dreame.DreameVacuumPropertyMapping
PROPERTY_ENUM = _dreame.DreameVacuumProperty
STATE_ADDRESS = PROPERTY_MAPPING[PROPERTY_ENUM.STATE]
BATTERY_ADDRESS = PROPERTY_MAPPING[PROPERTY_ENUM.BATTERY_LEVEL]
CHARGING_ADDRESS = PROPERTY_MAPPING[PROPERTY_ENUM.CHARGING_STATUS]
PROBE_ADDRESSES = (STATE_ADDRESS, BATTERY_ADDRESS, CHARGING_ADDRESS)
FAKE_DEVICE_ID = 987654321


class StubCloud:
    """Stand-in for the upstream cloud object: canned answer, recorded request."""

    def __init__(self, response):
        self.device_id = FAKE_DEVICE_ID
        self.response = response
        self.sent = []

    def send(self, method, parameters, retry_count=None, timeout=None):
        self.sent.append(
            {
                "method": method,
                "parameters": parameters,
                "retry_count": retry_count,
                "timeout": timeout,
            }
        )
        return self.response


def cloud_entry(address, value, code=0, stringify=False):
    """Build one property entry the way the Dreame cloud returns them."""
    siid, piid = address["siid"], address["piid"]
    if stringify:
        siid, piid = str(siid), str(piid)
    return {
        "did": str(FAKE_DEVICE_ID),
        "siid": siid,
        "piid": piid,
        "code": code,
        "value": value,
    }


def fetched(response, addresses=PROBE_ADDRESSES):
    """Return (properties, cloud) for a canned response, or the ToolError text."""
    cloud = StubCloud(response)
    try:
        return _dreame.get_props(cloud, list(addresses), _dreame.deadline()), cloud
    except ToolError as err:
        return str(err), cloud


def address_key(address):
    return address["siid"], address["piid"]


check(
    "6a: the three probe addresses are distinct",
    len({address_key(address) for address in PROBE_ADDRESSES}) == 3,
)

# The cloud answers in whatever order it likes. Reversed here so that any
# position-based pairing hands back the wrong property's value.
properties, cloud = fetched(
    [
        cloud_entry(CHARGING_ADDRESS, 1),
        cloud_entry(BATTERY_ADDRESS, 42),
        cloud_entry(STATE_ADDRESS, 2),
    ]
)
check(
    "6b: reversed entries still pair with their own addresses",
    _dreame.read_property(properties, STATE_ADDRESS) == 2
    and _dreame.read_whole_number(properties, BATTERY_ADDRESS) == 42
    and _dreame.read_property(properties, CHARGING_ADDRESS) == 1,
    detail=repr(properties),
)
check(
    "6c: the request addresses the device by did, siid and piid",
    len(cloud.sent) == 1
    and cloud.sent[0]["method"] == "get_properties"
    and cloud.sent[0]["retry_count"] == 0
    and cloud.sent[0]["parameters"]
    == [
        {"did": str(FAKE_DEVICE_ID), "siid": address["siid"], "piid": address["piid"]}
        for address in PROBE_ADDRESSES
    ],
    detail=repr(cloud.sent),
)

# An omitted entry must leave a hole, not shift the remaining values up.
properties, _ = fetched(
    [cloud_entry(STATE_ADDRESS, 2), cloud_entry(CHARGING_ADDRESS, 1)]
)
check(
    "6d: an omitted entry is absent rather than shifted",
    address_key(BATTERY_ADDRESS) not in properties
    and _dreame.read_whole_number(properties, BATTERY_ADDRESS) is None
    and _dreame.read_property(properties, STATE_ADDRESS) == 2
    and _dreame.read_property(properties, CHARGING_ADDRESS) == 1,
    detail=repr(properties),
)

# JSON numbers arrive as strings often enough that this must not be a hole.
properties, _ = fetched(
    [
        cloud_entry(STATE_ADDRESS, 2, stringify=True),
        cloud_entry(BATTERY_ADDRESS, 42, stringify=True),
        cloud_entry(CHARGING_ADDRESS, 1, stringify=True),
    ]
)
check(
    "6e: string siid and piid still match the int-keyed address",
    _dreame.read_property(properties, STATE_ADDRESS) == 2
    and _dreame.read_whole_number(properties, BATTERY_ADDRESS) == 42,
    detail=repr(properties),
)

# A per-property refusal is a readable answer, not a malformed response: the
# entry is kept and the read helpers report it as unreadable.
properties, _ = fetched(
    [
        cloud_entry(STATE_ADDRESS, None, code=-4004),
        cloud_entry(BATTERY_ADDRESS, 42),
        cloud_entry(CHARGING_ADDRESS, 1),
    ]
)
check(
    "6f: a per-property refusal reads as None without failing the batch",
    _dreame.read_property(properties, STATE_ADDRESS) is None
    and _dreame.read_whole_number(properties, BATTERY_ADDRESS) == 42,
    detail=repr(properties),
)

# Anything the pairing cannot key must become the stable ToolError, never a
# KeyError or a TypeError escaping into the tool's traceback.
MALFORMED_RESPONSES = (
    ("6g: a non-list response", {"code": 0, "value": 1}),
    ("6h: a string response", "unexpected"),
    ("6i: a non-mapping entry", [["siid", 4]]),
    ("6j: an entry with no piid", [{"siid": 4, "code": 0, "value": 1}]),
    ("6k: an entry with no siid", [{"piid": 23, "code": 0, "value": 1}]),
    ("6l: an entry with a non-numeric siid", [{"siid": "four", "piid": 23, "code": 0}]),
    ("6m: an entry with a null piid", [{"siid": 4, "piid": None, "code": 0}]),
)
for label, response in MALFORMED_RESPONSES:
    try:
        outcome, _ = fetched(response)
    except Exception as err:  # noqa: BLE001 - only ToolError may ever escape.
        outcome = f"raised {type(err).__name__}"
    check(
        f"{label} is a ToolError",
        isinstance(outcome, str) and "unexpected property response" in outcome,
        detail=repr(outcome),
    )

# ---------------------------------------------------------------------------
# 7. deadline() and timeout_remaining(): the whole safety net behind the
#    runner's hard 30-second kill. Every cloud call passes its timeout through
#    here, so the floor and the refusal are what stop a tool being killed
#    mid-request with nothing on stderr.
# ---------------------------------------------------------------------------
def remaining_or_error(limit):
    """Return the remaining seconds, or the ToolError message as a string."""
    try:
        return _dreame.timeout_remaining(limit)
    except ToolError as err:
        return str(err)


FLOOR = _dreame.MINIMUM_REQUEST_TIMEOUT_SECONDS

outcome = remaining_or_error(time.monotonic() + FLOOR - 0.5)
check(
    "7a: a limit already inside the 3s floor is a ToolError",
    isinstance(outcome, str) and "tool budget" in outcome,
    detail=repr(outcome),
)
outcome = remaining_or_error(time.monotonic() - 5)
check(
    "7b: a limit in the past is a ToolError",
    isinstance(outcome, str) and "tool budget" in outcome,
    detail=repr(outcome),
)
check(
    "7c: the budget message names the deadline and does not leak a path",
    isinstance(outcome, str)
    and f"{_dreame.TOOL_DEADLINE_SECONDS}-second" in outcome
    and "/" not in outcome,
    detail=repr(outcome),
)

outcome = remaining_or_error(time.monotonic() + FLOOR + 0.5)
check(
    "7d: a limit just above the floor returns the remaining seconds",
    isinstance(outcome, float) and FLOOR < outcome <= FLOOR + 0.5,
    detail=repr(outcome),
)

outcome = remaining_or_error(_dreame.deadline())
check(
    "7e: a comfortable limit returns nearly the whole budget",
    isinstance(outcome, float)
    and _dreame.TOOL_DEADLINE_SECONDS - 1 < outcome <= _dreame.TOOL_DEADLINE_SECONDS,
    detail=repr(outcome),
)

# The budget arithmetic itself. connect() only starts the refresh-token retry
# with a full login's worth of budget left, so the worst case is
# (TOOL_DEADLINE - WORST_CASE) spent before the gate plus WORST_CASE for the
# retry, i.e. TOOL_DEADLINE. That has to stay clear of the 30-second kill.
check(
    "7f: the login retry cannot push a tool past the 30-second kill",
    _dreame.UPSTREAM_LOGIN_WORST_CASE_SECONDS <= _dreame.TOOL_DEADLINE_SECONDS < 30,
    detail=f"{_dreame.UPSTREAM_LOGIN_WORST_CASE_SECONDS} then {_dreame.TOOL_DEADLINE_SECONDS}",
)

# ---------------------------------------------------------------------------
# 8. Refusal codes on writes and actions. A command the robot refused used to
#    be reported as done, which is the one failure mode a user cannot see. Only
#    an explicitly present, readable, non-zero code counts: an unrecognised
#    shape must stay non-fatal, because the robot may well have obeyed.
# ---------------------------------------------------------------------------
def refusal_error(response):
    """Return the refusal message for a canned response, or None."""
    try:
        _dreame._raise_if_refused(response)
    except ToolError as err:
        return str(err)
    return None


ACCEPTED_RESPONSES = (
    ("8a: a list item with code 0", [{"did": "1", "siid": 4, "piid": 23, "code": 0}]),
    ("8b: a bare mapping with code 0", {"code": 0, "out": []}),
    ("8c: every item accepted", [{"code": 0}, {"code": 0}]),
    ("8d: no response items at all", []),
    ("8e: an item with no code", [{"did": "1", "value": 1}]),
    ("8f: a mapping with no code", {"out": []}),
    ("8g: a null code", [{"code": None}]),
    ("8h: an uninterpretable code", [{"code": "busy"}]),
    ("8i: a non-mapping item", [["code", -4004]]),
    ("8j: a string response", "queued"),
    ("8k: no response at all", None),
)
for label, response in ACCEPTED_RESPONSES:
    message = refusal_error(response)
    check(f"{label} is not a refusal", message is None, detail=repr(message))

REFUSED_RESPONSES = (
    ("8l: a single non-zero code", [{"siid": 4, "piid": 23, "code": -4004}]),
    ("8m: a bare mapping with a non-zero code", {"code": 3}),
    ("8n: the second of two items", [{"code": 0}, {"code": -4004}]),
    ("8o: a non-zero code as a string", [{"code": "-4004"}]),
)
for label, response in REFUSED_RESPONSES:
    message = refusal_error(response)
    check(
        f"{label} is a refusal",
        message is not None and "refused the command" in message,
        detail=repr(message),
    )


def written(response):
    """Set a property against a canned response; return the ToolError text."""
    try:
        return _dreame.set_prop(
            StubCloud(response), STATE_ADDRESS, 1, _dreame.deadline()
        )
    except ToolError as err:
        return str(err)


def acted(response):
    """Run an action against a canned response; return the ToolError text."""
    action = _dreame.DreameVacuumActionMapping[_dreame.DreameVacuumAction.START]
    try:
        return _dreame.run_action(StubCloud(response), action, _dreame.deadline())
    except ToolError as err:
        return str(err)


REFUSAL = [{"siid": 4, "piid": 23, "code": -4004}]
ACCEPTANCE = [{"siid": 4, "piid": 23, "code": 0}]

WRITE_OUTCOMES = (
    ("8p: a refused property write raises instead of reporting a change", REFUSAL, _dreame.COMMAND_REFUSED_MESSAGE),
    ("8q: an accepted property write returns the response", ACCEPTANCE, ACCEPTANCE),
)
for label, response, expected in WRITE_OUTCOMES:
    outcome = written(response)
    check(label, outcome == expected, detail=repr(outcome))

ACTION_OUTCOMES = (
    ("8r: a refused action raises instead of reporting acceptance", {"code": -4004}, _dreame.COMMAND_REFUSED_MESSAGE),
    ("8s: an accepted action returns the response", {"code": 0, "out": []}, {"code": 0, "out": []}),
    # An action the cloud answered in an unfamiliar shape stays a success: the
    # robot may have obeyed, and a made-up failure would be the worse report.
    ("8t: an unrecognised action response is still a success", {"result": "ok"}, {"result": "ok"}),
)
for label, response, expected in ACTION_OUTCOMES:
    outcome = acted(response)
    check(label, outcome == expected, detail=repr(outcome))

# ---------------------------------------------------------------------------
print()
if FAILURES:
    print(f"{len(FAILURES)} FAILURES out of {CHECKS} checks: {FAILURES}")
    sys.exit(1)
print(f"ALL {CHECKS} CHECKS PASSED")
