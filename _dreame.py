"""Shared cloud helpers for the Dreame plugin tools.

Tools import this module after adding the plugin root to ``sys.path``.  Keeping
all cloud access here gives every tool the same configuration validation,
credential-safe error handling, session cache, and deadline budget.
"""

import json
import logging
import os
import pathlib
import sys
import tempfile
import time
import types as _types
from collections.abc import Callable, Mapping
from typing import Any


class ToolError(Exception):
    """Fatal, user-facing error whose message is safe to print."""


ROOT = pathlib.Path(__file__).resolve().parent
CACHE_FIELDS = ("auth_key", "did", "host", "model", "name")
CACHE_DIRECTORY = (".cache", "stavrobot-dreame")
CACHE_FILENAME = "session.json"
TOOL_DEADLINE_SECONDS = 25
MINIMUM_REQUEST_TIMEOUT_SECONDS = 3.0

# upstream login() uses a hardcoded 10-second request timeout and, when the
# cloud answers with a refresh-token error body, recurses once into itself with
# the password instead. One login() call is therefore worst-case two requests,
# i.e. 20 seconds, which is what the retry below has to budget for.
UPSTREAM_LOGIN_WORST_CASE_SECONDS = 20

VALID_COUNTRIES = {
    "dreame": ("eu", "cn", "us", "ru", "sg", "kr"),
    "mova": ("eu", "cn", "us", "sg"),
    "trouver": ("eu", "us", "ru", "sg"),
}

VACUUM_UNREACHABLE_MESSAGE = (
    "the vacuum did not answer, it may be asleep or offline; press a button on "
    "the robot to wake it and try again."
)

COMMAND_REFUSED_MESSAGE = (
    "The vacuum refused the command. It may be busy, or the feature is unsupported "
    "on this model."
)


# upstream protocol.py line 18 does `from miio.miioprotocol import MiIOProtocol`
# at module level, but uses it only at line 39 as the base class of the
# local-LAN class we never touch. python-miio pulls in netifaces, which has
# no wheels for modern Python and needs a C build, so stub it instead.
_m = _types.ModuleType("miio.miioprotocol")


class MiIOProtocol:
    def __init__(self, *a, **kw):
        pass


_m.MiIOProtocol = MiIOProtocol
_pkg = _types.ModuleType("miio")
_pkg.__path__ = []
_pkg.miioprotocol = _m
sys.modules["miio"] = _pkg
sys.modules["miio.miioprotocol"] = _m

_root = str(ROOT)
if not sys.path or sys.path[0] != _root:
    sys.path.insert(0, _root)

# Import through the package parent only. Never add upstream/ itself to
# sys.path: upstream/types.py would shadow stdlib types deep inside enum/typing.
_UPSTREAM_ATTRIBUTE_NAMES = frozenset(
    (
        "types",
        "DreameVacuumDreameHomeCloudProtocol",
        "DreameVacuumProperty",
        "DreameVacuumAction",
        "DreameVacuumPropertyMapping",
        "DreameVacuumActionMapping",
    )
)
_upstream_bindings: dict[str, Any] | None = None


def _silence_upstream_logging() -> None:
    """Prevent upstream request/login bodies from reaching the tool stderr."""
    for name in ("upstream", "upstream.protocol"):
        logging.getLogger(name).setLevel(logging.CRITICAL)


def _load_upstream() -> dict[str, Any]:
    """Load the generated upstream package on first use, not module import."""
    global _upstream_bindings
    if _upstream_bindings is not None:
        return _upstream_bindings

    try:
        from upstream.protocol import DreameVacuumDreameHomeCloudProtocol
        from upstream import exceptions as _upstream_exceptions
        from upstream import types as upstream_types
    except ImportError:
        # sys.path[0] is the plugin root, so with all four files in place none
        # of these names can be missing; an ImportError then means a genuinely
        # broken upstream, which is not a "try again" condition.
        incomplete_files = (
            ROOT / "upstream" / "__init__.py",
            ROOT / "upstream" / "protocol.py",
            ROOT / "upstream" / "types.py",
            ROOT / "upstream" / "exceptions.py",
        )
        if any(not path.is_file() for path in incomplete_files):
            raise ToolError("plugin setup is still running, try again in a moment.") from None
        raise

    _silence_upstream_logging()
    bindings = {
        "types": upstream_types,
        "DreameVacuumDreameHomeCloudProtocol": DreameVacuumDreameHomeCloudProtocol,
        "DreameVacuumProperty": upstream_types.DreameVacuumProperty,
        "DreameVacuumAction": upstream_types.DreameVacuumAction,
        "DreameVacuumPropertyMapping": upstream_types.DreameVacuumPropertyMapping,
        "DreameVacuumActionMapping": upstream_types.DreameVacuumActionMapping,
    }
    cleaning_modes = {
        "sweep": upstream_types.DreameVacuumCleaningMode.SWEEPING.value,
        "mop": upstream_types.DreameVacuumCleaningMode.MOPPING.value,
        "sweep_and_mop": upstream_types.DreameVacuumCleaningMode.SWEEPING_AND_MOPPING.value,
        "mop_after_sweep": upstream_types.DreameVacuumCleaningMode.MOPPING_AFTER_SWEEPING.value,
    }
    bindings["_CLEANING_MODES"] = cleaning_modes
    bindings["_CLEANING_MODE_NAMES"] = {
        value: name for name, value in cleaning_modes.items()
    }
    globals().update(bindings)
    _upstream_bindings = bindings
    return bindings


def __getattr__(name: str) -> Any:
    """Expose generated upstream symbols lazily via PEP 562."""
    if name in _UPSTREAM_ATTRIBUTE_NAMES:
        return _load_upstream()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def load_config() -> dict:
    """Load and validate the plugin configuration from a tool working directory."""
    config_path = pathlib.Path("../config.json")
    try:
        with config_path.open(encoding="utf-8") as config_file:
            config = json.load(config_file)
    except FileNotFoundError:
        raise ToolError(
            "config.json is missing. Configure the Dreame plugin with a username and password."
        ) from None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        raise ToolError(
            "config.json could not be read. Re-save the Dreame plugin configuration as valid JSON."
        ) from None

    if not isinstance(config, dict):
        raise ToolError("config.json must contain a JSON object.")

    username = config.get("username")
    if not isinstance(username, str) or not username.strip():
        raise ToolError("Dreame username is missing. Set it in the plugin configuration.")

    password = config.get("password")
    if not isinstance(password, str) or not password.strip():
        raise ToolError("Dreame password is missing. Set it in the plugin configuration.")

    account_type = str(config.get("account_type") or "dreame").strip().lower()
    if account_type not in VALID_COUNTRIES:
        raise ToolError("account_type must be one of: dreame, mova, trouver.")

    country = str(config.get("country") or "eu").strip().lower()
    if country not in VALID_COUNTRIES[account_type]:
        # Only whitelisted values reach this message: account_type was checked
        # against the same table above, and the country list is ours. No
        # configuration value is formatted into stderr; config.json holds the
        # account password.
        raise ToolError(
            f"country must be one of: {', '.join(VALID_COUNTRIES[account_type])} "
            f"for a {account_type} account."
        )

    # Use normalized optional settings while preserving passwords exactly; a
    # leading or trailing space can be a legitimate password character.
    config = dict(config)
    config["username"] = username.strip()
    config["account_type"] = account_type
    config["country"] = country
    return config


def _session_cache_path() -> pathlib.Path:
    """Return the per-plugin session location under the current HOME."""
    return pathlib.Path.home().joinpath(*CACHE_DIRECTORY, CACHE_FILENAME)


def _load_session_cache() -> dict | None:
    """Best-effort cache load; a damaged cache is equivalent to no cache."""
    try:
        with _session_cache_path().open(encoding="utf-8") as cache_file:
            cache = json.load(cache_file)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None

    if not isinstance(cache, dict) or any(field not in cache for field in CACHE_FIELDS):
        return None
    if any(
        cache[field] is not None and not isinstance(cache[field], str)
        for field in CACHE_FIELDS
    ):
        return None
    return {field: cache[field] for field in CACHE_FIELDS}


def _write_session_cache(cache: Mapping[str, Any]) -> None:
    """Atomically persist the credential-bearing session cache with mode 0600."""
    path = _session_cache_path()
    temporary_path: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{CACHE_FILENAME}.", dir=path.parent
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as cache_file:
            # mkstemp already creates the file 0600 and os.replace preserves
            # the mode; this states the requirement at the point it matters.
            os.fchmod(cache_file.fileno(), 0o600)
            json.dump({field: cache.get(field) for field in CACHE_FIELDS}, cache_file)
            cache_file.flush()
            os.fsync(cache_file.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    except (OSError, TypeError, ValueError):
        # A cache is only an optimization. Do not prevent a command from
        # completing because the per-plugin HOME is temporarily unavailable.
        pass
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


def _cached_string(cache: Mapping[str, Any] | None, field: str) -> str | None:
    if cache is None:
        return None
    value = cache.get(field)
    return value if isinstance(value, str) and value else None


def _device_name(
    record: Mapping[str, Any], default: str | None = "unnamed vacuum"
) -> str | None:
    """Name the vacuum the way the Dreame app does, else the caller's default.

    The device-list error paths need a placeholder to list; a status report has
    nothing to say about a vacuum with no name and passes None to omit it.
    """
    custom_name = record.get("customName")
    if isinstance(custom_name, str) and custom_name.strip():
        return custom_name.strip()

    device_info = record.get("deviceInfo")
    if isinstance(device_info, Mapping):
        display_name = device_info.get("displayName")
        if isinstance(display_name, str) and display_name.strip():
            return display_name.strip()

    return default


def _cache_snapshot(cloud: Any, name: str | None) -> dict:
    """Build the fixed cache schema without exposing its credential in errors."""
    did = cloud.device_id
    return {
        "auth_key": cloud.auth_key,
        "did": str(did) if did is not None else None,
        "host": getattr(cloud, "_host", None),
        "model": getattr(cloud, "_model", None),
        "name": name,
    }


def _new_cloud(config: Mapping[str, Any], auth_key: str | None, did: str | None):
    _load_upstream()
    return DreameVacuumDreameHomeCloudProtocol(
        config["username"],
        config["password"],
        config["account_type"],
        config["country"],
        auth_key=auth_key,
        did=did,
    )


def _get_devices(cloud: Any, limit: float) -> Any:
    """Call upstream's device-list endpoint without its unsafe default retries."""
    # upstream get_devices() hardcodes retry_count=2 and a 6s timeout, i.e. 18s
    # worst case, which does not fit the 30s tool kill. Same call, no retries,
    # timeout from the remaining budget. Path indices track the pinned SHA.
    path = "/".join(
        (cloud._strings[23], cloud._strings[24], cloud._strings[27], cloud._strings[28])
    )
    response = cloud._api_call(path, None, 0, timeout_remaining(limit))
    if isinstance(response, Mapping) and "data" in response and response.get("code") == 0:
        return response["data"]
    return None


def _device_records(devices: Any) -> list[Mapping[str, Any]] | None:
    if not isinstance(devices, Mapping):
        return None
    page = devices.get("page")
    if not isinstance(page, Mapping):
        return None
    records = page.get("records")
    if not isinstance(records, list) or not all(isinstance(record, Mapping) for record in records):
        return None
    return records


def deadline() -> float:
    """Start the shared budget below the runner's hard 30-second kill."""
    return time.monotonic() + TOOL_DEADLINE_SECONDS


def timeout_remaining(limit: float) -> float:
    """Return a deadline-bounded per-request timeout."""
    remaining = limit - time.monotonic()
    if remaining < MINIMUM_REQUEST_TIMEOUT_SECONDS:
        raise ToolError(
            f"Dreame cloud calls exceeded the {TOOL_DEADLINE_SECONDS}-second tool budget "
            "and were aborted. Try again shortly."
        )
    return remaining


def connect(limit: float, refresh_identity: bool = False) -> tuple[Any, Mapping[str, Any] | None]:
    """Log in and restore or refresh the single supported vacuum identity."""
    global _restored_identity
    timeout_remaining(limit)
    _silence_upstream_logging()
    config = load_config()
    cache = _load_session_cache()
    cached_auth_key = _cached_string(cache, "auth_key")
    cached_did = _cached_string(cache, "did")
    cached_host = _cached_string(cache, "host")
    cached_model = _cached_string(cache, "model")
    cached_name = _cached_string(cache, "name")

    cloud = _new_cloud(config, cached_auth_key, cached_did)
    logged_in = cloud.login()

    # A concurrent tool can rotate the cached refresh token. Retry exactly
    # once without it so the password-login path repairs that cache race, but
    # only with a full login's worth of budget left: the retry cannot be cut
    # short by a timeout argument, so starting one on a thin budget would run
    # past the runner's hard 30-second kill and report nothing at all.
    if (
        not logged_in
        and cached_auth_key is not None
        and limit - time.monotonic() >= UPSTREAM_LOGIN_WORST_CASE_SECONDS
    ):
        cloud = _new_cloud(config, None, cached_did)
        logged_in = cloud.login()

    if not logged_in:
        raise ToolError(
            "Dreame login failed. The password may be wrong, or the country may not "
            "match the account's region."
        )

    if not refresh_identity and cached_did is not None and cached_host is not None:
        cloud._did = cached_did
        cloud._host = cached_host
        cloud._model = cached_model
        _restored_identity = (cached_did, cached_host)
        if cloud.auth_key != cached_auth_key:
            _write_session_cache(_cache_snapshot(cloud, cached_name))
        return cloud, None

    devices = _get_devices(cloud, limit)
    if devices is None:
        raise ToolError("The Dreame cloud did not return a device list. Try again shortly.")

    records = _device_records(devices)
    if records is None:
        raise ToolError("The Dreame cloud returned an unexpected device list. Try again shortly.")
    if not records:
        raise ToolError(
            "No vacuum was found in this account. The country may not match the region "
            "where the account was created."
        )

    if len(records) > 1:
        names = ", ".join(_device_name(record) for record in records)
        raise ToolError(f"Found multiple vacuums: {names}. This plugin handles one vacuum.")

    record = records[0]
    try:
        # login() lazily decodes the string table that _handle_device_info uses.
        cloud._handle_device_info(record)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ToolError("The Dreame cloud returned incomplete device information. Try again shortly.") from None

    _write_session_cache(_cache_snapshot(cloud, _device_name(record)))
    return cloud, record


def _property_parts(address: Mapping[str, int]) -> tuple[int, int]:
    return address["siid"], address["piid"]


def _action_parts(address: Mapping[str, int]) -> tuple[int, int]:
    return address["siid"], address["aiid"]


# Set by connect() when it addresses the robot from the cached identity instead
# of the device list. One cloud per process, so a module global says what an
# attribute on the third-party cloud object was pretending to say.
_restored_identity: tuple[str, str] | None = None


def _discard_restored_identity_cache() -> None:
    """Remove the session cache only while it still holds what we restored."""
    if _restored_identity is None:
        return

    cached_did, cached_host = _restored_identity
    cache = _load_session_cache()
    if cache is None or cache.get("did") != cached_did or cache.get("host") != cached_host:
        return
    try:
        _session_cache_path().unlink()
    except Exception:
        # Cache invalidation is a best-effort self-heal and must not replace
        # the stable unreachable-vacuum message with a filesystem failure.
        pass


def _send(cloud: Any, method: str, parameters: Any, limit: float) -> Any:
    request_timeout = timeout_remaining(limit)
    response = cloud.send(method, parameters, retry_count=0, timeout=request_timeout)
    if response is None:
        _discard_restored_identity_cache()
        raise ToolError(VACUUM_UNREACHABLE_MESSAGE)
    return response


def _raise_if_refused(response: Any) -> None:
    """Fail when the robot answered a write or an action with a refusal code."""
    # Only an explicitly present, readable, non-zero code counts as a refusal.
    # An unrecognised response shape stays non-fatal: the robot may well have
    # carried the command out, and inventing a failure would be worse than
    # reporting a success we could not confirm.
    for item in response if isinstance(response, list) else [response]:
        if not isinstance(item, Mapping):
            continue
        code = item.get("code")
        if code is None:
            continue
        try:
            numeric_code = int(code)
        except (TypeError, ValueError):
            continue
        if numeric_code != 0:
            raise ToolError(COMMAND_REFUSED_MESSAGE)


def get_props(
    cloud: Any, addresses: list[Mapping[str, int]], limit: float
) -> dict[tuple[int, int], dict]:
    """Fetch a batch of MIoT properties, keyed by their (siid, piid) address."""
    parameters = []
    for address in addresses:
        siid, piid = _property_parts(address)
        parameters.append({"did": str(cloud.device_id), "siid": siid, "piid": piid})

    response = _send(cloud, "get_properties", parameters, limit)
    if not isinstance(response, list):
        raise ToolError("The Dreame cloud returned an unexpected property response. Try again shortly.")

    properties = {}
    for property_result in response:
        if not isinstance(property_result, dict):
            raise ToolError("The Dreame cloud returned an unexpected property response. Try again shortly.")
        try:
            key = (int(property_result["siid"]), int(property_result["piid"]))
        except (KeyError, TypeError, ValueError):
            raise ToolError("The Dreame cloud returned an unexpected property response. Try again shortly.") from None
        properties[key] = property_result
    return properties


def read_property(props: Mapping[tuple[int, int], Any], address: Mapping[str, int]) -> Any:
    """Return one property's value, or None when the cloud could not read it."""
    # A non-zero code means the cloud has no value for this property, and its
    # "value" field is then meaningless rather than merely stale.
    entry = props.get(_property_parts(address))
    if not isinstance(entry, Mapping) or entry.get("code") != 0:
        return None
    return entry.get("value")


def read_whole_number(props: Mapping[tuple[int, int], Any], address: Mapping[str, int]) -> int | None:
    """Return one property's value as an int, or None if it is not a number."""
    value = read_property(props, address)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def set_prop(cloud: Any, address: Mapping[str, int], value: Any, limit: float) -> Any:
    """Set one MIoT property without upstream retries that exceed the budget."""
    siid, piid = _property_parts(address)
    response = _send(
        cloud,
        "set_properties",
        [
            {
                "did": str(cloud.device_id),
                "siid": siid,
                "piid": piid,
                "value": value,
            }
        ],
        limit,
    )
    _raise_if_refused(response)
    return response


def run_action(cloud: Any, address: Mapping[str, int], limit: float) -> Any:
    """Run one MIoT action without upstream retries that exceed the budget."""
    siid, aiid = _action_parts(address)
    response = _send(
        cloud,
        "action",
        {"did": str(cloud.device_id), "siid": siid, "aiid": aiid, "in": []},
        limit,
    )
    _raise_if_refused(response)
    return response


def decode(enum_cls: Any, value: Any) -> str:
    """Turn an upstream enum value into a stable human string."""
    try:
        name = enum_cls(value).name
    except (TypeError, ValueError):
        return f"unknown ({value})"
    return name.lower().replace("_", " ")


def _property_key(property_name: Any) -> tuple[int, int]:
    _load_upstream()
    return _property_parts(DreameVacuumPropertyMapping[property_name])


def lifting_probes_present(props: Mapping[tuple[int, int], Any]) -> bool:
    """Report whether the cloud answered the two mop-pad-lifting probes at all.

    detect_mop_pad_lifting cannot tell "the probe came back unsupported", which
    is a real answer meaning no lifting, from "the cloud never mentioned the
    probe", which means nothing is known. Callers need the difference: with a
    probe absent, the sweep/sweep-and-mop wire encoding is unknowable and
    guessing it would set or report the opposite mode.
    """
    _load_upstream()
    return all(
        _property_key(name) in props
        for name in (
            DreameVacuumProperty.SELF_WASH_BASE_STATUS,
            DreameVacuumProperty.DUST_COLLECTION,
        )
    )


def detect_mop_pad_lifting(props: Mapping[tuple[int, int], Mapping[str, Any]]) -> bool:
    """Infer mop-pad lifting from successful availability probes.

    This assumes a self-wash plus auto-empty base, which is what the probes
    detect. On other mop-lifting models sweep and sweep_and_mop may come out
    exchanged, both when setting a mode and when reporting one.
    """
    _load_upstream()
    self_wash = props.get(_property_key(DreameVacuumProperty.SELF_WASH_BASE_STATUS))
    dust_collection = props.get(_property_key(DreameVacuumProperty.DUST_COLLECTION))

    # Deliberately test successful presence only. Upstream also clears its
    # auto-empty flag when DUST_COLLECTION is NEVER, but that controls
    # auto-empty features rather than cleaning-mode wire encoding. Copying it
    # would flip the sweep/sweep-and-mop swap for users who choose Never.
    return (
        isinstance(self_wash, Mapping)
        and self_wash.get("code") == 0
        and isinstance(dust_collection, Mapping)
        and dust_collection.get("code") == 0
    )


def encode_cleaning_mode(raw_value: int, mode_name: str, lifting: bool) -> int:
    """Replace only the cleaning-mode bits in the packed 4/23 property."""
    _load_upstream()
    try:
        logical_mode = _CLEANING_MODES[mode_name]
    except (KeyError, TypeError):
        raise ToolError(
            "Unknown cleaning mode. Choose one of: sweep, mop, sweep_and_mop, mop_after_sweep."
        ) from None

    wire_mode = {0: 2, 2: 0}.get(logical_mode, logical_mode) if lifting else logical_mode

    # Deliberate deviations from upstream. Both cite device.py in the upstream
    # repository at the pinned SHA; that file is not downloaded here, since
    # init.py fetches only protocol.py, types.py and exceptions.py.
    # 1. combine_group_value/split_group_value (device.py:2372-2388) round-trip
    #    the word to (V & 0x30000) | (V & 0xFF00) | (V & 0x03), silently
    #    clearing bits 2-7 and 18+. Masking with ~0x03 is more conservative:
    #    preserve fields we do not understand rather than clearing them.
    # 2. _update_cleaning_mode (device.py:2045-2069) only assigns values[0] for
    #    requested mode 2 on a self-wash model without mop-pad lifting. That
    #    looks like an upstream bug, so every requested mode is honoured.
    return (raw_value & ~0x03) | wire_mode


def decode_cleaning_mode(raw_value: int, lifting: bool) -> str:
    """Decode the packed wire mode back to the public logical mode name."""
    _load_upstream()
    wire_mode = raw_value & 0x03
    logical_mode = {0: 2, 2: 0}.get(wire_mode, wire_mode) if lifting else wire_mode
    return _CLEANING_MODE_NAMES[logical_mode]


def main_guard(main: Callable[[], None]) -> None:
    """Run a tool main function with the common safe user-facing error path."""
    try:
        main()
    except ToolError as err:
        print(str(err), file=sys.stderr)
        raise SystemExit(1)
    except Exception:
        # Anything that is not a ToolError is a bug or an upstream surprise:
        # upstream request() runs json.loads(response.text) outside its try, so
        # a 200 with a non-JSON body arrives here as a JSONDecodeError. Print a
        # fixed line and never the exception: its text is upstream's, can carry
        # a response body, and is not ours to hand to the user.
        print(
            "The Dreame plugin hit an unexpected error talking to the cloud. "
            "Try again shortly.",
            file=sys.stderr,
        )
        raise SystemExit(1)
