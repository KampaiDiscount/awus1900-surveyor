#!/usr/bin/env python3
"""
AWUS1900 Surveyor

A resilient, passive, dual-band wireless inventory tool for Kali Linux.
It deliberately avoids airmon-ng and packet capture for AP inventory work.
Instead, it uses the kernel nl80211 interface through `iw` to perform
repeated passive scans over every supported 2.4 GHz and 5 GHz channel.

The program is designed for a dedicated survey adapter. It temporarily
places only the selected adapter under its own control, checkpoints results
throughout the run, and restores the original interface state on exit.
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import html
import io
import json
import logging
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional, Sequence

VERSION = "1.0.1"
AWUS1900_USB_IDS = {"0bda:8813"}
DEFAULT_COUNTRY = None
DEFAULT_OUTPUT_ROOT = "./awus-surveys"
STATE_PREFIX = "awus-surveyor"

STOP_EVENT = threading.Event()


# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------


def local_iso(epoch: Optional[float] = None) -> str:
    if epoch is None:
        epoch = time.time()
    return datetime.fromtimestamp(epoch).astimezone().isoformat(timespec="seconds")


def compact_timestamp(epoch: Optional[float] = None) -> str:
    if epoch is None:
        epoch = time.time()
    return datetime.fromtimestamp(epoch).astimezone().strftime("%Y%m%d_%H%M%S")


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def parse_duration(value: str) -> float:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*", value, re.I)
    if not match:
        raise argparse.ArgumentTypeError("duration must look like 90, 10m, 2h, or 1d")
    number = float(match.group(1))
    unit = match.group(2).lower()
    multiplier = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return number * multiplier


def chunked(items: Sequence[int], size: int) -> list[list[int]]:
    size = max(1, size)
    return [list(items[i : i + size]) for i in range(0, len(items), size)]


def unique_preserve(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def truncate(value: str, width: int) -> str:
    value = value.replace("\n", " ").replace("\r", " ")
    if len(value) <= width:
        return value
    if width <= 1:
        return value[:width]
    return value[: width - 1] + "…"


def shell_join(argv: Sequence[str]) -> str:
    # A small dependency-free display helper. This is for logs only.
    def quote(item: str) -> str:
        if re.fullmatch(r"[A-Za-z0-9_./:=+,-]+", item):
            return item
        return "'" + item.replace("'", "'\\''") + "'"

    return " ".join(quote(str(item)) for item in argv)


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class CommandError(RuntimeError):
    pass


class ScanError(RuntimeError):
    pass


def run_command(
    argv: Sequence[str],
    *,
    timeout: Optional[float] = None,
    env: Optional[dict[str, str]] = None,
) -> CommandResult:
    command = [str(item) for item in argv]
    merged_env = os.environ.copy()
    # Force stable, English `iw` output regardless of the caller's locale.
    merged_env["LC_ALL"] = "C"
    merged_env["LANG"] = "C"
    if env:
        merged_env.update(env)
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=merged_env,
            check=False,
        )
        return CommandResult(
            argv=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return CommandResult(
            argv=command,
            returncode=124,
            stdout=stdout or "",
            stderr=stderr or f"command timed out after {timeout} seconds",
            timed_out=True,
        )
    except FileNotFoundError as exc:
        return CommandResult(command, 127, "", str(exc), False)


def require_commands(commands: Sequence[str]) -> None:
    missing = [command for command in commands if shutil.which(command) is None]
    if missing:
        raise CommandError(
            "missing required command(s): "
            + ", ".join(missing)
            + ". Install with: sudo apt install iw iproute2 python3"
        )


def atomic_write_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def atomic_write_json(path: Path, data: Any) -> None:
    atomic_write_text(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def interface_is_up(name: str) -> bool:
    flags_path = Path("/sys/class/net") / name / "flags"
    try:
        flags = int(flags_path.read_text(encoding="ascii").strip(), 16)
        return bool(flags & 0x1)  # IFF_UP
    except (OSError, ValueError):
        return False


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def get_driver_name(interface: str) -> str:
    driver_path = Path("/sys/class/net") / interface / "device" / "driver"
    try:
        return driver_path.resolve().name
    except OSError:
        return ""


def get_usb_identity(interface: str) -> tuple[str, str, str]:
    """Return (vendor:product, manufacturer, product_name) when available."""
    device_link = Path("/sys/class/net") / interface / "device"
    try:
        current = device_link.resolve()
    except OSError:
        return "", "", ""

    candidates = [current, *current.parents]
    for candidate in candidates:
        vendor_file = candidate / "idVendor"
        product_file = candidate / "idProduct"
        if vendor_file.exists() and product_file.exists():
            vendor = read_text(vendor_file).lower()
            product = read_text(product_file).lower()
            manufacturer = read_text(candidate / "manufacturer")
            product_name = read_text(candidate / "product")
            return f"{vendor}:{product}", manufacturer, product_name
    return "", "", ""


def nm_managed_state(interface: str) -> Optional[bool]:
    if shutil.which("nmcli") is None:
        return None
    result = run_command(
        ["nmcli", "-g", "GENERAL.NM-MANAGED", "device", "show", interface],
        timeout=5,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip().lower()
    if value in {"yes", "true", "1"}:
        return True
    if value in {"no", "false", "0"}:
        return False
    return None


def get_regulatory_country() -> str:
    result = run_command(["iw", "reg", "get"], timeout=5)
    if result.returncode != 0:
        return ""
    # The first country entry is the global regulatory domain on normal output.
    match = re.search(r"(?m)^country\s+([A-Z0-9]{2}):", result.stdout)
    return match.group(1).upper() if match else ""


# ---------------------------------------------------------------------------
# Wireless interface discovery and lifecycle
# ---------------------------------------------------------------------------


@dataclass
class WirelessInterface:
    name: str
    phy: str
    wiphy: int
    interface_type: str = ""
    mac: str = ""
    driver: str = ""
    usb_id: str = ""
    usb_manufacturer: str = ""
    usb_product: str = ""
    is_up: bool = False
    nm_managed: Optional[bool] = None

    @property
    def description(self) -> str:
        usb_text = self.usb_product or self.usb_manufacturer
        pieces = [self.name, self.phy, self.interface_type or "unknown-type"]
        if self.driver:
            pieces.append(self.driver)
        if self.usb_id:
            pieces.append(self.usb_id)
        if usb_text:
            pieces.append(usb_text)
        return " | ".join(pieces)


def list_wireless_interfaces() -> list[WirelessInterface]:
    result = run_command(["iw", "dev"], timeout=5)
    if result.returncode != 0:
        raise CommandError(f"unable to enumerate wireless interfaces: {result.stderr.strip()}")

    interfaces: list[WirelessInterface] = []
    current_phy = ""
    current: Optional[WirelessInterface] = None

    for raw_line in result.stdout.splitlines():
        stripped = raw_line.strip()
        phy_match = re.fullmatch(r"phy#(\d+)", stripped)
        if phy_match:
            current_phy = f"phy{phy_match.group(1)}"
            current = None
            continue
        if stripped.startswith("Interface "):
            name = stripped.split(None, 1)[1]
            wiphy = int(current_phy[3:]) if current_phy.startswith("phy") else -1
            current = WirelessInterface(name=name, phy=current_phy, wiphy=wiphy)
            interfaces.append(current)
            continue
        if current is None:
            continue
        if stripped.startswith("type "):
            current.interface_type = stripped.split(None, 1)[1]
        elif stripped.startswith("addr "):
            current.mac = stripped.split(None, 1)[1].lower()
        elif stripped.startswith("wiphy "):
            try:
                current.wiphy = int(stripped.split(None, 1)[1])
                current.phy = f"phy{current.wiphy}"
            except ValueError:
                pass

    for interface in interfaces:
        interface.driver = get_driver_name(interface.name)
        usb_id, manufacturer, product = get_usb_identity(interface.name)
        interface.usb_id = usb_id
        interface.usb_manufacturer = manufacturer
        interface.usb_product = product
        interface.is_up = interface_is_up(interface.name)
        interface.nm_managed = nm_managed_state(interface.name)

    return interfaces


def score_awus_candidate(interface: WirelessInterface) -> int:
    score = 0
    if interface.usb_id in AWUS1900_USB_IDS:
        score += 100
    if "8814" in interface.driver.lower():
        score += 60
    text = f"{interface.usb_manufacturer} {interface.usb_product}".lower()
    if "alfa" in text or "awus1900" in text:
        score += 50
    if interface.interface_type == "managed":
        score += 5
    if interface.name.endswith("mon") or interface.interface_type == "monitor":
        score -= 3
    return score


def select_interface(requested: Optional[str]) -> WirelessInterface:
    interfaces = list_wireless_interfaces()
    if not interfaces:
        raise CommandError("no nl80211 wireless interfaces were found")

    if requested:
        for interface in interfaces:
            if interface.name == requested:
                return interface
        available = ", ".join(item.name for item in interfaces)
        raise CommandError(f"interface {requested!r} was not found; available: {available}")

    ranked = sorted(interfaces, key=score_awus_candidate, reverse=True)
    best = ranked[0]
    if score_awus_candidate(best) > 0:
        return best
    if len(interfaces) == 1:
        return interfaces[0]

    descriptions = "\n  ".join(item.description for item in interfaces)
    raise CommandError(
        "multiple wireless interfaces were found but no AWUS1900 could be identified. "
        "Use --interface.\n  "
        + descriptions
    )


def state_file_for(interface: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", interface)
    return Path("/run") / f"{STATE_PREFIX}-{safe}.state.json"


def restore_saved_state(state_path: Path, logger: Optional[logging.Logger] = None) -> bool:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if logger:
            logger.error("could not read stale state file %s: %s", state_path, exc)
        return False

    pid = int(state.get("pid") or 0)
    if pid_is_alive(pid) and pid != os.getpid():
        raise CommandError(
            f"another surveyor process (PID {pid}) still owns {state.get('interface', 'the adapter')}"
        )

    interface = str(state.get("active_interface") or state.get("interface") or "")
    saved_usb_id = str(state.get("usb_id") or "")
    saved_driver = str(state.get("driver") or "")
    original_type = str(state.get("original_type") or "managed")
    original_up = bool(state.get("original_up"))
    original_nm = state.get("original_nm_managed")
    original_country = str(state.get("original_country") or "")
    changed_country = bool(state.get("country_changed"))

    success = True
    if interface and not (Path("/sys/class/net") / interface).exists():
        # USB re-enumeration can rename wlan interfaces. Match the saved hardware
        # identity before giving up on restoration.
        try:
            candidates = list_wireless_interfaces()
        except CommandError:
            candidates = []
        matches = [item for item in candidates if saved_usb_id and item.usb_id == saved_usb_id]
        if not matches and saved_driver:
            matches = [item for item in candidates if item.driver == saved_driver]
        if len(matches) == 1:
            if logger:
                logger.warning("restoring saved state through renamed interface %s", matches[0].name)
            interface = matches[0].name

    if interface and (Path("/sys/class/net") / interface).exists():
        run_command(["ip", "link", "set", "dev", interface, "down"], timeout=5)
        result = run_command(["iw", "dev", interface, "set", "type", original_type], timeout=5)
        if result.returncode != 0:
            success = False
            if logger:
                logger.warning("could not restore interface type %s: %s", original_type, result.stderr.strip())
        if original_up:
            result = run_command(["ip", "link", "set", "dev", interface, "up"], timeout=5)
            if result.returncode != 0:
                success = False
        if original_nm is not None and shutil.which("nmcli"):
            desired = "yes" if bool(original_nm) else "no"
            result = run_command(["nmcli", "device", "set", interface, "managed", desired], timeout=8)
            if result.returncode != 0:
                success = False
    elif interface:
        success = False
        if logger:
            logger.warning("saved interface %s no longer exists; state was not fully restored", interface)

    if changed_country and original_country:
        result = run_command(["iw", "reg", "set", original_country], timeout=5)
        if result.returncode != 0:
            success = False

    if success:
        try:
            state_path.unlink()
        except OSError:
            pass
    return success


class ProcessLock:
    def __init__(self, key: str):
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", key)
        self.path = Path("/run/lock") / f"{STATE_PREFIX}-{safe}.lock"
        self.handle: Optional[Any] = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CommandError(f"another surveyor process already holds {self.path}") from exc
        self.handle.seek(0)
        self.handle.truncate()
        self.handle.write(f"{os.getpid()}\n")
        self.handle.flush()

    def release(self) -> None:
        if self.handle is not None:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            self.handle.close()
            self.handle = None


class InterfaceManager:
    def __init__(
        self,
        selected: WirelessInterface,
        *,
        country: Optional[str],
        control_networkmanager: bool,
        logger: logging.Logger,
    ):
        self.selected = selected
        self.interface = selected.name
        self.phy = selected.phy
        self.driver = selected.driver
        self.usb_id = selected.usb_id
        self.country = country.upper() if country else None
        self.control_networkmanager = control_networkmanager
        self.logger = logger
        self.state_path = state_file_for(self.interface)
        self.prepared = False
        self.original_type = selected.interface_type or "managed"
        self.original_up = selected.is_up
        self.original_nm = selected.nm_managed
        self.original_country = get_regulatory_country()
        self.country_changed = False

    def _write_state(self) -> None:
        state = {
            "version": VERSION,
            "pid": os.getpid(),
            "created_at": local_iso(),
            "interface": self.selected.name,
            "active_interface": self.interface,
            "phy": self.phy,
            "driver": self.driver,
            "usb_id": self.usb_id,
            "original_type": self.original_type,
            "original_up": self.original_up,
            "original_nm_managed": self.original_nm,
            "original_country": self.original_country,
            "country_changed": self.country_changed,
        }
        atomic_write_json(self.state_path, state)

    def prepare(self) -> None:
        self._write_state()  # Save before changing anything.

        if self.country and self.country != self.original_country:
            result = run_command(["iw", "reg", "set", self.country], timeout=5)
            if result.returncode != 0:
                raise CommandError(f"failed to set regulatory country {self.country}: {result.stderr.strip()}")
            self.country_changed = True
            self._write_state()
            time.sleep(0.5)
            self.logger.info("regulatory country set to %s for this session", self.country)

        if self.control_networkmanager and self.original_nm is True and shutil.which("nmcli"):
            run_command(["nmcli", "device", "disconnect", self.interface], timeout=8)
            result = run_command(
                ["nmcli", "device", "set", self.interface, "managed", "no"], timeout=8
            )
            if result.returncode != 0:
                self.logger.warning("NetworkManager did not release %s: %s", self.interface, result.stderr.strip())
            else:
                self.logger.info("NetworkManager released %s", self.interface)

        self._configure_managed_up()
        self.prepared = True
        self._write_state()

    def _configure_managed_up(self) -> None:
        if not (Path("/sys/class/net") / self.interface).exists():
            raise CommandError(f"wireless interface {self.interface} disappeared")
        run_command(["ip", "link", "set", "dev", self.interface, "down"], timeout=5)
        result = run_command(["iw", "dev", self.interface, "set", "type", "managed"], timeout=5)
        if result.returncode != 0:
            raise CommandError(f"could not set {self.interface} to managed mode: {result.stderr.strip()}")
        result = run_command(["ip", "link", "set", "dev", self.interface, "up"], timeout=8)
        if result.returncode != 0:
            raise CommandError(f"could not bring {self.interface} up: {result.stderr.strip()}")
        time.sleep(1.0)

    def _find_replacement_interface(self) -> Optional[WirelessInterface]:
        try:
            candidates = list_wireless_interfaces()
        except CommandError:
            return None
        if self.usb_id:
            same_usb = [item for item in candidates if item.usb_id == self.usb_id]
            if same_usb:
                return sorted(same_usb, key=score_awus_candidate, reverse=True)[0]
        same_driver = [item for item in candidates if item.driver == self.driver and self.driver]
        if len(same_driver) == 1:
            return same_driver[0]
        return None

    def ensure_present(self, wait_seconds: float = 12.0) -> bool:
        if (Path("/sys/class/net") / self.interface).exists():
            return True
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline and not STOP_EVENT.is_set():
            replacement = self._find_replacement_interface()
            if replacement:
                old = self.interface
                self.interface = replacement.name
                self.phy = replacement.phy
                self.logger.warning("adapter reappeared as %s (previously %s)", self.interface, old)
                self._write_state()
                return True
            STOP_EVENT.wait(1.0)
        return False

    def recover(self) -> bool:
        self.logger.warning("attempting interface recovery")
        if not self.ensure_present():
            self.logger.error("AWUS1900 did not reappear during recovery window")
            return False
        try:
            if self.control_networkmanager and shutil.which("nmcli"):
                run_command(["nmcli", "device", "set", self.interface, "managed", "no"], timeout=8)
            run_command(["iw", "dev", self.interface, "scan", "abort"], timeout=4)
            self._configure_managed_up()
            self._write_state()
            return True
        except CommandError as exc:
            self.logger.error("interface recovery failed: %s", exc)
            return False

    def cleanup(self) -> None:
        if not self.prepared and not self.state_path.exists():
            return
        self.logger.info("restoring original wireless interface state")
        success = restore_saved_state(self.state_path, self.logger)
        if not success:
            self.logger.warning(
                "automatic restoration was incomplete; run with --restore-only after checking the adapter"
            )
        self.prepared = False


# ---------------------------------------------------------------------------
# Channel discovery
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Channel:
    frequency_mhz: int
    channel: int
    band: str
    radar: bool = False
    no_ir: bool = False


def band_for_frequency(frequency_mhz: Optional[int]) -> str:
    if frequency_mhz is None:
        return ""
    if 2400 <= frequency_mhz <= 2500:
        return "2.4 GHz"
    if 4900 <= frequency_mhz < 5925:
        return "5 GHz"
    if 5925 <= frequency_mhz <= 7125:
        return "6 GHz"
    return "Other"


def frequency_to_channel(frequency_mhz: Optional[int]) -> Optional[int]:
    if frequency_mhz is None:
        return None
    if frequency_mhz == 2484:
        return 14
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if 4900 <= frequency_mhz <= 5895:
        return (frequency_mhz - 5000) // 5
    if 5955 <= frequency_mhz <= 7115:
        return (frequency_mhz - 5950) // 5
    return None


def discover_channels(phy: str) -> list[Channel]:
    commands = (["iw", "phy", phy, "channels"], ["iw", "phy", phy, "info"])
    output = ""
    last_error = ""
    for command in commands:
        result = run_command(command, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout
            break
        last_error = result.stderr.strip()
    if not output:
        raise CommandError(f"could not read supported channels for {phy}: {last_error}")

    channels: list[Channel] = []
    pattern = re.compile(r"^\s*\*\s+(\d+)\s+MHz\s+\[(\d+)\](.*)$")
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        frequency = int(match.group(1))
        channel_number = int(match.group(2))
        flags = match.group(3).lower()
        if "disabled" in flags:
            continue
        band = band_for_frequency(frequency)
        if band not in {"2.4 GHz", "5 GHz"}:
            continue
        channels.append(
            Channel(
                frequency_mhz=frequency,
                channel=channel_number,
                band=band,
                radar="radar" in flags,
                no_ir="no ir" in flags or "passive scan" in flags,
            )
        )

    # De-duplicate because some iw outputs repeat capability sections.
    unique: dict[int, Channel] = {item.frequency_mhz: item for item in channels}
    return [unique[key] for key in sorted(unique)]


# ---------------------------------------------------------------------------
# iw scan parser and security classification
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    bssid: str
    ssid: str = ""
    hidden: bool = True
    frequency_mhz: Optional[int] = None
    channel: Optional[int] = None
    band: str = ""
    signal_dbm: Optional[float] = None
    last_seen_ms: Optional[int] = None
    beacon_interval_tu: Optional[int] = None
    capability: str = ""
    mode: str = ""
    country_ie: str = ""
    security: str = "Unknown"
    authentication: str = ""
    pairwise_ciphers: str = ""
    group_cipher: str = ""
    group_mgmt_cipher: str = ""
    pmf: str = "Unknown"
    wps: bool = False
    wps_locked: Optional[bool] = None
    wifi_standard: str = ""
    station_count: Optional[int] = None
    channel_utilization_pct: Optional[float] = None
    security_protocols: set[str] = field(default_factory=set)
    auth_values: list[str] = field(default_factory=list)
    pairwise_values: list[str] = field(default_factory=list)
    group_values: list[str] = field(default_factory=list)
    group_mgmt_values: list[str] = field(default_factory=list)
    rsn_capabilities: list[str] = field(default_factory=list)
    owe_transition: bool = False

    def finalize(self) -> "ScanResult":
        if self.frequency_mhz is not None:
            self.band = band_for_frequency(self.frequency_mhz)
        if self.channel is None:
            self.channel = frequency_to_channel(self.frequency_mhz)
        self.auth_values = unique_preserve(self.auth_values)
        self.pairwise_values = unique_preserve(self.pairwise_values)
        self.group_values = unique_preserve(self.group_values)
        self.group_mgmt_values = unique_preserve(self.group_mgmt_values)
        self.rsn_capabilities = unique_preserve(self.rsn_capabilities)
        self.authentication = " | ".join(self.auth_values)
        self.pairwise_ciphers = " | ".join(self.pairwise_values)
        self.group_cipher = " | ".join(self.group_values)
        self.group_mgmt_cipher = " | ".join(self.group_mgmt_values)
        capabilities = " ".join(self.rsn_capabilities).upper()
        if "MFP-REQUIRED" in capabilities:
            self.pmf = "Required"
        elif "MFP-CAPABLE" in capabilities:
            self.pmf = "Capable"
        elif "RSN" in self.security_protocols:
            self.pmf = "Not advertised"
        else:
            self.pmf = "N/A"
        self.security = classify_security(self)
        if not self.wifi_standard:
            if self.band == "5 GHz":
                self.wifi_standard = "802.11a (legacy/unknown)"
            elif self.band == "2.4 GHz":
                self.wifi_standard = "802.11b/g (legacy/unknown)"
        return self


def decode_iw_ssid(raw: str) -> tuple[str, bool]:
    """Decode iw's \\xNN escapes without interpreting unrelated backslashes."""
    data = bytearray()
    index = 0
    while index < len(raw):
        if (
            raw[index] == "\\"
            and index + 3 < len(raw)
            and raw[index + 1] == "x"
            and re.fullmatch(r"[0-9A-Fa-f]{2}", raw[index + 2 : index + 4])
        ):
            data.append(int(raw[index + 2 : index + 4], 16))
            index += 4
            continue
        if raw[index : index + 2] == "\\\\":
            data.append(ord("\\"))
            index += 2
            continue
        data.extend(raw[index].encode("utf-8", errors="replace"))
        index += 1
    hidden = not data or all(value == 0 for value in data)
    decoded = data.rstrip(b"\x00").decode("utf-8", errors="replace")
    return decoded, hidden


def classify_security(result: ScanResult) -> str:
    auth = result.authentication.upper()
    protocols = result.security_protocols
    privacy = "PRIVACY" in result.capability.upper()
    has_rsn = "RSN" in protocols
    has_wpa = "WPA" in protocols
    has_psk = "PSK" in auth
    has_sae = "SAE" in auth
    has_owe = "OWE" in auth
    has_dpp = "DPP" in auth
    has_enterprise = any(
        marker in auth
        for marker in (
            "802.1X",
            "8021X",
            "SUITE B",
            "SUITE-B",
            "FILS",
        )
    )

    if has_owe:
        return "Enhanced Open (OWE)"
    if result.owe_transition and not has_rsn:
        return "Open / OWE Transition"

    if has_rsn:
        if has_sae and has_psk:
            return "WPA2/WPA3-Personal (Transition)"
        if has_sae:
            return "WPA3-Personal (SAE)"
        if has_dpp:
            return "WPA3-DPP"
        if has_enterprise:
            if any(marker in auth for marker in ("SUITE B 192", "SUITE-B-192", "SHA-384")):
                return "WPA3-Enterprise 192-bit"
            if ("SHA-256" in auth or "SHA256" in auth) and result.pmf == "Required":
                return "WPA2/WPA3-Enterprise"
            return "WPA2-Enterprise"
        if has_psk:
            if has_wpa:
                return "WPA/WPA2-Personal"
            return "WPA2-Personal"
        if has_wpa:
            return "WPA/WPA2 (authentication unknown)"
        return "WPA2/RSN (authentication unknown)"

    if has_wpa:
        if has_enterprise:
            return "WPA-Enterprise"
        if has_psk:
            return "WPA-Personal"
        return "WPA (authentication unknown)"

    if privacy:
        return "WEP / Legacy Privacy"
    return "Open"


def parse_iw_scan(output: str) -> list[ScanResult]:
    results: list[ScanResult] = []
    current: Optional[ScanResult] = None
    section = ""
    standards: set[str] = set()

    def finish_current() -> None:
        nonlocal current, standards
        if current is None:
            return
        if "be" in standards:
            current.wifi_standard = "802.11be (Wi-Fi 7)"
        elif "ax" in standards:
            current.wifi_standard = "802.11ax (Wi-Fi 6/6E)"
        elif "ac" in standards:
            current.wifi_standard = "802.11ac (Wi-Fi 5)"
        elif "n" in standards:
            current.wifi_standard = "802.11n (Wi-Fi 4)"
        results.append(current.finalize())
        current = None
        standards = set()

    for raw_line in output.splitlines():
        line = raw_line.rstrip("\r\n")
        bss_match = re.match(r"^BSS\s+([0-9A-Fa-f:]{17})", line)
        if bss_match:
            finish_current()
            current = ScanResult(bssid=bss_match.group(1).lower())
            section = ""
            continue
        if current is None:
            continue

        stripped = line.strip()
        lowered = stripped.lower()

        # Top-level scalar fields.
        if lowered.startswith("freq:"):
            match = re.search(r"(\d+)", stripped)
            if match:
                current.frequency_mhz = int(match.group(1))
            continue
        if lowered.startswith("signal:"):
            match = re.search(r"(-?\d+(?:\.\d+)?)\s*dBm", stripped, re.I)
            if match:
                current.signal_dbm = float(match.group(1))
            continue
        if lowered.startswith("last seen:") and "ms ago" in lowered:
            match = re.search(r"(\d+)\s*ms\s+ago", stripped, re.I)
            if match:
                current.last_seen_ms = int(match.group(1))
            continue
        if lowered.startswith("beacon interval:"):
            match = re.search(r"(\d+)", stripped)
            if match:
                current.beacon_interval_tu = int(match.group(1))
            continue
        if lowered.startswith("capability:"):
            current.capability = stripped.split(":", 1)[1].strip()
            capability_upper = current.capability.upper()
            if "IBSS" in capability_upper:
                current.mode = "Ad-hoc / IBSS"
            elif "ESS" in capability_upper:
                current.mode = "Infrastructure / ESS"
            continue

        ssid_match = re.match(r"^\s*SSID:\s?(.*)$", line)
        if ssid_match and section not in {"wps"}:
            ssid, hidden = decode_iw_ssid(ssid_match.group(1))
            current.ssid = ssid
            current.hidden = hidden
            continue

        if lowered.startswith("ds parameter set: channel") or lowered.startswith("primary channel:"):
            match = re.search(r"(\d+)", stripped)
            if match:
                current.channel = int(match.group(1))
            continue
        if lowered.startswith("country:"):
            country_match = re.match(r"Country:\s*([A-Za-z0-9]{2})", stripped, re.I)
            if country_match:
                current.country_ie = country_match.group(1).upper()
            continue

        # Standard/capability markers can appear in various sections.
        if stripped.startswith("HT capabilities:") or stripped.startswith("HT operation:"):
            standards.add("n")
            section = "other"
        if stripped.startswith("VHT capabilities:") or stripped.startswith("VHT operation:"):
            standards.add("ac")
            section = "other"
        if stripped.startswith("HE capabilities:") or stripped.startswith("HE operation:"):
            standards.add("ax")
            section = "other"
        if stripped.startswith("EHT capabilities:") or stripped.startswith("EHT operation:"):
            standards.add("be")
            section = "other"
        if stripped.startswith("Information elements from "):
            section = ""

        # Section headings.
        if re.match(r"^RSN(?:\s+Element\s+Override(?:\s+2)?)?:", stripped, re.I):
            current.security_protocols.add("RSN")
            section = "rsn"
            continue
        if re.match(r"^WPA:", stripped, re.I):
            current.security_protocols.add("WPA")
            section = "wpa"
            continue
        if re.match(r"^(?:WPS|Wi-Fi Protected Setup):", stripped, re.I):
            current.wps = True
            section = "wps"
            continue
        if stripped.startswith("BSS Load:"):
            section = "bss_load"
            continue
        if stripped.startswith("OWE transition mode:"):
            current.owe_transition = True
            section = "owe_transition"
            continue

        # Security subfields.
        clean = stripped[1:].strip() if stripped.startswith("*") else stripped
        clean_lower = clean.lower()
        if section in {"rsn", "wpa"}:
            if clean_lower.startswith("authentication suites:"):
                current.auth_values.append(clean.split(":", 1)[1].strip())
                continue
            if clean_lower.startswith("pairwise ciphers:"):
                current.pairwise_values.append(clean.split(":", 1)[1].strip())
                continue
            if clean_lower.startswith("group cipher:"):
                current.group_values.append(clean.split(":", 1)[1].strip())
                continue
            if clean_lower.startswith("group mgmt cipher suite:"):
                current.group_mgmt_values.append(clean.split(":", 1)[1].strip())
                continue
            if clean_lower.startswith("capabilities:"):
                current.rsn_capabilities.append(clean.split(":", 1)[1].strip())
                continue

        if section == "wps":
            if "ap setup locked:" in clean_lower:
                value = clean.split(":", 1)[1].strip().lower()
                current.wps_locked = value in {"1", "0x01", "yes", "true", "locked"}
                continue

        if section == "bss_load":
            if "station count:" in clean_lower:
                match = re.search(r"station count:\s*(\d+)", clean, re.I)
                if match:
                    current.station_count = int(match.group(1))
                continue
            if "channel utilisation:" in clean_lower or "channel utilization:" in clean_lower:
                match = re.search(r"channel utili[sz]ation:\s*(\d+)\s*/\s*255", clean, re.I)
                if match:
                    current.channel_utilization_pct = round(int(match.group(1)) / 255 * 100, 1)
                continue

    finish_current()
    return results


# ---------------------------------------------------------------------------
# OUI/vendor lookup
# ---------------------------------------------------------------------------


class OUILookup:
    CANDIDATE_PATHS = (
        Path("/usr/share/ieee-data/oui.txt"),
        Path("/usr/share/nmap/nmap-mac-prefixes"),
        Path("/usr/share/wireshark/manuf"),
    )

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.prefixes: dict[str, str] = {}
        self.source = ""
        self._load()

    def _load(self) -> None:
        for path in self.CANDIDATE_PATHS:
            if not path.exists():
                continue
            try:
                if path.name == "oui.txt":
                    self._load_ieee(path)
                elif path.name == "nmap-mac-prefixes":
                    self._load_nmap(path)
                else:
                    self._load_manuf(path)
            except OSError as exc:
                self.logger.debug("failed to load OUI database %s: %s", path, exc)
                self.prefixes.clear()
                continue
            if self.prefixes:
                self.source = str(path)
                self.logger.info("loaded %d OUI prefixes from %s", len(self.prefixes), path)
                return
        self.logger.info("no local OUI database found; vendor names will be limited")

    def _load_ieee(self, path: Path) -> None:
        pattern = re.compile(
            r"^\s*([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$"
        )
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = pattern.match(line)
            if match:
                prefix = "".join(match.group(index) for index in (1, 2, 3)).upper()
                self.prefixes[prefix] = match.group(4).strip()

    def _load_nmap(self, path: Path) -> None:
        pattern = re.compile(r"^([0-9A-Fa-f]{6})\s+(.+?)\s*$")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = pattern.match(line)
            if match:
                self.prefixes[match.group(1).upper()] = match.group(2).strip()

    def _load_manuf(self, path: Path) -> None:
        pattern = re.compile(r"^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})(?:/24)?\s+(.+?)\s*$")
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            match = pattern.match(line)
            if match:
                prefix = "".join(match.group(index) for index in (1, 2, 3)).upper()
                value = match.group(4).split("\t", 1)[0].strip()
                self.prefixes[prefix] = value

    def lookup(self, bssid: str) -> str:
        compact = re.sub(r"[^0-9A-Fa-f]", "", bssid).upper()
        if len(compact) < 6:
            return "Unknown"
        try:
            first_octet = int(compact[:2], 16)
            if first_octet & 0x02:
                return "Locally administered"
        except ValueError:
            return "Unknown"
        return self.prefixes.get(compact[:6], "Unknown")


# ---------------------------------------------------------------------------
# Inventory model
# ---------------------------------------------------------------------------


STANDARD_RANK = {
    "": 0,
    "802.11b/g (legacy/unknown)": 1,
    "802.11a (legacy/unknown)": 1,
    "802.11n (Wi-Fi 4)": 2,
    "802.11ac (Wi-Fi 5)": 3,
    "802.11ax (Wi-Fi 6/6E)": 4,
    "802.11be (Wi-Fi 7)": 5,
}


def signal_quality(signal_dbm: Optional[float]) -> str:
    """Return a conservative human-readable RSSI band.

    These are survey-oriented labels, not protocol guarantees. Actual link
    performance also depends on SNR, channel utilization, modulation, antenna
    orientation, and the transmitting device.
    """
    if signal_dbm is None:
        return "Unknown"
    if signal_dbm >= -50:
        return "Excellent"
    if signal_dbm >= -60:
        return "Strong"
    if signal_dbm >= -67:
        return "Good"
    if signal_dbm >= -75:
        return "Fair"
    if signal_dbm >= -85:
        return "Weak"
    return "Very weak"


@dataclass
class NetworkRecord:
    bssid: str
    vendor: str
    first_seen_epoch: float
    last_seen_epoch: float
    ssid: str = ""
    hidden: bool = True
    ssid_history: list[str] = field(default_factory=list)
    frequency_mhz: Optional[int] = None
    channel: Optional[int] = None
    band: str = ""
    channel_history: list[str] = field(default_factory=list)
    security: str = "Unknown"
    security_history: list[str] = field(default_factory=list)
    authentication: str = ""
    pairwise_ciphers: str = ""
    group_cipher: str = ""
    group_mgmt_cipher: str = ""
    pmf: str = "Unknown"
    wps: bool = False
    wps_locked: Optional[bool] = None
    wifi_standard: str = ""
    country_ie: str = ""
    mode: str = ""
    capability: str = ""
    beacon_interval_tu: Optional[int] = None
    station_count: Optional[int] = None
    channel_utilization_pct: Optional[float] = None
    last_scan_age_ms: Optional[int] = None
    signal_last_dbm: Optional[float] = None
    signal_best_dbm: Optional[float] = None
    signal_worst_dbm: Optional[float] = None
    signal_sum_dbm: float = 0.0
    signal_samples: int = 0
    observations: int = 0

    def update(self, result: ScanResult, observed_epoch: float) -> None:
        self.last_seen_epoch = observed_epoch
        self.observations += 1

        if result.ssid:
            if result.ssid not in self.ssid_history:
                self.ssid_history.append(result.ssid)
            self.ssid = result.ssid
            self.hidden = False
        elif not self.ssid:
            self.hidden = True

        if result.frequency_mhz is not None:
            self.frequency_mhz = result.frequency_mhz
        if result.channel is not None:
            self.channel = result.channel
        if result.band:
            self.band = result.band
        location = f"{self.band}:{self.channel}" if self.band and self.channel is not None else ""
        if location and location not in self.channel_history:
            self.channel_history.append(location)

        if result.security and result.security != "Unknown":
            if result.security not in self.security_history:
                self.security_history.append(result.security)
            self.security = result.security
        if result.authentication:
            self.authentication = result.authentication
        if result.pairwise_ciphers:
            self.pairwise_ciphers = result.pairwise_ciphers
        if result.group_cipher:
            self.group_cipher = result.group_cipher
        if result.group_mgmt_cipher:
            self.group_mgmt_cipher = result.group_mgmt_cipher
        if result.pmf and result.pmf != "Unknown":
            self.pmf = result.pmf
        self.wps = self.wps or result.wps
        if result.wps_locked is not None:
            self.wps_locked = result.wps_locked
        if STANDARD_RANK.get(result.wifi_standard, 0) >= STANDARD_RANK.get(self.wifi_standard, 0):
            self.wifi_standard = result.wifi_standard
        if result.country_ie:
            self.country_ie = result.country_ie
        if result.mode:
            self.mode = result.mode
        if result.capability:
            self.capability = result.capability
        if result.beacon_interval_tu is not None:
            self.beacon_interval_tu = result.beacon_interval_tu
        if result.station_count is not None:
            self.station_count = result.station_count
        if result.channel_utilization_pct is not None:
            self.channel_utilization_pct = result.channel_utilization_pct
        self.last_scan_age_ms = result.last_seen_ms

        if result.signal_dbm is not None:
            signal_value = result.signal_dbm
            self.signal_last_dbm = signal_value
            self.signal_sum_dbm += signal_value
            self.signal_samples += 1
            if self.signal_best_dbm is None or signal_value > self.signal_best_dbm:
                self.signal_best_dbm = signal_value
            if self.signal_worst_dbm is None or signal_value < self.signal_worst_dbm:
                self.signal_worst_dbm = signal_value

    @property
    def signal_avg_dbm(self) -> Optional[float]:
        if not self.signal_samples:
            return None
        return self.signal_sum_dbm / self.signal_samples

    def risk_flags(self) -> list[str]:
        flags: list[str] = []
        security_upper = self.security.upper()
        if self.security == "Open":
            flags.append("OPEN")
        if "WEP" in security_upper:
            flags.append("WEP")
        if (
            self.security.startswith("WPA-")
            or self.security.startswith("WPA/")
            or self.security == "WPA (authentication unknown)"
        ):
            flags.append("LEGACY_WPA")
        if self.wps:
            flags.append("WPS")
        if self.hidden:
            flags.append("HIDDEN")
        return flags

    def to_dict(self, now_epoch: Optional[float] = None) -> dict[str, Any]:
        if now_epoch is None:
            now_epoch = time.time()
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "essid": self.ssid,
            "hidden": self.hidden,
            "ssid_history": list(self.ssid_history),
            "vendor": self.vendor,
            "band": self.band,
            "channel": self.channel,
            "frequency_mhz": self.frequency_mhz,
            "channel_history": list(self.channel_history),
            "security": self.security,
            "security_history": list(self.security_history),
            "authentication": self.authentication,
            "pairwise_ciphers": self.pairwise_ciphers,
            "group_cipher": self.group_cipher,
            "group_mgmt_cipher": self.group_mgmt_cipher,
            "pmf": self.pmf,
            "wps": self.wps,
            "wps_locked": self.wps_locked,
            "wifi_standard": self.wifi_standard,
            "country_ie": self.country_ie,
            "mode": self.mode,
            "capability": self.capability,
            "beacon_interval_tu": self.beacon_interval_tu,
            "station_count": self.station_count,
            "channel_utilization_pct": self.channel_utilization_pct,
            "signal_last_dbm": round(self.signal_last_dbm, 1) if self.signal_last_dbm is not None else None,
            "signal_best_dbm": round(self.signal_best_dbm, 1) if self.signal_best_dbm is not None else None,
            "signal_worst_dbm": round(self.signal_worst_dbm, 1) if self.signal_worst_dbm is not None else None,
            "signal_avg_dbm": round(self.signal_avg_dbm, 1) if self.signal_avg_dbm is not None else None,
            "signal_quality": signal_quality(self.signal_avg_dbm if self.signal_avg_dbm is not None else self.signal_last_dbm),
            "signal_spread_db": (
                round(self.signal_best_dbm - self.signal_worst_dbm, 1)
                if self.signal_best_dbm is not None and self.signal_worst_dbm is not None
                else None
            ),
            "signal_samples": self.signal_samples,
            "observations": self.observations,
            "last_scan_age_ms": self.last_scan_age_ms,
            "first_seen": local_iso(self.first_seen_epoch),
            "last_seen": local_iso(self.last_seen_epoch),
            "age_seconds": round(max(0.0, now_epoch - self.last_seen_epoch), 1),
            "risk_flags": self.risk_flags(),
        }


class Inventory:
    def __init__(self, oui: OUILookup):
        self.oui = oui
        self.records: dict[str, NetworkRecord] = {}

    def update(self, result: ScanResult, observed_epoch: float) -> NetworkRecord:
        record = self.records.get(result.bssid)
        if record is None:
            record = NetworkRecord(
                bssid=result.bssid,
                vendor=self.oui.lookup(result.bssid),
                first_seen_epoch=observed_epoch,
                last_seen_epoch=observed_epoch,
            )
            self.records[result.bssid] = record
        record.update(result, observed_epoch)
        return record

    def sorted_records(self) -> list[NetworkRecord]:
        def sort_key(record: NetworkRecord) -> tuple[float, str]:
            signal_value = record.signal_last_dbm if record.signal_last_dbm is not None else -999.0
            return (-signal_value, record.bssid)

        return sorted(self.records.values(), key=sort_key)

    def counts(self) -> dict[str, int]:
        records = list(self.records.values())
        return {
            "total": len(records),
            "2.4_ghz": sum(record.band == "2.4 GHz" for record in records),
            "5_ghz": sum(record.band == "5 GHz" for record in records),
            "hidden": sum(record.hidden for record in records),
            "open": sum(record.security == "Open" for record in records),
            "wep": sum("WEP" in record.security.upper() for record in records),
            "wps": sum(record.wps for record in records),
            "wpa3": sum(("WPA3" in record.security or "OWE" in record.security) for record in records),
        }


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------


CSV_FIELDS = [
    "bssid",
    "ssid",
    "essid",
    "hidden",
    "vendor",
    "band",
    "channel",
    "frequency_mhz",
    "signal_last_dbm",
    "signal_best_dbm",
    "signal_worst_dbm",
    "signal_avg_dbm",
    "signal_quality",
    "signal_spread_db",
    "security",
    "authentication",
    "pairwise_ciphers",
    "group_cipher",
    "group_mgmt_cipher",
    "pmf",
    "wps",
    "wps_locked",
    "wifi_standard",
    "mode",
    "country_ie",
    "station_count",
    "channel_utilization_pct",
    "first_seen",
    "last_seen",
    "age_seconds",
    "observations",
    "signal_samples",
    "last_scan_age_ms",
    "risk_flags",
    "ssid_history",
    "channel_history",
    "security_history",
]


def csv_text(networks: list[dict[str, Any]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for network in networks:
        row = dict(network)
        for key in ("risk_flags", "ssid_history", "channel_history", "security_history"):
            value = row.get(key)
            if isinstance(value, list):
                row[key] = "; ".join(str(item) for item in value)
        writer.writerow(row)
    return buffer.getvalue()


def markdown_escape(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\n", " ")


def markdown_text(session: dict[str, Any], networks: list[dict[str, Any]], counts: dict[str, int]) -> str:
    lines = [
        "# AWUS1900 Wireless Survey",
        "",
        f"- **Status:** {session.get('status', '')}",
        f"- **Started:** {session.get('started_at', '')}",
        f"- **Last checkpoint:** {session.get('updated_at', '')}",
        f"- **Interface:** {session.get('interface', '')} ({session.get('driver', '')})",
        f"- **Regulatory country:** {session.get('active_country', '') or 'unchanged/unknown'}",
        f"- **Networks:** {counts['total']} total; {counts['2.4_ghz']} on 2.4 GHz; {counts['5_ghz']} on 5 GHz",
        f"- **Output directory:** `{session.get('output_directory', '')}`",
        "",
        "| RSSI now | RSSI avg | Quality | Band/Ch | Security | PMF | WPS | BSSID | SSID / ESSID | Vendor | First seen | Last seen | Flags |",
        "|---:|---:|---|:---:|---|:---:|:---:|---|---|---|---|---|---|",
    ]
    for item in networks:
        signal_value = item.get("signal_last_dbm")
        signal_text = f"{signal_value:.1f}" if isinstance(signal_value, (int, float)) else ""
        signal_avg = item.get("signal_avg_dbm")
        signal_avg_text = f"{signal_avg:.1f}" if isinstance(signal_avg, (int, float)) else ""
        band_channel = f"{item.get('band', '')}/{item.get('channel', '')}"
        ssid = item.get("ssid") or "<hidden>"
        flags = ", ".join(item.get("risk_flags") or [])
        lines.append(
            "| "
            + " | ".join(
                markdown_escape(value)
                for value in (
                    signal_text,
                    signal_avg_text,
                    item.get("signal_quality", ""),
                    band_channel,
                    item.get("security", ""),
                    item.get("pmf", ""),
                    "Yes" if item.get("wps") else "No",
                    item.get("bssid", ""),
                    ssid,
                    item.get("vendor", ""),
                    item.get("first_seen", ""),
                    item.get("last_seen", ""),
                    flags,
                )
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)


def security_css_class(security: str) -> str:
    upper = security.upper()
    if security == "Open" or "WEP" in upper:
        return "critical"
    if security.startswith("WPA-") or security == "WPA (authentication unknown)":
        return "warning"
    if "WPA3" in upper or "OWE" in upper:
        return "strong"
    return "normal"


def html_text(session: dict[str, Any], networks: list[dict[str, Any]], counts: dict[str, int]) -> str:
    rows: list[str] = []
    for item in networks:
        signal_value = item.get("signal_last_dbm")
        signal_sort = signal_value if isinstance(signal_value, (int, float)) else -999
        signal_display = f"{signal_value:.1f}" if isinstance(signal_value, (int, float)) else ""
        signal_avg = item.get("signal_avg_dbm")
        signal_avg_sort = signal_avg if isinstance(signal_avg, (int, float)) else -999
        signal_avg_display = f"{signal_avg:.1f}" if isinstance(signal_avg, (int, float)) else ""
        ssid = item.get("ssid") or "<hidden>"
        risks = ", ".join(item.get("risk_flags") or [])
        wps = "Yes" if item.get("wps") else "No"
        css_class = security_css_class(str(item.get("security", "")))
        rows.append(
            "<tr>"
            f"<td data-sort='{signal_sort}'>{html.escape(signal_display)}</td>"
            f"<td data-sort='{signal_avg_sort}'>{html.escape(signal_avg_display)}</td>"
            f"<td>{html.escape(str(item.get('signal_quality') or ''))}</td>"
            f"<td>{html.escape(str(item.get('band') or ''))}</td>"
            f"<td data-sort='{item.get('channel') or -1}'>{html.escape(str(item.get('channel') or ''))}</td>"
            f"<td data-sort='{item.get('frequency_mhz') or -1}'>{html.escape(str(item.get('frequency_mhz') or ''))}</td>"
            f"<td><span class='badge {css_class}'>{html.escape(str(item.get('security') or ''))}</span></td>"
            f"<td>{html.escape(str(item.get('pmf') or ''))}</td>"
            f"<td>{wps}</td>"
            f"<td class='mono'>{html.escape(str(item.get('bssid') or ''))}</td>"
            f"<td>{html.escape(str(ssid))}</td>"
            f"<td>{html.escape(str(item.get('vendor') or ''))}</td>"
            f"<td>{html.escape(str(item.get('wifi_standard') or ''))}</td>"
            f"<td>{html.escape(str(item.get('authentication') or ''))}</td>"
            f"<td>{html.escape(str(item.get('pairwise_ciphers') or ''))}</td>"
            f"<td>{html.escape(str(item.get('first_seen') or ''))}</td>"
            f"<td>{html.escape(str(item.get('last_seen') or ''))}</td>"
            f"<td>{html.escape(risks)}</td>"
            "</tr>"
        )

    cards = "".join(
        f"<div class='card'><div class='number'>{value}</div><div class='label'>{html.escape(label)}</div></div>"
        for label, value in (
            ("Total APs", counts["total"]),
            ("2.4 GHz", counts["2.4_ghz"]),
            ("5 GHz", counts["5_ghz"]),
            ("Open", counts["open"]),
            ("WEP", counts["wep"]),
            ("WPS", counts["wps"]),
            ("WPA3 / OWE", counts["wpa3"]),
            ("Hidden", counts["hidden"]),
        )
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AWUS1900 Wireless Survey</title>
<style>
:root {{ color-scheme: dark; --bg:#0d1117; --panel:#161b22; --line:#30363d; --text:#e6edf3; --muted:#8b949e; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
main {{ max-width:1800px; margin:0 auto; padding:24px; }}
h1 {{ margin:0 0 6px; font-size:28px; }}
.meta {{ color:var(--muted); margin-bottom:18px; line-height:1.55; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; margin:18px 0; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px; }}
.number {{ font-size:24px; font-weight:700; }} .label {{ color:var(--muted); font-size:13px; }}
.controls {{ display:flex; gap:10px; margin:16px 0; }}
input {{ width:min(600px,100%); background:var(--panel); color:var(--text); border:1px solid var(--line); border-radius:8px; padding:10px 12px; }}
.table-wrap {{ overflow:auto; border:1px solid var(--line); border-radius:10px; }}
table {{ width:100%; border-collapse:collapse; min-width:1820px; background:var(--panel); }}
th,td {{ border-bottom:1px solid var(--line); padding:9px 10px; text-align:left; vertical-align:top; font-size:13px; }}
th {{ position:sticky; top:0; background:#21262d; cursor:pointer; user-select:none; white-space:nowrap; }}
tr:hover td {{ background:#1c2128; }}
.mono {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace; white-space:nowrap; }}
.badge {{ display:inline-block; border-radius:999px; padding:3px 8px; white-space:nowrap; border:1px solid var(--line); }}
.badge.critical {{ background:#5b1a1a; border-color:#b62324; }}
.badge.warning {{ background:#4d3408; border-color:#9e6a03; }}
.badge.strong {{ background:#153d2d; border-color:#238636; }}
.badge.normal {{ background:#1f2d43; border-color:#388bfd; }}
footer {{ color:var(--muted); margin-top:14px; font-size:12px; }}
</style>
</head>
<body>
<main>
<h1>AWUS1900 Wireless Survey</h1>
<div class="meta">
Status: <strong>{html.escape(str(session.get('status','')))}</strong> ·
Interface: <strong>{html.escape(str(session.get('interface','')))}</strong> ·
Driver: <strong>{html.escape(str(session.get('driver','')))}</strong> ·
Started: {html.escape(str(session.get('started_at','')))} ·
Updated: {html.escape(str(session.get('updated_at','')))}<br>
Passive dual-band sweeps: {html.escape(str(session.get('sweeps',0)))} ·
Successful scan requests: {html.escape(str(session.get('scan_successes',0)))} ·
Failures: {html.escape(str(session.get('scan_failures',0)))} ·
Regulatory country: {html.escape(str(session.get('active_country','') or 'unchanged/unknown'))}
</div>
<div class="cards">{cards}</div>
<div class="controls"><input id="filter" type="search" placeholder="Filter by SSID, BSSID, vendor, security, channel…" oninput="filterRows()"></div>
<div class="table-wrap">
<table id="survey">
<thead><tr>
<th onclick="sortTable(0)">RSSI now dBm</th><th onclick="sortTable(1)">RSSI avg dBm</th><th onclick="sortTable(2)">Quality</th><th onclick="sortTable(3)">Band</th><th onclick="sortTable(4)">Channel</th><th onclick="sortTable(5)">MHz</th>
<th onclick="sortTable(6)">Security</th><th onclick="sortTable(7)">PMF</th><th onclick="sortTable(8)">WPS</th><th onclick="sortTable(9)">BSSID</th>
<th onclick="sortTable(10)">SSID / ESSID</th><th onclick="sortTable(11)">Vendor</th><th onclick="sortTable(12)">Standard</th><th onclick="sortTable(13)">Authentication</th>
<th onclick="sortTable(14)">Pairwise ciphers</th><th onclick="sortTable(15)">First seen</th><th onclick="sortTable(16)">Last seen</th><th onclick="sortTable(17)">Flags</th>
</tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
</div>
<footer>Generated by AWUS1900 Surveyor v{VERSION}. Each BSSID is retained as a separate wireless zone/AP.</footer>
</main>
<script>
function filterRows() {{
  const q = document.getElementById('filter').value.toLowerCase();
  document.querySelectorAll('#survey tbody tr').forEach(row => {{
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
let sortState = {{}};
function sortTable(column) {{
  const tbody = document.querySelector('#survey tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  const ascending = !sortState[column]; sortState = {{[column]: ascending}};
  rows.sort((a,b) => {{
    const ac = a.children[column], bc = b.children[column];
    const av = ac.dataset.sort !== undefined ? Number(ac.dataset.sort) : ac.textContent.toLowerCase();
    const bv = bc.dataset.sort !== undefined ? Number(bc.dataset.sort) : bc.textContent.toLowerCase();
    if (av < bv) return ascending ? -1 : 1;
    if (av > bv) return ascending ? 1 : -1;
    return 0;
  }});
  rows.forEach(row => tbody.appendChild(row));
}}
</script>
</body>
</html>
"""


class OutputWriter:
    def __init__(self, directory: Path, logger: logging.Logger):
        self.directory = directory
        self.logger = logger
        self.directory.mkdir(parents=True, exist_ok=True)

    def checkpoint(self, session: dict[str, Any], inventory: Inventory) -> None:
        now_epoch = time.time()
        session["updated_at"] = local_iso(now_epoch)
        counts = inventory.counts()
        session["network_counts"] = counts
        networks = [record.to_dict(now_epoch) for record in inventory.sorted_records()]

        atomic_write_json(self.directory / "session.json", session)
        atomic_write_json(
            self.directory / "wireless_zones.json",
            {
                "session": session,
                "summary": counts,
                "networks": networks,
            },
        )
        atomic_write_text(self.directory / "wireless_zones.csv", csv_text(networks))
        atomic_write_text(self.directory / "wireless_zones.md", markdown_text(session, networks, counts))
        atomic_write_text(self.directory / "wireless_zones.html", html_text(session, networks, counts))

    def save_raw(self, band: str, frequencies: Sequence[int], output: str, keep_history: bool) -> None:
        safe_band = "2g" if band == "2.4 GHz" else "5g"
        header = (
            f"# Captured: {local_iso()}\n"
            f"# Band: {band}\n"
            f"# Frequencies: {' '.join(str(item) for item in frequencies)}\n\n"
        )
        atomic_write_text(self.directory / f"last_raw_scan_{safe_band}.txt", header + output)
        if keep_history:
            raw_dir = self.directory / "raw_scans"
            filename = f"{compact_timestamp()}_{safe_band}_{frequencies[0]}-{frequencies[-1]}.txt"
            atomic_write_text(raw_dir / filename, header + output)


# ---------------------------------------------------------------------------
# Scan runner
# ---------------------------------------------------------------------------


class ScanRunner:
    def __init__(
        self,
        manager: InterfaceManager,
        *,
        timeout_seconds: float,
        retries: int,
        use_flush: bool,
        logger: logging.Logger,
    ):
        self.manager = manager
        self.timeout_seconds = timeout_seconds
        self.retries = max(1, retries)
        self.flush_supported = use_flush
        self.logger = logger

    @staticmethod
    def _is_flush_problem(result: CommandResult) -> bool:
        text = f"{result.stdout}\n{result.stderr}".lower()
        return any(
            marker in text
            for marker in (
                "invalid argument",
                "unknown command",
                "usage:",
                "not supported",
            )
        )

    def scan(self, frequencies: Sequence[int]) -> str:
        if not frequencies:
            return ""
        last_message = "unknown scan failure"
        attempt = 1
        while attempt <= self.retries and not STOP_EVENT.is_set():
            if not self.manager.ensure_present():
                last_message = "wireless adapter is absent"
                attempt += 1
                continue

            command = ["iw", "dev", self.manager.interface, "scan"]
            if self.flush_supported:
                command.append("flush")
            command.extend(["freq", *[str(value) for value in frequencies], "passive"])
            self.logger.debug("scan command: %s", shell_join(command))
            result = run_command(command, timeout=self.timeout_seconds)

            if result.returncode == 0:
                return result.stdout

            if self.flush_supported and self._is_flush_problem(result):
                self.logger.info("kernel/iw scan flush flag unavailable; continuing without it")
                self.flush_supported = False
                continue  # Retry without consuming an attempt.

            message = (result.stderr or result.stdout).strip()
            if result.timed_out:
                message = f"scan timed out after {self.timeout_seconds:.1f}s"
            last_message = message or f"iw exited with status {result.returncode}"
            self.logger.warning(
                "scan attempt %d/%d failed on %s: %s",
                attempt,
                self.retries,
                self.manager.interface,
                last_message,
            )
            run_command(["iw", "dev", self.manager.interface, "scan", "abort"], timeout=4)
            if attempt < self.retries:
                STOP_EVENT.wait(min(1.5 * attempt, 4.0))
            attempt += 1

        raise ScanError(last_message)


# ---------------------------------------------------------------------------
# UI and logging
# ---------------------------------------------------------------------------


def configure_logging(log_path: Path, debug: bool) -> logging.Logger:
    logger = logging.getLogger("awus-surveyor")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.handlers.clear()
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def render_ui(
    inventory: Inventory,
    session: dict[str, Any],
    manager: InterfaceManager,
    output_directory: Path,
    current_band: str,
    current_channels: Sequence[int],
    top_n: int,
) -> None:
    if not sys.stdout.isatty():
        return
    counts = inventory.counts()
    runtime = time.monotonic() - float(session.get("started_monotonic", time.monotonic()))
    channel_text = ",".join(str(item) for item in current_channels)
    print("\033[2J\033[H", end="")
    print(f"AWUS1900 Surveyor v{VERSION}  |  PASSIVE 2.4/5 GHz INVENTORY")
    print("=" * 100)
    print(
        f"Adapter: {manager.interface}  Driver: {manager.driver or 'unknown'}  "
        f"PHY: {manager.phy}  Country: {session.get('active_country') or 'unchanged/unknown'}"
    )
    print(
        f"Runtime: {human_duration(runtime)}  Sweeps: {session.get('sweeps', 0)}  "
        f"Scan OK/Fail: {session.get('scan_successes', 0)}/{session.get('scan_failures', 0)}  "
        f"Recoveries: {session.get('recoveries', 0)}"
    )
    print(
        f"Networks: {counts['total']}  2.4 GHz: {counts['2.4_ghz']}  5 GHz: {counts['5_ghz']}  "
        f"Open: {counts['open']}  WEP: {counts['wep']}  WPS: {counts['wps']}  Hidden: {counts['hidden']}"
    )
    print(f"Current scan: {current_band or '-'} channels [{truncate(channel_text, 70)}]")
    print(f"Checkpoint directory: {output_directory}")
    print("-" * 100)
    print(f"{'RSSI':>6} {'AVG':>6}  {'BAND':<7} {'CH':>3}  {'SECURITY':<31} {'PMF':<10} {'WPS':<3}  {'BSSID':<17}  SSID / ESSID")
    print("-" * 100)
    for record in inventory.sorted_records()[: max(1, top_n)]:
        signal_text = f"{record.signal_last_dbm:5.1f}" if record.signal_last_dbm is not None else "    ?"
        signal_avg_text = f"{record.signal_avg_dbm:5.1f}" if record.signal_avg_dbm is not None else "    ?"
        ssid = record.ssid or "<hidden>"
        print(
            f"{signal_text:>6} {signal_avg_text:>6}  {record.band:<7} {str(record.channel or ''):>3}  "
            f"{truncate(record.security, 31):<31} {truncate(record.pmf, 10):<10} "
            f"{'Y' if record.wps else 'N':<3}  {record.bssid:<17}  {truncate(ssid, 36)}"
        )
    print("-" * 100)
    print("RSSI is received signal at the AWUS1900, not adapter transmit power. Ctrl-C stops cleanly and restores state.")
    sys.stdout.flush()


def console_notice(message: str, no_ui: bool = False) -> None:
    if no_ui or not sys.stdout.isatty():
        print(message, flush=True)


# ---------------------------------------------------------------------------
# Session orchestration
# ---------------------------------------------------------------------------


def build_jobs(channels: Sequence[Channel], band_choice: str, chunk_2g: int, chunk_5g: int) -> list[tuple[str, list[int], list[int]]]:
    jobs: list[tuple[str, list[int], list[int]]] = []
    by_band = {
        "2.4 GHz": [item for item in channels if item.band == "2.4 GHz"],
        "5 GHz": [item for item in channels if item.band == "5 GHz"],
    }
    selected_bands: list[str]
    if band_choice == "2.4":
        selected_bands = ["2.4 GHz"]
    elif band_choice == "5":
        selected_bands = ["5 GHz"]
    else:
        selected_bands = ["2.4 GHz", "5 GHz"]

    for band in selected_bands:
        band_channels = by_band[band]
        frequency_values = [item.frequency_mhz for item in band_channels]
        channel_map = {item.frequency_mhz: item.channel for item in band_channels}
        size = chunk_2g if band == "2.4 GHz" else chunk_5g
        for frequency_chunk in chunked(frequency_values, size):
            jobs.append((band, frequency_chunk, [channel_map[value] for value in frequency_chunk]))
    return jobs


def observation_dict(result: ScanResult, observed_at: str, scan_band: str) -> dict[str, Any]:
    return {
        "observed_at": observed_at,
        "scan_band": scan_band,
        "bssid": result.bssid,
        "ssid": result.ssid,
        "essid": result.ssid,
        "hidden": result.hidden,
        "frequency_mhz": result.frequency_mhz,
        "channel": result.channel,
        "band": result.band,
        "signal_dbm": result.signal_dbm,
        "last_seen_ms": result.last_seen_ms,
        "security": result.security,
        "authentication": result.authentication,
        "pairwise_ciphers": result.pairwise_ciphers,
        "group_cipher": result.group_cipher,
        "group_mgmt_cipher": result.group_mgmt_cipher,
        "pmf": result.pmf,
        "wps": result.wps,
        "wps_locked": result.wps_locked,
        "wifi_standard": result.wifi_standard,
        "mode": result.mode,
        "country_ie": result.country_ie,
        "station_count": result.station_count,
        "channel_utilization_pct": result.channel_utilization_pct,
    }


def chown_output_to_invoking_user(directory: Path, logger: logging.Logger) -> None:
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if not sudo_uid or not sudo_gid:
        return
    try:
        uid = int(sudo_uid)
        gid = int(sudo_gid)
    except ValueError:
        return
    try:
        for root, directories, files in os.walk(directory):
            os.chown(root, uid, gid)
            for name in directories:
                os.chown(Path(root) / name, uid, gid)
            for name in files:
                os.chown(Path(root) / name, uid, gid)
    except OSError as exc:
        logger.debug("could not chown all output files: %s", exc)


def run_self_test(interface_name: Optional[str]) -> int:
    require_commands(["iw", "ip"])
    interfaces = list_wireless_interfaces()
    if not interfaces:
        print("FAIL: no wireless interfaces found")
        return 2
    selected = select_interface(interface_name)
    print(f"Selected interface : {selected.name}")
    print(f"PHY                : {selected.phy}")
    print(f"Type               : {selected.interface_type}")
    print(f"Administrative up  : {selected.is_up}")
    print(f"MAC                : {selected.mac}")
    print(f"Driver             : {selected.driver or 'unknown'}")
    print(f"USB ID             : {selected.usb_id or 'not exposed'}")
    print(f"USB product        : {selected.usb_product or 'unknown'}")
    print(f"NetworkManager     : {selected.nm_managed}")
    print(f"Regulatory country : {get_regulatory_country() or 'unknown'}")
    channels = discover_channels(selected.phy)
    channels_2g = [item.channel for item in channels if item.band == "2.4 GHz"]
    channels_5g = [item.channel for item in channels if item.band == "5 GHz"]
    print(f"2.4 GHz channels   : {', '.join(map(str, channels_2g)) or 'NONE'}")
    print(f"5 GHz channels     : {', '.join(map(str, channels_5g)) or 'NONE'}")
    if selected.usb_id in AWUS1900_USB_IDS or "8814" in selected.driver:
        print("AWUS1900 match     : YES")
    else:
        print("AWUS1900 match     : not certain; use --interface explicitly")
    if not channels_2g or not channels_5g:
        print("FAIL: both requested bands are not available under the current driver/regulatory domain")
        return 2
    print("PASS: the adapter exposes both 2.4 GHz and 5 GHz channels")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="awus-surveyor",
        description=(
            "Autonomous passive 2.4/5 GHz AP inventory for the ALFA AWUS1900 on Kali. "
            "Results are checkpointed continuously to CSV, JSON, HTML, and Markdown."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--interface", help="wireless interface; AWUS1900 is auto-detected when omitted")
    parser.add_argument("--band", choices=("both", "2.4", "5"), default="both", help="band(s) to survey")
    parser.add_argument(
        "--country",
        default=DEFAULT_COUNTRY,
        help="temporary ISO 3166-1 alpha-2 regulatory country, e.g. ZA; restored on exit",
    )
    parser.add_argument("--output-root", default=DEFAULT_OUTPUT_ROOT, help="parent directory for timestamped sessions")
    parser.add_argument("--session-name", help="optional directory name instead of scan_YYYYmmdd_HHMMSS")
    parser.add_argument("--interval", type=float, default=2.0, help="pause between complete dual-band sweeps")
    parser.add_argument("--scan-timeout", type=float, default=22.0, help="timeout for each channel chunk")
    parser.add_argument("--retries", type=int, default=3, help="scan retries before interface recovery")
    parser.add_argument("--chunk-size-2g", type=int, default=14, help="2.4 GHz frequencies per scan request")
    parser.add_argument("--chunk-size-5g", type=int, default=8, help="5 GHz frequencies per scan request")
    parser.add_argument(
        "--max-stale-ms",
        type=int,
        default=15000,
        help="discard cached BSS entries older than this many milliseconds",
    )
    parser.add_argument("--duration", type=parse_duration, help="stop after duration, e.g. 30m or 2h")
    parser.add_argument("--once", action="store_true", help="perform one complete sweep and exit")
    parser.add_argument("--top", type=int, default=25, help="number of strongest APs shown in the live table")
    parser.add_argument("--keep-raw", action="store_true", help="retain every raw iw scan in addition to last-scan files")
    parser.add_argument("--no-flush", action="store_true", help="do not request kernel BSS-cache flushing")
    parser.add_argument(
        "--no-networkmanager-control",
        action="store_true",
        help="do not mark the selected adapter unmanaged during the survey",
    )
    parser.add_argument("--no-ui", action="store_true", help="disable the terminal dashboard")
    parser.add_argument("--debug", action="store_true", help="write debug details to surveyor.log")
    parser.add_argument("--list-interfaces", action="store_true", help="list wireless interfaces and exit")
    parser.add_argument("--self-test", action="store_true", help="inspect adapter/driver/band support without changing state")
    parser.add_argument("--restore-only", action="store_true", help="restore stale interface state from a prior hard crash")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def handle_restore_only(interface_name: Optional[str]) -> int:
    if os.geteuid() != 0:
        print("restore requires root: sudo awus-surveyor --restore-only", file=sys.stderr)
        return 1
    require_commands(["iw", "ip"])
    paths: list[Path]
    if interface_name:
        paths = [state_file_for(interface_name)]
    else:
        paths = sorted(Path("/run").glob(f"{STATE_PREFIX}-*.state.json"))
    existing = [path for path in paths if path.exists()]
    if not existing:
        print("No stale AWUS Surveyor state files were found.")
        return 0
    failed = False
    for path in existing:
        try:
            if restore_saved_state(path):
                print(f"Restored state from {path}")
            else:
                print(f"Could not fully restore state from {path}", file=sys.stderr)
                failed = True
        except CommandError as exc:
            print(str(exc), file=sys.stderr)
            failed = True
    return 1 if failed else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    STOP_EVENT.clear()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.country:
        args.country = args.country.upper()
        if not re.fullmatch(r"[A-Z]{2}|00", args.country):
            parser.error("--country must be a two-letter ISO country code such as ZA, or 00")
    if args.interval < 0 or args.scan_timeout <= 0 or args.retries < 1:
        parser.error("--interval must be non-negative; --scan-timeout and --retries must be positive")
    if args.chunk_size_2g < 1 or args.chunk_size_5g < 1 or args.max_stale_ms < 0:
        parser.error("chunk sizes must be positive and --max-stale-ms cannot be negative")

    try:
        require_commands(["iw", "ip"])
    except CommandError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.restore_only:
        return handle_restore_only(args.interface)

    if args.list_interfaces:
        try:
            interfaces = list_wireless_interfaces()
        except CommandError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        if not interfaces:
            print("No wireless interfaces found.")
            return 1
        for item in interfaces:
            marker = "AWUS1900 candidate" if score_awus_candidate(item) > 0 else ""
            print(f"{item.description} | up={item.is_up} | nm_managed={item.nm_managed} {marker}")
        return 0

    if args.self_test:
        try:
            return run_self_test(args.interface)
        except CommandError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    if os.geteuid() != 0:
        print("ERROR: passive nl80211 scans require root; run with sudo.", file=sys.stderr)
        return 1

    try:
        selected = select_interface(args.interface)
    except CommandError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    output_root = Path(args.output_root).expanduser().resolve()
    session_name = args.session_name or f"scan_{compact_timestamp()}"
    session_name = re.sub(r"[^A-Za-z0-9_.-]", "_", session_name)
    output_directory = output_root / session_name
    output_directory.mkdir(parents=True, exist_ok=True)
    logger = configure_logging(output_directory / "surveyor.log", args.debug)
    writer = OutputWriter(output_directory, logger)

    state_path = state_file_for(selected.name)
    if state_path.exists():
        try:
            stale_state = json.loads(state_path.read_text(encoding="utf-8"))
            stale_pid = int(stale_state.get("pid") or 0)
            if pid_is_alive(stale_pid):
                raise CommandError(f"another surveyor process is active with PID {stale_pid}")
            logger.warning("restoring stale state left by PID %s", stale_pid)
            if not restore_saved_state(state_path, logger):
                raise CommandError(f"stale state in {state_path} could not be restored safely")
            selected = select_interface(args.interface)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"ERROR: invalid stale state file {state_path}: {exc}", file=sys.stderr)
            return 1
        except CommandError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    lock = ProcessLock(selected.phy or selected.name)
    manager: Optional[InterfaceManager] = None
    observations_handle: Optional[Any] = None
    exit_code = 0
    error_message = ""
    started_epoch = time.time()
    started_monotonic = time.monotonic()

    session: dict[str, Any] = {
        "tool": "AWUS1900 Surveyor",
        "version": VERSION,
        "status": "starting",
        "started_at": local_iso(started_epoch),
        "updated_at": local_iso(started_epoch),
        "ended_at": None,
        "started_monotonic": started_monotonic,
        "output_directory": str(output_directory),
        "requested_interface": args.interface,
        "interface": selected.name,
        "phy": selected.phy,
        "driver": selected.driver,
        "usb_id": selected.usb_id,
        "usb_product": selected.usb_product,
        "mac": selected.mac,
        "original_type": selected.interface_type,
        "original_up": selected.is_up,
        "original_nm_managed": selected.nm_managed,
        "requested_country": args.country,
        "active_country": "",
        "band_selection": args.band,
        "passive_scan": True,
        "sweeps": 0,
        "scan_requests": 0,
        "scan_successes": 0,
        "scan_failures": 0,
        "recoveries": 0,
        "last_error": "",
        "network_counts": {},
    }

    inventory: Optional[Inventory] = None

    def request_stop(signum: int, _frame: Any) -> None:
        if not STOP_EVENT.is_set():
            STOP_EVENT.set()
            logger.info("received signal %s; stopping cleanly", signum)
            if args.no_ui or not sys.stdout.isatty():
                print("Stopping cleanly and finalizing reports…", flush=True)

    previous_sigint = signal.signal(signal.SIGINT, request_stop)
    previous_sigterm = signal.signal(signal.SIGTERM, request_stop)

    try:
        lock.acquire()
        manager = InterfaceManager(
            selected,
            country=args.country,
            control_networkmanager=not args.no_networkmanager_control,
            logger=logger,
        )
        manager.prepare()
        session["interface"] = manager.interface
        session["phy"] = manager.phy
        session["active_country"] = get_regulatory_country()

        channels = discover_channels(manager.phy)
        jobs = build_jobs(channels, args.band, args.chunk_size_2g, args.chunk_size_5g)
        available_bands = {band for band, _frequencies, _channels in jobs}
        required_bands = {"2.4 GHz", "5 GHz"} if args.band == "both" else ({"2.4 GHz"} if args.band == "2.4" else {"5 GHz"})
        missing_bands = sorted(required_bands - available_bands)
        if not jobs or missing_bands:
            missing_text = ", ".join(missing_bands) if missing_bands else args.band
            raise CommandError(
                f"no enabled channels are available for {missing_text} on {manager.phy} under country "
                f"{session['active_country'] or 'unknown'}"
            )

        selected_channels = [item for item in channels if (args.band == "both" or item.band.startswith(args.band))]
        session["channels"] = [
            {
                "band": item.band,
                "channel": item.channel,
                "frequency_mhz": item.frequency_mhz,
                "radar": item.radar,
                "no_ir": item.no_ir,
            }
            for item in selected_channels
        ]
        logger.info(
            "surveying %d enabled frequencies across %s using %s",
            len(selected_channels),
            args.band,
            manager.interface,
        )

        oui = OUILookup(logger)
        inventory = Inventory(oui)
        session["oui_database"] = oui.source
        session["status"] = "running"
        writer.checkpoint(session, inventory)

        observations_path = output_directory / "observations.jsonl"
        observations_handle = observations_path.open("a", encoding="utf-8", buffering=1)
        scan_runner = ScanRunner(
            manager,
            timeout_seconds=args.scan_timeout,
            retries=args.retries,
            use_flush=not args.no_flush,
            logger=logger,
        )

        deadline = started_monotonic + args.duration if args.duration else None
        consecutive_failures = 0
        completion_reason = "signal"

        while not STOP_EVENT.is_set():
            for scan_band, frequencies, channel_numbers in jobs:
                if STOP_EVENT.is_set():
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    completion_reason = "duration"
                    STOP_EVENT.set()
                    break

                session["scan_requests"] += 1
                session["interface"] = manager.interface
                try:
                    raw_output = scan_runner.scan(frequencies)
                    session["scan_successes"] += 1
                    consecutive_failures = 0
                    writer.save_raw(scan_band, frequencies, raw_output, args.keep_raw)
                    parsed = parse_iw_scan(raw_output)
                    frequency_set = set(frequencies)
                    accepted: list[ScanResult] = []
                    observed_epoch = time.time()
                    observed_at = local_iso(observed_epoch)
                    for result in parsed:
                        if result.frequency_mhz not in frequency_set:
                            continue
                        if result.last_seen_ms is not None and result.last_seen_ms > args.max_stale_ms:
                            continue
                        accepted.append(result)
                        inventory.update(result, observed_epoch)
                        observations_handle.write(
                            json.dumps(
                                observation_dict(result, observed_at, scan_band),
                                ensure_ascii=False,
                                separators=(",", ":"),
                            )
                            + "\n"
                        )
                    observations_handle.flush()
                    os.fsync(observations_handle.fileno())
                    logger.debug(
                        "scan %s frequencies=%s parsed=%d accepted=%d",
                        scan_band,
                        frequencies,
                        len(parsed),
                        len(accepted),
                    )
                except ScanError as exc:
                    session["scan_failures"] += 1
                    consecutive_failures += 1
                    session["last_error"] = str(exc)
                    logger.error("scan request failed: %s", exc)
                    if manager.recover():
                        session["recoveries"] += 1
                    if consecutive_failures >= 3:
                        logger.warning("multiple consecutive failures; applying extended backoff")
                        STOP_EVENT.wait(8.0)
                        consecutive_failures = 0
                    STOP_EVENT.wait(min(2.0 + session["scan_failures"], 10.0))

                session["status"] = "running"
                writer.checkpoint(session, inventory)
                if not args.no_ui:
                    render_ui(
                        inventory,
                        session,
                        manager,
                        output_directory,
                        scan_band,
                        channel_numbers,
                        args.top,
                    )

            if STOP_EVENT.is_set():
                break
            session["sweeps"] += 1
            writer.checkpoint(session, inventory)
            if args.once:
                completion_reason = "once"
                break
            if deadline is not None and time.monotonic() >= deadline:
                completion_reason = "duration"
                break
            STOP_EVENT.wait(max(0.0, args.interval))

        session["completion_reason"] = completion_reason
        session["status"] = "completed" if completion_reason in {"once", "duration"} else "stopped"

    except (CommandError, ScanError) as exc:
        exit_code = 1
        error_message = str(exc)
        session["status"] = "error"
        session["last_error"] = error_message
        logger.error("fatal error: %s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
    except Exception as exc:  # Defensive finalizer: never skip report/restore.
        exit_code = 1
        error_message = f"unexpected {type(exc).__name__}: {exc}"
        session["status"] = "error"
        session["last_error"] = error_message
        logger.exception("unexpected fatal error")
        print(f"ERROR: {error_message}", file=sys.stderr)
    finally:
        session["ended_at"] = local_iso()
        session["updated_at"] = session["ended_at"]
        session.pop("started_monotonic", None)
        if observations_handle is not None:
            try:
                observations_handle.flush()
                os.fsync(observations_handle.fileno())
                observations_handle.close()
            except OSError:
                pass
        if inventory is not None:
            try:
                writer.checkpoint(session, inventory)
            except Exception as exc:
                logger.exception("failed to write final checkpoint: %s", exc)
                exit_code = 1
        else:
            try:
                atomic_write_json(output_directory / "session.json", session)
            except OSError:
                pass
        if manager is not None:
            try:
                manager.cleanup()
            except Exception as exc:
                logger.exception("interface cleanup failed: %s", exc)
                exit_code = 1
        lock.release()
        chown_output_to_invoking_user(output_directory, logger)
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)

    counts = inventory.counts() if inventory is not None else {"total": 0}
    print()
    print(f"Survey {'failed' if exit_code else 'finished'}: {counts.get('total', 0)} wireless zones recorded")
    for label, filename in (("HTML", "wireless_zones.html"), ("CSV", "wireless_zones.csv"), ("JSON", "wireless_zones.json"), ("Log", "surveyor.log")):
        path = output_directory / filename
        if path.exists():
            print(f"{label:<5}: {path}")
    if error_message:
        print(f"Error: {error_message}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
