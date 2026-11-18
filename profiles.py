"""Gamepad profile system for loading, validating, and cycling mappings.

Loads JSON profile definitions (e.g. Shooter, RTS/Menu), validates
stick sensitivity / response curves and button/trigger mappings,
and manages profile cycling at runtime.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

import vgamepad as vg

from stick_mapper import MouseToStickMapper

# ── Win32 Virtual Key Lookup ─────────────────────────────────────────────

VK_F9: int = 0x78

# Map string names to Win32 Virtual-Key codes
_VK_NAME_MAP: dict[str, int] = {
    # Mouse buttons (tokens used in profile JSON and Win32 aliases)
    "MOUSE_LEFT": 0x01,
    "MOUSE_RIGHT": 0x02,
    "MOUSE_MIDDLE": 0x04,
    "MOUSE_X1": 0x05,
    "MOUSE_X2": 0x06,
    "VK_LBUTTON": 0x01,
    "VK_RBUTTON": 0x02,
    "VK_MBUTTON": 0x04,
    "VK_XBUTTON1": 0x05,
    "VK_XBUTTON2": 0x06,
    "LBUTTON": 0x01,
    "RBUTTON": 0x02,
    "MBUTTON": 0x04,
    "XBUTTON1": 0x05,
    "XBUTTON2": 0x06,
    # Standard control keys
    "VK_BACK": 0x08,
    "VK_TAB": 0x09,
    "VK_RETURN": 0x0D,
    "VK_ENTER": 0x0D,
    "VK_SHIFT": 0x10,
    "VK_CONTROL": 0x11,
    "VK_CTRL": 0x11,
    "VK_MENU": 0x12,
    "VK_ALT": 0x12,
    "VK_PAUSE": 0x13,
    "VK_CAPITAL": 0x14,
    "VK_CAPSLOCK": 0x14,
    "VK_ESCAPE": 0x1B,
    "VK_ESC": 0x1B,
    "VK_SPACE": 0x20,
    "VK_PRIOR": 0x21,
    "VK_PAGEUP": 0x21,
    "VK_NEXT": 0x22,
    "VK_PAGEDOWN": 0x22,
    "VK_END": 0x23,
    "VK_HOME": 0x24,
    "VK_LEFT": 0x25,
    "VK_UP": 0x26,
    "VK_RIGHT": 0x27,
    "VK_DOWN": 0x28,
    "VK_INSERT": 0x2D,
    "VK_DELETE": 0x2E,
    # Left / Right variant modifiers
    "VK_LSHIFT": 0xA0,
    "VK_RSHIFT": 0xA1,
    "VK_LCONTROL": 0xA2,
    "VK_RCONTROL": 0xA3,
    "VK_LMENU": 0xA4,
    "VK_RMENU": 0xA5,
    "VK_LALT": 0xA4,
    "VK_RALT": 0xA5,
}

# Add standard letters A-Z (VK_A = 0x41)
for c in range(ord("A"), ord("Z") + 1):
    char = chr(c)
    _VK_NAME_MAP[f"VK_{char}"] = c
    _VK_NAME_MAP[char] = c

# Add digits 0-9 (VK_0 = 0x30)
for d in range(ord("0"), ord("9") + 1):
    digit = chr(d)
    _VK_NAME_MAP[f"VK_{digit}"] = d
    _VK_NAME_MAP[digit] = d

# Add function keys F1-F24 (VK_F1 = 0x70)
for f in range(1, 25):
    _VK_NAME_MAP[f"VK_F{f}"] = 0x70 + (f - 1)
    _VK_NAME_MAP[f"F{f}"] = 0x70 + (f - 1)


# ── XUSB Button Lookup ───────────────────────────────────────────────────

_XUSB_BUTTON_MAP: dict[str, vg.XUSB_BUTTON] = {
    "XUSB_GAMEPAD_DPAD_UP": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP,
    "DPAD_UP": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP,
    "DPADUP": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP,
    "XUSB_GAMEPAD_DPAD_DOWN": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN,
    "DPAD_DOWN": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN,
    "DPADDOWN": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN,
    "XUSB_GAMEPAD_DPAD_LEFT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_LEFT,
    "DPAD_LEFT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_LEFT,
    "DPADLEFT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_LEFT,
    "XUSB_GAMEPAD_DPAD_RIGHT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT,
    "DPAD_RIGHT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT,
    "DPADRIGHT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT,
    "XUSB_GAMEPAD_START": vg.XUSB_BUTTON.XUSB_GAMEPAD_START,
    "START": vg.XUSB_BUTTON.XUSB_GAMEPAD_START,
    "XUSB_GAMEPAD_BACK": vg.XUSB_BUTTON.XUSB_GAMEPAD_BACK,
    "BACK": vg.XUSB_BUTTON.XUSB_GAMEPAD_BACK,
    "XUSB_GAMEPAD_LEFT_THUMB": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB,
    "LEFT_THUMB": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB,
    "LS": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB,
    "L3": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB,
    "XUSB_GAMEPAD_RIGHT_THUMB": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB,
    "RIGHT_THUMB": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB,
    "RS": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB,
    "R3": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB,
    "XUSB_GAMEPAD_LEFT_SHOULDER": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_SHOULDER,
    "LEFT_SHOULDER": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_SHOULDER,
    "LB": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_SHOULDER,
    "XUSB_GAMEPAD_RIGHT_SHOULDER": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_SHOULDER,
    "RIGHT_SHOULDER": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_SHOULDER,
    "RB": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_SHOULDER,
    "XUSB_GAMEPAD_GUIDE": vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE,
    "GUIDE": vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE,
    "XUSB_GAMEPAD_A": vg.XUSB_BUTTON.XUSB_GAMEPAD_A,
    "A": vg.XUSB_BUTTON.XUSB_GAMEPAD_A,
    "XUSB_GAMEPAD_B": vg.XUSB_BUTTON.XUSB_GAMEPAD_B,
    "B": vg.XUSB_BUTTON.XUSB_GAMEPAD_B,
    "XUSB_GAMEPAD_X": vg.XUSB_BUTTON.XUSB_GAMEPAD_X,
    "X": vg.XUSB_BUTTON.XUSB_GAMEPAD_X,
    "XUSB_GAMEPAD_Y": vg.XUSB_BUTTON.XUSB_GAMEPAD_Y,
    "Y": vg.XUSB_BUTTON.XUSB_GAMEPAD_Y,
}

_RESERVED_DEVICE_NAMES: frozenset[str] = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

_UNSUPPORTED_CONTROLLER_TOKENS: frozenset[str] = frozenset({
    "CROSS",
    "CIRCLE",
    "TRIANGLE",
    "SQUARE",
    "L1",
    "R1",
    "L2",
    "R2",
    "SHARE",
    "OPTIONS",
    "TOUCHPAD",
    "DS4_BUTTON_CROSS",
    "DS4_BUTTON_CIRCLE",
    "DS4_BUTTON_TRIANGLE",
    "DS4_BUTTON_SQUARE",
    "DS4_BUTTON_SHOULDER_LEFT",
    "DS4_BUTTON_SHOULDER_RIGHT",
    "DS4_BUTTON_TRIGGER_LEFT",
    "DS4_BUTTON_TRIGGER_RIGHT",
    "DS4_BUTTON_SHARE",
    "DS4_BUTTON_OPTIONS",
})

INV_SQRT2: float = 1.0 / math.sqrt(2.0)

MIN_BUTTON_HOLD_TICKS: int = 6
_WHEEL_HOLD_TICKS: int = 8
_WHEEL_GAP_TICKS: int = 6


def _reject_non_finite(val: str) -> None:
    """Reject non-finite JSON constants (NaN, Infinity, -Infinity) for security."""
    raise ValueError(f"Non-finite JSON constant rejected for security: {val!r}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject JSON objects containing duplicate keys (preventing parser ambiguity / schema injection)."""
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"Duplicate key in JSON object: {k!r}")
        d[k] = v
    return d


# ── Parsing Helpers ──────────────────────────────────────────────────────

def parse_vk(val: int | str) -> int:
    """Resolve a virtual-key identifier (integer or name string) to a VK code."""
    if isinstance(val, bool):
        raise ValueError(f"Boolean values cannot be used as virtual-key codes: {val!r}")

    if not isinstance(val, (int, str)):
        raise ValueError(
            f"Virtual-key identifier must be an int or str, got {type(val).__name__}: {val!r}"
        )

    if isinstance(val, int):
        if not (1 <= val <= 255):
            raise ValueError(f"VK code out of byte range [1, 255]: {val}")
        return val

    s = val.strip()
    if not s:
        raise ValueError("Virtual-key identifier cannot be empty or whitespace.")

    if s.isdigit():
        code = int(s)
        if not (1 <= code <= 255):
            raise ValueError(f"VK code out of byte range [1, 255]: {val!r}")
        return code

    if s.startswith(("0x", "0X")):
        try:
            code = int(s, 16)
        except ValueError as err:
            raise ValueError(f"Invalid hexadecimal VK code: {val!r}") from err
        if not (1 <= code <= 255):
            raise ValueError(f"VK code out of byte range [1, 255]: {val!r}")
        return code

    upper = s.upper()
    if upper in _VK_NAME_MAP:
        return _VK_NAME_MAP[upper]

    raise ValueError(f"Unknown virtual-key name: {val!r}")


def parse_target(target: str | vg.XUSB_BUTTON) -> str | vg.XUSB_BUTTON:
    """Parse a gamepad target string or enum into either a trigger token or XUSB_BUTTON."""
    if isinstance(target, vg.XUSB_BUTTON):
        return target

    if isinstance(target, Enum):
        raise ValueError(
            f"Unsupported gamepad enum {type(target).__name__}.{target.name}: "
            "only Xbox 360 (XUSB) controls are supported."
        )

    if not isinstance(target, str):
        raise ValueError(
            f"Button mapping target must be a string, got {type(target).__name__}: {target!r}"
        )

    t = target.strip().upper()
    if not t:
        raise ValueError("Controller target button or trigger cannot be empty.")

    # Triggers
    if t in ("LT", "LEFT_TRIGGER", "TRIGGER_LEFT", "L_TRIGGER", "LTRIGGER"):
        return "LT"
    if t in ("RT", "RIGHT_TRIGGER", "TRIGGER_RIGHT", "R_TRIGGER", "RTRIGGER"):
        return "RT"

    # Explicit check for unknown triggers
    if "TRIGGER" in t:
        raise ValueError(f"Unknown controller trigger target: {target!r}")

    # Check XUSB button map
    if t in _XUSB_BUTTON_MAP:
        return _XUSB_BUTTON_MAP[t]

    # Explicit check for known PlayStation / unsupported buttons
    if t in _UNSUPPORTED_CONTROLLER_TOKENS:
        raise ValueError(
            f"Unsupported gamepad button {target!r}: PlayStation controls are not supported on Xbox 360."
        )

    raise ValueError(f"Unknown controller target button or trigger: {target!r}")


def validate_profile_path(path: Path, base_dir: Path | None = None) -> Path:
    """Validate a profile path against traversal, DOS devices, ADS, UNC, and symlinks.

    Returns the canonical resolved Path.
    """
    raw_str = str(path)

    # 1. Extended UNC / NT device paths (\\?\, \\.\)
    if raw_str.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")):
        raise ValueError(f"Extended UNC/device paths are rejected for security: {path}")

    # 2. NTFS Alternate Data Streams (colon in path beyond drive letter)
    if len(raw_str) >= 2 and raw_str[0].isalpha() and raw_str[1] == ":":
        remainder = raw_str[2:]
    else:
        remainder = raw_str
    if ":" in remainder:
        raise ValueError(f"NTFS Alternate Data Streams (colon in path) are rejected: {path}")

    # 3. Windows DOS reserved device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    for part in path.parts:
        p_clean = part
        if len(p_clean) >= 2 and p_clean[0].isalpha() and p_clean[1] == ":":
            p_clean = p_clean[2:].lstrip("\\/")
        if not p_clean:
            continue
        base_name = p_clean.split(".")[0].split(":")[0].strip().upper()
        if base_name in _RESERVED_DEVICE_NAMES:
            raise ValueError(f"Windows reserved device name rejected: {path}")

    # 4. Resolve path
    try:
        resolved_path = path.resolve()
    except OSError as err:
        raise ValueError(f"Unable to resolve profile path {path}: {err}") from err

    resolved_str = str(resolved_path)
    if resolved_str.startswith(("\\\\?\\", "\\\\.\\", "//?/", "//./")):
        raise ValueError(f"Extended UNC/device paths are rejected for security: {resolved_path}")

    if len(resolved_str) >= 2 and resolved_str[0].isalpha() and resolved_str[1] == ":":
        res_remainder = resolved_str[2:]
    else:
        res_remainder = resolved_str
    if ":" in res_remainder:
        raise ValueError(f"NTFS Alternate Data Streams (colon in path) are rejected: {resolved_path}")

    for part in resolved_path.parts:
        p_clean = part
        if len(p_clean) >= 2 and p_clean[0].isalpha() and p_clean[1] == ":":
            p_clean = p_clean[2:].lstrip("\\/")
        if not p_clean:
            continue
        base_name = p_clean.split(".")[0].split(":")[0].strip().upper()
        if base_name in _RESERVED_DEVICE_NAMES:
            raise ValueError(f"Windows reserved device name rejected: {resolved_path}")

    # 5. Symlinks rejection (on unresolved path and resolved path)
    if path.is_symlink() or resolved_path.is_symlink():
        raise ValueError(f"Symlinks are rejected for security reasons: {path}")

    # Inspect lstat attributes for symlinks and reparse points
    try:
        lst: os.stat_result | None = path.lstat()
    except OSError:
        lst = None

    if lst is not None:
        if stat.S_ISLNK(lst.st_mode):
            raise ValueError(f"Symlinks are rejected for security reasons: {path}")
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
        if getattr(lst, "st_file_attributes", 0) & reparse_flag:
            raise ValueError(f"Reparse points and junctions are rejected for security: {path}")

    # 6. Path containment when base_dir is supplied
    if base_dir is not None:
        try:
            resolved_base = base_dir.resolve()
        except OSError as err:
            raise ValueError(f"Unable to resolve base directory {base_dir}: {err}") from err

        if not resolved_path.is_relative_to(resolved_base):
            raise ValueError(
                f"Path containment violation: {resolved_path} is outside base directory {resolved_base}"
            )

    return resolved_path


# ── Data Classes ─────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class StickConfig:
    """Right stick response and smoothing settings."""
    sensitivity: float
    curve_exponent: float
    deadzone_comp: float
    decay_rate: float
    smoothing_alpha: float
    invert_y: bool = False

    def create_mapper(self) -> MouseToStickMapper:
        """Instantiate a configured MouseToStickMapper."""
        return MouseToStickMapper(
            sensitivity=self.sensitivity,
            curve_exponent=self.curve_exponent,
            deadzone_comp=self.deadzone_comp,
            decay_rate=self.decay_rate,
            smoothing_alpha=self.smoothing_alpha,
            invert_y=self.invert_y,
        )


@dataclass(frozen=True, slots=True)
class WASDConfig:
    """Virtual-key codes for directional movement on Left Stick."""
    up: int
    down: int
    left: int
    right: int
    walk_key: int | None = None


# ── Profile ──────────────────────────────────────────────────────────────

class Profile:
    """A fully validated controller profile."""

    __slots__ = (
        "name",
        "file_path",
        "stick_config",
        "wasd",
        "mapper",
        "_mouse_targets",
        "_key_targets",
        "_all_buttons",
        "_uses_lt",
        "_uses_rt",
        "_wheel_up_ticks",
        "_wheel_down_ticks",
        "_wheel_up_queue",
        "_wheel_up_gap",
        "_wheel_down_queue",
        "_wheel_down_gap",
        "_hold_counters",
    )

    def __init__(
        self,
        name: str,
        file_path: Path,
        stick_config: StickConfig,
        wasd: WASDConfig,
        raw_buttons: dict[str, str],
    ) -> None:
        self.name: str = name
        self.file_path: Path = file_path
        self.stick_config: StickConfig = stick_config
        self.wasd: WASDConfig = wasd
        self.mapper: MouseToStickMapper = stick_config.create_mapper()

        # Parsed action containers
        self._mouse_targets: dict[str, list[str | vg.XUSB_BUTTON]] = {
            "left": [],
            "right": [],
            "middle": [],
            "x1": [],
            "x2": [],
            "wheel_up": [],
            "wheel_down": [],
        }
        self._key_targets: dict[int, list[str | vg.XUSB_BUTTON]] = {}
        self._all_buttons: set[vg.XUSB_BUTTON] = set()
        self._uses_lt: bool = False
        self._uses_rt: bool = False
        self._wheel_up_ticks: int = 0
        self._wheel_down_ticks: int = 0
        self._wheel_up_queue: int = 0
        self._wheel_up_gap: int = 0
        self._wheel_down_queue: int = 0
        self._wheel_down_gap: int = 0
        self._hold_counters: dict[str | vg.XUSB_BUTTON, int] = {}

        self._parse_buttons(raw_buttons)

    def _parse_buttons(self, raw_buttons: dict[str, str]) -> None:
        for src_str, tgt_str in raw_buttons.items():
            if not isinstance(src_str, str):
                raise ValueError(
                    f"Button mapping source must be a string, got {type(src_str).__name__}: {src_str!r}"
                )
            if not isinstance(tgt_str, str):
                raise ValueError(
                    f"Button mapping target must be a string, got {type(tgt_str).__name__}: {tgt_str!r}"
                )

            tgt = parse_target(tgt_str)
            if tgt == "LT":
                self._uses_lt = True
            elif tgt == "RT":
                self._uses_rt = True
            else:
                self._all_buttons.add(tgt)

            upper_src = src_str.strip().upper()
            if upper_src in ("MOUSE_LEFT", "LBUTTON", "VK_LBUTTON"):
                if tgt not in self._mouse_targets["left"]:
                    self._mouse_targets["left"].append(tgt)
            elif upper_src in ("MOUSE_RIGHT", "RBUTTON", "VK_RBUTTON"):
                if tgt not in self._mouse_targets["right"]:
                    self._mouse_targets["right"].append(tgt)
            elif upper_src in ("MOUSE_MIDDLE", "MBUTTON", "VK_MBUTTON"):
                if tgt not in self._mouse_targets["middle"]:
                    self._mouse_targets["middle"].append(tgt)
            elif upper_src in ("MOUSE_X1", "XBUTTON1", "VK_XBUTTON1"):
                if tgt not in self._mouse_targets["x1"]:
                    self._mouse_targets["x1"].append(tgt)
            elif upper_src in ("MOUSE_X2", "XBUTTON2", "VK_XBUTTON2"):
                if tgt not in self._mouse_targets["x2"]:
                    self._mouse_targets["x2"].append(tgt)
            elif upper_src in ("WHEEL_UP", "MOUSE_WHEEL_UP"):
                if tgt not in self._mouse_targets["wheel_up"]:
                    self._mouse_targets["wheel_up"].append(tgt)
            elif upper_src in ("WHEEL_DOWN", "MOUSE_WHEEL_DOWN"):
                if tgt not in self._mouse_targets["wheel_down"]:
                    self._mouse_targets["wheel_down"].append(tgt)
            else:
                vk = parse_vk(src_str)
                targets = self._key_targets.setdefault(vk, [])
                if tgt not in targets:
                    targets.append(tgt)

    def compute_left_stick(self, keys_pressed: frozenset[int] | set[int] | None) -> tuple[int, int]:
        """Convert WASD key states into normalized 16-bit left thumbstick integers.

        Returns (lx, ly) in [-32768, 32767].
        In XInput, +Y is UP and +X is RIGHT.
        """
        if keys_pressed is None:
            return (0, 0)

        up = 1 if self.wasd.up in keys_pressed else 0
        down = 1 if self.wasd.down in keys_pressed else 0
        left = 1 if self.wasd.left in keys_pressed else 0
        right = 1 if self.wasd.right in keys_pressed else 0

        wx = right - left
        wy = up - down

        if wx == 0 and wy == 0:
            return (0, 0)

        if wx != 0 and wy != 0:
            # Diagonal input: normalize to unit circle so magnitude <= 1.0
            lx = int(wx * 32767 * INV_SQRT2 + 0.5) if wx > 0 else -int(-wx * 32768 * INV_SQRT2 + 0.5)
            ly = int(wy * 32767 * INV_SQRT2 + 0.5) if wy > 0 else -int(-wy * 32768 * INV_SQRT2 + 0.5)
        else:
            lx = 32767 if wx > 0 else (-32768 if wx < 0 else 0)
            ly = 32767 if wy > 0 else (-32768 if wy < 0 else 0)

        if self.wasd.walk_key is not None and self.wasd.walk_key in keys_pressed:
            lx = int(lx * 0.5)
            ly = int(ly * 0.5)

        lx = max(-32768, min(32767, lx))
        ly = max(-32768, min(32767, ly))
        return (lx, ly)

    def apply_buttons(
        self,
        gamepad: vg.VX360Gamepad,
        keys_pressed: frozenset[int] | set[int] | None,
        lbutton: bool,
        rbutton: bool,
        mbutton: bool,
        xbutton1: bool = False,
        xbutton2: bool = False,
        wheel_delta: int = 0,
    ) -> None:
        """Map held keys, mouse buttons, and scroll wheel to virtual gamepad controls."""
        active_buttons: set[vg.XUSB_BUTTON] = set()
        lt_active = False
        rt_active = False
        keys = keys_pressed if keys_pressed is not None else frozenset()

        # Update wheel queue and ticks
        if wheel_delta > 0:
            notches = max(1, abs(wheel_delta) // 120)
            if self._wheel_up_ticks == 0 and self._wheel_up_gap == 0:
                self._wheel_up_ticks = _WHEEL_HOLD_TICKS
                self._wheel_up_queue = min(5, self._wheel_up_queue + (notches - 1))
            else:
                self._wheel_up_queue = min(5, self._wheel_up_queue + notches)
        elif wheel_delta < 0:
            notches = max(1, abs(wheel_delta) // 120)
            if self._wheel_down_ticks == 0 and self._wheel_down_gap == 0:
                self._wheel_down_ticks = _WHEEL_HOLD_TICKS
                self._wheel_down_queue = min(5, self._wheel_down_queue + (notches - 1))
            else:
                self._wheel_down_queue = min(5, self._wheel_down_queue + notches)

        wheel_up_active = False
        if self._wheel_up_ticks > 0:
            wheel_up_active = True
            self._wheel_up_ticks -= 1
            if self._wheel_up_ticks == 0 and self._wheel_up_queue > 0:
                self._wheel_up_gap = _WHEEL_GAP_TICKS
        elif self._wheel_up_gap > 0:
            self._wheel_up_gap -= 1
            if self._wheel_up_gap == 0 and self._wheel_up_queue > 0:
                self._wheel_up_queue -= 1
                self._wheel_up_ticks = _WHEEL_HOLD_TICKS

        wheel_down_active = False
        if self._wheel_down_ticks > 0:
            wheel_down_active = True
            self._wheel_down_ticks -= 1
            if self._wheel_down_ticks == 0 and self._wheel_down_queue > 0:
                self._wheel_down_gap = _WHEEL_GAP_TICKS
        elif self._wheel_down_gap > 0:
            self._wheel_down_gap -= 1
            if self._wheel_down_gap == 0 and self._wheel_down_queue > 0:
                self._wheel_down_queue -= 1
                self._wheel_down_ticks = _WHEEL_HOLD_TICKS

        # ── Physical inputs ──
        physical_targets: set[str | vg.XUSB_BUTTON] = set()
        if lbutton:
            physical_targets.update(self._mouse_targets["left"])
        if rbutton:
            physical_targets.update(self._mouse_targets["right"])
        if mbutton:
            physical_targets.update(self._mouse_targets["middle"])
        if xbutton1:
            physical_targets.update(self._mouse_targets["x1"])
        if xbutton2:
            physical_targets.update(self._mouse_targets["x2"])

        for vk, targets in self._key_targets.items():
            if vk in keys:
                physical_targets.update(targets)

        # ── Sub-frame hold counters ──
        active_physical_or_held: set[str | vg.XUSB_BUTTON] = set(physical_targets)
        for tgt in physical_targets:
            self._hold_counters[tgt] = MIN_BUTTON_HOLD_TICKS

        for tgt in list(self._hold_counters):
            if tgt not in physical_targets:
                if self._hold_counters[tgt] > 0:
                    self._hold_counters[tgt] -= 1
                    active_physical_or_held.add(tgt)
                if self._hold_counters[tgt] == 0:
                    del self._hold_counters[tgt]

        for tgt in active_physical_or_held:
            if tgt == "RT":
                rt_active = True
            elif tgt == "LT":
                lt_active = True
            else:
                active_buttons.add(tgt)

        # ── Wheel pulse actions (independent of hold counters to maintain release gap) ──
        if wheel_up_active:
            for tgt in self._mouse_targets["wheel_up"]:
                if tgt == "RT":
                    rt_active = True
                elif tgt == "LT":
                    lt_active = True
                else:
                    active_buttons.add(tgt)

        if wheel_down_active:
            for tgt in self._mouse_targets["wheel_down"]:
                if tgt == "RT":
                    rt_active = True
                elif tgt == "LT":
                    lt_active = True
                else:
                    active_buttons.add(tgt)

        # ── Commit triggers ──
        if self._uses_lt:
            gamepad.left_trigger(value=255 if lt_active else 0)
        else:
            gamepad.left_trigger(value=0)

        if self._uses_rt:
            gamepad.right_trigger(value=255 if rt_active else 0)
        else:
            gamepad.right_trigger(value=0)

        # ── Commit buttons ──
        for btn in self._all_buttons:
            if btn in active_buttons:
                gamepad.press_button(button=btn)
            else:
                gamepad.release_button(button=btn)

    def reset_controls(self, gamepad: vg.VX360Gamepad) -> None:
        """Release all mapped buttons and triggers on the virtual gamepad."""
        for btn in self._all_buttons:
            gamepad.release_button(button=btn)
        gamepad.left_trigger(value=0)
        gamepad.right_trigger(value=0)
        self._wheel_up_ticks = 0
        self._wheel_down_ticks = 0
        self._wheel_up_queue = 0
        self._wheel_up_gap = 0
        self._wheel_down_queue = 0
        self._wheel_down_gap = 0
        self._hold_counters.clear()
        self.mapper.reset()


# ── Profile Manager ──────────────────────────────────────────────────────

class ProfileManager:
    """Discovers, validates, and cycles JSON controller profiles at runtime."""

    def __init__(
        self,
        profiles_dir: Path | str,
        default_name: str | None = "Shooter",
    ) -> None:
        self.profiles_dir = Path(profiles_dir)
        self.profiles: list[Profile] = []
        self.current_index: int = 0

        self.reload(default_name=default_name)

    @property
    def current_profile(self) -> Profile:
        """The currently active Profile."""
        if not self.profiles:
            raise RuntimeError("No profiles loaded.")
        return self.profiles[self.current_index]

    def reload(self, default_name: str | None = None) -> None:
        """Load and validate all profile JSON files from the directory."""
        if not self.profiles_dir.is_dir():
            raise FileNotFoundError(f"Profiles directory does not exist: {self.profiles_dir}")

        validate_profile_path(self.profiles_dir)

        json_files = sorted(p for p in self.profiles_dir.glob("*.json") if p.is_file())
        if not json_files:
            raise FileNotFoundError(f"No .json profile files found in {self.profiles_dir}")

        loaded: list[Profile] = []
        errors: list[str] = []
        for p in json_files:
            try:
                profile = self.load_profile(p, base_dir=self.profiles_dir)
                loaded.append(profile)
            except Exception as err:
                errors.append(f"{p.name}: {err}")

        if not loaded:
            raise ValueError(f"No valid profiles found in {self.profiles_dir}. Errors: {errors}")

        self.profiles = loaded

        # Set default active profile if requested
        if default_name:
            target = default_name.strip().lower()
            matched_idx: int | None = None
            for idx, prof in enumerate(self.profiles):
                if (
                    prof.name.lower() == target
                    or prof.file_path.stem.lower() == target
                    or prof.file_path.name.lower() == target
                ):
                    matched_idx = idx
                    break

            if matched_idx is None:
                norm_target = "".join(c for c in target if c.isalnum())
                if norm_target:
                    for idx, prof in enumerate(self.profiles):
                        norm_name = "".join(c for c in prof.name.lower() if c.isalnum())
                        norm_stem = "".join(c for c in prof.file_path.stem.lower() if c.isalnum())
                        if (
                            norm_target in (norm_name, norm_stem)
                            or norm_name.startswith(norm_target)
                            or norm_stem.startswith(norm_target)
                        ):
                            matched_idx = idx
                            break

            self.current_index = matched_idx if matched_idx is not None else 0
        else:
            self.current_index = 0

    @staticmethod
    def load_profile(path: Path, base_dir: Path | None = None) -> Profile:
        """Load and validate a single profile from a JSON file.

        Hardened against TOCTOU race conditions, symlink bypasses, path
        traversals, ADS, device names, non-finite numeric injection,
        and descriptor leaks.
        """
        resolved_path = validate_profile_path(path, base_dir=base_dir)

        # Open file descriptor first to eliminate TOCTOU window
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        try:
            fd = os.open(str(resolved_path), flags)
        except OSError as err:
            raise ValueError(f"Unable to open profile {resolved_path}: {err}") from err

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"Profile path is not a regular file: {resolved_path}")

            # On Windows, reject NTFS junctions and reparse points
            file_attrs = getattr(st, "st_file_attributes", 0)
            reparse_point_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
            if file_attrs & reparse_point_flag:
                raise ValueError(
                    f"Reparse points and junctions are rejected for security: {resolved_path}"
                )

            if st.st_size > 65536:
                raise ValueError(
                    f"Profile file {resolved_path} exceeds maximum permitted size of 64 KB ({st.st_size} bytes)."
                )

            # Read bounded chunks directly from fd so descriptor is guaranteed closed before decoding/parsing
            chunks: list[bytes] = []
            total_read = 0
            while total_read <= 65536:
                chunk = os.read(fd, 65536 - total_read + 1)
                if not chunk:
                    break
                chunks.append(chunk)
                total_read += len(chunk)

            if total_read > 65536:
                raise ValueError(
                    f"Profile file {resolved_path} exceeds maximum permitted size of 64 KB."
                )
            raw_bytes = b"".join(chunks)
        finally:
            with contextlib.suppress(OSError):
                os.close(fd)

        # Decode UTF-8 safely with closed fd
        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as err:
            raise ValueError(
                f"Profile file {resolved_path} is not valid UTF-8: {err}"
            ) from err

        # Parse JSON rejecting duplicate keys and non-finite constants
        try:
            data = json.loads(
                raw_text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_non_finite,
            )
        except Exception as err:
            raise ValueError(f"Invalid JSON in profile {resolved_path}: {err}") from err

        if not isinstance(data, dict):
            raise ValueError(
                f"Profile {resolved_path}: Root must be a JSON object, got {type(data).__name__}."
            )

        # Check unexpected top-level keys
        allowed_top = {"name", "stick_config", "wasd_left_stick", "buttons"}
        unexpected_top = set(data.keys()) - allowed_top
        if unexpected_top:
            raise ValueError(
                f"Profile {resolved_path}: Unexpected top-level key(s) in schema: {sorted(unexpected_top)}"
            )

        name = data.get("name")
        if not isinstance(name, str) or not name.strip() or len(name.strip()) > 64:
            raise ValueError(f"Profile {resolved_path} missing valid 'name' string.")

        # ── Stick config ──
        raw_stick = data.get("stick_config")
        if not isinstance(raw_stick, dict):
            raise ValueError(f"Profile {resolved_path} missing 'stick_config' object.")

        allowed_stick_keys = {"sensitivity", "curve_exponent", "deadzone_comp", "decay_rate", "smoothing_alpha", "invert_y"}
        unexpected_stick = set(raw_stick.keys()) - allowed_stick_keys
        if unexpected_stick:
            raise ValueError(
                f"Profile {resolved_path}: Unexpected key(s) in 'stick_config': {sorted(unexpected_stick)}"
            )

        required_stick_keys = ("sensitivity", "curve_exponent", "deadzone_comp", "decay_rate", "smoothing_alpha")
        for k in required_stick_keys:
            if k not in raw_stick:
                raise ValueError(f"Profile {resolved_path}: Missing required parameter in 'stick_config': '{k}'.")
            val = raw_stick[k]
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                raise ValueError(
                    f"Profile {resolved_path}: '{k}' must be a numeric float/int, got {type(val).__name__}."
                )
            if not math.isfinite(float(val)):
                raise ValueError(
                    f"Profile {resolved_path}: '{k}' must be a finite number, got {val}."
                )

        sensitivity = float(raw_stick["sensitivity"])
        curve_exponent = float(raw_stick["curve_exponent"])
        deadzone_comp = float(raw_stick["deadzone_comp"])
        decay_rate = float(raw_stick["decay_rate"])
        smoothing_alpha = float(raw_stick["smoothing_alpha"])

        # Explicit type check for invert_y to avoid bool("false") == True pitfall
        if "invert_y" in raw_stick:
            raw_inv = raw_stick["invert_y"]
            if not isinstance(raw_inv, bool):
                raise ValueError(
                    f"Profile {resolved_path}: 'invert_y' must be a boolean (true/false), got {type(raw_inv).__name__}."
                )
            invert_y = raw_inv
        else:
            invert_y = False

        if sensitivity <= 0 or sensitivity > 100.0:
            raise ValueError(f"Profile {path}: sensitivity must be > 0 and <= 100.0.")
        if curve_exponent <= 0 or curve_exponent > 10.0:
            raise ValueError(f"Profile {path}: curve_exponent must be > 0 and <= 10.0.")
        if not (0.0 <= deadzone_comp <= 0.35):
            raise ValueError(f"Profile {path}: deadzone_comp must be in [0.0, 0.35].")
        if not (0.0 <= decay_rate <= 1.0):
            raise ValueError(f"Profile {path}: decay_rate must be in [0.0, 1.0].")
        if not (0.0 < smoothing_alpha <= 1.0):
            raise ValueError(f"Profile {path}: smoothing_alpha must be in (0.0, 1.0].")

        stick_config = StickConfig(
            sensitivity=sensitivity,
            curve_exponent=curve_exponent,
            deadzone_comp=deadzone_comp,
            decay_rate=decay_rate,
            smoothing_alpha=smoothing_alpha,
            invert_y=invert_y,
        )

        # ── WASD left stick config ──
        raw_wasd = data.get("wasd_left_stick")
        if not isinstance(raw_wasd, dict):
            raise ValueError(f"Profile {path} missing 'wasd_left_stick' object.")

        allowed_wasd_keys = {"up", "down", "left", "right", "walk"}
        unexpected_wasd = set(raw_wasd.keys()) - allowed_wasd_keys
        if unexpected_wasd:
            raise ValueError(
                f"Profile {path}: Unexpected key(s) in 'wasd_left_stick': {sorted(unexpected_wasd)}"
            )

        for dir_key in ("up", "down", "left", "right"):
            if dir_key not in raw_wasd:
                raise ValueError(f"Profile {path}: Missing required direction '{dir_key}' in 'wasd_left_stick'.")

        try:
            up_vk = parse_vk(raw_wasd["up"])
            down_vk = parse_vk(raw_wasd["down"])
            left_vk = parse_vk(raw_wasd["left"])
            right_vk = parse_vk(raw_wasd["right"])
            walk_vk = parse_vk(raw_wasd["walk"]) if "walk" in raw_wasd else None
        except (KeyError, ValueError) as err:
            raise ValueError(f"Profile {path} invalid 'wasd_left_stick': {err}") from err

        wasd_vks = [up_vk, down_vk, left_vk, right_vk]
        if len(set(wasd_vks)) != 4:
            raise ValueError(
                f"Profile {path}: Duplicate keys in 'wasd_left_stick': all 4 movement directions must be unique."
            )

        wasd = WASDConfig(up=up_vk, down=down_vk, left=left_vk, right=right_vk, walk_key=walk_vk)

        # ── Buttons mapping ──
        raw_buttons = data.get("buttons")
        if not isinstance(raw_buttons, dict):
            raise ValueError(f"Profile {path} missing 'buttons' dictionary.")

        return Profile(
            name=name.strip(),
            file_path=path,
            stick_config=stick_config,
            wasd=wasd,
            raw_buttons=raw_buttons,
        )

    def cycle(self) -> Profile:
        """Cycle to the next available profile and reset its stick mapper."""
        if not self.profiles:
            raise RuntimeError("No profiles available to cycle.")
        self.current_index = (self.current_index + 1) % len(self.profiles)
        new_profile = self.current_profile
        new_profile.mapper.reset()
        return new_profile


# ── Self-test ────────────────────────────────────────────────────────────

def main() -> None:
    """Unit test for profile loading, validation, left-stick WASD, and cycling."""
    profiles_dir = Path(__file__).parent / "profiles"
    print("profiles.py — unit tests")
    print("=" * 60)

    mgr = ProfileManager(profiles_dir=profiles_dir, default_name="Shooter")
    print(f"Loaded {len(mgr.profiles)} profiles: {[p.name for p in mgr.profiles]}")
    assert mgr.current_profile.name == "Shooter", f"Expected Shooter default, got {mgr.current_profile.name}"

    # Test WASD diagonal normalization
    prof = mgr.current_profile
    w_vk, d_vk = prof.wasd.up, prof.wasd.right
    lx, ly = prof.compute_left_stick(frozenset({w_vk, d_vk}))
    mag = math.hypot(lx, ly)
    print(f"WASD Diagonal (W+D): lx={lx}, ly={ly}, magnitude={mag:.1f}")
    assert mag <= 32767.5, f"Diagonal magnitude exceeds 32767: {mag}"

    # Test Profile Cycling
    first = mgr.current_profile.name
    cycled = mgr.cycle().name
    print(f"Cycled: {first} -> {cycled}")
    assert cycled != first, "Profile cycle did not change profile"

    print("=" * 60)
    print("Result: all profile tests PASSED.")


if __name__ == "__main__":
    main()
