"""Gamepad profile system for loading, validating, and cycling mappings.

Loads JSON profile definitions (e.g. Shooter, RTS/Menu), validates
stick sensitivity / response curves and button/trigger mappings,
and manages profile cycling at runtime.
"""

from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import dataclass
from pathlib import Path

import vgamepad as vg

from stick_mapper import MouseToStickMapper

# ── Win32 Virtual Key Lookup ─────────────────────────────────────────────

VK_F9: int = 0x78

# Map string names to Win32 Virtual-Key codes
_VK_NAME_MAP: dict[str, int] = {
    # Mouse buttons (tokens used in profile JSON)
    "MOUSE_LEFT": 0x01,
    "MOUSE_RIGHT": 0x02,
    "MOUSE_MIDDLE": 0x04,
    "MOUSE_X1": 0x05,
    "MOUSE_X2": 0x06,
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
    "XUSB_GAMEPAD_DPAD_DOWN": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN,
    "DPAD_DOWN": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN,
    "XUSB_GAMEPAD_DPAD_LEFT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_LEFT,
    "DPAD_LEFT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_LEFT,
    "XUSB_GAMEPAD_DPAD_RIGHT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT,
    "DPAD_RIGHT": vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT,
    "XUSB_GAMEPAD_START": vg.XUSB_BUTTON.XUSB_GAMEPAD_START,
    "START": vg.XUSB_BUTTON.XUSB_GAMEPAD_START,
    "XUSB_GAMEPAD_BACK": vg.XUSB_BUTTON.XUSB_GAMEPAD_BACK,
    "BACK": vg.XUSB_BUTTON.XUSB_GAMEPAD_BACK,
    "XUSB_GAMEPAD_LEFT_THUMB": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB,
    "LS": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB,
    "L3": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB,
    "XUSB_GAMEPAD_RIGHT_THUMB": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB,
    "RS": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB,
    "R3": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB,
    "XUSB_GAMEPAD_LEFT_SHOULDER": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_SHOULDER,
    "LB": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_SHOULDER,
    "XUSB_GAMEPAD_RIGHT_SHOULDER": vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_SHOULDER,
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

INV_SQRT2: float = 1.0 / math.sqrt(2.0)


def _reject_non_finite(val: str) -> None:
    """Reject non-finite JSON constants (NaN, Infinity, -Infinity) for security."""
    raise ValueError(f"Non-finite JSON constant rejected for security: {val!r}")


# ── Parsing Helpers ──────────────────────────────────────────────────────

def parse_vk(val: int | str) -> int:
    """Resolve a virtual-key identifier (integer or name string) to a VK code."""
    if isinstance(val, int):
        if not (0 <= val <= 255):
            raise ValueError(f"VK code out of byte range [0, 255]: {val}")
        return val

    s = str(val).strip()
    if s.isdigit():
        return int(s)
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)

    upper = s.upper()
    if upper in _VK_NAME_MAP:
        return _VK_NAME_MAP[upper]

    raise ValueError(f"Unknown virtual-key name: {val!r}")


def parse_target(target_str: str) -> str | vg.XUSB_BUTTON:
    """Parse a gamepad target string into either a trigger token or XUSB_BUTTON."""
    t = target_str.strip().upper()
    if t in ("LT", "LEFT_TRIGGER"):
        return "LT"
    if t in ("RT", "RIGHT_TRIGGER"):
        return "RT"
    if t in _XUSB_BUTTON_MAP:
        return _XUSB_BUTTON_MAP[t]

    raise ValueError(f"Unknown controller target button or trigger: {target_str!r}")


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
        }
        self._key_targets: dict[int, list[str | vg.XUSB_BUTTON]] = {}
        self._all_buttons: set[vg.XUSB_BUTTON] = set()
        self._uses_lt: bool = False
        self._uses_rt: bool = False

        self._parse_buttons(raw_buttons)

    def _parse_buttons(self, raw_buttons: dict[str, str]) -> None:
        for src_str, tgt_str in raw_buttons.items():
            tgt = parse_target(tgt_str)
            if tgt == "LT":
                self._uses_lt = True
            elif tgt == "RT":
                self._uses_rt = True
            else:
                self._all_buttons.add(tgt)

            upper_src = src_str.strip().upper()
            if upper_src in ("MOUSE_LEFT", "LBUTTON"):
                self._mouse_targets["left"].append(tgt)
            elif upper_src in ("MOUSE_RIGHT", "RBUTTON"):
                self._mouse_targets["right"].append(tgt)
            elif upper_src in ("MOUSE_MIDDLE", "MBUTTON"):
                self._mouse_targets["middle"].append(tgt)
            elif upper_src in ("MOUSE_X1", "XBUTTON1"):
                self._mouse_targets["x1"].append(tgt)
            elif upper_src in ("MOUSE_X2", "XBUTTON2"):
                self._mouse_targets["x2"].append(tgt)
            else:
                vk = parse_vk(src_str)
                self._key_targets.setdefault(vk, []).append(tgt)

    def compute_left_stick(self, keys_pressed: frozenset[int]) -> tuple[int, int]:
        """Convert WASD key states into normalized 16-bit left thumbstick integers.

        Returns (lx, ly) in [-32768, 32767].
        In XInput, +Y is UP and +X is RIGHT.
        """
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

        return (lx, ly)

    def apply_buttons(
        self,
        gamepad: vg.VX360Gamepad,
        keys_pressed: frozenset[int],
        lbutton: bool,
        rbutton: bool,
        mbutton: bool,
        xbutton1: bool = False,
        xbutton2: bool = False,
    ) -> None:
        """Map held keys and mouse buttons to virtual gamepad controls."""
        active_buttons: set[vg.XUSB_BUTTON] = set()
        lt_active = False
        rt_active = False

        # ── Mouse button actions ──
        if lbutton:
            for tgt in self._mouse_targets["left"]:
                if tgt == "RT":
                    rt_active = True
                elif tgt == "LT":
                    lt_active = True
                else:
                    active_buttons.add(tgt)

        if rbutton:
            for tgt in self._mouse_targets["right"]:
                if tgt == "RT":
                    rt_active = True
                elif tgt == "LT":
                    lt_active = True
                else:
                    active_buttons.add(tgt)

        if mbutton:
            for tgt in self._mouse_targets["middle"]:
                if tgt == "RT":
                    rt_active = True
                elif tgt == "LT":
                    lt_active = True
                else:
                    active_buttons.add(tgt)

        if xbutton1:
            for tgt in self._mouse_targets["x1"]:
                if tgt == "RT":
                    rt_active = True
                elif tgt == "LT":
                    lt_active = True
                else:
                    active_buttons.add(tgt)

        if xbutton2:
            for tgt in self._mouse_targets["x2"]:
                if tgt == "RT":
                    rt_active = True
                elif tgt == "LT":
                    lt_active = True
                else:
                    active_buttons.add(tgt)

        # ── Keyboard actions ──
        for vk, targets in self._key_targets.items():
            if vk in keys_pressed:
                for tgt in targets:
                    if tgt == "RT":
                        rt_active = True
                    elif tgt == "LT":
                        lt_active = True
                    else:
                        active_buttons.add(tgt)

        # ── Commit triggers ──
        if self._uses_lt:
            gamepad.left_trigger(value=255 if lt_active else 0)
        if self._uses_rt:
            gamepad.right_trigger(value=255 if rt_active else 0)

        # ── Commit buttons ──
        for btn in self._all_buttons:
            if btn in active_buttons:
                gamepad.press_button(button=btn)
            else:
                gamepad.release_button(button=btn)


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

        json_files = sorted(self.profiles_dir.glob("*.json"))
        if not json_files:
            raise FileNotFoundError(f"No .json profile files found in {self.profiles_dir}")

        loaded: list[Profile] = []
        for p in json_files:
            profile = self.load_profile(p, base_dir=self.profiles_dir)
            loaded.append(profile)

        self.profiles = loaded

        # Set default active profile if requested
        if default_name:
            target = default_name.strip().lower()
            for idx, prof in enumerate(self.profiles):
                if prof.name.lower() == target or prof.file_path.stem.lower() == target:
                    self.current_index = idx
                    break
            else:
                self.current_index = 0
        else:
            self.current_index = 0

    @staticmethod
    def load_profile(path: Path, base_dir: Path | None = None) -> Profile:
        """Load and validate a single profile from a JSON file.

        Hardened against TOCTOU race conditions, symlink bypasses, path
        traversals, and non-finite numeric injection.
        """
        resolved_path = path.resolve()

        # Security check: explicit symlink rejection
        if path.is_symlink() or resolved_path.is_symlink():
            raise ValueError(f"Symlinks are rejected for security reasons: {path}")

        # Enforce path containment when base_dir is supplied
        if base_dir is not None:
            resolved_base = base_dir.resolve()
            if not resolved_path.is_relative_to(resolved_base):
                raise ValueError(
                    f"Path containment violation: {resolved_path} is outside base directory {resolved_base}"
                )

        # Open file descriptor first to eliminate TOCTOU window
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
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
            if st.st_size > 65536:
                raise ValueError(
                    f"Profile file {resolved_path} exceeds maximum permitted size of 64 KB ({st.st_size} bytes)."
                )

            with os.fdopen(fd, "r", encoding="utf-8") as f:
                raw_text = f.read(65537)
                if len(raw_text) > 65536:
                    raise ValueError(
                        f"Profile file {resolved_path} exceeds maximum permitted size of 64 KB."
                    )
            fd = -1  # os.fdopen took ownership and closed the descriptor
        finally:
            if fd >= 0:
                os.close(fd)

        # Reject non-finite constants (NaN, Infinity, -Infinity)
        try:
            data = json.loads(raw_text, parse_constant=_reject_non_finite)
        except Exception as err:
            raise ValueError(f"Invalid JSON in profile {resolved_path}: {err}") from err

        name = data.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"Profile {resolved_path} missing valid 'name' string.")

        # ── Stick config ──
        raw_stick = data.get("stick_config")
        if not isinstance(raw_stick, dict):
            raise ValueError(f"Profile {resolved_path} missing 'stick_config' object.")

        try:
            sensitivity = float(raw_stick["sensitivity"])
            curve_exponent = float(raw_stick["curve_exponent"])
            deadzone_comp = float(raw_stick["deadzone_comp"])
            decay_rate = float(raw_stick["decay_rate"])
            smoothing_alpha = float(raw_stick["smoothing_alpha"])
        except (KeyError, TypeError, ValueError) as err:
            raise ValueError(f"Profile {resolved_path} invalid 'stick_config': {err}") from err

        # Verify finite numbers
        for num_val, num_name in [
            (sensitivity, "sensitivity"),
            (curve_exponent, "curve_exponent"),
            (deadzone_comp, "deadzone_comp"),
            (decay_rate, "decay_rate"),
            (smoothing_alpha, "smoothing_alpha"),
        ]:
            if not math.isfinite(num_val):
                raise ValueError(
                    f"Profile {resolved_path}: '{num_name}' must be a finite number, got {num_val}."
                )

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

        if sensitivity <= 0:
            raise ValueError(f"Profile {path}: sensitivity must be > 0.")
        if curve_exponent <= 0:
            raise ValueError(f"Profile {path}: curve_exponent must be > 0.")
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

        try:
            up_vk = parse_vk(raw_wasd["up"])
            down_vk = parse_vk(raw_wasd["down"])
            left_vk = parse_vk(raw_wasd["left"])
            right_vk = parse_vk(raw_wasd["right"])
        except (KeyError, ValueError) as err:
            raise ValueError(f"Profile {path} invalid 'wasd_left_stick': {err}") from err

        wasd = WASDConfig(up=up_vk, down=down_vk, left=left_vk, right=right_vk)

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
