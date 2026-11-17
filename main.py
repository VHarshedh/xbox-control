"""Main application entry point for the Mouse & Keyboard to Xbox 360 controller mapper.

Integrates ViGEmBus driver verification, low-level Win32 input hooks,
high-precision 250 Hz hybrid timer, profile management, and virtual
gamepad report delivery.
"""

from __future__ import annotations

import argparse
import atexit
import contextlib
import ctypes
import ctypes.wintypes as wt
import logging
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

import vgamepad as vg

from driver_check import (
    check_architecture,
    check_python_version,
    check_vgamepad_controller,
    check_vigembus_service,
    check_windows_os,
    is_headless_ci,
)
from input_hooks import VK_F8, InputHookManager
from profiles import ProfileManager
from stick_mapper import TARGET_HZ, HighResTimer, _track_period_released, _winmm

logger = logging.getLogger("vg_mapper")

# ── Win32 Function Prototypes & Types ────────────────────────────────────

PHANDLER_ROUTINE = ctypes.WINFUNCTYPE(wt.BOOL, wt.DWORD)

_user32: Any = None
try:
    _user32 = ctypes.windll.user32  # type: ignore[attr-defined]
    _user32.ClipCursor.argtypes = [ctypes.c_void_p]
    _user32.ClipCursor.restype = wt.BOOL
except Exception:
    _user32 = None

_kernel32: Any = None
try:
    _kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    _kernel32.SetConsoleCtrlHandler.argtypes = [PHANDLER_ROUTINE, wt.BOOL]
    _kernel32.SetConsoleCtrlHandler.restype = wt.BOOL
except Exception:
    _kernel32 = None

# Reserved MS-DOS/Windows device names (case-insensitive)
_RESERVED_DEVICE_NAMES: frozenset[str] = frozenset({
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
})

MAX_CONSECUTIVE_TICK_ERRORS: int = 50
TICK_ERROR_LOG_INTERVAL_SEC: float = 1.0


# ── CLI & Profile Name Validation ────────────────────────────────────────


def validate_profile_name(name: str) -> tuple[bool, str]:
    """Validate profile name against path traversal, reserved names, and malformed inputs.

    Returns (is_valid, failure_reason).
    """
    if not isinstance(name, str):
        return False, "Profile name must be a string."

    stripped = name.strip()
    if not stripped:
        return False, "Profile name cannot be empty or whitespace."

    if len(stripped) > 64:
        return False, f"Profile name exceeds maximum length of 64 characters (got {len(stripped)})."

    if "\0" in stripped:
        return False, "Profile name contains forbidden null byte."

    if ":" in stripped:
        return False, "Profile name contains forbidden NTFS Alternate Data Stream separator (':')."

    if "/" in stripped or "\\" in stripped or ".." in stripped:
        return False, "Profile name contains forbidden path separators or traversal components ('..')."

    if stripped.endswith("."):
        return False, "Profile name cannot end with a period."

    # Check for reserved Windows device names (e.g. CON, NUL, COM1, CON.json)
    base_stem = Path(stripped).stem.upper()
    if base_stem in _RESERVED_DEVICE_NAMES:
        return False, f"Profile name '{stripped}' refers to a reserved Windows device name."

    # Check forbidden characters for Windows filesystem naming
    forbidden_chars = set('<>"/\\|?*')
    found_forbidden = forbidden_chars.intersection(stripped)
    if found_forbidden:
        return False, f"Profile name contains forbidden characters: {' '.join(sorted(found_forbidden))}"

    return True, ""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for profile selection, listing, and verbosity."""
    parser = argparse.ArgumentParser(
        description="High-performance mouse & keyboard to Xbox 360 virtual controller mapper."
    )
    parser.add_argument(
        "--check",
        "-c",
        action="store_true",
        help="Verify system requirements, driver status, and exit",
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Run in headless CI mode (skips physical driver checks if absent)",
    )
    parser.add_argument(
        "--profile",
        "-p",
        type=str,
        default=None,
        help="Initial profile name or filename (default: Shooter)",
    )
    parser.add_argument(
        "--list-profiles",
        "-l",
        action="store_true",
        help="List all available profiles and exit",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable detailed diagnostic logging",
    )
    return parser.parse_args(argv)


# ── Failsafe Lifecycle Management ────────────────────────────────────────


class AppLifecycle:
    """Manages application lifecycle and guarantees failsafe resource teardown.

    Guarantees that under all exit paths (normal completion, SIGINT, SIGTERM,
    Windows console close/logoff/shutdown, or unhandled runtime exceptions):
    1. Virtual Xbox 360 controller is neutralized and released.
    2. Low-level Win32 hooks are unhooked and hook thread is stopped.
    3. Any cursor clipping or confinement is cleared.
    4. WinMM high-resolution timer period (timeEndPeriod) is restored.
    """

    def __init__(self) -> None:
        self.gamepad: vg.VX360Gamepad | None = None
        self.hooks: InputHookManager | None = None
        self.timer: HighResTimer | None = None
        self.timer_entered: bool = False
        self.shutdown_event = threading.Event()

        self._cleanup_lock = threading.RLock()
        self._cleaned_up: bool = False
        self._console_ctrl_routine: Any = None
        self._orig_excepthook: Any = sys.excepthook
        self._orig_sigint: Any = None
        self._orig_sigterm: Any = None
        self._registered_atexit: bool = False

    def setup_handlers(self) -> None:
        """Register failsafe handlers for console events, signals, excepthook, and atexit."""
        # 1. atexit registration
        atexit.register(self.cleanup)
        self._registered_atexit = True

        # 2. sys.excepthook override
        self._orig_excepthook = sys.excepthook

        def _failsafe_excepthook(
            etype: type[BaseException],
            val: BaseException,
            tb: Any,
        ) -> None:
            self.cleanup()
            self._orig_excepthook(etype, val, tb)

        sys.excepthook = _failsafe_excepthook

        # 3. Windows SetConsoleCtrlHandler
        if _kernel32 is not None:

            def _ctrl_handler(ctrl_type: int) -> int:
                # 0 = CTRL_C_EVENT, 1 = CTRL_BREAK_EVENT
                # 2 = CTRL_CLOSE_EVENT, 5 = CTRL_LOGOFF_EVENT, 6 = CTRL_SHUTDOWN_EVENT
                self.shutdown_event.set()
                if ctrl_type in (2, 5, 6):
                    self.cleanup()
                    return 1
                return 0

            self._console_ctrl_routine = PHANDLER_ROUTINE(_ctrl_handler)
            _kernel32.SetConsoleCtrlHandler(self._console_ctrl_routine, True)

        # 4. Signal Handlers (main thread only)
        if threading.current_thread() is threading.main_thread():
            try:
                self._orig_sigint = signal.getsignal(signal.SIGINT)
                self._orig_sigterm = signal.getsignal(signal.SIGTERM)

                def _sig_handler(signum: int, frame: Any) -> None:
                    self.shutdown_event.set()
                    if signum == signal.SIGINT:
                        raise KeyboardInterrupt
                    self.cleanup()
                    sys.exit(128 + signum)

                signal.signal(signal.SIGINT, _sig_handler)
                signal.signal(signal.SIGTERM, _sig_handler)
            except (ValueError, OSError):
                pass

    def cleanup(self) -> None:
        """Perform thread-safe, idempotent, failsafe teardown of all resources."""
        with self._cleanup_lock:
            if self._cleaned_up:
                return
            self._cleaned_up = True

            logger.debug("Executing failsafe application cleanup...")

            # 1. Release cursor clipping / locks
            if _user32 is not None:
                with contextlib.suppress(Exception):
                    _user32.ClipCursor(None)

            # 2. Stop and unhook Win32 hooks
            if self.hooks is not None:
                with contextlib.suppress(Exception):
                    self.hooks.stop()
                self.hooks = None

            # 3. Neutralize and delete virtual Xbox 360 controller
            if self.gamepad is not None:
                with contextlib.suppress(Exception):
                    self.gamepad.reset()
                    self.gamepad.update()
                with contextlib.suppress(Exception):
                    del self.gamepad
                self.gamepad = None

            # 4. Strictly pair WinMM timeEndPeriod(1)
            if self.timer_entered:
                self.timer_entered = False
                with contextlib.suppress(Exception):
                    if _winmm is not None:
                        _winmm.timeEndPeriod(ctypes.c_uint(1))
                        _track_period_released()
                    elif self.timer is not None:
                        self.timer.__exit__(None, None, None)
                if self.timer is not None:
                    self.timer._is_active = False
                    self.timer = None

            # 5. Restore handlers
            if self._console_ctrl_routine is not None and _kernel32 is not None:
                with contextlib.suppress(Exception):
                    _kernel32.SetConsoleCtrlHandler(self._console_ctrl_routine, False)
                self._console_ctrl_routine = None

            if self._registered_atexit:
                with contextlib.suppress(Exception):
                    atexit.unregister(self.cleanup)
                self._registered_atexit = False

            with contextlib.suppress(Exception):
                sys.excepthook = self._orig_excepthook

            if threading.current_thread() is threading.main_thread():
                with contextlib.suppress(Exception):
                    if self._orig_sigint is not None:
                        signal.signal(signal.SIGINT, self._orig_sigint)
                    if self._orig_sigterm is not None:
                        signal.signal(signal.SIGTERM, self._orig_sigterm)

    def __enter__(self) -> AppLifecycle:
        self.setup_handlers()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()


# ── System Verification ──────────────────────────────────────────────────


def verify_system_requirements(ci_mode: bool = False) -> bool:
    """Verify Python, architecture, Windows OS, ViGEmBus kernel driver, and controller creation."""
    checks = [
        ("Python version", check_python_version()),
        ("Architecture", check_architecture()),
        ("Windows OS", check_windows_os()),
        ("ViGEmBus service", check_vigembus_service(ci_mode=ci_mode)),
        ("vgamepad controller", check_vgamepad_controller(ci_mode=ci_mode)),
    ]

    for label, (ok, detail) in checks:
        if not ok:
            print(f"[FAIL] {label}:", file=sys.stderr)
            for line in detail.splitlines():
                print(f"       {line}", file=sys.stderr)
            return False

    return True


# ── Main Mapping Engine ──────────────────────────────────────────────────


def run_mapper(argv: list[str] | None = None) -> int:
    """Initialize subsystems and run the fixed 250 Hz input mapping loop."""
    args = parse_args(argv)

    # Configure structured logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    profiles_dir = Path(__file__).parent / "profiles"

    ci_mode = args.ci or is_headless_ci()

    # Handle --check
    if args.check:
        ok = verify_system_requirements(ci_mode=ci_mode)
        if ok:
            print("[PASS] System requirements and ViGEmBus driver verification succeeded.")
        return 0 if ok else 1

    # Handle --list-profiles
    if args.list_profiles:
        if not profiles_dir.is_dir():
            print(f"[FAIL] Profiles directory does not exist: {profiles_dir}", file=sys.stderr)
            return 1

        print("Available controller profiles:")
        try:
            json_files = sorted(profiles_dir.glob("*.json"))
            if not json_files:
                print("  (No profile files found in profiles directory)")
                return 0

            loaded_count = 0
            for json_path in json_files:
                try:
                    prof = ProfileManager.load_profile(json_path, base_dir=profiles_dir)
                    print(f"  • {prof.name:<15} ({json_path.name})")
                    loaded_count += 1
                except Exception as p_err:
                    print(f"  • [INVALID] {json_path.name}: {p_err}", file=sys.stderr)

            if loaded_count == 0:
                print("[WARNING] No valid profiles could be loaded.", file=sys.stderr)
                return 1
            return 0
        except Exception as exc:
            print(f"[FAIL] Error reading profiles: {exc}", file=sys.stderr)
            return 1

    # Validate requested profile argument if provided
    if args.profile is not None:
        valid_name, reason = validate_profile_name(args.profile)
        if not valid_name:
            print(f"[FAIL] Invalid profile name: {reason}", file=sys.stderr)
            return 1

    print("=" * 60)
    print("  ViGEmBus Mouse & Keyboard Gamepad Mapper")
    print("=" * 60)

    # 1. Subsystem and Driver Validation
    if not verify_system_requirements(ci_mode=ci_mode):
        print("\nInitialization failed. Resolve the driver/system issue above.", file=sys.stderr)
        return 1

    # 2. Discover and Load Mapping Profiles
    try:
        profile_mgr = ProfileManager(profiles_dir=profiles_dir)
    except Exception as exc:
        print(f"[FAIL] Error loading profiles: {exc}", file=sys.stderr)
        return 1

    if not profile_mgr.profiles:
        print("[FAIL] No valid profiles loaded.", file=sys.stderr)
        return 1

    # Select requested or default profile
    if args.profile is not None:
        target = args.profile.strip().lower()
        matched_idx: int | None = None
        # 1. Exact match (case-insensitive) against name, stem, or filename
        for idx, prof in enumerate(profile_mgr.profiles):
            if (
                prof.name.lower() == target
                or prof.file_path.stem.lower() == target
                or prof.file_path.name.lower() == target
            ):
                matched_idx = idx
                break

        # 2. Normalized alphanumeric match (e.g. "rts" matches "RTS / Menu" or "rts_menu")
        if matched_idx is None:
            norm_target = "".join(c for c in target if c.isalnum())
            if norm_target:
                for idx, prof in enumerate(profile_mgr.profiles):
                    norm_name = "".join(c for c in prof.name.lower() if c.isalnum())
                    norm_stem = "".join(c for c in prof.file_path.stem.lower() if c.isalnum())
                    if (
                        norm_target in (norm_name, norm_stem)
                        or norm_name.startswith(norm_target)
                        or norm_stem.startswith(norm_target)
                    ):
                        matched_idx = idx
                        break

        if matched_idx is None:
            available = ", ".join(p.name for p in profile_mgr.profiles)
            print(
                f"[FAIL] Profile '{args.profile}' not found. Available profiles: {available}",
                file=sys.stderr,
            )
            return 1
        profile_mgr.current_index = matched_idx
    else:
        # Default profile: look for "Shooter", else first available
        for idx, prof in enumerate(profile_mgr.profiles):
            if prof.name.lower() == "shooter" or prof.file_path.stem.lower() == "shooter":
                profile_mgr.current_index = idx
                break
        else:
            profile_mgr.current_index = 0

    with AppLifecycle() as lifecycle:
        # 3. Instantiate Virtual Xbox 360 Controller
        try:
            gamepad = vg.VX360Gamepad()
            gamepad.reset()
            gamepad.update()
            lifecycle.gamepad = gamepad
        except Exception as exc:
            print(f"[FAIL] Failed to allocate virtual controller: {exc}", file=sys.stderr)
            return 1

        print(f"  [OK] Controller created (Active Profile: {profile_mgr.current_profile.name})")
        print("  Controls:")
        print("    [F8] Toggle Input Capture ON / OFF")
        print("    [F9] Cycle Profiles (Shooter <-> RTS / Menu)")
        print("    [Ctrl+C] Clean Exit")
        print("=" * 60)

        # 4. Initialize Low-Level Win32 Hooks
        try:
            hooks = InputHookManager(toggle_key=VK_F8)
            lifecycle.hooks = hooks
            hooks.start()
        except Exception as exc:
            print(f"[FAIL] Failed to install Win32 input hooks: {exc}", file=sys.stderr)
            return 1

        # 5. Initialize High-Resolution Timer
        try:
            timer = HighResTimer(TARGET_HZ)
            lifecycle.timer = timer
            timer.__enter__()
            lifecycle.timer_entered = True
        except Exception as exc:
            print(f"[FAIL] Failed to initialize high-resolution timer: {exc}", file=sys.stderr)
            return 1

        was_active = False
        consecutive_tick_errors = 0
        last_tick_error_log = 0.0
        last_controller_state: tuple[int, int, int, int, int, int, int] | None = None
        ticks_since_update = 0

        try:
            while not lifecycle.shutdown_event.is_set():
                if not hooks.is_healthy:
                    logger.error("Low-level Win32 hook subsystem terminated unexpectedly. Shutting down.")
                    return 1

                # ── Profile cycling hotkey check (F9 consumed from hook thread) ──
                if hooks.consume_profile_cycle():
                    try:
                        profile_mgr.current_profile.reset_controls(gamepad)
                        hooks.reset_held_inputs()
                        active_prof = profile_mgr.cycle()
                        gamepad.reset()
                        gamepad.update()
                        last_controller_state = None
                        ticks_since_update = 0
                        print(f"[PROFILE] {active_prof.name}", flush=True)
                        logger.debug("Switched profile to: %s", active_prof.name)
                    except Exception as cyc_exc:
                        logger.warning("Error cycling profile: %s", cyc_exc)

                active = hooks.active

                # ── State transition detection ──
                if active != was_active:
                    try:
                        if active:
                            timer.reset()
                            profile_mgr.current_profile.mapper.reset()
                            last_controller_state = None
                            ticks_since_update = 0
                            print(f"[ON] Profile: {profile_mgr.current_profile.name}", flush=True)
                            logger.debug("Capture activated.")
                        else:
                            profile_mgr.current_profile.reset_controls(gamepad)
                            gamepad.reset()
                            gamepad.update()
                            last_controller_state = None
                            ticks_since_update = 0
                            print("[OFF] Mouse/KB Released", flush=True)
                            logger.debug("Capture deactivated.")
                    except Exception as trans_exc:
                        logger.warning("Error during state transition: %s", trans_exc)
                    was_active = active

                # ── Inactive idle path: save CPU cycles ──
                if not active:
                    time.sleep(0.010)
                    continue

                # ── Active 250 Hz tick (4 ms budget) ──
                try:
                    dt = timer.wait()
                    prof = profile_mgr.current_profile

                    # A. Right Stick: accumulate mouse deltas and apply curve
                    dx, dy = hooks.consume_mouse_delta()
                    rx, ry = prof.mapper.step(dx, dy, dt)
                    gamepad.right_joystick(x_value=rx, y_value=ry)

                    # B. Left Stick: WASD directional inputs with diagonal normalization
                    keys_pressed = hooks.get_keys_pressed()
                    lx, ly = prof.compute_left_stick(keys_pressed)
                    gamepad.left_joystick(x_value=lx, y_value=ly)

                    # C. Buttons & Triggers: apply active profile mappings
                    lb, rb, mb, x1, x2 = hooks.get_mouse_buttons()
                    wheel_delta = hooks.consume_wheel_delta()
                    prof.apply_buttons(
                        gamepad=gamepad,
                        keys_pressed=keys_pressed,
                        lbutton=lb,
                        rbutton=rb,
                        mbutton=mb,
                        xbutton1=x1,
                        xbutton2=x2,
                        wheel_delta=wheel_delta,
                    )

                    # D. Commit report to ViGEmBus if state changed or heartbeat reached
                    rep = getattr(gamepad, "report", None)
                    if rep is not None:
                        current_state = (
                            int(getattr(rep, "sThumbRX", rx)),
                            int(getattr(rep, "sThumbRY", ry)),
                            int(getattr(rep, "sThumbLX", lx)),
                            int(getattr(rep, "sThumbLY", ly)),
                            int(getattr(rep, "bLeftTrigger", 0)),
                            int(getattr(rep, "bRightTrigger", 0)),
                            int(getattr(rep, "wButtons", 0)),
                        )
                    else:
                        current_state = (int(rx), int(ry), int(lx), int(ly), 0, 0, 0)

                    ticks_since_update += 1
                    if current_state != last_controller_state or ticks_since_update >= 25:
                        gamepad.update()
                        last_controller_state = current_state
                        ticks_since_update = 0

                    consecutive_tick_errors = 0

                except Exception as tick_exc:
                    consecutive_tick_errors += 1
                    last_controller_state = None
                    ticks_since_update = 0
                    # Failsafe: reset controller immediately to prevent stuck inputs
                    with contextlib.suppress(Exception):
                        gamepad.reset()
                        gamepad.update()

                    # Throttle logging to prevent fast-path I/O saturation (at most 1 log / sec)
                    now = time.monotonic()
                    if now - last_tick_error_log >= TICK_ERROR_LOG_INTERVAL_SEC:
                        logger.warning(
                            "Transient per-tick error in mapping loop: %s (consecutive: %d)",
                            tick_exc,
                            consecutive_tick_errors,
                        )
                        last_tick_error_log = now

                    # Break out safely if persistent failure occurs (e.g. driver lost)
                    if consecutive_tick_errors >= MAX_CONSECUTIVE_TICK_ERRORS:
                        logger.error(
                            "Fatal: %d consecutive tick errors in 250 Hz loop. Shutting down.",
                            MAX_CONSECUTIVE_TICK_ERRORS,
                        )
                        if _user32 is not None:
                            with contextlib.suppress(Exception):
                                _user32.ClipCursor(None)
                        with contextlib.suppress(Exception):
                            hooks.stop()
                        return 1

        except KeyboardInterrupt:
            print("\nShutdown requested by user (Ctrl+C).")
        except Exception as loop_exc:
            logger.error("Unhandled runtime exception in mapping loop: %s", loop_exc, exc_info=True)
            return 1
        finally:
            print("Releasing virtual controller and Win32 hooks...")

    print("Shutdown complete.")
    return 0


if __name__ == "__main__":
    sys.exit(run_mapper())
