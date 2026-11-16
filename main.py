"""Main application entry point for the Mouse & Keyboard to Xbox 360 controller mapper.

Integrates ViGEmBus driver verification, low-level Win32 input hooks,
high-precision 250 Hz hybrid timer, profile management, and virtual
gamepad report delivery.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import vgamepad as vg
from driver_check import (
    check_python_version,
    check_vigembus_service,
    check_windows_os,
)
from input_hooks import VK_F8, InputHookManager
from profiles import VK_F9, ProfileManager
from stick_mapper import TARGET_HZ, HighResTimer


def verify_system_requirements() -> bool:
    """Verify Python, Windows OS, and ViGEmBus kernel driver status."""
    checks = [
        ("Python version", check_python_version()),
        ("Windows OS", check_windows_os()),
        ("ViGEmBus service", check_vigembus_service()),
    ]

    for label, (ok, detail) in checks:
        if not ok:
            print(f"[FAIL] {label}:", file=sys.stderr)
            for line in detail.splitlines():
                print(f"       {line}", file=sys.stderr)
            return False

    return True


def run_mapper() -> int:
    """Initialize subsystems and run the fixed 250 Hz input mapping loop."""
    print("=" * 60)
    print("  ViGEmBus Mouse & Keyboard Gamepad Mapper")
    print("=" * 60)

    # 1. Subsystem and Driver Validation
    if not verify_system_requirements():
        print("\nInitialization failed. Resolve the driver/system issue above.", file=sys.stderr)
        return 1

    # 2. Discover and Load Mapping Profiles
    profiles_dir = Path(__file__).parent / "profiles"
    try:
        profile_mgr = ProfileManager(profiles_dir=profiles_dir, default_name="Shooter")
    except Exception as exc:
        print(f"[FAIL] Error loading profiles: {exc}", file=sys.stderr)
        return 1

    # 3. Instantiate Virtual Xbox 360 Controller
    gamepad: vg.VX360Gamepad | None = None
    try:
        gamepad = vg.VX360Gamepad()
        gamepad.reset()
        gamepad.update()
    except Exception as exc:
        print(f"[FAIL] Failed to allocate virtual controller: {exc}", file=sys.stderr)
        return 1

    print(f"  [OK] Controller created (Default Profile: {profile_mgr.current_profile.name})")
    print("  Controls:")
    print("    [F8] Toggle Input Capture ON / OFF")
    print("    [F9] Cycle Profiles (Shooter <-> RTS / Menu)")
    print("    [Ctrl+C] Clean Exit")
    print("=" * 60)

    # 4. Initialize Low-Level Win32 Hooks (F8 toggle, F9 passthrough)
    hooks = InputHookManager(
        toggle_key=VK_F8,
        passthrough_keys=(VK_F9,),
    )

    was_active = False

    try:
        with hooks, HighResTimer(TARGET_HZ) as timer:
            while True:
                # ── Profile cycling hotkey check (F9) ──
                if profile_mgr.check_f9_hotkey():
                    active_prof = profile_mgr.current_profile
                    gamepad.reset()
                    gamepad.update()
                    print(f"[PROFILE] {active_prof.name}", flush=True)

                active = hooks.active

                # ── State transition detection ──
                if active != was_active:
                    if active:
                        profile_mgr.current_profile.mapper.reset()
                        print(f"[ON] Profile: {profile_mgr.current_profile.name}", flush=True)
                    else:
                        gamepad.reset()
                        gamepad.update()
                        print("[OFF] Mouse/KB Released", flush=True)
                    was_active = active

                # ── Inactive idle path: save CPU cycles ──
                if not active:
                    time.sleep(0.010)
                    continue

                # ── Active 250 Hz tick (4 ms budget) ──
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
                lbutton, rbutton, mbutton = hooks.get_mouse_buttons()
                prof.apply_buttons(
                    gamepad=gamepad,
                    keys_pressed=keys_pressed,
                    lbutton=lbutton,
                    rbutton=rbutton,
                    mbutton=mbutton,
                )

                # D. Commit report to ViGEmBus
                gamepad.update()

    except KeyboardInterrupt:
        print("\nShutdown requested by user (Ctrl+C).")
    finally:
        # Full failsafe cleanup
        print("Releasing virtual controller and Win32 hooks...")
        if gamepad is not None:
            try:
                gamepad.reset()
                gamepad.update()
            except Exception:
                pass
            try:
                del gamepad
            except Exception:
                pass
        print("Shutdown complete.")

    return 0


if __name__ == "__main__":
    sys.exit(run_mapper())
