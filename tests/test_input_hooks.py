"""Unit tests for input_hooks module.

Audits Win32 hook safety, concurrency & thread synchronization,
API error handling (DPI awareness, SetConsoleCtrlHandler return codes,
GetCursorPos bounds), and input processing edge cases.
"""

from __future__ import annotations

import ctypes
from typing import Any
from unittest.mock import MagicMock, patch

import input_hooks
from input_hooks import (
    CTRL_BREAK_EVENT,
    CTRL_C_EVENT,
    CTRL_CLOSE_EVENT,
    CTRL_LOGOFF_EVENT,
    CTRL_SHUTDOWN_EVENT,
    DEFAULT_PASSTHROUGH_KEYS,
    KBDLLHOOKSTRUCT,
    LLKHF_ALTDOWN,
    LLKHF_INJECTED,
    LLKHF_LOWER_IL_INJECTED,
    LLMHF_LOWER_IL_INJECTED,
    MSLLHOOKSTRUCT,
    VK_F7,
    VK_F8,
    VK_F9,
    VK_F10,
    VK_F11,
    VK_LWIN,
    VK_OEM_3,
    VK_RWIN,
    VK_TAB,
    WM_KEYDOWN,
    WM_KEYUP,
    WM_LBUTTONDBLCLK,
    WM_LBUTTONUP,
    WM_MBUTTONDBLCLK,
    WM_MBUTTONUP,
    WM_MOUSEMOVE,
    WM_MOUSEWHEEL,
    WM_RBUTTONDBLCLK,
    WM_RBUTTONUP,
    WM_XBUTTONDBLCLK,
    WM_XBUTTONDOWN,
    WM_XBUTTONUP,
    XBUTTON1,
    XBUTTON2,
    InputHooks,
)


class TestWin32HookSafety:
    """Validate 32/64-bit alignment, field offsets, and callback lifetimes."""

    def test_kbdllhookstruct_layout_and_alignment(self) -> None:
        is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8
        expected_size = 24 if is_64bit else 20
        assert ctypes.sizeof(KBDLLHOOKSTRUCT) == expected_size
        assert KBDLLHOOKSTRUCT.vkCode.offset == 0
        assert KBDLLHOOKSTRUCT.scanCode.offset == 4
        assert KBDLLHOOKSTRUCT.flags.offset == 8
        assert KBDLLHOOKSTRUCT.time.offset == 12
        assert KBDLLHOOKSTRUCT.dwExtraInfo.offset == 16

    def test_msllhookstruct_layout_and_alignment(self) -> None:
        is_64bit = ctypes.sizeof(ctypes.c_void_p) == 8
        expected_size = 32 if is_64bit else 24
        expected_extra_offset = 24 if is_64bit else 20
        assert ctypes.sizeof(MSLLHOOKSTRUCT) == expected_size
        assert MSLLHOOKSTRUCT.pt.offset == 0
        assert MSLLHOOKSTRUCT.mouseData.offset == 8
        assert MSLLHOOKSTRUCT.flags.offset == 12
        assert MSLLHOOKSTRUCT.time.offset == 16
        assert MSLLHOOKSTRUCT.dwExtraInfo.offset == expected_extra_offset

    def test_callback_wrapper_lifetime(self) -> None:
        hooks = InputHooks()
        assert hooks._kb_proc_ref is not None
        assert hooks._mouse_proc_ref is not None
        assert callable(hooks._kb_proc_ref)
        assert callable(hooks._mouse_proc_ref)


class TestConcurrencyAndAtomicState:
    """Validate thread synchronization, atomic state resets, and reentrancy."""

    def test_f8_atomic_state_activation(self) -> None:
        toggled_states: list[bool] = []
        hooks = InputHooks(on_toggle=lambda st: toggled_states.append(st))

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F8
        kbd.flags = 0

        with (
            patch.object(input_hooks._user32, "SetCursorPos", return_value=True),
            patch.object(input_hooks._user32, "GetCursorPos", return_value=False),
            patch.object(input_hooks._user32, "GetSystemMetrics", return_value=1920),
        ):
            res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))

        assert res != 1  # F8 toggle is never swallowed
        assert hooks.active is True
        assert hooks._f8_held is True
        assert toggled_states == [True]

        # Release F8 key
        hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
        assert hooks._f8_held is False
        assert hooks.active is True

    def test_f8_atomic_state_deactivation(self) -> None:
        hooks = InputHooks()
        hooks._active = True
        hooks._keys_down.add(0x41)  # 'A'
        hooks._lbutton = True
        hooks._last_pt = (500, 500)

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F8
        kbd.flags = 0

        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert hooks.active is False
        assert len(hooks.get_keys_pressed()) == 0
        assert hooks._last_pt is None
        assert hooks.get_mouse_buttons() == (False, False, False, False, False)

    def test_f9_profile_cycle_atomic(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F9
        kbd.flags = 0

        res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert res == 1  # Swallowed while active
        assert hooks._f9_held is True
        assert hooks.consume_profile_cycle() is True
        # Consumption resets the flag atomically
        assert hooks.consume_profile_cycle() is False

        # Release F9 key
        hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
        assert hooks._f9_held is False

    def test_f10_stick_swap_atomic(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F10
        kbd.flags = 0

        res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert res == 1  # Swallowed while active
        assert hooks._f10_held is True
        assert hooks.consume_stick_swap() is True
        # Consumption resets the flag atomically
        assert hooks.consume_stick_swap() is False

        # Release F10 key
        hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
        assert hooks._f10_held is False

    def test_f10_passthrough_when_inactive(self) -> None:
        hooks = InputHooks()
        hooks._active = False

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F10
        kbd.flags = 0

        with patch("input_hooks._user32.CallNextHookEx", return_value=42):
            res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            assert res == 42  # Passed through when inactive
            assert hooks._f10_held is True
            assert hooks.consume_stick_swap() is True
            assert hooks.consume_stick_swap() is False

        with patch("input_hooks._user32.CallNextHookEx", return_value=42):
            hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
            assert hooks._f10_held is False

    def test_f10_injected_ignored(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F10
        kbd.flags = LLKHF_INJECTED

        res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert res == 1  # Swallowed while active
        assert hooks._f10_held is False
        assert hooks.consume_stick_swap() is False

    def test_f10_debounce_key_repeat(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F10
        kbd.flags = 0

        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert hooks.consume_stick_swap() is True

        # Second keydown while held does NOT request another swap
        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert hooks.consume_stick_swap() is False

        hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
        assert hooks._f10_held is False

        # Keydown after release requests swap again
        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert hooks.consume_stick_swap() is True

    def test_f7_wake_pulse_atomic(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F7
        kbd.flags = 0

        res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert res == 1  # Swallowed while active
        assert hooks._f7_held is True
        assert hooks.consume_wake_pulse() is True
        # Consumption resets the flag atomically
        assert hooks.consume_wake_pulse() is False

        # Release F7 key
        hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
        assert hooks._f7_held is False

    def test_f7_passthrough_when_inactive(self) -> None:
        hooks = InputHooks()
        hooks._active = False

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F7
        kbd.flags = 0

        with patch("input_hooks._user32.CallNextHookEx", return_value=42):
            res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            assert res == 42  # Passed through when inactive
            assert hooks._f7_held is True
            assert hooks.consume_wake_pulse() is True
            assert hooks.consume_wake_pulse() is False

        with patch("input_hooks._user32.CallNextHookEx", return_value=42):
            hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
            assert hooks._f7_held is False

    def test_f7_injected_ignored(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F7
        kbd.flags = LLKHF_INJECTED

        res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert res == 1  # Swallowed while active
        assert hooks._f7_held is False
        assert hooks.consume_wake_pulse() is False

    def test_f7_debounce_key_repeat(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F7
        kbd.flags = 0

        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert hooks.consume_wake_pulse() is True

        # Second keydown while held does NOT request another pulse
        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert hooks.consume_wake_pulse() is False

        hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
        assert hooks._f7_held is False

        # Keydown after release requests pulse again
        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert hooks.consume_wake_pulse() is True

    def test_reentrancy_in_stop_and_force_unhook(self) -> None:
        hooks = InputHooks()
        # Verify multiple calls to stop and force_unhook do not throw or deadlock
        hooks.stop()
        hooks.stop()
        hooks._force_unhook()
        hooks._force_unhook()
        assert not hooks.active

    def test_force_unhook_verifies_success_and_error_1404(self) -> None:
        """_force_unhook zeroes hook handles only when UnhookWindowsHookEx succeeds or returns 1404."""
        hooks = InputHooks()
        hooks._kb_hook = 0xAAAA
        hooks._mouse_hook = 0xBBBB

        # Unhook fails with error code other than 1404 (e.g. 5: Access Denied) -> handles not zeroed
        with (
            patch.object(input_hooks._user32, "UnhookWindowsHookEx", return_value=0),
            patch.object(input_hooks._kernel32, "GetLastError", return_value=5),
        ):
            hooks._force_unhook()
            assert hooks._kb_hook == 0xAAAA
            assert hooks._mouse_hook == 0xBBBB

        # Unhook returns 0 but GetLastError is 1404 (ERROR_INVALID_HOOK_HANDLE) -> handles zeroed
        with (
            patch.object(input_hooks._user32, "UnhookWindowsHookEx", return_value=0),
            patch.object(input_hooks._kernel32, "GetLastError", return_value=1404),
        ):
            hooks._force_unhook()
            assert hooks._kb_hook == 0
            assert hooks._mouse_hook == 0

        # Normal successful unhook (returns 1)
        hooks._kb_hook = 0x1111
        hooks._mouse_hook = 0x2222
        with patch.object(input_hooks._user32, "UnhookWindowsHookEx", return_value=1):
            hooks._force_unhook()
            assert hooks._kb_hook == 0
            assert hooks._mouse_hook == 0

    def test_f8_activation_exception_rolls_back_cleanly(self) -> None:
        """Exception during F8 cursor initialization rolls back active state cleanly (SIL-04)."""
        toggled: list[bool] = []
        hooks = InputHooks(on_toggle=lambda st: toggled.append(st))
        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F8

        with patch.object(
            input_hooks._user32, "GetSystemMetrics", side_effect=RuntimeError("System error")
        ):
            hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))

        assert hooks.active is False
        assert hooks._center_pt is None
        assert hooks._last_pt is None
        assert toggled == [False]


class TestWin32APIErrorHandlingAndBounds:
    """Validate DPI awareness, SetConsoleCtrlHandler return codes, and GetCursorPos bounds."""

    def test_dpi_awareness_access_denied_handled(self) -> None:
        # If SetProcessDpiAwarenessContext returns False and GetLastError is 5 (Access Denied),
        # it means DPI awareness is already set, so it should return cleanly without raising.
        with (
            patch.object(input_hooks._user32, "SetProcessDpiAwarenessContext", return_value=0),
            patch.object(input_hooks._kernel32, "GetLastError", return_value=5),
        ):
            input_hooks._enable_per_monitor_dpi_awareness()

    def test_dpi_awareness_shcore_and_user32_fallbacks(self) -> None:
        """Verify fallback from SetProcessDpiAwarenessContext to shcore and user32."""
        with (
            patch.object(
                input_hooks._user32, "SetProcessDpiAwarenessContext", side_effect=AttributeError
            ),
            patch.object(ctypes, "WinDLL") as mock_windll,
        ):
            mock_shcore = MagicMock()
            mock_shcore.SetProcessDpiAwareness.return_value = 0
            mock_windll.return_value = mock_shcore
            input_hooks._enable_per_monitor_dpi_awareness()
            mock_shcore.SetProcessDpiAwareness.assert_called_once_with(2)

        with (
            patch.object(
                input_hooks._user32, "SetProcessDpiAwarenessContext", side_effect=AttributeError
            ),
            patch.object(ctypes, "WinDLL", side_effect=OSError("Not found")),
            patch.object(
                input_hooks._user32, "SetProcessDPIAware", return_value=1
            ) as mock_user32_dpi,
        ):
            input_hooks._enable_per_monitor_dpi_awareness()
            mock_user32_dpi.assert_called_once()

    def test_console_ctrl_handler_return_codes(self) -> None:
        hooks = InputHooks()
        # All console ctrl events must return 0 (FALSE) so downstream handlers (e.g. AppLifecycle) receive them
        assert hooks._console_ctrl_handler(CTRL_CLOSE_EVENT) == 0
        assert hooks._console_ctrl_handler(CTRL_LOGOFF_EVENT) == 0
        assert hooks._console_ctrl_handler(CTRL_SHUTDOWN_EVENT) == 0

        # Ctrl+C and Ctrl+Break must return 0 (FALSE) to allow Python SIGINT handler
        assert hooks._console_ctrl_handler(CTRL_C_EVENT) == 0
        assert hooks._console_ctrl_handler(CTRL_BREAK_EVENT) == 0

    def test_getcursorpos_bounds_validation(self) -> None:
        hooks = InputHooks()
        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F8
        kbd.flags = 0

        def fake_get_system_metrics(n: int) -> int:
            if n in (0, 78):
                return 1920
            if n in (1, 79):
                return 1080
            return 0  # SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN = 0

        # Case 1: Landed coordinates inside bounds
        def fake_get_cursor_pos_in_bounds(arg: Any) -> int:
            obj = getattr(arg, "_obj", getattr(arg, "contents", None))
            if obj is not None:
                obj.x = 960
                obj.y = 540
            return 1

        with (
            patch.object(
                input_hooks._user32, "GetSystemMetrics", side_effect=fake_get_system_metrics
            ),
            patch.object(input_hooks._user32, "SetCursorPos", return_value=True),
            patch.object(
                input_hooks._user32, "GetCursorPos", side_effect=fake_get_cursor_pos_in_bounds
            ),
        ):
            hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            assert hooks._last_pt == (960, 540)

        # Release F8 key
        hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))

        # Deactivate
        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))

        # Case 2: Landed coordinates outside bounds (e.g. 5000, 5000)
        def fake_get_cursor_pos_out_of_bounds(arg: Any) -> int:
            obj = getattr(arg, "_obj", getattr(arg, "contents", None))
            if obj is not None:
                obj.x = 5000
                obj.y = 5000
            return 1

        with (
            patch.object(
                input_hooks._user32, "GetSystemMetrics", side_effect=fake_get_system_metrics
            ),
            patch.object(input_hooks._user32, "SetCursorPos", return_value=True),
            patch.object(
                input_hooks._user32, "GetCursorPos", side_effect=fake_get_cursor_pos_out_of_bounds
            ),
        ):
            hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            # Must fall back to screen center (960, 540)
            assert hooks._last_pt == (960, 540)


class TestEdgeCasesMessageProcessing:
    """Validate wheel deltas, XBUTTON bitwise logic, sanitization, and injection masking."""

    def test_mouse_wheel_signed_delta_extraction(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        ms = MSLLHOOKSTRUCT()
        ms.flags = 0

        # Positive delta (+120)
        ms.mouseData = 120 << 16
        res = hooks._mouse_ll_proc(0, WM_MOUSEWHEEL, ctypes.addressof(ms))
        assert res == 1
        assert hooks.consume_wheel_delta() == 120

        # Negative delta (-120: 0xFF88 in high word)
        ms.mouseData = 0xFF880000
        res = hooks._mouse_ll_proc(0, WM_MOUSEWHEEL, ctypes.addressof(ms))
        assert res == 1
        assert hooks.consume_wheel_delta() == -120

    def test_mouse_horizontal_wheel_extraction(self) -> None:
        """Horizontal wheel scroll delta (WM_MOUSEHWHEEL) extracted via bitwise logic."""
        hooks = InputHooks()
        hooks._active = True

        ms = MSLLHOOKSTRUCT()
        ms.flags = 0

        # Positive horizontal delta (+120)
        ms.mouseData = 120 << 16
        res = hooks._mouse_ll_proc(0, input_hooks.WM_MOUSEHWHEEL, ctypes.addressof(ms))
        assert res == 1
        assert hooks.consume_wheel_delta() == 120

    def test_custom_passthrough_keys_configuration(self) -> None:
        """Constructor properly accepts and applies custom passthrough keys."""
        hooks = InputHooks(passthrough_keys=[0x41, 0x42])
        assert 0x41 in hooks._passthrough_keys
        assert 0x42 in hooks._passthrough_keys
        assert input_hooks.VK_LWIN not in hooks._passthrough_keys

    def test_xbutton_bitwise_processing(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        ms = MSLLHOOKSTRUCT()
        ms.flags = 0

        # XBUTTON1 down
        ms.mouseData = XBUTTON1 << 16
        hooks._mouse_ll_proc(0, WM_XBUTTONDOWN, ctypes.addressof(ms))
        assert hooks.get_extra_mouse_buttons() == (True, False)

        # XBUTTON2 down (both active)
        ms.mouseData = (XBUTTON1 | XBUTTON2) << 16
        hooks._mouse_ll_proc(0, WM_XBUTTONDOWN, ctypes.addressof(ms))
        assert hooks.get_extra_mouse_buttons() == (True, True)

        # XBUTTON1 up
        ms.mouseData = XBUTTON1 << 16
        hooks._mouse_ll_proc(0, WM_XBUTTONUP, ctypes.addressof(ms))
        assert hooks.get_extra_mouse_buttons() == (False, True)

        # XBUTTON2 up
        ms.mouseData = XBUTTON2 << 16
        hooks._mouse_ll_proc(0, WM_XBUTTONUP, ctypes.addressof(ms))
        assert hooks.get_extra_mouse_buttons() == (False, False)

    def test_double_click_mapping(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        ms = MSLLHOOKSTRUCT()
        ms.flags = 0

        # Left double-click should set lbutton True
        hooks._mouse_ll_proc(0, WM_LBUTTONDBLCLK, ctypes.addressof(ms))
        assert hooks._lbutton is True
        hooks._mouse_ll_proc(0, WM_LBUTTONUP, ctypes.addressof(ms))
        assert hooks._lbutton is False

        # Right double-click
        hooks._mouse_ll_proc(0, WM_RBUTTONDBLCLK, ctypes.addressof(ms))
        assert hooks._rbutton is True
        hooks._mouse_ll_proc(0, WM_RBUTTONUP, ctypes.addressof(ms))
        assert hooks._rbutton is False

        # Middle double-click
        hooks._mouse_ll_proc(0, WM_MBUTTONDBLCLK, ctypes.addressof(ms))
        assert hooks._mbutton is True
        hooks._mouse_ll_proc(0, WM_MBUTTONUP, ctypes.addressof(ms))
        assert hooks._mbutton is False

        # XBUTTON double-click
        ms.mouseData = XBUTTON1 << 16
        hooks._mouse_ll_proc(0, WM_XBUTTONDBLCLK, ctypes.addressof(ms))
        assert hooks._xbutton1 is True
        hooks._mouse_ll_proc(0, WM_XBUTTONUP, ctypes.addressof(ms))
        assert hooks._xbutton1 is False

    def test_virtual_key_code_sanitization(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.flags = 0

        with patch.object(input_hooks._user32, "CallNextHookEx", return_value=0) as mock_call_next:
            # vkCode = 0 (invalid)
            kbd.vkCode = 0
            hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            mock_call_next.assert_called()
            assert len(hooks.get_keys_pressed()) == 0

            # vkCode > 255 (invalid)
            mock_call_next.reset_mock()
            kbd.vkCode = 0x1234
            hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            mock_call_next.assert_called()
            assert len(hooks.get_keys_pressed()) == 0

            # Valid key (0x41 = 'A')
            kbd.vkCode = 0x41
            res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            assert res == 1  # Swallowed
            assert 0x41 in hooks.get_keys_pressed()

    def test_injection_flag_masking(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F8

        # Standard injection
        kbd.flags = LLKHF_INJECTED
        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert hooks._f8_held is False
        assert hooks.active is True  # Did not toggle

        # Lower-IL injection
        kbd.flags = LLKHF_LOWER_IL_INJECTED
        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert hooks._f8_held is False
        assert hooks.active is True

        # Mouse lower-IL injection
        ms = MSLLHOOKSTRUCT()
        ms.flags = LLMHF_LOWER_IL_INJECTED
        ms.pt.x = 200
        ms.pt.y = 200
        hooks._last_pt = (100, 100)
        res = hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
        assert res == 1
        dx, dy = hooks.consume_mouse_delta()
        assert dx == 0
        assert dy == 0


class TestMouseTrackingAndRecentering:
    """Validate mouse delta tracking, baseline progression, and cursor recentering."""

    def test_mouse_movement_relative_delta_progression(self) -> None:
        hooks = InputHooks()
        hooks._active = True
        hooks._center_pt = (100, 100)
        hooks._last_pt = (100, 100)

        ms = MSLLHOOKSTRUCT()
        ms.flags = 0

        # Step 1: Move from center (100, 100) by +10 in X
        ms.pt.x = 110
        ms.pt.y = 100
        hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
        dx1, dy1 = hooks.consume_mouse_delta()
        assert dx1 == 10
        assert dy1 == 0
        assert hooks._last_pt == (100, 100)

        # Step 2: Move from center by +15 in X
        ms.pt.x = 115
        ms.pt.y = 100
        hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
        dx2, dy2 = hooks.consume_mouse_delta()
        assert dx2 == 15
        assert dy2 == 0
        assert hooks._last_pt == (100, 100)

        # Step 3: Reverse direction: move from center by -5 in X
        ms.pt.x = 95
        ms.pt.y = 100
        hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
        dx3, dy3 = hooks.consume_mouse_delta()
        assert dx3 == -5
        assert dy3 == 0
        assert hooks._last_pt == (100, 100)

        # Step 4: Stationary event (at center 100, 100) -> delta must be 0
        ms.pt.x = 100
        ms.pt.y = 100
        hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
        dx4, dy4 = hooks.consume_mouse_delta()
        assert dx4 == 0
        assert dy4 == 0
        assert hooks._last_pt == (100, 100)

    def test_cursor_recentering_when_threshold_exceeded(self) -> None:
        hooks = InputHooks()
        hooks._active = True
        hooks._center_pt = (960, 540)
        hooks._last_pt = (960, 540)
        hooks._recenter_threshold = 150

        ms = MSLLHOOKSTRUCT()
        ms.flags = 0

        with patch.object(input_hooks._user32, "SetCursorPos") as mock_set_cursor:
            # Move by 50 px relative to center: return 1 swallows movement and keeps cursor anchored
            ms.pt.x = 1010
            ms.pt.y = 540
            res = hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
            assert res == 1
            mock_set_cursor.assert_not_called()
            assert hooks._last_pt == (960, 540)
            dx1, dy1 = hooks.consume_mouse_delta()
            assert dx1 == 50
            assert dy1 == 0

            # Large movement relative to center: remains anchored at center without SetCursorPos
            ms.pt.x = 1130
            ms.pt.y = 540
            res = hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
            assert res == 1
            mock_set_cursor.assert_not_called()
            assert hooks._last_pt == (960, 540)
            dx2, dy2 = hooks.consume_mouse_delta()
            assert dx2 == 170
            assert dy2 == 0

    def test_stop_unclips_cursor(self) -> None:
        hooks = InputHooks()
        with patch.object(input_hooks._user32, "ClipCursor") as mock_clip:
            hooks.stop()
            mock_clip.assert_called_with(None)

    def test_concurrent_f8_toggle_and_mouse_move(self) -> None:
        """Stress test rapid F8 toggles (50 Hz) concurrent with continuous mouse moves."""
        import threading
        import time

        hooks = InputHooks()
        kbd_down = KBDLLHOOKSTRUCT(vkCode=VK_F8, flags=0)
        kbd_up = KBDLLHOOKSTRUCT(vkCode=VK_F8, flags=0)
        errors: list[str] = []

        def toggle_worker() -> None:
            for _ in range(100):
                hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd_down))
                hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd_up))
                time.sleep(0.001)

        def mouse_worker() -> None:
            ms = MSLLHOOKSTRUCT()
            for i in range(500):
                ms.pt.x = i % 300
                ms.pt.y = i % 300
                hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
                if not hooks.active and hooks._last_pt is not None:
                    errors.append(f"Stale _last_pt while inactive: {hooks._last_pt}")

        t1 = threading.Thread(target=toggle_worker)
        t2 = threading.Thread(target=mouse_worker)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert errors == [], f"Detected race conditions: {errors[:5]}"

    def test_hook_is_healthy_property(self) -> None:
        hooks = InputHooks()
        assert hooks.is_healthy is False
        hooks._running = True
        mock_thread = MagicMock()
        mock_thread.is_alive.return_value = True
        hooks._thread = mock_thread
        hooks._kb_hook = 101
        hooks._mouse_hook = 202
        assert hooks.is_healthy is True

        # If thread dies
        mock_thread.is_alive.return_value = False
        assert hooks.is_healthy is False

        # If unhooked
        mock_thread.is_alive.return_value = True
        hooks._kb_hook = 0
        assert hooks.is_healthy is False

    def test_setcursorpos_failure_does_not_corrupt_last_pt(self) -> None:
        hooks = InputHooks()
        hooks._active = True
        hooks._center_pt = (960, 540)
        hooks._last_pt = (960, 540)
        hooks._recenter_threshold = 150

        ms = MSLLHOOKSTRUCT()
        ms.flags = 0
        ms.pt.x = 1200
        ms.pt.y = 540

        # _last_pt remains anchored at _center_pt (960, 540)
        with patch.object(input_hooks._user32, "SetCursorPos", return_value=0):
            res = hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
            assert res == 1
            assert hooks._last_pt == (960, 540)

    def test_multi_monitor_screen_center_detection(self) -> None:
        def fake_metrics(n: int) -> int:
            if n == 0:  # SM_CXSCREEN
                return 1920
            if n == 1:  # SM_CYSCREEN
                return 1080
            if n == 76:  # SM_XVIRTUALSCREEN
                return 0
            if n == 77:  # SM_YVIRTUALSCREEN
                return 0
            if n == 78:  # SM_CXVIRTUALSCREEN (dual 1080p monitors)
                return 3840
            if n == 79:  # SM_CYVIRTUALSCREEN
                return 1080
            return 0

        # Cursor is on monitor 2 at x=2500, y=500
        # Monitor 2 is from 1920 to 3840, center is (2880, 540)
        def fake_get_monitor_info(h: Any, p_mi: Any) -> int:
            mi = getattr(p_mi, "_obj", getattr(p_mi, "contents", None))
            if mi is not None:
                mi.rcMonitor.left = 1920
                mi.rcMonitor.top = 0
                mi.rcMonitor.right = 3840
                mi.rcMonitor.bottom = 1080
            return 1

        with (
            patch.object(input_hooks._user32, "GetSystemMetrics", side_effect=fake_metrics),
            patch.object(input_hooks._user32, "MonitorFromPoint", return_value=12345),
            patch.object(input_hooks._user32, "GetMonitorInfoW", side_effect=fake_get_monitor_info),
        ):
            cx, cy, rc = input_hooks._get_screen_center((2500, 500))
            assert cx == 2880
            assert cy == 540
            assert rc is not None
            assert rc.left == 1920 and rc.right == 3840


class TestWindowSwitchAndPreCaptureKeys:
    """Validate Alt+Tab / Win auto-deactivation, F11 passthrough, and pre-capture held key release."""

    def test_alt_tab_auto_deactivation_and_passthrough(self) -> None:
        toggled_states: list[bool] = []

        def _on_toggle(st: bool) -> None:
            toggled_states.append(st)

        hooks = InputHooks(on_toggle=_on_toggle)
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_TAB
        kbd.flags = LLKHF_ALTDOWN

        with patch.object(input_hooks._user32, "CallNextHookEx", return_value=42) as mock_next:
            res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            assert res == 42
            mock_next.assert_called_once()

        assert hooks.active is False
        assert toggled_states == [False]

    def test_windows_key_auto_deactivation(self) -> None:
        toggled_states: list[bool] = []

        def _on_toggle(st: bool) -> None:
            toggled_states.append(st)

        for win_vk in (VK_LWIN, VK_RWIN):
            toggled_states.clear()
            hooks = InputHooks(on_toggle=_on_toggle)
            hooks._active = True

            kbd = KBDLLHOOKSTRUCT()
            kbd.vkCode = win_vk
            kbd.flags = 0

            with patch.object(input_hooks._user32, "CallNextHookEx", return_value=42) as mock_next:
                res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
                assert res == 42
                mock_next.assert_called_once()

            assert hooks.active is False
            assert toggled_states == [False]

    def test_pre_capture_held_key_release_passthrough(self) -> None:
        hooks = InputHooks()
        hooks._active = True
        # W key (0x57) was pressed BEFORE F8 capture, so it is NOT in _keys_down
        assert 0x57 not in hooks._keys_down

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = 0x57
        kbd.flags = 0

        # When released (WM_KEYUP), must pass through so browser releases the key
        with patch.object(input_hooks._user32, "CallNextHookEx", return_value=42) as mock_next:
            res = hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
            assert res == 42
            mock_next.assert_called_once()

    def test_in_capture_key_release_swallowed(self) -> None:
        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = 0x57  # 'W'
        kbd.flags = 0

        # Press down during capture -> recorded and swallowed
        res_down = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert res_down == 1
        assert 0x57 in hooks.get_keys_pressed()

        # Release during capture -> discarded and swallowed
        with patch.object(input_hooks._user32, "CallNextHookEx") as mock_next:
            res_up = hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd))
            assert res_up == 1
            mock_next.assert_not_called()
        assert 0x57 not in hooks.get_keys_pressed()

    def test_f11_fullscreen_passthrough(self) -> None:
        assert VK_F11 in DEFAULT_PASSTHROUGH_KEYS

        hooks = InputHooks()
        hooks._active = True

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F11
        kbd.flags = 0

        with patch.object(input_hooks._user32, "CallNextHookEx", return_value=42) as mock_next:
            res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            assert res == 42
            mock_next.assert_called_once()

        # Capture remains active when F11 passes through
        assert hooks.active is True

    def test_reset_held_inputs(self) -> None:
        hooks = InputHooks()
        hooks._dx = 55
        hooks._dy = -33
        hooks._wheel_delta = 120
        hooks._lbutton = True
        hooks._rbutton = True
        hooks._mbutton = True
        hooks._xbutton1 = True
        hooks._xbutton2 = True

        hooks.reset_held_inputs()

        assert hooks._dx == 0
        assert hooks._dy == 0
        assert hooks._wheel_delta == 0
        assert hooks._lbutton is False
        assert hooks._rbutton is False
        assert hooks._mbutton is False
        assert hooks._xbutton1 is False
        assert hooks._xbutton2 is False

    def test_foreground_window_check_and_deactivate(self) -> None:
        toggled: list[bool] = []

        def _on_toggle(st: bool) -> None:
            toggled.append(st)

        hooks = InputHooks(on_toggle=_on_toggle)

        # Inactive or target_hwnd == 0 always returns True
        assert hooks.check_foreground_window() is True

        hooks._active = True
        hooks._target_hwnd = 0x1234

        # Foreground matches target -> returns True, remains active
        with patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0x1234):
            assert hooks.check_foreground_window() is True
            assert hooks.active is True
            assert len(toggled) == 0

        # Foreground changed to 0x5678 -> returns False, auto-deactivates, fires on_toggle(False)
        with patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0x5678):
            assert hooks.check_foreground_window() is False
            assert hooks.active is False
            assert hooks._target_hwnd == 0
            assert toggled == [False]

    def test_f8_activation_records_target_hwnd(self) -> None:
        hooks = InputHooks()
        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = input_hooks.VK_F8
        kbd.flags = 0

        with (
            patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0xABCD),
            patch.object(input_hooks._user32, "SetCursorPos"),
            patch.object(input_hooks._user32, "ClipCursor"),
            patch.object(input_hooks._user32, "CallNextHookEx", return_value=0),
        ):
            hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
            assert hooks.active is True
            assert hooks._target_hwnd == 0xABCD

    def test_foreground_window_chromium_fullscreen_pid_match(self) -> None:
        """When Chromium toggles F11 fullscreen, matching process ID preserves capture and updates target HWND."""
        hooks = InputHooks()
        hooks._active = True
        hooks._target_hwnd = 0x1000
        hooks._target_pid = 7777

        def fake_pid(h: Any, ptr: Any) -> int:
            ptr._obj.value = 7777
            return 1

        with (
            patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0x3000),
            patch.object(input_hooks._user32, "GetWindowThreadProcessId", side_effect=fake_pid),
        ):
            assert hooks.check_foreground_window() is True
            assert hooks.active is True
            assert hooks._target_hwnd == 0x3000

    def test_foreground_window_different_process_auto_deactivates(self) -> None:
        """Focusing an unrelated window belonging to a different process causes auto-deactivation."""
        toggled: list[bool] = []
        hooks = InputHooks(on_toggle=lambda st: toggled.append(st))
        hooks._active = True
        hooks._target_hwnd = 0x1000
        hooks._target_pid = 7777

        def diff_pid(h: Any, ptr: Any) -> int:
            ptr._obj.value = 8888
            return 1

        with (
            patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0x4000),
            patch.object(input_hooks._user32, "GetWindowThreadProcessId", side_effect=diff_pid),
        ):
            assert hooks.check_foreground_window() is False
            assert hooks.active is False
            assert hooks._target_hwnd == 0
            assert hooks._target_pid == 0
            assert toggled == [False]

    def test_foreground_window_null_hwnd_auto_deactivates(self) -> None:
        """Focus lost to null/desktop causes auto-deactivation."""
        hooks = InputHooks()
        hooks._active = True
        hooks._target_hwnd = 0x1000

        with patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0):
            assert hooks.check_foreground_window() is False
            assert hooks.active is False

    def test_foreground_window_chromium_fullscreen_lazy_pid_resolution(self) -> None:
        """When _target_pid is 0, check_foreground_window lazily queries and caches target PID."""
        hooks = InputHooks()
        hooks._active = True
        hooks._target_hwnd = 0x1000
        assert hooks._target_pid == 0

        def fake_pid(h: Any, ptr: Any) -> int:
            ptr._obj.value = 5555
            return 1

        with (
            patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0x2500),
            patch.object(input_hooks._user32, "GetWindowThreadProcessId", side_effect=fake_pid),
        ):
            assert hooks.check_foreground_window() is True
            assert hooks.active is True
            assert hooks._target_pid == 5555
            assert hooks._target_hwnd == 0x2500

    def test_foreground_window_exception_auto_deactivates(self) -> None:
        """If GetForegroundWindow raises an exception, foreground check safely auto-deactivates."""
        hooks = InputHooks()
        hooks._active = True
        hooks._target_hwnd = 0x1000
        hooks._target_pid = 7777

        with patch.object(
            input_hooks._user32, "GetForegroundWindow", side_effect=OSError("Win32 error")
        ):
            assert hooks.check_foreground_window() is False
            assert hooks.active is False

    def test_foreground_window_initial_zero_target_binds_to_current(self) -> None:
        """If capture starts when foreground is 0 (desktop), it safely binds to foreground window."""
        hooks = InputHooks()
        hooks._active = True
        hooks._target_hwnd = 0
        hooks._target_pid = 0

        def fake_pid(h: Any, ptr: Any) -> int:
            ptr._obj.value = 4321
            return 1

        with (
            patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0x5000),
            patch.object(input_hooks._user32, "GetWindowThreadProcessId", side_effect=fake_pid),
        ):
            assert hooks.check_foreground_window() is True
            assert hooks.active is True
            assert hooks._target_hwnd == 0x5000
            assert hooks._target_pid == 4321

    def test_check_foreground_window_aborts_if_deactivated_during_pid_query(self) -> None:
        """If capture becomes inactive while querying PID, check_foreground_window returns False without modifying target."""
        hooks = InputHooks()
        hooks._active = True
        hooks._target_hwnd = 0x1000
        hooks._target_pid = 7777

        def deactivate_during_call(h: Any, ptr: Any) -> int:
            hooks._active = False
            ptr._obj.value = 7777
            return 1

        with (
            patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0x3000),
            patch.object(
                input_hooks._user32, "GetWindowThreadProcessId", side_effect=deactivate_during_call
            ),
        ):
            assert hooks.check_foreground_window() is False
            assert hooks._target_hwnd == 0x1000

    def test_check_foreground_window_adopts_from_terminal_process_name(self) -> None:
        """If target process is a terminal image (e.g. windowsterminal.exe), switching to game/browser adopts it."""
        hooks = InputHooks()
        hooks._active = True
        hooks._target_hwnd = 0x1000
        hooks._target_pid = 8888  # WindowsTerminal.exe

        def fake_pid(h: Any, ptr: Any) -> int:
            ptr._obj.value = 9999  # chrome.exe
            return 1

        def fake_proc_name(pid: int) -> str:
            if pid == 8888:
                return "windowsterminal.exe"
            if pid == 9999:
                return "chrome.exe"
            return ""

        with (
            patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0x2000),
            patch.object(input_hooks._user32, "GetWindowThreadProcessId", side_effect=fake_pid),
            patch("input_hooks.get_process_image_name", side_effect=fake_proc_name),
        ):
            assert hooks.check_foreground_window() is True
            assert hooks.active is True
            assert hooks._target_hwnd == 0x2000
            assert hooks._target_pid == 9999

    def test_check_foreground_window_adopts_within_same_application(self) -> None:
        """Switching between tabs or windows of the same application adopts the new HWND/PID."""
        hooks = InputHooks()
        hooks._active = True
        hooks._target_hwnd = 0x1000
        hooks._target_pid = 5001  # Chrome tab 1

        def fake_pid(h: Any, ptr: Any) -> int:
            ptr._obj.value = 5002  # Chrome tab 2 (different PID)
            return 1

        with (
            patch.object(input_hooks._user32, "GetForegroundWindow", return_value=0x2000),
            patch.object(input_hooks._user32, "GetWindowThreadProcessId", side_effect=fake_pid),
            patch("input_hooks.get_process_image_name", return_value="chrome.exe"),
        ):
            assert hooks.check_foreground_window() is True
            assert hooks.active is True
            assert hooks._target_hwnd == 0x2000
            assert hooks._target_pid == 5002

    def test_momentary_ui_clutch_activation_and_release(self) -> None:
        """Holding ~ (VK_OEM_3) temporarily unswallows events and unclips cursor; releasing restores capture."""
        hooks = InputHooks()
        hooks._active = True
        hooks._center_pt = (960, 540)
        hooks._last_pt = (960, 540)

        kbd_down = KBDLLHOOKSTRUCT()
        kbd_down.vkCode = VK_OEM_3
        kbd_down.flags = 0

        with (
            patch.object(input_hooks._user32, "CallNextHookEx", return_value=42),
            patch.object(input_hooks._user32, "ClipCursor") as mock_clip,
            patch.object(input_hooks._user32, "SetCursorPos") as mock_set_cursor,
        ):
            # 1. Keydown on ~: activates clutch, unclips cursor
            res = hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd_down))
            assert res == 42
            assert hooks.clutch_active is True
            mock_clip.assert_called_with(None)

            # 2. While clutch is active, mouse move passes through to Windows/Chrome
            ms = MSLLHOOKSTRUCT()
            ms.flags = 0
            ms.pt.x = 500
            ms.pt.y = 300
            res_m = hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
            assert res_m == 42

            # 3. Keyup on ~: deactivates clutch, recenters cursor to (960, 540)
            kbd_up = KBDLLHOOKSTRUCT()
            kbd_up.vkCode = VK_OEM_3
            kbd_up.flags = 0
            res_up = hooks._keyboard_ll_proc(0, WM_KEYUP, ctypes.addressof(kbd_up))
            assert res_up == 42
            assert hooks.clutch_active is False
            mock_set_cursor.assert_called_with(960, 540)
