"""Unit tests for main.py application lifecycle, CLI security, and failsafe teardown."""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import vgamepad_compat  # noqa: F401  # isort: skip
import vgamepad as vg

import main
from main import (
    MAX_CONSECUTIVE_TICK_ERRORS,
    WAKEUP_PULSE_TICKS,
    WAKEUP_STICK_VALUE,
    AppLifecycle,
    parse_args,
    run_mapper,
    validate_profile_name,
)


class TestProfileNameValidation:
    """Validate profile name security and Windows filename constraints."""

    def test_valid_profile_names(self) -> None:
        valid_cases = [
            "Shooter",
            "RTS",
            "RTS / Menu",
            "Action / RPG",
            "rts_menu.json",
            "shooter.json",
            "Halo_Infinite",
            "profile-v2",
            "CallOfDuty2024",
        ]
        for name in valid_cases:
            ok, reason = validate_profile_name(name)
            assert ok is True, f"Expected {name!r} to be valid, got reason: {reason}"

    def test_empty_and_whitespace_rejected(self) -> None:
        for invalid in ["", "   ", "\t\n"]:
            ok, reason = validate_profile_name(invalid)
            assert ok is False
            assert "empty" in reason

    def test_type_error_rejected(self) -> None:
        ok, reason = validate_profile_name(123)  # type: ignore[arg-type]
        assert ok is False
        assert "string" in reason

    def test_excessive_length_rejected(self) -> None:
        long_name = "a" * 65
        ok, reason = validate_profile_name(long_name)
        assert ok is False
        assert "maximum length" in reason

    def test_null_byte_injection_rejected(self) -> None:
        ok, reason = validate_profile_name("Shooter\x00.json")
        assert ok is False
        assert "null byte" in reason

    def test_ntfs_alternate_data_stream_rejected(self) -> None:
        cases = ["Shooter:stream", "profile.json:hidden", "C:test"]
        for c in cases:
            ok, reason = validate_profile_name(c)
            assert ok is False
            assert "Alternate Data Stream" in reason

    def test_path_traversal_rejected(self) -> None:
        cases = [
            "../evil",
            "..\\evil",
            "sub/profile",
            "sub\\profile",
            "../../etc/passwd",
            "..",
            "/absolute",
            "\\windows\\system32",
        ]
        for c in cases:
            ok, reason = validate_profile_name(c)
            assert ok is False
            assert "forbidden path separators" in reason or "traversal" in reason

    def test_reserved_windows_device_names_rejected(self) -> None:
        reserved_cases = [
            "CON",
            "con",
            "PRN",
            "prn",
            "AUX",
            "NUL",
            "nul",
            "CONIN$",
            "conin$",
            "CONOUT$",
            "conout$",
            "COM0",
            "com0",
            "COM1",
            "com9",
            "LPT0",
            "lpt0",
            "LPT1",
            "lpt3",
            "CON.json",
            "nul.json",
            "aux.profile",
            "con.test.json",
            "com0.custom.json",
        ]
        for c in reserved_cases:
            ok, reason = validate_profile_name(c)
            assert ok is False, f"Expected reserved name {c!r} to be rejected"
            assert "reserved Windows device name" in reason

    def test_forbidden_filename_characters_rejected(self) -> None:
        cases = ["profile<1>", 'test"quote"', "wild*card", "pipe|name", "what?"]
        for c in cases:
            ok, reason = validate_profile_name(c)
            assert ok is False
            assert "forbidden characters" in reason

    def test_trailing_period_rejected(self) -> None:
        ok, reason = validate_profile_name("Shooter.")
        assert ok is False
        assert "cannot end with a period" in reason


class TestCLIArgumentParsing:
    """Validate argument parsing behaviors and defaults."""

    def test_default_arguments(self) -> None:
        args = parse_args([])
        assert args.profile is None
        assert args.list_profiles is False
        assert args.verbose is False

    def test_profile_flag(self) -> None:
        args = parse_args(["-p", "RTS"])
        assert args.profile == "RTS"

        args2 = parse_args(["--profile", "Shooter.json"])
        assert args2.profile == "Shooter.json"

    def test_list_profiles_flag(self) -> None:
        args = parse_args(["-l"])
        assert args.list_profiles is True

        args2 = parse_args(["--list-profiles"])
        assert args2.list_profiles is True

    def test_verbose_flag(self) -> None:
        args = parse_args(["-v"])
        assert args.verbose is True

        args2 = parse_args(["--verbose"])
        assert args2.verbose is True

    def test_check_flag(self) -> None:
        args = parse_args(["-c"])
        assert args.check is True

        args2 = parse_args(["--check"])
        assert args2.check is True


class TestListProfilesAndExecutionCLI:
    """Test CLI behavior under list-profiles and profile selection."""

    def test_check_execution_success(self) -> None:
        with patch.object(main, "verify_system_requirements", return_value=True):
            code = run_mapper(["--check"])
            assert code == 0

    def test_check_execution_failure(self) -> None:
        with patch.object(main, "verify_system_requirements", return_value=False):
            code = run_mapper(["--check"])
            assert code == 1

    def test_list_profiles_execution(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run_mapper(["--list-profiles"])
        assert code == 0
        captured = capsys.readouterr()
        assert "Available controller profiles:" in captured.out
        assert "Shooter" in captured.out

    def test_nonexistent_profile_handled_gracefully(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = run_mapper(["--profile", "NonExistentProfile123"])
        assert code == 1
        captured = capsys.readouterr()
        assert "[FAIL]" in captured.err
        assert "not found" in captured.err
        assert "Available profiles:" in captured.err

    def test_malicious_traversal_profile_handled_gracefully(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = run_mapper(["--profile", "../malicious"])
        assert code == 1
        captured = capsys.readouterr()
        assert "[FAIL] Invalid profile name:" in captured.err

    def test_reserved_device_profile_handled_gracefully(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = run_mapper(["--profile", "CON.json"])
        assert code == 1
        captured = capsys.readouterr()
        assert "[FAIL] Invalid profile name:" in captured.err


class TestAppLifecycleFailsafe:
    """Test AppLifecycle resource management and shutdown guarantees."""

    def test_lifecycle_context_manager_normal(self) -> None:
        with AppLifecycle() as lifecycle:
            assert lifecycle.shutdown_event.is_set() is False
        assert lifecycle._cleaned_up is True

    def test_lifecycle_cleanup_idempotent(self) -> None:
        lifecycle = AppLifecycle()
        lifecycle.cleanup()
        assert lifecycle._cleaned_up is True
        # Calling cleanup again should not raise or fail
        lifecycle.cleanup()
        assert lifecycle._cleaned_up is True

    def test_lifecycle_gamepad_reset_and_release(self) -> None:
        lifecycle = AppLifecycle()
        mock_gamepad = MagicMock()
        lifecycle.gamepad = mock_gamepad

        lifecycle.cleanup()

        mock_gamepad.reset.assert_called_once()
        mock_gamepad.update.assert_called_once()
        assert lifecycle.gamepad is None

    def test_lifecycle_hooks_stop(self) -> None:
        lifecycle = AppLifecycle()
        mock_hooks = MagicMock()
        lifecycle.hooks = mock_hooks

        lifecycle.cleanup()

        mock_hooks.stop.assert_called_once()
        assert lifecycle.hooks is None

    def test_lifecycle_winmm_timer_period_restored(self) -> None:
        lifecycle = AppLifecycle()
        lifecycle.timer_entered = True
        mock_timer = MagicMock()
        lifecycle.timer = mock_timer

        with patch.object(main, "_winmm", MagicMock()) as mock_winmm:
            lifecycle.cleanup()
            assert lifecycle.timer_entered is False
            mock_winmm.timeEndPeriod.assert_called_once()
            called_arg = mock_winmm.timeEndPeriod.call_args[0][0]
            assert getattr(called_arg, "value", called_arg) == 1
            assert lifecycle.timer is None

    def test_lifecycle_winmm_fallback_to_timer_exit(self) -> None:
        lifecycle = AppLifecycle()
        lifecycle.timer_entered = True
        mock_timer = MagicMock()
        lifecycle.timer = mock_timer

        with patch.object(main, "_winmm", None):
            lifecycle.cleanup()
            assert lifecycle.timer_entered is False
            mock_timer.__exit__.assert_called_once_with(None, None, None)
            assert lifecycle.timer is None

    def test_lifecycle_cursor_unclipped(self) -> None:
        lifecycle = AppLifecycle()
        with patch.object(main, "_user32", MagicMock()) as mock_user32:
            lifecycle.cleanup()
            mock_user32.ClipCursor.assert_called_once_with(None)

    def test_lifecycle_console_ctrl_close_triggers_cleanup(self) -> None:
        lifecycle = AppLifecycle()
        lifecycle.setup_handlers()

        # Simulate CTRL_CLOSE_EVENT (2)
        assert lifecycle._console_ctrl_routine is not None
        # Call the underlying routine
        ret = lifecycle._console_ctrl_routine(2)
        assert ret == 1
        assert lifecycle.shutdown_event.is_set() is True
        assert lifecycle._cleaned_up is True

    def test_lifecycle_console_ctrl_c_sets_event(self) -> None:
        lifecycle = AppLifecycle()
        lifecycle.setup_handlers()

        # Simulate CTRL_C_EVENT (0)
        assert lifecycle._console_ctrl_routine is not None
        ret = lifecycle._console_ctrl_routine(0)
        assert ret == 0  # Allow Python KeyboardInterrupt
        assert lifecycle.shutdown_event.is_set() is True


class TestMainLoopExceptionResilience:
    """Test per-tick exception handling and max consecutive tick failure."""

    def test_transient_tick_error_recovers(self) -> None:
        mock_gamepad = MagicMock()
        consecutive_tick_errors = 0

        # Simulate a transient exception on tick 1, followed by success on tick 2
        for tick in range(2):
            try:
                if tick == 0:
                    raise RuntimeError("Temporary math glitch")
                consecutive_tick_errors = 0
            except Exception:
                consecutive_tick_errors += 1
                mock_gamepad.reset()
                mock_gamepad.update()

        assert consecutive_tick_errors == 0
        assert mock_gamepad.reset.call_count == 1
        assert mock_gamepad.update.call_count == 1

    def test_max_consecutive_tick_errors_breaks_loop(self) -> None:
        mock_gamepad = MagicMock()
        consecutive_tick_errors = 0
        broken = False

        for _ in range(MAX_CONSECUTIVE_TICK_ERRORS + 5):
            try:
                raise RuntimeError("Persistent driver communication failure")
            except Exception:
                consecutive_tick_errors += 1
                mock_gamepad.reset()
                mock_gamepad.update()

                if consecutive_tick_errors >= MAX_CONSECUTIVE_TICK_ERRORS:
                    broken = True
                    break

        assert broken is True
        assert consecutive_tick_errors == MAX_CONSECUTIVE_TICK_ERRORS

    def test_lifecycle_cleanup_clears_timer_period_count(self) -> None:
        import stick_mapper
        from stick_mapper import HighResTimer

        initial_count = stick_mapper._period_active_count
        with AppLifecycle() as lc:
            timer = HighResTimer(hz=250.0)
            lc.timer = timer
            timer.__enter__()
            lc.timer_entered = True
            assert stick_mapper._period_active_count == initial_count + 1

        assert stick_mapper._period_active_count == initial_count

    def test_ci_flag_argument_and_check(self) -> None:
        args = parse_args(["--check", "--ci"])
        assert args.check is True
        assert args.ci is True

        with patch("main.verify_system_requirements", return_value=True) as mock_verify:
            ret = run_mapper(["--check", "--ci"])
            assert ret == 0
            mock_verify.assert_called_once_with(ci_mode=True)

    def test_profile_selection_normalized_matching(self) -> None:
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad"),
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer"),
        ):
            instance = mock_hooks.return_value
            instance.active = False
            instance.consume_profile_cycle.return_value = False
            instance.is_healthy = True

            # Use -p RTS to verify it resolves to "RTS / Menu"
            with patch("time.sleep", side_effect=KeyboardInterrupt):
                ret = run_mapper(["-p", "RTS"])
                assert ret == 0

    def test_main_loop_detects_unhealthy_hook_subsystem(self) -> None:
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad"),
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer"),
        ):
            instance = mock_hooks.return_value
            instance.active = True
            instance.consume_profile_cycle.return_value = False
            # Simulate hook thread dying / becoming unhealthy
            instance.is_healthy = False

            ret = run_mapper([])
            assert ret == 1

    def test_verify_system_requirements_check_controller_flag(self) -> None:
        with (
            patch("main.check_python_version", return_value=(True, "")),
            patch("main.check_architecture", return_value=(True, "")),
            patch("main.check_windows_os", return_value=(True, "")),
            patch("main.check_vigembus_service", return_value=(True, "")),
            patch("main.check_vgamepad_controller") as mock_check_ctrl,
        ):
            # check_controller=False should skip check_vgamepad_controller
            ok = main.verify_system_requirements(ci_mode=True, check_controller=False)
            assert ok is True
            mock_check_ctrl.assert_not_called()

            # check_controller=True calls check_vgamepad_controller
            mock_check_ctrl.return_value = (True, "")
            ok2 = main.verify_system_requirements(ci_mode=True, check_controller=True)
            assert ok2 is True
            mock_check_ctrl.assert_called_once_with(ci_mode=True)

    def test_run_mapper_skips_controller_check_on_startup(self) -> None:
        with (
            patch("main.verify_system_requirements", return_value=True) as mock_verify,
            patch("vgamepad.VX360Gamepad"),
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer"),
        ):
            instance = mock_hooks.return_value
            instance.active = False
            instance.consume_profile_cycle.return_value = False
            instance.is_healthy = True

            with patch("time.sleep", side_effect=KeyboardInterrupt):
                run_mapper([])

            # Verify that verify_system_requirements was called with check_controller=False
            mock_verify.assert_called_once_with(
                ci_mode=mock_verify.call_args.kwargs.get("ci_mode"), check_controller=False
            )

    def test_wakeup_pulse_on_f8_activation(self) -> None:
        """Verify 40ms 10-tick Chromium wakeup pulse on F8 activation and immediate cancellation on mouse move."""
        # 1. On F8 activation with dx=0, dy=0:
        # right_joystick(x_value=1, y_value=0) sent for WAKEUP_PULSE_TICKS (10 ticks)
        # then returns to (0, 0) on the 11th tick.
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > WAKEUP_PULSE_TICKS + 1:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                run_mapper([])

            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(rj_calls) >= WAKEUP_PULSE_TICKS + 1

            # Ticks 1 to WAKEUP_PULSE_TICKS (first 10 ticks) must be overridden with WAKEUP_STICK_VALUE
            for i in range(WAKEUP_PULSE_TICKS):
                assert rj_calls[i] == ((), {"x_value": WAKEUP_STICK_VALUE, "y_value": 0}), (
                    f"Tick {i + 1} expected WAKEUP_STICK_VALUE ({WAKEUP_STICK_VALUE}), got {rj_calls[i]}"
                )

            # Tick 11 (next tick) must restore naturally to (0, 0)
            assert rj_calls[WAKEUP_PULSE_TICKS] == ((), {"x_value": 0, "y_value": 0}), (
                f"Tick 11 expected neutral (0, 0), got {rj_calls[WAKEUP_PULSE_TICKS]}"
            )

            # Verification of update commits:
            # 1 (init) + 1 (tick 1 pulse start) + 1 (tick 11 pulse end neutral) + 1 (cleanup) = 4
            assert pad_instance.update.call_count == 4

        # 2. Moving the mouse horizontally (dx != 0) immediately cancels any remaining wakeup ticks
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.is_healthy = True
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Return (0, 0) on tick 1 (wakeup tick 1 fires), then (25, 0) on tick 2 (mouse move cancels wakeup)
            deltas = [(0, 0), (25, 0), (0, 0), (0, 0)]
            hooks_inst.consume_mouse_delta.side_effect = lambda: deltas.pop(0) if deltas else (0, 0)

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait2() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 4:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait2

            with patch("time.sleep"):
                run_mapper([])

            rj_calls = pad_instance.right_joystick.call_args_list
            wakeup_call_count = sum(
                1 for c in rj_calls if c == ((), {"x_value": WAKEUP_STICK_VALUE, "y_value": 0})
            )
            assert wakeup_call_count == 1, (
                f"Expected exactly 1 wakeup call before cancellation, but got {wakeup_call_count}"
            )

        # 3. Moving the mouse vertically (dy != 0) immediately cancels any remaining wakeup ticks
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.is_healthy = True
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Return (0, 0) on tick 1, then (0, 25) on tick 2
            deltas_y = [(0, 0), (0, 25), (0, 0), (0, 0)]
            hooks_inst.consume_mouse_delta.side_effect = lambda: (
                deltas_y.pop(0) if deltas_y else (0, 0)
            )

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait3() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 4:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait3

            with patch("time.sleep"):
                run_mapper([])

            rj_calls = pad_instance.right_joystick.call_args_list
            wakeup_call_count = sum(
                1 for c in rj_calls if c == ((), {"x_value": WAKEUP_STICK_VALUE, "y_value": 0})
            )
            assert wakeup_call_count == 1, (
                f"Expected exactly 1 wakeup call before cancellation by dy, but got {wakeup_call_count}"
            )

        # 4. Moving the mouse on tick 1 immediately cancels wakeup before any pulse is sent
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.is_healthy = True
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Moving mouse immediately on tick 1
            deltas_immediate = [(15, 0), (0, 0), (0, 0)]
            hooks_inst.consume_mouse_delta.side_effect = lambda: (
                deltas_immediate.pop(0) if deltas_immediate else (0, 0)
            )

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait4() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 3:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait4

            with patch("time.sleep"):
                run_mapper([])

            rj_calls = pad_instance.right_joystick.call_args_list
            wakeup_call_count = sum(
                1 for c in rj_calls if c == ((), {"x_value": WAKEUP_STICK_VALUE, "y_value": 0})
            )
            assert wakeup_call_count == 0, (
                f"Expected 0 wakeup calls when mouse moves on tick 1, but got {wakeup_call_count}"
            )

    def test_hot_reconnect_at_ten_consecutive_tick_errors(self) -> None:
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            mock_hooks_inst = mock_hooks.return_value
            mock_hooks_inst.active = True
            mock_hooks_inst.is_healthy = True
            mock_hooks_inst.consume_profile_cycle.return_value = False
            mock_hooks_inst.check_foreground_window.return_value = True

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 10:
                    raise KeyboardInterrupt
                raise RuntimeError("Kernel IOCTL dropped during sleep")

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                run_mapper([])

            # Initial allocation + 1 hot-reconnect at error 10 = 2 allocations
            assert mock_pad_cls.call_count == 2

    def test_hot_reconnect_instantiation_failure_resilience(self) -> None:
        """When VX360Gamepad fails during hot-reconnect, gamepad remains bound and does not raise UnboundLocalError."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            mock_hooks_inst = mock_hooks.return_value
            mock_hooks_inst.active = True
            mock_hooks_inst.is_healthy = True
            mock_hooks_inst.consume_profile_cycle.return_value = False
            mock_hooks_inst.check_foreground_window.return_value = True

            timer_inst = mock_timer.return_value
            tick_count = 0

            # 1st call succeeds (initialization), 2nd call fails (hot-reconnect)
            init_pad = MagicMock()
            mock_pad_cls.side_effect = [init_pad, RuntimeError("Driver communication fault")]

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 12:
                    raise KeyboardInterrupt
                raise RuntimeError("Kernel IOCTL dropped during sleep")

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                run_mapper([])

            # Verified loop survived past tick 10 to tick 12 without UnboundLocalError
            assert tick_count == 13

    def test_register_notification_warning_when_player_2(
        self, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
    ) -> None:
        """Verify ViGEmBus register_notification warns if assigned to Player 2 (led_number == 1)."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False

            with patch("time.sleep", side_effect=KeyboardInterrupt):
                run_mapper([])

            pad_instance.register_notification.assert_called_once()
            callback = pad_instance.register_notification.call_args[0][0]

            # Clear startup logs / outputs
            capsys.readouterr()
            caplog.clear()

            # Trigger notification with led_number = 1 (Player 2)
            with caplog.at_level(logging.WARNING, logger="vg_mapper"):
                callback(None, None, 0, 0, 1, None)

            # Verify logger.warning was called
            assert any(
                "Slot 1" in rec.message
                and "Player 2" in rec.message
                and "xbox.com/play" in rec.message
                for rec in caplog.records
            )

            # Verify stdout output
            captured = capsys.readouterr()
            assert "[WARNING]" in captured.out
            assert "Slot 1" in captured.out
            assert "Player 2" in captured.out
            assert "xbox.com/play" in captured.out

            # Verify deduplication (printed once to stdout)
            callback(None, None, 0, 0, 1, None)
            captured_again = capsys.readouterr()
            assert captured_again.out == ""

    def test_register_notification_no_warning_when_player_1(
        self, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
    ) -> None:
        """Verify ViGEmBus register_notification does not warn when assigned to Player 1 (led_number == 0)."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False

            with patch("time.sleep", side_effect=KeyboardInterrupt):
                run_mapper([])

            pad_instance.register_notification.assert_called_once()
            callback = pad_instance.register_notification.call_args[0][0]

            capsys.readouterr()
            caplog.clear()

            with caplog.at_level(logging.WARNING, logger="vg_mapper"):
                callback(None, None, 0, 0, 0, None)

            # Slot 0 is Player 1: no warning should be logged or printed
            assert not any("Slot" in rec.message for rec in caplog.records)
            captured = capsys.readouterr()
            assert "[WARNING]" not in captured.out

    def test_lifecycle_cleanup_unregisters_notification_safely(self) -> None:
        """Verify AppLifecycle.cleanup cleanly unregisters notification before deleting gamepad."""
        lifecycle = AppLifecycle()
        mock_gamepad = MagicMock()
        lifecycle.gamepad = mock_gamepad

        lifecycle.cleanup()

        mock_gamepad.unregister_notification.assert_called_once()
        mock_gamepad.reset.assert_called_once()
        mock_gamepad.update.assert_called_once()
        assert lifecycle.gamepad is None

    def test_wakeup_cancelled_on_f9_profile_switch(self) -> None:
        """Verify that F9 profile cycling immediately resets wakeup_ticks_remaining."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Trigger F9 profile cycle on tick 2
            f9_cycles = [False, True, False, False]
            hooks_inst.consume_profile_cycle.side_effect = lambda: (
                f9_cycles.pop(0) if f9_cycles else False
            )

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 4:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                run_mapper([])

            rj_calls = pad_instance.right_joystick.call_args_list
            # Tick 1 sent wakeup value. Tick 2 had F9 which reset wakeup_ticks_remaining to 0.
            # Tick 2 onwards did not send wakeup value.
            wakeup_call_count = sum(
                1 for c in rj_calls if c == ((), {"x_value": WAKEUP_STICK_VALUE, "y_value": 0})
            )
            assert wakeup_call_count == 1

    def test_register_notification_exception_suppression(self) -> None:
        """Verify that register_notification raising an exception does not abort run_mapper."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            _ = mock_timer
            pad_instance = mock_pad_cls.return_value
            pad_instance.register_notification.side_effect = RuntimeError(
                "Driver notification unsupported"
            )
            hooks_inst = mock_hooks.return_value
            hooks_inst.active = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False

            with patch("time.sleep", side_effect=KeyboardInterrupt):
                ret = run_mapper([])
                assert ret == 0

    def test_lifecycle_cleanup_unregister_notification_exception_suppressed(self) -> None:
        """Verify that an exception in unregister_notification does not break cleanup."""
        lifecycle = AppLifecycle()
        mock_gamepad = MagicMock()
        mock_gamepad.unregister_notification.side_effect = RuntimeError(
            "Failed to unregister notification"
        )
        lifecycle.gamepad = mock_gamepad

        lifecycle.cleanup()

        mock_gamepad.reset.assert_called_once()
        mock_gamepad.update.assert_called_once()
        assert lifecycle.gamepad is None

    def test_wakeup_cancelled_on_deactivation_and_restarts_on_reactivation(self) -> None:
        """Verify wakeup pulse cancels on F8 deactivation and restarts on next F8 activation."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Sequence of active states:
            # Tick 1: active=True (wakeup pulse starts: 10 remaining -> 9)
            # Tick 2: active=True (wakeup pulse tick 2: 9 remaining -> 8)
            # Tick 3: active=False (deactivation resets wakeup_ticks_remaining to 0)
            # Tick 4: active=True (reactivation triggers new 10-tick wakeup pulse)
            active_sequence = [True, True, False, True, True]

            def fake_active_prop() -> bool:
                if active_sequence:
                    return active_sequence.pop(0)
                raise KeyboardInterrupt

            type(hooks_inst).active = property(lambda self: fake_active_prop())  # type: ignore[assignment]

            timer_inst = mock_timer.return_value
            timer_inst.wait.return_value = 0.004

            with patch("time.sleep"):
                run_mapper([])

            rj_calls = pad_instance.right_joystick.call_args_list
            wakeup_call_count = sum(
                1 for c in rj_calls if c == ((), {"x_value": WAKEUP_STICK_VALUE, "y_value": 0})
            )
            # 2 calls during 1st activation + 2 calls during 2nd activation = 4 wakeup calls
            assert wakeup_call_count == 4

    def test_register_notification_synchronous_callback_on_registration(
        self, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
    ) -> None:
        """Verify warning is handled correctly if ViGEmBus calls callback synchronously during register_notification."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            _ = mock_timer
            pad_instance = mock_pad_cls.return_value

            def fake_register(cb: Any) -> None:
                # Driver fires notification synchronously with led_number = 1
                cb(None, None, 0, 0, 1, None)

            pad_instance.register_notification.side_effect = fake_register

            hooks_inst = mock_hooks.return_value
            hooks_inst.active = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False

            with (
                caplog.at_level(logging.WARNING, logger="vg_mapper"),
                patch("time.sleep", side_effect=KeyboardInterrupt),
            ):
                run_mapper([])

            # Verify logger.warning was called
            assert any(
                "Slot 1" in rec.message
                and "Player 2" in rec.message
                and "xbox.com/play" in rec.message
                for rec in caplog.records
            )

            # Verify stdout output
            captured = capsys.readouterr()
            assert "[WARNING]" in captured.out
            assert "Slot 1" in captured.out
            assert "Player 2" in captured.out

    def test_register_notification_higher_player_slots(
        self, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
    ) -> None:
        """Verify ViGEmBus register_notification warns properly for Slot 2 (Player 3) and Slot 3 (Player 4)."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False

            with patch("time.sleep", side_effect=KeyboardInterrupt):
                run_mapper([])

            callback = pad_instance.register_notification.call_args[0][0]

            capsys.readouterr()
            caplog.clear()

            # Test Slot 2 (Player 3)
            with caplog.at_level(logging.WARNING, logger="vg_mapper"):
                callback(None, None, 0, 0, 2, None)

            assert any(
                "Slot 2" in rec.message and "Player 3" in rec.message for rec in caplog.records
            )
            captured = capsys.readouterr()
            assert "Slot 2" in captured.out
            assert "Player 3" in captured.out

    def test_hot_reconnect_unregisters_old_controller_before_allocating(self) -> None:
        """Verify that hot-reconnect cleans up the old controller before creating the new one."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            mock_hooks_inst = mock_hooks.return_value
            mock_hooks_inst.active = True
            mock_hooks_inst.is_healthy = True
            mock_hooks_inst.consume_profile_cycle.return_value = False
            mock_hooks_inst.check_foreground_window.return_value = True

            init_pad = MagicMock()
            reconnect_pad = MagicMock()
            mock_pad_cls.side_effect = [init_pad, reconnect_pad]

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 10:
                    raise KeyboardInterrupt
                raise RuntimeError("Kernel IOCTL dropped during sleep")

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                run_mapper([])

            # Old gamepad must have had unregister_notification called
            init_pad.unregister_notification.assert_called_once()
            init_pad.reset.assert_called()
            # New gamepad must have had register_notification called
            reconnect_pad.register_notification.assert_called_once()


class TestMouseStickRouting:
    """Verify routing of physical mouse and WASD keys to joysticks based on mouse_stick configuration."""

    def test_mouse_stick_left_routes_mouse_to_left_and_wasd_to_right(self) -> None:
        """When mouse_stick is 'left' (e.g. RTS / Menu), mouse -> left stick and WASD -> right stick."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (50, 0)
            hooks_inst.get_keys_pressed.return_value = {87}  # 'W' key (Up)
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 1:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "rts_menu"])
                assert ret == 0

            # Mouse output must go to left joystick
            lj_calls = pad_instance.left_joystick.call_args_list
            assert len(lj_calls) >= 1
            first_lj_call = lj_calls[0]
            assert first_lj_call[1]["x_value"] > 0
            assert first_lj_call[1]["y_value"] == 0

            # WASD output (W = Up) must go to right joystick
            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(rj_calls) >= 1
            first_rj_call = rj_calls[0]
            assert first_rj_call[1]["x_value"] == 0
            assert first_rj_call[1]["y_value"] == 32767

    def test_mouse_stick_right_routes_mouse_to_right_and_wasd_to_left(self) -> None:
        """When mouse_stick is 'right' (default / Shooter), mouse -> right stick and WASD -> left stick."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (50, 0)
            hooks_inst.get_keys_pressed.return_value = {87}  # 'W' key (Up)
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 1:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0
                assert pad_instance.reset.called

            # Mouse output must go to right joystick
            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(rj_calls) >= 1
            first_rj_call = rj_calls[0]
            assert first_rj_call[1]["x_value"] > 0
            assert first_rj_call[1]["y_value"] == 0

            # WASD output (W = Up) must go to left joystick
            lj_calls = pad_instance.left_joystick.call_args_list
            assert len(lj_calls) >= 1
            first_lj_call = lj_calls[0]
            assert first_lj_call[1]["x_value"] == 0
            assert first_lj_call[1]["y_value"] == 32767

    def test_wakeup_pulse_routes_to_left_joystick_when_mouse_stick_is_left(self) -> None:
        """Wakeup pulse must route to left_joystick when mouse_stick == 'left'."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 1:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "rts_menu"])
                assert ret == 0

            # Left stick must receive wakeup pulse
            lj_calls = pad_instance.left_joystick.call_args_list
            assert len(lj_calls) >= 1
            assert lj_calls[0] == ((), {"x_value": WAKEUP_STICK_VALUE, "y_value": 0})

            # Right stick (WASD) must be neutral
            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(rj_calls) >= 1
            assert rj_calls[0] == ((), {"x_value": 0, "y_value": 0})

    def test_wakeup_pulse_routes_to_right_joystick_when_mouse_stick_is_right(self) -> None:
        """Wakeup pulse must route to right_joystick when mouse_stick == 'right'."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 1:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0
                assert pad_instance.reset.called

            # Right stick must receive wakeup pulse
            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(rj_calls) >= 1
            assert rj_calls[0] == ((), {"x_value": WAKEUP_STICK_VALUE, "y_value": 0})

            # Left stick (WASD) must be neutral
            lj_calls = pad_instance.left_joystick.call_args_list
            assert len(lj_calls) >= 1
            assert lj_calls[0] == ((), {"x_value": 0, "y_value": 0})

    def test_rts_menu_profile_routes_mouse_to_left_and_wasd_to_right(self) -> None:
        """Verify RTS / Menu profile (--profile rts_menu) routes mouse to left stick and WASD to right stick."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (40, -20)
            hooks_inst.get_keys_pressed.return_value = {68}  # 'D' key (Right)
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 1:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "rts_menu"])
                assert ret == 0

            # Mouse output must go to left joystick (dy=-20 inverted -> positive stick Y)
            lj_calls = pad_instance.left_joystick.call_args_list
            assert len(lj_calls) >= 1
            assert lj_calls[0][1]["x_value"] > 0
            assert lj_calls[0][1]["y_value"] > 0

            # WASD output (D = Right) must go to right joystick
            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(rj_calls) >= 1
            assert rj_calls[0][1]["x_value"] == 32767
            assert rj_calls[0][1]["y_value"] == 0

    def test_rts_walk_key_halves_wasd_on_right_joystick(self) -> None:
        """In RTS / Menu, walk key (VK_LMENU = 0xA4) halves the camera pan speed on right_joystick."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (40, -20)
            # W key (87) + Left Alt walk key (0xA4)
            hooks_inst.get_keys_pressed.return_value = {87, 0xA4}
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 1:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "rts_menu"])
                assert ret == 0

            # Right stick (WASD) must have halved magnitude (32767 // 2 = 16383)
            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(rj_calls) >= 1
            assert rj_calls[0][1]["x_value"] == 0
            assert rj_calls[0][1]["y_value"] == 16383

    def test_runtime_profile_cycling_dynamically_switches_joystick_routing(self) -> None:
        """Switching profile at runtime via F9 swaps joystick routing from right to left stick."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (50, 0)
            hooks_inst.get_keys_pressed.return_value = {87}  # 'W' key
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            # Tick 1: Action / RPG (mouse -> right stick, wasd -> left stick)
            # Tick 2: F9 cycle consumes True -> switches to RTS / Menu
            # Tick 3: RTS / Menu (mouse -> left stick, wasd -> right stick)
            cycle_events = [False, True, False]

            def fake_cycle() -> bool:
                if cycle_events:
                    return cycle_events.pop(0)
                return False

            hooks_inst.consume_profile_cycle.side_effect = fake_cycle

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 2:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                # Start with Action / RPG profile
                ret = run_mapper(["--profile", "action_rpg"])
                assert ret == 0

            lj_calls = pad_instance.left_joystick.call_args_list
            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(lj_calls) >= 2
            assert len(rj_calls) >= 2

            # Tick 1 (Action / RPG): mouse -> right stick, wasd -> left stick
            assert rj_calls[0][1]["x_value"] > 0
            assert lj_calls[0][1]["y_value"] == 32767

            # Tick 2 (RTS / Menu after cycle): mouse -> left stick, wasd -> right stick
            assert lj_calls[1][1]["x_value"] > 0
            assert rj_calls[1][1]["y_value"] == 32767

    def test_wakeup_pulse_left_thumb_press_and_release(self) -> None:
        """Verify XUSB_GAMEPAD_LEFT_THUMB is pressed during 10-tick wakeup pulse and released when it ends."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > WAKEUP_PULSE_TICKS + 1:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper([])
                assert ret == 0

            # Verify LEFT_THUMB pressed during the 10 wakeup ticks, and Button A is NOT pressed
            press_calls = [
                c
                for c in pad_instance.press_button.call_args_list
                if c == ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB})
            ]
            assert len(press_calls) == WAKEUP_PULSE_TICKS
            assert (
                (),
                {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_A},
            ) not in pad_instance.press_button.call_args_list

            # Verify LEFT_THUMB released when wakeup ticks transition to 0 (tick 11)
            release_calls = [
                c
                for c in pad_instance.release_button.call_args_list
                if c == ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB})
            ]
            assert len(release_calls) >= 1

    def test_wakeup_pulse_left_thumb_cancelled_by_mouse_move(self) -> None:
        """Moving the mouse during wakeup pulse immediately cancels pulse and releases LEFT_THUMB."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.consume_stick_swap.return_value = False
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Tick 1: (0, 0) -> wakeup pulse fires, press_button called
            # Tick 2: (25, 0) -> mouse move cancels wakeup pulse, release_button called
            # Tick 3: (0, 0) -> wakeup cancelled, remains released
            deltas = [(0, 0), (25, 0), (0, 0)]
            hooks_inst.consume_mouse_delta.side_effect = lambda: deltas.pop(0) if deltas else (0, 0)

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 3:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0

            press_calls = [
                c
                for c in pad_instance.press_button.call_args_list
                if c == ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB})
            ]
            assert len(press_calls) == 1  # Only tick 1 had pulse active

            release_calls = [
                c
                for c in pad_instance.release_button.call_args_list
                if c == ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB})
            ]
            assert len(release_calls) >= 1

    def test_wakeup_pulse_left_thumb_held_if_physically_pressed_in_profile(self) -> None:
        """When a physical input mapped to LEFT_THUMB is pressed, button is not released on wakeup cancellation."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.consume_stick_swap.return_value = False
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Tick 1: no keys -> wakeup pulse active
            # Tick 2, 3: VK_R pressed (0x52, mapped to LEFT_THUMB in rts_menu)
            keys_list = [set(), {ord("R")}, {ord("R")}]
            hooks_inst.get_keys_pressed.side_effect = lambda: (
                keys_list.pop(0) if keys_list else {ord("R")}
            )

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 3:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "rts_menu"])
                assert ret == 0

            presses = [
                c
                for c in pad_instance.press_button.call_args_list
                if c == ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB})
            ]
            assert len(presses) >= 2  # Wakeup pulse tick 1 + profile mapping tick 2

    def test_wakeup_pulse_left_thumb_cancelled_by_f8_deactivation(self) -> None:
        """Deactivating capture during wakeup pulse releases LEFT_THUMB immediately."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.consume_stick_swap.return_value = False
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            active_states = [True, False]
            type(hooks_inst).active = property(
                lambda self: active_states.pop(0) if active_states else False
            )

            timer_inst = mock_timer.return_value
            timer_inst.wait.return_value = 0.004

            with patch("time.sleep", side_effect=KeyboardInterrupt):
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0

            presses = [
                c
                for c in pad_instance.press_button.call_args_list
                if c == ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB})
            ]
            assert len(presses) == 1
            releases = [
                c
                for c in pad_instance.release_button.call_args_list
                if c == ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB})
            ]
            assert len(releases) >= 1

    def test_f10_stick_swap_runtime_toggle(self) -> None:
        """Verify F10 runtime stick swap toggles mouse routing between Right and Left sticks."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (50, 0)
            hooks_inst.get_keys_pressed.return_value = {87}  # 'W' key
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            # Tick 1: normal Shooter (mouse -> right stick, wasd -> left stick)
            # Tick 2: F10 swap consumed -> overrides to left stick
            # Tick 3: swapped (mouse -> left stick, wasd -> right stick)
            # Tick 4: F10 swap consumed -> toggles back to right stick
            # Tick 5: restored (mouse -> right stick, wasd -> left stick)
            f10_swaps = [False, True, False, True, False]

            def fake_swap() -> bool:
                if f10_swaps:
                    return f10_swaps.pop(0)
                return False

            hooks_inst.consume_stick_swap.side_effect = fake_swap

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 5:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0
                assert pad_instance.reset.called

            lj_calls = pad_instance.left_joystick.call_args_list
            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(lj_calls) >= 5
            assert len(rj_calls) >= 5

            # Tick 1 (default Shooter): mouse -> RS, wasd -> LS
            assert rj_calls[0][1]["x_value"] > 0
            assert lj_calls[0][1]["y_value"] == 32767

            # Tick 2: F10 swap resets sticks to (0, 0), then routes mouse -> LS, wasd -> RS
            assert lj_calls[1] == ((), {"x_value": 0, "y_value": 0})
            assert rj_calls[1] == ((), {"x_value": 0, "y_value": 0})
            assert lj_calls[2][1]["x_value"] > 0
            assert rj_calls[2][1]["y_value"] == 32767

            # Tick 4: F10 swap resets sticks to (0, 0), then routes mouse -> RS, wasd -> LS
            assert lj_calls[4] == ((), {"x_value": 0, "y_value": 0})
            assert rj_calls[4] == ((), {"x_value": 0, "y_value": 0})
            assert rj_calls[5][1]["x_value"] > 0
            assert lj_calls[5][1]["y_value"] == 32767

    def test_f10_stick_swap_runtime_toggle_on_left_stick_profile(self) -> None:
        """Verify F10 runtime stick swap toggles mouse routing when base profile has mouse_stick='left'."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (50, 0)
            hooks_inst.get_keys_pressed.return_value = {87}
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            # Tick 1: RTS / Menu (mouse -> left stick, wasd -> right stick)
            # Tick 2: F10 swap -> overrides to right stick
            # Tick 4: F10 swap -> toggles back to left stick
            f10_swaps = [False, True, False, True, False]
            hooks_inst.consume_stick_swap.side_effect = lambda: (
                f10_swaps.pop(0) if f10_swaps else False
            )

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 5:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "rts_menu"])
                assert ret == 0

            lj_calls = pad_instance.left_joystick.call_args_list
            rj_calls = pad_instance.right_joystick.call_args_list

            # Tick 1 (default RTS): mouse -> LS, wasd -> RS
            assert lj_calls[0][1]["x_value"] > 0
            assert rj_calls[0][1]["y_value"] > 0

            # Tick 2: F10 swap resets sticks to (0, 0), then routes mouse -> RS, wasd -> LS
            assert lj_calls[1] == ((), {"x_value": 0, "y_value": 0})
            assert rj_calls[1] == ((), {"x_value": 0, "y_value": 0})
            assert rj_calls[2][1]["x_value"] > 0
            assert lj_calls[2][1]["y_value"] > 0

            # Tick 4: F10 swap resets sticks to (0, 0), then routes mouse -> LS, wasd -> RS
            assert lj_calls[4] == ((), {"x_value": 0, "y_value": 0})
            assert rj_calls[4] == ((), {"x_value": 0, "y_value": 0})
            assert lj_calls[5][1]["x_value"] > 0
            assert rj_calls[5][1]["y_value"] > 0

    def test_f10_stick_swap_override_resets_on_f9_profile_cycle(self) -> None:
        """Verify that stick_swap_override is reset to False when cycling profiles via F9."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (50, 0)
            hooks_inst.get_keys_pressed.return_value = {87}
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            # Tick 1: normal Shooter (mouse -> RS, wasd -> LS)
            # Tick 2: F10 swap -> effective stick becomes 'left' (mouse -> LS, wasd -> RS)
            # Tick 3: F9 cycle -> cycles profile to Action / RPG (mouse_stick='right'), resets stick_swap_override to False
            # Tick 4: under Action / RPG with stick_swap_override=False -> mouse routes to RS, wasd to LS
            f10_events = [False, True, False, False, False]
            f9_events = [False, False, True, False, False]

            hooks_inst.consume_stick_swap.side_effect = lambda: (
                f10_events.pop(0) if f10_events else False
            )
            hooks_inst.consume_profile_cycle.side_effect = lambda: (
                f9_events.pop(0) if f9_events else False
            )

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 4:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0
                assert pad_instance.reset.called

            lj_calls = pad_instance.left_joystick.call_args_list
            rj_calls = pad_instance.right_joystick.call_args_list

            # Tick 1 (Shooter, normal): mouse -> RS, wasd -> LS
            assert rj_calls[0][1]["x_value"] > 0
            assert lj_calls[0][1]["y_value"] == 32767

            # Tick 2: F10 swap resets sticks to (0, 0), then routes mouse -> LS, wasd -> RS
            assert lj_calls[1] == ((), {"x_value": 0, "y_value": 0})
            assert rj_calls[1] == ((), {"x_value": 0, "y_value": 0})
            assert lj_calls[2][1]["x_value"] > 0
            assert rj_calls[2][1]["y_value"] == 32767

            # Tick 3: F9 cycle resets stick_swap_override to False, cycles profile to Action / RPG
            # Tick 4: Action / RPG has mouse_stick='right', so mouse routes to RS, wasd to LS
            assert rj_calls[4][1]["x_value"] > 0
            assert lj_calls[4][1]["y_value"] == 32767

    def test_f7_wake_pulse_runtime_trigger(self) -> None:
        """Verify that F7 hotkey triggers a manual wakeup pulse with L3 + A."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.consume_stick_swap.return_value = False

            f7_events = [True, False, False]
            hooks_inst.consume_wake_pulse.side_effect = lambda: (
                f7_events.pop(0) if f7_events else False
            )

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 3:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0

            press_calls = pad_instance.press_button.call_args_list
            assert ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB}) in press_calls
            assert ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_A}) in press_calls

    def test_inactive_idle_heartbeat_pulses_controller(self) -> None:
        """Verify that inactive loop periodically pulses LEFT_THUMB to keep controller alive in browser."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_wake_pulse.return_value = False

            loop_count = 0

            def fake_sleep(duration: float) -> None:
                nonlocal loop_count
                loop_count += 1
                if loop_count > 3:
                    raise KeyboardInterrupt

            with patch("time.sleep", side_effect=fake_sleep), patch("time.monotonic") as mock_mono:
                mock_mono.side_effect = [0.0, 0.0, 2.5, 2.5, 5.0, 5.0]
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0

            press_calls = [
                c
                for c in pad_instance.press_button.call_args_list
                if c == ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB})
            ]
            assert len(press_calls) >= 1

    def test_mouse_stick_left_routes_wasd_to_left_when_mouse_stationary(self) -> None:
        """When mouse_stick is 'left' and mouse is stationary, WASD directly drives Left Stick for menu navigation."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (0, 0)  # Stationary mouse!
            hooks_inst.get_keys_pressed.return_value = {87}  # 'W' key (Up)
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 1:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "rts_menu"])
                assert ret == 0

            # When mouse is stationary, Left Stick receives WASD (W = Up) for menu navigation
            lj_calls = pad_instance.left_joystick.call_args_list
            assert len(lj_calls) >= 1
            assert lj_calls[0] == ((), {"x_value": 0, "y_value": 32767})

            # Right Stick remains neutral (0, 0)
            rj_calls = pad_instance.right_joystick.call_args_list
            assert len(rj_calls) >= 1
            assert rj_calls[0] == ((), {"x_value": 0, "y_value": 0})

    def test_browser_focus_triggers_auto_wakeup_pulse(self) -> None:
        """Switching focus to Chrome/Edge immediately pulses L3 silently without waiting for idle timer."""

        def fake_pid(h: Any, ptr: Any) -> int:
            ptr._obj.value = 1234
            return 1

        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
            patch.object(main._user32, "GetForegroundWindow", return_value=0x1000),
            patch.object(main._user32, "GetWindowThreadProcessId", side_effect=fake_pid),
            patch("main.get_process_image_name", return_value="chrome.exe"),
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_wake_pulse.return_value = False
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.consume_stick_swap.return_value = False

            loop_count = 0

            def fake_sleep(duration: float) -> None:
                nonlocal loop_count
                loop_count += 1
                if loop_count > 2:
                    raise KeyboardInterrupt

            with patch("time.sleep", side_effect=fake_sleep):
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0

            # Left Thumb must have been pressed, but A button must NOT be pressed
            press_calls = pad_instance.press_button.call_args_list
            assert ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB}) in press_calls
            assert ((), {"button": vg.XUSB_BUTTON.XUSB_GAMEPAD_A}) not in press_calls

    def test_momentary_clutch_pauses_gamepad_writes_and_resets_controls(self) -> None:
        """When hooks.clutch_active is True, virtual controller resets controls once and skips writes."""
        with (
            patch("main.verify_system_requirements", return_value=True),
            patch("vgamepad.VX360Gamepad") as mock_pad_cls,
            patch("main.InputHookManager") as mock_hooks,
            patch("main.HighResTimer") as mock_timer,
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            _ = mock_timer
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.consume_stick_swap.return_value = False
            hooks_inst.check_foreground_window.return_value = True
            hooks_inst.consume_mouse_delta.return_value = (50, 50)
            hooks_inst.get_keys_pressed.return_value = {87}
            hooks_inst.get_mouse_buttons.return_value = (True, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0

            # Tick 1: normal active write
            # Tick 2, 3: clutch active -> resets controls once, skips stick/button writes
            # Tick 4: clutch released -> normal write resumes
            clutch_states = [False, True, True, False]
            type(hooks_inst).clutch_active = property(
                lambda self: clutch_states.pop(0) if clutch_states else False
            )

            timer_inst = mock_timer.return_value
            tick_count = 0

            def fake_wait() -> float:
                nonlocal tick_count
                tick_count += 1
                if tick_count > 4:
                    raise KeyboardInterrupt
                return 0.004

            timer_inst.wait.side_effect = fake_wait

            with patch("time.sleep"):
                ret = run_mapper(["--profile", "Shooter"])
                assert ret == 0

            # Verify pad_instance.reset() was called: 1 init + 1 entering clutch + 1 shutdown cleanup = 3
            assert pad_instance.reset.call_count == 3
            # Verify stick writes occurred on ticks 1 and 4, but were skipped during clutch ticks 2 and 3
            assert len(pad_instance.right_joystick.call_args_list) == 2
            assert len(pad_instance.left_joystick.call_args_list) == 2
