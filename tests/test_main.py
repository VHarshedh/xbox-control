"""Unit tests for main.py application lifecycle, CLI security, and failsafe teardown."""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

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
        cases = ['profile<1>', 'test"quote"', 'wild*card', 'pipe|name', 'what?']
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

    def test_nonexistent_profile_handled_gracefully(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run_mapper(["--profile", "NonExistentProfile123"])
        assert code == 1
        captured = capsys.readouterr()
        assert "[FAIL]" in captured.err
        assert "not found" in captured.err
        assert "Available profiles:" in captured.err

    def test_malicious_traversal_profile_handled_gracefully(self, capsys: pytest.CaptureFixture[str]) -> None:
        code = run_mapper(["--profile", "../malicious"])
        assert code == 1
        captured = capsys.readouterr()
        assert "[FAIL] Invalid profile name:" in captured.err

    def test_reserved_device_profile_handled_gracefully(self, capsys: pytest.CaptureFixture[str]) -> None:
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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ), patch("main.InputHookManager") as mock_hooks, patch("main.HighResTimer"):
            instance = mock_hooks.return_value
            instance.active = False
            instance.consume_profile_cycle.return_value = False
            instance.is_healthy = True

            # Use -p RTS to verify it resolves to "RTS / Menu"
            with patch("time.sleep", side_effect=KeyboardInterrupt):
                ret = run_mapper(["-p", "RTS"])
                assert ret == 0

    def test_main_loop_detects_unhealthy_hook_subsystem(self) -> None:
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ), patch("main.InputHookManager") as mock_hooks, patch("main.HighResTimer"):
            instance = mock_hooks.return_value
            instance.active = True
            instance.consume_profile_cycle.return_value = False
            # Simulate hook thread dying / becoming unhealthy
            instance.is_healthy = False

            ret = run_mapper([])
            assert ret == 1

    def test_verify_system_requirements_check_controller_flag(self) -> None:
        with patch("main.check_python_version", return_value=(True, "")), patch(
            "main.check_architecture", return_value=(True, "")
        ), patch("main.check_windows_os", return_value=(True, "")), patch(
            "main.check_vigembus_service", return_value=(True, "")
        ), patch("main.check_vgamepad_controller") as mock_check_ctrl:
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
        with patch("main.verify_system_requirements", return_value=True) as mock_verify, patch(
            "vgamepad.VX360Gamepad"
        ), patch("main.InputHookManager") as mock_hooks, patch("main.HighResTimer"):
            instance = mock_hooks.return_value
            instance.active = False
            instance.consume_profile_cycle.return_value = False
            instance.is_healthy = True

            with patch("time.sleep", side_effect=KeyboardInterrupt):
                run_mapper([])

            # Verify that verify_system_requirements was called with check_controller=False
            mock_verify.assert_called_once_with(ci_mode=mock_verify.call_args.kwargs.get("ci_mode"), check_controller=False)

    def test_wakeup_pulse_on_f8_activation(self) -> None:
        """Verify 40ms 10-tick Chromium wakeup pulse on F8 activation and immediate cancellation on mouse move."""
        # 1. On F8 activation with dx=0, dy=0:
        # right_joystick(x_value=12000, y_value=0) sent for WAKEUP_PULSE_TICKS (10 ticks)
        # then returns to (0, 0) on the 11th tick.
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ) as mock_timer:
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
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
                    f"Tick {i+1} expected WAKEUP_STICK_VALUE ({WAKEUP_STICK_VALUE}), got {rj_calls[i]}"
                )

            # Tick 11 (next tick) must restore naturally to (0, 0)
            assert rj_calls[WAKEUP_PULSE_TICKS] == ((), {"x_value": 0, "y_value": 0}), (
                f"Tick 11 expected neutral (0, 0), got {rj_calls[WAKEUP_PULSE_TICKS]}"
            )

            # Verification of update commits:
            # 1 (init) + 1 (tick 1 pulse start) + 1 (tick 11 pulse end neutral) + 1 (cleanup) = 4
            assert pad_instance.update.call_count == 4

        # 2. Moving the mouse horizontally (dx != 0) immediately cancels any remaining wakeup ticks
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ) as mock_timer:
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ) as mock_timer:
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            hooks_inst.active = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.is_healthy = True
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Return (0, 0) on tick 1, then (0, 25) on tick 2
            deltas_y = [(0, 0), (0, 25), (0, 0), (0, 0)]
            hooks_inst.consume_mouse_delta.side_effect = lambda: deltas_y.pop(0) if deltas_y else (0, 0)

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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ) as mock_timer:
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            hooks_inst.active = True
            hooks_inst.consume_profile_cycle.return_value = False
            hooks_inst.is_healthy = True
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Moving mouse immediately on tick 1
            deltas_immediate = [(15, 0), (0, 0), (0, 0)]
            hooks_inst.consume_mouse_delta.side_effect = (
                lambda: deltas_immediate.pop(0) if deltas_immediate else (0, 0)
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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch("main.HighResTimer") as mock_timer:
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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch("main.HighResTimer") as mock_timer:
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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
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
                "Slot 1" in rec.message and "Player 2" in rec.message and "xbox.com/play" in rec.message
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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ) as mock_timer:
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
            hooks_inst.active = True
            hooks_inst.is_healthy = True
            hooks_inst.consume_mouse_delta.return_value = (0, 0)
            hooks_inst.get_keys_pressed.return_value = set()
            hooks_inst.get_mouse_buttons.return_value = (False, False, False, False, False)
            hooks_inst.consume_wheel_delta.return_value = 0
            hooks_inst.check_foreground_window.return_value = True

            # Trigger F9 profile cycle on tick 2
            f9_cycles = [False, True, False, False]
            hooks_inst.consume_profile_cycle.side_effect = lambda: f9_cycles.pop(0) if f9_cycles else False

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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ):
            pad_instance = mock_pad_cls.return_value
            pad_instance.register_notification.side_effect = RuntimeError("Driver notification unsupported")
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
        mock_gamepad.unregister_notification.side_effect = RuntimeError("Failed to unregister notification")
        lifecycle.gamepad = mock_gamepad

        lifecycle.cleanup()

        mock_gamepad.reset.assert_called_once()
        mock_gamepad.update.assert_called_once()
        assert lifecycle.gamepad is None

    def test_wakeup_cancelled_on_deactivation_and_restarts_on_reactivation(self) -> None:
        """Verify wakeup pulse cancels on F8 deactivation and restarts on next F8 activation."""
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ) as mock_timer:
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ):
            pad_instance = mock_pad_cls.return_value

            def fake_register(cb: Any) -> None:
                # Driver fires notification synchronously with led_number = 1
                cb(None, None, 0, 0, 1, None)

            pad_instance.register_notification.side_effect = fake_register

            hooks_inst = mock_hooks.return_value
            hooks_inst.active = False
            hooks_inst.is_healthy = True
            hooks_inst.consume_profile_cycle.return_value = False

            with caplog.at_level(logging.WARNING, logger="vg_mapper"), patch(
                "time.sleep", side_effect=KeyboardInterrupt
            ):
                run_mapper([])

            # Verify logger.warning was called
            assert any(
                "Slot 1" in rec.message and "Player 2" in rec.message and "xbox.com/play" in rec.message
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
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch(
            "main.HighResTimer"
        ):
            pad_instance = mock_pad_cls.return_value
            hooks_inst = mock_hooks.return_value
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

            assert any("Slot 2" in rec.message and "Player 3" in rec.message for rec in caplog.records)
            captured = capsys.readouterr()
            assert "Slot 2" in captured.out
            assert "Player 3" in captured.out

    def test_hot_reconnect_unregisters_old_controller_before_allocating(self) -> None:
        """Verify that hot-reconnect cleans up the old controller before creating the new one."""
        with patch("main.verify_system_requirements", return_value=True), patch(
            "vgamepad.VX360Gamepad"
        ) as mock_pad_cls, patch("main.InputHookManager") as mock_hooks, patch("main.HighResTimer") as mock_timer:
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
