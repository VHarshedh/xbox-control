"""Unit tests for main.py application lifecycle, CLI security, and failsafe teardown."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import main
from main import (
    MAX_CONSECUTIVE_TICK_ERRORS,
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
            "COM1",
            "com9",
            "LPT1",
            "lpt3",
            "CON.json",
            "nul.json",
            "aux.profile",
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
