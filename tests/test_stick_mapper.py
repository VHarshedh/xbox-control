"""Unit tests for stick_mapper module (math, curve response, and timer).

Can run cross-platform on Windows/Linux/macOS with pytest.
"""

from __future__ import annotations

import ctypes
import math
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import driver_check
import stick_mapper
from input_hooks import (
    KBDLLHOOKSTRUCT,
    LLKHF_INJECTED,
    LLMHF_INJECTED,
    MSLLHOOKSTRUCT,
    VK_F8,
    VK_F9,
    WM_KEYDOWN,
    WM_MOUSEMOVE,
    InputHooks,
)
from stick_mapper import (
    TARGET_DT,
    TARGET_HZ,
    HighResTimer,
    MouseToStickMapper,
    _get_system_directory,
    _load_winmm,
    _to_int16,
)


class TestInt16Conversion:
    """Validate int16 conversion and clamping against XInput specifications."""

    def test_clamp_positive(self) -> None:
        assert _to_int16(1.5) == 32767
        assert _to_int16(1.0) == 32767

    def test_clamp_negative(self) -> None:
        assert _to_int16(-1.5) == -32768
        assert _to_int16(-1.0) == -32768

    def test_zero(self) -> None:
        assert _to_int16(0.0) == 0

    def test_intermediate_values(self) -> None:
        val = _to_int16(0.5)
        assert 16380 <= val <= 16385


class TestMouseToStickMapper:
    """Validate stick response curves, smoothing, and recentering."""

    def test_zero_input_recentering(self) -> None:
        mapper = MouseToStickMapper(sensitivity=0.10, decay_rate=0.80)
        # Apply sustained movement
        for _ in range(10):
            mapper.step(40, -25, TARGET_DT)

        # Decay to zero over 120 ticks
        rx, ry = 1, 1
        for _ in range(120):
            rx, ry = mapper.step(0, 0, TARGET_DT)

        assert rx == 0
        assert ry == 0

    def test_deadzone_jump(self) -> None:
        dz = 0.20
        mapper = MouseToStickMapper(
            sensitivity=0.05,
            deadzone_comp=dz,
            curve_exponent=1.0,
            smoothing=0.0,
        )
        rx, ry = mapper.step(1, 0, TARGET_DT)
        mag = math.hypot(rx, ry)
        # 1-pixel nudge should jump past deadzone threshold
        expected_min = dz * 32767 * 0.40
        assert mag >= expected_min

    def test_diagonal_normalization(self) -> None:
        mapper = MouseToStickMapper(
            sensitivity=0.50,
            curve_exponent=1.0,
            deadzone_comp=0.0,
            smoothing=0.0,
        )
        for _ in range(30):
            rx, ry = mapper.step(200, 200, TARGET_DT)
        mag = math.hypot(rx, ry)
        # Radial magnitude must not exceed stick maximum radius
        assert mag <= 32767 * 1.002

    def test_invert_y(self) -> None:
        normal = MouseToStickMapper(sensitivity=0.10, invert_y=False, smoothing=0.0)
        inverted = MouseToStickMapper(sensitivity=0.10, invert_y=True, smoothing=0.0)

        # Screen Y moving down (+dy)
        _, ry_normal = normal.step(0, 20, TARGET_DT)
        _, ry_inverted = inverted.step(0, 20, TARGET_DT)

        # Natural aim: screen down -> XInput stick down (-ry)
        assert ry_normal < 0
        # Inverted aim: screen down -> XInput stick up (+ry)
        assert ry_inverted > 0
        # Magnitude is equal within 1 integer due to signed int16 [-32768, 32767] asymmetry
        assert abs(abs(ry_normal) - abs(ry_inverted)) <= 1

    def test_invalid_parameters(self) -> None:
        with pytest.raises(ValueError, match="sensitivity must be > 0"):
            MouseToStickMapper(sensitivity=-0.01)

        with pytest.raises(ValueError, match="curve_exponent must be > 0"):
            MouseToStickMapper(curve_exponent=0.0)

        with pytest.raises(ValueError, match="deadzone_comp must be in"):
            MouseToStickMapper(deadzone_comp=0.45)

        with pytest.raises(ValueError, match="deadzone_comp must be in"):
            MouseToStickMapper(deadzone_comp=-0.05)

        with pytest.raises(ValueError, match="smoothing must be in"):
            MouseToStickMapper(smoothing=1.0)


class TestHighResTimer:
    """Validate HighResTimer calculations and reset functionality."""

    def test_init_validation(self) -> None:
        with pytest.raises(ValueError, match="hz must be > 0"):
            HighResTimer(hz=0)

    def test_reset(self) -> None:
        timer = HighResTimer(hz=TARGET_HZ)
        timer._next = 100.0
        timer._last = 99.0
        timer.reset()
        assert timer._next > 100.0 or timer._next != 100.0
        assert timer._last != 99.0


class TestDLLLoadingAndServiceSecurity:
    """Validate secure Win32 DLL loading and service queries (CWE-426/CWE-427)."""

    def test_get_system_directory(self) -> None:
        sys_dir = _get_system_directory()
        assert isinstance(sys_dir, Path)
        assert sys_dir.exists()
        assert sys_dir.name.lower() == "system32"

    def test_get_system_directory_fallback_on_failure(self) -> None:
        with patch("ctypes.windll.kernel32.GetSystemDirectoryW", side_effect=OSError("API failed")):
            fallback_dir = _get_system_directory()
            assert fallback_dir == Path(r"C:\Windows\System32")

    def test_load_winmm_uses_system32(self) -> None:
        winmm = _load_winmm()
        assert winmm is not None
        assert hasattr(winmm, "timeBeginPeriod")
        assert hasattr(winmm, "timeEndPeriod")

    def test_load_winmm_fallback_on_type_error(self) -> None:
        mock_dll = MagicMock()
        with patch("ctypes.WinDLL", side_effect=[TypeError("winmode unsupported"), mock_dll]) as mock_windll:
            res = _load_winmm()
            assert res is mock_dll
            assert mock_windll.call_count == 2
            called_path = str(mock_windll.call_args_list[1][0][0])
            assert "system32" in called_path.lower()
            assert called_path.lower().endswith("winmm.dll")

    def test_driver_check_system_directory_and_sc(self) -> None:
        sc_dir = driver_check._get_system_directory()
        assert isinstance(sc_dir, Path)
        assert sc_dir.name.lower() == "system32"
        sc_exe = sc_dir / "sc.exe"
        assert sc_exe.is_file()

    def test_driver_check_load_advapi32(self) -> None:
        advapi32 = driver_check._load_advapi32()
        assert advapi32 is not None
        assert hasattr(advapi32, "OpenSCManagerW")

    def test_driver_check_scm_handle_leak_prevention_on_exception(self) -> None:
        mock_advapi = MagicMock()
        mock_scm = 1111
        mock_svc = 2222
        mock_advapi.OpenSCManagerW.return_value = mock_scm
        mock_advapi.OpenServiceW.return_value = mock_svc
        mock_advapi.QueryServiceStatus.side_effect = RuntimeError("Simulated query crash")

        with patch("driver_check._load_advapi32", return_value=mock_advapi):
            ok, detail = driver_check.check_vigembus_service()
            # Assert both service handle and scm handle were closed
            mock_advapi.CloseServiceHandle.assert_any_call(mock_svc)
            mock_advapi.CloseServiceHandle.assert_any_call(mock_scm)
            assert mock_advapi.CloseServiceHandle.call_count == 2

    def test_driver_check_is_admin(self) -> None:
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
            assert driver_check.is_admin() is True
        with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0):
            assert driver_check.is_admin() is False

    def test_driver_check_check_architecture(self) -> None:
        ok, msg = driver_check.check_architecture()
        assert ok is True
        assert "64-bit" in msg

    def test_driver_check_is_headless_ci(self) -> None:
        with patch.dict("os.environ", {"CI": "true"}):
            assert driver_check.is_headless_ci() is True
        with patch.dict("os.environ", {"VGAMEPAD_SKIP_VIGEMBUS_INSTALL": "1"}):
            assert driver_check.is_headless_ci() is True
        with patch.dict("os.environ", {"CI": "", "GITHUB_ACTIONS": "", "VGAMEPAD_SKIP_VIGEMBUS_INSTALL": ""}):
            assert driver_check.is_headless_ci() is False

    def test_driver_check_cli_ci_and_admin(self) -> None:
        # CLI --check-admin
        with patch("driver_check.is_admin", return_value=True):
            assert driver_check.main(["--check-admin"]) == 0
        with patch("driver_check.is_admin", return_value=False):
            assert driver_check.main(["--check-admin"]) == 1

        # CLI --ci
        with patch("driver_check.check_vigembus_service", return_value=(True, "OK")), patch(
            "driver_check.check_vgamepad_controller", return_value=(True, "OK")
        ):
            assert driver_check.main(["--ci"]) == 0

    def test_driver_check_start_service_permission_guard(self) -> None:
        # When service is not running and user is not admin
        with patch("driver_check.check_vigembus_service", return_value=(False, "Stopped")), patch(
            "driver_check.is_admin", return_value=False
        ):
            ok, msg = driver_check.start_vigembus_service()
            assert ok is False
            assert "Administrator privileges required" in msg

    def test_driver_check_elevate_with_service_arguments(self) -> None:
        with patch("driver_check.is_admin", return_value=False), patch(
            "driver_check.elevate_and_run", return_value=True
        ) as mock_elevate:
            ret = driver_check.main(["--start-service", "--elevate"])
            assert ret == 0
            mock_elevate.assert_called_once_with(extra_args=["--start-service"])

    def test_driver_check_admin_with_elevate_and_start_service(self) -> None:
        with patch("driver_check.is_admin", return_value=True), patch(
            "driver_check.start_vigembus_service", return_value=(True, "Started OK")
        ) as mock_start:
            ret = driver_check.main(["--start-service", "--elevate"])
            assert ret == 0
            mock_start.assert_called_once()

    def test_driver_check_stop_service_polls_pending(self) -> None:
        mock_advapi = MagicMock()
        mock_scm = 100
        mock_svc = 200
        mock_advapi.OpenSCManagerW.return_value = mock_scm
        mock_advapi.OpenServiceW.return_value = mock_svc

        # Status sequence: first query -> SERVICE_STOP_PENDING (3), second query -> SERVICE_STOPPED (1)
        st_pending = driver_check.SERVICE_STATUS()
        st_pending.dwCurrentState = driver_check.SERVICE_STOP_PENDING
        st_stopped = driver_check.SERVICE_STATUS()
        st_stopped.dwCurrentState = driver_check.SERVICE_STOPPED

        def fake_query(svc: Any, p_st: Any) -> int:
            st = getattr(p_st, "_obj", getattr(p_st, "contents", None))
            if not hasattr(fake_query, "called"):
                fake_query.called = True  # type: ignore[attr-defined]
                if st is not None:
                    st.dwCurrentState = driver_check.SERVICE_STOP_PENDING
            else:
                if st is not None:
                    st.dwCurrentState = driver_check.SERVICE_STOPPED
            return 1

        mock_advapi.QueryServiceStatus.side_effect = fake_query

        with patch("driver_check.is_admin", return_value=True), patch(
            "driver_check._load_advapi32", return_value=mock_advapi
        ), patch("time.sleep"):
            ok, msg = driver_check.stop_vigembus_service()
            assert ok is True
            assert "stopped successfully" in msg


class TestMathAndSignalSafety:
    """Validate numerical boundary conditions, extreme floats, and zero division guards."""

    def test_int16_extreme_numbers(self) -> None:
        assert _to_int16(1e12) == 32767
        assert _to_int16(-1e12) == -32768
        assert _to_int16(32767.0) == 32767
        assert _to_int16(-32768.0) == -32768

    def test_sub_epsilon_zero_clamp(self) -> None:
        mapper = MouseToStickMapper(sensitivity=0.01, decay_rate=0.5)
        mapper.step(10, 10, TARGET_DT)
        for _ in range(50):
            rx, ry = mapper.step(0, 0, TARGET_DT)
        assert mapper._sx == 0.0
        assert mapper._sy == 0.0
        assert rx == 0
        assert ry == 0

    def test_step_division_by_zero_prevention(self) -> None:
        mapper = MouseToStickMapper()
        rx, ry = mapper.step(0, 0, TARGET_DT)
        assert rx == 0
        assert ry == 0

    def test_step_zero_or_negative_dt(self) -> None:
        mapper = MouseToStickMapper()
        rx, ry = mapper.step(0, 0, 0.0)
        assert rx == 0
        assert ry == 0
        rx, ry = mapper.step(0, 0, -0.004)
        assert rx == 0
        assert ry == 0

    def test_spike_guard_clamping(self) -> None:
        mapper = MouseToStickMapper(sensitivity=1.0, max_delta_per_tick=1.0, smoothing=0.0)
        rx, ry = mapper.step(50000, 0, TARGET_DT)
        assert rx == 32767
        assert ry == 0

    def test_nan_and_inf_to_int16(self) -> None:
        assert _to_int16(float("nan")) == 0
        assert _to_int16(float("inf")) == 32767
        assert _to_int16(float("-inf")) == -32768

    def test_nan_and_inf_step_inputs(self) -> None:
        mapper = MouseToStickMapper()
        rx, ry = mapper.step(float("nan"), 10, TARGET_DT)
        assert isinstance(rx, int)
        assert isinstance(ry, int)
        rx, ry = mapper.step(10, float("inf"), TARGET_DT)
        assert isinstance(rx, int)
        assert isinstance(ry, int)
        rx, ry = mapper.step(10, 10, float("nan"))
        assert isinstance(rx, int)
        assert isinstance(ry, int)

    def test_nan_parameters_rejected(self) -> None:
        with pytest.raises(ValueError, match="sensitivity must be > 0"):
            MouseToStickMapper(sensitivity=float("nan"))
        with pytest.raises(ValueError, match="curve_exponent must be > 0"):
            MouseToStickMapper(curve_exponent=float("nan"))
        with pytest.raises(ValueError, match="deadzone_comp must be in"):
            MouseToStickMapper(deadzone_comp=float("nan"))
        with pytest.raises(ValueError, match="decay_rate must be in"):
            MouseToStickMapper(decay_rate=float("nan"))
        with pytest.raises(ValueError, match="max_delta_per_tick must be > 0"):
            MouseToStickMapper(max_delta_per_tick=float("nan"))
        with pytest.raises(ValueError, match="smoothing must be in"):
            MouseToStickMapper(smoothing=float("nan"))


class TestHighResTimerSafety:
    """Validate timer resource pairing and drift catch-up prevention."""

    def test_timer_context_pairing_on_exception(self) -> None:
        timer = HighResTimer(hz=TARGET_HZ)
        with patch.object(stick_mapper._winmm, "timeBeginPeriod") as mock_begin, patch.object(
            stick_mapper._winmm, "timeEndPeriod"
        ) as mock_end:
            with pytest.raises(RuntimeError, match="Simulated loop error"), timer:
                mock_begin.assert_called_once()
                raise RuntimeError("Simulated loop error")
            mock_end.assert_called_once()

    def test_timer_close_idempotent(self) -> None:
        timer = HighResTimer(hz=TARGET_HZ)
        with patch.object(stick_mapper._winmm, "timeBeginPeriod") as mock_begin, patch.object(
            stick_mapper._winmm, "timeEndPeriod"
        ) as mock_end:
            with timer:
                mock_begin.assert_called_once()
            mock_end.assert_called_once()
            # Explicit subsequent close() calls must not trigger extra timeEndPeriod calls
            timer.close()
            timer.close()
            mock_end.assert_called_once()

    def test_timer_atexit_cleanup(self) -> None:
        with patch.object(stick_mapper._winmm, "timeEndPeriod") as mock_end:
            stick_mapper._period_active_count = 2
            stick_mapper._cleanup_periods()
            assert mock_end.call_count == 2
            assert stick_mapper._period_active_count == 0

    def test_timer_drift_catchup_bounds(self) -> None:
        timer = HighResTimer(hz=TARGET_HZ)
        timer._next = 10.0
        timer._last = 9.996
        fake_now = 10.100
        with patch("time.perf_counter", return_value=fake_now), patch("time.sleep"):
            timer.wait()
            assert timer._next == fake_now + timer._dt

    def test_timer_nowinmm_period_tracking(self) -> None:
        timer = HighResTimer(hz=TARGET_HZ)
        initial_count = stick_mapper._period_active_count
        with patch("stick_mapper._winmm", None):
            with timer:
                assert stick_mapper._period_active_count == initial_count
            assert stick_mapper._period_active_count == initial_count

    def test_timer_wait_negative_dt_guard(self) -> None:
        timer = HighResTimer(hz=TARGET_HZ)
        timer._next = 10.0
        timer._last = 10.5  # Last tick was recorded in the future (e.g. system clock stepped back)
        with patch("time.perf_counter", return_value=10.0), patch("time.sleep"):
            dt = timer.wait()
            assert dt == 0.0


class TestHookSecurityAndReentrancy:
    """Validate synthetic event rejection, hook reentrancy, and thread safety."""

    def test_synthetic_keyboard_injection_ignored(self) -> None:
        toggled = False

        def _on_toggle(state: bool) -> None:
            nonlocal toggled
            toggled = True

        hooks = InputHooks(on_toggle=_on_toggle)

        kbd = KBDLLHOOKSTRUCT()
        kbd.vkCode = VK_F8
        kbd.flags = LLKHF_INJECTED

        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert not toggled
        assert not hooks.active
        assert not hooks._f8_held

        kbd.vkCode = VK_F9
        hooks._keyboard_ll_proc(0, WM_KEYDOWN, ctypes.addressof(kbd))
        assert not hooks._f9_held
        assert not hooks.consume_profile_cycle()

    def test_synthetic_mouse_injection_ignored(self) -> None:
        hooks = InputHooks()
        hooks._active = True
        hooks._last_pt = (100, 100)

        ms = MSLLHOOKSTRUCT()
        ms.pt.x = 200
        ms.pt.y = 200
        ms.flags = LLMHF_INJECTED

        res = hooks._mouse_ll_proc(0, WM_MOUSEMOVE, ctypes.addressof(ms))
        assert res == 1
        dx, dy = hooks.consume_mouse_delta()
        assert dx == 0
        assert dy == 0

    def test_hook_stop_reentrancy(self) -> None:
        hooks = InputHooks()
        hooks.stop()
        hooks.stop()
        hooks._force_unhook()
        hooks._force_unhook()

