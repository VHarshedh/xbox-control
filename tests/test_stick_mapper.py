"""Unit tests for stick_mapper module (math, curve response, and timer).

Can run cross-platform on Windows/Linux/macOS with pytest.
"""

from __future__ import annotations

import math

import pytest

from stick_mapper import (
    TARGET_DT,
    TARGET_HZ,
    HighResTimer,
    MouseToStickMapper,
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
