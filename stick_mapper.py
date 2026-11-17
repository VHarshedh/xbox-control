"""Mouse-to-Xbox 360 Right Thumbstick mapper at a fixed 250 Hz tick rate.

Provides
--------
- **HighResTimer** — Win32 ``timeBeginPeriod(1)`` + hybrid sleep / yield / busy-wait
  loop targeting 250 Hz with sub-ms jitter and drift/starvation protection.
- **MouseToStickMapper** — EMA smoothing, power-curve response, radial
  deadzone compensation, auto-recentering decay, and signed-int16 output.

Pure stdlib: ``math``, ``time``, ``ctypes``, ``threading``, ``atexit``. No numpy.
"""

from __future__ import annotations

import atexit
import contextlib
import ctypes
import math
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

# ── Module constants ─────────────────────────────────────────────────────

TARGET_HZ: float = 250.0
TARGET_DT: float = 1.0 / TARGET_HZ          # 0.004 s

_EPSILON: float = 1e-4
_I16_POS: int = 32_767                       #  max  int16
_I16_NEG: int = 32_768                       # |min| int16


# ── Win32 high-resolution timing (Hardened DLL loading) ─────────────────

def _get_system_directory() -> Path:
    """Resolve the true Windows System32 directory via kernel32 API (CWE-426)."""
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        buf = ctypes.create_unicode_buffer(260)
        kernel32.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        kernel32.GetSystemDirectoryW.restype = ctypes.c_uint
        n = kernel32.GetSystemDirectoryW(buf, 260)
        if n > 260:
            buf = ctypes.create_unicode_buffer(n)
            n = kernel32.GetSystemDirectoryW(buf, n)
        if 0 < n <= len(buf):
            p = Path(buf.value)
            if p.is_dir():
                return p
    except Exception:
        pass
    return Path(r"C:\Windows\System32")


def _load_winmm() -> ctypes.WinDLL | None:
    """Load winmm.dll strictly from System32 using LOAD_LIBRARY_SEARCH_SYSTEM32 (CWE-426)."""
    if sys.platform != "win32":
        return None
    # LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
    try:
        return ctypes.WinDLL("winmm.dll", winmode=0x00000800)
    except TypeError:
        sys_dir = _get_system_directory()
        return ctypes.WinDLL(str(sys_dir / "winmm.dll"))
    except Exception as exc:
        sys_dir = _get_system_directory()
        dll_path = sys_dir / "winmm.dll"
        if not dll_path.is_file():
            raise FileNotFoundError(f"winmm.dll not found at secure path: {dll_path}") from exc
        return ctypes.WinDLL(str(dll_path), winmode=0x00000800)


_winmm = _load_winmm()
if _winmm is not None:
    _winmm.timeBeginPeriod.argtypes = [ctypes.c_uint]
    _winmm.timeBeginPeriod.restype = ctypes.c_uint
    _winmm.timeEndPeriod.argtypes = [ctypes.c_uint]
    _winmm.timeEndPeriod.restype = ctypes.c_uint


# ── Global Period Tracking & Abnormal Termination Protection ───────────

_period_active_count: int = 0
_period_lock = threading.Lock()


def _track_period_acquired() -> None:
    global _period_active_count
    with _period_lock:
        _period_active_count += 1


def _track_period_released() -> None:
    global _period_active_count
    with _period_lock:
        if _period_active_count > 0:
            _period_active_count -= 1


def _cleanup_periods() -> None:
    """atexit hook guaranteeing timeEndPeriod(1) pairing even on abnormal process termination."""
    global _period_active_count
    with _period_lock:
        if _winmm is not None:
            while _period_active_count > 0:
                with contextlib.suppress(Exception):
                    _winmm.timeEndPeriod(ctypes.c_uint(1))
                _period_active_count -= 1


atexit.register(_cleanup_periods)


# ── HighResTimer ─────────────────────────────────────────────────────────


class HighResTimer:
    """Hybrid sleep / yield / busy-wait interval timer at *hz* Hz.

    Uses ``winmm.timeBeginPeriod(1)`` to lower the Windows scheduler
    quantum to ~1 ms, sleeps for the bulk of each interval, yields
    via ``time.sleep(0)`` to prevent CPU and scheduling starvation,
    then busy-waits on ``time.perf_counter()`` for the final sub-ms fraction
    to hit the target with microsecond accuracy.

    Guarantees strict pairing of ``timeBeginPeriod(1)`` and ``timeEndPeriod(1)``
    via context management, instance cleanup, and ``atexit`` handlers.
    Drift and catch-up iterations are strictly bounded to prevent CPU spikes.
    """

    __slots__ = ("_dt", "_next", "_last", "_is_active")

    def __init__(self, hz: float = TARGET_HZ) -> None:
        self._is_active: bool = False
        self._dt: float = 0.0
        self._next: float = 0.0
        self._last: float = 0.0
        if not math.isfinite(hz) or hz <= 0.0:
            raise ValueError(f"hz must be > 0, got {hz}")
        self._dt = 1.0 / hz

    # ── context manager ──────────────────────────────────────────────────

    def __enter__(self) -> HighResTimer:
        if not self._is_active:
            if _winmm is not None:
                _winmm.timeBeginPeriod(ctypes.c_uint(1))
                _track_period_acquired()
            self._is_active = True
        self.reset()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Release the high-resolution timer period if active."""
        if getattr(self, "_is_active", False):
            if _winmm is not None:
                _winmm.timeEndPeriod(ctypes.c_uint(1))
                _track_period_released()
            self._is_active = False

    def __del__(self) -> None:
        self.close()

    def reset(self) -> None:
        """Resync _next and _last to time.perf_counter()."""
        now = time.perf_counter()
        self._next = now + self._dt
        self._last = now

    # ── tick ─────────────────────────────────────────────────────────────

    def wait(self) -> float:
        """Block until the next tick.  Returns the **actual** dt (seconds).

        The returned dt may differ slightly from ``1/hz`` but averages
        to it over many ticks.
        """
        target = self._next

        # ── hybrid sleep: coarse sleep → thread yield → sub-ms busy-wait ──
        while True:
            now = time.perf_counter()
            remaining = target - now
            if remaining <= 0.0:
                break
            if remaining > 0.002:
                # Coarse sleep: wake ~1.5 ms before target
                time.sleep(remaining - 0.0015)
            elif remaining > 0.0005:
                # Intermediate zone (0.5 ms - 2.0 ms): yield remainder of
                # thread quantum to prevent CPU and scheduling starvation
                time.sleep(0)
            # else: tight spin for sub-ms precision (<0.5 ms)

        now = time.perf_counter()
        dt = max(0.0, now - self._last)
        self._last = now
        self._next = target + self._dt

        # If we fell more than one full tick behind, reset to avoid a
        # burst of rapid catch-up iterations.
        if now > self._next + self._dt:
            self._next = now + self._dt

        return dt


# ── Helpers ──────────────────────────────────────────────────────────────


def _to_int16(v: float) -> int:
    """Clamp ``v`` to [-1.0, 1.0] and scale to signed 16-bit XInput range.

    Positive maps to  [0, 32767].
    Negative maps to [0, -32768] (asymmetric, per XInput spec).
    NaN values return 0 (neutral position).
    Guarantees exact clamping within [-32768, 32767].
    """
    if math.isnan(v):
        return 0
    c = max(-1.0, min(1.0, v))
    val = int(c * _I16_POS + 0.5) if c >= 0.0 else -int(-c * _I16_NEG + 0.5)
    if val > 32767:
        return 32767
    if val < -32768:
        return -32768
    return val


# ── MouseToStickMapper ──────────────────────────────────────────────────


class MouseToStickMapper:
    """Convert accumulated mouse deltas to Xbox 360 Right Thumbstick values.

    Call :meth:`step` once per 250 Hz tick with the raw pixel deltas
    consumed from the input hooks.

    Parameters
    ----------
    sensitivity : float
        Multiplier on raw pixel deltas before smoothing.  Higher values
        make the stick reach full deflection with less mouse travel.
    curve_exponent : float
        Power curve on radial magnitude.  ``1.0`` = linear, ``2.0`` =
        precision (slow start), ``0.5`` = aggressive (fast start).
    deadzone_comp : float ∈ [0.0, 0.35]
        Radial deadzone compensation.  Output magnitude is remapped from
        ``[0, 1]`` → ``[deadzone_comp, 1]`` so that even the tiniest
        mouse nudge jumps past in-game controller deadzones.
    decay_rate : float ∈ [0.0, 1.0]
        Per-tick multiplier for auto-recentering when the mouse is idle.
        ``0.0`` = instant snap to centre, ``1.0`` = never recentre.
    max_delta_per_tick : float
        Hard clamp on the sensitivity-scaled delta each tick (spike guard).
    invert_y : bool
        ``False`` (default) = natural aim (mouse-up → stick-up).
        ``True``  = inverted flight-sim (mouse-up → stick-down).
    smoothing : float ∈ [0.0, 1.0)
        EMA smoothing factor.  ``0.0`` = raw (no smoothing),
        ``0.9`` = very smooth but laggy.
    smoothing_alpha : float | None
        Alternative EMA alpha parameter (1.0 - smoothing).
    """

    __slots__ = (
        "sensitivity",
        "curve_exponent",
        "deadzone_comp",
        "decay_rate",
        "max_delta_per_tick",
        "invert_y",
        "_alpha",
        "_sx",
        "_sy",
    )

    def __init__(
        self,
        *,
        sensitivity: float = 0.065,
        curve_exponent: float = 1.4,
        deadzone_comp: float = 0.12,
        decay_rate: float = 0.82,
        max_delta_per_tick: float = 1.0,
        invert_y: bool = False,
        smoothing: float = 0.45,
        smoothing_alpha: float | None = None,
    ) -> None:
        if smoothing_alpha is not None:
            if not math.isfinite(smoothing_alpha) or not 0.0 < smoothing_alpha <= 1.0:
                raise ValueError(
                    f"smoothing_alpha must be finite and in (0.0, 1.0], got {smoothing_alpha}"
                )
            smoothing = 1.0 - smoothing_alpha

        # ── validate ──
        if not math.isfinite(sensitivity) or sensitivity <= 0.0:
            raise ValueError(f"sensitivity must be > 0, got {sensitivity}")
        if not math.isfinite(curve_exponent) or curve_exponent <= 0.0:
            raise ValueError(f"curve_exponent must be > 0, got {curve_exponent}")
        if not math.isfinite(deadzone_comp) or not 0.0 <= deadzone_comp <= 0.35:
            raise ValueError(
                f"deadzone_comp must be in [0.0, 0.35], got {deadzone_comp}"
            )
        if not math.isfinite(decay_rate) or not 0.0 <= decay_rate <= 1.0:
            raise ValueError(f"decay_rate must be in [0.0, 1.0], got {decay_rate}")
        if not math.isfinite(max_delta_per_tick) or max_delta_per_tick <= 0.0:
            raise ValueError(f"max_delta_per_tick must be > 0, got {max_delta_per_tick}")
        if not math.isfinite(smoothing) or not 0.0 <= smoothing < 1.0:
            raise ValueError(f"smoothing must be in [0.0, 1.0), got {smoothing}")

        self.sensitivity: float = sensitivity
        self.curve_exponent: float = curve_exponent
        self.deadzone_comp: float = deadzone_comp
        self.decay_rate: float = decay_rate
        self.max_delta_per_tick: float = max_delta_per_tick
        self.invert_y: bool = invert_y
        self._alpha: float = 1.0 - smoothing     # EMA weight for new sample

        # Internal smoothed stick vector (normalised ≈ [-1, 1])
        self._sx: float = 0.0
        self._sy: float = 0.0

    # ── public API ───────────────────────────────────────────────────────

    def reset(self) -> None:
        """Zero the internal stick state immediately."""
        self._sx = self._sy = 0.0

    def step(self, dx: int | float, dy: int | float, dt: float) -> tuple[int, int]:
        """Process one tick of mouse input.

        Parameters
        ----------
        dx, dy : int | float
            Raw pixel deltas consumed from the input hooks since the
            previous tick.
        dt : float
            Actual elapsed time for this tick (seconds).  Used for
            frame-rate-independent decay.

        Returns
        -------
        (rx, ry) : tuple[int, int]
            Signed 16-bit XInput right-stick values in [-32768, 32767].
        """
        # Guard against NaN/Inf or non-finite inputs
        if not math.isfinite(dx):
            dx = 0.0
        if not math.isfinite(dy):
            dy = 0.0
        if not math.isfinite(dt) or dt < 0.0:
            dt = TARGET_DT

        # 1 ── scale by sensitivity, clamp spikes ────────────────────────
        cap = self.max_delta_per_tick
        fdx: float = max(-cap, min(cap, float(dx) * self.sensitivity))
        fdy: float = max(-cap, min(cap, float(dy) * self.sensitivity))
        if not math.isfinite(fdx):
            fdx = 0.0
        if not math.isfinite(fdy):
            fdy = 0.0

        # 2 ── EMA smooth (input present) / decay (idle) ─────────────────
        if dx != 0 or dy != 0:
            a = self._alpha
            one_minus_a = 1.0 - a
            self._sx = a * fdx + one_minus_a * self._sx
            self._sy = a * fdy + one_minus_a * self._sy
        else:
            # Frame-rate-independent: decay_rate is calibrated per 250 Hz tick
            ticks = dt * TARGET_HZ if dt > 0.0 else 1.0
            ticks = max(0.0, min(1000.0, ticks))
            decay = self.decay_rate ** ticks
            if not math.isfinite(decay):
                decay = 0.0
            self._sx *= decay
            self._sy *= decay
            if abs(self._sx) < _EPSILON:
                self._sx = 0.0
            if abs(self._sy) < _EPSILON:
                self._sy = 0.0

        if not math.isfinite(self._sx):
            self._sx = 0.0
        if not math.isfinite(self._sy):
            self._sy = 0.0

        # 3 ── radial magnitude & power curve ────────────────────────────
        sx, sy = self._sx, self._sy
        r = math.hypot(sx, sy)

        if not math.isfinite(r) or r < _EPSILON:
            return (0, 0)

        # Power curve on normalized radial magnitude [0.0, 1.0]
        r_clamped = max(0.0, min(1.0, r))
        r_curved: float = r_clamped ** self.curve_exponent
        if not math.isfinite(r_curved):
            r_curved = 0.0

        # 4 ── deadzone compensation: [0, 1] → [deadzone_comp, 1.0] ─────
        dz = self.deadzone_comp
        r_out: float = dz + r_curved * (1.0 - dz)
        if not math.isfinite(r_out):
            r_out = 0.0
        r_out = max(0.0, min(1.0, r_out))

        # 5 ── reconstruct output vector (unit direction × new magnitude) ─
        # Division-by-zero guard
        inv_r = (1.0 / r) if r > 0.0 else 0.0
        out_x: float = sx * inv_r * r_out
        out_y: float = sy * inv_r * r_out

        if not math.isfinite(out_x):
            out_x = 0.0
        if not math.isfinite(out_y):
            out_y = 0.0

        out_x = max(-1.0, min(1.0, out_x))
        out_y = max(-1.0, min(1.0, out_y))

        # 6 ── Y-axis: screen-down → XInput-up (unless inverted) ─────────
        if not self.invert_y:
            out_y = -out_y

        return (_to_int16(out_x), _to_int16(out_y))


# ── Self-test / unit tests ───────────────────────────────────────────────


def _test_recentering() -> tuple[bool, str]:
    """Idle mouse must decay the stick back to exactly (0, 0)."""
    m = MouseToStickMapper(sensitivity=0.10, decay_rate=0.80)
    # Push sustained input to deflect the stick
    for _ in range(10):
        m.step(40, -25, TARGET_DT)
    # Let it decay with zero input for 120 ticks (480 ms)
    rx, ry = 1, 1
    for _ in range(120):
        rx, ry = m.step(0, 0, TARGET_DT)
    ok = rx == 0 and ry == 0
    return ok, f"final=({rx}, {ry}), want (0, 0)"


def _test_deadzone_jump() -> tuple[bool, str]:
    """Tiny nudge must produce output ≥ deadzone_comp × 32767 (approx)."""
    dz = 0.20
    m = MouseToStickMapper(
        sensitivity=0.05,
        deadzone_comp=dz,
        curve_exponent=1.0,
        smoothing=0.0,          # no EMA lag
    )
    rx, ry = m.step(1, 0, TARGET_DT)
    mag = math.hypot(rx, ry)
    # With smoothing=0.0 (alpha=1.0), one step sets _sx = 0.05
    # r_curved = 0.05, r_out = 0.20 + 0.05*0.80 = 0.24
    # expected ≈ 0.24 * 32767 ≈ 7864
    threshold = dz * _I16_POS * 0.40   # generous margin
    ok = mag >= threshold
    return ok, f"mag={mag:.0f} ≥ threshold={threshold:.0f}"


def _test_diagonal_normalization() -> tuple[bool, str]:
    """Full diagonal input must not exceed stick radius (32767)."""
    m = MouseToStickMapper(
        sensitivity=0.50,
        curve_exponent=1.0,
        deadzone_comp=0.0,
        smoothing=0.0,
    )
    # Slam both axes with large equal deltas until converged
    for _ in range(30):
        rx, ry = m.step(200, 200, TARGET_DT)
    mag = math.hypot(rx, ry)
    limit = _I16_POS * 1.001       # tiny floating-point tolerance
    ok = mag <= limit
    return ok, f"mag={mag:.1f} ≤ {limit:.1f}"


def _test_timing_accuracy() -> tuple[bool, str]:
    """250 Hz loop average dt must be 4.0 ms ± 0.5 ms."""
    n_ticks = 250
    dts: list[float] = []
    with HighResTimer(TARGET_HZ) as clk:
        for _ in range(n_ticks):
            dts.append(clk.wait())
    # Skip first 10 warmup ticks
    trimmed = dts[10:]
    avg_ms = sum(trimmed) / len(trimmed) * 1000.0
    max_ms = max(trimmed) * 1000.0
    min_ms = min(trimmed) * 1000.0
    ok = abs(avg_ms - 4.0) < 0.5
    return ok, (
        f"avg={avg_ms:.3f} ms  min={min_ms:.3f} ms  max={max_ms:.3f} ms  "
        f"(target 4.000 ms)"
    )


def main() -> None:
    """Run all unit tests and print PASS/FAIL."""
    if sys.platform != "win32":
        print("SKIP — Windows is required.")
        sys.exit(0)

    tests: list[tuple[str, Callable[[], tuple[bool, str]]]] = [
        ("Zero-input recentering",  _test_recentering),
        ("Deadzone jump",           _test_deadzone_jump),
        ("Diagonal normalization",  _test_diagonal_normalization),
        ("250 Hz timing accuracy",  _test_timing_accuracy),
    ]

    print("stick_mapper.py — unit tests")
    print("=" * 60)

    all_ok = True
    for name, fn in tests:
        ok, detail = fn()
        icon = "✔" if ok else "✘"
        tag = "PASS" if ok else "FAIL"
        print(f"\n  [{icon}] {tag}  {name}")
        for line in detail.splitlines():
            print(f"         {line}")
        if not ok:
            all_ok = False

    print("\n" + "=" * 60)
    if all_ok:
        print("  Result: all tests PASSED.")
    else:
        print("  Result: some tests FAILED.")
        sys.exit(1)


if __name__ == "__main__":
    main()
