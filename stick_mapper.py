"""Mouse-to-Xbox 360 Right Thumbstick mapper at a fixed 250 Hz tick rate.

Provides
--------
- **HighResTimer** — Win32 ``timeBeginPeriod(1)`` + hybrid sleep / busy-wait
  loop targeting 250 Hz with sub-ms jitter.
- **MouseToStickMapper** — EMA smoothing, power-curve response, radial
  deadzone compensation, auto-recentering decay, and signed-int16 output.

Pure stdlib: ``math``, ``time``, ``ctypes``.  No numpy.
"""

from __future__ import annotations

import ctypes
import math
import sys
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
        if 0 < n <= 260:
            return Path(buf.value)
    except Exception:
        pass
    return Path(r"C:\Windows\System32")


def _load_winmm() -> ctypes.WinDLL:
    """Load winmm.dll strictly from System32 using LOAD_LIBRARY_SEARCH_SYSTEM32 (CWE-426)."""
    # LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
    try:
        return ctypes.WinDLL("winmm.dll", winmode=0x00000800)
    except TypeError:
        sys_dir = _get_system_directory()
        return ctypes.WinDLL(str(sys_dir / "winmm.dll"))
    except Exception as exc:
        raise RuntimeError(f"Failed to securely load winmm.dll from System32: {exc}") from exc


_winmm = _load_winmm()
_winmm.timeBeginPeriod.argtypes = [ctypes.c_uint]
_winmm.timeBeginPeriod.restype = ctypes.c_uint
_winmm.timeEndPeriod.argtypes = [ctypes.c_uint]
_winmm.timeEndPeriod.restype = ctypes.c_uint


# ── HighResTimer ─────────────────────────────────────────────────────────


class HighResTimer:
    """Hybrid sleep / busy-wait interval timer at *hz* Hz.

    Uses ``winmm.timeBeginPeriod(1)`` to lower the Windows scheduler
    quantum to ~1 ms, sleeps for the bulk of each interval, then
    busy-waits on ``time.perf_counter()`` for the final ~1 ms to hit
    the target with sub-ms accuracy.

    Must be used as a context manager so ``timeEndPeriod(1)`` is
    guaranteed to run::

        with HighResTimer(250.0) as clk:
            while running:
                dt = clk.wait()   # blocks until next tick
                ...
    """

    __slots__ = ("_dt", "_next", "_last")

    def __init__(self, hz: float = TARGET_HZ) -> None:
        if hz <= 0.0:
            raise ValueError(f"hz must be > 0, got {hz}")
        self._dt: float = 1.0 / hz
        self._next: float = 0.0
        self._last: float = 0.0

    # ── context manager ──────────────────────────────────────────────────

    def __enter__(self) -> HighResTimer:
        _winmm.timeBeginPeriod(ctypes.c_uint(1))
        now = time.perf_counter()
        self._next = now + self._dt
        self._last = now
        return self

    def __exit__(self, *exc: object) -> None:
        _winmm.timeEndPeriod(ctypes.c_uint(1))

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

        # ── hybrid sleep: coarse sleep → sub-ms busy-wait ──
        while True:
            now = time.perf_counter()
            remaining = target - now
            if remaining <= 0.0:
                break
            if remaining > 0.0015:                  # >1.5 ms left: sleep
                time.sleep(remaining - 0.001)       # wake ~1 ms before target
            # else: busy-wait for final <1.5 ms

        now = time.perf_counter()
        dt = now - self._last
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
    """
    c = max(-1.0, min(1.0, v))
    if c >= 0.0:
        return int(c * _I16_POS + 0.5)
    return -int(-c * _I16_NEG + 0.5)


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
    decay_rate : float
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
            smoothing = 1.0 - smoothing_alpha
        # ── validate ──
        if sensitivity <= 0.0:
            raise ValueError(f"sensitivity must be > 0, got {sensitivity}")
        if curve_exponent <= 0.0:
            raise ValueError(f"curve_exponent must be > 0, got {curve_exponent}")
        if not 0.0 <= deadzone_comp <= 0.35:
            raise ValueError(
                f"deadzone_comp must be in [0.0, 0.35], got {deadzone_comp}"
            )
        if not 0.0 <= smoothing < 1.0:
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

    def step(self, dx: int, dy: int, dt: float) -> tuple[int, int]:
        """Process one tick of mouse input.

        Parameters
        ----------
        dx, dy : int
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
        # 1 ── scale by sensitivity, clamp spikes ────────────────────────
        cap = self.max_delta_per_tick
        fdx: float = max(-cap, min(cap, dx * self.sensitivity))
        fdy: float = max(-cap, min(cap, dy * self.sensitivity))

        # 2 ── EMA smooth (input present) / decay (idle) ─────────────────
        if dx != 0 or dy != 0:
            a = self._alpha
            one_minus_a = 1.0 - a
            self._sx = a * fdx + one_minus_a * self._sx
            self._sy = a * fdy + one_minus_a * self._sy
        else:
            # Frame-rate-independent: decay_rate is calibrated per 250 Hz tick
            ticks = dt * TARGET_HZ if dt > 0.0 else 1.0
            decay = self.decay_rate ** ticks
            self._sx *= decay
            self._sy *= decay
            if abs(self._sx) < _EPSILON:
                self._sx = 0.0
            if abs(self._sy) < _EPSILON:
                self._sy = 0.0

        # 3 ── radial magnitude & power curve ────────────────────────────
        sx, sy = self._sx, self._sy
        r = math.hypot(sx, sy)

        if r < _EPSILON:
            return (0, 0)

        r_curved: float = min(1.0, r) ** self.curve_exponent

        # 4 ── deadzone compensation: [0, 1] → [deadzone_comp, 1.0] ─────
        dz = self.deadzone_comp
        r_out: float = dz + r_curved * (1.0 - dz)

        # 5 ── reconstruct output vector (unit direction × new magnitude) ─
        inv_r = 1.0 / r
        out_x: float = sx * inv_r * r_out
        out_y: float = sy * inv_r * r_out

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
