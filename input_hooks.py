"""Low-level Win32 input hooks for intercepting mouse and keyboard events.

Uses WH_KEYBOARD_LL and WH_MOUSE_LL hooks on a dedicated background
thread running a Win32 message pump.  F8 toggles capture on/off;
captured events are swallowed so they never reach Chrome, Xbox, etc.
"""

from __future__ import annotations

import atexit
import ctypes
import ctypes.wintypes as wt
import signal
import sys
import threading
import time
from collections.abc import Callable
from types import TracebackType

# ── Win32 Constants ──────────────────────────────────────────────────────

WH_KEYBOARD_LL: int = 13
WH_MOUSE_LL: int = 14

WM_KEYDOWN: int = 0x0100
WM_KEYUP: int = 0x0101
WM_SYSKEYDOWN: int = 0x0104
WM_SYSKEYUP: int = 0x0105

WM_MOUSEMOVE: int = 0x0200
WM_LBUTTONDOWN: int = 0x0201
WM_LBUTTONUP: int = 0x0202
WM_RBUTTONDOWN: int = 0x0204
WM_RBUTTONUP: int = 0x0205
WM_MBUTTONDOWN: int = 0x0207
WM_MBUTTONUP: int = 0x0208
WM_MOUSEWHEEL: int = 0x020A

WM_QUIT: int = 0x0012
VK_F8: int = 0x77

_KEY_DOWN_MSGS: frozenset[int] = frozenset({WM_KEYDOWN, WM_SYSKEYDOWN})
_KEY_UP_MSGS: frozenset[int] = frozenset({WM_KEYUP, WM_SYSKEYUP})

_BTN_DOWN_MAP: dict[int, str] = {
    WM_LBUTTONDOWN: "left",
    WM_RBUTTONDOWN: "right",
    WM_MBUTTONDOWN: "middle",
}
_BTN_UP_MAP: dict[int, str] = {
    WM_LBUTTONUP: "left",
    WM_RBUTTONUP: "right",
    WM_MBUTTONUP: "middle",
}

# ── Win32 Type Aliases ───────────────────────────────────────────────────

LRESULT: type[ctypes.c_ssize_t] = ctypes.c_ssize_t
ULONG_PTR: type[ctypes.c_size_t] = ctypes.c_size_t

# LRESULT CALLBACK LowLevelProc(int nCode, WPARAM wParam, LPARAM lParam)
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wt.WPARAM, wt.LPARAM)

# ── Win32 Structures ────────────────────────────────────────────────────


class KBDLLHOOKSTRUCT(ctypes.Structure):
    """Win32 KBDLLHOOKSTRUCT for WH_KEYBOARD_LL."""

    _fields_ = [
        ("vkCode", wt.DWORD),
        ("scanCode", wt.DWORD),
        ("flags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class MSLLHOOKSTRUCT(ctypes.Structure):
    """Win32 MSLLHOOKSTRUCT for WH_MOUSE_LL."""

    _fields_ = [
        ("pt", wt.POINT),
        ("mouseData", wt.DWORD),
        ("flags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


# ── Win32 Function Prototypes ───────────────────────────────────────────

_user32 = ctypes.windll.user32
_kernel32 = ctypes.windll.kernel32

_user32.SetWindowsHookExW.argtypes = [
    ctypes.c_int, HOOKPROC, wt.HINSTANCE, wt.DWORD,
]
_user32.SetWindowsHookExW.restype = ctypes.c_void_p  # HHOOK

_user32.CallNextHookEx.argtypes = [
    ctypes.c_void_p, ctypes.c_int, wt.WPARAM, wt.LPARAM,
]
_user32.CallNextHookEx.restype = LRESULT

_user32.UnhookWindowsHookEx.argtypes = [ctypes.c_void_p]
_user32.UnhookWindowsHookEx.restype = wt.BOOL

_user32.GetMessageW.argtypes = [
    ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT,
]
_user32.GetMessageW.restype = ctypes.c_int  # -1 error, 0 WM_QUIT, >0 ok

_user32.PeekMessageW.argtypes = [
    ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT, wt.UINT,
]
_user32.PeekMessageW.restype = wt.BOOL

_user32.PostThreadMessageW.argtypes = [
    wt.DWORD, wt.UINT, wt.WPARAM, wt.LPARAM,
]
_user32.PostThreadMessageW.restype = wt.BOOL

_kernel32.GetCurrentThreadId.argtypes = []
_kernel32.GetCurrentThreadId.restype = wt.DWORD

_kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
_kernel32.GetModuleHandleW.restype = wt.HMODULE


# ── InputHooks ───────────────────────────────────────────────────────────


class InputHooks:
    """Low-level Win32 keyboard/mouse hooks with F8 toggle.

    When *active* (toggled by F8), every keyboard and mouse event is
    recorded into thread-safe buffers and **swallowed** (return 1) so
    Chrome, the Xbox app, or any other foreground window sees nothing.

    Usage::

        with InputHooks() as hooks:
            while True:
                if hooks.active:
                    dx, dy = hooks.consume_mouse_delta()
                    keys   = hooks.get_keys_pressed()
                    ...

    The ``on_toggle`` callback, if supplied, **must complete in < 1 ms**
    because it runs inside the low-level hook callback on the pump thread.
    """

    # ── Construction ─────────────────────────────────────────────────────

    def __init__(
        self,
        *,
        toggle_key: int = VK_F8,
        passthrough_keys: tuple[int, ...] | set[int] | frozenset[int] | None = None,
        on_toggle: Callable[[bool], None] | None = None,
    ) -> None:
        self._toggle_vk: int = toggle_key
        self._passthrough_keys: frozenset[int] = (
            frozenset(passthrough_keys) if passthrough_keys is not None else frozenset()
        )
        self._on_toggle: Callable[[bool], None] | None = on_toggle

        # Public observable state (written only on hook thread)
        self._active: bool = False
        self._f8_held: bool = False

        # Keyboard: set of currently-pressed virtual-key codes
        self._keys_lock = threading.Lock()
        self._keys_down: set[int] = set()

        # Mouse: accumulated deltas, button states, wheel
        self._mouse_lock = threading.Lock()
        self._dx: int = 0
        self._dy: int = 0
        self._last_pt: tuple[int, int] | None = None
        self._lbutton: bool = False
        self._rbutton: bool = False
        self._mbutton: bool = False
        self._wheel_delta: int = 0

        # Hook handles (pointer-sized)
        self._kb_hook: int = 0
        self._mouse_hook: int = 0

        # Dedicated hook / message-pump thread
        self._thread: threading.Thread | None = None
        self._thread_id: int = 0
        self._ready = threading.Event()

        # prevent GC of ctypes callback wrappers ──────────────────────────
        self._kb_proc_ref: HOOKPROC = HOOKPROC(self._keyboard_ll_proc)
        self._mouse_proc_ref: HOOKPROC = HOOKPROC(self._mouse_ll_proc)

        # Cleanup guard
        self._cleanup_lock = threading.Lock()
        self._running: bool = False

        # Stash originals for failsafe restoration
        self._orig_sigint: signal._HANDLER = signal.SIG_DFL
        self._orig_sigterm: signal._HANDLER = signal.SIG_DFL
        self._orig_excepthook = sys.excepthook

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def active(self) -> bool:
        """Whether input capture is currently active."""
        return self._active

    # ── Consumer API (thread-safe) ───────────────────────────────────────

    def consume_mouse_delta(self) -> tuple[int, int]:
        """Return accumulated ``(dx, dy)`` since last call, then reset."""
        with self._mouse_lock:
            dx, dy = self._dx, self._dy
            self._dx = self._dy = 0
        return dx, dy

    def consume_wheel_delta(self) -> int:
        """Return accumulated wheel delta since last call, then reset."""
        with self._mouse_lock:
            d = self._wheel_delta
            self._wheel_delta = 0
        return d

    def get_keys_pressed(self) -> frozenset[int]:
        """Snapshot of currently held virtual-key codes."""
        with self._keys_lock:
            return frozenset(self._keys_down)

    def get_mouse_buttons(self) -> tuple[bool, bool, bool]:
        """Return ``(left, right, middle)`` button-down states."""
        with self._mouse_lock:
            return self._lbutton, self._rbutton, self._mbutton

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Install hooks and start the Win32 message-pump thread."""
        with self._cleanup_lock:
            if self._running:
                return
            self._running = True

        self._ready.clear()
        self._thread = threading.Thread(
            target=self._pump_thread,
            name="InputHooks-pump",
            daemon=True,
        )
        self._thread.start()

        if not self._ready.wait(timeout=5.0):
            self._running = False
            raise RuntimeError("Hook thread did not start within 5 s")

        # Register failsafe teardown paths
        atexit.register(self.stop)
        self._install_failsafes()

    def stop(self) -> None:
        """Deactivate, unhook, stop the pump, and join the thread."""
        with self._cleanup_lock:
            if not self._running:
                return
            self._running = False

        self._active = False

        # Tell the pump thread to exit
        tid = self._thread_id
        if tid:
            _user32.PostThreadMessageW(wt.DWORD(tid), WM_QUIT, 0, 0)

        # Wait for pump thread to finish (hooks are unhooked in its finally)
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=3.0)

        # Belt-and-suspenders: unhook from *this* thread if still hooked
        self._force_unhook()

        try:
            atexit.unregister(self.stop)
        except Exception:
            pass

        self._restore_failsafes()

    # ── Context Manager ──────────────────────────────────────────────────

    def __enter__(self) -> InputHooks:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.stop()

    # ── Pump Thread ──────────────────────────────────────────────────────

    def _pump_thread(self) -> None:
        """Install hooks, run the Win32 message loop, unhook on exit."""
        try:
            # Force-create a message queue before anyone posts to us
            msg = wt.MSG()
            _user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 0)

            hmod = _kernel32.GetModuleHandleW(None)

            # ── install keyboard hook ──
            self._kb_hook = _user32.SetWindowsHookExW(
                WH_KEYBOARD_LL, self._kb_proc_ref, hmod, 0,
            )
            if not self._kb_hook:
                raise OSError(
                    f"SetWindowsHookExW(WH_KEYBOARD_LL) failed: "
                    f"{ctypes.WinError()}"
                )

            # ── install mouse hook ──
            self._mouse_hook = _user32.SetWindowsHookExW(
                WH_MOUSE_LL, self._mouse_proc_ref, hmod, 0,
            )
            if not self._mouse_hook:
                _user32.UnhookWindowsHookEx(self._kb_hook)
                self._kb_hook = 0
                raise OSError(
                    f"SetWindowsHookExW(WH_MOUSE_LL) failed: "
                    f"{ctypes.WinError()}"
                )

            self._thread_id = _kernel32.GetCurrentThreadId()
            self._ready.set()

            # ── message pump (drives low-level hook callbacks) ──
            while True:
                ret = _user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if ret <= 0:  # 0 → WM_QUIT, -1 → error
                    break
        finally:
            self._force_unhook()

    def _force_unhook(self) -> None:
        """Unhook both hooks if still installed (idempotent, any thread)."""
        with self._cleanup_lock:
            kb, self._kb_hook = self._kb_hook, 0
            ms, self._mouse_hook = self._mouse_hook, 0
        if kb:
            _user32.UnhookWindowsHookEx(kb)
        if ms:
            _user32.UnhookWindowsHookEx(ms)

    # ── Hook Callbacks (ultra-fast, <1 ms) ───────────────────────────────

    def _keyboard_ll_proc(
        self, nCode: int, wParam: int, lParam: int,
    ) -> int:
        """``WH_KEYBOARD_LL`` callback — capture keys or pass through."""
        try:
            if nCode < 0:
                return _user32.CallNextHookEx(
                    self._kb_hook, nCode, wParam, lParam,
                )

            kbd = ctypes.cast(
                lParam, ctypes.POINTER(KBDLLHOOKSTRUCT),
            ).contents
            vk: int = kbd.vkCode

            # ── Toggle key (F8) — always passed through ──
            if vk == self._toggle_vk:
                if wParam in _KEY_DOWN_MSGS and not self._f8_held:
                    self._f8_held = True
                    new_active = not self._active
                    self._active = new_active
                    if new_active:
                        # Reset all accumulators on activation
                        with self._mouse_lock:
                            self._last_pt = None
                            self._dx = self._dy = 0
                            self._lbutton = False
                            self._rbutton = False
                            self._mbutton = False
                            self._wheel_delta = 0
                        with self._keys_lock:
                            self._keys_down.clear()
                    else:
                        # Clear state on deactivation
                        with self._keys_lock:
                            self._keys_down.clear()
                        with self._mouse_lock:
                            self._lbutton = False
                            self._rbutton = False
                            self._mbutton = False
                    if self._on_toggle is not None:
                        self._on_toggle(new_active)
                elif wParam in _KEY_UP_MSGS:
                    self._f8_held = False
                # NEVER swallow the toggle key
                return _user32.CallNextHookEx(
                    self._kb_hook, nCode, wParam, lParam,
                )

            # ── Additional passthrough keys (e.g. F9 profile switch) ──
            if vk in self._passthrough_keys:
                return _user32.CallNextHookEx(
                    self._kb_hook, nCode, wParam, lParam,
                )

            # ── Active → record and swallow ──
            if self._active:
                if wParam in _KEY_DOWN_MSGS:
                    with self._keys_lock:
                        self._keys_down.add(vk)
                elif wParam in _KEY_UP_MSGS:
                    with self._keys_lock:
                        self._keys_down.discard(vk)
                return 1  # swallow

        except Exception:
            pass  # Never let a Python exception escape into Win32

        return _user32.CallNextHookEx(self._kb_hook, nCode, wParam, lParam)

    def _mouse_ll_proc(
        self, nCode: int, wParam: int, lParam: int,
    ) -> int:
        """``WH_MOUSE_LL`` callback — capture mouse or pass through."""
        try:
            if nCode < 0 or not self._active:
                return _user32.CallNextHookEx(
                    self._mouse_hook, nCode, wParam, lParam,
                )

            mouse = ctypes.cast(
                lParam, ctypes.POINTER(MSLLHOOKSTRUCT),
            ).contents
            msg: int = wParam

            # ── Movement → accumulate dx/dy ──
            if msg == WM_MOUSEMOVE:
                x, y = mouse.pt.x, mouse.pt.y
                with self._mouse_lock:
                    if self._last_pt is not None:
                        self._dx += x - self._last_pt[0]
                        self._dy += y - self._last_pt[1]
                    self._last_pt = (x, y)
                return 1  # swallow (cursor freezes)

            # ── Button down ──
            btn = _BTN_DOWN_MAP.get(msg)
            if btn is not None:
                with self._mouse_lock:
                    if btn == "left":
                        self._lbutton = True
                    elif btn == "right":
                        self._rbutton = True
                    else:
                        self._mbutton = True
                return 1

            # ── Button up ──
            btn = _BTN_UP_MAP.get(msg)
            if btn is not None:
                with self._mouse_lock:
                    if btn == "left":
                        self._lbutton = False
                    elif btn == "right":
                        self._rbutton = False
                    else:
                        self._mbutton = False
                return 1

            # ── Mouse wheel ──
            if msg == WM_MOUSEWHEEL:
                # Signed wheel delta lives in the high word of mouseData
                raw: int = mouse.mouseData
                delta: int = ctypes.c_short((raw >> 16) & 0xFFFF).value
                with self._mouse_lock:
                    self._wheel_delta += delta
                return 1

            # Any other mouse message while active → swallow
            return 1

        except Exception:
            pass

        return _user32.CallNextHookEx(
            self._mouse_hook, nCode, wParam, lParam,
        )

    # ── Failsafe Registration ────────────────────────────────────────────

    def _install_failsafes(self) -> None:
        """Register SIGINT/SIGTERM handlers, sys.excepthook override."""
        # Signal handlers (main thread only)
        if threading.current_thread() is threading.main_thread():
            self._orig_sigint = signal.getsignal(signal.SIGINT)
            self._orig_sigterm = signal.getsignal(signal.SIGTERM)

            def _sig_handler(signum: int, frame: object) -> None:
                self.stop()
                if signum == signal.SIGINT:
                    raise KeyboardInterrupt
                sys.exit(128 + signum)

            signal.signal(signal.SIGINT, _sig_handler)
            signal.signal(signal.SIGTERM, _sig_handler)

        # sys.excepthook
        self._orig_excepthook = sys.excepthook

        def _excepthook(
            etype: type[BaseException],
            val: BaseException,
            tb: TracebackType | None,
        ) -> None:
            self.stop()
            self._orig_excepthook(etype, val, tb)

        sys.excepthook = _excepthook

    def _restore_failsafes(self) -> None:
        """Restore original signal handlers and excepthook."""
        if threading.current_thread() is threading.main_thread():
            try:
                signal.signal(signal.SIGINT, self._orig_sigint)
                signal.signal(signal.SIGTERM, self._orig_sigterm)
            except (OSError, ValueError):
                pass
        try:
            sys.excepthook = self._orig_excepthook
        except Exception:
            pass


# ── Class Alias ──────────────────────────────────────────────────────────

InputHookManager = InputHooks


# ── Self-test ────────────────────────────────────────────────────────────

def main() -> None:
    """Run a 10-second self-test: press F8 to toggle, Ctrl+C to quit."""
    print("InputHooks self-test")
    print("=" * 55)
    print("  Press F8 to toggle capture ON / OFF.")
    print("  While ON every key / mouse event is swallowed.")
    print("  Press Ctrl+C to exit early.")
    print("  Auto-exits after 10 seconds.")
    print("=" * 55, "\n")

    def _on_toggle(now_active: bool) -> None:
        tag = "ON  ✓" if now_active else "OFF ✗"
        # print() is fast enough for a low-level hook callback self-test
        print(f"  [F8] Capture toggled → {tag}")

    hooks = InputHooks(on_toggle=_on_toggle)

    try:
        with hooks:
            t0 = time.monotonic()
            while time.monotonic() - t0 < 10.0:
                time.sleep(0.20)
                if not hooks.active:
                    continue

                dx, dy = hooks.consume_mouse_delta()
                wheel = hooks.consume_wheel_delta()
                keys = hooks.get_keys_pressed()
                lb, rb, mb = hooks.get_mouse_buttons()

                parts: list[str] = []
                if dx or dy:
                    parts.append(f"mouse Δ({dx:+d}, {dy:+d})")
                if wheel:
                    parts.append(f"wheel {wheel:+d}")
                if keys:
                    vk_hex = [f"0x{k:02X}" for k in sorted(keys)]
                    parts.append(f"keys [{', '.join(vk_hex)}]")
                btns = ("L" if lb else "") + ("R" if rb else "") + ("M" if mb else "")
                if btns:
                    parts.append(f"btn [{btns}]")
                if parts:
                    print(f"    {' │ '.join(parts)}")

    except KeyboardInterrupt:
        print("\n  [Ctrl+C] Interrupted — cleaning up.")

    print("\nSelf-test finished. All hooks released.")


if __name__ == "__main__":
    main()
