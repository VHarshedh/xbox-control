"""Low-level Win32 input hooks for intercepting mouse and keyboard events.

Uses WH_KEYBOARD_LL and WH_MOUSE_LL hooks on a dedicated background
thread running a Win32 message pump. F8 toggles capture on/off;
captured events are swallowed so they never reach Chrome, Xbox, etc.
"""

from __future__ import annotations

import atexit
import contextlib
import ctypes
import ctypes.wintypes as wt
import signal
import sys
import threading
import time
from collections.abc import Callable
from types import TracebackType
from typing import Any

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
WM_LBUTTONDBLCLK: int = 0x0203
WM_RBUTTONDOWN: int = 0x0204
WM_RBUTTONUP: int = 0x0205
WM_RBUTTONDBLCLK: int = 0x0206
WM_MBUTTONDOWN: int = 0x0207
WM_MBUTTONUP: int = 0x0208
WM_MBUTTONDBLCLK: int = 0x0209
WM_MOUSEWHEEL: int = 0x020A
WM_XBUTTONDOWN: int = 0x020B
WM_XBUTTONUP: int = 0x020C
WM_XBUTTONDBLCLK: int = 0x020D
WM_MOUSEHWHEEL: int = 0x020E

WM_QUIT: int = 0x0012
VK_F8: int = 0x77
VK_F9: int = 0x78
VK_LWIN: int = 0x5B
VK_RWIN: int = 0x5C

DEFAULT_PASSTHROUGH_KEYS: frozenset[int] = frozenset({VK_LWIN, VK_RWIN})

LLMHF_INJECTED: int = 0x01
LLMHF_LOWER_IL_INJECTED: int = 0x02
LLMHF_INJECTED_MASK: int = LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED

LLKHF_EXTENDED: int = 0x01
LLKHF_LOWER_IL_INJECTED: int = 0x02
LLKHF_INJECTED: int = 0x10
LLKHF_ALTDOWN: int = 0x20
LLKHF_UP: int = 0x80
LLKHF_INJECTED_MASK: int = LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED

XBUTTON1: int = 0x0001
XBUTTON2: int = 0x0002

CTRL_C_EVENT: int = 0
CTRL_BREAK_EVENT: int = 1
CTRL_CLOSE_EVENT: int = 2
CTRL_LOGOFF_EVENT: int = 5
CTRL_SHUTDOWN_EVENT: int = 6

SM_CXSCREEN: int = 0
SM_CYSCREEN: int = 1
SM_XVIRTUALSCREEN: int = 76
SM_YVIRTUALSCREEN: int = 77
SM_CXVIRTUALSCREEN: int = 78
SM_CYVIRTUALSCREEN: int = 79

_KEY_DOWN_MSGS: frozenset[int] = frozenset({WM_KEYDOWN, WM_SYSKEYDOWN})
_KEY_UP_MSGS: frozenset[int] = frozenset({WM_KEYUP, WM_SYSKEYUP})

_BTN_DOWN_MAP: dict[int, str] = {
    WM_LBUTTONDOWN: "left",
    WM_LBUTTONDBLCLK: "left",
    WM_RBUTTONDOWN: "right",
    WM_RBUTTONDBLCLK: "right",
    WM_MBUTTONDOWN: "middle",
    WM_MBUTTONDBLCLK: "middle",
}
_BTN_UP_MAP: dict[int, str] = {
    WM_LBUTTONUP: "left",
    WM_RBUTTONUP: "right",
    WM_MBUTTONUP: "middle",
}

# ── Win32 Type Aliases ───────────────────────────────────────────────────

if ctypes.sizeof(ctypes.c_void_p) == 8:
    ULONG_PTR: type[ctypes.c_uint64] = ctypes.c_uint64
    LRESULT: type[ctypes.c_int64] = ctypes.c_int64
else:
    ULONG_PTR: type[ctypes.c_uint32] = ctypes.c_uint32  # type: ignore[no-redef]
    LRESULT: type[ctypes.c_int32] = ctypes.c_int32      # type: ignore[no-redef]

# LRESULT CALLBACK LowLevelProc(int nCode, WPARAM wParam, LPARAM lParam)
HOOKPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_int, wt.WPARAM, wt.LPARAM)

# BOOL WINAPI HandlerRoutine(DWORD dwCtrlType)
PHANDLER_ROUTINE = ctypes.WINFUNCTYPE(wt.BOOL, wt.DWORD)

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


# Validate structural alignment and field offsets per Win32 ABI specifications
if ctypes.sizeof(ctypes.c_void_p) == 8:
    assert ctypes.sizeof(KBDLLHOOKSTRUCT) == 24, "KBDLLHOOKSTRUCT size mismatch"
    assert ctypes.sizeof(MSLLHOOKSTRUCT) == 32, "MSLLHOOKSTRUCT size mismatch"
    assert KBDLLHOOKSTRUCT.dwExtraInfo.offset == 16, "KBDLLHOOKSTRUCT dwExtraInfo offset mismatch"
    assert MSLLHOOKSTRUCT.dwExtraInfo.offset == 24, "MSLLHOOKSTRUCT dwExtraInfo offset mismatch"
else:
    assert ctypes.sizeof(KBDLLHOOKSTRUCT) == 20, "KBDLLHOOKSTRUCT size mismatch"
    assert ctypes.sizeof(MSLLHOOKSTRUCT) == 24, "MSLLHOOKSTRUCT size mismatch"
    assert KBDLLHOOKSTRUCT.dwExtraInfo.offset == 16, "KBDLLHOOKSTRUCT dwExtraInfo offset mismatch"
    assert MSLLHOOKSTRUCT.dwExtraInfo.offset == 20, "MSLLHOOKSTRUCT dwExtraInfo offset mismatch"


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

_user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
_user32.SetCursorPos.restype = wt.BOOL

_user32.GetCursorPos.argtypes = [ctypes.POINTER(wt.POINT)]
_user32.GetCursorPos.restype = wt.BOOL

_user32.GetSystemMetrics.argtypes = [ctypes.c_int]
_user32.GetSystemMetrics.restype = ctypes.c_int

_kernel32.GetCurrentThreadId.argtypes = []
_kernel32.GetCurrentThreadId.restype = wt.DWORD

_kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
_kernel32.GetModuleHandleW.restype = wt.HMODULE

_kernel32.SetConsoleCtrlHandler.argtypes = [PHANDLER_ROUTINE, wt.BOOL]
_kernel32.SetConsoleCtrlHandler.restype = wt.BOOL

_kernel32.GetLastError.argtypes = []
_kernel32.GetLastError.restype = wt.DWORD


# ── DPI Awareness Initialization ─────────────────────────────────────────

def _enable_per_monitor_dpi_awareness() -> None:
    """Enable Per-Monitor V2 DPI awareness for pixel-accurate cursor geometry."""
    ERROR_ACCESS_DENIED = 5

    # 1. Try SetProcessDpiAwarenessContext (Windows 10 1703+)
    try:
        _user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        _user32.SetProcessDpiAwarenessContext.restype = wt.BOOL
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        if _user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            return
        if _kernel32.GetLastError() == ERROR_ACCESS_DENIED:
            return  # Already set by application manifest or earlier call

        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE = -3
        if _user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-3)):
            return
        if _kernel32.GetLastError() == ERROR_ACCESS_DENIED:
            return
    except (AttributeError, OSError):
        pass

    # 2. Try SetProcessDpiAwareness via shcore (Windows 8.1+)
    try:
        shcore = ctypes.WinDLL("shcore.dll")
        shcore.SetProcessDpiAwareness.argtypes = [ctypes.c_int]
        shcore.SetProcessDpiAwareness.restype = ctypes.c_long  # HRESULT
        # PROCESS_PER_MONITOR_DPI_AWARE = 2
        hr = shcore.SetProcessDpiAwareness(2)
        # S_OK = 0, E_ACCESSDENIED = 0x80070005 (-2147024891)
        if hr in (0, -2147024891):
            return
    except (AttributeError, OSError):
        pass

    # 3. Fallback to SetProcessDPIAware via user32 (Windows Vista+)
    try:
        _user32.SetProcessDPIAware.argtypes = []
        _user32.SetProcessDPIAware.restype = wt.BOOL
        _user32.SetProcessDPIAware()
    except (AttributeError, OSError):
        pass


# ── InputHooks ───────────────────────────────────────────────────────────


class InputHooks:
    """Low-level Win32 keyboard/mouse hooks with F8 toggle and F9 cycling.

    When *active* (toggled by F8), keyboard and mouse events are recorded
    into thread-safe buffers and swallowed (return 1) to prevent leakage
    to foreground applications. F9 requests are queued atomically for
    safe profile cycling without input contention.
    """

    # ── Construction ─────────────────────────────────────────────────────

    def __init__(
        self,
        *,
        toggle_key: int = VK_F8,
        passthrough_keys: tuple[int, ...] | set[int] | frozenset[int] | None = None,
        on_toggle: Callable[[bool], None] | None = None,
    ) -> None:
        self._toggle_vk: int = toggle_key & 0xFF
        if passthrough_keys is not None:
            self._passthrough_keys: frozenset[int] = frozenset(k & 0xFF for k in passthrough_keys)
        else:
            self._passthrough_keys = DEFAULT_PASSTHROUGH_KEYS
        self._on_toggle: Callable[[bool], None] | None = on_toggle

        # Unified reentrant state lock for atomic state transitions and consumer reads
        self._lock = threading.RLock()
        self._keys_lock = self._lock    # Backwards compatibility alias
        self._mouse_lock = self._lock   # Backwards compatibility alias

        # Capture and toggle states
        self._active: bool = False
        self._f8_held: bool = False
        self._f9_held: bool = False
        self._profile_cycle_requested: bool = False

        # Keyboard: set of currently-pressed virtual-key codes
        self._keys_down: set[int] = set()

        # Mouse: accumulated deltas, button states, wheel
        self._dx: int = 0
        self._dy: int = 0
        self._last_pt: tuple[int, int] | None = None
        self._lbutton: bool = False
        self._rbutton: bool = False
        self._mbutton: bool = False
        self._xbutton1: bool = False
        self._xbutton2: bool = False
        self._wheel_delta: int = 0

        # Hook handles (pointer-sized)
        self._kb_hook: int = 0
        self._mouse_hook: int = 0

        # Dedicated hook / message-pump thread
        self._thread: threading.Thread | None = None
        self._thread_id: int = 0
        self._ready = threading.Event()
        self._init_error: Exception | None = None

        # Pinned ctypes callback wrappers to prevent GC while installed
        self._kb_proc_ref: Any = HOOKPROC(self._keyboard_ll_proc)
        self._mouse_proc_ref: Any = HOOKPROC(self._mouse_ll_proc)
        self._console_ctrl_routine: Any = None

        # Reentrant cleanup guard to prevent deadlocks and race conditions
        self._cleanup_lock = threading.RLock()
        self._running: bool = False

        # Stash originals for failsafe restoration
        self._orig_sigint: signal._HANDLER = signal.SIG_DFL
        self._orig_sigterm: signal._HANDLER = signal.SIG_DFL
        self._orig_excepthook = sys.excepthook
        self._orig_threading_excepthook = threading.excepthook

    # ── Properties ───────────────────────────────────────────────────────

    @property
    def active(self) -> bool:
        """Whether input capture is currently active."""
        with self._lock:
            return self._active

    # ── Consumer API (thread-safe) ───────────────────────────────────────

    def consume_mouse_delta(self) -> tuple[int, int]:
        """Return accumulated ``(dx, dy)`` since last call, then reset."""
        with self._lock:
            dx, dy = self._dx, self._dy
            self._dx = self._dy = 0
            return dx, dy

    def consume_wheel_delta(self) -> int:
        """Return accumulated wheel delta since last call, then reset."""
        with self._lock:
            d = self._wheel_delta
            self._wheel_delta = 0
            return d

    def consume_profile_cycle(self) -> bool:
        """Atomically check and consume any pending F9 profile cycle request."""
        with self._lock:
            req = self._profile_cycle_requested
            self._profile_cycle_requested = False
            return req

    def get_keys_pressed(self) -> frozenset[int]:
        """Snapshot of currently held virtual-key codes."""
        with self._lock:
            return frozenset(self._keys_down)

    def get_mouse_buttons(self) -> tuple[bool, bool, bool, bool, bool]:
        """Return ``(left, right, middle, xbutton1, xbutton2)`` button states."""
        with self._lock:
            return (
                self._lbutton,
                self._rbutton,
                self._mbutton,
                self._xbutton1,
                self._xbutton2,
            )

    def get_extra_mouse_buttons(self) -> tuple[bool, bool]:
        """Return ``(xbutton1, xbutton2)`` button states."""
        with self._lock:
            return self._xbutton1, self._xbutton2

    # ── Lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        """Install hooks and start the Win32 message-pump thread."""
        with self._cleanup_lock:
            if self._running:
                return
            self._running = True

        _enable_per_monitor_dpi_awareness()

        self._ready.clear()
        self._init_error = None
        self._thread = threading.Thread(
            target=self._pump_thread,
            name="InputHooks-pump",
            daemon=True,
        )
        self._thread.start()

        if not self._ready.wait(timeout=5.0):
            self.stop()
            raise RuntimeError("Hook thread did not start within 5 s")

        if self._init_error is not None:
            self.stop()
            raise self._init_error

        # Register failsafe teardown paths
        atexit.register(self.stop)
        self._install_failsafes()

    def stop(self) -> None:
        """Deactivate, unhook, stop the pump, and join the thread."""
        with self._cleanup_lock:
            if not self._running:
                self._force_unhook()
                return
            self._running = False

        # Reset active flag and clear buffers atomically under state lock
        with self._lock:
            self._active = False
            self._keys_down.clear()
            self._last_pt = None
            self._dx = self._dy = self._wheel_delta = 0
            self._lbutton = False
            self._rbutton = False
            self._mbutton = False
            self._xbutton1 = False
            self._xbutton2 = False

        # Immediately detach hooks so OS ceases delivering events
        self._force_unhook()

        # Tell the pump thread to exit
        tid = self._thread_id
        if tid:
            with contextlib.suppress(Exception):
                _user32.PostThreadMessageW(wt.DWORD(tid), WM_QUIT, 0, 0)

        # Wait for pump thread to finish (avoid joining current thread)
        cur_thread = threading.current_thread()
        if self._thread is not None and self._thread is not cur_thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

        with contextlib.suppress(Exception):
            atexit.unregister(self.stop)

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
            msg = wt.MSG()
            # Force message queue allocation on this thread
            _user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 0)
            self._thread_id = _kernel32.GetCurrentThreadId()

            hmod = _kernel32.GetModuleHandleW(None)

            # Keyboard hook
            self._kb_hook = _user32.SetWindowsHookExW(
                WH_KEYBOARD_LL, self._kb_proc_ref, hmod, 0,
            )
            if not self._kb_hook:
                raise OSError(
                    f"SetWindowsHookExW(WH_KEYBOARD_LL) failed: {ctypes.WinError()}"
                )

            # Mouse hook
            self._mouse_hook = _user32.SetWindowsHookExW(
                WH_MOUSE_LL, self._mouse_proc_ref, hmod, 0,
            )
            if not self._mouse_hook:
                _user32.UnhookWindowsHookEx(self._kb_hook)
                self._kb_hook = 0
                raise OSError(
                    f"SetWindowsHookExW(WH_MOUSE_LL) failed: {ctypes.WinError()}"
                )

            self._ready.set()

            # Message pump loop
            while True:
                ret = _user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if ret <= 0:
                    break
        except Exception as exc:
            self._init_error = exc
            self._ready.set()
        finally:
            self._force_unhook()

    def _force_unhook(self) -> None:
        """Unhook both hooks if still installed (idempotent, thread-safe, reentrant)."""
        with self._cleanup_lock:
            kb, self._kb_hook = self._kb_hook, 0
            ms, self._mouse_hook = self._mouse_hook, 0
        if kb:
            with contextlib.suppress(Exception):
                _user32.UnhookWindowsHookEx(kb)
        if ms:
            with contextlib.suppress(Exception):
                _user32.UnhookWindowsHookEx(ms)

    # ── Hook Callbacks ───────────────────────────────────────────────────

    def _keyboard_ll_proc(
        self, nCode: int, wParam: int, lParam: int,
    ) -> int:
        """``WH_KEYBOARD_LL`` callback — capture keys, handle F8/F9 or pass through."""
        try:
            if nCode < 0:
                return int(_user32.CallNextHookEx(
                    self._kb_hook, nCode, wParam, lParam,
                ))

            kbd = ctypes.cast(
                lParam, ctypes.POINTER(KBDLLHOOKSTRUCT),
            ).contents
            raw_vk: int = kbd.vkCode
            # Virtual key code sanitization: must be within valid 1..255 byte boundary
            if raw_vk <= 0 or raw_vk > 0xFF:
                return int(_user32.CallNextHookEx(
                    self._kb_hook, nCode, wParam, lParam,
                ))

            vk: int = raw_vk & 0xFF
            is_injected = bool(kbd.flags & LLKHF_INJECTED_MASK)

            # ── Toggle key (F8) ──
            if vk == self._toggle_vk:
                if not is_injected:
                    if wParam in _KEY_DOWN_MSGS and not self._f8_held:
                        self._f8_held = True
                        new_active = not self._active

                        if new_active:
                            # Center cursor *before* activating capture
                            sm_cx = _user32.GetSystemMetrics(SM_CXSCREEN)
                            sm_cy = _user32.GetSystemMetrics(SM_CYSCREEN)
                            cx = (sm_cx // 2) if sm_cx > 0 else 960
                            cy = (sm_cy // 2) if sm_cy > 0 else 540
                            _user32.SetCursorPos(cx, cy)

                            # Read and validate landed cursor coordinate within bounds
                            landed = wt.POINT()
                            actual_pt = (cx, cy)
                            if _user32.GetCursorPos(ctypes.byref(landed)):
                                vx = _user32.GetSystemMetrics(SM_XVIRTUALSCREEN)
                                vy = _user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
                                vw = _user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
                                vh = _user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
                                if vw <= 0 or vh <= 0:
                                    vx, vy = 0, 0
                                    vw = sm_cx if sm_cx > 0 else 1920
                                    vh = sm_cy if sm_cy > 0 else 1080
                                if vx <= landed.x < vx + vw and vy <= landed.y < vy + vh:
                                    actual_pt = (landed.x, landed.y)

                            with self._lock:
                                self._last_pt = actual_pt
                                self._dx = self._dy = 0
                                self._lbutton = False
                                self._rbutton = False
                                self._mbutton = False
                                self._xbutton1 = False
                                self._xbutton2 = False
                                self._wheel_delta = 0
                                self._keys_down.clear()
                                self._active = True
                        else:
                            with self._lock:
                                self._active = False
                                self._keys_down.clear()
                                self._last_pt = None
                                self._lbutton = False
                                self._rbutton = False
                                self._mbutton = False
                                self._xbutton1 = False
                                self._xbutton2 = False
                                self._dx = self._dy = 0
                                self._wheel_delta = 0

                        if self._on_toggle is not None:
                            with contextlib.suppress(Exception):
                                self._on_toggle(new_active)

                    elif wParam in _KEY_UP_MSGS:
                        self._f8_held = False

                # NEVER swallow the toggle key
                return int(_user32.CallNextHookEx(
                    self._kb_hook, nCode, wParam, lParam,
                ))

            # ── Profile cycle hotkey (F9) ──
            if vk == VK_F9:
                if not is_injected:
                    if wParam in _KEY_DOWN_MSGS and not self._f9_held:
                        self._f9_held = True
                        with self._lock:
                            self._profile_cycle_requested = True
                    elif wParam in _KEY_UP_MSGS:
                        self._f9_held = False

                # When active, swallow F9 so game UI never sees it
                if self._active:
                    return 1
                return int(_user32.CallNextHookEx(
                    self._kb_hook, nCode, wParam, lParam,
                ))

            # ── Additional configured passthrough keys ──
            if vk in self._passthrough_keys:
                return int(_user32.CallNextHookEx(
                    self._kb_hook, nCode, wParam, lParam,
                ))

            # ── Active → record and swallow ──
            if self._active:
                if not is_injected:
                    if wParam in _KEY_DOWN_MSGS:
                        with self._lock:
                            self._keys_down.add(vk)
                    elif wParam in _KEY_UP_MSGS:
                        with self._lock:
                            self._keys_down.discard(vk)
                return 1

        except Exception:
            pass

        return int(_user32.CallNextHookEx(self._kb_hook, nCode, wParam, lParam))

    def _mouse_ll_proc(
        self, nCode: int, wParam: int, lParam: int,
    ) -> int:
        """``WH_MOUSE_LL`` callback — capture mouse or pass through."""
        try:
            if nCode < 0 or not self._active:
                return int(_user32.CallNextHookEx(
                    self._mouse_hook, nCode, wParam, lParam,
                ))

            mouse = ctypes.cast(
                lParam, ctypes.POINTER(MSLLHOOKSTRUCT),
            ).contents

            # Ignore injected synthetic events (e.g. from SetCursorPos or SendInput)
            if mouse.flags & LLMHF_INJECTED_MASK:
                return 1

            msg: int = wParam

            # ── Movement → accumulate dx/dy without overwriting baseline ──
            if msg == WM_MOUSEMOVE:
                x, y = mouse.pt.x, mouse.pt.y
                with self._lock:
                    if self._last_pt is not None:
                        self._dx += x - self._last_pt[0]
                        self._dy += y - self._last_pt[1]
                return 1

            # ── Standard buttons down (including double-clicks) ──
            btn = _BTN_DOWN_MAP.get(msg)
            if btn is not None:
                with self._lock:
                    if btn == "left":
                        self._lbutton = True
                    elif btn == "right":
                        self._rbutton = True
                    else:
                        self._mbutton = True
                return 1

            # ── Standard buttons up ──
            btn = _BTN_UP_MAP.get(msg)
            if btn is not None:
                with self._lock:
                    if btn == "left":
                        self._lbutton = False
                    elif btn == "right":
                        self._rbutton = False
                    else:
                        self._mbutton = False
                return 1

            # ── X buttons down (thumb buttons, including double-clicks) ──
            if msg in (WM_XBUTTONDOWN, WM_XBUTTONDBLCLK):
                xbtn = (mouse.mouseData >> 16) & 0xFFFF
                with self._lock:
                    if xbtn & XBUTTON1:
                        self._xbutton1 = True
                    if xbtn & XBUTTON2:
                        self._xbutton2 = True
                return 1

            # ── X buttons up ──
            if msg == WM_XBUTTONUP:
                xbtn = (mouse.mouseData >> 16) & 0xFFFF
                with self._lock:
                    if xbtn & XBUTTON1:
                        self._xbutton1 = False
                    if xbtn & XBUTTON2:
                        self._xbutton2 = False
                return 1

            # ── Mouse wheel (signed 16-bit delta via bitwise extraction) ──
            if msg in (WM_MOUSEWHEEL, WM_MOUSEHWHEEL):
                raw: int = mouse.mouseData
                hiword: int = (raw >> 16) & 0xFFFF
                delta: int = hiword if hiword < 0x8000 else hiword - 0x10000
                with self._lock:
                    self._wheel_delta += delta
                return 1

            return 1

        except Exception:
            pass

        return int(_user32.CallNextHookEx(
            self._mouse_hook, nCode, wParam, lParam,
        ))

    # ── Console Control Handler ──────────────────────────────────────────

    def _console_ctrl_handler(self, ctrl_type: int) -> int:
        """Handle console close, break, or shutdown events cleanly."""
        self.stop()
        if ctrl_type in (CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT):
            return 1  # TRUE: handled, cleanup complete
        return 0  # FALSE: pass through to Python runtime for CTRL_C / CTRL_BREAK (SIGINT)

    # ── Failsafe Registration ────────────────────────────────────────────

    def _install_failsafes(self) -> None:
        """Register SIGINT/SIGTERM, console ctrl, and excepthook overrides."""
        # Console control handler for Windows CLI / Close Window events
        self._console_ctrl_routine = PHANDLER_ROUTINE(self._console_ctrl_handler)
        if not _kernel32.SetConsoleCtrlHandler(self._console_ctrl_routine, True):
            self._console_ctrl_routine = None

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

        # sys.excepthook and threading.excepthook
        self._orig_excepthook = sys.excepthook
        self._orig_threading_excepthook = threading.excepthook

        def _excepthook(
            etype: type[BaseException],
            val: BaseException,
            tb: TracebackType | None,
        ) -> None:
            self.stop()
            self._orig_excepthook(etype, val, tb)

        def _thread_excepthook(args: threading.ExceptHookArgs) -> None:
            self.stop()
            self._orig_threading_excepthook(args)

        sys.excepthook = _excepthook
        threading.excepthook = _thread_excepthook

    def _restore_failsafes(self) -> None:
        """Restore original console handler, signal handlers, and excepthooks."""
        if self._console_ctrl_routine is not None:
            routine = self._console_ctrl_routine
            self._console_ctrl_routine = None
            with contextlib.suppress(Exception):
                _kernel32.SetConsoleCtrlHandler(routine, False)

        if threading.current_thread() is threading.main_thread():
            try:
                signal.signal(signal.SIGINT, self._orig_sigint)
                signal.signal(signal.SIGTERM, self._orig_sigterm)
            except (OSError, ValueError):
                pass
        with contextlib.suppress(Exception):
            sys.excepthook = self._orig_excepthook
        with contextlib.suppress(Exception):
            threading.excepthook = self._orig_threading_excepthook


# ── Class Alias ──────────────────────────────────────────────────────────

InputHookManager = InputHooks


# ── Self-test ────────────────────────────────────────────────────────────

def main() -> None:
    """Run a 10-second self-test: press F8 to toggle, Ctrl+C to quit."""
    print("InputHooks self-test")
    print("=" * 55)
    print("  Press F8 to toggle capture ON / OFF.")
    print("  Press F9 to test profile cycle flag.")
    print("  While ON every key / mouse event is swallowed.")
    print("  Press Ctrl+C to exit early.")
    print("  Auto-exits after 10 seconds.")
    print("=" * 55, "\n")

    def _on_toggle(now_active: bool) -> None:
        tag = "ON  ✓" if now_active else "OFF ✗"
        print(f"  [F8] Capture toggled → {tag}")

    hooks = InputHooks(on_toggle=_on_toggle)

    try:
        with hooks:
            t0 = time.monotonic()
            while time.monotonic() - t0 < 10.0:
                time.sleep(0.20)
                if hooks.consume_profile_cycle():
                    print("  [F9] Profile cycle consumed!")

                if not hooks.active:
                    continue

                dx, dy = hooks.consume_mouse_delta()
                wheel = hooks.consume_wheel_delta()
                keys = hooks.get_keys_pressed()
                lb, rb, mb, x1, x2 = hooks.get_mouse_buttons()

                parts: list[str] = []
                if dx or dy:
                    parts.append(f"mouse Δ({dx:+d}, {dy:+d})")
                if wheel:
                    parts.append(f"wheel {wheel:+d}")
                if keys:
                    vk_hex = [f"0x{k:02X}" for k in sorted(keys)]
                    parts.append(f"keys [{', '.join(vk_hex)}]")
                btns = (
                    ("L" if lb else "")
                    + ("R" if rb else "")
                    + ("M" if mb else "")
                    + ("X1" if x1 else "")
                    + ("X2" if x2 else "")
                )
                if btns:
                    parts.append(f"btn [{btns}]")
                if parts:
                    print(f"    {' │ '.join(parts)}")

    except KeyboardInterrupt:
        print("\n  [Ctrl+C] Interrupted — cleaning up.")

    print("\nSelf-test finished. All hooks released.")


if __name__ == "__main__":
    main()
