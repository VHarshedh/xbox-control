"""ViGEmBus driver verification script.

Checks Python version, OS, ViGEmBus kernel driver status, and validates
virtual Xbox 360 controller creation via the vgamepad library.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.wintypes as wt
import platform
import subprocess
import sys
from enum import IntEnum
from pathlib import Path


class Status(IntEnum):
    """Exit codes for the verification script."""
    PASS = 0
    FAIL = 1


def check_python_version(min_major: int = 3, min_minor: int = 12) -> tuple[bool, str]:
    """Verify the running Python interpreter meets the minimum version."""
    major, minor = sys.version_info.major, sys.version_info.minor
    current = f"{major}.{minor}.{sys.version_info.micro}"
    required = f"{min_major}.{min_minor}"

    if major > min_major or (major == min_major and minor >= min_minor):
        return True, f"Python {current} >= {required}"
    return False, (
        f"Python {current} < {required}. "
        f"Install Python {required}+ from https://www.python.org/downloads/"
    )


def check_windows_os() -> tuple[bool, str]:
    """Verify the script is running on Windows."""
    os_name = platform.system()
    if os_name == "Windows":
        return True, f"OS: Windows {platform.version()}"
    return False, f"Unsupported OS '{os_name}'. This script requires Windows."


def _get_system_directory() -> Path:
    """Resolve the true 64-bit Windows System32 directory via kernel32 API (CWE-426)."""
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        buf = ctypes.create_unicode_buffer(260)
        kernel32.GetSystemDirectoryW.argtypes = [wt.LPWSTR, wt.UINT]
        kernel32.GetSystemDirectoryW.restype = wt.UINT
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


def _load_advapi32() -> ctypes.WinDLL:
    """Load advapi32.dll strictly from System32 using LOAD_LIBRARY_SEARCH_SYSTEM32 (CWE-426/427)."""
    # LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
    try:
        return ctypes.WinDLL("advapi32.dll", winmode=0x00000800)
    except TypeError:
        sys_dir = _get_system_directory()
        return ctypes.WinDLL(str(sys_dir / "advapi32.dll"))
    except Exception as exc:
        sys_dir = _get_system_directory()
        dll_path = sys_dir / "advapi32.dll"
        if not dll_path.is_file():
            raise FileNotFoundError(f"advapi32.dll not found at secure path: {dll_path}") from exc
        return ctypes.WinDLL(str(dll_path), winmode=0x00000800)


def check_vigembus_service() -> tuple[bool, str]:
    """Query the ViGEmBus Windows service status.

    Checks the Service Control Manager via Win32 advapi32 ctypes first
    (locale-independent, avoids 64-bit pointer truncation). Falls back
    to `sc query ViGEmBus` if ctypes SCM query fails. Guarantees that
    SCM and Service handles are closed under all exceptions and return paths.
    """
    scm = None
    svc = None
    advapi32 = None

    # --- Attempt 1: Win32 Service Control Manager via ctypes (Primary) ---
    try:
        advapi32 = _load_advapi32()

        SC_MANAGER_CONNECT: int = 0x0001
        SERVICE_QUERY_STATUS: int = 0x0004
        SERVICE_RUNNING: int = 0x0004

        class SERVICE_STATUS(ctypes.Structure):
            """Win32 SERVICE_STATUS structure."""
            _fields_ = [
                ("dwServiceType", ctypes.c_ulong),
                ("dwCurrentState", ctypes.c_ulong),
                ("dwControlsAccepted", ctypes.c_ulong),
                ("dwWin32ExitCode", ctypes.c_ulong),
                ("dwServiceSpecificExitCode", ctypes.c_ulong),
                ("dwCheckPoint", ctypes.c_ulong),
                ("dwWaitHint", ctypes.c_ulong),
            ]

        # Explicit prototypes to prevent 64-bit pointer truncation
        advapi32.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
        advapi32.OpenSCManagerW.restype = ctypes.c_void_p

        advapi32.OpenServiceW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, wt.DWORD]
        advapi32.OpenServiceW.restype = ctypes.c_void_p

        advapi32.QueryServiceStatus.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(SERVICE_STATUS),
        ]
        advapi32.QueryServiceStatus.restype = wt.BOOL

        advapi32.CloseServiceHandle.argtypes = [ctypes.c_void_p]
        advapi32.CloseServiceHandle.restype = wt.BOOL

        scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if scm:
            svc = advapi32.OpenServiceW(scm, "ViGEmBus", SERVICE_QUERY_STATUS)
            if svc:
                status = SERVICE_STATUS()
                ok = advapi32.QueryServiceStatus(svc, ctypes.byref(status))
                if ok and status.dwCurrentState == SERVICE_RUNNING:
                    return True, "ViGEmBus service is installed and RUNNING."
                if ok:
                    return False, (
                        "ViGEmBus service is installed but NOT running.\n"
                        "  → Try: sc start ViGEmBus  (as Administrator)\n"
                        "  → Or reboot after installing ViGEmBus v1.17.333+."
                    )
            else:
                err = ctypes.GetLastError()
                # ERROR_SERVICE_DOES_NOT_EXIST = 1060
                if err == 1060:
                    return False, _vigembus_install_message()
    except Exception:
        pass  # Fall through to `sc query` fallback
    finally:
        if advapi32 is not None:
            if svc:
                with contextlib.suppress(Exception):
                    advapi32.CloseServiceHandle(svc)
            if scm:
                with contextlib.suppress(Exception):
                    advapi32.CloseServiceHandle(scm)

    # --- Attempt 2: `sc.exe query` (Fallback - Hardened against CWE-426/427) ---
    try:
        sc_path = _get_system_directory() / "sc.exe"
        if not sc_path.is_file():
            return False, _vigembus_install_message()

        result = subprocess.run(
            [str(sc_path), "query", "ViGEmBus"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr

        if result.returncode == 0 and "RUNNING" in output.upper():
            return True, "ViGEmBus service is installed and RUNNING (sc query fallback)."

        if result.returncode == 0:
            return False, (
                "ViGEmBus service is installed but NOT running.\n"
                "  → Try: sc start ViGEmBus  (as Administrator)\n"
                "  → Or reboot after installing ViGEmBus v1.17.333+."
            )

        return False, _vigembus_install_message()

    except Exception as exc:
        return False, f"Could not query ViGEmBus service: {exc}"


def check_vgamepad_controller() -> tuple[bool, str]:
    """Attempt to create, reset, and release a virtual Xbox 360 controller."""
    try:
        import vgamepad  # noqa: WPS433 — late import is intentional
    except ImportError:
        return False, (
            "The 'vgamepad' package is not installed.\n"
            "  → pip install vgamepad"
        )

    gamepad: vgamepad.VX360Gamepad | None = None
    try:
        gamepad = vgamepad.VX360Gamepad()
        gamepad.reset()
        gamepad.update()
        return True, "Virtual Xbox 360 controller created, reset, and updated OK."
    except Exception as exc:
        return False, (
            f"Failed to instantiate VX360Gamepad: {exc}\n"
            "  → Ensure ViGEmBus v1.17.333+ is installed and the service is running.\n"
            "  → Download: https://github.com/nefarius/ViGEmBus/releases\n"
            "  → After installing, reboot your PC."
        )
    finally:
        if gamepad is not None:
            with contextlib.suppress(Exception):
                del gamepad  # releases the virtual controller


# ── Helpers ──────────────────────────────────────────────────────────────

def _vigembus_install_message() -> str:
    """Standard remediation text when ViGEmBus is not found."""
    return (
        "ViGEmBus driver/service is NOT installed.\n"
        "  → Download ViGEmBus v1.17.333+ from:\n"
        "    https://github.com/nefarius/ViGEmBus/releases\n"
        "  → Run the installer as Administrator, then reboot."
    )


# ── CLI entry point ─────────────────────────────────────────────────────

def main() -> int:
    """Run all checks and print a PASS/FAIL report."""
    checks: list[tuple[str, tuple[bool, str]]] = [
        ("Python version", check_python_version()),
        ("Windows OS",     check_windows_os()),
        ("ViGEmBus service", check_vigembus_service()),
        ("vgamepad controller", check_vgamepad_controller()),
    ]

    all_ok = True
    print("=" * 60)
    print("  ViGEmBus Driver Verification Report")
    print("=" * 60)

    for label, (ok, detail) in checks:
        icon = "✔" if ok else "✘"
        print(f"\n [{icon}] {label}")
        for line in detail.splitlines():
            print(f"     {line}")
        if not ok:
            all_ok = False

    print("\n" + "=" * 60)
    if all_ok:
        print("  Result: PASS — all checks succeeded.")
    else:
        print("  Result: FAIL — see diagnostics above.")
    print("=" * 60)

    return Status.PASS if all_ok else Status.FAIL


if __name__ == "__main__":
    sys.exit(main())
