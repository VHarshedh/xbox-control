"""ViGEmBus driver verification and service management script.

Checks Python version, architecture (64-bit), OS, ViGEmBus kernel driver status,
UAC elevation, headless CI environments, and validates virtual Xbox 360
controller creation via the vgamepad library. Supports service start/restart.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import ctypes.wintypes as wt
import logging
import os
import platform
import subprocess
import sys
import time
from enum import IntEnum
from pathlib import Path

logger = logging.getLogger("driver_check")


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


def check_architecture() -> tuple[bool, str]:
    """Verify running on 64-bit Python required by ViGEmBus and vgamepad."""
    is_64bit = sys.maxsize > 2**32
    if is_64bit:
        return True, "Python 64-bit architecture confirmed."
    return False, (
        "32-bit Python detected. ViGEmBus driver and vgamepad require a 64-bit Python interpreter.\n"
        "  → Install 64-bit Python from https://www.python.org/downloads/windows/"
    )


def check_windows_os() -> tuple[bool, str]:
    """Verify the script is running on Windows."""
    os_name = platform.system()
    if os_name == "Windows":
        return True, f"OS: Windows {platform.version()}"
    return False, f"Unsupported OS '{os_name}'. This script requires Windows."


def is_admin() -> bool:
    """Check if current process has elevated Administrator privileges (UAC elevated)."""
    try:
        shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_headless_ci() -> bool:
    """Detect if running in a headless CI / automated test environment."""
    return (
        os.environ.get("CI", "").strip().lower() in ("1", "true", "yes")
        or os.environ.get("GITHUB_ACTIONS", "").strip().lower() in ("1", "true")
        or os.environ.get("VGAMEPAD_SKIP_VIGEMBUS_INSTALL", "").strip().lower() in ("1", "true")
    )


def elevate_and_run(extra_args: list[str] | None = None) -> bool:
    """Relaunch the current script with elevated Administrator privileges via UAC."""
    if is_admin():
        return True
    try:
        shell32 = ctypes.windll.shell32  # type: ignore[attr-defined]
        shell32.ShellExecuteW.argtypes = [
            wt.HWND,
            wt.LPCWSTR,
            wt.LPCWSTR,
            wt.LPCWSTR,
            wt.LPCWSTR,
            ctypes.c_int,
        ]
        shell32.ShellExecuteW.restype = ctypes.c_void_p
        args_list = [sys.executable, str(Path(__file__).resolve())]
        if extra_args:
            args_list.extend(extra_args)
        params = subprocess.list2cmdline(args_list[1:])
        cur_dir = str(Path(__file__).parent.resolve())
        # SW_SHOWNORMAL = 1
        ret = shell32.ShellExecuteW(None, "runas", sys.executable, params, cur_dir, 1)
        # ShellExecute returns > 32 on success (casted through pointer size on 64-bit)
        ret_val = int(ret or 0)
        return ret_val > 32
    except Exception as exc:
        logger.error("Failed to request UAC elevation: %s", exc)
        return False


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
        return ctypes.WinDLL("advapi32.dll", winmode=0x00000800, use_last_error=True)
    except TypeError:
        sys_dir = _get_system_directory()
        return ctypes.WinDLL(str(sys_dir / "advapi32.dll"), use_last_error=True)
    except Exception as exc:
        sys_dir = _get_system_directory()
        dll_path = sys_dir / "advapi32.dll"
        if not dll_path.is_file():
            raise FileNotFoundError(f"advapi32.dll not found at secure path: {dll_path}") from exc
        return ctypes.WinDLL(str(dll_path), winmode=0x00000800, use_last_error=True)


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


# Win32 Service Constants
SC_MANAGER_CONNECT: int = 0x0001
SC_MANAGER_ALL_ACCESS: int = 0xF003F
SERVICE_QUERY_STATUS: int = 0x0004
SERVICE_START: int = 0x0010
SERVICE_STOP: int = 0x0020
SERVICE_CONTROL_STOP: int = 0x00000001
SERVICE_STOPPED: int = 0x00000001
SERVICE_START_PENDING: int = 0x00000002
SERVICE_STOP_PENDING: int = 0x00000003
SERVICE_RUNNING: int = 0x00000004


def _configure_advapi32_prototypes(advapi32: ctypes.WinDLL) -> None:
    """Set explicit 64-bit prototypes on advapi32 functions to prevent pointer truncation."""
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

    if hasattr(advapi32, "StartServiceW"):
        advapi32.StartServiceW.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.c_void_p]
        advapi32.StartServiceW.restype = wt.BOOL

    if hasattr(advapi32, "ControlService"):
        advapi32.ControlService.argtypes = [
            ctypes.c_void_p,
            wt.DWORD,
            ctypes.POINTER(SERVICE_STATUS),
        ]
        advapi32.ControlService.restype = wt.BOOL


def check_vigembus_service(ci_mode: bool = False) -> tuple[bool, str]:
    """Query the ViGEmBus Windows service status.

    Checks the Service Control Manager via Win32 advapi32 ctypes first
    (locale-independent, avoids 64-bit pointer truncation). Falls back
    to `sc query ViGEmBus` if ctypes SCM query fails. Guarantees that
    SCM and Service handles are closed under all exceptions and return paths.
    """
    if ci_mode or is_headless_ci():
        # First check if the real driver happens to be installed
        real_ok, real_detail = _check_vigembus_service_internal()
        if real_ok:
            return True, real_detail
        return True, "ViGEmBus service check skipped (headless CI / test environment detected)."

    return _check_vigembus_service_internal()


def _check_vigembus_service_internal() -> tuple[bool, str]:
    """Internal implementation of ViGEmBus service check."""
    scm = None
    svc = None
    advapi32 = None

    # --- Attempt 1: Win32 Service Control Manager via ctypes (Primary) ---
    try:
        advapi32 = _load_advapi32()
        _configure_advapi32_prototypes(advapi32)

        scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if scm:
            svc = advapi32.OpenServiceW(scm, "ViGEmBus", SERVICE_QUERY_STATUS)
            if svc:
                status = SERVICE_STATUS()
                ok = advapi32.QueryServiceStatus(svc, ctypes.byref(status))
                # Poll briefly if in START_PENDING state
                if ok and status.dwCurrentState == SERVICE_START_PENDING:
                    for _ in range(6):
                        time.sleep(0.5)
                        ok = advapi32.QueryServiceStatus(svc, ctypes.byref(status))
                        if not ok or status.dwCurrentState != SERVICE_START_PENDING:
                            break

                if ok and status.dwCurrentState == SERVICE_RUNNING:
                    return True, "ViGEmBus service is installed and RUNNING."
                if ok:
                    return False, (
                        "ViGEmBus service is installed but NOT running.\n"
                        "  → Try: python driver_check.py --start-service  (or sc start ViGEmBus as Administrator)\n"
                        "  → Or reboot after installing ViGEmBus v1.17.333+."
                    )
            else:
                err = ctypes.get_last_error()
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
                "  → Try: python driver_check.py --start-service  (or sc start ViGEmBus as Administrator)\n"
                "  → Or reboot after installing ViGEmBus v1.17.333+."
            )

        return False, _vigembus_install_message()

    except Exception as exc:
        return False, f"Could not query ViGEmBus service: {exc}"


def start_vigembus_service(timeout: float = 10.0) -> tuple[bool, str]:
    """Start the ViGEmBus service (requires Administrator / UAC elevation)."""
    running, _ = check_vigembus_service(ci_mode=False)
    if running:
        return True, "ViGEmBus service is already running."

    if not is_admin():
        return False, (
            "Administrator privileges required (UAC elevation needed).\n"
            "  → Re-run in an elevated Administrator terminal, or use: python driver_check.py --start-service --elevate"
        )

    # Attempt 1: advapi32
    advapi32 = None
    scm = None
    svc = None
    try:
        advapi32 = _load_advapi32()
        _configure_advapi32_prototypes(advapi32)
        scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if scm:
            svc = advapi32.OpenServiceW(scm, "ViGEmBus", SERVICE_START | SERVICE_QUERY_STATUS)
            if svc:
                ok = advapi32.StartServiceW(svc, 0, None)
                if ok or ctypes.get_last_error() == 1056:  # ERROR_SERVICE_ALREADY_RUNNING
                    status = SERVICE_STATUS()
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        if (
                            advapi32.QueryServiceStatus(svc, ctypes.byref(status))
                            and status.dwCurrentState == SERVICE_RUNNING
                        ):
                            return True, "ViGEmBus service started successfully."
                        time.sleep(0.5)
    except Exception as exc:
        logger.debug("advapi32 StartService failed: %s", exc)
    finally:
        if advapi32 is not None:
            if svc:
                with contextlib.suppress(Exception):
                    advapi32.CloseServiceHandle(svc)
            if scm:
                with contextlib.suppress(Exception):
                    advapi32.CloseServiceHandle(scm)

    # Attempt 2: sc.exe start ViGEmBus
    try:
        sc_path = _get_system_directory() / "sc.exe"
        if sc_path.is_file():
            res = subprocess.run(
                [str(sc_path), "start", "ViGEmBus"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if res.returncode == 0 or "ALREADY_RUNNING" in res.stdout.upper():
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    running, _ = check_vigembus_service(ci_mode=False)
                    if running:
                        return True, "ViGEmBus service started successfully (sc.exe)."
                    time.sleep(0.5)
            return False, f"sc start ViGEmBus failed: {res.stdout.strip()} {res.stderr.strip()}"
    except Exception as exc:
        return False, f"Failed to start service via sc.exe: {exc}"

    return False, "Failed to start ViGEmBus service. Please verify the driver is installed."


def stop_vigembus_service(timeout: float = 10.0) -> tuple[bool, str]:
    """Stop the ViGEmBus service (requires Administrator / UAC elevation)."""
    if not is_admin():
        return False, (
            "Administrator privileges required (UAC elevation needed).\n"
            "  → Re-run in an elevated Administrator terminal, or use: python driver_check.py --start-service --elevate"
        )

    # Attempt 1: advapi32
    advapi32 = None
    scm = None
    svc = None
    try:
        advapi32 = _load_advapi32()
        _configure_advapi32_prototypes(advapi32)
        scm = advapi32.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
        if scm:
            svc = advapi32.OpenServiceW(scm, "ViGEmBus", SERVICE_STOP | SERVICE_QUERY_STATUS)
            if svc:
                status = SERVICE_STATUS()
                if advapi32.QueryServiceStatus(svc, ctypes.byref(status)):
                    if status.dwCurrentState == SERVICE_STOPPED:
                        return True, "ViGEmBus service is already stopped."
                    if status.dwCurrentState == SERVICE_STOP_PENDING:
                        deadline = time.monotonic() + timeout
                        while time.monotonic() < deadline:
                            time.sleep(0.5)
                            if (
                                advapi32.QueryServiceStatus(svc, ctypes.byref(status))
                                and status.dwCurrentState == SERVICE_STOPPED
                            ):
                                return True, "ViGEmBus service stopped successfully."
                        return False, "ViGEmBus service stop timed out while pending."

                ok = advapi32.ControlService(svc, SERVICE_CONTROL_STOP, ctypes.byref(status))
                if ok or ctypes.get_last_error() == 1062:  # ERROR_SERVICE_NOT_ACTIVE
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        if (
                            advapi32.QueryServiceStatus(svc, ctypes.byref(status))
                            and status.dwCurrentState == SERVICE_STOPPED
                        ):
                            return True, "ViGEmBus service stopped successfully."
                        time.sleep(0.5)
    except Exception as exc:
        logger.debug("advapi32 ControlService failed: %s", exc)
    finally:
        if advapi32 is not None:
            if svc:
                with contextlib.suppress(Exception):
                    advapi32.CloseServiceHandle(svc)
            if scm:
                with contextlib.suppress(Exception):
                    advapi32.CloseServiceHandle(scm)

    # Attempt 2: sc.exe stop ViGEmBus
    try:
        sc_path = _get_system_directory() / "sc.exe"
        if sc_path.is_file():
            res = subprocess.run(
                [str(sc_path), "stop", "ViGEmBus"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if res.returncode == 0 or "NOT_ACTIVE" in res.stdout.upper():
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    running, _ = check_vigembus_service(ci_mode=False)
                    if not running:
                        return True, "ViGEmBus service stopped successfully (sc.exe)."
                    time.sleep(0.5)
            elif "ALREADY STOPPED" in (res.stdout + res.stderr).upper():
                return True, "ViGEmBus service is already stopped."
            return False, f"sc stop ViGEmBus failed: {res.stdout.strip()} {res.stderr.strip()}"
    except Exception as exc:
        return False, f"Failed to stop service via sc.exe: {exc}"

    return False, "Failed to stop ViGEmBus service."


def restart_vigembus_service(timeout: float = 15.0) -> tuple[bool, str]:
    """Restart the ViGEmBus service."""
    stop_ok, stop_msg = stop_vigembus_service(timeout=timeout / 2)
    if not stop_ok and "already stopped" not in stop_msg:
        return False, f"Restart failed during service stop phase: {stop_msg}"
    time.sleep(1.0)
    return start_vigembus_service(timeout=timeout / 2)


def check_vgamepad_controller(ci_mode: bool = False) -> tuple[bool, str]:
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
        if ci_mode or is_headless_ci():
            return True, "vgamepad VX360Gamepad allocation skipped (headless CI environment detected)."
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

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command line arguments for driver_check."""
    parser = argparse.ArgumentParser(
        description="ViGEmBus driver verification and service management tool."
    )
    parser.add_argument(
        "--ci",
        action="store_true",
        help="Run in headless CI mode (skips physical driver checks if absent)",
    )
    parser.add_argument(
        "--check-admin",
        action="store_true",
        help="Check whether running with Administrator (UAC elevated) privileges",
    )
    parser.add_argument(
        "--start-service",
        action="store_true",
        help="Start the ViGEmBus service (requires Administrator privileges)",
    )
    parser.add_argument(
        "--stop-service",
        action="store_true",
        help="Stop the ViGEmBus service (requires Administrator privileges)",
    )
    parser.add_argument(
        "--restart-service",
        action="store_true",
        help="Restart the ViGEmBus service (requires Administrator privileges)",
    )
    parser.add_argument(
        "--elevate",
        action="store_true",
        help="Re-launch this script with Administrator (UAC elevated) privileges",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run all checks and print a PASS/FAIL report or execute service operations."""
    args = parse_args(argv)

    if args.check_admin:
        admin = is_admin()
        tag = "YES (Administrator)" if admin else "NO (Standard User)"
        print(f"Running as Administrator: {tag}")
        return Status.PASS if admin else Status.FAIL

    if args.elevate:
        service_args: list[str] = []
        if args.start_service:
            service_args.append("--start-service")
        elif args.stop_service:
            service_args.append("--stop-service")
        elif args.restart_service:
            service_args.append("--restart-service")

        if is_admin():
            if not service_args:
                print("Already running with Administrator privileges.")
                return Status.PASS
            # If already admin and service action requested, fall through to execute it directly!
        else:
            print("Requesting UAC elevation...")
            ok = elevate_and_run(extra_args=service_args)
            if ok:
                print("UAC elevation prompt initiated successfully.")
                return Status.PASS
            print("Failed to elevate privileges.", file=sys.stderr)
            return Status.FAIL

    if args.start_service:
        print("Starting ViGEmBus service...")
        ok, msg = start_vigembus_service()
        print(msg)
        return Status.PASS if ok else Status.FAIL

    if args.stop_service:
        print("Stopping ViGEmBus service...")
        ok, msg = stop_vigembus_service()
        print(msg)
        return Status.PASS if ok else Status.FAIL

    if args.restart_service:
        print("Restarting ViGEmBus service...")
        ok, msg = restart_vigembus_service()
        print(msg)
        return Status.PASS if ok else Status.FAIL

    ci_mode = args.ci or is_headless_ci()

    checks: list[tuple[str, tuple[bool, str]]] = [
        ("Python version", check_python_version()),
        ("Architecture", check_architecture()),
        ("Windows OS", check_windows_os()),
        ("ViGEmBus service", check_vigembus_service(ci_mode=ci_mode)),
        ("vgamepad controller", check_vgamepad_controller(ci_mode=ci_mode)),
    ]

    all_ok = True
    print("=" * 60)
    print("  ViGEmBus Driver Verification Report" + (" (CI Mode)" if ci_mode else ""))
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
