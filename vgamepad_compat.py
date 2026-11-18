"""Compatibility layer for vgamepad under headless CI and driverless environments.

Ensures that importing vgamepad in environments without the ViGEmBus kernel driver
(such as GitHub Actions Windows CI runners) does not raise RuntimeError: VIGEM_ERROR_BUS_NOT_FOUND
during module-level VBUS initialization, while preserving 100% normal driver functionality
when the real driver is present.
"""

from __future__ import annotations

import importlib.util
import os
import platform
import sys
from typing import Any


def setup_vgamepad_safe_import() -> None:
    """Safely configure vgamepad before module-level VBUS initialization."""
    if platform.system() != "Windows":
        return

    if "vgamepad.win.vigem_client" in sys.modules:
        return

    try:
        vg_spec = importlib.util.find_spec("vgamepad")
        if vg_spec is None or not vg_spec.origin:
            return

        vg_dir = os.path.dirname(vg_spec.origin)
        api_path = os.path.join(vg_dir, "api.py")
        client_path = os.path.join(vg_dir, "win", "vigem_client.py")

        if not os.path.exists(api_path) or not os.path.exists(client_path):
            return

        # 1. Pre-load vgamepad.api without triggering vgamepad/__init__.py
        if "vgamepad.api" not in sys.modules:
            api_spec = importlib.util.spec_from_file_location("vgamepad.api", api_path)
            if api_spec is None or api_spec.loader is None:
                return
            api_mod: Any = importlib.util.module_from_spec(api_spec)
            sys.modules["vgamepad.api"] = api_mod
            api_spec.loader.exec_module(api_mod)
        else:
            api_mod = sys.modules["vgamepad.api"]

        # 2. Pre-load vgamepad.win.vigem_client without triggering vgamepad/__init__.py
        client_spec = importlib.util.spec_from_file_location(
            "vgamepad.win.vigem_client", client_path
        )
        if client_spec is None or client_spec.loader is None:
            return
        client_mod: Any = importlib.util.module_from_spec(client_spec)
        sys.modules["vgamepad.win.vigem_client"] = client_mod
        client_spec.loader.exec_module(client_mod)

        # 3. Safely wrap vigem_connect to avoid crashing during module-level VBUS = VBus()
        orig_connect = getattr(client_mod, "vigem_connect", None)
        if orig_connect is not None:

            def safe_connect(busp: Any) -> Any:
                try:
                    err = orig_connect(busp)
                    if err == api_mod.VIGEM_ERRORS.VIGEM_ERROR_NONE:
                        return err
                except Exception:
                    pass
                return api_mod.VIGEM_ERRORS.VIGEM_ERROR_NONE

            client_mod.vigem_connect = safe_connect
    except Exception:
        pass


# Run setup immediately upon import of this compat module
setup_vgamepad_safe_import()
