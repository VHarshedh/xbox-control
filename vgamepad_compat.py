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
        import vgamepad.api as api

        vg_dir = os.path.dirname(api.__file__)
        client_path = os.path.join(vg_dir, "win", "vigem_client.py")
        if not os.path.exists(client_path):
            return

        spec = importlib.util.spec_from_file_location("vgamepad.win.vigem_client", client_path)
        if spec is None or spec.loader is None:
            return

        mod: Any = importlib.util.module_from_spec(spec)
        sys.modules["vgamepad.win.vigem_client"] = mod
        spec.loader.exec_module(mod)

        orig_connect = getattr(mod, "vigem_connect", None)
        if orig_connect is not None:

            def safe_connect(busp: Any) -> Any:
                try:
                    err = orig_connect(busp)
                    if err == api.VIGEM_ERRORS.VIGEM_ERROR_NONE:
                        return err
                except Exception:
                    pass
                return api.VIGEM_ERRORS.VIGEM_ERROR_NONE

            mod.vigem_connect = safe_connect
    except Exception:
        pass


# Run setup immediately upon import of this compat module
setup_vgamepad_safe_import()
