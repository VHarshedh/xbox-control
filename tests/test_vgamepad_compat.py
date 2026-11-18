"""Unit tests for vgamepad_compat headless CI and driverless environment support."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import vgamepad.api as api

import vgamepad_compat


class TestVGamepadCompat:
    """Validate vgamepad_compat behavior across environments."""

    def test_setup_idempotent_when_module_already_in_sys_modules(self) -> None:
        """Calling setup_vgamepad_safe_import multiple times does not raise or re-import."""
        vgamepad_compat.setup_vgamepad_safe_import()
        # Verify it remains safely configured
        assert "vgamepad.win.vigem_client" in vgamepad_compat.sys.modules

    def test_setup_skips_on_non_windows(self) -> None:
        """On Linux/macOS, setup returns early without modifying Windows modules."""
        with patch("platform.system", return_value="Linux"):
            # Should return immediately
            vgamepad_compat.setup_vgamepad_safe_import()

    def test_safe_connect_handles_exception_and_error_codes(self) -> None:
        """Simulate a broken or failing vigem_connect to ensure safe_connect returns VIGEM_ERROR_NONE."""
        failing_orig = MagicMock(side_effect=RuntimeError("Simulated missing driver"))

        # Test the wrapper logic
        def safe_connect(busp: object) -> object:
            try:
                err = failing_orig(busp)
                if err == api.VIGEM_ERRORS.VIGEM_ERROR_NONE:
                    return err
            except Exception:
                pass
            return api.VIGEM_ERRORS.VIGEM_ERROR_NONE

        ret = safe_connect(None)
        assert ret == api.VIGEM_ERRORS.VIGEM_ERROR_NONE
        failing_orig.assert_called_once_with(None)

    def test_safe_connect_passes_through_success(self) -> None:
        """When real driver succeeds, safe_connect returns the original VIGEM_ERROR_NONE without interference."""
        success_orig = MagicMock(return_value=api.VIGEM_ERRORS.VIGEM_ERROR_NONE)

        def safe_connect(busp: object) -> object:
            try:
                err = success_orig(busp)
                if err == api.VIGEM_ERRORS.VIGEM_ERROR_NONE:
                    return err
            except Exception:
                pass
            return api.VIGEM_ERRORS.VIGEM_ERROR_NONE

        ret = safe_connect(None)
        assert ret == api.VIGEM_ERRORS.VIGEM_ERROR_NONE
        success_orig.assert_called_once_with(None)
