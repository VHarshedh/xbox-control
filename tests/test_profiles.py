"""Unit tests for profiles module (validation, security, and parsing).

Compatible with both pytest and python -m unittest.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from profiles import ProfileManager, parse_target, parse_vk


class TestVKParsing:
    """Validate virtual key string and integer resolution."""

    def test_parse_vk_integers(self) -> None:
        assert parse_vk(87) == 87
        assert parse_vk(0x20) == 0x20

    def test_parse_vk_names(self) -> None:
        assert parse_vk("VK_SPACE") == 0x20
        assert parse_vk("VK_W") == ord("W")
        assert parse_vk("W") == ord("W")
        assert parse_vk("VK_ESCAPE") == 0x1B
        assert parse_vk("VK_F8") == 0x77
        assert parse_vk("VK_F9") == 0x78

    def test_parse_vk_mouse_tokens(self) -> None:
        assert parse_vk("MOUSE_LEFT") == 0x01
        assert parse_vk("MOUSE_RIGHT") == 0x02
        assert parse_vk("MOUSE_X1") == 0x05
        assert parse_vk("MOUSE_X2") == 0x06

    def test_parse_vk_invalid(self) -> None:
        with pytest.raises(ValueError, match="Unknown virtual-key name"):
            parse_vk("UNKNOWN_KEY_NAME_XYZ")

        with pytest.raises(ValueError, match="VK code out of byte range"):
            parse_vk(300)

    def test_parse_vk_booleans_rejected(self) -> None:
        with pytest.raises(ValueError, match="Boolean values cannot be used"):
            parse_vk(True)

        with pytest.raises(ValueError, match="Boolean values cannot be used"):
            parse_vk(False)

    def test_parse_vk_string_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="VK code out of byte range"):
            parse_vk("999")

        with pytest.raises(ValueError, match="VK code out of byte range"):
            parse_vk("0x1FF")

        with pytest.raises(ValueError, match="VK code out of byte range"):
            parse_vk("0xFFFF")


class TestTargetParsing:
    """Validate XInput buttons and triggers resolution."""

    def test_triggers(self) -> None:
        assert parse_target("LT") == "LT"
        assert parse_target("RT") == "RT"
        assert parse_target("left_trigger") == "LT"
        assert parse_target("right_trigger") == "RT"

    def test_buttons(self) -> None:
        assert parse_target("XUSB_GAMEPAD_A") is not None
        assert parse_target("A") is not None
        assert parse_target("B") is not None
        assert parse_target("X") is not None
        assert parse_target("Y") is not None

    def test_invalid_target(self) -> None:
        with pytest.raises(ValueError, match="Unknown controller target button"):
            parse_target("INVALID_BUTTON")


class TestProfileSecurityAndValidation:
    """Validate enterprise security constraints and schema validation."""

    def test_symlink_rejection(self, tmp_path: Path) -> None:
        dummy_file = tmp_path / "target.json"
        dummy_file.write_text('{"name": "test"}', encoding="utf-8")

        symlink_file = tmp_path / "link.json"
        try:
            symlink_file.symlink_to(dummy_file)
        except OSError:
            # On Windows without SeCreateSymbolicLinkPrivilege, mock is_symlink
            with patch.object(Path, "is_symlink", return_value=True), pytest.raises(
                ValueError, match="Symlinks are rejected for security"
            ):
                ProfileManager.load_profile(dummy_file)
            return

        with pytest.raises(ValueError, match="Symlinks are rejected for security"):
            ProfileManager.load_profile(symlink_file)

    def test_file_size_limit_rejection(self, tmp_path: Path) -> None:
        oversized = tmp_path / "large.json"
        # Write > 64 KB file
        oversized.write_text(" " * 70000, encoding="utf-8")

        with pytest.raises(ValueError, match="exceeds maximum permitted size of 64 KB"):
            ProfileManager.load_profile(oversized)

    def test_invert_y_string_type_rejection(self, tmp_path: Path) -> None:
        bad_profile = tmp_path / "bad_invert_y.json"
        data = {
            "name": "Bad Invert",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
                "invert_y": "false",  # Must be rejected because bool("false") is True
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {},
        }
        bad_profile.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(ValueError, match="'invert_y' must be a boolean"):
            ProfileManager.load_profile(bad_profile)

    def test_numeric_boundary_validation(self, tmp_path: Path) -> None:
        profile = tmp_path / "bad_deadzone.json"
        data = {
            "name": "Bad DZ",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.50,  # > 0.35 limit
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {},
        }
        profile.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(ValueError, match="deadzone_comp must be in"):
            ProfileManager.load_profile(profile)

    def test_nan_rejection(self, tmp_path: Path) -> None:
        nan_file = tmp_path / "nan_profile.json"
        nan_file.write_text(
            '{"name": "NaN Profile", "stick_config": {"sensitivity": NaN, "curve_exponent": 1.0, "deadzone_comp": 0.1, "decay_rate": 0.8, "smoothing_alpha": 0.5}, "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68}, "buttons": {}}',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Non-finite JSON constant"):
            ProfileManager.load_profile(nan_file)

    def test_infinity_rejection(self, tmp_path: Path) -> None:
        inf_file = tmp_path / "inf_profile.json"
        inf_file.write_text(
            '{"name": "Inf Profile", "stick_config": {"sensitivity": Infinity, "curve_exponent": 1.0, "deadzone_comp": 0.1, "decay_rate": 0.8, "smoothing_alpha": 0.5}, "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68}, "buttons": {}}',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Non-finite JSON constant"):
            ProfileManager.load_profile(inf_file)

    def test_path_containment_violation(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "allowed_dir"
        base_dir.mkdir()

        outside_dir = tmp_path / "outside_dir"
        outside_dir.mkdir()

        outside_file = outside_dir / "external.json"
        data = {
            "name": "Outside Profile",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {},
        }
        outside_file.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(ValueError, match="Path containment violation"):
            ProfileManager.load_profile(outside_file, base_dir=base_dir)

    def test_non_string_button_target_rejection(self, tmp_path: Path) -> None:
        bad_btn = tmp_path / "bad_button.json"
        data = {
            "name": "Bad Button",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {"VK_SPACE": 123},  # Non-string target must be rejected
        }
        bad_btn.write_text(json.dumps(data), encoding="utf-8")

        with pytest.raises(ValueError, match="Button mapping target must be a string"):
            ProfileManager.load_profile(bad_btn)

    def test_reparse_point_rejection(self, tmp_path: Path) -> None:
        dummy = tmp_path / "normal.json"
        data = {
            "name": "Normal",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {},
        }
        dummy.write_text(json.dumps(data), encoding="utf-8")

        orig_fstat = os.fstat

        def mock_fstat(fd: int) -> MagicMock:
            real_st = orig_fstat(fd)
            mock_st = MagicMock(spec=real_st)
            mock_st.st_mode = real_st.st_mode
            mock_st.st_size = real_st.st_size
            mock_st.st_file_attributes = getattr(real_st, "st_file_attributes", 0) | 0x0400
            return mock_st

        with patch("os.fstat", side_effect=mock_fstat), pytest.raises(
            ValueError, match="Reparse points and junctions are rejected"
        ):
            ProfileManager.load_profile(dummy)


class TestWASDNormalization:
    """Validate directional Left Stick calculations."""

    def test_single_axis(self) -> None:
        profiles_dir = Path(__file__).parents[1] / "profiles"
        mgr = ProfileManager(profiles_dir=profiles_dir)
        prof = mgr.current_profile

        # Only W (Up)
        lx, ly = prof.compute_left_stick(frozenset({prof.wasd.up}))
        assert lx == 0
        assert ly == 32767

        # Only S (Down)
        lx, ly = prof.compute_left_stick(frozenset({prof.wasd.down}))
        assert lx == 0
        assert ly == -32768

    def test_diagonal_normalized_magnitude(self) -> None:
        profiles_dir = Path(__file__).parents[1] / "profiles"
        mgr = ProfileManager(profiles_dir=profiles_dir)
        prof = mgr.current_profile

        # W + D (Up + Right diagonal)
        lx, ly = prof.compute_left_stick(frozenset({prof.wasd.up, prof.wasd.right}))
        mag = math.hypot(lx, ly)
        assert mag <= 32767.5
        assert lx > 0 and ly > 0
