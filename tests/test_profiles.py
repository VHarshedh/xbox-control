"""Unit tests for profiles module (validation, security, and parsing).

Compatible with both pytest and python -m unittest.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import vgamepad_compat  # noqa: F401  # isort: skip
import vgamepad as vg

from profiles import ProfileManager, StickConfig, parse_target, parse_vk


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

    def test_parse_vk_zero_rejected(self) -> None:
        with pytest.raises(ValueError, match="VK code out of byte range"):
            parse_vk(0)

        with pytest.raises(ValueError, match="VK code out of byte range"):
            parse_vk("0")

        with pytest.raises(ValueError, match="VK code out of byte range"):
            parse_vk("0x00")


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

    def test_unsupported_playstation_and_unknown_triggers(self) -> None:
        with pytest.raises(ValueError, match="PlayStation controls are not supported"):
            parse_target("CROSS")
        with pytest.raises(ValueError, match="PlayStation controls are not supported"):
            parse_target("TRIANGLE")
        with pytest.raises(ValueError, match="Unknown controller trigger target"):
            parse_target("UNKNOWN_TRIGGER")


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
            with (
                patch.object(Path, "is_symlink", return_value=True),
                pytest.raises(ValueError, match="Symlinks are rejected for security"),
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

    def test_negative_infinity_rejection(self, tmp_path: Path) -> None:
        neginf_file = tmp_path / "neginf_profile.json"
        neginf_file.write_text(
            '{"name": "NegInf Profile", "stick_config": {"sensitivity": -Infinity, "curve_exponent": 1.0, "deadzone_comp": 0.1, "decay_rate": 0.8, "smoothing_alpha": 0.5}, "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68}, "buttons": {}}',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Non-finite JSON constant"):
            ProfileManager.load_profile(neginf_file)

    def test_wasd_invalid_vk(self, tmp_path: Path) -> None:
        bad_wasd = tmp_path / "bad_wasd.json"
        data = {
            "name": "Bad WASD",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": "INVALID_KEY_XYZ", "down": 83, "left": 65, "right": 68},
            "buttons": {},
        }
        bad_wasd.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match="invalid 'wasd_left_stick'"):
            ProfileManager.load_profile(bad_wasd)

    def test_stick_config_invalid_bounds(self, tmp_path: Path) -> None:
        def make_profile(stick_cfg: dict[str, Any]) -> dict[str, Any]:
            return {
                "name": "Test",
                "stick_config": stick_cfg,
                "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
                "buttons": {},
            }

        # sensitivity <= 0
        p = tmp_path / "bad_sens.json"
        cfg: dict[str, Any] = {
            "sensitivity": -1.0,
            "curve_exponent": 1.0,
            "deadzone_comp": 0.1,
            "decay_rate": 0.8,
            "smoothing_alpha": 0.5,
        }
        p.write_text(json.dumps(make_profile(cfg)), encoding="utf-8")
        with pytest.raises(ValueError, match="sensitivity must be > 0"):
            ProfileManager.load_profile(p)

        # decay_rate > 1.0
        p = tmp_path / "bad_decay.json"
        cfg["sensitivity"] = 0.05
        cfg["decay_rate"] = 1.5
        p.write_text(json.dumps(make_profile(cfg)), encoding="utf-8")
        with pytest.raises(ValueError, match="decay_rate must be in"):
            ProfileManager.load_profile(p)

        # smoothing_alpha <= 0
        p = tmp_path / "bad_smoothing.json"
        cfg["decay_rate"] = 0.8
        cfg["smoothing_alpha"] = 0.0
        p.write_text(json.dumps(make_profile(cfg)), encoding="utf-8")
        with pytest.raises(ValueError, match="smoothing_alpha must be in"):
            ProfileManager.load_profile(p)

    def test_profile_manager_lifecycle(self, tmp_path: Path) -> None:
        # Non-existent directory
        with pytest.raises(FileNotFoundError, match="Profiles directory does not exist"):
            ProfileManager(profiles_dir=tmp_path / "nonexistent")

        # Empty directory
        empty_dir = tmp_path / "empty_profiles"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError, match="No .json profile files found"):
            ProfileManager(profiles_dir=empty_dir)

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

        with (
            patch("os.fstat", side_effect=mock_fstat),
            pytest.raises(ValueError, match="Reparse points and junctions are rejected"),
        ):
            ProfileManager.load_profile(dummy)

    def test_windows_reserved_device_names(self, tmp_path: Path) -> None:
        for dev in ("CON.json", "NUL.json", "AUX.json", "PRN.json", "COM1.json", "LPT1.json"):
            bad_path = tmp_path / dev
            with pytest.raises(ValueError, match="Windows reserved device name rejected"):
                ProfileManager.load_profile(bad_path)

    def test_ntfs_alternate_data_streams(self, tmp_path: Path) -> None:
        valid_file = tmp_path / "valid.json"
        valid_file.write_text('{"name": "Valid"}', encoding="utf-8")
        ads_path = Path(str(valid_file) + ":stream")
        with pytest.raises(ValueError, match="NTFS Alternate Data Streams"):
            ProfileManager.load_profile(ads_path)

    def test_extended_unc_path_rejection(self) -> None:
        unc_path = Path(r"\\?\C:\profiles\shooter.json")
        with pytest.raises(ValueError, match="Extended UNC/device paths are rejected"):
            ProfileManager.load_profile(unc_path)

    def test_duplicate_json_keys_rejection(self, tmp_path: Path) -> None:
        dup_file = tmp_path / "dup.json"
        dup_file.write_text(
            '{"name": "First", "name": "Second", "stick_config": {"sensitivity": 0.05, "curve_exponent": 1.0, "deadzone_comp": 0.1, "decay_rate": 0.8, "smoothing_alpha": 0.5}, "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68}, "buttons": {}}',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="Duplicate key in JSON object"):
            ProfileManager.load_profile(dup_file)

    def test_file_descriptor_closed_on_invalid_utf8(self, tmp_path: Path) -> None:
        bad_utf8 = tmp_path / "bad_utf8.json"
        bad_utf8.write_bytes(b"\xff\xfe\x00\x00 invalid binary data")
        with pytest.raises(ValueError, match="is not valid UTF-8"):
            ProfileManager.load_profile(bad_utf8)

    def test_profile_manager_reload_mixed_valid_and_invalid(self, tmp_path: Path) -> None:
        valid_file = tmp_path / "valid.json"
        valid_data = {
            "name": "ValidProfile",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
                "invert_y": False,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {},
        }
        valid_file.write_text(json.dumps(valid_data), encoding="utf-8")

        # Corrupt file
        bad_file = tmp_path / "corrupt.json"
        bad_file.write_text("{invalid json", encoding="utf-8")

        mgr = ProfileManager(profiles_dir=tmp_path)
        assert len(mgr.profiles) == 1
        assert mgr.profiles[0].name == "ValidProfile"

    def test_profile_manager_reload_normalized_default(self) -> None:
        profiles_dir = Path(__file__).parents[1] / "profiles"
        mgr = ProfileManager(profiles_dir=profiles_dir, default_name="rts")
        assert mgr.current_profile.name == "RTS / Menu"


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

    def test_wasd_walk_modifier(self, tmp_path: Path) -> None:
        p_file = tmp_path / "walk_profile.json"
        data = {
            "name": "Walk Profile",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {
                "up": 87,
                "down": 83,
                "left": 65,
                "right": 68,
                "walk": "VK_LMENU",  # Left Alt = 0xA4
            },
            "buttons": {},
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        assert prof.wasd.walk_key == 0xA4

        # Full speed Up
        lx, ly = prof.compute_left_stick(frozenset({87}))
        assert lx == 0
        assert ly == 32767

        # Walk speed Up (scaled by 0.5)
        lx_walk, ly_walk = prof.compute_left_stick(frozenset({87, 0xA4}))
        assert lx_walk == 0
        assert ly_walk == int(32767 * 0.5)


class TestWheelMappingAndGuideButtons:
    """Validate scroll wheel pulse dynamics, decay across ticks, and guide button mappings."""

    def test_wheel_up_down_pulse_activation_and_decay(self, tmp_path: Path) -> None:
        p_file = tmp_path / "wheel_profile.json"
        data = {
            "name": "Wheel Profile",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "WHEEL_UP": "XUSB_GAMEPAD_Y",
                "WHEEL_DOWN": "XUSB_GAMEPAD_X",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)

        mock_gamepad = MagicMock()

        # Step 1: Scroll UP impulse (wheel_delta=+120)
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
            wheel_delta=120,
        )
        assert prof._wheel_up_ticks == 7
        mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_Y)

        # Pulse remains active for remaining 7 ticks (total 8 ticks)
        for expected_remaining in range(6, -1, -1):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=False,
                rbutton=False,
                mbutton=False,
                wheel_delta=0,
            )
            assert prof._wheel_up_ticks == expected_remaining
            mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_Y)

        # Tick 9: pulse expired -> button released
        mock_gamepad.reset_mock()
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
            wheel_delta=0,
        )
        assert prof._wheel_up_ticks == 0
        mock_gamepad.release_button.assert_any_call(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_Y)

    def test_shooter_and_rts_profiles_guide_and_wheel(self) -> None:
        profiles_dir = Path(__file__).parents[1] / "profiles"

        # Shooter profile
        shooter = ProfileManager.load_profile(profiles_dir / "shooter.json")
        assert 0x24 in shooter._key_targets  # VK_HOME
        assert shooter._key_targets[0x24] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE]
        assert shooter._mouse_targets["wheel_up"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_Y]
        assert shooter._mouse_targets["wheel_down"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_Y]

        # RTS / Menu profile
        rts = ProfileManager.load_profile(profiles_dir / "rts_menu.json")
        assert 0x24 in rts._key_targets  # VK_HOME
        assert rts._key_targets[0x24] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE]

    def test_subframe_tap_loss_min_button_hold_ticks(self, tmp_path: Path) -> None:
        p_file = tmp_path / "tap_profile.json"
        data = {
            "name": "Tap Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "XUSB_GAMEPAD_A",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        mock_gamepad = MagicMock()

        # Tick 1: Physical click (1-tick tap: initialized to 6, decremented to 5 on rising edge)
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=True,
            rbutton=False,
            mbutton=False,
        )
        assert prof._hold_counters[vg.XUSB_BUTTON.XUSB_GAMEPAD_A] == 5
        mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_A)

        # Inactive ticks where hold counter decays from 4 to 0 (kept active for 6 ticks total)
        for expected_counter in range(4, -1, -1):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=False,
                rbutton=False,
                mbutton=False,
            )
            mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_A)
            if expected_counter > 0:
                assert prof._hold_counters[vg.XUSB_BUTTON.XUSB_GAMEPAD_A] == expected_counter
            else:
                assert vg.XUSB_BUTTON.XUSB_GAMEPAD_A not in prof._hold_counters

        # Following tick: hold expired, button is released
        mock_gamepad.reset_mock()
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
        )
        mock_gamepad.release_button.assert_any_call(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_A)

    def test_rapid_multi_notch_scroll_queue_with_release_gaps(self, tmp_path: Path) -> None:
        p_file = tmp_path / "wheel_queue_profile.json"
        data = {
            "name": "Wheel Queue Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "WHEEL_UP": "XUSB_GAMEPAD_Y",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        mock_gamepad = MagicMock()

        # Tick 1: 2 notches in single event (wheel_delta = +240)
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
            wheel_delta=240,
        )
        assert prof._wheel_up_ticks == 7
        assert prof._wheel_up_queue == 1
        mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_Y)

        # Remaining 7 ticks of first notch hold
        for _ in range(7):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=False,
                rbutton=False,
                mbutton=False,
                wheel_delta=0,
            )
            mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_Y)

        assert prof._wheel_up_ticks == 0
        assert prof._wheel_up_gap == 6
        assert prof._wheel_up_queue == 1

        # Release gap of 6 ticks (button released to avoid WebRTC coalescing)
        for expected_gap in range(5, -1, -1):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=False,
                rbutton=False,
                mbutton=False,
                wheel_delta=0,
            )
            mock_gamepad.release_button.assert_any_call(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_Y)
            if expected_gap > 0:
                assert prof._wheel_up_gap == expected_gap

        # Second notch now begins
        assert prof._wheel_up_ticks == 8
        assert prof._wheel_up_queue == 0

        # Tick of second notch pulse
        mock_gamepad.reset_mock()
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
            wheel_delta=0,
        )
        assert prof._wheel_up_ticks == 7
        mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_Y)

    def test_held_button_long_press_zero_latency_release(self, tmp_path: Path) -> None:
        p_file = tmp_path / "long_hold_profile.json"
        data = {
            "name": "Long Hold Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "XUSB_GAMEPAD_A",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        mock_gamepad = MagicMock()

        # Hold button down for 10 ticks (well past the 6-tick minimum hold duration)
        for tick in range(1, 11):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=True,
                rbutton=False,
                mbutton=False,
            )
            mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_A)
            if tick <= 5:
                assert prof._hold_counters[vg.XUSB_BUTTON.XUSB_GAMEPAD_A] == (6 - tick)
            else:
                # Expired after 6 decrement ticks from rising edge
                assert vg.XUSB_BUTTON.XUSB_GAMEPAD_A not in prof._hold_counters

        # Tick 11: Released after long hold -> zero release latency (released on this tick)
        mock_gamepad.reset_mock()
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
        )
        assert vg.XUSB_BUTTON.XUSB_GAMEPAD_A not in prof._hold_counters
        mock_gamepad.release_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_A)

    def test_held_button_exact_six_ticks_zero_latency_release(self, tmp_path: Path) -> None:
        p_file = tmp_path / "six_tick_hold_profile.json"
        data = {
            "name": "Six Tick Hold Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "XUSB_GAMEPAD_A",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        mock_gamepad = MagicMock()

        # Hold for exactly 6 ticks (24 ms)
        for tick in range(1, 7):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=True,
                rbutton=False,
                mbutton=False,
            )
            mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_A)
            if tick <= 5:
                assert prof._hold_counters[vg.XUSB_BUTTON.XUSB_GAMEPAD_A] == (6 - tick)
            else:
                assert vg.XUSB_BUTTON.XUSB_GAMEPAD_A not in prof._hold_counters

        # Tick 7: Released -> immediate 0 ms release (released on this tick)
        mock_gamepad.reset_mock()
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
        )
        assert vg.XUSB_BUTTON.XUSB_GAMEPAD_A not in prof._hold_counters
        mock_gamepad.release_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_A)

    def test_held_trigger_long_press_zero_latency_release(self, tmp_path: Path) -> None:
        p_file = tmp_path / "rt_hold_profile.json"
        data = {
            "name": "RT Hold Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "RT",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        mock_gamepad = MagicMock()

        # Hold RT for 10 ticks
        for _tick in range(1, 11):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=True,
                rbutton=False,
                mbutton=False,
            )
            mock_gamepad.right_trigger.assert_called_with(value=255)

        # Tick 11: Released -> immediate 0 ms release
        mock_gamepad.reset_mock()
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
        )
        assert "RT" not in prof._hold_counters
        mock_gamepad.right_trigger.assert_called_with(value=0)

    def test_held_trigger_exact_six_ticks_zero_latency_release(self, tmp_path: Path) -> None:
        p_file = tmp_path / "rt_six_tick_profile.json"
        data = {
            "name": "RT Six Tick Hold Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "RT",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        mock_gamepad = MagicMock()

        # Hold RT for exactly 6 ticks (24 ms)
        for _tick in range(1, 7):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=True,
                rbutton=False,
                mbutton=False,
            )
            mock_gamepad.right_trigger.assert_called_with(value=255)

        # Tick 7: Released -> immediate 0 ms release
        mock_gamepad.reset_mock()
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
        )
        assert "RT" not in prof._hold_counters
        mock_gamepad.right_trigger.assert_called_with(value=0)

    def test_fast_tap_one_tick_maintains_six_tick_minimum_duration(self, tmp_path: Path) -> None:
        p_file = tmp_path / "one_tick_tap_profile.json"
        data = {
            "name": "One Tick Tap Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "XUSB_GAMEPAD_X",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        mock_gamepad = MagicMock()

        # Tick 1: Pressed physically (rising edge)
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=True,
            rbutton=False,
            mbutton=False,
        )
        mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_X)
        assert prof._hold_counters[vg.XUSB_BUTTON.XUSB_GAMEPAD_X] == 5

        # Ticks 2-6: Physically released, decays from 4 down to 0, remaining pressed for 6 ticks total
        for expected_counter in range(4, -1, -1):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=False,
                rbutton=False,
                mbutton=False,
            )
            mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_X)
            if expected_counter > 0:
                assert prof._hold_counters[vg.XUSB_BUTTON.XUSB_GAMEPAD_X] == expected_counter
            else:
                assert vg.XUSB_BUTTON.XUSB_GAMEPAD_X not in prof._hold_counters

        # Tick 7: Released with 0 ms latency once 6 ticks complete
        mock_gamepad.reset_mock()
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
        )
        mock_gamepad.release_button.assert_any_call(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_X)

    def test_short_hold_three_ticks_maintains_minimum_duration(self, tmp_path: Path) -> None:
        p_file = tmp_path / "short_hold_profile.json"
        data = {
            "name": "Short Hold Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "XUSB_GAMEPAD_B",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        mock_gamepad = MagicMock()

        # Held for 3 ticks
        for tick in range(1, 4):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=True,
                rbutton=False,
                mbutton=False,
            )
            mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_B)
            assert prof._hold_counters[vg.XUSB_BUTTON.XUSB_GAMEPAD_B] == (6 - tick)

        assert prof._hold_counters[vg.XUSB_BUTTON.XUSB_GAMEPAD_B] == 3

        # Released on tick 4: decays from 2 down to 0, staying pressed for ticks 4, 5, 6 (total 6 ticks)
        for expected_counter in range(2, -1, -1):
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=False,
                rbutton=False,
                mbutton=False,
            )
            mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_B)
            if expected_counter > 0:
                assert prof._hold_counters[vg.XUSB_BUTTON.XUSB_GAMEPAD_B] == expected_counter
            else:
                assert vg.XUSB_BUTTON.XUSB_GAMEPAD_B not in prof._hold_counters

        # Following tick 7: released
        mock_gamepad.reset_mock()
        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=False,
            rbutton=False,
            mbutton=False,
        )
        mock_gamepad.release_button.assert_any_call(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_B)

    def test_reset_controls_clears_hold_and_prev_targets(self, tmp_path: Path) -> None:
        p_file = tmp_path / "reset_profile.json"
        data = {
            "name": "Reset Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "XUSB_GAMEPAD_X",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        mock_gamepad = MagicMock()

        prof.apply_buttons(
            gamepad=mock_gamepad,
            keys_pressed=None,
            lbutton=True,
            rbutton=False,
            mbutton=False,
        )
        assert len(prof._hold_counters) > 0
        assert len(prof._prev_physical_targets) > 0

        prof.reset_controls(mock_gamepad)
        assert len(prof._hold_counters) == 0
        assert len(prof._prev_physical_targets) == 0

    def test_profile_wasd_null_walk_key_accepted(self, tmp_path: Path) -> None:
        p_file = tmp_path / "null_walk_profile.json"
        data = {
            "name": "Null Walk Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68, "walk": None},
            "buttons": {
                "MOUSE_LEFT": "XUSB_GAMEPAD_A",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        assert prof.wasd.walk_key is None

    def test_profile_multi_dot_reserved_device_names_rejected(self, tmp_path: Path) -> None:
        p_file = tmp_path / "con.test.json"
        data = {
            "name": "Reserved Name Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "XUSB_GAMEPAD_A",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match="Windows reserved device name rejected"):
            ProfileManager.load_profile(p_file)

    def test_profile_com0_reserved_device_name_rejected(self, tmp_path: Path) -> None:
        p_file = tmp_path / "com0.json"
        data = {
            "name": "COM0 Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {
                "MOUSE_LEFT": "XUSB_GAMEPAD_A",
            },
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match="Windows reserved device name rejected"):
            ProfileManager.load_profile(p_file)

    def test_profile_duplicate_wasd_keys_rejected(self, tmp_path: Path) -> None:
        """Profiles with duplicate keys in wasd_left_stick must be rejected."""
        p_file = tmp_path / "dup_wasd.json"
        data = {
            "name": "Dup WASD Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 87, "left": 65, "right": 68},
            "buttons": {"MOUSE_LEFT": "XUSB_GAMEPAD_A"},
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match="Duplicate keys in 'wasd_left_stick'"):
            ProfileManager.load_profile(p_file)

    def test_profile_unexpected_top_level_keys_rejected(self, tmp_path: Path) -> None:
        """Profiles with unexpected schema keys must be rejected."""
        p_file = tmp_path / "extra_keys.json"
        data = {
            "name": "Extra Keys Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {"MOUSE_LEFT": "XUSB_GAMEPAD_A"},
            "malicious_key": True,
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(ValueError, match="Unexpected top-level key.*in schema"):
            ProfileManager.load_profile(p_file)

    def test_subframe_tap_held_for_six_ticks_multiple_durations(self, tmp_path: Path) -> None:
        """Verify that holds of 2, 4, and 5 ticks all hold for 6 ticks total and release on tick 7."""
        p_file = tmp_path / "multi_dur_test.json"
        data = {
            "name": "Multi Duration Test",
            "stick_config": {
                "sensitivity": 1.0,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {"MOUSE_LEFT": "XUSB_GAMEPAD_X"},
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")

        for press_duration in (2, 4, 5):
            prof = ProfileManager.load_profile(p_file)
            mock_gamepad = MagicMock()

            # Physically hold for press_duration ticks
            for _ in range(press_duration):
                mock_gamepad.reset_mock()
                prof.apply_buttons(
                    gamepad=mock_gamepad,
                    keys_pressed=None,
                    lbutton=True,
                    rbutton=False,
                    mbutton=False,
                )
                mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_X)

            # Physically released: must stay held until tick 6 is complete
            for _ in range(6 - press_duration):
                mock_gamepad.reset_mock()
                prof.apply_buttons(
                    gamepad=mock_gamepad,
                    keys_pressed=None,
                    lbutton=False,
                    rbutton=False,
                    mbutton=False,
                )
                mock_gamepad.press_button.assert_called_with(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_X)

            # Tick 7: Expired, button must be released
            mock_gamepad.reset_mock()
            prof.apply_buttons(
                gamepad=mock_gamepad,
                keys_pressed=None,
                lbutton=False,
                rbutton=False,
                mbutton=False,
            )
            mock_gamepad.release_button.assert_any_call(button=vg.XUSB_BUTTON.XUSB_GAMEPAD_X)


class TestMouseStickConfig:
    """Validate configurable mouse_stick routing (left vs right) and profile loading."""

    def test_stick_config_default_mouse_stick(self) -> None:
        cfg = StickConfig(
            sensitivity=0.08,
            curve_exponent=1.3,
            deadzone_comp=0.18,
            decay_rate=0.72,
            smoothing_alpha=0.75,
        )
        assert cfg.mouse_stick == "right"
        assert cfg.invert_y is False

    def test_stick_config_direct_instantiation_validation(self) -> None:
        cfg_left = StickConfig(0.08, 1.3, 0.18, 0.72, 0.75, False, "left")
        assert cfg_left.mouse_stick == "left"

        # Case and whitespace normalization
        cfg_upper = StickConfig(0.08, 1.3, 0.18, 0.72, 0.75, False, "  LEFT  ")
        assert cfg_upper.mouse_stick == "left"

        with pytest.raises(ValueError, match="'mouse_stick' must be 'left' or 'right'"):
            StickConfig(0.08, 1.3, 0.18, 0.72, 0.75, False, "invalid")

        with pytest.raises(ValueError, match="'mouse_stick' must be a string"):
            StickConfig(0.08, 1.3, 0.18, 0.72, 0.75, False, 123)  # type: ignore[arg-type]

    def test_mouse_stick_left_and_right(self, tmp_path: Path) -> None:
        for val in ("left", "right"):
            p_file = tmp_path / f"profile_{val}.json"
            data = {
                "name": f"Profile {val}",
                "stick_config": {
                    "sensitivity": 0.05,
                    "curve_exponent": 1.0,
                    "deadzone_comp": 0.1,
                    "decay_rate": 0.8,
                    "smoothing_alpha": 0.5,
                    "mouse_stick": val,
                },
                "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
                "buttons": {"MOUSE_LEFT": "XUSB_GAMEPAD_A"},
            }
            p_file.write_text(json.dumps(data), encoding="utf-8")
            prof = ProfileManager.load_profile(p_file)
            assert prof.stick_config.mouse_stick == val

    def test_mouse_stick_whitespace_and_case_insensitivity(self, tmp_path: Path) -> None:
        cases = [
            ("  LEFT  ", "left"),
            ("Right", "right"),
            ("  right\t", "right"),
            ("LeFt", "left"),
        ]
        for idx, (raw_val, expected) in enumerate(cases):
            p_file = tmp_path / f"profile_{idx}_{expected}.json"
            data = {
                "name": f"Profile {expected}",
                "stick_config": {
                    "sensitivity": 0.05,
                    "curve_exponent": 1.0,
                    "deadzone_comp": 0.1,
                    "decay_rate": 0.8,
                    "smoothing_alpha": 0.5,
                    "mouse_stick": raw_val,
                },
                "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
                "buttons": {"MOUSE_LEFT": "XUSB_GAMEPAD_A"},
            }
            p_file.write_text(json.dumps(data), encoding="utf-8")
            prof = ProfileManager.load_profile(p_file)
            assert prof.stick_config.mouse_stick == expected

    def test_mouse_stick_default_when_omitted(self, tmp_path: Path) -> None:
        p_file = tmp_path / "profile_default.json"
        data = {
            "name": "Profile Default",
            "stick_config": {
                "sensitivity": 0.05,
                "curve_exponent": 1.0,
                "deadzone_comp": 0.1,
                "decay_rate": 0.8,
                "smoothing_alpha": 0.5,
            },
            "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
            "buttons": {"MOUSE_LEFT": "XUSB_GAMEPAD_A"},
        }
        p_file.write_text(json.dumps(data), encoding="utf-8")
        prof = ProfileManager.load_profile(p_file)
        assert prof.stick_config.mouse_stick == "right"

    def test_mouse_stick_invalid_value_rejected(self, tmp_path: Path) -> None:
        invalid_values = ["middle", "center", "up", "down", "both", "", "   "]
        for bad_val in invalid_values:
            p_file = tmp_path / "profile_bad_val.json"
            data = {
                "name": "Bad Mouse Stick",
                "stick_config": {
                    "sensitivity": 0.05,
                    "curve_exponent": 1.0,
                    "deadzone_comp": 0.1,
                    "decay_rate": 0.8,
                    "smoothing_alpha": 0.5,
                    "mouse_stick": bad_val,
                },
                "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
                "buttons": {"MOUSE_LEFT": "XUSB_GAMEPAD_A"},
            }
            p_file.write_text(json.dumps(data), encoding="utf-8")
            with pytest.raises(ValueError, match="'mouse_stick' must be 'left' or 'right'"):
                ProfileManager.load_profile(p_file)

    def test_mouse_stick_non_string_rejected(self, tmp_path: Path) -> None:
        invalid_types: list[Any] = [True, False, 1, 0, 1.5, [], {}]
        for bad_type in invalid_types:
            p_file = tmp_path / "profile_bad_type.json"
            data = {
                "name": "Bad Mouse Stick Type",
                "stick_config": {
                    "sensitivity": 0.05,
                    "curve_exponent": 1.0,
                    "deadzone_comp": 0.1,
                    "decay_rate": 0.8,
                    "smoothing_alpha": 0.5,
                    "mouse_stick": bad_type,
                },
                "wasd_left_stick": {"up": 87, "down": 83, "left": 65, "right": 68},
                "buttons": {"MOUSE_LEFT": "XUSB_GAMEPAD_A"},
            }
            p_file.write_text(json.dumps(data), encoding="utf-8")
            with pytest.raises(ValueError, match="'mouse_stick' must be a string"):
                ProfileManager.load_profile(p_file)

    def test_rts_menu_profile_loaded_and_valid(self) -> None:
        profiles_dir = Path(__file__).parents[1] / "profiles"
        rts_file = profiles_dir / "rts_menu.json"
        assert rts_file.is_file(), f"Expected {rts_file} to exist"

        prof = ProfileManager.load_profile(rts_file)
        assert prof.name == "RTS / Menu"
        assert prof.stick_config.mouse_stick == "left"
        assert prof.stick_config.sensitivity == 0.070
        assert prof.stick_config.curve_exponent == 1.2
        assert prof.stick_config.deadzone_comp == 0.15
        assert prof.stick_config.decay_rate == 0.78
        assert prof.stick_config.smoothing_alpha == 0.75
        assert prof.stick_config.invert_y is False

        assert prof.wasd.up == 87
        assert prof.wasd.down == 83
        assert prof.wasd.left == 65
        assert prof.wasd.right == 68
        assert prof.wasd.walk_key == 0xA4  # VK_LMENU

        # Verify button mappings
        assert prof._mouse_targets["left"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_A]
        assert prof._mouse_targets["right"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_X]
        assert prof._mouse_targets["middle"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_B]
        assert prof._mouse_targets["x1"] == ["RT"]
        assert prof._mouse_targets["x2"] == ["LT"]
        assert prof._mouse_targets["wheel_up"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_SHOULDER]
        assert prof._mouse_targets["wheel_down"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_SHOULDER]

        assert prof._key_targets[0x20] == ["RT"]  # VK_SPACE
        assert prof._key_targets[0xA0] == ["LT"]  # VK_LSHIFT
        assert prof._key_targets[ord("F")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_Y]
        assert prof._key_targets[ord("C")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_B]
        assert prof._key_targets[ord("Q")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_SHOULDER]
        assert prof._key_targets[ord("E")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_SHOULDER]
        assert prof._key_targets[ord("R")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB]
        assert prof._key_targets[ord("G")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB]
        assert prof._key_targets[ord("1")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP]
        assert prof._key_targets[ord("2")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT]
        assert prof._key_targets[ord("3")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN]
        assert prof._key_targets[ord("4")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_LEFT]
        assert prof._key_targets[0x09] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_BACK]  # VK_TAB
        assert prof._key_targets[0x1B] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_START]  # VK_ESCAPE
        assert prof._key_targets[0x24] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE]  # VK_HOME

    def test_action_rpg_profile_loaded_and_valid(self) -> None:
        profiles_dir = Path(__file__).parents[1] / "profiles"
        rpg_file = profiles_dir / "action_rpg.json"
        assert rpg_file.is_file(), f"Expected {rpg_file} to exist"

        prof = ProfileManager.load_profile(rpg_file)
        assert prof.name == "Action / RPG"
        assert prof.stick_config.mouse_stick == "right"
        assert prof.stick_config.sensitivity == 0.075
        assert prof.stick_config.curve_exponent == 1.25
        assert prof.stick_config.deadzone_comp == 0.16
        assert prof.stick_config.decay_rate == 0.75
        assert prof.stick_config.smoothing_alpha == 0.75
        assert prof.stick_config.invert_y is False

        assert prof.wasd.up == 87
        assert prof.wasd.down == 83
        assert prof.wasd.left == 65
        assert prof.wasd.right == 68
        assert prof.wasd.walk_key is None

        # Verify button mappings
        assert prof._mouse_targets["left"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_SHOULDER]
        assert prof._mouse_targets["right"] == ["RT"]
        assert prof._mouse_targets["middle"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_RIGHT_THUMB]
        assert prof._mouse_targets["x1"] == ["LT"]
        assert prof._mouse_targets["x2"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_SHOULDER]
        assert prof._mouse_targets["wheel_up"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP]
        assert prof._mouse_targets["wheel_down"] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN]

        assert prof._key_targets[0x20] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_B]  # VK_SPACE
        assert prof._key_targets[ord("F")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_A]
        assert prof._key_targets[ord("E")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_Y]
        assert prof._key_targets[ord("R")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_X]
        assert prof._key_targets[0xA0] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB]  # VK_LSHIFT
        assert prof._key_targets[ord("Q")] == ["LT"]
        assert prof._key_targets[ord("1")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP]
        assert prof._key_targets[ord("2")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT]
        assert prof._key_targets[ord("3")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN]
        assert prof._key_targets[ord("4")] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_LEFT]
        assert prof._key_targets[0x09] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_BACK]  # VK_TAB
        assert prof._key_targets[0x1B] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_START]  # VK_ESCAPE
        assert prof._key_targets[0x24] == [vg.XUSB_BUTTON.XUSB_GAMEPAD_GUIDE]  # VK_HOME

    def test_load_all_shipped_profiles(self) -> None:
        profiles_dir = Path(__file__).parents[1] / "profiles"
        mgr = ProfileManager(profiles_dir=profiles_dir, default_name="Shooter")
        assert len(mgr.profiles) >= 3

        names = {p.name for p in mgr.profiles}
        assert "Shooter" in names
        assert "RTS / Menu" in names
        assert "Action / RPG" in names

        for prof in mgr.profiles:
            # Verify mapper creation and operational sanity
            mapper = prof.stick_config.create_mapper()
            assert mapper is not None
            out_x, out_y = mapper.step(10, 0, 0.004)
            assert isinstance(out_x, int)
            assert isinstance(out_y, int)

            # Verify left stick computation
            lx, ly = prof.compute_left_stick({prof.wasd.up})
            assert ly > 0

            # Verify button application and reset
            mock_gamepad = MagicMock()
            prof.apply_buttons(
                mock_gamepad,
                keys_pressed=set(),
                lbutton=False,
                rbutton=False,
                mbutton=False,
            )
            prof.reset_controls(mock_gamepad)

    def test_profile_is_button_active(self) -> None:
        profiles_dir = Path(__file__).parents[1] / "profiles"
        rts_file = profiles_dir / "rts_menu.json"
        prof = ProfileManager.load_profile(rts_file)

        mock_gamepad = MagicMock()
        # Initially no buttons active
        assert not prof.is_button_active(vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB)
        assert not prof.is_button_active(vg.XUSB_BUTTON.XUSB_GAMEPAD_A)

        # In RTS profile, VK_R (0x52) is mapped to LEFT_THUMB
        prof.apply_buttons(
            mock_gamepad,
            keys_pressed={ord("R")},
            lbutton=False,
            rbutton=False,
            mbutton=False,
        )
        assert prof.is_button_active(vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB)
        assert not prof.is_button_active(vg.XUSB_BUTTON.XUSB_GAMEPAD_A)

        # Mouse left click maps to XUSB_GAMEPAD_A
        prof.apply_buttons(
            mock_gamepad,
            keys_pressed=set(),
            lbutton=True,
            rbutton=False,
            mbutton=False,
        )
        assert prof.is_button_active(vg.XUSB_BUTTON.XUSB_GAMEPAD_A)
        # Note: LEFT_THUMB remains active across sub-frame hold ticks (MIN_BUTTON_HOLD_TICKS)
        assert prof.is_button_active(vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB)

        # reset_controls clears all active and held states
        prof.reset_controls(mock_gamepad)
        assert not prof.is_button_active(vg.XUSB_BUTTON.XUSB_GAMEPAD_LEFT_THUMB)
        assert not prof.is_button_active(vg.XUSB_BUTTON.XUSB_GAMEPAD_A)

    def test_universal_console_menu_bindings_across_all_profiles(self) -> None:
        profiles_dir = Path(__file__).parents[1] / "profiles"
        expected_menu_mappings = {
            0x26: [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_UP],  # VK_UP
            0x28: [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_DOWN],  # VK_DOWN
            0x25: [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_LEFT],  # VK_LEFT
            0x27: [vg.XUSB_BUTTON.XUSB_GAMEPAD_DPAD_RIGHT],  # VK_RIGHT
            0x0D: [vg.XUSB_BUTTON.XUSB_GAMEPAD_A],  # VK_RETURN
            0x08: [vg.XUSB_BUTTON.XUSB_GAMEPAD_B],  # VK_BACK (Backspace)
            ord("X"): [vg.XUSB_BUTTON.XUSB_GAMEPAD_X],  # VK_X
        }
        for profile_name in ["shooter.json", "rts_menu.json", "action_rpg.json"]:
            prof = ProfileManager.load_profile(profiles_dir / profile_name)
            for vk_code, expected_buttons in expected_menu_mappings.items():
                assert vk_code in prof._key_targets, (
                    f"Profile {profile_name} missing VK {hex(vk_code)}"
                )
                assert prof._key_targets[vk_code] == expected_buttons, (
                    f"Profile {profile_name} VK {hex(vk_code)} mapped to {prof._key_targets[vk_code]}, "
                    f"expected {expected_buttons}"
                )
