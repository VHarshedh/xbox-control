# ViGEmBus Virtual Xbox 360 Controller Mapper

A hardened, ultra-low-latency Windows input bridge that translates raw mouse and keyboard events into standard Xbox 360 controller reports via the **ViGEmBus** kernel driver at a fixed **250 Hz (4 ms)** tick rate.

Designed for PC gaming, remote play, and accessibility with strict memory limits (**< 25 MB RAM**), sub-millisecond hook callbacks, and zero input leakage.

---

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │        Win32 Low-Level Hooks           │
                      │  WH_KEYBOARD_LL  │  WH_MOUSE_LL        │
                      └──────────────────┬─────────────────────┘
                                         │ (Swallows input when active)
                                         ▼
                      ┌────────────────────────────────────────┐
                      │      Thread-Safe Atomic Buffers        │
                      │  dx/dy counters, VK bitmask, buttons   │
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │     HighResTimer Tick Loop (250 Hz)    │
                      │   winmm timeBeginPeriod(1) + hybrid    │
                      │      sleep & perf_counter busywait     │
                      └──────────────────┬─────────────────────┘
                                         │
              ┌──────────────────────────┴──────────────────────────┐
              ▼                                                     ▼
┌───────────────────────────┐                         ┌───────────────────────────┐
│    MouseToStickMapper     │                         │  Directional Normalizer   │
│  • Sensitivity Scaling    │                         │  • WASD -> Left Stick     │
│  • EMA Smoothing          │                         │  • Diagonal Scale 1/√2    │
│  • Radial Power Curve     │                         │  • Range [-32768, 32767]  │
│  • Radial Deadzone Comp   │                         └─────────────┬─────────────┘
│  • Auto-Recentering Decay │                                       │
└─────────────┬─────────────┘                                       │
              │                                                     │
              └──────────────────────────┬──────────────────────────┘
                                         ▼
                      ┌────────────────────────────────────────┐
                      │    Button & Analog Trigger Resolver    │
                      │  • LT / RT [0, 255]                    │
                      │  • XUSB_GAMEPAD_* Digital Buttons      │
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │     ViGEmBus Virtual Controller        │
                      │         (vgamepad VX360Gamepad)        │
                      └────────────────────────────────────────┘
```

---

## 250 Hz Real-Time Pipeline

1. **Sub-Millisecond Win32 Hook Callbacks**:
   - Background pump thread installs `WH_KEYBOARD_LL` (13) and `WH_MOUSE_LL` (14).
   - Callbacks complete in `< 0.05 ms` to prevent Windows `LowLevelHooksTimeout` removals.
   - When capture is active, events are swallowed (`return 1`) to freeze the OS cursor and eliminate UI focus leaks to browsers or system windows.
   - Injected events (`LLMHF_INJECTED = 0x01`) from cursor recentering are automatically discarded.

2. **High-Precision Hybrid Timer (`HighResTimer`)**:
   - Configures `timeBeginPeriod(1)` to reduce the OS scheduler quantum to ~1 ms.
   - Hybrid sleep strategy: coarse sleep for intervals `> 1.5 ms`, followed by a sub-millisecond `time.perf_counter()` spinwait.
   - Delivers a precise **4.000 ms** tick interval with typical jitter under **±0.03 ms**.
   - `timer.reset()` resyncs timing baselines on unpause to avoid catch-up bursts.

3. **Thumbstick Signal Processing**:
   - **Right Stick**: Exponential Moving Average (EMA) smoothing filters micro-jitter, followed by a radial power curve ($r^{\text{exponent}}$). A deadzone compensation offset maps $[0, 1] \rightarrow [\text{deadzone}, 1.0]$, bypassing controller deadzones in modern game engines.
   - **Left Stick**: WASD keys are combined into $(w_x, w_y)$ vectors and normalized on diagonals by $1/\sqrt{2}$ so radial deflection never exceeds unit magnitude ($32767$).
   - **Walk Modifier**: Optional `walk` key in `wasd_left_stick` (e.g. `VK_LMENU` / Left Alt) scales deflection by 50% for stealth and precision positioning.

---

## Key Features

- **WHEEL_UP / WHEEL_DOWN Weapon Switching**: Scroll-wheel notch events are converted into pulse actions (e.g. mapped to `XUSB_GAMEPAD_Y`) with minimum hold durations and inter-notch release gaps for dependable weapon cycling.
- **Xbox Guide Button Support (`VK_HOME`)**: Direct mapping to `XUSB_GAMEPAD_GUIDE` allows opening the Xbox Game Bar, Steam overlay, or dashboard overlays directly from the keyboard.
- **Walk Speed Modifier**: Configurable `walk` modifier in `wasd_left_stick` scales analog stick magnitude by 0.5 when held.
- **Alt+Tab & Focus-Loss Auto-Release**: Background foreground-window monitoring detects window switching (`Alt+Tab`, Windows key, lock screen, or clicking out) and immediately deactivates capture while resetting all virtual buttons to prevent stuck inputs.
- **F11 Fullscreen Passthrough**: Window monitoring tracks browser process IDs (PID), maintaining active capture when toggling F11 fullscreen in Chrome or Edge across top-level container HWND changes.

---

## Privacy & Security Guarantees

- **No Keylogging**: Keystrokes are mapped strictly in volatile process memory to virtual controller bits. No keystrokes, mouse coordinates, or timings are ever logged, cached to disk, or transmitted over any network socket.
- **Enterprise Profile Validation**:
  - Symlinks are explicitly rejected (`is_symlink()`) to prevent link-traversal attacks.
  - Profiles are capped at **64 KB** to mitigate memory exhaustion.
  - Strict type checking ensures configuration parameters like `invert_y` are boolean literals (avoiding `bool("false") == True` traps).
- **Failsafe Teardown**: Hooks and timers are guarded by `threading.RLock()` and registered with `atexit`, `sys.excepthook`, `SIGINT`/`SIGTERM`, and Windows `SetConsoleCtrlHandler` (`CTRL_CLOSE_EVENT`, `CTRL_SHUTDOWN_EVENT`). Terminating the process or closing the terminal window immediately restores the system cursor and unhooks Win32 callbacks.

---

## System Requirements

- **Operating System**: Windows 10 / 11 (64-bit)
- **Python**: 3.12.0 or newer
- **Kernel Driver**: [ViGEmBus v1.17.333+](https://github.com/nefarius/ViGEmBus/releases)

---

## Installation & Setup

1. **Verify ViGEmBus Driver**:
   ```pwsh
   python driver_check.py
   # Or in headless CI:
   python driver_check.py --ci
   # Service management (with optional UAC auto-elevation):
   python driver_check.py --start-service --elevate
   python driver_check.py --restart-service --elevate
   ```
   Ensure all 5 diagnostics report `[✔] PASS`.

2. **Install Dependencies**:
   ```pwsh
   pip install -r requirements.txt
   ```

3. **Install Development / Test Dependencies (Optional)**:
   ```pwsh
   pip install -e .[dev]
   ```

---

## Usage

Run the mapper with the default profile (`Shooter`):
```pwsh
python main.py
```

### Command-Line Arguments

```
options:
  -h, --help            Show this help message and exit
  --check, -c           Verify system requirements, driver status, and exit
  --ci                  Run in headless CI mode (skips physical driver checks if absent)
  --profile PROFILE, -p PROFILE
                        Initial profile name or filename (default: Shooter, supports normalized match like 'RTS')
  --list-profiles, -l   List all available profiles and exit
  --verbose, -v         Enable detailed diagnostic logging
```

### Hotkeys

| Hotkey | Action |
|---|---|
| `F8` | **Toggle Capture ON / OFF**. When active, all mouse and keyboard inputs are captured and swallowed. |
| `F9` | **Cycle Profiles**. Seamlessly rotates through available profiles (e.g. Shooter $\leftrightarrow$ RTS / Menu) without input drop. |
| `F11` | **Fullscreen Passthrough**. Allows browser and game fullscreen toggling without dropping capture or leaking input. |
| `Alt+Tab` | **Auto-Release & Focus Loss Deactivation**. Automatically deactivates capture and releases all controller buttons on focus switch. |
| `Ctrl+C` | Cleanly release hooks, reset virtual gamepad, and exit. |

---

## Profile Configuration Schema

Profiles are stored as JSON files under `profiles/`.

```json
{
    "name": "Shooter",
    "stick_config": {
        "sensitivity": 0.080,
        "curve_exponent": 1.3,
        "deadzone_comp": 0.18,
        "decay_rate": 0.72,
        "smoothing_alpha": 0.75,
        "invert_y": false
    },
    "wasd_left_stick": {
        "up": 87,
        "down": 83,
        "left": 65,
        "right": 68,
        "walk": "VK_LMENU"
    },
    "buttons": {
        "MOUSE_LEFT": "RT",
        "MOUSE_RIGHT": "LT",
        "MOUSE_MIDDLE": "XUSB_GAMEPAD_RIGHT_THUMB",
        "MOUSE_X1": "XUSB_GAMEPAD_RIGHT_SHOULDER",
        "MOUSE_X2": "XUSB_GAMEPAD_LEFT_SHOULDER",
        "VK_SPACE": "XUSB_GAMEPAD_A",
        "VK_LSHIFT": "XUSB_GAMEPAD_LEFT_THUMB",
        "VK_R": "XUSB_GAMEPAD_X",
        "VK_E": "XUSB_GAMEPAD_Y",
        "VK_C": "XUSB_GAMEPAD_B",
        "VK_F": "XUSB_GAMEPAD_RIGHT_THUMB",
        "VK_Q": "XUSB_GAMEPAD_LEFT_SHOULDER",
        "VK_G": "XUSB_GAMEPAD_RIGHT_SHOULDER",
        "VK_TAB": "XUSB_GAMEPAD_BACK",
        "VK_ESCAPE": "XUSB_GAMEPAD_START",
        "VK_1": "XUSB_GAMEPAD_DPAD_UP",
        "VK_2": "XUSB_GAMEPAD_DPAD_RIGHT",
        "VK_3": "XUSB_GAMEPAD_DPAD_DOWN",
        "VK_4": "XUSB_GAMEPAD_DPAD_LEFT",
        "WHEEL_UP": "XUSB_GAMEPAD_Y",
        "WHEEL_DOWN": "XUSB_GAMEPAD_Y",
        "VK_HOME": "XUSB_GAMEPAD_GUIDE"
    }
}
```

### Parameter Reference

- `sensitivity` *(float > 0)*: Multiplier on raw pixel deltas before smoothing.
- `curve_exponent` *(float > 0)*: Radial power curve ($1.0$ = linear, $1.3$–$1.5$ = precision aim, $2.0$ = soft response).
- `deadzone_comp` *(float $\in [0.0, 0.35]$)*: Minimum radial jump to skip in-game deadzones.
- `decay_rate` *(float $\in [0.0, 1.0]$)*: Auto-recentering factor applied each tick when mouse is idle.
- `smoothing_alpha` *(float $\in (0.0, 1.0]$)*: Exponential moving average weight for new mouse samples ($0.75$ = snappy, $0.35$ = heavy smoothing).
- `invert_y` *(bool)*: Set `true` to invert vertical look (flight sim mode).
- `walk` *(str or int, optional)*: Key in `wasd_left_stick` to scale thumbstick deflection by 0.5 (e.g. `"VK_LMENU"`).

---

## Running the Test Suite

```pwsh
# Run linter
ruff check .

# Run static type checker
mypy driver_check.py input_hooks.py stick_mapper.py profiles.py main.py

# Run unit tests
pytest
```
