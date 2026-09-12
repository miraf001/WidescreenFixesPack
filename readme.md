# Resident Evil Revelations 2 FusionFix

This is a focused fork of
[ThirteenAG/WidescreenFixesPack](https://github.com/ThirteenAG/WidescreenFixesPack)
for the Windows version of **Resident Evil Revelations 2**. Other game targets
have been removed so the repository, build and releases describe this title
only.

The fork keeps the original widescreen fixes and adds local co-op corrections
developed and tested against the current Steam executable.

## Co-op fixes

- Native keyboard and mouse ownership for player 1 while player 2 remains on a
  gamepad, coordinated with the optional virtual-gamepad bridge.
- Viewport-local ammo, herbs, flashlight and base reticle HUD using the
  single-player proportions.
- Crosshair size and center derived from the owning player's current viewport.
- Adaptive Campaign Inventory and Quick Menu: uniform scaling up to the
  single-player size, shrinking only when the verified content bounds would not
  fit the viewport.
- Correct item preview position and size for both player viewports.
- Correct Quick Menu hotkey assignment block position and scale.
- Viewport-local partner CommandNear and CommandFar indicators for both players.
- Player 1 keyboard `Tab` shows the partner indicator in co-op for about three
  seconds while preserving native character switching in single-player.
- Healing icon, progress ring and fill centered in the owning player's
  viewport.
- Full-height fade-to-black in split screen, derived from the active viewport
  height.
- Story subtitles calibrated to their single-player scale and height: shared
  in side-by-side mode, or duplicated at the centres of two monitors when
  `DualMonitorMode` is enabled.
- Two-monitor presentation mode for equal-width displays: menus, single-player
  gameplay, FMVs and single-view cutscenes render natively into the left half
  and the completed frame is mirrored to the right. Native player 1/player 2
  rendering resumes automatically whenever real split screen is active.
- Dual-monitor pause menu, current objective and contextual help duplicated
  into the second player viewport without modifying the single-monitor path.
- Open story notes duplicated into the second player viewport in dual-monitor
  split screen, with their offset derived from half the live canvas width.
- Mixed input keeps contextual interactions actor-local: player 1 keyboard and
  mouse no longer trigger an action for the gamepad-only second player.

All co-op transforms read the live viewport dimensions. They are not fixed
offsets for one resolution and are designed to work at 16:9 and wider desktop
layouts.

## Install

1. Download the latest release archive.
2. Copy its contents to the Resident Evil Revelations 2 game directory.
3. Keep an ASI loader installed (the release contains the same loader marker
   convention used by WidescreenFixesPack).
4. Review `scripts/ResidentEvilRevelations2.FusionFix.ini` and restart the game
   after changing any `[COOP]` option.

The defaults enable the confirmed co-op fixes. Each major group has a separate
INI rollback switch:

```ini
[COOP]
ViewportHud = 1
NativeKeyboardMousePlayer1 = 1
AdaptiveInventory = 1
PartnerCommandViewport = 1
KeyboardPartnerCommand = 1
DualMonitorMode = 0
```

`DualMonitorMode = 0` preserves the normal single-monitor paths, including one
shared subtitle and one native pause interface. Set it to `1` only when the game
spans two equal-resolution monitors. Outside real split screen, the game uses a
native half-width left viewport with the correct aspect ratio and mirrors that
finished image to the right monitor. During real split screen the mirror is
disabled and the existing player 1/player 2 viewports remain independent; story
subtitles and the pause interface are duplicated where both players need them.
Open story notes are likewise duplicated only during real split screen.
FMV placement, subtitle scaling and all positions are derived from the live
combined resolution rather than fixed 1920/3840 coordinates. A restart is
required after changing this option.

The optional keyboard-to-gamepad bridge is documented in
[DEVELOPMENT.md](DEVELOPMENT.md). Its hotkeys include F7 to briefly unplug and
reconnect both virtual pads, F8 to select the virtual pad, F9 to release/capture
input and Backspace for the emulated Back button.

## Build and test

Requirements: Windows, Git with submodules, Visual Studio C++ x86 build tools,
CMake and Python 3.

```powershell
git submodule update --init --recursive
powershell -ExecutionPolicy Bypass -File tools/test-rerev2-coop-permanent.ps1
powershell -ExecutionPolicy Bypass -File tools/build.ps1 -Configuration Release
```

The package is written to `out/packages/rerev2/release`. A successful compile
is static verification only; GUI and input changes must also pass an in-game
single-player and local co-op test.

## Development history

- [DEVELOPMENT.md](DEVELOPMENT.md) describes the focused workflow and tests.
- [REREV2_RENDERING_NOTES.txt](REREV2_RENDERING_NOTES.txt) is the recovery log
  for the reverse-engineered rendering, inventory, input and partner-command
  behavior.

## Credits and license

Based on WidescreenFixesPack by ThirteenAG and its contributors. The focused
RE:Rev2 co-op work was developed with miraf001. See [license](license) for the
upstream MIT license.
