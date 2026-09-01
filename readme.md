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
```

The optional keyboard-to-gamepad bridge is documented in
[DEVELOPMENT.md](DEVELOPMENT.md). Its hotkeys include F8 to select the virtual
pad, F9 to release/capture input and Backspace for the emulated Back button.

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
