# Focused Resident Evil FusionFix development

This checkout keeps the full WidescreenFixesPack history and dependencies, but
normal development does not require its generated Visual Studio solution. A small
CMake/Ninja build compiles only the Resident Evil Revelations 2 plugin.

## Current scope

Resident Evil Revelations 2 is the sole target of this development checkout.

The recovered RE:Rev2 branch is intended to support side-by-side split screen on:

- one regular 16:9 display; and
- two equal-aspect displays exposed to the game as one wide desktop through
  Eyefinity, SoftTH, or an equivalent tool.

Known RE:Rev2 work items from the original discussion:

1. restore and independently position split-screen subtitles;
2. derive the HUD layout reliably from the active resolution instead of requiring
   manual INI tuning;
3. correct 3D inventory-item placement;
4. render shared cutscenes on one monitor and mirror them to the other;
5. correct the main menu after split screen becomes active;
6. identify and remove the dark/post-process effect over the upper half;
7. audit effects lost in co-op, starting with bullet-impact marks, and make
   verified restorations independently configurable without changing HUD routing.

The generic "SP canvas" HUD experiment was rejected in game on 2026-08-30 and
removed from active source. The previous usable HUD, dual subtitles and fullscreen
menu correction are restored in source. See `REREV2_RENDERING_NOTES.txt` for the
newly identified native per-controller SP/MP branches and the read-only effects
probe. The user confirmed the restored HUD is usable on 2026-08-30. It still uses
the previous empirical MP correction (0.8 horizontal scale and a downward shift
of 0.25 viewport height), with neutral HUD INI tuning; automatic SP-style layout
is not yet implemented.

`[GRAPHICS] DisableCoopEffectFilter=1` removes the additional native co-op
`mExclusionTrait` mask (6 -> 0), preserving per-effect rules. The separate
`RestoreCoopBulletMarks=1` bypasses the native split-screen bullet-mark creation
exit. Both are enabled in this testing INI at the user's request; both require
a restart, not F5. They were built and deployed on 2026-08-30, with code changes
confirmed in process memory. The user subsequently confirmed working bullet-impact
marks and has not noticed objectionable effects so far. Complete effect coverage,
both-camera behavior across scenes, and long-term stability remain unverified.

A reversible live SP-layout experiment for `uGUIEquip`, `uGUIHeal`, and
`uGUIHealNum` is available in `tools/test-rerev2-sp-hud-live.py`. It is pinned to
the currently deployed Debug ASI and does not replace files in the game. See the
rendering notes for the process-specific state/restore command and verification
limits. This is not yet the permanent automatic-HUD implementation.
The live tool's optional `stretch` mode switches explicit uniform-fit selectors
to native independent X/Y scaling in the selected loaded HUD trees; `unstretch`
reverts only that step, and `restore` reverts both steps. This part is currently
instance-local and must be revalidated if co-op recreates the GUI trees.
Because native updates can overwrite that selector, the live test also offers
`maintain-stretch` (three narrow native post-update wrappers) and `refresh-stretch`
(invalidate only those controllers' cached bounds so the engine rebuilds their
GUI trees). `unstretch`/`restore` remove the update wrappers too. Visual validation
is still required; unchanged/stale matrices are not considered a successful test.

The user confirmed Claire's position is correct with this live test, but icons
are vertically stretched; Moira's flashlight meter is a separate `uGUIFlash`
controller and was NOT included. Loaded copies of Equip/Heal are not evidence
that both characters' visible HUDs are covered.
The new `aspect` mode keeps the independent-axis anchor calculation and uses
viewport-height scale on both geometry axes, scoped to the backed-up nodes in
MP. `unaspect` reverts only this addition; `unstretch`/`restore` remove it first.
The user subsequently confirmed Claire's proportions look good. The separate
`tools/test-rerev2-flash-live.py` extension applies the same native SP-layout and
aspect treatment to Moira's `uGUIFlash` node 2. The user says its position looks
right; a direct comparison while controlling Moira in SP is still pending.
Restore Flash FIRST before changing/restoring the parent aspect test: its
geometry hook delegates unmatched nodes to the unchanged Claire hook.

`tools/test-rerev2-input-live.py` is the FAILED auto-selection-only experiment:
keyboard/mouse controlled BOTH actors. It has been restored; do not reapply
alone. The native `actor+7920==0` check is not P1 ownership (both local actors
have zero). Actual actor ID is the byte at `+790C`; primary assignment is
`*(157AE00)+8F8`. Further tests must enforce that assignment in gameplay input
paths as well as enable auto-selection. For testing, release bridge capture
with F9 (keep the two virtual pads connected). All HUD/input live tests
disappear on game exit and are not yet in
the on-disk ASI. Process-specific apply/inspect/restore commands are in the notes.

`tools/test-rerev2-input-owner-live.py` adds the missing per-actor isolation:
28 verified gameplay keyboard predicates additionally compare the actor pointer
with the native primary-assignment slot. Non-primary actors take the existing
gamepad branch; SP and native device auto-selection are retained. It does not
emulate a gamepad, change actor fields, or alter controller joining. This live
version is applied. The user confirmed native keyboard/mouse controls ONLY
player 1, and also confirmed simultaneous Claire keyboard/mouse + Moira pad
movement works. A temporary capture relay coordinates bridge F9 state with
native auto-selection. On 2026-08-31 the user also confirmed that this capture
fix works well. It remains a live helper, not part of the on-disk ASI.
`tools/test-rerev2-input-owner-live-offline.py` executes the small x86 thunks in
Unicorn solely as an OFFLINE CPU test harness (336 cases across 8 tests). Unicorn
is not loaded into the game and never generates game input. Tests check native
flags/registers, SP, reversed assignment, invalid assignments, and write scope.

## Build

The build uses the installed x86 MSVC compiler directly through Ninja. It does not
use MSBuild and therefore avoids the broken `Microsoft.Build.Tasks.Core.dll` in the
current Visual Studio installation. The same VS 2022 installation also contains a
damaged standard-library header, so the script caches the matching official
Microsoft STL `vs-2022-17.14` headers under `out/toolchain/` and places them first
on the compiler include path. It does not modify Visual Studio. After repairing
the installation, `-UseInstalledStl` disables this local header override.

From PowerShell in the repository root:

```powershell
.\tools\build.ps1
```

Useful variants:

```powershell
.\tools\build.ps1 -Configuration Debug
.\tools\build.ps1 -Clean
```

RE:Rev2 release output is packaged under:

```text
out\packages\rerev2\release\
  dinput8.ual
  scripts\
    ResidentEvilRevelations2.FusionFix.asi
    ResidentEvilRevelations2.FusionFix.ini
```

Generated build directories and packages are ignored by Git. The active C++ file
is always `source/ResidentEvilRevelations2.FusionFix/dllmain.cpp`; historical files
are stored under `recovery/` and are not compiled.

## Subtitle diagnostic

`[SUBTITLES]` has independent `OffsetX`, `OffsetY`, `ScaleX`, and `ScaleY`
settings for split-screen only. Single-player preserves the game's original
subtitle transform and placement. Split-screen subtitles use their own dynamic
aspect correction and do not inherit the side-by-side HUD's hardcoded scale or
quarter-screen vertical shift. All HUD and subtitle values reload with F5.

Runtime verification on 2026-08-29 established that the visible single-player
dialogue subtitles are drawn by `uGUITextVoice` using the `txt_voice` resource.
This is the GUI controller that subtitle position and scale tuning must target.
`uBioGUISubtitles` uses the separate `txt_voice_2` resource and changing its GUI
instance coordinates did not move the visible single-player dialogue text.
`uBioGUISubtitlesEx` was observed with the `reticle_scope` resource and must not
be treated as visible dialogue merely because of its class name.

The Debug build writes `ResidentEvilRevelations2.FusionFix.log` next to the ASI.
Its `[SUBTITLES]` records show whether the game routed the subtitle draw through
the left, right, single-screen, or unmatched viewport branch, along with input
and output transform values. `[TUNING]` confirms every initial or F5 reload.
`[SUBTITLE-ACTIVE]` is emitted once per second while the subtitle class requests
its transform and includes the active D3D viewport and scissor state. If the
initialization record exists but no subtitle record appears while dialogue is
visible, the subtitle class-name detection did not intercept that rendering path.

One diagnostic run is enough:

```powershell
.\tools\build.ps1 -Configuration Debug
.\tools\deploy.ps1 -Configuration Debug `
  -GamePath 'G:\Steam\steamapps\common\RESIDENT EVIL REVELATIONS 2' `
  -IncludeSymbols
```

Start the game manually, activate split screen, reach one line of dialogue, and
then exit. Inspect `scripts\ResidentEvilRevelations2.FusionFix.log`. Deployment
automatically backs up a different existing ASI under
`scripts\.fusionfix-backups\`; the existing INI is preserved unless
`-OverwriteIni` is explicitly passed.

## Deploy

Pass the game directory explicitly:

```powershell
.\tools\deploy.ps1 -GamePath 'D:\Games\Resident Evil Revelations 2'
```

Or set `REREV2_GAME_DIR` and omit `-GamePath`. Existing INI files are preserved so
local tuning is not lost. Use `-OverwriteIni` only when the repository copy should
replace it. `-InstallLoader` installs the `dinput8.ual` marker when it is missing,
and `-IncludeSymbols` also copies the PDB for debugging.

Visual Studio remains optional for attaching a debugger to the running game. It is
not required for editing or routine compilation.

## Two virtual controllers from one keyboard

For solo split-screen testing, start the keyboard bridge before starting the
game:

```powershell
.\tools\gamepad-bridge.ps1
```

It creates two persistent virtual Xbox 360 controllers through the already
installed ViGEmBus driver. The same keyboard controls only the active controller.
`F7` physically unplugs both virtual pads for `BRIDGE.DisconnectSeconds` (2 seconds
by default) and then reconnects them automatically. This is useful for exercising
the co-op -> single-view -> co-op transition without stopping the bridge. `F8`
switches between P1 and P2, `F9` temporarily releases or recaptures the mapped
keyboard keys, and `F10` exits and disconnects both controllers. An audible single
or double beep identifies the selected player. `Enter` is the active controller's
Start button, so select P2 with `F8` and press `Enter` to join the second player.

The game assigns whichever controller sent Start to player 2. Consequently,
bridge device numbers are not fixed game-player numbers: either bridge device
can end up controlling Moira. The F2 demo cycle intentionally tries both.

Raw mouse movement controls the active player's right stick. The left and right
mouse buttons map to RT and LT respectively. The wheel maps to D-pad up/down,
while mouse side buttons map to D-pad left/right. Keyboard D-pad taps (`I/J/K/L`)
are latched for 180 ms so short key events remain visible to the game.

Default controls are stored in
`data/ResidentEvilRevelations2.FusionFix/gamepad-bridge.ini`. The bridge suppresses
mapped keys before they reach the game to avoid simultaneous native keyboard
input. Alt-based system shortcuts such as Alt+Tab remain available. Run a
connection-only check with:

```powershell
.\tools\gamepad-bridge.ps1 -SelfTest
```

The launcher downloads and hash-verifies pinned `vgamepad` 0.1.0 source into the
ignored `out/toolchain/gamepad-bridge/` directory and loads only its Python client
and ViGEm client DLL. It does not run the package's bundled driver installer.

For a simultaneous native-keyboard P1 / virtual-pad P2 test, the bridge now
accepts bounded demo commands through its own private message window:

```powershell
python tools/gamepad-bridge-control.py --pid <bridge-python-pid> --command start --game-pid <rerev2-pid> --seconds 120
python tools/gamepad-bridge-control.py --pid <bridge-python-pid> --command stop
```

Starting requires active co-op, releases bridge capture automatically, and
drives only the selected virtual pad. Device order is NOT the in-game actor
order: select the desired device with `--pad 1` / `--pad 2` (CLI default is
`BRIDGE.DemoPad`). The repeating pattern uses gentle movement,
right-stick camera changes and LT; no RT, face buttons, Start or interactions.
It returns neutral when the game is not foreground and stops after the requested
1..300 seconds for CLI starts. The user-requested test-only `F2` cycle is:
**off -> bridge controller 1 -> bridge controller 2 -> off**, repeating.
Movement continues until the next state change; switching neutralizes the
previous pad. Keyboard/mouse remain released in all three states, and starting
requires foreground RE:Rev2 co-op. No controller disconnects are involved.
Do not assume bridge controller 2 means the second game actor.
F8/F9 also cancel the demo before changing keyboard routing. CLI commands
`status`, `release`, and `quit` address only the bridge, never the game UI. The
F7 pulse preserves the current F9 capture/release selection, clears held reports
before unplugging, and performs ViGEm remove/add operations only on the bridge
updater thread so they cannot race controller report updates.
Use `gamepad-bridge.ps1 -StartReleased` to leave native input free at startup.
Updating an already running old bridge requires one bridge restart and rejoining
co-op; the game itself and its live patches need not be restarted. Offline demo
tests: `python tools/test-gamepad-demo.py` (8 tests, no virtual devices created).

### Native mouse versus bridge capture

The game also polls a DirectInput mouse path (`C27987`, state size `0x14`),
so bridge legacy-event suppression alone does not establish exclusive native
versus virtual input. With the confirmed input-owner live experiment loaded,
`tools/sync-rerev2-bridge-capture.py` reads the bridge capture flag every 20 ms.
Only on transitions, it switches the native selector at `98861C` between the
confirmed auto-input path (released) and existing gamepad-only path (captured).
This does not change actor ownership, controller assignments, HUD or F2 logic.
It works without restarting the game or bridge and has no game-thread callbacks.

Use its `--mode inspect` while it is active. Stop it with `--mode stop` BEFORE
restoring the parent input-owner experiment; parent's strict inspector correctly
rejects the temporary capture branch while captured. Normal stop, bridge exit
and IPC timeouts release native input. If the relay is forcibly killed while
captured, run its stop command to restore the exact backed-up branch. This is
a temporary process-bound live test, not yet part of the on-disk ASI.
Offline tests: `python tools/test-rerev2-bridge-capture-offline.py`.

### Reticle viewport test (2026-08-31)

`tools/test-rerev2-reticle-live.py` is a reversible extension for
`uGUIReticleBase` (ordinary weapon reticles), not scope/throw/Natalia classes.
It selects the native SP local layout (640,360, scale 1), maps its position
with the actual viewport's independent X/Y factors, and scales geometry
uniformly by viewport height. Native weapon animations/spread are untouched.
Only this class bypasses the legacy MP HUD render offsets/scale. SP keeps its
original render path. This is not yet integrated into the on-disk ASI.

Last test state: `out/runtime/reticle-live-20260831-01.json`, process 35776.
Restore RETICLE FIRST, then Flash, then Claire HUD. Reticle inspection validates
the whole chained geometry hook; the older parent inspectors correctly reject
the new outer redirect. Geometry identities are instance-bound: recreate the
test from a fresh scan if GUI trees change. Never reuse a state after game exit.

```powershell
python tools/test-rerev2-reticle-live.py --pid 35776 --hud-state out/runtime/sp-hud-live-20260830-01.json --flash-state out/runtime/flash-live-20260830-01.json --state out/runtime/reticle-live-20260831-01.json --mode inspect
# Change --mode to restore to remove only this reticle experiment.
python tools/test-rerev2-reticle-live-offline.py
```

Seven offline tests pass, including native x86 execution of selector and
geometry thunks, SP/unmatched fallback, ABI and write-scope checks. Release
build passed; no game restart or ASI replacement. Live P1 matrix reports
position (480,540) and uniform scale (1.5,1.5) in its 960x1080 viewport,
with a nonzero draw counter. The user subsequently tested the pistol and
reported that everything seems OK. Shotgun testing is deferred until the next
session; other weapons/resolutions and a direct SP comparison are not confirmed.

Session handoff: no cleanup was performed. The folder/recording cleanup request
was sent to the wrong chat and explicitly withdrawn. Do not act on recordings.
Before the next game test, check process identity and restore the confirmed live
setup as needed: HUD -> Flash -> reticle, plus input-owner and capture relay.
Game 35776 and its capture relay were no longer present at the last process
check; bridge 27344 remained running. Recheck rather than assuming that state.
The saved process addresses are historical, not a restartable configuration.

### Persistent co-op HUD and native input (2026-08-31)

The source now includes `CoopRuntime.h` and `CoopNativeCode.h` from the active
`dllmain.cpp`. Build with `tools/build.ps1`. This version was built for the NEXT
launch, not deployed to the currently running game. The game directory still
contains the previous Debug ASI; process 25124 uses restored live experiments.

Restart-only `[COOP]` options, enabled by default:

- `ViewportHud=1`: SP local layout for Equip, Heal, HealNum, Flash, ReticleBase.
  Node positions use viewport width/height independently, geometry uses viewport
  height uniformly. Only these classes bypass the old HUD X scale/Y offset.
  Native controller/node-table identity replaces session-specific addresses;
  native updates restore selector 5 in SP and maintain selector 2 in co-op.
- `NativeKeyboardMousePlayer1=1`: the exact 29 tested actor-ownership predicates
  plus native auto-device selection. No global actor state/device assignments
  are overwritten. The pad pressing Start remains assigned to player 2.
  The ASI's background tuning thread reads the existing bridge status IPC;
  F9 captured selects gamepad-only, released enables native P1 input. Missing or
  unresponsive bridge releases native input. No external capture relay is needed
  with this new ASI; do not apply the old live scripts on top of it.

Inventory, action prompts, other reticle classes and untested characters are
not implicitly added to the five-class HUD fix. Existing `[HUD]` fine tuning
continues to affect the legacy GUI paths, not these five classes. Subtitles,
menus, bullet marks and effect-filter settings remain unchanged.

`tools/test-rerev2-coop-permanent.ps1` compiles the actual C++ code generator,
checks all 29 input thunks against the accepted live bytes, executes their CPU
tests, and tests dynamic HUD ownership, rebuilt nodes, viewport aspect ratios,
register/flag preservation, native fallbacks and capture branches. It never
opens the game or creates a virtual controller. These tests and a successful
Release build do not replace first-launch rendering/input validation.

Current live state files all use suffix `20260831-03.json`: `sp-hud-live`,
`flash-live`, `reticle-live`, `input-owner-live`, `bridge-capture` under
`out/runtime/`. Game PID 25124, identity 134326821210490783; bridge PID 27344;
capture relay PID 53160. Restore order remains relay before input, and reticle
before Flash before HUD. Recheck process identity before any subsequent work.
Checkpoint: `recovery/checkpoints/2026-08-31-before-permanent-hud-input/`.

### Dual-monitor non-split renderer candidate (2026-09-08)

`DualMonitorMode=1` now installs a guarded D3D9/native-layout state machine.
Outside real split screen, it asks the game's own single-view layout builder to
construct a `W/2 x H` left viewport, restores the physical renderer dimensions
immediately afterwards, and copies the completed left backbuffer half to the
right immediately before `Present`. On entry to real split screen it restores
the full logical canvas, rebuilds the native two-player layout once, stops the
final-frame copy, and thereafter leaves both native screen slots alone.

Retained default-pool surfaces are released before `Reset`. The backbuffer is
revalidated after reset, on split/non-split transitions, after a failed copy,
and periodically every 300 non-split presents. This avoids both stale-surface
blinking and the per-frame `GetBackBuffer` overhead used during live diagnosis.
FMVs use the existing exact WMV draw hook to map the quad into the left half;
only TextVoice draws adjacent to a detected FMV frame receive the matching
horizontal scale. Ordinary SP and in-engine TextVoice already use the W/2-local
canvas and must not receive a second 0.5 scale.

In true split screen, `uGUIActionIcon2` alone selects its SP-local layout and
bypasses the legacy generic co-op rescale. The world-attached `uGUIActionIcon`
is unchanged. Dual pause replay covers `uGUICommonMenu`, `uGUIPurpose` and
`uGUIGuide`. Their cached bounds may be either canonical or exactly one
viewport translated after a replay; both are accepted, and the original cache
is restored immediately after the right-hand pass to prevent alternating-frame
flicker. Active story `uGUIFileText` notes are also replayed once at a dynamic
`physicalWidth / 2` offset during true split screen. The exact class, active
state and dual/split guards keep cached notes and single-monitor/SP paths native;
the source X coordinate is restored synchronously after the right-hand draw.

Release verification remains an in-game task. At minimum test main menu/SP
mirroring, an FMV with subtitles, an in-engine single-view cutscene, transition
into and out of co-op, the independent P2 viewport, fixed HUD action prompt,
and a non-blinking duplicated pause menu. The game INI must use
`DualMonitorMode=1`; the packaged default remains safely disabled.
