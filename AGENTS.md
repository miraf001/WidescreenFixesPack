# Focused development instructions

- This repository workflow targets Resident Evil Revelations 2 only. Keep all
  build options, documentation, and planned work specific to this title.
- Edit source files under `source/` and configuration under `data/`. Do not edit
  generated files under `build/` or `out/`.
- Build RE:Rev2 Release after relevant changes with `tools/build.ps1`.
- Use `tools/build.ps1 -Configuration Debug` when symbols are needed.
- Keep historical source snapshots under `recovery/`; only the explicit active
  `dllmain.cpp` is part of the focused CMake target.
- Treat a successful compile as a static verification only. Rendering, HUD,
  subtitle and post-processing behavior must still be validated in the game.
- Keep runtime collaboration terminal-only: the user controls the game and
  reports when a test state is ready; Codex builds, deploys, tails logs, captures
  dumps, and attaches CLI instrumentation. Do not use Computer Use for this
  project.
- Prefer reproducible project scripts and repo-local portable CLI tooling under
  ignored `out/toolchain/` over GUI-only reverse-engineering tools.
- Preserve compatibility with the upstream WidescreenFixesPack dependencies and
  keep upstream changes separate from the recovered RE:Rev2 modifications.
