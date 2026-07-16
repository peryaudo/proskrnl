# ADR 0008 — Wine's desktop before the ReactOS shell

**Status:** Accepted

## Context
A "desktop" can come from Wine's `programs/explorer` (a wallpaper window, tray, simple file
browser — no taskbar/Start menu/icons) or from ReactOS's full shell. ReactOS's explorer is
written against ReactOS's shell32 across an **undocumented same-vendor internal seam**; the
two are a set and cannot be mixed with Wine's shell32. Taking the ROS shell forces ROS
shell32 onto Wine's user32/gdi32 — an untested combination — plus a version mismatch (NT 5.2
vs Win10), build-extraction from ReactOS's build system, and a GPL/LGPL map.

## Decision
Use Wine's desktop first. Initialize the registry at runtime via Wine's `wineboot.exe`
(which calls our `NtCreateKey`, doubling as the Cm integration test), so no hive-generation
tool is needed. The ReactOS shell is an optional later milestone (M17) governed by a
`user/dllmap.toml` collision map, done only after Wine's desktop provides a regression
baseline.

## Consequences
- Deletes the entire two-upstream integration risk from the critical path.
- The golden artifact is a wallpaper rectangle + file window — modest, but reached cheaply
  and with upstream-tested components.
- Window frames/close/minimize buttons work regardless (USER's job, not the shell's).
- Gives up a Windows-looking desktop initially. Accepted; it is additive later.
