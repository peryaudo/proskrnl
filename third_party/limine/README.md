# third_party/limine

Vendored, pinned kernel-facing header for the Limine boot protocol (ADR 0010).

- `limine.h` — from `limine-bootloader/limine-protocol`, `include/limine.h`,
  pinned at commit `630686a3dd3ce40f9e510a7dd9fea6b4c60d952e` (no tagged release
  exists yet; the repo has only a `trunk` branch). License: **0BSD** (see the
  file header) — no attribution obligation, clean for `docs/11`.

The bootloader binaries and the `limine` deploy tool come from Homebrew
(`brew "limine"`, currently 12.4.2); `tools/mkimage.sh` reads them from
`$(brew --prefix limine)/share/limine`. Keep this header's protocol base
revision (3) in step with the installed Limine major version.
