#!/usr/bin/env bash
# fetch_third_party.sh — restore the pinned third_party builds from the
# GitHub release cache instead of building them (hours) from source.
#
# CI (.github/workflows/test.yml) publishes the finished build trees
#
#   third_party/limine        third_party/qemu/build        third_party/wine
#
# as zstd tarballs on the rolling `third-party-cache` prerelease, named by
# the same submodule-pin key its Actions cache uses (git ls-tree over
# third_party — the pins ARE the key, so a restore can never version-drift
# from the tree abi/ is generated from). This script is the download side:
# ephemeral containers (Claude Code on the web, fresh CI-like boxes) run
#
#   tools/fetch_third_party.sh && tools/setup_linux.sh
#
# and setup_linux.sh's idempotent skip-logic no-ops every build. If the
# release has no assets for the current pins (first run after a pin bump,
# or the publish hasn't happened yet) this FAILS LOUDLY with exit 1 rather
# than falling back to a multi-hour source build — callers with a time
# budget (web environment setup scripts) must fail fast, and callers
# without one can just run setup_linux.sh.
#
# Idempotent per component: already-restored (or already-built) trees are
# skipped. GITHUB_TOKEN/GH_TOKEN are used for the API call when set.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

REPO="${PROSKRNL_REPO:-peryaudo/proskrnl}"
TAG="third-party-cache"

SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    SUDO="sudo"
fi

# The pins are the key — must match the computation in test.yml exactly.
KEY="$(git ls-tree HEAD third_party | sha256sum | cut -c1-16)"
echo "== third_party cache key: $KEY =="

# .gitmodules pins third_party/wine by SSH URL; an ephemeral container has
# no SSH key, so route github.com submodule fetches over HTTPS (same trick
# as test.yml). ALL submodules, no path list — this doubles as the session's
# submodule init. Init BEFORE extracting — git refuses to clone into a
# non-empty directory, so the tarballs must overlay the checkouts, not
# precede them.
echo "== pinned submodules =="
git config --global url."https://github.com/".insteadOf "git@github.com:"
git submodule update --init --depth 1

# CI packs the trees from the runner's workspace, and qemu's build dir links
# its firmware bundle (qemu-bundle/.../bios-256k.bin etc.) by ABSOLUTE path
# into that workspace — dangling on any machine with a different checkout
# path ("qemu: could not load PC BIOS 'bios-256k.bin'"). Re-root every broken
# absolute link that points into a third_party tree onto this checkout. Runs
# on the already-present path too: a tree restored elsewhere (environment
# snapshot, older script) may still carry the build machine's paths.
RerootSymlinks() {
    echo "== re-rooting absolute symlinks from the build machine's path =="
    local rerooted=0 link tgt
    while IFS= read -r link; do
        tgt="$(readlink "$link")"
        case "$tgt" in
            /*/third_party/*)
                ln -sfn "$ROOT/third_party/${tgt#*/third_party/}" "$link"
                rerooted=$((rerooted + 1))
                ;;
        esac
    done < <(find third_party -xtype l 2>/dev/null)
    echo "   $rerooted re-rooted"
    # Links into meson-downloaded qemu subprojects (bundle include/ headers)
    # stay dangling — those sources exist only on the build machine and are
    # never needed at runtime. Only the firmware bundle (share/qemu) is
    # load-bearing: qemu refuses to boot without it, so that stays fatal.
    local stillBroken
    stillBroken="$(find third_party -xtype l 2>/dev/null)"
    if grep -q "/share/qemu/" <<<"$stillBroken"; then
        echo "fetch_third_party: qemu firmware symlinks remain broken:" >&2
        grep "/share/qemu/" <<<"$stillBroken" | head -5 >&2
        exit 1
    fi
    if [[ -n "$stillBroken" ]]; then
        echo "   note: non-runtime links left dangling (build-only headers):"
        head -3 <<<"$stillBroken" | sed 's/^/     /'
    fi
}

# component name (in asset filenames) -> finished-build marker, the same
# markers setup_linux.sh's skip-logic tests. wine's marker is the pass-2
# test exe: the tarball holds both wine passes, so pass 2 present => whole
# tree present.
declare -A MARKER=(
    [limine]="third_party/limine/limine"
    [qemu-build]="third_party/qemu/build/qemu-system-x86_64"
    [wine]="third_party/wine/dlls/ntdll/tests/x86_64-windows/ntdll_test.exe"
)
COMPONENTS=(limine qemu-build wine)

missing=()
for c in "${COMPONENTS[@]}"; do
    if [[ -e "${MARKER[$c]}" ]]; then
        echo "== $c: already present — skipping =="
    else
        missing+=("$c")
    fi
done
if [[ ${#missing[@]} -eq 0 ]]; then
    RerootSymlinks
    echo "fetch_third_party: everything already present."
    exit 0
fi

if ! command -v zstd >/dev/null 2>&1; then
    echo "== apt: zstd (needed to unpack the cache tarballs) =="
    $SUDO apt-get update -qq
    $SUDO apt-get install -y --no-install-recommends zstd
fi

AUTH=()
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
if [[ -n "$TOKEN" ]]; then
    AUTH=(-H "Authorization: Bearer $TOKEN")
fi

echo "== release assets: $REPO @ $TAG =="
release_json="$(curl -fsSL --retry 3 "${AUTH[@]}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/releases/tags/$TAG")" || {
    echo "fetch_third_party: release '$TAG' not found on $REPO." >&2
    echo "  It is published by the test workflow on pushes to main;" >&2
    echo "  until then, build from source with tools/setup_linux.sh." >&2
    exit 1
}

# name<TAB>url per asset, sorted so multi-part tarballs concatenate in order.
assets="$(python3 -c '
import json, sys
for a in json.load(sys.stdin).get("assets", []):
    print(a["name"] + "\t" + a["browser_download_url"])
' <<<"$release_json" | sort)"

# The tarballs hold binaries linked against the builder's glibc and shared
# libraries, so the restoring distro must match the building distro
# (test.yml pins ubuntu-24.04). The publish step uploads the per-key
# distro.txt LAST, so its presence also proves the key's asset set is
# complete — treat its absence as a miss, and a different distro as fatal.
distro_url="$(awk -F'\t' -v n="tp-v2-$KEY-distro.txt" '$1 == n { print $2 }' <<<"$assets")"
if [[ -z "$distro_url" ]]; then
    echo "fetch_third_party: no complete asset set for the current pins ($KEY)." >&2
    echo "  Either the pins were just bumped and CI on main has not" >&2
    echo "  republished yet, or this branch's pins differ from main's." >&2
    echo "  Build from source instead: tools/setup_linux.sh" >&2
    exit 1
fi
build_distro="$(curl -fsSL --retry 3 "$distro_url")"
local_distro="$(. /etc/os-release && echo "$ID-$VERSION_ID")"
if [[ "$build_distro" != "$local_distro" ]]; then
    echo "fetch_third_party: cache was built on $build_distro but this is" >&2
    echo "  $local_distro — the binaries would link against the wrong" >&2
    echo "  glibc/shared libraries. Either move the CI runner and this" >&2
    echo "  container to the same distro release, or build from source:" >&2
    echo "  tools/setup_linux.sh" >&2
    exit 1
fi
echo "== distro match: $build_distro =="

for c in "${missing[@]}"; do
    prefix="tp-v2-$KEY-$c.tar.zst.part"
    parts="$(grep "^$prefix" <<<"$assets" || true)"
    if [[ -z "$parts" ]]; then
        echo "fetch_third_party: no '$prefix*' assets for the current pins." >&2
        echo "  Either the pins were just bumped and CI on main has not" >&2
        echo "  republished yet, or this branch's pins differ from main's." >&2
        echo "  Build from source instead: tools/setup_linux.sh" >&2
        exit 1
    fi
    echo "== $c: downloading $(wc -l <<<"$parts") part(s) =="
    # Stream the concatenated parts straight into tar — no staging disk.
    # The part list came from one API snapshot, so the sequence is complete;
    # a truncated download corrupts the zstd stream and tar fails the script.
    while IFS=$'\t' read -r name url; do
        echo "   $name" >&2
        curl -fSL --retry 3 "$url"
    done <<<"$parts" | tar --zstd -xf - -C "$ROOT"
    [[ -e "${MARKER[$c]}" ]] || {
        echo "fetch_third_party: extracted $c but marker ${MARKER[$c]} is missing" >&2
        exit 1
    }
done

RerootSymlinks

echo
echo "fetch_third_party: done. Next:"
echo "  tools/setup_linux.sh        # apt toolchain; restored builds are skipped"
