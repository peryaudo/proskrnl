#!/usr/bin/env python3
"""check_audio.py -- the AUD-1 WAV verdict (docs/23 section 6a).

Regenerate the guest's deterministic S16 reference sequence from the
parameters in its own "[KTEST] audio playing ..." serial line (the
check_rect.py rule: the guest reports, the host never hardcodes) and assert
the recorded WAV contains it SAMPLE-EXACT as a contiguous byte subsequence.

Property-based, never byte-golden on the file: leading/trailing silence and
the recording's total length are host-scheduling artifacts (the wav backend
consumes on host timers -- the docs/19 section 11c trap), and the kmt SND
suite legitimately plays its own distinct pattern into the same recording
earlier in the boot. Nothing about position, span length, or what surrounds
the reference is asserted -- only that the played span survived, verbatim.

The RIFF/data size fields are never trusted: qemu's wav backend patches them
only at clean teardown (audio/wavaudio.c), and the harness's grace-kill can
outrun the QMP quit. The sample stream is read from the data chunk's start
to EOF instead.
"""

import argparse
import re
import struct
import sys


def parse_playing_line(log_path):
    """The guest's generation parameters, from its own serial report."""
    pattern = re.compile(
        r"\[KTEST\] audio playing seed=([0-9a-f]+) periods=(\d+)"
        r" period_bytes=(\d+) rate=(\d+) ch=(\d+) fmt=s16"
    )
    with open(log_path, "r", errors="replace") as log:
        for line in log:
            match = pattern.search(line)
            if match:
                return {
                    "seed": int(match.group(1), 16),
                    "periods": int(match.group(2)),
                    "period_bytes": int(match.group(3)),
                    "rate": int(match.group(4)),
                    "channels": int(match.group(5)),
                }
    return None


def reference_bytes(seed, total_bytes):
    """The aud_smoke.c LCG, replayed: state' = state * 6364136223846793005 +
    1442695040558665139 (mod 2^64); sample = int16(state' >> 48)."""
    mask = (1 << 64) - 1
    state = seed
    samples = []
    for _ in range(total_bytes // 2):
        state = (state * 6364136223846793005 + 1442695040558665139) & mask
        samples.append((state >> 48) & 0xFFFF)
    return struct.pack("<%dH" % len(samples), *samples)


def wav_data_chunk(wav_path):
    """The data chunk's bytes, read to EOF -- the declared sizes are only
    used to SKIP non-data chunks, never to bound the data itself."""
    with open(wav_path, "rb") as wav:
        blob = wav.read()
    if len(blob) < 12 or blob[0:4] != b"RIFF" or blob[8:12] != b"WAVE":
        return None, "not a RIFF/WAVE file"
    offset = 12
    fmt = None
    while offset + 8 <= len(blob):
        chunk_id = blob[offset : offset + 4]
        (chunk_size,) = struct.unpack_from("<I", blob, offset + 4)
        if chunk_id == b"fmt " and offset + 8 + 16 <= len(blob):
            fmt = struct.unpack_from("<HHIIHH", blob, offset + 8)
        if chunk_id == b"data":
            return blob[offset + 8 :], fmt  # to EOF, deliberately
        offset += 8 + chunk_size + (chunk_size & 1)
    return None, "no data chunk"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True, help="the guest serial log")
    parser.add_argument("--wav", required=True, help="the recorded WAV")
    args = parser.parse_args()

    params = parse_playing_line(args.log)
    if params is None:
        print("check_audio: no '[KTEST] audio playing' line in the log")
        return 1

    data, fmt = wav_data_chunk(args.wav)
    if data is None:
        print("check_audio: %s" % fmt)
        return 1
    if fmt is not None:
        # The leg pins the audiodev to the negotiated format so qemu's
        # mixeng conversion is the identity (docs/23 section 6a); a
        # mismatch here means the leg's pin drifted, not the kernel.
        audio_format, channels, rate, _, _, bits = fmt
        if (audio_format, channels, rate, bits) != (
            1,
            params["channels"],
            params["rate"],
            16,
        ):
            print(
                "check_audio: WAV format %r does not match the negotiated "
                "s16/%dch/%dHz -- the audiodev pin drifted" % (fmt, params["channels"], params["rate"])
            )
            return 1

    reference = reference_bytes(params["seed"], params["periods"] * params["period_bytes"])
    if reference in data:
        print(
            "check_audio: PASS (%d reference bytes found sample-exact in %d recorded)"
            % (len(reference), len(data))
        )
        return 0

    # Diagnosis, not verdict: how much of a prefix survived says whether the
    # stream was truncated or never present at all.
    prefix = len(reference)
    while prefix > 0 and reference[:prefix] not in data:
        prefix //= 2
    print(
        "check_audio: FAIL (reference sequence not in the recording; "
        "longest surviving power-of-two prefix ~%d of %d bytes)" % (prefix, len(reference))
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
