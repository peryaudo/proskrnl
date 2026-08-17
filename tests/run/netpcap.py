#!/usr/bin/env python3
"""netpcap.py — content assertions over the net leg's filter-dump pcap
(tests/run/run.sh net; docs/24 §6b).

The pcap is networking's screendump: QEMU's own device model recorded
every frame on the guest's wire (net/dump.c in the pinned tree), so the
assertions below convict the kernel's account of itself against an
external witness (Art. 6). Everything asserted is CONTENT — a frame with
our MAC, the DHCP DISCOVER/REQUEST exchange, the ACK's yiaddr matching
the serial-reported lease, the echo payload in both directions. Nothing
is byte-golden, counted, ordered beyond protocol necessity, or timed:
packet timing and slirp's TCP segmentation choices are host-scheduling
artifacts (the docs/19 §11c trap class).

stdlib only. Usage:
    netpcap.py <pcap> --src-mac aa:bb:cc:dd:ee:ff --dhcp-yiaddr 10.0.2.15 \
               --payload <ascii-string>
Exits 0 with a one-line summary when every assertion holds; exits 1
naming the first missing fact otherwise.
"""

import argparse
import struct
import sys

ETHERTYPE_IPV4 = 0x0800
IPPROTO_UDP = 17
IPPROTO_TCP = 6
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
# BOOTP layout (RFC 951 / RFC 2131): yiaddr at offset 16, options after the
# 236-byte fixed header + the 4-byte magic cookie. Option 53 is the DHCP
# message type (RFC 2132): 1 DISCOVER, 3 REQUEST, 5 ACK.
BOOTP_YIADDR_OFFSET = 16
BOOTP_OPTIONS_OFFSET = 240
DHCP_OPT_MSG_TYPE = 53
DHCP_DISCOVER = 1
DHCP_REQUEST = 3
DHCP_ACK = 5


def frames(path):
    with open(path, "rb") as handle:
        data = handle.read()
    if len(data) < 24:
        sys.exit("netpcap: %s is not a pcap (too short)" % path)
    magic = struct.unpack("<I", data[:4])[0]
    if magic == 0xA1B2C3D4 or magic == 0xA1B23C4D:
        endian = "<"
    elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
        endian = ">"
    else:
        sys.exit("netpcap: %s has no pcap magic" % path)
    offset = 24
    out = []
    while offset + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[offset : offset + 16])
        out.append(data[offset + 16 : offset + 16 + incl])
        offset += 16 + incl
    return out


def parse_mac(text):
    parts = text.strip().split(":")
    if len(parts) != 6:
        sys.exit("netpcap: bad mac %r" % text)
    return bytes(int(p, 16) for p in parts)


def ipv4_payload(frame, protocol):
    """(src_port, dst_port, l4_payload) for a matching IPv4 frame, else None."""
    if len(frame) < 34 or struct.unpack(">H", frame[12:14])[0] != ETHERTYPE_IPV4:
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[23] != protocol or len(frame) < 14 + ihl + 4:
        return None
    l4 = frame[14 + ihl :]
    src_port, dst_port = struct.unpack(">HH", l4[:4])
    if protocol == IPPROTO_TCP:
        if len(l4) < 20:
            return None
        data_off = ((l4[12] >> 4) & 0xF) * 4
        return (src_port, dst_port, l4[data_off:])
    return (src_port, dst_port, l4[8:])


def dhcp_message_type(bootp):
    if len(bootp) < BOOTP_OPTIONS_OFFSET:
        return None
    options = bootp[BOOTP_OPTIONS_OFFSET:]
    i = 0
    while i + 1 < len(options):
        opt = options[i]
        if opt == 255:
            return None
        if opt == 0:
            i += 1
            continue
        length = options[i + 1]
        if opt == DHCP_OPT_MSG_TYPE and length == 1:
            return options[i + 2]
        i += 2 + length
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    parser.add_argument("--src-mac", required=True)
    parser.add_argument("--dhcp-yiaddr", required=True)
    parser.add_argument("--payload", required=True)
    args = parser.parse_args()

    mac = parse_mac(args.src_mac)
    yiaddr = bytes(int(p) for p in args.dhcp_yiaddr.strip().split("."))
    payload = args.payload.encode("ascii")

    ours = 0
    discover = request = 0
    ack_yiaddr_match = 0
    echo_from_guest = echo_to_guest = 0

    for frame in frames(args.pcap):
        if len(frame) < 14:
            continue
        from_guest = frame[6:12] == mac
        if from_guest:
            ours += 1

        udp = ipv4_payload(frame, IPPROTO_UDP)
        if udp is not None:
            src_port, dst_port, bootp = udp
            if from_guest and src_port == DHCP_CLIENT_PORT and dst_port == DHCP_SERVER_PORT:
                kind = dhcp_message_type(bootp)
                if kind == DHCP_DISCOVER:
                    discover += 1
                elif kind == DHCP_REQUEST:
                    request += 1
            if src_port == DHCP_SERVER_PORT and dst_port == DHCP_CLIENT_PORT:
                if dhcp_message_type(bootp) == DHCP_ACK and len(bootp) >= 20:
                    if bootp[BOOTP_YIADDR_OFFSET : BOOTP_YIADDR_OFFSET + 4] == yiaddr:
                        ack_yiaddr_match += 1

        tcp = ipv4_payload(frame, IPPROTO_TCP)
        if tcp is not None and payload in tcp[2]:
            if from_guest:
                echo_from_guest += 1
            else:
                echo_to_guest += 1

    checks = [
        (ours > 0, "no frame carries the guest MAC as Ethernet source"),
        (discover > 0, "no DHCP DISCOVER from the guest"),
        (request > 0, "no DHCP REQUEST from the guest"),
        (
            ack_yiaddr_match > 0,
            "no DHCP ACK offering the serial-reported address %s" % args.dhcp_yiaddr,
        ),
        (echo_from_guest > 0, "echo payload never left the guest"),
        (echo_to_guest > 0, "echo payload never came back from the host"),
    ]
    for passed, what in checks:
        if not passed:
            sys.exit("netpcap: FAIL — %s" % what)
    print(
        "netpcap: ok (guest-src frames=%d discover=%d request=%d ack=%d "
        "echo out/in=%d/%d)"
        % (ours, discover, request, ack_yiaddr_match, echo_from_guest, echo_to_guest)
    )


if __name__ == "__main__":
    main()
