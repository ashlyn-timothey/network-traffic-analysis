"""Validated readers for classic PCAP and PCAPNG capture files."""

import struct
from collections.abc import Iterator

from .models import PacketRecord

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET = 1


class CaptureError(ValueError):
    """Raised when a capture is truncated, malformed, or unsupported."""


def iter_capture_packets(data: bytes) -> Iterator[PacketRecord]:
    if len(data) < 4:
        raise CaptureError("file is too short to contain a PCAP or PCAPNG header")
    if data[:4] in PCAP_MAGICS:
        yield from _read_pcap(data)
    elif data[:4] == PCAPNG_SHB:
        yield from _read_pcapng(data)
    else:
        raise CaptureError("not a pcap or pcapng file")


def read_packets(path: str) -> Iterator[tuple[float, int, bytes]]:
    """Compatibility reader yielding the original (timestamp, linktype, bytes) tuples."""
    with open(path, "rb") as capture:
        data = capture.read()
    for packet in iter_capture_packets(data):
        yield packet.timestamp, packet.linktype, packet.raw


def _read_pcap(data: bytes) -> Iterator[PacketRecord]:
    endian, units_per_second = PCAP_MAGICS[data[:4]]
    if len(data) < 24:
        raise CaptureError("truncated PCAP global header")

    major, minor, _, _, snaplen, network = struct.unpack(
        endian + "HHIIII", data[4:24]
    )
    if major != 2 or minor < 4:
        raise CaptureError(f"unsupported PCAP version {major}.{minor}")
    if snaplen == 0:
        raise CaptureError("PCAP snap length must be greater than zero")

    linktype = network & 0xFFFF
    position = 24
    packet_number = 0
    while position < len(data):
        if len(data) - position < 16:
            raise CaptureError("truncated PCAP packet record header")
        seconds, fraction, captured_len, original_len = struct.unpack(
            endian + "IIII", data[position : position + 16]
        )
        position += 16
        if fraction >= units_per_second:
            raise CaptureError("PCAP packet timestamp fraction is out of range")
        if captured_len > original_len:
            raise CaptureError("PCAP captured packet length exceeds original length")
        if captured_len > snaplen:
            raise CaptureError("PCAP captured packet length exceeds snap length")
        end = position + captured_len
        if end > len(data):
            raise CaptureError("truncated PCAP packet data")

        packet_number += 1
        yield PacketRecord(
            seconds + fraction / units_per_second,
            linktype,
            data[position:end],
            packet_number,
        )
        position = end


def _read_pcapng(data: bytes) -> Iterator[PacketRecord]:
    position = 0
    endian = "<"
    interfaces: list[tuple[int, float]] = []
    packet_number = 0
    saw_section = False

    while position < len(data):
        if len(data) - position < 12:
            raise CaptureError("truncated PCAPNG block header")
        if data[position : position + 4] == PCAPNG_SHB:
            byte_order = data[position + 8 : position + 12]
            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureError("invalid PCAPNG byte-order magic")
            interfaces = []
            saw_section = True

        if not saw_section:
            raise CaptureError("PCAPNG data does not begin with a section header")

        block_type, block_len = struct.unpack(
            endian + "II", data[position : position + 8]
        )
        if block_len < 12 or block_len % 4:
            raise CaptureError("invalid PCAPNG block length")
        end = position + block_len
        if end > len(data):
            raise CaptureError("truncated PCAPNG block")
        trailing_len = struct.unpack(endian + "I", data[end - 4 : end])[0]
        if trailing_len != block_len:
            raise CaptureError("PCAPNG block length does not match trailing length")

        body = data[position + 8 : end - 4]
        if block_type == 0x0A0D0D0A:
            if len(body) < 16:
                raise CaptureError("truncated PCAPNG section header")
            major, minor = struct.unpack(endian + "HH", body[4:8])
            if major != 1:
                raise CaptureError(f"unsupported PCAPNG version {major}.{minor}")
            interfaces = []
        elif block_type == 1:
            if len(body) < 8:
                raise CaptureError("truncated PCAPNG interface description")
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _timestamp_unit(body[8:], endian)))
        elif block_type == 6:
            if len(body) < 20:
                raise CaptureError("truncated PCAPNG enhanced packet block")
            interface_id, high, low, captured_len, original_len = struct.unpack(
                endian + "IIIII", body[:20]
            )
            padded_len = (captured_len + 3) & ~3
            if 20 + padded_len > len(body):
                raise CaptureError("truncated PCAPNG packet data")
            if captured_len > original_len:
                raise CaptureError(
                    "PCAPNG captured packet length exceeds original length"
                )
            if interface_id >= len(interfaces):
                raise CaptureError("PCAPNG packet references an unknown interface")
            linktype, unit = interfaces[interface_id]
            raw_timestamp = (high << 32) | low
            packet_number += 1
            yield PacketRecord(
                raw_timestamp * unit,
                linktype,
                body[20 : 20 + captured_len],
                packet_number,
            )
        position = end


def _timestamp_unit(options: bytes, endian: str) -> float:
    position = 0
    while position < len(options):
        if len(options) - position < 4:
            raise CaptureError("truncated PCAPNG interface option")
        code, length = struct.unpack(endian + "HH", options[position : position + 4])
        position += 4
        if code == 0:
            if length != 0:
                raise CaptureError("invalid PCAPNG end-of-options marker")
            return 1e-6
        padded_len = (length + 3) & ~3
        if position + padded_len > len(options):
            raise CaptureError("truncated PCAPNG interface option value")
        if code == 9:
            if length != 1:
                raise CaptureError("invalid PCAPNG timestamp resolution option")
            resolution = options[position]
            exponent = resolution & 0x7F
            return (
                2.0 ** -exponent
                if resolution & 0x80
                else 10.0 ** -exponent
            )
        position += padded_len
    return 1e-6
