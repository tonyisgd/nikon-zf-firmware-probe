#!/usr/bin/env python3
"""Experimental Nikon Zf firmware format probe and guarded legacy-XOR decoder.

This is a research utility, not a validated Zf decryptor. It uses the publicly
documented legacy Nikon XOR format as a hypothesis, with a configurable body
label offset. It writes a decoded file only after module-directory and CRC
checks pass.

The optional table JSON format is this script's own simple format:
{"t1": [256 integers], "t2": [256 integers], "t3": [256 integers]}.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path


LABEL = b" " * 32
DEFAULT_LABEL_OFFSET = 0x260


def crc16_nikon(data: bytes) -> int:
    """CRC-16/CCITT with poly 0x1021, init 0, no reflection/final xor."""
    crc = 0
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def load_tables(path: Path) -> tuple[bytes, bytes, bytes]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    tables = []
    for name in ("t1", "t2", "t3"):
        values = obj.get(name)
        if not isinstance(values, list) or len(values) != 256:
            raise ValueError(f"{name} must be a list of exactly 256 byte values")
        if any(not isinstance(v, int) or v < 0 or v > 255 for v in values):
            raise ValueError(f"{name} contains a value outside 0..255")
        tables.append(bytes(values))
    return tuple(tables)  # type: ignore[return-value]


def decode_legacy_xor(raw: bytes, label_offset: int, tables: tuple[bytes, bytes, bytes]) -> bytes:
    if raw[label_offset:label_offset + 32] != LABEL:
        raise ValueError(f"32-space label is not present at 0x{label_offset:x}")
    t1, t2, t3 = tables
    out = bytearray(raw)
    # Legacy tool's i is the body-relative position; label starts at body offset 0.
    for file_offset in range(label_offset + 0x20, len(raw)):
        i = file_offset - label_offset
        out[file_offset] ^= t1[i & 0xFF] ^ t2[(i >> 8) & 0xFF] ^ t3[(i >> 16) & 0xFF]
    return bytes(out)


def validate_container(data: bytes, label_offset: int) -> list[str]:
    """Validate the legacy module directory, chained extents and CRCs."""
    body = data[label_offset:]
    if body[:32] != LABEL:
        raise ValueError("plaintext label mismatch")
    if len(body) < 0x50:
        raise ValueError("body is too short for a module directory")
    count, directory_size = struct.unpack_from(">II", body, 0x20)
    if not (1 <= count <= 128):
        raise ValueError(f"implausible module count: {count}")
    expected_directory_size = 48 + count * 32
    if directory_size != expected_directory_size:
        raise ValueError(f"directory size {directory_size} != expected {expected_directory_size}")
    if body[0x28:0x30] != bytes(8):
        raise ValueError("directory reserved bytes are not zero")
    if 0x30 + count * 32 > len(body) - 16:
        raise ValueError("module directory extends past the package body")

    names: list[str] = []
    cursor = directory_size
    for i in range(count):
        entry_at = 0x30 + i * 32
        entry = body[entry_at:entry_at + 32]
        name_bytes = entry[:16].split(b"\0", 1)[0]
        try:
            name = name_bytes.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError(f"module {i} name is not ASCII") from exc
        offset, length = struct.unpack_from(">II", entry, 16)
        if entry[24:32] != bytes(8):
            raise ValueError(f"module {i} reserved bytes are not zero")
        if not name or length < 2 or offset != cursor or offset + length > len(body) - 16:
            raise ValueError(f"module {i} has invalid name/offset/length")
        module = body[offset:offset + length]
        if crc16_nikon(module) != 0:
            raise ValueError(f"module {name} CRC failed")
        names.append(name)
        cursor += length

    if cursor != len(body) - 16:
        raise ValueError("module extents do not end at the 16-byte package trailer")
    stored_package_crc = int.from_bytes(body[-16:-14], "big")
    if crc16_nikon(body[:-16]) != stored_package_crc:
        raise ValueError("package CRC failed")
    if body[-14:] != bytes(14):
        raise ValueError("package trailer padding is not zero")
    return names


def normalized_padding_probe(paths: list[Path], label_offset: int) -> tuple[int, int]:
    """Count repeated normalized sectors at different offsets.

    The legacy extractor's constant-fill padding technique predicts that a
    sector normalized by its first byte repeats at multiple body offsets.
    Identical sectors at the same offset in different releases do not count.
    """
    first_position: dict[bytes, int] = {}
    repeated_elsewhere: set[bytes] = set()
    sectors_seen = 0
    for path in paths:
        data = path.read_bytes()
        if data[label_offset:label_offset + 32] != LABEL:
            continue
        body = data[label_offset:]
        for j, start in enumerate(range(0x20, len(body) - 255, 256)):
            sector = body[start:start + 256]
            signature = hashlib.sha256(bytes(b ^ sector[0] for b in sector)).digest()
            position = j
            old = first_position.get(signature)
            if old is None:
                first_position[signature] = position
            elif old != position:
                repeated_elsewhere.add(signature)
            sectors_seen += 1
    return len(repeated_elsewhere), sectors_seen


def inspect(paths: list[Path], label_offset: int) -> int:
    valid_paths = []
    print(f"Candidate plaintext label offset: 0x{label_offset:x}")
    for path in paths:
        data = path.read_bytes()
        label_ok = data[label_offset:label_offset + 32] == LABEL
        print(
            f"{path.name}: bytes={len(data):,}, sha256={hashlib.sha256(data).hexdigest()}, "
            f"label={'yes' if label_ok else 'no'}"
        )
        if label_ok:
            valid_paths.append(path)
    if not valid_paths:
        print("No input has the expected label at that offset.")
        return 2
    repeat_count, sectors_seen = normalized_padding_probe(valid_paths, label_offset)
    print(
        f"Legacy-XOR padding signal: repeated normalized sectors at different offsets "
        f"= {repeat_count}; sectors scanned = {sectors_seen:,}."
    )
    if repeat_count == 0:
        print(
            "The public legacy T1/T2/T3 table-recovery assumption was not observed. "
            "This does not rule out every XOR variant, but it is not enough to derive keys."
        )
    else:
        print("Some legacy-style padding evidence exists; it still does not recover tables by itself.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", nargs="+", type=Path, help="one or more user-supplied Nikon .bin files")
    parser.add_argument("--label-offset", type=lambda v: int(v, 0), default=DEFAULT_LABEL_OFFSET)
    parser.add_argument("--tables", type=Path, help="JSON with t1/t2/t3 arrays; applies the legacy XOR hypothesis")
    parser.add_argument("--output", type=Path, help="write decoded bytes only after structure and CRC validation")
    args = parser.parse_args()
    if args.tables:
        if len(args.firmware) != 1 or not args.output:
            parser.error("--tables requires exactly one firmware input and --output")
        raw = args.firmware[0].read_bytes()
        tables = load_tables(args.tables)
        decoded = decode_legacy_xor(raw, args.label_offset, tables)
        names = validate_container(decoded, args.label_offset)
        args.output.write_bytes(decoded)
        print(f"Validated {len(names)} modules; decoded image written to {args.output}")
        print("Modules:", ", ".join(names))
        return 0
    if args.output:
        parser.error("--output is only valid together with --tables")
    return inspect(args.firmware, args.label_offset)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
