#!/usr/bin/env python3
"""Extract <ROMFILE> XML payloads from router backup files.

This utility is intended for legitimate recovery and audit of configuration
backups from devices you own or are explicitly authorized to administer.
"""

from __future__ import annotations

import argparse
import base64
import bz2
import gzip
import hashlib
import lzma
import sys
import zlib
from pathlib import Path
from typing import Iterable
from xml.dom import minidom
from xml.etree import ElementTree as ET

ROM_START = b"<ROMFILE"
ROM_END = b"</ROMFILE>"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract XML config payload from romfile.cfg backups.",
    )
    parser.add_argument("input_file", type=Path, help="Path to backup file.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output XML path (default: <input>.xml).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print XML output.",
    )
    parser.add_argument(
        "--try-xor",
        action="store_true",
        help="Try single-byte XOR deobfuscation sweep (slower).",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum nested decode depth (default: 2).",
    )
    return parser.parse_args()


def extract_romfile_xml(blob: bytes) -> bytes | None:
    start = blob.find(ROM_START)
    if start < 0:
        return None

    end = blob.find(ROM_END, start)
    if end < 0:
        return None

    end += len(ROM_END)
    return blob[start:end]


def is_valid_xml(xml_blob: bytes) -> bool:
    try:
        ET.fromstring(xml_blob)
        return True
    except ET.ParseError:
        return False


def _decode_b64(data: bytes) -> bytes:
    stripped = b"".join(data.split())
    if not stripped:
        raise ValueError("empty base64 candidate")
    return base64.b64decode(stripped, validate=True)


def decoder_attempts(data: bytes) -> Iterable[tuple[str, bytes]]:
    decoders = (
        ("gzip", gzip.decompress),
        ("zlib", zlib.decompress),
        ("zlib-auto", lambda b: zlib.decompress(b, wbits=47)),
        ("deflate-raw", lambda b: zlib.decompress(b, wbits=-15)),
        ("bz2", bz2.decompress),
        ("lzma", lzma.decompress),
        ("base64", _decode_b64),
    )

    for name, decoder in decoders:
        try:
            decoded = decoder(data)
        except Exception:
            continue
        if decoded and decoded != data:
            yield name, decoded


def decode_search(raw_data: bytes, max_depth: int, try_xor: bool) -> tuple[str, bytes] | None:
    queue: list[tuple[str, bytes, int]] = [("raw", raw_data, 0)]
    seen: set[str] = set()

    if try_xor:
        for key in range(1, 256):
            xored = bytes(byte ^ key for byte in raw_data)
            if ROM_START in xored:
                queue.append((f"xor-0x{key:02x}", xored, 1))

    while queue:
        source, blob, depth = queue.pop(0)
        digest = hashlib.sha256(blob).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)

        xml_payload = extract_romfile_xml(blob)
        if xml_payload and is_valid_xml(xml_payload):
            return source, xml_payload

        if depth >= max_depth:
            continue

        for decoder_name, decoded in decoder_attempts(blob):
            queue.append((f"{source}->{decoder_name}", decoded, depth + 1))

    return None


def pretty_xml(xml_blob: bytes) -> bytes:
    parsed = minidom.parseString(xml_blob)
    pretty = parsed.toprettyxml(indent="  ", encoding="utf-8")
    return pretty


def default_output_path(input_file: Path) -> Path:
    return input_file.with_suffix(input_file.suffix + ".xml")


def main() -> int:
    args = parse_args()
    if args.max_depth < 0:
        print("error: --max-depth must be >= 0", file=sys.stderr)
        return 2

    if not args.input_file.exists():
        print(f"error: file not found: {args.input_file}", file=sys.stderr)
        return 2

    raw_data = args.input_file.read_bytes()
    result = decode_search(raw_data, max_depth=args.max_depth, try_xor=args.try_xor)
    if result is None:
        print(
            "error: ROMFILE XML payload not found. "
            "Try --try-xor and/or a higher --max-depth.",
            file=sys.stderr,
        )
        return 1

    source, xml_blob = result
    output_data = pretty_xml(xml_blob) if args.pretty else xml_blob
    output_file = args.output if args.output is not None else default_output_path(args.input_file)
    output_file.write_bytes(output_data)

    print(f"ok: extracted ROMFILE XML from '{source}'")
    print(f"ok: wrote {len(output_data)} bytes to {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
