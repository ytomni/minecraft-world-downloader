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
import struct
import sys
import zlib
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Iterable
from xml.dom import minidom

ROM_START = b"<ROMFILE"
ROM_END = b"</ROMFILE>"

ZTE_CFG_MAGIC = b"\x99\x99\x99\x99DDDDUUUU\xaa\xaa\xaa\xaa"
ZTE_PAYLOAD_MAGIC = 0x01020304
ZTE_SIGNATURE_MAGIC = 0x04030201

TYPE2_KNOWN_KEYS = (
    "MIK@0STzKpB%qJZe",
    "MIK@0STzKpB%qJZf",
    "402c38de39bed665",
    "Q#Zxn*x3kVLc",
    "Wj",
    "m8@96&ZG3Nm7N&Iz",
    "GrWM2Hz&LTvz&f^5",
    "GrWM3Hz&LTvz&f^9",
    "Renjx%2$CjM",
    "tHG@Ti&GVh@ql3XN",
    "SDEwOE5WMi41Uk9T",
)
TYPE3_KNOWN_MODELS = ("H268Q", "H298Q", "H188A", "H288A", "H267AV1_CZ")
TYPE3_KNOWN_KEY_IVS = (("H267AV1_CZkey", "H267AV1_CZIV"),)

KNOWN_SIGNATURE_PREFIX_BY_KEY = {
    "MIK@0STzKpB%qJZe": ("zxhn h118n e",),
    "MIK@0STzKpB%qJZf": ("zxhn h118n v",),
    "402c38de39bed665": ("zxhn h267a",),
    "Q#Zxn*x3kVLc": ("zxhn h168n v2",),
    "Wj": ("zxhn h298n",),
    "m8@96&ZG3Nm7N&Iz": ("zxhn h298a",),
    "GrWM2Hz&LTvz&f^5": ("zxhn h108n",),
    "GrWM3Hz&LTvz&f^9": ("zxhn h168n v3", "zxhn h168n h"),
    "Renjx%2$CjM": ("zxhn h208n", "zxv10 h201l"),
    "tHG@Ti&GVh@ql3XN": ("zxhn h267n",),
}

try:
    from Cryptodome.Cipher import AES as _AES  # type: ignore
except Exception:
    try:
        from Crypto.Cipher import AES as _AES  # type: ignore
    except Exception:
        _AES = None


@dataclass(frozen=True)
class DecodeContext:
    max_depth: int
    try_xor: bool
    zte_keys: tuple[str, ...]
    zte_models: tuple[str, ...]
    serial: str
    mac: str
    longpass: str
    signature: str
    try_all_known_keys: bool


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
    parser.add_argument(
        "--zte-key",
        action="append",
        default=[],
        help="Try this ZTE decryption key (repeatable).",
    )
    parser.add_argument(
        "--model",
        action="append",
        default=[],
        help="Try this ZTE model for type-3 key derivation (repeatable).",
    )
    parser.add_argument("--serial", default="", help="Serial for type-4 key generation.")
    parser.add_argument("--mac", default="", help="MAC for type-4 key generation.")
    parser.add_argument("--longpass", default="", help="Long password for type-4 keygen.")
    parser.add_argument("--signature", default="", help="Override device signature.")
    parser.add_argument(
        "--try-all-known-keys",
        action="store_true",
        help="Try all bundled known ZTE keys and model guesses.",
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


def looks_like_romfile(xml_blob: bytes) -> bool:
    stripped = xml_blob.strip()
    if not stripped.startswith(b"<ROMFILE") or not stripped.endswith(ROM_END):
        return False
    # Router dumps can include malformed XML attribute names (e.g. "11nMode"),
    # so we only require a plausible ROMFILE envelope.
    return b"<" in stripped and b">" in stripped and len(stripped) > len(ROM_END) + 8


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


def _be_u32(blob: bytes, offset: int) -> int:
    return struct.unpack_from(">I", blob, offset)[0]


def _decompress_zte_block_stream(stream: bytes) -> bytes | None:
    out = bytearray()
    offset = 0
    guard = 0
    while True:
        guard += 1
        if guard > 65536:
            return None
        if offset + 12 > len(stream):
            return None
        dec_len, comp_len, next_off = struct.unpack_from(">3I", stream, offset)
        offset += 12
        if offset + comp_len > len(stream):
            return None
        chunk = stream[offset : offset + comp_len]
        offset += comp_len
        try:
            dec = zlib.decompress(chunk)
        except Exception:
            return None
        if len(dec) != dec_len:
            return None
        out.extend(dec)
        if next_off == 0:
            break
    return bytes(out)


def decode_zte_cfg_container(blob: bytes) -> bytes | None:
    # Format used by some ZTE .cfg exports:
    # [128-byte file header][12-byte device header][name][60-byte block header][blocks]
    if len(blob) < 128 + 12 + 60 or not blob.startswith(ZTE_CFG_MAGIC):
        return None

    if blob[128:132] != b"\x04\x03\x02\x01":
        return None

    try:
        name_len = _be_u32(blob, 136)
    except Exception:
        return None

    blocks_offset = 128 + 12 + name_len
    if blocks_offset + 60 > len(blob):
        return None
    if blob[blocks_offset : blocks_offset + 4] != b"\x01\x02\x03\x04":
        return None

    blocks = blob[blocks_offset:]
    current = 60
    out = bytearray()
    seen_offsets: set[int] = set()
    while True:
        if current in seen_offsets:
            return None
        seen_offsets.add(current)
        if current + 12 > len(blocks):
            return None
        size, compressed_size, next_offset = struct.unpack_from(">3I", blocks, current)
        content_start = current + 12
        content_end = content_start + compressed_size
        if content_end > len(blocks):
            return None
        try:
            dec = zlib.decompress(blocks[content_start:content_end])
        except Exception:
            return None
        if len(dec) != size:
            return None
        out.extend(dec)
        if next_offset == 0:
            break
        current = next_offset

    return bytes(out)


def _parse_zte_payload_header(blob: bytes) -> tuple[int, str, int] | None:
    # Returns (payload_content_offset, signature, payload_type)
    offset = 0
    if len(blob) >= 128 and blob.startswith(ZTE_CFG_MAGIC):
        offset = 128

    signature = ""
    if offset + 12 <= len(blob) and _be_u32(blob, offset) == ZTE_SIGNATURE_MAGIC:
        sig_len = _be_u32(blob, offset + 8)
        sig_start = offset + 12
        sig_end = sig_start + sig_len
        if sig_end > len(blob):
            return None
        signature = blob[sig_start:sig_end].decode("utf-8", errors="ignore")
        offset = sig_end

    if offset + 60 > len(blob):
        return None
    if _be_u32(blob, offset) != ZTE_PAYLOAD_MAGIC:
        return None
    payload_type = _be_u32(blob, offset + 4)
    return offset + 60, signature, payload_type


def _read_encrypted_type2_stream(stream: bytes) -> tuple[bytes, int] | None:
    off = 0
    dec_total = 0
    chunks: list[bytes] = []
    guard = 0
    while True:
        guard += 1
        if guard > 65536 or off + 12 > len(stream):
            return None
        chunk_size, dec_size, more = struct.unpack_from(">3I", stream, off)
        off += 12
        if off + chunk_size > len(stream):
            return None
        chunks.append(stream[off : off + chunk_size])
        off += chunk_size
        dec_total += dec_size
        if more == 0:
            break
    return b"".join(chunks), dec_total


def _read_encrypted_type34_stream(stream: bytes) -> tuple[bytes, int] | None:
    off = 0
    dec_total = 0
    chunks: list[bytes] = []
    guard = 0
    while True:
        guard += 1
        if guard > 65536 or off + 12 > len(stream):
            return None
        dec_size, chunk_size, more = struct.unpack_from(">3I", stream, off)
        off += 12
        if off + chunk_size > len(stream):
            return None
        chunks.append(stream[off : off + chunk_size])
        off += chunk_size
        dec_total += dec_size
        if more == 0:
            break
    return b"".join(chunks), dec_total


def _try_payload0(payload_blob: bytes) -> bytes | None:
    if len(payload_blob) < 60 or _be_u32(payload_blob, 0) != ZTE_PAYLOAD_MAGIC:
        return None
    if _be_u32(payload_blob, 4) != 0:
        return None
    return _decompress_zte_block_stream(payload_blob[60:])


def _aes_ecb_decrypt(data: bytes, key: str) -> bytes | None:
    if _AES is None:
        return None
    key_bytes = key.encode("utf-8", errors="ignore").ljust(16, b"\0")[:16]
    cipher = _AES.new(key_bytes, _AES.MODE_ECB)
    return cipher.decrypt(data)


def _aes_cbc_decrypt_sha256(data: bytes, key: str, iv: str) -> bytes | None:
    if _AES is None:
        return None
    key_hash = sha256(key.encode("utf-8", errors="ignore")).digest()
    iv_hash = sha256(iv.encode("utf-8", errors="ignore")).digest()[:16]
    cipher = _AES.new(key_hash, _AES.MODE_CBC, iv_hash)
    return cipher.decrypt(data)


def _find_key_by_signature(signature: str) -> str | None:
    sig = signature.lower()
    for key, prefixes in KNOWN_SIGNATURE_PREFIX_BY_KEY.items():
        for prefix in prefixes:
            if sig.startswith(prefix):
                return key
    return None


def _mac_to_str(raw: str) -> str:
    cleaned = raw.strip().replace("-", "").replace(":", "").lower()
    if len(cleaned) != 12:
        return ""
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def _type4_key_ivs(signature: str, ctx: DecodeContext) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    sig = signature.replace(" ", "")

    # Signature-derived combinations used in known tools.
    if sig:
        out.extend(
            [
                (sig + "Key02721401", sig + "Iv02721401"),
                (sig + "Key02710010", sig + "Iv02710010"),
                (sig + "Key02710001", sig + "Iv02710001"),
                (sig + "Key02660004", sig + "Iv02660004"),
                (
                    sig + "8cc72b05705d5c46f412af8cbed55aa",
                    sig + "667b02a85c61c786def4521b060265e",
                ),
            ]
        )

    if ctx.serial:
        out.append(("8cc72b05705d5c46" + ctx.serial, "667b02a85c61c786" + ctx.serial))
    if ctx.serial and ctx.longpass:
        mac_str = _mac_to_str(ctx.mac)
        if mac_str:
            out.append(
                (
                    ctx.longpass + ctx.serial + "Mcd5c46e",
                    "G21b667b" + mac_str + ctx.longpass,
                )
            )
    return out


def decode_zte_payload(blob: bytes, ctx: DecodeContext) -> list[tuple[str, bytes]]:
    parsed = _parse_zte_payload_header(blob)
    if parsed is None:
        return []

    payload_off, detected_sig, payload_type = parsed
    signature = ctx.signature or detected_sig
    stream = blob[payload_off:]
    decoded_results: list[tuple[str, bytes]] = []

    if payload_type == 0:
        plain = _decompress_zte_block_stream(stream)
        if plain:
            decoded_results.append(("zte-payload0", plain))
        return decoded_results

    if _AES is None:
        return []

    if payload_type == 2:
        parsed_stream = _read_encrypted_type2_stream(stream)
        if parsed_stream is None:
            return []
        encrypted, dec_total = parsed_stream

        keys: list[str] = list(ctx.zte_keys)
        guessed = _find_key_by_signature(signature)
        if guessed:
            keys.append(guessed)
        if ctx.try_all_known_keys:
            keys.extend(TYPE2_KNOWN_KEYS)
        keys = list(dict.fromkeys(k for k in keys if k))

        for key in keys:
            decrypted = _aes_ecb_decrypt(encrypted, key)
            if not decrypted:
                continue
            candidate = decrypted[:dec_total]
            plain = _try_payload0(candidate)
            if plain:
                decoded_results.append((f"zte-payload2:{key}", plain))
        return decoded_results

    if payload_type in (3, 4):
        parsed_stream = _read_encrypted_type34_stream(stream)
        if parsed_stream is None:
            return []
        encrypted, dec_total = parsed_stream

        key_ivs: list[tuple[str, str]] = []
        for model in ctx.zte_models:
            key_ivs.append((model, model))
        if ctx.try_all_known_keys:
            key_ivs.extend((m, m) for m in TYPE3_KNOWN_MODELS)
            key_ivs.extend(TYPE3_KNOWN_KEY_IVS)
            if payload_type == 4:
                key_ivs.extend(_type4_key_ivs(signature, ctx))

        # Remove duplicate candidate key/iv pairs while preserving order.
        key_ivs = list(dict.fromkeys((k, v) for k, v in key_ivs if k))
        for key, iv in key_ivs:
            decrypted = _aes_cbc_decrypt_sha256(encrypted, key, iv)
            if not decrypted:
                continue
            candidate = decrypted[:dec_total]
            plain = _try_payload0(candidate)
            if plain:
                decoded_results.append((f"zte-payload{payload_type}:{key}", plain))
        return decoded_results

    return []


def decode_search(raw_data: bytes, ctx: DecodeContext) -> tuple[str, bytes] | None:
    queue: list[tuple[str, bytes, int]] = [("raw", raw_data, 0)]
    seen: set[str] = set()

    if ctx.try_xor:
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
        if xml_payload and looks_like_romfile(xml_payload):
            return source, xml_payload

        zte_cfg_decoded = decode_zte_cfg_container(blob)
        if zte_cfg_decoded:
            queue.append((f"{source}->ztecfg", zte_cfg_decoded, depth + 1))

        for zte_source, zte_blob in decode_zte_payload(blob, ctx):
            queue.append((f"{source}->{zte_source}", zte_blob, depth + 1))

        if depth >= ctx.max_depth:
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
    ctx = DecodeContext(
        max_depth=args.max_depth,
        try_xor=args.try_xor,
        zte_keys=tuple(args.zte_key),
        zte_models=tuple(args.model),
        serial=args.serial,
        mac=args.mac,
        longpass=args.longpass,
        signature=args.signature,
        try_all_known_keys=args.try_all_known_keys,
    )
    result = decode_search(raw_data, ctx=ctx)
    if result is None:
        print(
            "error: ROMFILE XML payload not found. "
            "Try --try-xor, --try-all-known-keys, and/or a higher --max-depth.",
            file=sys.stderr,
        )
        if _AES is None:
            print(
                "note: AES module not found. For encrypted ZTE backups install "
                "'pycryptodomex' or 'pycryptodome'.",
                file=sys.stderr,
            )
        return 1

    source, xml_blob = result
    if args.pretty:
        try:
            output_data = pretty_xml(xml_blob)
        except Exception:
            print(
                "warn: XML is not strictly well-formed; writing raw extracted payload.",
                file=sys.stderr,
            )
            output_data = xml_blob
    else:
        output_data = xml_blob
    output_file = args.output if args.output is not None else default_output_path(args.input_file)
    output_file.write_bytes(output_data)

    print(f"ok: extracted ROMFILE XML from '{source}'")
    print(f"ok: wrote {len(output_data)} bytes to {output_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
