"""Binary decompressor, CPIO newc archive extractor, and Module.symvers parser."""

import lzma
import re
import shutil
import subprocess
import zlib
from typing import Dict, List, Tuple

from .bootimg import parse_vendor_boot_img

MAGIC_GZIP = b"\x1f\x8b\x08"
MAGIC_XZ = b"\xfd7zXZ\x00"
MAGIC_ZSTD = b"\x28\xb5\x2f\xfd"
MAGIC_LZ4_FRAME = b"\x04\x22\x4d\x18"
MAGIC_LZ4_LEGACY = b"\x02\x21\x4c\x18"
MAGIC_ARM64 = b"ARM\x64"


def _run_decompressor(tool_name: str, args: List[str], payload: bytes) -> bytes:
    exe = shutil.which(tool_name)
    if not exe:
        raise RuntimeError(f"Required decompressor '{tool_name}' is not installed in PATH")
    proc = subprocess.run(
        [exe] + args,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0 or not proc.stdout:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"{tool_name} decompression failed: {err}")
    return proc.stdout


def decompress_bytes(payload: bytes) -> Tuple[str, bytes]:
    """Decompress gzip, xz, zstd, lz4 frame, or lz4 legacy payloads. Returns (format, raw_bytes)."""
    if len(payload) < 8:
        return "raw", payload

    if payload[:3] == MAGIC_GZIP:
        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
        return "gzip", decomp.decompress(payload)

    if payload[:6] == MAGIC_XZ:
        return "xz", lzma.decompress(payload)

    if payload[:4] == MAGIC_ZSTD:
        return "zstd", _run_decompressor("zstd", ["-d", "-q", "-c"], payload)

    if payload[:4] == MAGIC_LZ4_FRAME:
        return "lz4", _run_decompressor("lz4", ["-d", "-q", "-c"], payload)

    if payload[:4] == MAGIC_LZ4_LEGACY:
        return "lz4_legacy", _run_decompressor("lz4", ["-d", "-q", "-c"], payload)

    if len(payload) > 64 and payload[56:60] == MAGIC_ARM64:
        return "raw", payload

    # Fallback: search first 64 KiB for embedded compressed ARM64 kernel stream
    for fmt, magic in (
        ("gzip", MAGIC_GZIP),
        ("lz4", MAGIC_LZ4_FRAME),
        ("lz4_legacy", MAGIC_LZ4_LEGACY),
        ("zstd", MAGIC_ZSTD),
    ):
        pos = payload.find(magic, 1, 65536)
        if pos != -1:
            try:
                _, raw = decompress_bytes(payload[pos:])
                if len(raw) > 64 and raw[56:60] == MAGIC_ARM64:
                    return fmt, raw
            except Exception:
                pass

    return "raw", payload


def extract_cpio_newc(cpio_bytes: bytes) -> List[Dict]:
    """Pure-Python SVR4 CPIO (070701 / 070702) extractor for vendor_boot ramdisks."""
    entries: List[Dict] = []
    pos = 0
    total = len(cpio_bytes)

    while pos + 110 <= total:
        while pos < total and cpio_bytes[pos] == 0:
            pos += 1
        if pos + 110 > total:
            break

        magic = cpio_bytes[pos : pos + 6]
        if magic not in (b"070701", b"070702"):
            next_p = cpio_bytes.find(b"070701", pos + 1)
            if next_p == -1:
                break
            pos = next_p
            continue

        hdr = cpio_bytes[pos : pos + 110].decode("ascii", errors="ignore")
        try:
            mode = int(hdr[14:22], 16)
            filesize = int(hdr[54:62], 16)
            namesize = int(hdr[94:102], 16)
        except ValueError:
            break

        name_start = pos + 110
        name_end = name_start + namesize
        if name_end > total:
            break

        name = cpio_bytes[name_start:name_end].rstrip(b"\x00").decode("utf-8", errors="replace")
        data_start = (name_end + 3) & ~3
        data_end = data_start + filesize
        if data_end > total:
            break

        if name == "TRAILER!!!":
            pos = (data_end + 3) & ~3
            continue

        if (mode & 0o170000) == 0o100000:
            entries.append(
                {
                    "path": re.sub(r"^(?:\./|/)*", "", name),
                    "size": filesize,
                    "bytes": cpio_bytes[data_start:data_end],
                }
            )

        pos = (data_end + 3) & ~3

    return entries


def _decompress_ramdisk_stream(blob: bytes) -> bytes:
    if not blob:
        return b""
    if blob[:6] in (b"070701", b"070702"):
        return blob
    try:
        _, raw = decompress_bytes(blob)
        return raw
    except Exception:
        out = bytearray()
        pos = 0
        while pos < len(blob):
            if blob[pos : pos + 6] in (b"070701", b"070702"):
                out.extend(blob[pos:])
                break
            if blob[pos : pos + 3] == MAGIC_GZIP:
                d = zlib.decompressobj(16 + zlib.MAX_WBITS)
                out.extend(d.decompress(blob[pos:]))
                consumed = len(blob[pos:]) - len(d.unused_data)
                if consumed <= 0:
                    break
                pos += consumed
            else:
                break
        return bytes(out) if out else blob


def extract_ko_from_vendor_boot(raw_bytes: bytes) -> Tuple[Dict, List[Dict]]:
    """Parse vendor_boot.img and extract all embedded .ko / .ko.* kernel modules."""
    vboot_info, fragments = parse_vendor_boot_img(raw_bytes)
    modules: List[Dict] = []
    seen = set()

    for frag in fragments:
        raw_cpio = _decompress_ramdisk_stream(frag["bytes"])
        for ent in extract_cpio_newc(raw_cpio):
            path = ent["path"]
            base = path.rsplit("/", 1)[-1]
            if base.lower().endswith((".ko", ".ko.gz", ".ko.zst", ".ko.xz", ".ko.lz4")):
                if base in seen:
                    continue
                seen.add(base)
                modules.append(
                    {
                        "name": base,
                        "archive_path": path,
                        "fragment": frag["name"],
                        "bytes": ent["bytes"],
                    }
                )

    vboot_info["extracted_ko_count"] = len(modules)
    vboot_info["extracted_ko_names"] = sorted(m["name"] for m in modules)
    return vboot_info, modules


def parse_module_symvers(text: str) -> Dict[str, Dict]:
    """Parse standard Linux Module.symvers text file into a symbol->meta dictionary."""
    symbols: Dict[str, Dict] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        crc_str, name, module, exp_type = parts[0], parts[1], parts[2], parts[3]
        ns = parts[4] if len(parts) >= 5 else ""
        try:
            crc = int(crc_str, 16) & 0xFFFFFFFF
        except ValueError:
            continue
        symbols[name] = {
            "crc": crc,
            "type": exp_type,
            "module": module,
            "namespace": ns,
        }
    return symbols
