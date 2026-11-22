"""Android boot.img (v0-v4), vendor_boot.img (v3-v4), AVB footer, and OEM stub utilities."""

import io
import os
import re
import shutil
import struct
import subprocess
import tarfile
from typing import Dict, List, Optional, Tuple


VENDOR_RAMDISK_TYPES = {
    0: "NONE",
    1: "PLATFORM",
    2: "RECOVERY",
    3: "DLKM",
}

FDT_MAGIC = b"\xd0\x0d\xfe\xed"


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return (value + alignment - 1) & ~(alignment - 1)


def parse_avb_footer(data: bytes) -> Optional[Dict]:
    """Parse trailing 64-byte AVBf footer and referenced AVB0 VBMETA descriptor."""
    if len(data) < 64 or data[-64:-60] != b"AVBf":
        return None

    ver_maj, ver_min, orig_img_sz, vbmeta_off, vbmeta_sz = struct.unpack_from(
        ">IIQQQ", data, len(data) - 60
    )
    avb_info: Dict = {
        "version": f"{ver_maj}.{ver_min}",
        "original_image_size": orig_img_sz,
        "vbmeta_offset": vbmeta_off,
        "vbmeta_size": vbmeta_sz,
        "algorithm_type": None,
        "flags": None,
        "props": {},
    }

    if 0 < vbmeta_off < len(data) and vbmeta_off + vbmeta_sz <= len(data):
        vb_blob = data[vbmeta_off : vbmeta_off + vbmeta_sz]
        if vb_blob[:4] == b"AVB0" and len(vb_blob) >= 256:
            avb_info["algorithm_type"] = struct.unpack_from(">I", vb_blob, 28)[0]
            avb_info["flags"] = struct.unpack_from(">I", vb_blob, 120)[0]
            for match in re.finditer(
                rb"(com\.android\.build\.[a-z0-9_.-]+)\x00([^\x00]{1,160})", vb_blob
            ):
                k = match.group(1).decode("ascii", errors="ignore")
                v = match.group(2).decode("ascii", errors="ignore")
                avb_info["props"][k] = v

    return avb_info


def decode_os_version(os_ver: int) -> Tuple[str, str]:
    if os_ver == 0:
        return "none", "none"
    v = os_ver >> 11
    p = os_ver & 0x7FF
    a, b, c = (v >> 14) & 0x7F, (v >> 7) & 0x7F, v & 0x7F
    y, m = 2000 + (p >> 4), p & 0x0F
    return f"{a}.{b}.{c}", f"{y:04d}-{m:02d}"


def parse_boot_img(data: bytes) -> Tuple[Dict, bytes]:
    """Parse Android boot.img (header versions 0, 1, 2, 3, and 4)."""
    if len(data) < 4096 or data[:8] != b"ANDROID!":
        raise ValueError("Input is not a valid Android boot image (missing ANDROID! magic)")

    info: Dict = {
        "image_kind": "boot",
        "file_size": len(data),
        "header_version": 0,
        "header_size": 0,
        "page_size": 4096,
        "kernel_size": 0,
        "ramdisk_size": 0,
        "os_version_str": "none",
        "os_patch_level": "none",
        "cmdline": "",
        "avb_footer": parse_avb_footer(data),
    }

    hdr_ver_v3 = struct.unpack_from("<I", data, 40)[0]
    if hdr_ver_v3 in (3, 4):
        k_sz, r_sz, os_ver, hdr_sz = struct.unpack_from("<IIII", data, 8)
        info["header_version"] = hdr_ver_v3
        info["kernel_size"] = k_sz
        info["ramdisk_size"] = r_sz
        info["header_size"] = hdr_sz
        info["page_size"] = 4096
        info["os_version_str"], info["os_patch_level"] = decode_os_version(os_ver)
        cmdline_raw = data[44 : 44 + 1536].split(b"\x00", 1)[0]
        info["cmdline"] = cmdline_raw.decode("utf-8", errors="replace")
        kernel_offset = 4096
    else:
        (
            k_sz,
            _,
            r_sz,
            _,
            _,
            _,
            _,
            page_sz,
            hdr_ver,
            os_ver,
        ) = struct.unpack_from("<IIIIIIIIII", data, 8)
        info["header_version"] = hdr_ver
        info["kernel_size"] = k_sz
        info["ramdisk_size"] = r_sz
        info["page_size"] = page_sz if page_sz in (2048, 4096, 8192, 16384) else 4096
        info["os_version_str"], info["os_patch_level"] = decode_os_version(os_ver)
        cmdline_raw = data[64 : 64 + 512].split(b"\x00", 1)[0]
        info["cmdline"] = cmdline_raw.decode("utf-8", errors="replace")
        kernel_offset = info["page_size"]

    if kernel_offset + info["kernel_size"] > len(data):
        raise ValueError(
            f"Corrupt boot.img: kernel payload ({info['kernel_size']} B) exceeds file size ({len(data)} B)"
        )

    kernel_payload = data[kernel_offset : kernel_offset + info["kernel_size"]]
    return info, kernel_payload


def parse_vendor_boot_img(data: bytes) -> Tuple[Dict, List[Dict]]:
    """Parse Android vendor_boot.img (v3 and v4) and return header info + raw ramdisk fragments."""
    if len(data) < 2128 or data[:8] != b"VNDRBOOT":
        raise ValueError("Input is not a valid Android vendor_boot image (missing VNDRBOOT magic)")

    hdr_ver, page_sz, _k_addr, _r_addr, v_ramdisk_sz = struct.unpack_from("<IIIII", data, 8)
    if page_sz not in (2048, 4096, 8192, 16384):
        page_sz = 4096

    cmdline = data[28 : 28 + 2048].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    name = data[2080 : 2080 + 16].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    hdr_sz, dtb_sz = struct.unpack_from("<II", data, 2096)

    ramdisk_off = align_up(hdr_sz, page_sz)
    dtb_off = ramdisk_off + align_up(v_ramdisk_sz, page_sz)
    ramdisk_blob = data[ramdisk_off : ramdisk_off + v_ramdisk_sz]
    dtb_blob = data[dtb_off : dtb_off + dtb_sz] if dtb_sz > 0 else b""
    dtb_count = dtb_blob.count(FDT_MAGIC) if dtb_blob else 0

    info: Dict = {
        "image_kind": "vendor_boot",
        "file_size": len(data),
        "header_version": hdr_ver,
        "header_size": hdr_sz,
        "page_size": page_sz,
        "name": name,
        "cmdline": cmdline,
        "vendor_ramdisk_size": v_ramdisk_sz,
        "dtb_size": dtb_sz,
        "dtb_count": dtb_count,
        "bootconfig": "",
        "ramdisk_fragments": [],
        "avb_footer": parse_avb_footer(data),
    }

    fragments: List[Dict] = []

    if hdr_ver >= 4:
        tbl_sz, tbl_num, tbl_ent_sz, bootcfg_sz = struct.unpack_from("<IIII", data, 2112)
        tbl_off = dtb_off + align_up(dtb_sz, page_sz)
        bootcfg_off = tbl_off + align_up(tbl_sz, page_sz)

        if bootcfg_sz > 0 and bootcfg_off + bootcfg_sz <= len(data):
            info["bootconfig"] = (
                data[bootcfg_off : bootcfg_off + bootcfg_sz]
                .split(b"\x00", 1)[0]
                .decode("utf-8", errors="replace")
                .strip()
            )

        if tbl_num > 0 and tbl_ent_sz >= 44:
            for idx in range(tbl_num):
                ent_pos = tbl_off + idx * tbl_ent_sz
                if ent_pos + 44 > len(data):
                    break
                f_sz, f_off, f_type = struct.unpack_from("<III", data, ent_pos)
                f_name = (
                    data[ent_pos + 12 : ent_pos + 44]
                    .split(b"\x00", 1)[0]
                    .decode("utf-8", errors="replace")
                ) or f"fragment_{idx}"
                type_label = VENDOR_RAMDISK_TYPES.get(f_type, f"TYPE_{f_type}")
                frag_bytes = ramdisk_blob[f_off : f_off + f_sz]
                info["ramdisk_fragments"].append(
                    {
                        "index": idx,
                        "name": f_name,
                        "type": type_label,
                        "offset": f_off,
                        "size": f_sz,
                    }
                )
                fragments.append({"name": f_name, "type": type_label, "bytes": frag_bytes})

    if not fragments and ramdisk_blob:
        info["ramdisk_fragments"].append(
            {
                "index": 0,
                "name": "vendor_ramdisk",
                "type": "PLATFORM",
                "offset": 0,
                "size": len(ramdisk_blob),
            }
        )
        fragments.append({"name": "vendor_ramdisk", "type": "PLATFORM", "bytes": ramdisk_blob})

    return info, fragments


def build_boot_stub_bytes(stock_boot_bytes: bytes, zstd_level: int = 19) -> Tuple[bytes, Dict]:
    """
    Zero out the kernel payload region inside a stock boot.img while preserving
    the boot header, any ramdisk, and the trailing AVB VBMETA + AVBf footer,
    then pack as a .tzst (tar + zstd) archive without requiring external magiskboot.
    """
    info, _ = parse_boot_img(stock_boot_bytes)
    page_sz = info["page_size"]
    k_sz = info["kernel_size"]
    zero_len = align_up(k_sz, page_sz)
    zero_blocks = zero_len // page_sz

    stub_buf = bytearray(stock_boot_bytes)
    stub_buf[page_sz : page_sz + zero_len] = bytes(zero_len)

    tar_mem = io.BytesIO()
    with tarfile.open(fileobj=tar_mem, mode="w") as tf:
        ti = tarfile.TarInfo(name="stub_boot.img")
        ti.size = len(stub_buf)
        ti.mode = 0o644
        tf.addfile(ti, io.BytesIO(stub_buf))

    zstd_bin = shutil.which("zstd")
    if not zstd_bin:
        raise RuntimeError("zstd binary is required in PATH to generate .tzst boot stub")

    proc = subprocess.run(
        [zstd_bin, f"-{zstd_level}", "-q", "-c"],
        input=tar_mem.getvalue(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"zstd compression failed: {proc.stderr.decode(errors='replace')}")

    archive_bytes = proc.stdout
    warnings: List[str] = []
    if info["header_version"] >= 4 and info["ramdisk_size"] == 0:
        stub_profile = "GKI 2.0 v4 (ramdisk-less, optimal compact stub)"
    else:
        stub_profile = f"Legacy v{info['header_version']} (ramdisk={info['ramdisk_size']} B)"
        if info["ramdisk_size"] > 0:
            warnings.append(
                f"Input boot.img contains a non-empty ramdisk ({info['ramdisk_size']} B). "
                "The ramdisk was preserved intact, so the .tzst stub will be larger than a GKI 2.0 v4 stub."
            )
    if not info["avb_footer"]:
        warnings.append("No trailing AVBf footer detected in stock boot.img.")

    meta = {
        "stub_profile": stub_profile,
        "header_version": info["header_version"],
        "page_size": page_sz,
        "original_size": len(stock_boot_bytes),
        "kernel_size": k_sz,
        "ramdisk_size": info["ramdisk_size"],
        "zeroed_blocks": zero_blocks,
        "zeroed_bytes": zero_len,
        "vbmeta_size": info["avb_footer"]["vbmeta_size"] if info["avb_footer"] else 0,
        "stub_archive_size": len(archive_bytes),
        "warnings": warnings,
    }
    return archive_bytes, meta


def save_boot_stub(stock_boot_bytes: bytes, output_path: str, zstd_level: int = 19) -> Dict:
    archive_bytes, meta = build_boot_stub_bytes(stock_boot_bytes, zstd_level=zstd_level)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(archive_bytes)
    meta["output_path"] = output_path
    return meta
