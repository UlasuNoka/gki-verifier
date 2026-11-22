"""KMI/vABI symbol extractor (PREL32 raw Image, ELF64 vmlinux, Module.symvers, baselines)."""

import array
import gzip
import io
import json
import os
import re
import struct
import sys
import zipfile
from typing import Dict, Optional

from .bootimg import parse_boot_img
from .unpacker import decompress_bytes, extract_ko_from_vendor_boot, parse_module_symvers

SUBSYSTEM_RULES = [
    ("android_vendor_hooks", r"^(__SCK__tp_func_|__trace(iter|point)_)?android_(r?vh)_"),
    ("sched / task_struct", r"^(init_task|wake_up|schedule|__put_task_struct|set_cpus_allowed|sched_|cpufreq_|uclamp_|cpu_rq|runqueues|__sched_|finish_task_switch)"),
    ("cgroup / namespaces", r"^(cgroup_|css_|cgrp_|init_css_set|pids_cgrp|init_pid_ns|find_task_by_|__cgroup_|of_css)"),
    ("net / core & sk_buff", r"^(___?pskb_|__alloc_skb|__kfree_skb|kfree_skb|skb_|__dev_|netif_|register_netdev|unregister_netdev|l3mdev_|ipvlan_|macvlan_|ethtool_|napi_|sock_|sk_|__sock_|dev_queue_xmit)"),
    ("net / ipv4_ipv6_netfilter", r"^(__ip_|ip_|__ip6_|ip6_|__inet|inet|nf_|xt_|fib|rt6_|tcp_|udp_|icmp|neigh_|dst_|__dst_|init_net)"),
    ("mm / memory_management", r"^(__alloc_pages|alloc_pages|__free_pages|folio_|page_|vma_|vm_|kmem_cache|kmalloc|__kmalloc|kvfree|kfree|mmap_|get_user_pages|pin_user_pages|lru_|zap_)"),
    ("fs / vfs_storage", r"^(vfs_|d_|inode_|iput|igrab|ihold|file_|filp_|path_|mnt_|mount_|sb_|ext4_|f2fs_|ovl_|seq_|kernfs_|sysfs_|proc_|squashfs_)"),
    ("lib / compression_crypto", r"^(LZ4_|zstd_|ZSTD_|FSE_|HUF_|crypto_|zlib_|sha|aes|crc)"),
    ("drivers / core_device", r"^(device_|dev_|__dynamic_dev_dbg|__devm_|devm_|driver_|bus_|class_|platform_|of_|fwnode_|pm_runtime_)"),
    ("drivers / usb_gadget", r"^(usb_|udc_|configfs_|hid_|f_hid|composite_|usbip_)"),
    ("drivers / gpu_drm_dmabuf", r"^(drm_|dma_buf|dma_fence|iommu_|mipi_dsi_)"),
    ("drivers / block_ufs_scsi", r"^(blk_|__blk_|bio_|scsi_|ufshcd_|mmc_|sdhci_)"),
    ("kernel / locking_rcu_irq", r"^(mutex_|__mutex_|raw_spin_|_raw_spin_|rt_mutex|down_|up_|rcu_|call_rcu|synchronize_rcu|queue_work|__wake_up|request_threaded_irq|free_irq)"),
]


def classify_symbol(sym_name: str) -> str:
    for zone_id, pattern in SUBSYSTEM_RULES:
        if re.search(pattern, sym_name):
            return zone_id
    return "other / general_kernel"


def extract_ikconfig(data: bytes) -> Dict[str, str]:
    s_pos = data.find(b"IKCFG_ST")
    if s_pos == -1:
        return {}
    e_pos = data.find(b"IKCFG_ED", s_pos + 8)
    if e_pos == -1:
        return {}
    try:
        text = gzip.decompress(data[s_pos + 8 : e_pos]).decode("utf-8", errors="replace")
    except Exception:
        return {}

    cfg: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("CONFIG_") and "=" in line:
            k, v = line.split("=", 1)
            cfg[k] = v
    return cfg


def extract_kmi_from_elf_vmlinux(elf_bytes: bytes) -> Optional[Dict[str, Dict]]:
    """Extract exact __ksymtab/__ksymtab_gpl and __kcrctab/__kcrctab_gpl from an ELF64 vmlinux."""
    if len(elf_bytes) < 64 or elf_bytes[:4] != b"\x7fELF" or elf_bytes[4] != 2:
        return None

    e_shoff = struct.unpack_from("<Q", elf_bytes, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", elf_bytes, 58)
    if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return None

    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off, shstr_sz = struct.unpack_from("<QQ", elf_bytes, shstr_hdr + 24)
    shstrtab = elf_bytes[shstr_off : shstr_off + shstr_sz]

    sections = {}
    all_secs = []
    for i in range(e_shnum):
        pos = e_shoff + i * e_shentsize
        sh_name_idx = struct.unpack_from("<I", elf_bytes, pos)[0]
        sh_addr, sh_off, sh_sz = struct.unpack_from("<QQQ", elf_bytes, pos + 16)
        n_end = shstrtab.find(b"\x00", sh_name_idx)
        sec_name = shstrtab[sh_name_idx:n_end].decode("ascii", errors="ignore")
        sec = {"name": sec_name, "addr": sh_addr, "off": sh_off, "size": sh_sz}
        sections[sec_name] = sec
        all_secs.append(sec)

    def vaddr_to_off(vaddr: int) -> Optional[int]:
        for s in all_secs:
            if s["addr"] and s["size"] and s["addr"] <= vaddr < s["addr"] + s["size"]:
                return s["off"] + (vaddr - s["addr"])
        return None

    pairs = [
        ("__ksymtab", "__kcrctab", "EXPORT_SYMBOL"),
        ("__ksymtab_gpl", "__kcrctab_gpl", "EXPORT_SYMBOL_GPL"),
    ]
    symbols: Dict[str, Dict] = {}

    for sym_sec_name, crc_sec_name, exp_type in pairs:
        sym_s = sections.get(sym_sec_name)
        crc_s = sections.get(crc_sec_name)
        if not sym_s or not crc_s or sym_s["size"] == 0:
            continue
        count = sym_s["size"] // 12
        if crc_s["size"] < count * 4:
            continue
        for i in range(count):
            f_pos = sym_s["off"] + i * 12
            v_pos = sym_s["addr"] + i * 12
            _, n_off, ns_off = struct.unpack_from("<iii", elf_bytes, f_pos)
            s_off = vaddr_to_off(v_pos + 4 + n_off)
            if s_off is None or s_off >= len(elf_bytes):
                continue
            s_end = elf_bytes.find(b"\x00", s_off, s_off + 128)
            if s_end <= s_off:
                continue
            name = elf_bytes[s_off:s_end].decode("ascii", errors="ignore")
            ns = ""
            if ns_off != 0:
                ns_f = vaddr_to_off(v_pos + 8 + ns_off)
                if ns_f is not None and ns_f < len(elf_bytes):
                    ns_e = elf_bytes.find(b"\x00", ns_f, ns_f + 128)
                    if ns_e > ns_f:
                        ns = elf_bytes[ns_f:ns_e].decode("ascii", errors="ignore")
            crc = struct.unpack_from("<I", elf_bytes, crc_s["off"] + i * 4)[0]
            symbols[name] = {
                "crc": crc,
                "type": exp_type,
                "namespace": ns,
                "zone": classify_symbol(name),
            }

    return symbols if symbols else None


def extract_kmi_from_raw_image(data: bytes) -> Dict[str, Dict]:
    """Locate PREL32 __ksymtab / __ksymtab_gpl and trailing __kcrctab in a raw ARM64 Image."""

    def is_valid_ident(b_str: bytes) -> bool:
        if not (1 <= len(b_str) <= 128):
            return False
        return all(
            (48 <= b <= 57) or (65 <= b <= 90) or (97 <= b <= 122) or b == 95 for b in b_str
        )

    def is_valid_entry(p: int) -> bool:
        if p < 0 or p + 12 > len(data):
            return False
        v_off, n_off, ns_off = struct.unpack_from("<iii", data, p)
        if not (-0x08000000 < v_off < 0x08000000):
            return False
        if not (-0x02000000 < n_off < 0x02000000):
            return False
        if ns_off != 0 and not (-0x02000000 < ns_off < 0x02000000):
            return False
        s_pos = p + 4 + n_off
        if not (0 <= s_pos < len(data) - 2):
            return False
        end = data.find(b"\x00", s_pos, s_pos + 128)
        if end == -1 or end == s_pos:
            return False
        return is_valid_ident(data[s_pos:end])

    words = array.array("i")
    if words.itemsize != 4:
        raise RuntimeError("Unsupported platform: array('i') is not 32-bit")
    words.frombytes(data[: len(data) & ~3])
    if sys.byteorder == "big":
        words.byteswap()

    def find_entry_near(str_off: int, window: int) -> Optional[int]:
        lo = max(0, (str_off - window) & ~3) // 4
        hi = min(len(words) - 1, (str_off + window) // 4)
        for i in range(lo, hi):
            p = i * 4
            if p + 4 + words[i + 1] == str_off:
                if is_valid_entry(p) and is_valid_entry(p - 12) and is_valid_entry(p + 12):
                    return p
        return None

    ksym_entry_pos = None
    for window in (1572864, 4194304):
        for anchor in (b"\x00init_task\x00", b"\x00schedule\x00", b"\x00_printk\x00"):
            idx = 0
            while True:
                pos = data.find(anchor, idx)
                if pos == -1:
                    break
                found = find_entry_near(pos + 1, window)
                if found is not None:
                    ksym_entry_pos = found
                    break
                idx = pos + 1
            if ksym_entry_pos is not None:
                break
        if ksym_entry_pos is not None:
            break

    if ksym_entry_pos is None:
        raise RuntimeError("Could not locate PREL32 __ksymtab symbol table in kernel image")

    start = ksym_entry_pos
    while is_valid_entry(start - 12):
        start -= 12
    end = ksym_entry_pos
    while is_valid_entry(end):
        end += 12

    count = (end - start) // 12
    crc_base = end
    if crc_base + count * 4 > len(data):
        raise RuntimeError("Truncated __kcrctab table in kernel image")

    symbols: Dict[str, Dict] = {}
    is_gpl = False
    prev_name = ""

    for i in range(count):
        p = start + i * 12
        _, n_off, ns_off = struct.unpack_from("<iii", data, p)
        s_pos = p + 4 + n_off
        s_end = data.find(b"\x00", s_pos, s_pos + 128)
        name = data[s_pos:s_end].decode("ascii", errors="ignore")

        if i > 0 and not is_gpl and name < prev_name:
            is_gpl = True
        prev_name = name

        ns = ""
        if ns_off != 0:
            ns_pos = p + 8 + ns_off
            if 0 <= ns_pos < len(data) - 1:
                ns_end = data.find(b"\x00", ns_pos, ns_pos + 128)
                if ns_end > ns_pos:
                    ns = data[ns_pos:ns_end].decode("ascii", errors="ignore")

        crc = struct.unpack_from("<I", data, crc_base + i * 4)[0]
        symbols[name] = {
            "crc": crc,
            "type": "EXPORT_SYMBOL_GPL" if is_gpl else "EXPORT_SYMBOL",
            "namespace": ns,
            "zone": classify_symbol(name),
        }

    return symbols


def _try_load_baseline_json(raw_bytes: bytes, source_name: str) -> Optional[Dict]:
    blob = raw_bytes
    if raw_bytes[:2] == b"\x1f\x8b":
        try:
            blob = gzip.decompress(raw_bytes)
        except Exception:
            return None
    if not blob.lstrip().startswith(b"{"):
        return None
    try:
        obj = json.loads(blob.decode("utf-8"))
    except Exception:
        return None
    if obj.get("format") != "gki-verifier-baseline-v1":
        return None
    if "symbols" not in obj:
        return None

    symbols: Dict[str, Dict] = {}
    for name, entry in obj["symbols"].items():
        if isinstance(entry, list):
            crc = int(entry[0]) & 0xFFFFFFFF
            exp_type = "EXPORT_SYMBOL_GPL" if entry[1] == "G" else "EXPORT_SYMBOL"
            ns = entry[2] if len(entry) > 2 else ""
        else:
            crc = int(entry["crc"]) & 0xFFFFFFFF
            exp_type = entry.get("type", "EXPORT_SYMBOL")
            ns = entry.get("namespace", "")
        symbols[name] = {
            "crc": crc,
            "type": exp_type,
            "namespace": ns,
            "zone": classify_symbol(name),
        }

    return {
        "source_name": obj.get("source_name", source_name),
        "container_type": "kmi_baseline",
        "kernel_format": obj.get("kernel_format", "baseline"),
        "decompressed_size": obj.get("decompressed_size", 0),
        "boot_info": obj.get("boot_info"),
        "vendor_boot_info": None,
        "vendor_boot_modules": [],
        "arm64_header": obj.get("arm64_header"),
        "linux_banner": obj.get("linux_banner", "unknown"),
        "ikconfig": obj.get("ikconfig", {}),
        "symbols": symbols,
    }


def _try_load_symvers(raw_bytes: bytes, source_name: str) -> Optional[Dict]:
    if b"\x00" in raw_bytes[:4096]:
        return None
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

    sample = [l.strip() for l in text.splitlines()[:25] if l.strip()]
    if not sample or not re.match(r"^0x[0-9a-fA-F]{8}\s+\S+\s+\S+\s+EXPORT_SYMBOL", sample[0]):
        return None

    parsed = parse_module_symvers(text)
    for name, meta in parsed.items():
        meta["zone"] = classify_symbol(name)
    return {
        "source_name": source_name,
        "container_type": "module_symvers",
        "kernel_format": "text",
        "decompressed_size": len(raw_bytes),
        "boot_info": None,
        "vendor_boot_info": None,
        "vendor_boot_modules": [],
        "arm64_header": None,
        "linux_banner": "Module.symvers",
        "ikconfig": {},
        "symbols": parsed,
    }


def load_kernel_artifact(path: str, raw_bytes: Optional[bytes] = None) -> Dict:
    """Load boot.img, vendor_boot.img, AK3.zip, Image.*, vmlinux, Module.symvers, or .kmi.json.gz."""
    if raw_bytes is None:
        with open(path, "rb") as f:
            raw_bytes = f.read()

    source_name = os.path.basename(path)

    baseline = _try_load_baseline_json(raw_bytes, source_name)
    if baseline is not None:
        return baseline

    if raw_bytes[:8] == b"VNDRBOOT":
        vboot_info, ko_list = extract_ko_from_vendor_boot(raw_bytes)
        return {
            "source_name": source_name,
            "container_type": "vendor_boot_img",
            "kernel_format": "vendor_ramdisk",
            "decompressed_size": len(raw_bytes),
            "boot_info": None,
            "vendor_boot_info": vboot_info,
            "vendor_boot_modules": ko_list,
            "arm64_header": None,
            "linux_banner": f"vendor_boot v{vboot_info['header_version']} ({vboot_info['extracted_ko_count']} .ko modules)",
            "ikconfig": {},
            "symbols": {},
        }

    symvers = _try_load_symvers(raw_bytes, source_name)
    if symvers is not None:
        return symvers

    artifact: Dict = {
        "source_name": source_name,
        "container_type": "raw_image",
        "kernel_format": "raw",
        "decompressed_size": 0,
        "boot_info": None,
        "vendor_boot_info": None,
        "vendor_boot_modules": [],
        "arm64_header": None,
        "linux_banner": "unknown",
        "ikconfig": {},
        "symbols": {},
    }

    payload = raw_bytes

    if raw_bytes[:4] == b"PK\x03\x04":
        artifact["container_type"] = "anykernel3_zip"
        with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
            names = zf.namelist()
            found = None
            for cand in ("Image", "Image.gz", "Image.lz4", "Image.zst", "kernel", "zImage"):
                if cand in names:
                    found = cand
                    break
            if not found:
                for n in names:
                    if os.path.basename(n) in ("Image", "Image.gz", "Image.lz4", "Image.zst", "kernel"):
                        found = n
                        break
            if not found:
                raise ValueError(f"No kernel image found inside ZIP archive: {source_name}")
            payload = zf.read(found)

    elif raw_bytes[:8] == b"ANDROID!":
        artifact["container_type"] = "android_boot_img"
        boot_info, payload = parse_boot_img(raw_bytes)
        artifact["boot_info"] = boot_info

    if payload[:4] == b"\x7fELF":
        artifact["container_type"] = "vmlinux_elf"
        artifact["kernel_format"] = "elf64"
        artifact["decompressed_size"] = len(payload)
        banner_match = re.search(rb"Linux version [0-9]+\.[0-9]+[^\x00\n]{10,250}", payload)
        if banner_match:
            artifact["linux_banner"] = banner_match.group(0).decode("utf-8", errors="replace").strip()
        artifact["ikconfig"] = extract_ikconfig(payload)
        elf_syms = extract_kmi_from_elf_vmlinux(payload)
        if elf_syms is None:
            raise RuntimeError("Could not extract __ksymtab/__kcrctab sections from ELF64 vmlinux")
        artifact["symbols"] = elf_syms
        return artifact

    fmt, image_bytes = decompress_bytes(payload)
    artifact["kernel_format"] = fmt
    artifact["decompressed_size"] = len(image_bytes)

    if len(image_bytes) >= 64 and image_bytes[56:60] == b"ARM\x64":
        text_offset, img_size, flags = struct.unpack_from("<QQQ", image_bytes, 8)
        page_shift = (flags >> 1) & 0x3
        page_sz_map = {1: "4K", 2: "16K", 3: "64K"}
        artifact["arm64_header"] = {
            "text_offset": hex(text_offset),
            "image_size_memory": img_size,
            "page_size": page_sz_map.get(page_shift, "unknown"),
        }

    banner_match = re.search(rb"Linux version [0-9]+\.[0-9]+[^\x00\n]{10,250}", image_bytes)
    if banner_match:
        artifact["linux_banner"] = banner_match.group(0).decode("utf-8", errors="replace").strip()

    artifact["ikconfig"] = extract_ikconfig(image_bytes)
    artifact["symbols"] = extract_kmi_from_raw_image(image_bytes)
    return artifact


def export_baseline_bytes(artifact: Dict) -> bytes:
    """Serialize a kernel artifact into a compact ~150 KB gzipped JSON KMI baseline."""
    if not artifact.get("symbols"):
        raise ValueError("Cannot export KMI baseline: artifact contains 0 exported symbols")

    compact_syms = {}
    for name, meta in sorted(artifact["symbols"].items()):
        t_flag = "G" if meta.get("type") == "EXPORT_SYMBOL_GPL" else "S"
        ns = meta.get("namespace", "")
        compact_syms[name] = [meta["crc"], t_flag, ns] if ns else [meta["crc"], t_flag]

    payload = {
        "format": "gki-verifier-baseline-v1",
        "source_name": artifact["source_name"],
        "kernel_format": artifact.get("kernel_format", "raw"),
        "decompressed_size": artifact.get("decompressed_size", 0),
        "linux_banner": artifact.get("linux_banner", "unknown"),
        "arm64_header": artifact.get("arm64_header"),
        "boot_info": artifact.get("boot_info"),
        "ikconfig": artifact.get("ikconfig", {}),
        "symbols": compact_syms,
    }
    raw_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return gzip.compress(raw_json, compresslevel=9)


def save_baseline(artifact: Dict, output_path: str) -> Dict:
    gz_bytes = export_baseline_bytes(artifact)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(gz_bytes)
    return {
        "output_path": output_path,
        "symbol_count": len(artifact["symbols"]),
        "ikconfig_count": len(artifact.get("ikconfig", {})),
        "baseline_size": len(gz_bytes),
    }
