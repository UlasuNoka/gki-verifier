"""ELF64 Linux kernel module (.ko / .ko.*) verifier with sibling-module __crc_ resolution."""

import os
import struct
from typing import Dict, List, Optional, Tuple

from .unpacker import decompress_bytes, extract_ko_from_vendor_boot

SHN_ABS = 0xFFF1
SHT_SYMTAB = 2


def decompress_ko_if_needed(name: str, data: bytes) -> Tuple[str, bytes]:
    if data[:4] == b"\x7fELF":
        return name, data
    _, raw = decompress_bytes(data)
    clean_name = name
    for ext in (".gz", ".zst", ".xz", ".lz4"):
        if clean_name.lower().endswith(ext):
            clean_name = clean_name[: -len(ext)]
            break
    return clean_name, raw


def parse_ko_elf(ko_bytes: bytes, ko_name: str) -> Dict:
    """
    Parse ELF64 .ko:
      - __versions: imported symbol names and expected 32-bit CRCs
      - .symtab (SHN_ABS __crc_*): exported symbols and CRCs provided by this .ko
      - .modinfo: vermagic, license, depends
    """
    clean_name, raw = decompress_ko_if_needed(ko_name, ko_bytes)
    result: Dict = {
        "module_name": clean_name,
        "valid_elf": False,
        "vermagic": "",
        "license": "",
        "depends": "",
        "imports": [],
        "exports": {},
    }
    if len(raw) < 64 or raw[:4] != b"\x7fELF" or raw[4] != 2:
        return result

    result["valid_elf"] = True
    e_shoff = struct.unpack_from("<Q", raw, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", raw, 58)
    if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return result

    shstr_hdr = e_shoff + e_shstrndx * e_shentsize
    shstr_off, shstr_sz = struct.unpack_from("<QQ", raw, shstr_hdr + 24)
    shstrtab = raw[shstr_off : shstr_off + shstr_sz]

    sec_headers = []
    for i in range(e_shnum):
        sh_pos = e_shoff + i * e_shentsize
        sh_name_idx, sh_type = struct.unpack_from("<II", raw, sh_pos)
        sh_off, sh_sz = struct.unpack_from("<QQ", raw, sh_pos + 24)
        sh_link = struct.unpack_from("<I", raw, sh_pos + 40)[0]
        sh_entsize = struct.unpack_from("<Q", raw, sh_pos + 56)[0]
        n_end = shstrtab.find(b"\x00", sh_name_idx)
        sec_name = shstrtab[sh_name_idx:n_end].decode("ascii", errors="ignore")
        sec_headers.append(
            {
                "name": sec_name,
                "type": sh_type,
                "off": sh_off,
                "size": sh_sz,
                "link": sh_link,
                "entsize": sh_entsize,
            }
        )

    for sh in sec_headers:
        if sh["name"] == "__versions":
            for off in range(sh["off"], sh["off"] + sh["size"], 64):
                if off + 64 > len(raw):
                    break
                crc = struct.unpack_from("<Q", raw, off)[0] & 0xFFFFFFFF
                raw_sym = raw[off + 8 : off + 64].split(b"\x00", 1)[0]
                sym_name = raw_sym.decode("ascii", errors="ignore")
                if sym_name:
                    result["imports"].append({"symbol": sym_name, "expected_crc": crc})

        elif sh["name"] == ".modinfo":
            blob = raw[sh["off"] : sh["off"] + sh["size"]]
            for item in blob.split(b"\x00"):
                if b"=" not in item:
                    continue
                k_b, v_b = item.split(b"=", 1)
                k = k_b.decode("ascii", errors="ignore")
                v = v_b.decode("utf-8", errors="replace")
                if k in ("vermagic", "license", "depends"):
                    result[k] = v

        elif sh["type"] == SHT_SYMTAB and sh["entsize"] >= 24 and sh["link"] < len(sec_headers):
            str_sh = sec_headers[sh["link"]]
            strtab = raw[str_sh["off"] : str_sh["off"] + str_sh["size"]]
            for off in range(sh["off"], sh["off"] + sh["size"], sh["entsize"]):
                if off + 24 > len(raw):
                    break
                st_name, _st_info, _st_other, st_shndx, st_value = struct.unpack_from(
                    "<IBBHQ", raw, off
                )
                if st_shndx == SHN_ABS and st_name < len(strtab):
                    end = strtab.find(b"\x00", st_name)
                    sym = strtab[st_name:end].decode("ascii", errors="ignore")
                    if sym.startswith("__crc_") and len(sym) > 6:
                        result["exports"][sym[6:]] = st_value & 0xFFFFFFFF

    return result


def collect_modules_from_inputs(raw_items: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Expand any vendor_boot.img entries into their embedded early-boot .ko modules."""
    expanded: List[Dict] = []
    vboot_summaries: List[Dict] = []

    for item in raw_items:
        data = item["bytes"]
        name = item["name"]
        if data[:8] == b"VNDRBOOT":
            v_info, kos = extract_ko_from_vendor_boot(data)
            v_info["source_name"] = name
            vboot_summaries.append(v_info)
            expanded.extend(kos)
        else:
            expanded.append(item)

    return expanded, vboot_summaries


def collect_modules_from_path(path: str) -> Tuple[List[Dict], List[Dict]]:
    raw_items: List[Dict] = []
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fn in sorted(files):
                if fn.lower().endswith((".ko", ".ko.gz", ".ko.zst", ".ko.xz", ".ko.lz4")):
                    full = os.path.join(root, fn)
                    with open(full, "rb") as f:
                        raw_items.append({"name": fn, "bytes": f.read()})
    elif os.path.exists(path):
        with open(path, "rb") as f:
            raw_items.append({"name": os.path.basename(path), "bytes": f.read()})
    return collect_modules_from_inputs(raw_items)


def verify_modules_against_kernel(
    modules_list: List[Dict],
    cand_symbols: Dict[str, Dict],
    ref_symbols: Optional[Dict[str, Dict]] = None,
) -> List[Dict]:
    """
    Verify .ko modules against candidate kernel symbols and sibling .ko exports.
    Distinguishes real kernel failures (CRC_MISMATCH, REMOVED_FROM_KERNEL) from
    unresolved cross-partition vendor .ko dependencies (EXTERNAL_KO_DEP).
    """
    parsed_mods = [parse_ko_elf(m["bytes"], m["name"]) for m in modules_list]

    sibling_exports: Dict[str, Dict] = {}
    for pm in parsed_mods:
        for sym, crc in pm["exports"].items():
            sibling_exports[sym] = {"crc": crc, "provider": pm["module_name"]}

    results: List[Dict] = []
    for pm in parsed_mods:
        imports = pm["imports"]
        failures = []
        external_deps = []
        sibling_resolved = 0

        for imp in imports:
            sym = imp["symbol"]
            exp_crc = imp["expected_crc"]

            if sym in cand_symbols:
                actual_crc = cand_symbols[sym]["crc"]
                if actual_crc != exp_crc:
                    failures.append(
                        {
                            "symbol": sym,
                            "reason": "CRC_MISMATCH",
                            "expected_crc": f"0x{exp_crc:08x}",
                            "actual_crc": f"0x{actual_crc:08x}",
                        }
                    )
            elif sym in sibling_exports:
                sibling_resolved += 1
                actual_crc = sibling_exports[sym]["crc"]
                if actual_crc != exp_crc:
                    failures.append(
                        {
                            "symbol": sym,
                            "reason": "SIBLING_CRC_MISMATCH",
                            "expected_crc": f"0x{exp_crc:08x}",
                            "actual_crc": f"0x{actual_crc:08x} ({sibling_exports[sym]['provider']})",
                        }
                    )
            elif ref_symbols is not None and sym in ref_symbols:
                failures.append(
                    {
                        "symbol": sym,
                        "reason": "REMOVED_FROM_KERNEL",
                        "expected_crc": f"0x{exp_crc:08x}",
                        "actual_crc": "MISSING",
                    }
                )
            else:
                external_deps.append(
                    {
                        "symbol": sym,
                        "reason": "EXTERNAL_KO_DEP",
                        "expected_crc": f"0x{exp_crc:08x}",
                    }
                )

        results.append(
            {
                "module_name": pm["module_name"],
                "valid_elf": pm["valid_elf"],
                "vermagic": pm["vermagic"],
                "license": pm["license"],
                "total_imports": len(imports),
                "sibling_resolved": sibling_resolved,
                "external_deps_count": len(external_deps),
                "compatible": pm["valid_elf"] and len(failures) == 0,
                "failures": failures,
                "external_deps": external_deps[:50],
            }
        )

    return results
