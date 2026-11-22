"""KMI/vABI comparison engine: exact CRC diffing plus clearly-labelled heuristic hints."""

from collections import Counter
from typing import Dict, List, Optional, Set

from .ko_verifier import collect_modules_from_inputs, verify_modules_against_kernel

STRUCTURAL_SENTINELS = [
    (
        "struct task_struct (<linux/sched.h>)",
        lambda d: "__put_task_struct" in d,
        "'__put_task_struct' (exported in kernel/fork.c) changed CRC, indicating struct task_struct or included cgroup headers changed layout.",
    ),
    (
        "Scheduler internals (kernel/sched/sched.h)",
        lambda d: "wake_up_process" in d and "__put_task_struct" not in d and "__alloc_skb" not in d,
        "'wake_up_process' changed CRC while '__put_task_struct' stayed intact, pointing to struct rq, cfs_rq, or task_group layout changes.",
    ),
    (
        "struct net_device / struct net (<linux/netdevice.h>)",
        lambda d: ("register_netdev" in d or "__dev_queue_xmit" in d) and "__put_task_struct" not in d,
        "Core netdevice symbols changed CRC, pointing to struct net_device or struct net field offset changes.",
    ),
    (
        "struct sk_buff (<linux/skbuff.h>)",
        lambda d: "__alloc_skb" in d and "register_netdev" not in d,
        "'__alloc_skb' changed CRC while 'register_netdev' stayed intact, pointing directly to struct sk_buff layout changes.",
    ),
    (
        "struct cgroup / css_set (<linux/cgroup-defs.h>)",
        lambda d: ("cgrp_dfl_root" in d or "cgroup_get_e_css" in d) and "__alloc_skb" not in d,
        "Core cgroup symbols changed CRC independently of networking, pointing to CGROUP_SUBSYS_COUNT or struct cgroup / css_set changes.",
    ),
    (
        "VFS core (struct inode / dentry / super_block)",
        lambda d: ("iget_locked" in d or "d_alloc" in d) and "__put_task_struct" not in d and "__alloc_skb" not in d,
        "Core VFS symbols changed CRC, pointing to struct inode, struct dentry, or struct super_block layout changes.",
    ),
]


def _symbol_prefix(sym: str) -> str:
    clean = sym.lstrip("_")
    parts = clean.split("_")
    if len(parts) >= 2 and parts[0]:
        return parts[0] + "_"
    return clean[:8]


def compute_prefix_clusters(symbol_names: List[str], limit: int = 12) -> List[Dict]:
    if not symbol_names:
        return []
    counts = Counter(_symbol_prefix(s) for s in symbol_names)
    return [{"prefix": p, "count": c} for p, c in counts.most_common(limit)]


def analyze_breakage(diffs: List[Dict], missing: List[Dict], zone_summary: Dict) -> Dict:
    """Breakage summary (counts plus heuristic hints), populated only when CRC mismatches or missing symbols exist."""
    broken_count = len(diffs) + len(missing)
    if broken_count == 0:
        return {
            "has_breakage": False,
            "blast_radius": "none",
            "affected_zones_count": 0,
            "dominant_prefixes": [],
            "sentinel_findings": [],
        }

    affected_zones = [
        z for z, st in zone_summary.items() if st["crc_changed"] > 0 or st["missing"] > 0
    ]
    if broken_count >= 100 or len(affected_zones) >= 4:
        blast = "widespread_transitive"
    elif broken_count >= 15 or len(affected_zones) >= 2:
        blast = "subsystem_scoped"
    else:
        blast = "localized"

    diff_names = {d["symbol"] for d in diffs}
    all_broken = [d["symbol"] for d in diffs] + [m["symbol"] for m in missing]

    sentinels = []
    for title, pred, details in STRUCTURAL_SENTINELS:
        if pred(diff_names):
            sentinels.append({"target": title, "details": details})

    return {
        "has_breakage": True,
        "blast_radius": blast,
        "affected_zones_count": len(affected_zones),
        "dominant_prefixes": compute_prefix_clusters(all_broken),
        "sentinel_findings": sentinels,
    }


def parse_symbol_list(text: str) -> Set[str]:
    """Parse a Google-style abi_gki_aarch64 symbol list ('#' comments, '[section]' headers, one symbol per line)."""
    symbols: Set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        symbols.add(line.split()[0])
    return symbols


def check_boot_structure(ref_art: Dict, cand_art: Dict) -> List[Dict]:
    """Verify objective boot image & AVB VBMETA structural invariants."""
    issues: List[Dict] = []
    b1 = ref_art.get("boot_info")
    b2 = cand_art.get("boot_info")
    if not b1 or not b2:
        return issues

    if b1.get("header_version") != b2.get("header_version"):
        issues.append(
            {
                "severity": "CRITICAL",
                "title": "Android Boot Header Version Mismatch",
                "details": (
                    f"Reference uses boot header v{b1.get('header_version')}, "
                    f"while Candidate uses v{b2.get('header_version')}."
                ),
            }
        )

    avb1 = b1.get("avb_footer")
    avb2 = b2.get("avb_footer")
    if avb1 and not avb2:
        issues.append(
            {
                "severity": "CRITICAL",
                "title": "Missing AVB Footer in Candidate boot.img",
                "details": (
                    f"Reference has a {avb1.get('vbmeta_size', 0)}-byte VBMETA descriptor, "
                    "while Candidate has no trailing AVBf footer."
                ),
            }
        )
    elif avb1 and avb2:
        sz1 = avb1.get("vbmeta_size", 0)
        sz2 = avb2.get("vbmeta_size", 0)
        if sz1 > 1024 and sz2 <= 512:
            issues.append(
                {
                    "severity": "CRITICAL",
                    "title": "Stripped / Unsigned AVB VBMETA Descriptor",
                    "details": (
                        f"Reference carries a {sz1}-byte OEM VBMETA descriptor, while Candidate "
                        f"has only {sz2} bytes. Strict bootloaders will reject boot."
                    ),
                }
            )

    return issues


def compare_kernels(
    ref_art: Dict,
    cand_art: Dict,
    raw_module_inputs: Optional[List[Dict]] = None,
    kmi_symbol_list: Optional[Set[str]] = None,
) -> Dict:
    s1 = ref_art.get("symbols", {})
    s2 = cand_art.get("symbols", {})
    if not s1 or not s2:
        raise ValueError("Both Reference and Candidate must contain KMI symbol tables")

    diffs = []
    missing = []
    added = []
    zone_summary: Dict[str, Dict[str, int]] = {}

    for sym, meta1 in s1.items():
        if sym not in s2:
            missing.append(
                {
                    "symbol": sym,
                    "ref_crc": f"0x{meta1['crc']:08x}",
                    "type": meta1["type"],
                    "zone": meta1["zone"],
                }
            )
            z = meta1["zone"]
            zone_summary.setdefault(z, {"crc_changed": 0, "missing": 0, "added": 0})
            zone_summary[z]["missing"] += 1
        elif s2[sym]["crc"] != meta1["crc"]:
            meta2 = s2[sym]
            diffs.append(
                {
                    "symbol": sym,
                    "ref_crc": f"0x{meta1['crc']:08x}",
                    "cand_crc": f"0x{meta2['crc']:08x}",
                    "type": meta2["type"],
                    "zone": meta2["zone"],
                }
            )
            z = meta2["zone"]
            zone_summary.setdefault(z, {"crc_changed": 0, "missing": 0, "added": 0})
            zone_summary[z]["crc_changed"] += 1

    for sym, meta2 in s2.items():
        if sym not in s1:
            added.append(
                {
                    "symbol": sym,
                    "cand_crc": f"0x{meta2['crc']:08x}",
                    "type": meta2["type"],
                    "zone": meta2["zone"],
                }
            )
            z = meta2["zone"]
            zone_summary.setdefault(z, {"crc_changed": 0, "missing": 0, "added": 0})
            zone_summary[z]["added"] += 1

    diffs.sort(key=lambda x: x["symbol"])
    missing.sort(key=lambda x: x["symbol"])
    added.sort(key=lambda x: x["symbol"])

    kmi_listed_breakages: Optional[int] = None
    if kmi_symbol_list is not None:
        kmi_listed_breakages = 0
        for entry in diffs + missing:
            entry["in_kmi_list"] = entry["symbol"] in kmi_symbol_list
            if entry["in_kmi_list"]:
                kmi_listed_breakages += 1

    kc1 = ref_art.get("ikconfig", {})
    kc2 = cand_art.get("ikconfig", {})
    kconfig_diff: Dict[str, Dict[str, str]] = {"added_or_changed": {}, "removed": {}}
    if kc1 and kc2:
        for k, v2 in sorted(kc2.items()):
            if k not in kc1 or kc1[k] != v2:
                kconfig_diff["added_or_changed"][k] = v2
        for k, v1 in sorted(kc1.items()):
            if k not in kc2:
                kconfig_diff["removed"][k] = v1

    ko_list, vboot_sources = collect_modules_from_inputs(raw_module_inputs or [])
    module_checks = verify_modules_against_kernel(ko_list, s2, ref_symbols=s1) if ko_list else []
    structural_issues = check_boot_structure(ref_art, cand_art)
    breakage = analyze_breakage(diffs, missing, zone_summary)

    failed_modules = [m for m in module_checks if not m["compatible"]]
    is_safe = (
        len(diffs) == 0
        and len(missing) == 0
        and len(structural_issues) == 0
        and len(failed_modules) == 0
    )

    return {
        "verdict": "SAFE_TO_FLASH" if is_safe else "VABI_OR_BOOT_MISMATCH",
        "is_safe": is_safe,
        "reference": {
            "name": ref_art["source_name"],
            "container_type": ref_art["container_type"],
            "kernel_format": ref_art["kernel_format"],
            "decompressed_size": ref_art["decompressed_size"],
            "linux_banner": ref_art["linux_banner"],
            "arm64_header": ref_art["arm64_header"],
            "boot_info": ref_art["boot_info"],
            "total_symbols": len(s1),
            "ikconfig_count": len(kc1),
        },
        "candidate": {
            "name": cand_art["source_name"],
            "container_type": cand_art["container_type"],
            "kernel_format": cand_art["kernel_format"],
            "decompressed_size": cand_art["decompressed_size"],
            "linux_banner": cand_art["linux_banner"],
            "arm64_header": cand_art["arm64_header"],
            "boot_info": cand_art["boot_info"],
            "total_symbols": len(s2),
            "ikconfig_count": len(kc2),
        },
        "summary": {
            "identical_symbols": len(s1) - len(diffs) - len(missing),
            "crc_mismatches": len(diffs),
            "missing_symbols": len(missing),
            "added_symbols": len(added),
            "modules_checked": len(module_checks),
            "modules_failed": len(failed_modules),
            "structural_issues": len(structural_issues),
            "kmi_listed_breakages": kmi_listed_breakages,
        },
        "breakage_analysis": breakage,
        "structural_issues": structural_issues,
        "zone_breakdown": zone_summary,
        "kconfig_diff": kconfig_diff,
        "vendor_boot_sources": vboot_sources,
        "module_verification": module_checks,
        "crc_diffs": diffs[:500],
        "missing_list": missing[:500],
        "added_list": added[:500],
    }
