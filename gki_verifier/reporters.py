"""CLI (UNIX), JSON, and GitHub Actions Markdown report formatters."""

from typing import Dict, List


def _fmt_mib(size_bytes: int) -> str:
    if not size_bytes:
        return "N/A"
    return f"{size_bytes / 1048576:.2f} MiB"


def format_cli_diff(report: Dict) -> str:
    lines: List[str] = []
    sep = "=" * 78
    sub = "-" * 78

    ref = report["reference"]
    cand = report["candidate"]
    s = report["summary"]

    lines.append(sep)
    lines.append(" GKI VERIFIER: KMI / vABI AUDIT REPORT")
    lines.append(sep)
    lines.append(f" Reference : {ref['name']} ({ref['container_type']}, {ref['total_symbols']} symbols)")
    lines.append(f" Candidate : {cand['name']} ({cand['container_type']}, {cand['total_symbols']} symbols)")
    lines.append(f" Banner    : {cand['linux_banner']}")
    avb = (cand.get("boot_info") or {}).get("avb_footer")
    if avb:
        lines.append(f" AVB Footer: VBMETA = {avb['vbmeta_size']} B @ offset {avb['vbmeta_offset']}")
    lines.append(sub)
    lines.append(
        f" Identical : {s['identical_symbols']} | CRC Mismatches: {s['crc_mismatches']} | "
        f"Missing: {s['missing_symbols']} | Added: {s['added_symbols']}"
    )
    if s["modules_checked"] > 0:
        lines.append(
            f" Modules   : {s['modules_checked']} checked | {s['modules_failed']} failed"
        )
    if s.get("kmi_listed_breakages") is not None:
        lines.append(f" KMI list  : {s['kmi_listed_breakages']} breaking symbol(s) are in the supplied --symbol-list")
    lines.append(sub)

    if report["structural_issues"]:
        lines.append("\n[BOOT / AVB STRUCTURAL ISSUES]")
        for iss in report["structural_issues"]:
            lines.append(f"  [{iss['severity']}] {iss['title']}")
            lines.append(f"      -> {iss['details']}")

    brk = report["breakage_analysis"]
    if brk["has_breakage"]:
        lines.append("\n[BREAKAGE SUMMARY]")
        lines.append(
            f"  Blast Radius    : {brk['blast_radius']} ({brk['affected_zones_count']} subsystem zone(s))"
        )
        if brk["dominant_prefixes"]:
            pref_str = ", ".join(f"{x['prefix']}* ({x['count']})" for x in brk["dominant_prefixes"][:8])
            lines.append(f"  Dominant Prefix : {pref_str}")
        for sent in brk["sentinel_findings"]:
            lines.append(f"  [SENTINEL] {sent['target']}")
            lines.append(f"      -> {sent['details']}")

    if report["zone_breakdown"]:
        lines.append("\n[AFFECTED KERNEL ZONES / SUBSYSTEMS]")
        lines.append(f"  {'Subsystem Zone':32s} | {'CRC Changed':11s} | {'Missing':8s} | {'Added':8s}")
        lines.append("  " + "-" * 68)
        for z, st in sorted(
            report["zone_breakdown"].items(),
            key=lambda x: (-(x[1]["crc_changed"] + x[1]["missing"]), -x[1]["added"], x[0]),
        ):
            lines.append(
                f"  {z:32s} | {st['crc_changed']:11d} | {st['missing']:8d} | {st['added']:8d}"
            )

    kc = report["kconfig_diff"]
    if kc["added_or_changed"] or kc["removed"]:
        lines.append("\n[EMBEDDED KCONFIG DIFF]")
        for k, v in kc["added_or_changed"].items():
            lines.append(f"  + {k}={v}")
        for k, v in kc["removed"].items():
            lines.append(f"  - {k} (was {v})")

    if report["module_verification"]:
        lines.append("\n[VENDOR .KO MODULE VERIFICATION]")
        for m in report["module_verification"]:
            status = "PASS" if m["compatible"] else f"FAIL ({len(m['failures'])} broken)"
            ext_note = f", {m['external_deps_count']} ext-ko" if m["external_deps_count"] else ""
            lines.append(
                f"  - {m['module_name']:34s}: {status} ({m['total_imports']} imports{ext_note})"
            )
            for f in m["failures"][:10]:
                lines.append(
                    f"      ! [{f['reason']}] {f['symbol']}: expected {f['expected_crc']}, got {f['actual_crc']}"
                )

    if report["crc_diffs"]:
        lines.append("\n[SYMBOL CRC MISMATCHES (UP TO 30)]")
        for x in report["crc_diffs"][:30]:
            kmi_tag = " [KMI]" if x.get("in_kmi_list") else ""
            lines.append(f"  [DIFF] {x['symbol']:36s} ({x['zone']}){kmi_tag}: {x['ref_crc']} -> {x['cand_crc']}")

    if report["missing_list"]:
        lines.append("\n[MISSING SYMBOLS (UP TO 30)]")
        for x in report["missing_list"][:30]:
            kmi_tag = " [KMI]" if x.get("in_kmi_list") else ""
            lines.append(f"  [MISS] {x['symbol']:36s} ({x['zone']}){kmi_tag}: was {x['ref_crc']}")

    lines.append("\n" + sep)
    if report["is_safe"]:
        lines.append(" VERDICT: [OK] KMI / vABI SAFE TO FLASH")
    else:
        lines.append(" VERDICT: [ERROR] vABI / BOOT MISMATCH - DO NOT FLASH")
    lines.append(sep)
    return "\n".join(lines)


def format_markdown_diff(report: Dict) -> str:
    s = report["summary"]
    ref = report["reference"]
    cand = report["candidate"]
    status_label = "[OK] KMI / vABI SAFE" if report["is_safe"] else "[ERROR] vABI / BOOT MISMATCH"

    out: List[str] = [
        f"### GKI Verifier Audit: {status_label}",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| **Reference** | `{ref['name']}` ({ref['total_symbols']} symbols) |",
        f"| **Candidate** | `{cand['name']}` ({cand['total_symbols']} symbols) |",
        f"| **Identical CRCs** | `{s['identical_symbols']}` |",
        f"| **CRC Mismatches** | `{s['crc_mismatches']}` |",
        f"| **Missing Symbols** | `{s['missing_symbols']}` |",
        f"| **Added Symbols** | `{s['added_symbols']}` |",
    ]

    avb1 = (ref.get("boot_info") or {}).get("avb_footer")
    avb2 = (cand.get("boot_info") or {}).get("avb_footer")
    if avb1 or avb2:
        sz1 = f"{avb1['vbmeta_size']} B" if avb1 else "none"
        sz2 = f"{avb2['vbmeta_size']} B" if avb2 else "none"
        out.append(f"| **AVB VBMETA Size** | Ref: `{sz1}` / Cand: `{sz2}` |")

    if s["modules_checked"] > 0:
        out.append(f"| **Vendor .ko Checked** | `{s['modules_checked']}` (`{s['modules_failed']}` failed) |")
    if s.get("kmi_listed_breakages") is not None:
        out.append(f"| **Breaks in KMI symbol list** | `{s['kmi_listed_breakages']}` |")

    if report["structural_issues"]:
        out.append("")
        out.append("#### Structural Issues")
        for iss in report["structural_issues"]:
            out.append(f"- **[{iss['severity']}] {iss['title']}:** {iss['details']}")

    brk = report["breakage_analysis"]
    if brk["has_breakage"]:
        out.append("")
        out.append("#### Breakage Analysis")
        out.append(f"- **Blast Radius:** `{brk['blast_radius']}` across `{brk['affected_zones_count']}` zone(s)")
        if brk["dominant_prefixes"]:
            prefs = ", ".join(f"`{x['prefix']}*` ({x['count']})" for x in brk["dominant_prefixes"][:8])
            out.append(f"- **Dominant Prefixes:** {prefs}")
        for sent in brk["sentinel_findings"]:
            out.append(f"- **Sentinel (`{sent['target']}`):** {sent['details']}")

    if report["crc_diffs"]:
        out.append("")
        out.append("<details><summary>CRC Mismatches (first 50)</summary>\n")
        out.append("| Symbol | Zone | Ref CRC | Candidate CRC |")
        out.append("|--------|------|---------|---------------|")
        for x in report["crc_diffs"][:50]:
            out.append(f"| `{x['symbol']}` | {x['zone']} | `{x['ref_crc']}` | `{x['cand_crc']}` |")
        out.append("\n</details>")

    if report["missing_list"]:
        out.append("")
        out.append("<details><summary>Missing Symbols (first 50)</summary>\n")
        out.append("| Symbol | Zone | Ref CRC |")
        out.append("|--------|------|---------|")
        for x in report["missing_list"][:50]:
            out.append(f"| `{x['symbol']}` | {x['zone']} | `{x['ref_crc']}` |")
        out.append("\n</details>")

    return "\n".join(out) + "\n"


def format_cli_inspect(artifact: Dict, config_grep: str = "") -> str:
    lines: List[str] = [
        "=" * 78,
        f" GKI VERIFIER: ARTIFACT INSPECTION ({artifact['source_name']})",
        "=" * 78,
        f" Container : {artifact['container_type']} ({artifact['kernel_format']})",
        f" Size      : {_fmt_mib(artifact.get('decompressed_size', 0))}",
        f" Banner    : {artifact.get('linux_banner', 'unknown')}",
        f" Symbols   : {len(artifact.get('symbols', {}))}",
        f" IKCONFIG  : {len(artifact.get('ikconfig', {}))} entries",
    ]

    arm = artifact.get("arm64_header")
    if arm:
        lines.append(
            f" ARM64 Hdr : page_size={arm['page_size']}, text_offset={arm['text_offset']}, "
            f"mem_size={_fmt_mib(arm['image_size_memory'])}"
        )

    bi = artifact.get("boot_info")
    if bi:
        lines.append(
            f" Boot Hdr  : v{bi['header_version']}, page_size={bi['page_size']}, "
            f"kernel={_fmt_mib(bi['kernel_size'])}, ramdisk={bi['ramdisk_size']} B, "
            f"os={bi['os_version_str']} ({bi['os_patch_level']})"
        )
        avb = bi.get("avb_footer")
        if avb:
            lines.append(
                f" AVB Footer: v{avb['version']}, vbmeta={avb['vbmeta_size']} B @ {avb['vbmeta_offset']}"
            )
            for k, v in avb.get("props", {}).items():
                lines.append(f"   prop {k} = {v}")

    vbi = artifact.get("vendor_boot_info")
    if vbi:
        lines.append(
            f" VndrBoot  : v{vbi['header_version']}, page_size={vbi['page_size']}, "
            f"ramdisk={_fmt_mib(vbi['vendor_ramdisk_size'])}, dtb={vbi['dtb_size']} B ({vbi['dtb_count']} FDTs), "
            f"extracted_ko={vbi['extracted_ko_count']}"
        )
        for frag in vbi.get("ramdisk_fragments", []):
            lines.append(f"   fragment[{frag['index']}] {frag['name']} ({frag['type']}): {frag['size']} B")

    if config_grep and artifact.get("ikconfig"):
        q = config_grep.lower()
        matches = [(k, v) for k, v in sorted(artifact["ikconfig"].items()) if q in k.lower()]
        lines.append(f"\n[IKCONFIG MATCHES FOR '{config_grep}' ({len(matches)})]")
        for k, v in matches[:100]:
            lines.append(f"  {k}={v}")

    lines.append("=" * 78)
    return "\n".join(lines)


def format_cli_ko_verify(results: List[Dict], kernel_name: str) -> str:
    failed = [r for r in results if not r["compatible"]]
    lines = [
        "=" * 78,
        f" GKI VERIFIER: VENDOR MODULE AUDIT vs {kernel_name}",
        "=" * 78,
        f" Modules checked: {len(results)} | Passed: {len(results) - len(failed)} | Failed: {len(failed)}",
        "-" * 78,
    ]
    for r in results:
        tag = "[OK]" if r["compatible"] else "[FAIL]"
        ext_s = f", ext_ko={r['external_deps_count']}" if r["external_deps_count"] else ""
        lines.append(f" {tag:6s} {r['module_name']:34s} (imports={r['total_imports']}, sib={r['sibling_resolved']}{ext_s})")
        for f in r["failures"][:15]:
            lines.append(f"    ! [{f['reason']}] {f['symbol']}: expected {f['expected_crc']}, got {f['actual_crc']}")
    lines.append("=" * 78)
    return "\n".join(lines)
