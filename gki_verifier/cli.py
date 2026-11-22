"""GKI Verifier command-line interface (run as: python3 -m gki_verifier ...)."""

import argparse
import json
import os
import sys

from .analyzer import compare_kernels, parse_symbol_list
from .bootimg import save_boot_stub
from .kmi import load_kernel_artifact, save_baseline
from .ko_verifier import collect_modules_from_path, verify_modules_against_kernel
from .reporters import (
    format_cli_diff,
    format_cli_inspect,
    format_cli_ko_verify,
    format_markdown_diff,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python3 -m gki_verifier",
        description="Android GKI 2.0 KMI/vABI auditor and boot image toolkit",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_diff = sub.add_parser("diff", help="Compare Reference vs Candidate kernel or baseline")
    p_diff.add_argument("reference", help="Reference boot.img, AK3.zip, Image, vmlinux, Module.symvers, or .kmi.json.gz")
    p_diff.add_argument("candidate", help="Candidate boot.img, AK3.zip, Image, vmlinux, or Module.symvers")
    p_diff.add_argument("--modules", action="append", default=[], help="Path to .ko file, directory of .ko, or vendor_boot.img (repeatable)")
    p_diff.add_argument("--symbol-list", default="", help="Optional Google abi_gki_aarch64 symbol list: tags broken symbols that are part of the official KMI (verdict is NOT relaxed)")
    p_diff.add_argument("--json", default="", help="Write full JSON report to path")
    p_diff.add_argument("--markdown", default="", help="Write Markdown summary report to path")

    p_insp = sub.add_parser("inspect", help="Inspect a single GKI artifact")
    p_insp.add_argument("artifact", help="Path to boot.img, vendor_boot.img, AK3.zip, Image.*, vmlinux, Module.symvers, or .kmi.json.gz")
    p_insp.add_argument("--config-grep", default="", help="Filter embedded IKCONFIG entries by substring")
    p_insp.add_argument("--json", default="", help="Write inspection JSON to path")

    p_ko = sub.add_parser("verify-ko", help="Verify .ko modules or vendor_boot.img against a kernel")
    p_ko.add_argument("kernel", help="Target kernel artifact or .kmi.json.gz baseline")
    p_ko.add_argument("modules", nargs="+", help="One or more .ko files, directories, or vendor_boot.img files")
    p_ko.add_argument("--ref", default="", help="Optional reference kernel to detect removed vmlinux symbols")
    p_ko.add_argument("--json", default="", help="Write JSON results to path")

    p_base = sub.add_parser("export-baseline", help="Export compact ~150 KB .kmi.json.gz baseline")
    p_base.add_argument("artifact", help="Source stock boot.img, AK3.zip, Image, vmlinux, or Module.symvers")
    p_base.add_argument("-o", "--output", required=True, help="Output .kmi.json.gz file path")

    p_stub = sub.add_parser("export-stub", help="Generate OEM .tzst boot stub from stock boot.img")
    p_stub.add_argument("boot_img", help="Path to stock Android boot.img")
    p_stub.add_argument("-o", "--output", required=True, help="Output .tzst file path")
    p_stub.add_argument("--zstd-level", type=int, default=19, help="zstd compression level (1-19, default: 19)")

    p_srv = sub.add_parser("serve", help="Start offline Web UI server")
    p_srv.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1; use 0.0.0.0 inside Docker)")
    p_srv.add_argument("--port", type=int, default=8080)
    p_srv.add_argument("--debug", action="store_true", help="Include Python tracebacks in API error responses")

    args = parser.parse_args()

    if args.cmd == "serve":
        if args.debug:
            os.environ["GKI_DEBUG"] = "1"
        from .web import run_server  # lazy: the CLI works without the web layer

        run_server(args.host, args.port)
        return

    if args.cmd == "diff":
        ref_art = load_kernel_artifact(args.reference)
        cand_art = load_kernel_artifact(args.candidate)
        raw_mods = []
        for mp in args.modules:
            if os.path.isdir(mp):
                kos, _ = collect_modules_from_path(mp)
                raw_mods.extend(kos)
            elif os.path.exists(mp):
                with open(mp, "rb") as f:
                    raw_mods.append({"name": os.path.basename(mp), "bytes": f.read()})
            else:
                print(f"[ERROR] Module path not found: {mp}", file=sys.stderr)
                sys.exit(2)

        kmi_list = None
        if args.symbol_list:
            if not os.path.isfile(args.symbol_list):
                print(f"[ERROR] Symbol list not found: {args.symbol_list}", file=sys.stderr)
                sys.exit(2)
            with open(args.symbol_list, "r", encoding="utf-8", errors="replace") as f:
                kmi_list = parse_symbol_list(f.read())

        report = compare_kernels(ref_art, cand_art, raw_mods, kmi_symbol_list=kmi_list)
        print(format_cli_diff(report))
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        if args.markdown:
            with open(args.markdown, "w", encoding="utf-8") as f:
                f.write(format_markdown_diff(report))
        sys.exit(0 if report["is_safe"] else 1)

    if args.cmd == "inspect":
        art = load_kernel_artifact(args.artifact)
        print(format_cli_inspect(art, config_grep=args.config_grep))
        if args.json:
            export_art = {k: v for k, v in art.items() if k not in ("symbols", "vendor_boot_modules")}
            export_art["total_symbols"] = len(art.get("symbols", {}))
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(export_art, f, indent=2)
        return

    if args.cmd == "verify-ko":
        kern_art = load_kernel_artifact(args.kernel)
        ref_syms = load_kernel_artifact(args.ref)["symbols"] if args.ref else None
        all_kos = []
        for mp in args.modules:
            kos, _ = collect_modules_from_path(mp)
            all_kos.extend(kos)
        results = verify_modules_against_kernel(all_kos, kern_art["symbols"], ref_symbols=ref_syms)
        print(format_cli_ko_verify(results, kern_art["source_name"]))
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
        sys.exit(0 if all(r["compatible"] for r in results) else 1)

    if args.cmd == "export-baseline":
        art = load_kernel_artifact(args.artifact)
        meta = save_baseline(art, args.output)
        print(
            f"[OK] Baseline exported: {meta['output_path']} "
            f"({meta['symbol_count']} symbols, {meta['ikconfig_count']} configs, {meta['baseline_size']} B)"
        )
        return

    if args.cmd == "export-stub":
        with open(args.boot_img, "rb") as f:
            raw = f.read()
        meta = save_boot_stub(raw, args.output, zstd_level=args.zstd_level)
        print(
            f"[OK] OEM boot stub created: {meta['output_path']} "
            f"({meta['stub_profile']}, zeroed={meta['zeroed_blocks']} blocks, "
            f"vbmeta={meta['vbmeta_size']} B, archive={meta['stub_archive_size']} B)"
        )
        for w in meta["warnings"]:
            print(f"[WARN] {w}")
        return


if __name__ == "__main__":
    main()
