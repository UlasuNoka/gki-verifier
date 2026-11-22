"""Unit tests for GKI Verifier using synthetic binary fixtures."""

import gzip
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from gki_verifier.analyzer import compare_kernels, parse_symbol_list
from gki_verifier.bootimg import build_boot_stub_bytes, parse_boot_img
from gki_verifier.kmi import export_baseline_bytes, load_kernel_artifact
from gki_verifier.ko_verifier import verify_modules_against_kernel
from unittest import mock
from gki_verifier.unpacker import decompress_bytes, extract_cpio_newc, extract_ko_from_vendor_boot
from gki_verifier.web import VerifierHTTPHandler

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make_synthetic_raw_image(symbols_std, symbols_gpl, ikconfig_text="CONFIG_TEST=y\n"):
    buf = bytearray(0x4000)
    # ARM64 Image header: text_offset, image_size, flags (4K pages), magic at offset 56
    struct.pack_into("<QQQ", buf, 8, 0, len(buf), 1 << 1)
    buf[56:60] = b"ARM\x64"

    banner = b"Linux version 6.6.118-android15-synthetic #1 SMP PREEMPT\x00"
    buf[128 : 128 + len(banner)] = banner

    all_syms = symbols_std + symbols_gpl
    str_pos = 0x200
    str_offsets = {}
    buf[str_pos] = 0
    str_pos += 1
    for name, _ in all_syms:
        str_offsets[name] = str_pos
        b = name.encode("ascii") + b"\x00"
        buf[str_pos : str_pos + len(b)] = b
        str_pos += len(b)

    ksym_base = 0x1000
    for i, (name, _) in enumerate(all_syms):
        entry_p = ksym_base + i * 12
        n_off = str_offsets[name] - (entry_p + 4)
        struct.pack_into("<iii", buf, entry_p, -0x100, n_off, 0)

    crc_base = ksym_base + len(all_syms) * 12
    for i, (_, crc) in enumerate(all_syms):
        struct.pack_into("<I", buf, crc_base + i * 4, crc)

    ik = b"IKCFG_ST" + gzip.compress(ikconfig_text.encode("utf-8")) + b"IKCFG_ED"
    buf[0x2800 : 0x2800 + len(ik)] = ik
    return bytes(buf)


def make_synthetic_boot_v4(kernel_bytes, cmdline="console=ttyMSM0", vbmeta_size=2368):
    page_sz = 4096
    hdr = bytearray(page_sz)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<IIII", hdr, 8, len(kernel_bytes), 0, 0, 1584)
    struct.pack_into("<I", hdr, 40, 4)
    cmd_b = cmdline.encode("ascii")
    hdr[44 : 44 + len(cmd_b)] = cmd_b

    k_aligned = (len(kernel_bytes) + page_sz - 1) & ~(page_sz - 1)
    k_padded = kernel_bytes + bytes(k_aligned - len(kernel_bytes))

    vbmeta_off = page_sz + k_aligned
    vbmeta = bytearray(vbmeta_size)
    vbmeta[0:4] = b"AVB0"
    prop = b"com.android.build.boot.os_version\x0016\x00"
    vbmeta[256 : 256 + len(prop)] = prop

    total_size = vbmeta_off + vbmeta_size + 4096
    img = bytearray(total_size)
    img[0:page_sz] = hdr
    img[page_sz : page_sz + k_aligned] = k_padded
    img[vbmeta_off : vbmeta_off + vbmeta_size] = vbmeta

    footer = bytearray(64)
    footer[0:4] = b"AVBf"
    struct.pack_into(">IIQQQ", footer, 4, 1, 0, vbmeta_off, vbmeta_off, vbmeta_size)
    img[-64:] = footer
    return bytes(img)


def make_cpio_newc(files):
    def entry(name_bytes, content):
        hdr = (
            "070701"
            f"{1:08x}{0o100644:08x}{0:08x}{0:08x}{1:08x}{0:08x}"
            f"{len(content):08x}{0:08x}{0:08x}{0:08x}{0:08x}"
            f"{len(name_bytes):08x}{0:08x}"
        ).encode("ascii")
        out = bytearray(hdr + name_bytes)
        while len(out) % 4:
            out.append(0)
        out.extend(content)
        while len(out) % 4:
            out.append(0)
        return bytes(out)

    out = bytearray()
    for name, content in files:
        out.extend(entry(name.encode("utf-8") + b"\x00", content))
    out.extend(entry(b"TRAILER!!!\x00", b""))
    return bytes(out)


def make_synthetic_ko(imports, exports=None):
    exports = exports or {}
    shstrtab = b"\x00.shstrtab\x00__versions\x00.modinfo\x00.strtab\x00.symtab\x00"
    ver_data = bytearray()
    for sym, crc in imports:
        ver_data.extend(struct.pack("<Q", crc))
        ver_data.extend(sym.encode("ascii").ljust(56, b"\x00"))
    modinfo = b"vermagic=6.6.118-android15\x00license=GPL\x00"

    strtab = bytearray(b"\x00")
    symtab = bytearray(24)  # STN_UNDEF
    for sym, crc in exports.items():
        s_off = len(strtab)
        strtab.extend(f"__crc_{sym}\x00".encode("ascii"))
        symtab.extend(struct.pack("<IBBHQQ", s_off, 0, 0, 0xFFF1, crc, 0))

    off_shstr = 64
    off_ver = off_shstr + len(shstrtab)
    off_mod = off_ver + len(ver_data)
    off_str = off_mod + len(modinfo)
    off_sym = (off_str + len(strtab) + 7) & ~7
    off_shdr = (off_sym + len(symtab) + 7) & ~7

    buf = bytearray(off_shdr + 6 * 64)
    e_ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", buf, 0, e_ident, 1, 183, 1, 0, 0, off_shdr, 0, 64, 0, 0, 64, 6, 1)

    buf[off_shstr : off_shstr + len(shstrtab)] = shstrtab
    buf[off_ver : off_ver + len(ver_data)] = ver_data
    buf[off_mod : off_mod + len(modinfo)] = modinfo
    buf[off_str : off_str + len(strtab)] = strtab
    buf[off_sym : off_sym + len(symtab)] = symtab

    def write_sh(idx, name_off, sh_type, off, sz, link=0, entsize=0):
        struct.pack_into("<IIQQQQIIQQ", buf, off_shdr + idx * 64, name_off, sh_type, 0, 0, off, sz, link, 0, 8, entsize)

    write_sh(0, 0, 0, 0, 0)
    write_sh(1, shstrtab.index(b".shstrtab"), 3, off_shstr, len(shstrtab))
    write_sh(2, shstrtab.index(b"__versions"), 1, off_ver, len(ver_data))
    write_sh(3, shstrtab.index(b".modinfo"), 1, off_mod, len(modinfo))
    write_sh(4, shstrtab.index(b".strtab"), 3, off_str, len(strtab))
    write_sh(5, shstrtab.index(b".symtab"), 2, off_sym, len(symtab), link=4, entsize=24)
    return bytes(buf)


class TestGKIVerifier(unittest.TestCase):
    def test_boot_v4_cmdline_offset_and_avb(self):
        std = [("__put_task_struct", 0x11111111), ("init_task", 0x22222222), ("schedule", 0x33333333)]
        gpl = [("cgroup_get_e_css", 0x44444444), ("zstd_compress_cctx", 0x55555555)]
        raw_img = make_synthetic_raw_image(std, gpl)
        boot_bytes = make_synthetic_boot_v4(raw_img, cmdline="androidboot.hardware=qcom", vbmeta_size=2368)

        info, payload = parse_boot_img(boot_bytes)
        self.assertEqual(info["header_version"], 4)
        self.assertEqual(info["cmdline"], "androidboot.hardware=qcom")
        self.assertEqual(info["avb_footer"]["vbmeta_size"], 2368)
        self.assertEqual(info["avb_footer"]["props"]["com.android.build.boot.os_version"], "16")
        self.assertEqual(payload, raw_img)

    def test_cpio_preserves_dotfiles(self):
        cpio = make_cpio_newc([("./lib/modules/test.ko", b"abc"), ("./.hidden_cfg", b"xyz"), ("/abs.ko", b"q")])
        paths = [e["path"] for e in extract_cpio_newc(cpio)]
        self.assertEqual(paths, ["lib/modules/test.ko", ".hidden_cfg", "abs.ko"])

    def test_symbol_list_parser(self):
        text = "# comment\n[abi_symbol_list]\n  schedule\n  init_task\n\n  _printk # trailing\n"
        self.assertEqual(parse_symbol_list(text), {"schedule", "init_task", "_printk"})

    def test_diff_baseline_and_symbol_list_tagging(self):
        std1 = [("__put_task_struct", 0x11111111), ("init_task", 0x22222222), ("schedule", 0x33333333)]
        gpl1 = [("zstd_compress_cctx", 0x55555555), ("zstd_free_cctx", 0x66666666)]
        raw1 = make_synthetic_raw_image(std1, gpl1, "CONFIG_A=y\n")
        art1 = load_kernel_artifact("stock_boot.img", make_synthetic_boot_v4(raw1))
        self.assertEqual(len(art1["symbols"]), 5)

        base_gz = export_baseline_bytes(art1)
        base_art = load_kernel_artifact("stock.kmi.json.gz", base_gz)
        self.assertEqual(base_art["container_type"], "kmi_baseline")
        self.assertEqual(len(base_art["symbols"]), 5)

        rep_ok = compare_kernels(base_art, art1)
        self.assertTrue(rep_ok["is_safe"])
        self.assertFalse(rep_ok["breakage_analysis"]["has_breakage"])
        self.assertIsNone(rep_ok["summary"]["kmi_listed_breakages"])

        # Candidate: zstd_compress_cctx CRC changed, zstd_free_cctx removed
        raw2 = make_synthetic_raw_image(std1, [("zstd_compress_cctx", 0xDEADBEEF)], "CONFIG_A=y\nCONFIG_B=y\n")
        art2 = load_kernel_artifact("cand_boot.img", make_synthetic_boot_v4(raw2))
        rep_bad = compare_kernels(base_art, art2)
        self.assertFalse(rep_bad["is_safe"])
        self.assertEqual(rep_bad["summary"]["crc_mismatches"], 1)
        self.assertEqual(rep_bad["summary"]["missing_symbols"], 1)
        self.assertEqual(rep_bad["breakage_analysis"]["dominant_prefixes"][0]["prefix"], "zstd_")

        # A symbol list only TAGS breakage; it must never relax the verdict.
        rep_tag = compare_kernels(base_art, art2, kmi_symbol_list={"zstd_compress_cctx", "init_task"})
        self.assertFalse(rep_tag["is_safe"])
        self.assertEqual(rep_tag["summary"]["kmi_listed_breakages"], 1)
        tags = {x["symbol"]: x["in_kmi_list"] for x in rep_tag["crc_diffs"] + rep_tag["missing_list"]}
        self.assertEqual(tags, {"zstd_compress_cctx": True, "zstd_free_cctx": False})

    def test_pure_python_lz4_fallback(self):
        lz4_blk = bytes([0x22]) + b"AB" + bytes([0x02, 0x00])
        legacy_stream = b"\x02\x21\x4c\x18" + struct.pack("<I", len(lz4_blk)) + lz4_blk
        legacy_double = legacy_stream + legacy_stream
        frame_stream = (
            b"\x04\x22\x4d\x18\x60\x40\x00"
            + struct.pack("<I", len(lz4_blk))
            + lz4_blk
            + struct.pack("<I", 0)
        )
        with mock.patch("gki_verifier.unpacker.shutil.which", return_value=None):
            fmt1, out1 = decompress_bytes(legacy_double)
            self.assertEqual(fmt1, "lz4_legacy")
            self.assertEqual(out1, b"ABABABABABABABAB")
            fmt2, out2 = decompress_bytes(frame_stream)
            self.assertEqual(fmt2, "lz4")
            self.assertEqual(out2, b"ABABABAB")

    def test_ko_sibling_resolution_and_vendor_boot(self):
        kern_syms = {"init_task": {"crc": 0x22222222, "type": "EXPORT_SYMBOL", "namespace": "", "zone": "sched"}}
        provider_ko = make_synthetic_ko([("init_task", 0x22222222)], exports={"vendor_helper": 0xCAFEBABE})
        consumer_ko = make_synthetic_ko(
            [("init_task", 0x22222222), ("vendor_helper", 0xCAFEBABE), ("dlkm_other_sym", 0x12345678)]
        )

        cpio_gz = gzip.compress(
            make_cpio_newc([("lib/modules/provider.ko", provider_ko), ("lib/modules/consumer.ko", consumer_ko)])
        )
        page_sz = 4096
        vb = bytearray(page_sz * 4)
        vb[0:8] = b"VNDRBOOT"
        struct.pack_into("<IIIII", vb, 8, 4, page_sz, 0, 0, len(cpio_gz))
        struct.pack_into("<II", vb, 2096, 2128, 0)
        vb[page_sz : page_sz + len(cpio_gz)] = cpio_gz

        v_info, kos = extract_ko_from_vendor_boot(bytes(vb))
        self.assertEqual(v_info["extracted_ko_count"], 2)

        res = verify_modules_against_kernel(kos, kern_syms, ref_symbols=kern_syms)
        self.assertTrue(all(r["compatible"] for r in res))
        cons = next(r for r in res if r["module_name"] == "consumer.ko")
        self.assertEqual(cons["sibling_resolved"], 1)
        self.assertEqual(cons["external_deps_count"], 1)

        broken_syms = {"init_task": {"crc": 0x99999999, "type": "EXPORT_SYMBOL", "namespace": "", "zone": "sched"}}
        res_bad = verify_modules_against_kernel(kos, broken_syms, ref_symbols=kern_syms)
        self.assertTrue(all(not r["compatible"] for r in res_bad))

    def test_cli_exit_codes(self):
        std = [("__put_task_struct", 0x11111111), ("init_task", 0x22222222), ("schedule", 0x33333333)]
        img_a = make_synthetic_raw_image(std, [("zstd_init", 0x44444444)])
        img_b = make_synthetic_raw_image(std, [("zstd_init", 0x55555555)])
        with tempfile.TemporaryDirectory() as td:
            pa, pb = os.path.join(td, "a.img"), os.path.join(td, "b.img")
            with open(pa, "wb") as f:
                f.write(img_a)
            with open(pb, "wb") as f:
                f.write(img_b)

            def run(*args):
                return subprocess.run(
                    [sys.executable, "-m", "gki_verifier", *args],
                    cwd=REPO_ROOT, capture_output=True, text=True,
                )

            same = run("diff", pa, pa)
            self.assertEqual(same.returncode, 0, same.stderr)
            self.assertIn("SAFE TO FLASH", same.stdout)

            out_json = os.path.join(td, "r.json")
            bad = run("diff", pa, pb, "--json", out_json)
            self.assertEqual(bad.returncode, 1, bad.stderr)
            with open(out_json, "r", encoding="utf-8") as f:
                self.assertEqual(json.load(f)["summary"]["crc_mismatches"], 1)

    def test_web_ui_and_compare_api(self):
        std = [("__put_task_struct", 0x11111111), ("init_task", 0x22222222), ("schedule", 0x33333333)]
        img_a = make_synthetic_raw_image(std, [("zstd_init", 0x44444444)])
        img_b = make_synthetic_raw_image(std, [("zstd_init", 0x55555555)])
        boundary = "----gkiverifierboundary"

        def multipart(fields):
            body = bytearray()
            for name, filename, data in fields:
                body.extend(
                    (
                        f"--{boundary}\r\n"
                        f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                        "Content-Type: application/octet-stream\r\n\r\n"
                    ).encode("ascii")
                )
                body.extend(data + b"\r\n")
            body.extend(f"--{boundary}--\r\n".encode("ascii"))
            return bytes(body)

        class QuietHandler(VerifierHTTPHandler):
            def log_message(self, *args):
                pass

        srv = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
                html_body = resp.read().decode("utf-8")
                self.assertEqual(resp.status, 200)
                self.assertIn("data-palette", html_body)

            payload = multipart([
                ("reference", "a.img", img_a),
                ("candidate", "b.img", img_b),
                ("symbol_list", "abi.txt", b"zstd_init\n"),
            ])
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/compare",
                data=payload,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
            with urllib.request.urlopen(req) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                self.assertFalse(res["is_safe"])
                self.assertEqual(res["summary"]["crc_mismatches"], 1)
                self.assertEqual(res["summary"]["kmi_listed_breakages"], 1)
        finally:
            srv.shutdown()
            srv.server_close()

    @unittest.skipUnless(shutil.which("zstd"), "zstd binary required")
    def test_export_stub_preserves_avb_and_zeroes_kernel(self):
        raw_img = make_synthetic_raw_image(
            [("__put_task_struct", 1), ("init_task", 2), ("schedule", 3)], [("zstd_init", 4)]
        )
        boot_bytes = make_synthetic_boot_v4(raw_img)
        stub_bytes, meta = build_boot_stub_bytes(boot_bytes, zstd_level=3)
        self.assertEqual(meta["vbmeta_size"], 2368)
        self.assertGreater(len(stub_bytes), 0)
        self.assertLess(len(stub_bytes), len(boot_bytes))


if __name__ == "__main__":
    unittest.main()
