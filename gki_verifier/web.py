"""Zero-dependency HTTP server and REST API for GKI Verifier Web UI."""

import json
import os
import re
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict

from . import __version__
from .analyzer import compare_kernels, parse_symbol_list
from .bootimg import build_boot_stub_bytes
from .kmi import export_baseline_bytes, load_kernel_artifact
from .ko_verifier import collect_modules_from_inputs, verify_modules_against_kernel

UI_INDEX_PATH = os.path.join(os.path.dirname(__file__), "ui", "index.html")
MAX_UPLOAD_BYTES = int(os.environ.get("GKI_MAX_UPLOAD_MB", "512")) * 1024 * 1024


def parse_multipart_form(body: bytes, boundary: bytes) -> Dict:
    parts = body.split(b"--" + boundary)
    files: Dict = {"modules": []}
    for part in parts[1:]:
        if part.startswith(b"--") or b"\r\n\r\n" not in part:
            continue
        hdr_block, content = part.split(b"\r\n\r\n", 1)
        if content.endswith(b"\r\n"):
            content = content[:-2]
        hdr_str = hdr_block.decode("utf-8", errors="ignore")
        name_m = re.search(r'name="([^"]+)"', hdr_str)
        fn_m = re.search(r'filename="([^"]*)"', hdr_str)
        if not name_m:
            continue
        field = name_m.group(1)
        filename = fn_m.group(1) if fn_m else ""
        if not filename or len(content) == 0:
            continue
        if field == "modules":
            files["modules"].append({"name": filename, "bytes": content})
        else:
            files[field] = {"name": filename, "bytes": content}
    return files


class VerifierHTTPHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, obj: object) -> None:
        payload = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_multipart(self) -> Dict:
        ctype = self.headers.get("Content-Type", "")
        b_match = re.search(r"boundary=([^\s;]+)", ctype)
        if not b_match:
            raise ValueError("Missing multipart boundary")
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_UPLOAD_BYTES:
            raise ValueError(f"Upload size {length} bytes exceeds allowed limit ({MAX_UPLOAD_BYTES} bytes)")
        body = self.rfile.read(length)
        return parse_multipart_form(body, b_match.group(1).strip('"').encode("ascii"))

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/?"):
            with open(UI_INDEX_PATH, "rb") as f:
                html = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
        elif self.path == "/api/health":
            self._send_json(200, {"status": "ok", "version": __version__})
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        try:
            form = self._read_multipart()

            if self.path == "/api/compare":
                if "reference" not in form or "candidate" not in form:
                    raise ValueError("Both reference and candidate kernel files are required")
                ref_art = load_kernel_artifact(form["reference"]["name"], form["reference"]["bytes"])
                cand_art = load_kernel_artifact(form["candidate"]["name"], form["candidate"]["bytes"])
                kmi_list = None
                if "symbol_list" in form:
                    kmi_list = parse_symbol_list(form["symbol_list"]["bytes"].decode("utf-8", errors="replace"))
                report = compare_kernels(ref_art, cand_art, form.get("modules", []), kmi_symbol_list=kmi_list)
                self._send_json(200, report)
                return

            if self.path == "/api/inspect":
                if "artifact" not in form:
                    raise ValueError("Artifact file is required")
                art = load_kernel_artifact(form["artifact"]["name"], form["artifact"]["bytes"])
                resp = {k: v for k, v in art.items() if k not in ("symbols", "vendor_boot_modules")}
                resp["total_symbols"] = len(art.get("symbols", {}))
                self._send_json(200, resp)
                return

            if self.path == "/api/verify-ko":
                if "kernel" not in form or not form.get("modules"):
                    raise ValueError("Kernel file and at least one .ko or vendor_boot.img file are required")
                kern_art = load_kernel_artifact(form["kernel"]["name"], form["kernel"]["bytes"])
                ref_syms = None
                if "reference" in form:
                    ref_syms = load_kernel_artifact(form["reference"]["name"], form["reference"]["bytes"])["symbols"]
                ko_list, vboots = collect_modules_from_inputs(form["modules"])
                results = verify_modules_against_kernel(ko_list, kern_art["symbols"], ref_symbols=ref_syms)
                failed = [r for r in results if not r["compatible"]]
                self._send_json(
                    200,
                    {
                        "kernel_name": kern_art["source_name"],
                        "total_symbols": len(kern_art["symbols"]),
                        "vendor_boot_sources": vboots,
                        "total_modules": len(results),
                        "failed_modules": len(failed),
                        "all_compatible": len(failed) == 0,
                        "results": results,
                    },
                )
                return

            if self.path == "/api/export-baseline":
                if "artifact" not in form:
                    raise ValueError("Kernel artifact file is required")
                art = load_kernel_artifact(form["artifact"]["name"], form["artifact"]["bytes"])
                gz_bytes = export_baseline_bytes(art)
                stem = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(art["source_name"])[0])
                out_name = f"{stem}.kmi.json.gz"
                self.send_response(200)
                self.send_header("Content-Type", "application/gzip")
                self.send_header("Content-Disposition", f'attachment; filename="{out_name}"')
                self.send_header("Content-Length", str(len(gz_bytes)))
                self.end_headers()
                self.wfile.write(gz_bytes)
                return

            if self.path == "/api/export-stub":
                if "boot_img" not in form:
                    raise ValueError("Stock boot.img file is required")
                stub_bytes, meta = build_boot_stub_bytes(form["boot_img"]["bytes"])
                stem = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.splitext(form["boot_img"]["name"])[0])
                out_name = f"{stem}_stub.tzst"
                self.send_response(200)
                self.send_header("Content-Type", "application/zstd")
                self.send_header("Content-Disposition", f'attachment; filename="{out_name}"')
                self.send_header("X-Stub-Meta", json.dumps(meta))
                self.send_header("Content-Length", str(len(stub_bytes)))
                self.end_headers()
                self.wfile.write(stub_bytes)
                return

            self.send_error(404)
        except Exception as e:
            payload = {"error": str(e)}
            if os.environ.get("GKI_DEBUG") == "1":
                payload["trace"] = traceback.format_exc()
            self._send_json(400, payload)


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    print(f"[OK] GKI Verifier v{__version__} Web UI listening on http://{host}:{port}")
    server = ThreadingHTTPServer((host, port), VerifierHTTPHandler)
    server.serve_forever()
