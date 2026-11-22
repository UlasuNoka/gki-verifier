# gki-verifier

KMI/vABI symbol verifier and boot image inspector for ARM64 Android GKI 2.0 kernels (`CONFIG_MODVERSIONS=y`, `CONFIG_HAVE_ARCH_PREL32_RELOCATIONS=y`, Linux 5.10 - 6.12+).

Runs on the Python 3 standard library. The external `zstd` binary is required only for zstd-compressed kernel images and `export-stub`. Gzip, XZ, LZ4 frame, and LZ4 legacy streams are handled in-process.

## Commands

- `diff <reference> <candidate>` — compare `__ksymtab` / `__kcrctab` CRCs, `IKCONFIG`, boot headers, and `AVB` descriptors between two kernel artifacts (`boot.img`, `AnyKernel3.zip`, `Image.*`, `vmlinux`, `Module.symvers`, or `.kmi.json.gz`).
- `inspect <artifact>` — print boot/vendor_boot headers, AVB properties, ARM64 image metadata, symbol count, and `IKCONFIG` (`--config-grep`).
- `verify-ko <kernel> <modules...>` — check `__versions` CRCs of `.ko` files (`.ko`, `.ko.gz`, `.ko.zst`, `.ko.xz`, `.ko.lz4`), module directories, or `vendor_boot.img` ramdisks against a kernel or baseline.
- `export-baseline <artifact> -o <out.kmi.json.gz>` — save a compact KMI + AVB snapshot (~150 KB) for CI checks without storing full boot images in Git.
- `export-stub <stock_boot.img> -o <out.tzst>` — zero the kernel payload inside a stock `boot.img` while keeping the header, ramdisk, and trailing AVB VBMETA descriptor.
- `serve [--host 127.0.0.1] [--port 8080]` — start the local web interface.

## Usage

```bash
python3 -m gki_verifier diff stock_boot.img new_boot.img
python3 -m gki_verifier diff stock.kmi.json.gz new_boot.img --modules vendor_boot.img --markdown summary.md
python3 -m gki_verifier diff stock_boot.img new_boot.img --symbol-list abi_gki_aarch64
python3 -m gki_verifier inspect /dev/block/by-name/boot_b --config-grep IPVLAN
python3 -m gki_verifier verify-ko /dev/block/by-name/boot_b /dev/block/by-name/vendor_boot_b /vendor_dlkm/lib/modules
python3 -m gki_verifier export-baseline stock_boot.img -o device.kmi.json.gz
python3 -m gki_verifier export-stub stock_boot.img -o device_boot_stub.tzst
python3 -m gki_verifier serve
```

`diff` and `verify-ko` exit with `0` when compatible and `1` on any CRC mismatch, missing export, or structural error. Passing `--symbol-list` tags symbols that belong to the supplied KMI list (`[KMI]`) without relaxing the exit code.

## Docker

```bash
docker compose up -d --build
# listens on http://localhost:18205
```

## GitHub Actions

```yaml
- name: Verify KMI compatibility
  uses: UlasuNoka/gki-verifier@main
  with:
    reference: kmi_baselines/device.kmi.json.gz
    candidate: out/boot.img
    fail_on_mismatch: 'true'
    write_summary: 'true'
```

## Notes

- Raw `Image` scanning locates the `PREL32` symbol table via anchor symbols (`init_task`, `schedule`, `_printk`). Non-GKI kernels without `PREL32` relocations or with `CONFIG_MODVERSIONS=n` are not supported.
- Stock Google Kleaf images compiled with `CONFIG_TRIM_UNUSED_KSYMS=y` export only the whitelisted KMI symbols (~9000), while untrimmed custom builds export the full symbol table (~16500). Always use the stock image (or its `.kmi.json.gz` baseline) as `reference` and the custom build as `candidate`.
- `serve` binds to `127.0.0.1` by default and provides no authentication. Use `--debug` (or `GKI_DEBUG=1`) to include tracebacks in HTTP 400 responses.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## License

MIT
