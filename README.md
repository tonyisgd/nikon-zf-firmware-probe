# Nikon Zf firmware format probe

**Status: experimental research tool. This is not a working Zf firmware decryptor.** No plaintext firmware modules have been recovered with this prototype.

The probe was written after inspecting user-supplied Zf firmware versions 1.20, 1.21, 2.00, 2.01, 2.02, 3.00, and 3.01. All seven contain a 32-space marker at file offset `0x260`. The probe checks the publicly documented Nikon legacy `T1`/`T2`/`T3` XOR hypothesis at that offset and only writes decoded output if the module directory, module CRCs, package CRC, and trailer all validate.

The run on those seven samples inspected 2,804,108 aligned 256-byte sectors and found no repeated normalized sectors at different offsets. That means the legacy tool's published constant-fill-padding key-recovery assumption did not yield a key for these samples. This does **not** prove that every XOR variant is absent; it means the current evidence is insufficient to recover the tables.

The public reference tool explicitly lists Zf among models whose newer packaging it does not support: [WonderLantern/nikon-fw-key-tool](https://github.com/WonderLantern/nikon-fw-key-tool). Its README documents the legacy XOR transform and module-directory/CRC structure that this probe uses as a hypothesis.

## Run the format probe

Requires Python 3. The probe uses only the Python standard library.

```powershell
python zf_firmware_probe.py Z_f_0300.bin Z_f_0301.bin
```

To try the legacy XOR hypothesis when you already have candidate tables, provide a JSON file with three 256-byte tables:

```json
{"t1": [0, 0, 0], "t2": [0, 0, 0], "t3": [0, 0, 0]}
```

Each array must contain exactly 256 integer values from 0 to 255. The shortened arrays above are only illustrative and will be rejected. Then run:

```powershell
python zf_firmware_probe.py Z_f_0301.bin --tables candidate_tables.json --output candidate.dec
```

The tool refuses to write the output unless the hypothesized decode passes the package structure and CRC checks. Passing those checks would validate this legacy-format hypothesis for that image; it would not establish that arbitrary patched firmware is safe to install.

## Scope and limitations

- This tool does not recover `T1`/`T2`/`T3` tables.
- It does not bypass firmware signatures, generate signing keys, modify shutter sounds, or install firmware.
- No Nikon firmware binaries or other vendor files are included.
- The container parser and transform are adapted from a public legacy-format description and remain unvalidated on Zf.

## License

No license is specified yet. Add the license you want before inviting reuse or contributions.
