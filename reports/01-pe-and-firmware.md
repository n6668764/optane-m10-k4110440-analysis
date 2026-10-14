# Offline static analysis: SB_K4110440_x64.dll

The DLL contains an exactly identifiable, extractable **585,728-byte signed K4110440-005 firmware image**. Its PBUF/VBUF segments contain readable ARM/Thumb firmware code, including media initialization checks and candidate register-access routines. This is a useful reverse-engineering input. **It does not yet establish AHU14132 identity or a complete 3D XPoint PHY register/wire protocol.**

Analysis performed 2026-10-13. The attachment from the referenced conversation was copied to the working directory. All findings below come from its bytes and offline parsing/disassembly. No DLL entry point, export, TLS callback, updater, target firmware, emulated target code, or hardware command was executed. No web lookup or network verification was used.

## 1. File identity and PE structure

- File length: **1,622,376 bytes**.
- SHA-256: `254e2b87f2f85435dc83798b634345a402a2212d8e64bb80bbe85cf6a0b68857`.
- SHA-1: `de48228f95f8426f1c9f8d04d562e86f03b45cab`.
- MD5: `0c5d057fe9ebaf69a2798ae35cf58664`; included as an identifier, not as a security guarantee.
- Architecture: AMD64 (`Machine=0x8664`), native PE32+ DLL (`Magic=0x20B`, COFF flags `0x2022`); no CLR directory.
- PE header file offset `0x110`; image base `0x180000000`; entry point RVA `0x59724`.
- Linker version `14.0`; PE timestamp **2019-11-02 01:24:27 UTC**. This is metadata, not an independently proven build time.
- Image size `0x193000`, header size `0x400`, section/file alignments `0x1000`/`0x200`; GUI subsystem 2.
- DLL characteristics `0x160`: high-entropy VA, dynamic base and NX compatibility flags. `.gfids` exists, but the optional-header Guard CF flag is not set; do not infer complete CFG protection from the section name.
- Stored and independently calculated PE checksum both equal `0x18EE82`.
- Whole-file Shannon entropy: **6.501 bits/byte**. Entropy is descriptive, not proof of compression/encryption.

| Section | File offset | RVA | Raw size | Virtual size | Entropy |
|---|---:|---:|---:|---:|---:|
| .text | `0x400` | `0x1000` | `0xA8200` | `0xA800D` | 6.428 |
| .rdata | `0xA8600` | `0xAA000` | `0x40A00` | `0x4092A` | 4.730 |
| .data | `0xE9000` | `0xEB000` | `0x94800` | `0x98BF0` | 6.344 |
| .pdata | `0x17D800` | `0x184000` | `0xA000` | `0x9F3C` | 5.815 |
| .gfids | `0x187800` | `0x18E000` | `0xA00` | `0x8C4` | 3.469 |
| .tls | `0x188200` | `0x18F000` | `0x200` | `0x9` | 0.020 |
| .rsrc | `0x188400` | `0x190000` | `0x200` | `0x1E0` | 4.709 |
| .reloc | `0x188600` | `0x191000` | `0x1E00` | `0x1DCC` | 5.445 |

Only `.text` is executable; `.data` and `.tls` are writable. The firmware is stored as host **data**, although its bytes are executable instructions for the device's CPU. The exception directory is `0x9F3C` bytes (3,397 x64 runtime-function entries). TLS callback VAs: `0x18006f5d0`. These were parsed, never called. Full directory values, section hashes and TLS metadata are in `analysis.json`.

The raw section data ends at `0x18A400`. The entire remaining **7,528-byte overlay** is the PE certificate table (`WIN_CERTIFICATE`, revision `0x0200`, type 2); there is no separate firmware overlay.

## 2. Imports, exports, resources and version clues

There is one import descriptor: **KERNEL32.dll, 99 named imports**, zero ordinal imports. Examples are `GetProcAddress`, `LoadLibraryExW`, `CreateFileW`, `ReadFile`, `WriteFile`, heap/TLS/synchronization functions and exception support. No delay-import or CLR directory is present. `DeviceIoControl` is not in the static import list; dynamic resolution/shared-library abstractions remain possible. Imports alone do not prove whether every code path is hardware independent. The complete list is in `imports.txt`.

The export-directory module name is **firmware_module.dll**:

| Ordinal | Export | RVA | File offset |
|---:|---|---:|---:|
| 1 | `GetFirmwareConfigurationAttributes` | `0x9c30` | `0x9030` |
| 2 | `GetTargetFirmwareBinary` | `0xa220` | `0x9620` |
| 3 | `GetTargetFirmwareMappingAttributes` | `0xa010` | `0x9410` |

These are metadata/binary-provider exports. Static disassembly of `GetTargetFirmwareBinary` shows selection of a fixed embedded byte array and a size-checked copy helper. It does not require invoking the export to recover the array.

Exactly one resource was found: **RT_MANIFEST / ID 2 / language 1033**, 381 bytes at file offset `0x188460`. It requests `asInvoker`, `uiAccess=false`. There is **no RT_VERSION and no firmware RCDATA resource**. The XML is extracted as `manifest.xml`.

Concrete strings and original DLL file offsets:

| Offset | String | Interpretation |
|---:|---|---|
| `0xC10E8` | `K4110440_005_dell_client_signed` | Host firmware-selection key |
| `0xC1BF8` | `INTEL MEMPEK1J032GAD` | Model string in host metadata |
| `0xC1C28` | `INTEL MEMPEK1J016GAD` | Matches the model from the referenced conversation |
| `0xC1C10` | `K4110440` | Firmware revision metadata |
| `0xC1C1C` | `A03 ` | Adjacent release string; exact field meaning unconfirmed |
| `0xC1C98` | `1.0.0` | Version-like host string, not a verified PE file version |
| `0xC1CA0` | `Dell` | OEM metadata |
| `0xEA368` | `K4110440-005` | Firmware image revision |
| `0xEA9FC` | `Intel StonyBeach` | Firmware platform string |
| `0xEDC44` | `$FwRev:K4110440$` | Explicit firmware revision marker |
| `0x176024` | `INTEL MEMPEK1W016GA` | Model-like string inside firmware configuration; not an established compatibility statement |

The CodeView RSDS record embeds `c:\Dev\FIAT\customertools\CustomerTools\firmware_module\firmware_module\x64\Release-s\firmware_module.pdb`, age 430. The actual PDB is not present in this attachment. Generic platform/model tables and strings from shared components must not be treated as confirmed support for all named hardware. `strings.tsv` contains 17,285 ASCII/UTF-16LE printable runs, many of which are accidental instruction-byte strings.

## 3. Exact firmware extraction

The saved `K4110440_005_signed_firmware.bin` is the byte-for-byte DLL range **[0xEA0D0, 0x1790D0)**, length **0x8F000 = 585,728 bytes**. Its SHA-256 is:

`0a42b2e10bd725f3eecdbdbf52fd4fc4c7581887a5fe94c0cecb3561f600a7ee`

The boundary is supported by three independent observations:

1. Export code at DLL RVA `0xA2A6` loads size `0x8F000`.
2. RVA `0xA2B0` loads VA `0x1800EC0D0`, mapping to file offset `0xEA0D0`.
3. Firmware header word at relative `+0x18` is `0x23C00`; multiplied by four it equals `0x8F000`. Host C++ RTTI begins immediately after this range.

The extraction includes the signed header, inner container, all five segments, gaps/trailer and original padding. It is an analysis artifact; no hardware acceptance or update operation was tested.

## 4. Firmware headers, segment layout and compression

The outer header starts with little-endian words `0x00000006`, `0x000000A1`, `0x00010000`. Other observed words are `+0x10=0x8086` and `+0x14=0x20190726`, the latter plausibly representing **2019-07-26** as a packed date. `0xA1 * 4 = 0x284` matches the start of the next structure. Field names other than the validated signature fields remain partly inferred.

At firmware-relative **0x284** is the ASCII magic **EFLI**. Its fields include `0x8EB80`, `0x10000`, segment count 5, `0xBA000`, and revision `K4110440-005`. Five 16-byte descriptors at **0x300–0x34F** contain four-byte tag, source offset, length, and a plausible destination address. Descriptor source offsets are relative to the inferred segment-data base **0x400**. The interpretation is supported by valid vectors/code at the first segment and coherent cross-segment calls.

| Segment | Firmware offset | DLL file offset | Length | Candidate load address | Entropy |
|---|---:|---:|---:|---:|---:|
| PBUF | `0x400` | `0xea4d0` | `0x3b42c` (242,732) | `0xba000` | 6.582 |
| VBUF | `0x3bc00` | `0x125cd0` | `0x48400` (295,936) | `0x400000` | 6.357 |
| SECD | `0x84000` | `0x16e0d0` | `0x7e00` (32,256) | `0x22000000` | 1.644 |
| FCFG | `0x8be00` | `0x175ed0` | `0x800` (2,048) | `0x20000000` | 1.978 |
| PMCB | `0x8c600` | `0x1766d0` | `0x2800` (10,240) | `0x21000000` | 0.135 |

- **PBUF:** ARM exception/entry branches begin at the inferred VA `0xBA000`; the reset path starts at `0xBA024`. A branch at `0xBA01C` switches into Thumb code. Other parts contain Thumb-2 code and data.
- **VBUF:** clear Thumb instructions at inferred VA `0x400000`, including valid calls back into the PBUF address range. For example, `0x400036` calls `0xD0C78`. This supports the proposed load addresses.
- **SECD:** begins `OPAL` and contains `LEVEL0` plus low-entropy data, consistent with security/configuration material; do not assume it is executable code.
- **FCFG:** begins `CFGF`, followed by version-like words and tagged configuration records.
- **PMCB:** begins `PMCB` and is mostly padding/sparse data.

After the segment data are eight uninterpreted bytes at `0x8EE00`: `D2 00 DF 0D 0B E8 DF AE`. The candidate EFLI extent, `0x284 + 4 + 0x8EB80 = 0x8EE08`, is followed by exactly **504 bytes of 0xFF**. Treat the size convention and trailer semantics as inferred. Tested straightforward CRC32 coverages did not match the trailer words.

No ZIP, gzip, xz, bzip2, 7z, CAB, framed LZ4 or Zstandard magic was found. No ELF or Intel `$FPT`/`$MN2`/`$MAN` marker was found. Three extra `MZ` byte pairs occur inside host `.text`; their supposed PE-header offsets are out of bounds, so they are not embedded PE images. Bounded tests of common zlib headers and plausible `0x5D` LZMA-alone headers produced **no complete valid decompression stream**. This does not rule out proprietary/raw codecs in subregions. However, valid direct ARM/Thumb disassembly and plaintext metadata establish that the firmware image is **not wholly encrypted or compressed**.

## 5. Two separate signature layers

**Firmware signature:** the outer firmware header contains a 256-byte RSA modulus at `+0x80`, little-endian exponent **65537** at `+0x180`, and a 256-byte signature at `+0x184`. Interpreting modulus and signature as little-endian produces a valid **RSA-2048 PKCS#1 v1.5 SHA-256** block. Cryptographic verification succeeds for exactly:

`SHA256(firmware[0:0x80] || firmware[0x284:0x8F000])`

The signed digest is `244ce0fce130929e2969257bed73af7e18ac3850700187dad537acc238df080c`. This coverage includes the 0xFF padding and excludes the modulus/exponent/signature region. `firmware_embedded_rsa_public_key.pem` preserves the recovered key. Verification proves internal consistency against the embedded key; it does not establish an externally trusted vendor key or the controller's verification policy.

**DLL Authenticode:** the recomputed PE Authenticode SHA-256 digest is `32e1c89570991bbce8ef7c33c2d2458e0ac4ffa4415ccadd356096c395bd12dc`, exactly matching the signed content. The primary signer's RSA signature and signed-attribute content digest verify against the embedded certificate with subject **Intel(R) Corporation - NAND Flash Memory**. A countersignature from **timestamp.intel.com** also verifies, including its SHA-1 message digest over the primary signature; its signed time is **2019-11-02 01:24:31 UTC**. The certificate table includes the associated Intel/QuoVadis intermediate material.

These are **offline mathematical checks**, not Windows trust validation: no trust-store/root-chain validation, revocation checks or online timestamp validation was performed. Results are in `signature_verification.json`, `firmware_analysis.json` and `authenticode_0.p7b`.

## 6. What is revealed about initialization and register access

Searches of the entire DLL, case-insensitive ASCII and UTF-16LE, found no `AHU14132`, `AHU`, `14132`, `3D XPoint`, `XPoint`, `Silicon Motion`, `SM2263`, or `PHY`. Absence of labels cannot rule out an unlabeled implementation, and the file does not confirm the prior conversation's proposed chip-vendor identity.

There is real initialization code, beyond host updater strings. The PBUF reset path reads/writes controller addresses including **0x0200A800, 0x0200A840, 0x0202001C, 0x02020018, 0x0202027C and 0x0200B000/004/008**. These addresses are derived from decoded instructions and literal pools; their hardware block/bit names are unknown and they are not established PHY registers.

Media-related evidence is more specific:

| Finding | Firmware address or offset | Static evidence |
|---|---|---|
| Initialization candidate | VA `0xDA3DA` | Contains setup, per-index loops and error paths |
| `*ID_BAD_MEDIA_PLL` | VA `0xDA6A8`, firmware offset `0x20AA8` | ADR at `0xDA4A4`, then error/log call at `0xDA4AC` after a polling/elapsed-value condition |
| `*MISSING_DQS` | VA `0xDA6BC`, firmware offset `0x20ABC` | ADR at `0xDA58A`, call at `0xDA594` |
| `*TRAINING_FAILED` | VA `0xDAC90`, firmware offset `0x21090` | ADR at `0xDAB46`, call at `0xDAB4C`, when a stored count is less than 2 |
| Training-related candidate | VA `0xDAA74` | Register-like reads and loops precede the training failure path |
| Register-read candidate | `0xE2B48 → 0xE2E28 → 0xE7D5A` | Selector packing, command submission, response read |
| Register-write candidate | `0xE2B60 → 0xE2E3A → 0xE8076` | Selector/value packing and command submission |
| Completion poll | VA `0xE7BF8` | Polls status bit 0; success requires ten successive set observations within a counter limit |
| Response bit transformation | VA `0xE8FF0` | Shifts/masks/recombines bits; full permutation not reconstructed |

The candidate access functions constrain a first index to **0..1** and a second to **0..7**. Interpreting these as channel/die indexes is plausible but not proven. They obtain a register-window base via the object slot at `ctx + 0x110 + 4*first_index`, then dereference the stored wrapper/base pointer.

| Controller-window field | Observed behavior |
|---|---|
| `base + 0x08` | Status bit 0 checked before submission and in the poll helper |
| `base + 0x1C` | Command word |
| `base + 0x20` | Selector shifted left 16 for reads; selector shifted left 16 OR value argument for writes |
| `base + 0x30` | Response read in the read candidate, followed by bit transformations |
| Command bits 3:0 | `0xC` in the read candidate, `0xD` in the write candidate |
| Command bits 18:16 | Second index |
| Other command bits | Bit 8 cleared, bit 28 from a per-first-index flag, bit 31 set; other bits preserved |

This reveals a **partial controller-side register-command mechanism** and useful initialization/training entry points. It does **not** show that 0xC/0xD are commands on the physical 3D XPoint interface, identify the external register bank, recover a complete PHY initialization sequence, or establish pins, signal timings, voltage levels, training parameters, register names or bit semantics. The evidence supports continuing static reverse engineering; it does not support claiming that an AHU14132/3D XPoint protocol has already been recovered.

All firmware VAs above use the inferred PBUF base. For a PBUF address `v`: PBUF offset = `v - 0xBA000`; firmware offset = that + `0x400`; original DLL file offset = that + `0xEA4D0`. Host DLL RVAs/VA values use a different address space.

## 7. Useful next steps, all offline

1. Import the extracted PBUF/VBUF into a disassembler as little-endian ARM, at `0xBA000` and `0x400000`. Use ARM mode for the PBUF entry vectors, Thumb mode for the cited media routines and VBUF. Mixed code/data must be marked explicitly; the provided linear disassembly also decodes some literal pools as apparent instructions. The load addresses are supported by header fields and coherent calls, but are still reconstructed, not observed at runtime.
2. Follow the `0xDA3DA` initialization and `0xDAA74` training paths, using the **confirmed ADR string references**, rather than treating every printable word as a symbol. Recover call arguments, loop counts, conditional ordering and delays.
3. Trace the context constructor at `0xE74CC` and its callers to recover the actual per-index register-window base addresses. Then annotate `0xE7D5A`, `0xE8076`, `0xE7BF8` and the response permutation at `0xE8FF0`. This is the shortest path toward a defensible register map.
4. Decode the FCFG/PMCB tagged records and relate values to initialization code. `OPAL` security data should be analyzed separately from media/PHY setup.
5. If another already-obtained StonyBeach/M10 firmware revision is available, statically compare segment tables, key fingerprints and the initialization routines. Changes around the verified PLL/DQS/training paths would be more informative than host DLL differences.
6. For confirming **AHU14132 identity and external XPoint protocol**, obtain trusted chip/board documentation, clear chip markings/board connectivity evidence, or an independently obtained matching controller firmware/ROM artifact. This DLL alone cannot settle those mappings.

The bundle contains the full image, five carved segments, machine-readable inventories, complete strings, entropy tables, recovered signature data and focused disassembly evidence. Nothing needs to be loaded as a Windows DLL to use these results.
