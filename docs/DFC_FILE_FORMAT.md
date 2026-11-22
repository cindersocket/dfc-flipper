# DFC Credential File Format

This document describes the on-disk format of a **DFC credential** — the file the
DFC reader/emulator (CinderSocket `dfc-flipper`) saves and loads to represent one
MIFARE DESFire card (EV1 / EV2 / EV3). It is the authoritative, human-facing
description of what the text parser (`lib/core/src/dfc_text.c`) and the binary
codec (`lib/core/src/dfc_der.c`) accept.

> Audience: developers and power users creating or inspecting `.dfc` / `.dfcb`
> files by hand or with tooling. Field names and rules below are taken directly
> from the parser, not from memory.

---

## 1. Two encodings: `.dfc` (text) and `.dfcb` (binary)

A credential can be stored two ways. Both describe the **same** model and are
interchangeable:

| Form | Extension | First byte | Decoder | Needs the text-codec plugin? |
|------|-----------|-----------|---------|------------------------------|
| Text | `.dfc`    | a letter (`F` of `Filetype`) | `dfc_text_parse` | **Yes** (`dfc_text_import.fal`) |
| Binary (DER/ASN.1) | `.dfcb` | `0x60` | `dfc_der_decode` | No |

- **Text** is human-readable and the format the Flipper app writes when you save a
  card. It is self-describing (`Key: Value` lines).
- **Binary** is compact and loads with no plugin, so it is the memory-cheap form
  on a constrained device. Produce one from a text file with
  `tests/compile_dfcb.py input.dfc output.dfcb` (set `CC=gcc` on Windows).

The loader picks the decoder from the **first byte**, not the extension: a file
whose first byte is `0x60` is treated as binary, anything else as text.

---

## 2. Text syntax rules

- One field per line, `Key: Value`. The value must be non-empty.
- **Lines are order-sensitive.** The parser looks for each key in a fixed order;
  a key that appears out of order is reported as "unrecognised or out of order".
- Byte strings are **uppercase** hex octet pairs separated by single spaces, e.g.
  `04 A1 7C 6E 9B 2D 58`. Lowercase or missing separators are rejected.
- Integers are plain decimal with no leading zeros (except the value `0`).
- Booleans are `0` or `1`.
- No trailing whitespace is allowed on a line (watch out for `CRLF` line endings
  on Windows — save as `LF`).
- `Filetype` and `Version` **must be the first two lines, in that order.**

The current format version is **6**. Older versions (e.g. 4) are still accepted;
some fields below are gated on `Version >= 6` and are noted as such.

---

## 3. File header (always first)

```
Filetype: DFC Credential
Version: 6
```

---

## 4. Card-level fields

These describe the physical card the credential emulates.

| Key | Required | Value | Notes |
|-----|----------|-------|-------|
| `Card Generation` | yes | `EV1` \| `EV2` \| `EV3` | Selects the chip generation. |
| `Card Storage` | yes | bytes | One of `1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072`. EV3 is limited to `2048/4096/8192`. Maps to the GetVersion storage code (`8192 → 0x1A`). |
| `UID` | yes | 7 octets | Must start with `0x04` (NXP) to be detectable in the field. |
| `UID Provenance` | yes | `Real` \| `Random` \| `Unknown` | Where the UID came from. |
| `Card Static Signature` | optional | 56 octets | Originality signature (only meaningful when static-signature support is built in). |
| `Card Hardware Version` | optional | 7 octets | Overrides the GetVersion hardware frame. If absent, it is synthesised from generation + storage, e.g. EV3 8K → `04 01 01 33 00 1A 05`. |
| `Card Software Version` | optional | 7 octets | Overrides the GetVersion software frame. |

---

## 5. PICC (card master) fields

The PICC level is "application 0" — the card master key and card-wide settings.

| Key | Required | Value | Notes |
|-----|----------|-------|-------|
| `PICC Key Settings 1` | yes | 1 octet | DESFire key-settings byte 1 (change/config bits), commonly `0F`. |
| `PICC Key Settings 2` | yes | 1 octet | Crypto + key count. High bits select the crypto of the master key: `0x00` = DES/2K3DES, `0x40` = 3K3DES, `0x80` = AES. **The authentication commands below must match this crypto.** |
| `PICC Authentication Commands` | yes *(Version ≥ 6)* | comma list | Allowed auth commands: `D40, ISO, AES, EV2First, EV2NonFirst, ISO7816`. Must be consistent with the key crypto (e.g. `AES`/`EV2First` require an AES master key). |
| `PICC Preferred Authentication Command` | optional *(Version ≥ 6)* | one token | Which of the above the emulator advertises/prefers. |
| `PICC Authentication Mode` | yes *(Version < 6)* | `D40` \| `ISO` \| `AES` | The pre-v6 single-mode field (what older files like Version 4 use). |
| `PICC Key Count` | yes | integer | Number of PICC keys (usually `1`). |
| `PICC Key NN` | per key | 16/24 octets | Key `NN` (`00`-based, two hex digits). Length follows the key crypto. |
| `PICC Key NN Version` | per key | 1 octet | Key version byte. |
| `PICC File Count` | yes | integer | PICC-level files (usually `0`). |

Optional PICC behaviour flags (mostly Version ≥ 6):

| Key | Value | Meaning |
|-----|-------|---------|
| `PICC Random ID` | `0`/`1` | Card answers anticollision with a random ID until authenticated. |
| `PICC Format Disabled` | `0`/`1` | FormatPICC is refused. |
| `PICC ATS` | octets | User-defined Answer-To-Select (TL-prefixed). The length octet must equal the ATS length. |
| `PICC SAK` | 1 octet | Overridden SAK. |

---

## 6. Applications

```
Application Count: <n>
```

Then, for each application `NN` (`00`-based):

| Key | Required | Value | Notes |
|-----|----------|-------|-------|
| `Application NN AID` | yes | 3 octets | DESFire AID, **DESFire byte order** (as stored on the wire). |
| `Application NN ISO File ID` | optional | 2 octets | ISO FID; reserved values are rejected. |
| `Application NN DF Name` | optional | 1–16 octets | ISO DF name / AID. |
| `Application NN Key Settings 1` | yes | 1 octet | |
| `Application NN Key Settings 2` | yes | 1 octet | Same crypto encoding as the PICC. |
| `Application NN Authentication Commands` | yes *(V≥6)* | comma list | Same token set and consistency rule as the PICC. |
| `Application NN Preferred Authentication Command` | optional *(V≥6)* | one token | |
| `Application NN Authentication Mode` | yes *(V<6)* | `D40`/`ISO`/`AES` | Pre-v6 single-mode field. |
| `Application NN Key Count` | yes | integer | |
| `Application NN Key KK` / `... Version` | per key | octets / 1 octet | Keys `KK` and versions. |
| `Application NN File Count` | yes | integer | |

(Applications may also carry key-set and delegated-application fields when those
features are built in; those are out of scope for a plain access credential.)

---

## 7. Files

For each file `KK` inside an application (`Application NN File KK ...`):

| Key | Value | Notes |
|-----|-------|-------|
| `... Number` | 1 octet | File number. |
| `... Type` | `Standard Data` \| `Backup Data` \| `Value` \| `Linear Record` \| `Cyclic Record` \| `Transaction MAC` | |
| `... Communication Settings` | 1 octet | `00` plain, `01` MACed, `03` enciphered. |
| `... Access Rights` | 2 octets | Read/Write/ReadWrite/Change nibbles. |
| `... ISO File ID` | 2 octets | Optional. |

Then type-specific fields:

- **Standard / Backup Data:** `... Size` (octets), `... Data` (hex, ≤ Size),
  `... Data Complete` (`0`/`1`; `1` requires `Data` length == `Size`).
- **Value:** `... Value Lower Limit`, `... Value Upper Limit`, `... Value`,
  and the limited-credit fields.
- **Linear / Cyclic Record:** `... Record Size`, `... Record Count`,
  `... Record KK` (one per stored record), `... Record Complete`.

---

## 8. Blank-card examples

Ready-to-use blank cards (no application, default all-zero master key) are in
[`examples/blank-cards/`](../examples/blank-cards/). Each one validates with
`tests/compile_dfcb.py` and loads on the device.

| File | Generation | Storage | Master-key crypto | Auth commands |
|------|-----------|---------|-------------------|---------------|
| `blank-ev1-2k.dfc` | EV1 | 2 KiB | DES/2K3DES | `D40, ISO` |
| `blank-ev2-4k.dfc` | EV2 | 4 KiB | AES | `AES, EV2First, EV2NonFirst, ISO7816` |
| `blank-ev3-8k.dfc` | EV3 | 8 KiB | DES/2K3DES | `ISO, ISO7816` |

Minimal blank EV3 8 KiB card:

```
Filetype: DFC Credential
Version: 6
Card Generation: EV3
Card Storage: 8192
UID: 04 00 00 00 00 00 01
UID Provenance: Random
PICC Key Settings 1: 0F
PICC Key Settings 2: 01
PICC Authentication Commands: ISO, ISO7816
PICC Preferred Authentication Command: ISO7816
PICC Key Count: 1
PICC Key 00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
PICC Key 00 Version: 00
PICC File Count: 0
Application Count: 0
```

> The master key here is all zeroes (the factory default), so a reader can
> authenticate and personalise the card from scratch.
