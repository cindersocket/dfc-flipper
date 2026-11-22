#!/usr/bin/env python3
"""Convert a DFC credential (.dfc text format) to a Proxmark3 Iceman
"mfdes v1" card image (JSON), loadable with `hf mfdes eload` and simulated
with `hf mfdes sim`.

Why: the Flipper Zero emulates ISO14443-4 at 106 kbit/s only, which some
access-control readers refuse at the activation layer. A Proxmark3 can present
the same credential at the higher bitrates a real DESFire negotiates, so a card
that a Flipper cannot get read may still be simulated from a Proxmark.

Usage:
    python dfc2pm3.py <input.dfc> [output.json] [--ats <hex>]

--ats overrides the ATS the image advertises. Default advertises TA1=0x77
(212/424/848 kbit/s both directions), which is the whole point of moving to the
Proxmark. To match the real card byte-for-byte, capture it on the Proxmark with
`hf 14a info` and pass that ATS here.

Only Standard Data and Backup Data files are fully mapped (what access-control
credentials use); value/record files are passed through best-effort with a
warning. Keys are embedded so the simulated card can authenticate.
"""
import sys
import json
import re

# A clean DESFire ATS that advertises higher bitrates (TA1=0x77). TL=0x06,
# T0=0x75 (TA1/TB1/TC1 present, FSCI=5), TA1=0x77 (DR/DS 212/424/848),
# TB1=0x81 (FWI=8,SFGI=1), TC1=0x02 (CID yes, NAD no), T1=0x80 (historical).
DEFAULT_ATS = "067577810280"

GEN_VER = {
    # generation: (major, minor) identifying bytes in VersionHW/SW
    "EV1": (0x01, 0x00),
    "EV2": (0x12, 0x00),
    "EV3": (0x33, 0x00),
}


def hexclean(v):
    return re.sub(r"[^0-9A-Fa-f]", "", v).upper()


def storage_code(storage_bytes):
    # size = 2^(code>>1); 2048->0x16, 4096->0x18, 8192->0x1A
    n = int(storage_bytes)
    code = 0
    size = 1
    # find code such that 2^(code>>1) == n, trying even codes
    for c in range(0, 32, 1):
        if (1 << (c >> 1)) == n:
            code = c
            break
    # prefer the canonical even code for whole-chip sizes
    for c in (0x16, 0x18, 0x1A, 0x1C):
        if (1 << (c >> 1)) == n:
            return c
    return code or 0x1A


def parse_dfc(text):
    d = {}
    for line in text.splitlines():
        line = line.rstrip("\n")
        s = line.strip()
        if not s or ":" not in s:
            continue
        k, v = s.split(":", 1)
        d[k.strip()] = v.strip()
    return d


def keytype_from(ks2, auth_mode, key_hex):
    crypto = ks2 & 0xC0
    if crypto == 0x80:
        return "aes"
    if crypto == 0x40:
        return "3tdea"
    # crypto == 0x00: DES or 2K3DES
    if auth_mode.upper() == "D40" and len(key_hex) == 16:  # 8 bytes
        return "des"
    return "2tdea"


FILETYPE = {
    "Standard Data": ("standard", "00"),
    "Backup Data": ("backup", "01"),
    "Value": ("value", "02"),
    "Linear Record": ("linear_record", "03"),
    "Cyclic Record": ("cyclic_record", "04"),
}

COMMMODE = {"00": "plain", "01": "mac", "02": "mac", "03": "encrypt"}


def build_keys(d, prefix, numkeys):
    keys = {}
    for i in range(numkeys):
        kk = f"{prefix}Key {i:02X}"
        vk = f"{prefix}Key {i:02X} Version"
        if kk not in d:
            continue
        entry = {}
        if vk in d:
            entry["Version"] = hexclean(d[vk])
        else:
            entry["Version"] = "00"
        entry["Key"] = hexclean(d[kk])
        keys[str(i)] = entry
    return keys


def build_app(d, prefix, aid_hex):
    ks1 = hexclean(d.get(prefix + "Key Settings 1", "0F"))
    ks2_hex = hexclean(d.get(prefix + "Key Settings 2", "00"))
    ks2 = int(ks2_hex, 16) if ks2_hex else 0
    numkeys = int(d.get(prefix + "Key Count", "1"))
    auth_mode = d.get(prefix + "Authentication Mode", "D40")
    # pick key type from the first present key length
    first_key = hexclean(d.get(prefix + "Key 00", ""))
    app = {
        "KeySettings": ks1,
        "NumKeysRaw": f"{ks2:02X}",
        "NumKeys": numkeys,
        "KeyType": keytype_from(ks2, auth_mode, first_key),
        "Authenticated": True,
        "Keys": build_keys(d, prefix, numkeys),
    }
    dfname = d.get(prefix + "DF Name")
    if dfname:
        app["DFName"] = hexclean(dfname)
    isofid = d.get(prefix + "ISO File ID")
    if isofid:
        app["ISOFileID"] = hexclean(isofid)
    # files
    fcount = int(d.get(prefix + "File Count", "0"))
    files = {}
    for fi in range(fcount):
        fp = f"{prefix}File {fi:02X} "
        num = d.get(fp + "Number")
        if num is None:
            continue
        fnum = hexclean(num)
        ftype_name = d.get(fp + "Type", "Standard Data")
        tname, traw = FILETYPE.get(ftype_name, ("standard", "00"))
        comm = hexclean(d.get(fp + "Communication Settings", "00"))
        fobj = {
            "Type": tname,
            "TypeRaw": traw,
            "CommMode": COMMMODE.get(comm, "plain"),
            "AccessRights": hexclean(d.get(fp + "Access Rights", "0000")),
        }
        isoff = d.get(fp + "ISO File ID")
        if isoff:
            fobj["ISOFileID"] = hexclean(isoff)
        if tname in ("standard", "backup"):
            size = int(d.get(fp + "Size", "0"))
            fobj["FileSize"] = size
            data = hexclean(d.get(fp + "Data", ""))
            # pad to declared size
            if len(data) < size * 2:
                data = data + "00" * (size - len(data) // 2)
            fobj["Data"] = data[: size * 2] if size else data
            fobj["Read"] = True
        else:
            # value / record: best effort, warn
            sys.stderr.write(
                f"WARNING: file {fnum} type '{ftype_name}' not fully mapped; "
                "emitting header only. Check it on the Proxmark.\n"
            )
            fobj["Read"] = False
        files[fnum] = fobj
    if files:
        app["Files"] = files
    return app


def build_image(d):
    uid = hexclean(d.get("UID", ""))
    gen = d.get("Card Generation", "EV3").upper()
    storage = d.get("Card Storage", "8192")
    major, minor = GEN_VER.get(gen, GEN_VER["EV3"])
    scode = storage_code(storage)
    vhw = bytes([0x04, 0x01, 0x01, major, minor, scode, 0x05]).hex().upper()
    vsw = bytes([0x04, 0x01, 0x01, major, minor, scode, 0x05]).hex().upper()
    # VersionProd: UID(7) + batch(5) + CW(1) + Year(1) = 14 bytes (synthetic)
    uid_bytes = bytes.fromhex(uid) if len(uid) in (8, 14) else b""
    prod = (uid_bytes + bytes(14 - len(uid_bytes))).hex().upper()

    card = {
        "UID": uid,
        "ATQA": hexclean(d.get("PICC ATQA", "4403")),
        "SAK": hexclean(d.get("PICC SAK", "20")),
        "ATS": d["_ats"],
        "VersionHW": vhw,
        "VersionSW": vsw,
        "VersionProd": prod,
    }
    storage_overhead = 256
    try:
        card["FreeMem"] = max(0, int(storage) - storage_overhead)
    except ValueError:
        pass

    apps = {}
    # PICC master settings/keys -> application 000000
    apps["000000"] = build_app(d, "PICC ", "000000")

    appcount = int(d.get("Application Count", "0"))
    for ai in range(appcount):
        prefix = f"Application {ai:02X} "
        aid = hexclean(d.get(prefix + "AID", ""))
        if not aid:
            continue
        apps[aid] = build_app(d, prefix, aid)

    return {
        "Created": "dfc2pm3",
        "FileType": "mfdes v1",
        "Version": 1,
        "Card": card,
        "Applications": apps,
    }


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    inp = argv[1]
    out = None
    ats = DEFAULT_ATS
    rest = argv[2:]
    i = 0
    while i < len(rest):
        if rest[i] == "--ats" and i + 1 < len(rest):
            ats = hexclean(rest[i + 1])
            i += 2
        else:
            out = rest[i]
            i += 1
    if out is None:
        out = inp.rsplit(".", 1)[0] + ".json"

    with open(inp, "r", encoding="utf-8") as f:
        d = parse_dfc(f.read())
    d["_ats"] = ats
    img = build_image(d)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(img, f, indent=2)
        f.write("\n")
    sys.stderr.write(
        f"Wrote {out}\n"
        f"  UID={img['Card']['UID']} gen={d.get('Card Generation')} "
        f"apps={len(img['Applications'])} ATS={img['Card']['ATS']}\n"
        f"Load on Proxmark3 (Iceman):\n"
        f"  hf mfdes eload -f {out}\n"
        f"  hf mfdes sim\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
