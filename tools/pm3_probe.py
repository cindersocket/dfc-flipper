#!/usr/bin/env python3
"""Build the 33-byte payload for Proxmark3 Iceman `hf mfdes sim --probe`.

The probe loads a synthetic card image (hf mfdes eload) and, when a live reader
starts AES authentication on the target application, answers the challenge with
the key embedded in that image and reports whether the reader continued
consistently with that key (MATCH) or not. It never completes auth, so it does
not open a door -- it is a credential/key validation + reader-behaviour probe.

Layout (packed, 33 bytes) -- verified against include/desfire.h
(struct desfire_sim_probe_cmd_t) on rfidresearchgroup/proxmark3 master:

  off size field                value
  0   3    aid[3]               target AID, WIRE ORDER (LSB-first on the wire)
  3   1    keyno                0xFF = accept the key number the reader requests
  4   1    algorithm            0x03 = T_AES  (DesfireCryptoAlgorithm)
  5   4    candidate_id (LE)    opaque host tag, never key material
  9   16   rndb                 fresh host nonce (MUST be random every live run)
  25  3    discovery_aid[3]     000000 = disabled
  28  1    discovery_file       00
  29  2    overall_timeout (LE) ms, 1000..60000
  31  2    continuation  (LE)   ms, 100..overall_timeout

Outcome codes printed by the Proxmark when the probe ends:
  0 DISCOVERY_FAILED  reader did not select/read the expected app before target
  1 NO_RESPONSE       reader field on but no frames the sim decoded
                      (watch for this: it is the signature of the sim NOT
                       following the reader's PPS rate switch, same wall as the Flipper)
  2 NO_MATCH          reader continued AES auth but not consistent with our key
                      (expected when the loaded key is not the reader's key)
  3 MATCH             reader continued consistent with our key -> credential+key correct
  4 UNSUPPORTED       reader used a non-AES / unsupported auth path

Usage:
  python pm3_probe.py <AID hex e.g. D3494F> [--keyno FF] [--algo 03]
         [--candidate 1] [--rndb <32 hex>] [--overall 30000]
         [--continuation 5000] [--aid-order wire|stored]

The AID is emitted LSB-first (wire order) by default, because DESFire
SelectApplication carries the AID LSB-first. If the probe returns
DISCOVERY_FAILED / NO_RESPONSE against a reader you KNOW selects that AID,
re-run with --aid-order stored to emit it as written.
"""
import sys
import os
import argparse


def main():
    p = argparse.ArgumentParser(description="Build hf mfdes sim --probe payload")
    p.add_argument("aid", help="3-byte application AID in hex, e.g. D3494F")
    p.add_argument("--keyno", default="FF", help="key number hex (default FF=reader-requested)")
    p.add_argument("--algo", default="03", help="algorithm hex (default 03=AES)")
    p.add_argument("--candidate", type=int, default=1, help="opaque candidate id (default 1)")
    p.add_argument("--rndb", default=None, help="16-byte nonce hex (default: fresh random)")
    p.add_argument("--overall", type=int, default=30000, help="overall timeout ms (default 30000)")
    p.add_argument("--continuation", type=int, default=5000, help="post-challenge timeout ms (default 5000)")
    p.add_argument("--aid-order", choices=["wire", "stored"], default="wire",
                   help="wire=LSB-first (default), stored=as written")
    a = p.parse_args()

    aid = bytes.fromhex(a.aid.replace(" ", ""))
    if len(aid) != 3:
        sys.exit("error: AID must be exactly 3 bytes")
    if a.aid_order == "wire":
        aid = aid[::-1]  # SelectApplication sends the AID LSB-first

    keyno = bytes([int(a.keyno, 16)])
    algo = bytes([int(a.algo, 16)])
    candidate = a.candidate.to_bytes(4, "little")
    rndb = bytes.fromhex(a.rndb.replace(" ", "")) if a.rndb else os.urandom(16)
    if len(rndb) != 16:
        sys.exit("error: rndb must be exactly 16 bytes")

    if not (1000 <= a.overall <= 60000):
        sys.exit("error: --overall must be 1000..60000 ms")
    if not (100 <= a.continuation <= a.overall):
        sys.exit("error: --continuation must be 100..overall ms")

    disc_aid = b"\x00\x00\x00"
    disc_file = b"\x00"
    overall = a.overall.to_bytes(2, "little")
    cont = a.continuation.to_bytes(2, "little")

    payload = aid + keyno + algo + candidate + rndb + disc_aid + disc_file + overall + cont
    assert len(payload) == 33, f"payload is {len(payload)} bytes, expected 33"

    hexp = payload.hex().upper()
    sys.stderr.write(
        f"AID(wire)={aid.hex().upper()} keyno={keyno.hex().upper()} "
        f"algo={algo.hex().upper()} rndb={rndb.hex().upper()}\n"
        f"overall={a.overall}ms continuation={a.continuation}ms\n"
    )
    print("hf mfdes sim --probe " + hexp)


if __name__ == "__main__":
    main()
