#!/usr/bin/env python3
# gbcap_scan.py — offline parser for a /proc/gbcap dump produced by gb_capture.c.
# Usage: python3 gbcap_scan.py dump.bin [--out recs/] [--needle <ascii-or-0xhex> ...] [--min-str 4]
#
# Pure offline analysis — never touches the device. Each record = fixed 336-byte header + a main
# payload + an optional stack window + an optional frame-pointer call-stack (attribution). Interpret
# payloads against SNAP_SEAL_COMPOSITION.md; the call-stack (lr + walked return addresses) tells you
# WHO built/read the capture (member vs frida vs which sub-collector) — minus the lib base = the RVA.
import sys, os, struct, argparse

HDR = struct.Struct("<IIIIII" + "Q" * 39)   # 6 u32 (magic,slot,flags,len,stack_len,fp_depth) + 39 u64
HDR_LEN = HDR.size                           # = 336
MAGIC = 0x31434247  # "GBC1"

def ascii_runs(b, minlen):
    out, cur = [], bytearray()
    for ch in b:
        if 32 <= ch < 127:
            cur.append(ch)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("ascii", "replace"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("ascii", "replace"))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--out", default="recs")
    ap.add_argument("--needle", action="append", default=[])
    ap.add_argument("--min-str", type=int, default=4)
    a = ap.parse_args()
    needles = [(n, bytes.fromhex(n[2:]) if n.startswith("0x") else n.encode()) for n in a.needle]

    data = open(a.dump, "rb").read()
    os.makedirs(a.out, exist_ok=True)
    off, idx = 0, 0
    print(f"# {len(data)} bytes, parsing records (hdr={HDR_LEN})")
    while off + HDR_LEN <= len(data):
        f = HDR.unpack_from(data, off)
        magic, slot, flags, plen, stack_len, fp_depth = f[0:6]
        fire_va, src_va, raw_len, pc, sp, lr, pstate, ts = f[6:14]
        regs = f[14:45]   # x0..x30
        if magic != MAGIC:
            print(f"!! bad magic 0x{magic:08x} at off {off} — stop")
            break
        off += HDR_LEN
        payload = data[off:off + plen];            off += plen
        stack   = data[off:off + stack_len];       off += stack_len
        fpbytes = data[off:off + fp_depth * 16];   off += fp_depth * 16
        fp = struct.unpack_from("<" + "Q" * (fp_depth * 2), fpbytes) if fp_depth else ()

        tag = "PEEK" if slot == 0xFFFFFFFF else f"slot{slot}"
        trunc = " TRUNC" if (flags & 1) else ""
        fault = " DEREF-FAULT" if (flags & 2) else ""
        print(f"\n[{idx}] {tag} len={plen} raw_len={raw_len} stack={stack_len} fp={fp_depth}{trunc}{fault}")
        print(f"     fire_va=0x{fire_va:x} src_va=0x{src_va:x} pc=0x{pc:x} lr=0x{lr:x} sp=0x{sp:x} ts={ts}")
        print(f"     x0..x7=" + " ".join(f"0x{r:x}" for r in regs[:8]))
        if fp_depth:
            lrs = [fp[i * 2 + 1] for i in range(fp_depth)]   # saved_lr per frame = the call-stack
            print(f"     callstack: 0x{lr:x} <- " + " <- ".join(f"0x{x:x}" for x in lrs))
        pf = os.path.join(a.out, f"rec_{idx:03d}_{tag}.bin")
        open(pf, "wb").write(payload)
        if payload:
            print(f"     head: {payload[:48].hex(' ')}")
            strs = ascii_runs(payload, a.min_str)
            if strs:
                print(f"     strings({len(strs)}): " + " | ".join(strs[:12]))
            for n, raw in needles:
                p = payload.find(raw)
                if p >= 0:
                    print(f"     ** needle {n} @ +{p}")
        if stack:
            sfn = os.path.join(a.out, f"rec_{idx:03d}_{tag}.stack")
            open(sfn, "wb").write(stack)
        print(f"     -> {pf}" + (f"  (+ .stack {stack_len}B)" if stack else ""))
        idx += 1
    print(f"\n# {idx} records -> {a.out}/")

if __name__ == "__main__":
    main()
