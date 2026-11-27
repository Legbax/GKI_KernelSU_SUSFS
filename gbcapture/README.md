# gbcapture — in-kernel member-plaintext capture (raven, WildKernels GKI fork)

Reads the Snap **member plaintext** (the cached ~668B sub-collector blob + the serialized member
before whiten) straight out of Snap's address space **from EL1**, invisibly to RASP. Built to break
the capture wall where frida/ptrace/heap-scan all fail:

| wall | why kernel HW-bp beats it |
|---|---|
| self-CRC32 over `.text` @ `0xbe858` (§9.2) | HW breakpoints do **not** modify memory → CRC sees pristine bytes (uprobe/`brk` would be caught) |
| frida off52 contamination (§7) | no in-process instrumentation; capture is clean |
| seccomp `Seccomp_filters` 1→2 tell (§5.4) | no seccomp filter installed |
| `/proc/self/mem` `-EIO` RASP | `copy_from_user_nofault` / `access_process_vm` from kernel, never via `/proc` |
| ptrace↔gb_force trigger conflict | wide HW-bp coexists with any trigger; no ptrace attach |

## ⛔ HARD RULES
- **NO login. NO `pm clear`. This is REFRESH only.** `pm clear`/login would log out the live
  survival-test account. Never suggest or do either. (Owner rule, relayed by Melaza 2026-11-27.)
- The member is **CACHED**: built once (login/first-sign) and reused per-refresh. We do **NOT** try to
  catch the build (measured: uprobe `0x13ba10` = 0 hits cold-startup; builder `0x139054` = 0 hits in
  refresh). We target the **cache READ** that runs on every refresh/`gb_force`.

## Measured anchors (raven, Papagayo/Melaza, 2026-11-27)
- orchestrator `base+0x14cfcc` (fires 4×) → table of ~20 sub-collector fn-ptrs; **one** writes the
  +668B to **`context+0xB8`**.
- `base+0x13bbc0` = whiten (too late — whitened). `base+0x128c6c` = cipher prologue
  `ff 43 06 d1 fd 7b 13 a9 fc 6f 14 a9 fa 67 15 a9` (locates base).
- libscplugin base = `maps` segment with `pgoff 0x59ec000`, minus `0x59ec000`. uid=10308, pid=3325
  (**per-run — resolve at runtime**, ASLR).
- **PENDING (Papagayo):** the per-refresh serializer **read-RVA** of `context+0xB8` (+ which reg/stack
  holds ptr+len there), and whether `context` is reachable by a pointer chain from a **static**
  `.data/.bss` symbol. Those two pick the mode below.
- **✅ RESOLVED (Papagayo, 2026-11-27): the cache at `context+0xB8` is WHITENED** (2-run diff, 0.7%
  match = noise) → **PEEK of the cache is MOOT** (scrambled bytes, not plaintext). The plaintext +668B
  is built during the **app INIT** (owner reframe), which runs on every **cold-start** (force-stop +
  relaunch, **no login**). ⟹ the PRIMARY mode is **AUTO-ARM** (`watch`): a clean EXEC HW-bp at the init
  build-point **`base+0x13ba10`** (before the fold `0x13bbc0`) captures the plaintext pre-fold on each
  cold-start. (The earlier uprobe 0-hits at `0x13ba10` was an ARTIFACT — uprobe patches `.text` →
  self-CRC `0xbe858` aborts the build phase; the HW-bp doesn't, so the init-build runs clean.)
  - build-point RVA `0x13ba10` → **`--build-off 0x5b27a10`** (apk-file-offset `0x59ec000`+RVA, since
    libscplugin is embedded in the apk); `len=[sp+2048]`, `ptr=[sp+2056]` → `--addr deref --base-reg sp
    --off-ptr 2056 --len deref --len-reg sp --off-len 2048`.
  - **EXEC-keystream** (backup, if the build turns out login-only — not yet measured) + **PEEK** (moot)
    kept for completeness.

## Files
- `gb_capture.c` — the in-kernel core (tree-agnostic). Entry `gb_capture_cmd(cmd,arg)` +
  `gb_capture_init()`. Dump at **`/proc/gbcap`** (2 MiB ring, root `0400`).
- `gb_capture_arm.c` — userspace trigger (`arm|peek|disarm|reset`).
- `gbcap_scan.py` — offline dump parser.

## Addressing (one build, any anchor — no rebuild to chase an offset)
- src ptr: `REG` (`x[base]+off`) · `ABS` (`capture_addr`) · `DEREF` (`*(x[base]+off)`, base `31`=SP)
- length: `FIXED` (`len_fixed`) · `DEREF` (`*(x[len_reg]+off_len)`, `31`=SP)
- trap: `exec` (insn bp) · `dataw` (write WP) · `datar` (**read WP** — the per-refresh cache read)
- `peek`: on-demand `access_process_vm` read by PID (+1 optional deref) — no breakpoint.
- `watch`: **AUTO-ARM (primary)** — kernel kretprobes `mmap_region`, watches the mmap of the apk that
  carries libscplugin, resolves `vm_start − (pgoff<<PAGE_SHIFT)` = the **apk-file-base**, and arms an
  EXEC bp at `apk_file_base + --build-off` from a workqueue **before the init-build runs**. ✅
  `mmap_region` kprobe-able on raven, args x0=file / x4=pgoff (Melaza 2026-11-27); built-in (`obj-y`)
  only. Re-arms on each cold-start's fresh base.
  - ⚠ **`--build-off` is the APK-FILE-OFFSET, not the lib RVA.** libscplugin is stored inside the apk
    at apk-offset `0x59ec000`, so the base above is the apk-file-base → `--build-off = 0x59ec000 + RVA`.
    The init-build RVA `0x13ba10` → **`--build-off 0x5b27a10`**. `--lib split_config` (the mapped file
    is the apk `split_config.arm64_v8a.apk`, never "libscplugin").
- **call-stack / attribution** (any exec bp or watch): `--stack-len N` also dumps N bytes of stack from
  `sp`; `--fp-depth K` walks K frame-pointer levels (`x29`) for the return-address chain. Every record
  also carries **x0–x30 + sp + pc + pstate + lr**. Settles "member vs frida vs which sub-collector"
  from one capture (the LR chain minus the lib base = caller RVAs).
- **6 exec + 4 data bps at once** (`GBCAP_MAX_BPS=10`) — arm the whole pipeline simultaneously (build
  `0x13ba10` + cipher `0x128c6c` + fold `0x13bbc0` + orchestrator `0x14cfcc` + sub-collectors) and read
  the order/dataflow off the per-record timestamps in one run.
- **multi-level deref** (`sym→a→b→context+0xB8`): resolved USERSPACE-side — read `/proc/<pid>/mem` as
  root (no `-EIO` from outside) to walk the chain to the final VA, then one `peek`/`arm` at it.
  In-kernel DEREF is single-hop by design.

## Build — kernel (in-tree inject, like the uptime / .nomedia patches)
Target fork `Legbax/GKI_KernelSU_SUSFS` (raven, gki-android14-6.1). **ONE** wiring point — NO
susfs-init edit, NO dispatch hook: `gb_capture.c` self-registers via `late_initcall` and owns its
control via `/proc/gbcap_ctl` (CAP_SYS_ADMIN-gated inside the handler). This sidesteps raven's susfs
dispatch, which is NOT merlin's reboot-magic (raven's clock-offset was hardcoded in
`timekeeping_init`, so it may have no reboot(2) CMD path at all):
1. drop `gb_capture.c` into the KernelSU/susfs source dir; add its object to that `Makefile` as
   **built-in** (`obj-y` — late_initcall only fires for built-in, not a module).
   (`apply_gbcapture.py` automates this.)
2. ✅ `CONFIG_HAVE_HW_BREAKPOINT=y` + `register_wide_hw_breakpoint` / `access_process_vm` exported —
   **CONFIRMED on raven** (config.gz + kallsyms, Melaza 2026-11-27). Build via the fork's Actions
   workflow, flash the repacked `boot.img` by fastboot. **Keep the known-good boot for revert.**

## Build — userspace (native aarch64, static)
```
aarch64-linux-gnu-gcc -O2 -static -o gb_capture gb_capture_arm.c
```
Push `gb_capture` + `gbcap_scan.py` to the device; run `gb_capture` as **root**.

## Runbook — AUTO-ARM the init-build (PRIMARY; NO login, NO pm-clear)
Catches the +668B plaintext as the app INIT builds it, before the fold `0x13bbc0`. Arm `watch` first,
then cold-start Snap so the kernel auto-arms at the fresh ASLR base.
```sh
# 1. clear the ring + arm the watch (kernel resolves base from libscplugin's mmap)
./gb_capture reset
./gb_capture watch --uid 10308 --lib split_config --build-off 0x5b27a10 \
    --addr deref --base-reg sp --off-ptr 2056 \
    --len  deref --len-reg  sp --off-len 2048 --max-len 8192 \
    --stack-len 512 --fp-depth 16        # +call-stack for attribution

# 2. COLD-START Snap (re-runs app init → the init-build fires the bp). NO login, NO pm clear.
am force-stop com.snapchat.android
monkey -p com.snapchat.android -c android.intent.category.LAUNCHER 1

# 3. drain + parse (dmesg: "gbcap: auto-armed init-build bp @ 0x...")
cat /proc/gbcap > /data/local/tmp/dump.bin
python3 gbcap_scan.py /data/local/tmp/dump.bin --out recs

# 4. stop the watch
./gb_capture unwatch
```
If the init-build never fires (→ it may be login-only after all — NOT yet measured, the prior 0-hits
was a uprobe artifact), fall back to **EXEC-keystream**: arm an EXEC bp at the whiten `0x13bbc0` to grab
the ChaCha key material + decode offline (`project_1433_member_decode_wall_is_churn_seed…`). The cache
**PEEK is moot** (measured whitened). Base can be resolved manually too:
`base=$(awk '$3=="59ec000"{print $1}' /proc/$(pidof com.snapchat.android)/maps | cut -d- -f1)`.

## Validation — clean-control (§7, mandatory before trusting a capture)
Capture the wire member of a refresh **without** any bp armed, then **with** the anchor armed.
Outside the region we read, the two wire members must be **byte-identical** — that proves the HW-bp
read did not perturb off52/timing (no contamination). A diff outside the read region = reject the
capture and investigate before concluding anything about the plaintext.

## Notes
- EXEC/build anchors (`0x13ba10`, `0x139054`) stay supported in the tool but are **not** the refresh
  target (build-once, don't re-fire in refresh). Keep them only to re-confirm build-once cleanly.
- `register_wide_hw_breakpoint` is CPU-wide + uid-filtered in the handler → thread-agnostic (catches
  whatever thread serializes), and only Snap's uid at the ASLR'd VA matches.
- Per the owner methodology, this is an RE capture instrument; a frida/ptrace-assisted rc16 must be
  validated against this clean kernel capture (§7 capture-contamination).
