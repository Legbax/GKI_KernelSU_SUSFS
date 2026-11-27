// gb_capture.c — GhostBuster in-kernel member-capture instrument.
//
// Captures the login/refresh member BUILD plaintext (and/or any sub-collector output)
// straight out of Snap's address space from EL1, invisibly to RASP:
//   - no ptrace / TracerPid           (not a debugger; also dodges the gb_force trigger conflict)
//   - no Seccomp_filters 1->2 tell    (not a seccomp hook; CLAUDE.md §5.4)
//   - no .text modification           (HARDWARE breakpoints — the self-CRC32 @0xbe858 §9.2 sees pristine bytes)
//   - no /proc/self/mem round-trip    (copy_from_user_nofault from the task's own context)
//
// Measured ground truth (Melaza/Papagayo, raven, 2026-11-27):
//   * the +668B is NOT the library-set (refuted: dl_iterate_phdr=0 hits; it is the C++ unwinder).
//   * orchestrator base+0x14cfcc fires 4x, arms ~20 sub-collector fn-ptrs; ONE writes the +668B
//     to context+0xB8. Candidate dump point base+0x13ba10 with len=[sp+2048], ptr=[sp+2056],
//     BEFORE the whiten at base+0x13bbc0.
//   * ⚠ the member is CACHED — built ONCE (startup/login) then reused per-refresh. So arm the
//     wide bp BEFORE Snap launches and catch the one-time BUILD; hooking the per-sign path only
//     yields the cached/whitened blob.
//
// Addressing is GENERALIZED so one build covers every anchor shape Papagayo isolates — you never
// rebuild the kernel to chase a new offset/ABI:
//   source ptr : REG (x[base]+off) | ABS (capture_addr) | DEREF (*(x[base]+off), base=31=SP)
//   length     : FIXED (len_fixed) | DEREF (*(x[len_reg]+off_len), 31=SP)
//   trap       : EXEC (insn bp) | DATAW (write watchpoint)
// e.g. base+0x13ba10: trap=EXEC addr=DEREF base=SP off_ptr=2056  len=DEREF len_reg=SP off_len=2048.
//
// TREE-AGNOSTIC: compiled into the kernel by the per-vehicle inject (apply_gbcapture_merlin.py);
// the susfs reboot(2) dispatch calls gb_capture_cmd() with the copied-in struct, exactly like
// CMD_SUSFS_ADD_CLOCK_OFFSET (merlin_kernel/README.md — ⚠ ShockWAVE arg is void __user **).
//
// ⚠ NOT compiled on Windows. Compile-validated by the Actions kernel build. Version-compat `// COMPAT`.

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/ktime.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/version.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/err.h>
#include <asm/ptrace.h>

/* ---- wire contract with userspace (gb_capture_arm.c). Keep byte-identical. ---- */

/* CMDs through the susfs reboot(2) hook. Inject greps the CMD_SUSFS_* enum + remaps on collision. */
#define GBCAP_CMD_ARM     0x60141u   /* arg = struct gbcap_arm_req  */
#define GBCAP_CMD_DISARM  0x60142u   /* arg = NULL                  */
#define GBCAP_CMD_RESET   0x60143u   /* arg = NULL (truncate ring)   */
#define GBCAP_CMD_PEEK    0x60144u   /* arg = struct gbcap_peek_req  */
#define GBCAP_CMD_WATCH   0x60145u   /* arg = struct gbcap_watch_req */
#define GBCAP_CMD_UNWATCH 0x60146u   /* arg = NULL                   */

#define GBCAP_TRAP_EXEC   0u
#define GBCAP_TRAP_DATAW  1u  /* write watchpoint                                   */
#define GBCAP_TRAP_DATAR  2u  /* READ watchpoint — fires when the per-refresh        */
			      /* serialization READS the cached member (context+0xB8) */

#define GBCAP_ADDR_REG    0u  /* src = x[base_reg] + off_ptr        (base_reg 31 = SP) */
#define GBCAP_ADDR_ABS    1u  /* src = capture_addr                                   */
#define GBCAP_ADDR_DEREF  2u  /* src = *(u64*)(x[base_reg] + off_ptr)                 */

#define GBCAP_LEN_FIXED   0u  /* len = len_fixed                                      */
#define GBCAP_LEN_DEREF   1u  /* len = *(u64*)(x[len_reg] + off_len) (len_reg 31 = SP)*/

#define GBCAP_REGSP       31u

struct gbcap_arm_req {
	__u32 target_uid;
	__u32 trap;         /* EXEC | DATAW */
	__u64 bp_addr;      /* RUNTIME VA to break/watch (caller: base + file_off) */
	__u32 addr_mode;    /* REG | ABS | DEREF */
	__u32 base_reg;     /* 0..30, 31=SP */
	__u64 off_ptr;
	__u64 capture_addr; /* ABS mode */
	__u32 len_mode;     /* FIXED | DEREF */
	__u32 len_reg;      /* 0..30, 31=SP */
	__u64 off_len;
	__u32 len_fixed;
	__u32 max_len;       /* hard cap, <= GBCAP_MAX_LEN */
	__u32 cap_stack_len; /* also dump this many bytes of stack from sp (0 = none) */
	__u32 cap_fp_depth;  /* also walk this many frame-pointer levels (x29) (0 = none) */
} __packed;

/* on-demand read of Snap's memory at an absolute VA (no breakpoint) — reads the cached member
 * directly if context+0xB8 is a stable singleton (Melaza option (b)). access_process_vm bypasses
 * the /proc/self/mem -EIO RASP. deref: 0 = read [addr+off]; 1 = read *(u64*)[addr] then [p+off]. */
struct gbcap_peek_req {
	__u32 target_pid;
	__u32 deref;
	__u64 addr;
	__u64 off;
	__u32 len;
	__u32 max_len;
} __packed;

/* AUTO-ARM-ON-LOAD: watch Snap's mmap of libscplugin, resolve the ASLR base IN-KERNEL, and arm an
 * EXEC HW-bp at base+build_off automatically — to catch the INIT-build of the +668B, which runs in
 * the first ms of every cold-start (force-stop + relaunch, NO login). Userspace is too slow to win
 * that race; the kernel arms before the init code at base+build_off ever executes. The capture
 * descriptor is the same generalized addressing as gbcap_arm_req (minus bp_addr, which is derived). */
struct gbcap_watch_req {
	__u32 target_uid;
	__u32 _pad;
	__u64 build_off;      /* file offset of the init-build EXEC site; bp = base + build_off */
	char  lib[32];        /* substring matched in the mapped file name, e.g. "libscplugin" */
	__u32 addr_mode, base_reg;
	__u64 off_ptr;
	__u32 len_mode, len_reg;
	__u64 off_len;
	__u32 len_fixed, max_len;
	__u32 cap_stack_len, cap_fp_depth;   /* call-stack capture at the auto-armed bp */
} __packed;

#define GBCAP_REC_MAGIC  0x31434247u  /* "GBC1" LE */
/* ring layout per record: [header][main payload: len][stack window: stack_len][fp pairs: fp_depth*16] */
struct gbcap_rec {
	__u32 magic;
	__u32 bp_slot;
	__u32 flags;       /* bit0: payload truncated; bit1: ptr/len deref faulted */
	__u32 len;         /* main payload bytes (follow the header) */
	__u32 stack_len;   /* stack-window bytes (follow the payload) */
	__u32 fp_depth;    /* (saved_fp,saved_lr) u64 pairs (follow the stack window) */
	__u64 fire_va;
	__u64 src_va;
	__u64 raw_len;     /* len read before clamping (DEREF) */
	__u64 pc;
	__u64 sp;
	__u64 lr;          /* x30 = direct caller (attribution) */
	__u64 pstate;
	__u64 ts_ns;
	__u64 regs[31];    /* x0..x30 at the trap */
} __packed;

#define GBCAP_MAX_BPS    10u   /* arm64: 6 instruction + 4 data debug registers, armed together */
#define GBCAP_MAX_LEN    (64u * 1024u)
#define GBCAP_RING_BYTES (2u * 1024u * 1024u)
#define GBCAP_STACK_MAX  2048u /* max stack-window bytes per hit */
#define GBCAP_FP_MAX     32u   /* max frame-pointer levels walked per hit */

struct gbcap_slot {
	struct perf_event * __percpu *ev;
	struct gbcap_arm_req req;
	bool used;
};

static DEFINE_SPINLOCK(gbcap_lock);
static struct gbcap_slot gbcap_slots[GBCAP_MAX_BPS];
static u8   *gbcap_ring;
static u32   gbcap_off;
static u32   gbcap_dropped;
static struct proc_dir_entry *gbcap_proc;
static struct proc_dir_entry *gbcap_ctl;

/* Scudo/MTE top-byte-tagged user pointers (0xb4.. heap) fail copy_from_user/access_process_vm's
 * access_ok() (tagged addr > TASK_SIZE → -EFAULT). Every member/df2/FD buffer ptr in Snap is a
 * tagged Scudo heap ptr, so clear the tag byte before ANY user read. (Measured 2026-11-27: without
 * this the payload read returns len=0 while the untagged stack window captures fine.) */
#define GBCAP_UNTAG(a) ((u64)(a) & 0x00ffffffffffffffULL)

/* COMPAT nofault user read: >=5.8 copy_from_user_nofault; else __copy_from_user_inatomic. */
static int gbcap_user_read(void *dst, u64 uaddr, u32 len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	return copy_from_user_nofault(dst, (const void __user *)(uintptr_t)uaddr, len);
#else
	unsigned long n;
	pagefault_disable();
	n = __copy_from_user_inatomic(dst, (const void __user *)(uintptr_t)uaddr, len);
	pagefault_enable();
	return n ? -EFAULT : 0;
#endif
}

static inline u64 gbcap_reg(struct pt_regs *regs, u32 r)
{
	return (r == GBCAP_REGSP) ? regs->sp : regs->regs[r & 31];
}

/* caller MUST hold gbcap_lock (serializes shared scratch against multi-CPU bp fires) */
static bool gbcap_ring_reserve_locked(u32 total)
{
	return gbcap_ring && gbcap_off + total <= GBCAP_RING_BYTES;
}
static void gbcap_ring_raw_locked(const void *b, u32 n)
{
	memcpy(gbcap_ring + gbcap_off, b, n);
	gbcap_off += n;
}
static void gbcap_ring_put_locked(const struct gbcap_rec *hdr, const void *payload)
{
	if (!gbcap_ring_reserve_locked(sizeof(*hdr) + hdr->len)) {
		gbcap_dropped++;
		return;
	}
	gbcap_ring_raw_locked(hdr, sizeof(*hdr));
	if (hdr->len)
		gbcap_ring_raw_locked(payload, hdr->len);
}

static void gbcap_triggered(struct perf_event *bp,
			    struct perf_sample_data *data,
			    struct pt_regs *regs)
{
	struct gbcap_rec hdr;
	static u8 scratch[GBCAP_MAX_LEN];   /* handler is serialized per-trap; put copies under lock */
	const struct gbcap_arm_req *req = NULL;
	u64 src = 0, rawlen = 0, cap = GBCAP_MAX_LEN;
	u32 slot = 0, i, len = 0, flags = 0;

	if (!regs)
		return;
	for (i = 0; i < GBCAP_MAX_BPS; i++) {
		if (gbcap_slots[i].used && bp->attr.bp_addr == gbcap_slots[i].req.bp_addr) {
			slot = i; req = &gbcap_slots[i].req; break;
		}
	}
	if (!req || from_kuid(&init_user_ns, current_uid()) != req->target_uid)
		return;                                /* wide bp fires for everyone — uid-filter */

	/* source pointer */
	switch (req->addr_mode) {
	case GBCAP_ADDR_ABS:
		src = req->capture_addr;
		break;
	case GBCAP_ADDR_DEREF: {
		u64 p = GBCAP_UNTAG(gbcap_reg(regs, req->base_reg) + req->off_ptr), v = 0;
		if (gbcap_user_read(&v, p, 8)) { flags |= 2; src = 0; }
		else src = v;
		break;
	}
	case GBCAP_ADDR_REG:
	default:
		src = gbcap_reg(regs, req->base_reg) + req->off_ptr;
		break;
	}

	/* length */
	if (req->len_mode == GBCAP_LEN_DEREF) {
		u64 p = GBCAP_UNTAG(gbcap_reg(regs, req->len_reg) + req->off_len), v = 0;
		if (gbcap_user_read(&v, p, 8)) { flags |= 2; rawlen = 0; }
		else rawlen = v;
	} else {
		rawlen = req->len_fixed;
	}
	if (req->max_len && req->max_len < cap)
		cap = req->max_len;
	len = (u32)min_t(u64, rawlen, cap);
	if (rawlen > len)
		flags |= 1;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = GBCAP_REC_MAGIC;
	hdr.bp_slot = slot;
	hdr.flags = flags;
	hdr.fire_va = req->bp_addr;
	hdr.src_va = src;
	hdr.raw_len = rawlen;
	hdr.pc = regs->pc;
	hdr.sp = regs->sp;
	hdr.lr = regs->regs[30];
	hdr.pstate = regs->pstate;
	for (i = 0; i < 31; i++)
		hdr.regs[i] = regs->regs[i];
	hdr.ts_ns = ktime_get_ns();

	{
		unsigned long sflags;
		static u8  stkbuf[GBCAP_STACK_MAX];
		static u64 fparr[GBCAP_FP_MAX * 2];
		u32 stk = min_t(u32, req->cap_stack_len, GBCAP_STACK_MAX);
		u32 want_fp = min_t(u32, req->cap_fp_depth, GBCAP_FP_MAX);
		u32 fp_got = 0, total;
		u64 fp = regs->regs[29];

		spin_lock_irqsave(&gbcap_lock, sflags);   /* nofault reads are atomic-safe under spinlock */

		/* main payload */
		if (!(len && src && gbcap_user_read(scratch, GBCAP_UNTAG(src), len) == 0))
			len = 0;
		hdr.len = len;

		/* stack window from sp (call context / attribution) */
		if (stk && gbcap_user_read(stkbuf, regs->sp, stk) != 0)
			stk = 0;
		hdr.stack_len = stk;

		/* frame-pointer chain: x29 -> [fp]=saved_fp, [fp+8]=saved_lr (full call-stack) */
		while (fp_got < want_fp && fp) {
			u64 sfp = 0, slr = 0;
			if (gbcap_user_read(&sfp, fp, 8) || gbcap_user_read(&slr, fp + 8, 8))
				break;
			fparr[fp_got * 2]     = sfp;
			fparr[fp_got * 2 + 1] = slr;
			fp_got++;
			if (sfp <= fp)                 /* FP must grow upward; stop on loop/garbage */
				break;
			fp = sfp;
		}
		hdr.fp_depth = fp_got;

		total = sizeof(hdr) + hdr.len + hdr.stack_len + hdr.fp_depth * 16;
		if (gbcap_ring_reserve_locked(total)) {
			gbcap_ring_raw_locked(&hdr, sizeof(hdr));
			if (hdr.len)       gbcap_ring_raw_locked(scratch, hdr.len);
			if (hdr.stack_len) gbcap_ring_raw_locked(stkbuf, hdr.stack_len);
			if (hdr.fp_depth)  gbcap_ring_raw_locked(fparr, hdr.fp_depth * 16);
		} else {
			gbcap_dropped++;
		}
		spin_unlock_irqrestore(&gbcap_lock, sflags);
	}
}

static int gbcap_arm_one(const struct gbcap_arm_req *req)
{
	struct perf_event_attr attr;
	struct perf_event * __percpu *ev;
	u32 i, slot = GBCAP_MAX_BPS;

	if (!req->bp_addr || (req->max_len && req->max_len > GBCAP_MAX_LEN))
		return -EINVAL;
	for (i = 0; i < GBCAP_MAX_BPS; i++)
		if (!gbcap_slots[i].used) { slot = i; break; }
	if (slot == GBCAP_MAX_BPS)
		return -ENOSPC;

	hw_breakpoint_init(&attr);
	attr.bp_addr = req->bp_addr;
	if (req->trap == GBCAP_TRAP_DATAW) {
		attr.bp_len = HW_BREAKPOINT_LEN_8;
		attr.bp_type = HW_BREAKPOINT_W;
	} else if (req->trap == GBCAP_TRAP_DATAR) {
		attr.bp_len = HW_BREAKPOINT_LEN_8;
		attr.bp_type = HW_BREAKPOINT_R;
	} else {
		attr.bp_len = HW_BREAKPOINT_LEN_4;
		attr.bp_type = HW_BREAKPOINT_X;
	}
	/* CPU-wide: not task-bound → thread-agnostic (catches whatever thread runs the build),
	 * uid-filtered in the handler. EXPORT_SYMBOL_GPL; we are in-tree. */
	ev = register_wide_hw_breakpoint(&attr, gbcap_triggered, NULL);
	if (IS_ERR((void *)ev))
		return PTR_ERR((void *)ev);

	gbcap_slots[slot].ev = ev;
	gbcap_slots[slot].req = *req;
	gbcap_slots[slot].used = true;
	pr_info("gbcap: armed slot=%u uid=%u trap=%u va=0x%llx addr=%u/base%u/off0x%llx len=%u/reg%u/off0x%llx fix=%u cap=%u\n",
		slot, req->target_uid, req->trap, req->bp_addr, req->addr_mode, req->base_reg,
		req->off_ptr, req->len_mode, req->len_reg, req->off_len, req->len_fixed, req->max_len);
	return 0;
}

static void gbcap_disarm_all(void)
{
	u32 i;
	for (i = 0; i < GBCAP_MAX_BPS; i++) {
		if (gbcap_slots[i].used && gbcap_slots[i].ev) {
			unregister_wide_hw_breakpoint(gbcap_slots[i].ev);
			gbcap_slots[i].ev = NULL;
			gbcap_slots[i].used = false;
		}
	}
	pr_info("gbcap: disarmed all\n");
}

static void gbcap_disarm_addr(u64 bp)   /* disarm whichever slot holds this bp_addr */
{
	u32 i;
	for (i = 0; i < GBCAP_MAX_BPS; i++) {
		if (gbcap_slots[i].used && gbcap_slots[i].ev &&
		    gbcap_slots[i].req.bp_addr == bp) {
			unregister_wide_hw_breakpoint(gbcap_slots[i].ev);
			gbcap_slots[i].ev = NULL;
			gbcap_slots[i].used = false;
		}
	}
}

/* ---- AUTO-ARM-ON-LOAD (mmap-watch) ---- */
static struct gbcap_watch_req gbcap_watch;
static bool  gbcap_watch_active;
static u64   gbcap_watch_base_pending;
static bool  gbcap_watch_pending;
static u64   gbcap_watch_armed_base;          /* 0 = nothing armed for the current load */
static struct work_struct gbcap_watch_work;

/* workqueue (process context, sleepable): register_wide_hw_breakpoint can sleep, so the arm MUST
 * happen here, NOT in the atomic kretprobe handler. */
static void gbcap_watch_work_fn(struct work_struct *w)
{
	struct gbcap_arm_req req;
	u64 base;

	if (!READ_ONCE(gbcap_watch_pending))
		return;
	WRITE_ONCE(gbcap_watch_pending, false);
	base = gbcap_watch_base_pending;
	if (!base)
		return;

	/* a fresh load (new ASLR base) → drop the old watch bp and re-arm at the new base */
	if (gbcap_watch_armed_base && gbcap_watch_armed_base != base)
		gbcap_disarm_addr(gbcap_watch_armed_base + gbcap_watch.build_off);

	memset(&req, 0, sizeof(req));
	req.target_uid = gbcap_watch.target_uid;
	req.trap       = GBCAP_TRAP_EXEC;
	req.bp_addr    = base + gbcap_watch.build_off;
	req.addr_mode  = gbcap_watch.addr_mode;
	req.base_reg   = gbcap_watch.base_reg;
	req.off_ptr    = gbcap_watch.off_ptr;
	req.len_mode   = gbcap_watch.len_mode;
	req.len_reg    = gbcap_watch.len_reg;
	req.off_len    = gbcap_watch.off_len;
	req.len_fixed  = gbcap_watch.len_fixed;
	req.max_len    = gbcap_watch.max_len;
	req.cap_stack_len = gbcap_watch.cap_stack_len;
	req.cap_fp_depth  = gbcap_watch.cap_fp_depth;

	if (gbcap_arm_one(&req) == 0) {
		gbcap_watch_armed_base = base;
		pr_info("gbcap: auto-armed init-build bp @ 0x%llx (base 0x%llx)\n", req.bp_addr, base);
	}
}

/* called from the mmap kretprobe (atomic): resolve base, flag pending, kick the workqueue.
 * Keep it minimal + non-sleeping. */
void gb_capture_on_mmap(struct file *file, unsigned long vm_start, unsigned long vm_pgoff)
{
	const unsigned char *name;
	u64 base;

	if (!READ_ONCE(gbcap_watch_active) || !file || !vm_start)
		return;
	if (from_kuid(&init_user_ns, current_uid()) != gbcap_watch.target_uid)
		return;
	name = (file->f_path.dentry) ? file->f_path.dentry->d_name.name : NULL;
	if (!name || !strstr((const char *)name, gbcap_watch.lib))
		return;
	/* An apk mmaps one segment per embedded .so, each with its OWN ASLR base (NOT one shared ELF
	 * bias). vm_start-(pgoff<<SHIFT) is only the correct build base for the segment whose file-offset
	 * range covers build_off; sibling libs (e.g. libclient pgoff 0x1e0000) give a wrong base and the
	 * build bp lands on garbage. Arm ONLY on the segment holding build_off (<4MB past its file off).
	 * (Measured 2026-11-27: without this the watch armed 4 wrong VAs across split_config mmaps.) */
	{
		u64 foff = (u64)vm_pgoff << PAGE_SHIFT;
		if (gbcap_watch.build_off < foff || gbcap_watch.build_off - foff >= 0x400000)
			return;
	}
	/* ELF LOAD bias is constant across segments: base = vm_start - file_offset_of_this_segment */
	base = (u64)vm_start - ((u64)vm_pgoff << PAGE_SHIFT);
	if (!base || base == gbcap_watch_armed_base)
		return;                                 /* already armed for this load */
	gbcap_watch_base_pending = base;
	WRITE_ONCE(gbcap_watch_pending, true);
	schedule_work(&gbcap_watch_work);
}

/* kretprobe on mmap_region: entry stashes (file, pgoff); ret gives the actual mapped address.
 * ⚠ arm64 arg registers for mmap_region(file, addr, len, vm_flags, pgoff, uf): x0=file, x4=pgoff.
 *   VERIFY this signature against raven's mm/mmap.c (it can differ across kernel versions). */
#define GBCAP_MMAP_FILE_REG   0
#define GBCAP_MMAP_PGOFF_REG  4
struct gbcap_mmap_ctx { struct file *file; unsigned long pgoff; };

static int gbcap_mmap_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gbcap_mmap_ctx *c = (struct gbcap_mmap_ctx *)ri->data;
	c->file  = (struct file *)regs->regs[GBCAP_MMAP_FILE_REG];
	c->pgoff = regs->regs[GBCAP_MMAP_PGOFF_REG];
	return 0;
}
static int gbcap_mmap_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct gbcap_mmap_ctx *c = (struct gbcap_mmap_ctx *)ri->data;
	unsigned long va = regs_return_value(regs);

	if (!IS_ERR_VALUE(va) && va)
		gb_capture_on_mmap(c->file, va, c->pgoff);
	return 0;
}
static struct kretprobe gbcap_krp = {
	.handler       = gbcap_mmap_ret,
	.entry_handler = gbcap_mmap_entry,
	.data_size     = sizeof(struct gbcap_mmap_ctx),
	.maxactive     = 64,
};

static int gbcap_watch_start(const struct gbcap_watch_req *wr)
{
	if (wr->max_len && wr->max_len > GBCAP_MAX_LEN)
		return -EINVAL;
	gbcap_watch = *wr;
	gbcap_watch.lib[sizeof(gbcap_watch.lib) - 1] = '\0';   /* ensure NUL-terminated for strstr */
	gbcap_watch_armed_base = 0;
	WRITE_ONCE(gbcap_watch_active, true);
	pr_info("gbcap: WATCH uid=%u lib=%s build_off=0x%llx\n",
		wr->target_uid, gbcap_watch.lib, wr->build_off);
	return 0;
}

static void gbcap_watch_stop(void)
{
	WRITE_ONCE(gbcap_watch_active, false);
	cancel_work_sync(&gbcap_watch_work);
	if (gbcap_watch_armed_base) {
		gbcap_disarm_addr(gbcap_watch_armed_base + gbcap_watch.build_off);
		gbcap_watch_armed_base = 0;
	}
	pr_info("gbcap: WATCH stopped\n");
}

/* on-demand read of another task's user memory (no breakpoint); appends a record to the ring */
static int gbcap_peek_one(const struct gbcap_peek_req *pr)
{
	struct gbcap_rec hdr;
	static u8 scratch[GBCAP_MAX_LEN];     /* serialized by the single reboot-hook caller path */
	struct pid *pidp;
	struct task_struct *task;
	u64 src = pr->addr;
	u32 len, cap = GBCAP_MAX_LEN, flags = 0;
	int got;

	if (pr->max_len && pr->max_len > GBCAP_MAX_LEN)
		return -EINVAL;
	pidp = find_get_pid((pid_t)pr->target_pid);
	task = pidp ? get_pid_task(pidp, PIDTYPE_PID) : NULL;
	if (!task) {
		if (pidp) put_pid(pidp);
		return -ESRCH;
	}

	if (pr->deref) {
		u64 p = 0;
		if (access_process_vm(task, GBCAP_UNTAG(pr->addr), &p, 8, 0) != 8) { flags |= 2; src = 0; }
		else src = p + pr->off;
	} else {
		src = pr->addr + pr->off;
	}

	if (pr->max_len && pr->max_len < cap)
		cap = pr->max_len;
	len = (u32)min_t(u64, pr->len, cap);

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = GBCAP_REC_MAGIC;
	hdr.bp_slot = 0xFFFFFFFFu;             /* sentinel: PEEK, not a breakpoint hit */
	hdr.flags = flags;
	hdr.fire_va = pr->addr;
	hdr.src_va = src;
	hdr.raw_len = pr->len;
	hdr.ts_ns = ktime_get_ns();

	{
		unsigned long sflags;
		got = (len && src) ? access_process_vm(task, GBCAP_UNTAG(src), scratch, len, 0) : 0;
		spin_lock_irqsave(&gbcap_lock, sflags);   /* access_process_vm done OUTSIDE the lock (it sleeps) */
		if (got > 0) { hdr.len = (u32)got; gbcap_ring_put_locked(&hdr, scratch); }
		else { hdr.len = 0; gbcap_ring_put_locked(&hdr, NULL); }
		spin_unlock_irqrestore(&gbcap_lock, sflags);
	}
	put_task_struct(task);
	put_pid(pidp);
	return 0;
}

/* called from the susfs reboot(2) dispatch (uid==0 enforced there). */
int gb_capture_cmd(unsigned int cmd, void __user *arg)
{
	struct gbcap_arm_req req;
	struct gbcap_peek_req pr;
	unsigned long flags;

	switch (cmd) {
	case GBCAP_CMD_ARM:
		if (!arg || copy_from_user(&req, arg, sizeof(req)))
			return -EFAULT;
		return gbcap_arm_one(&req);
	case GBCAP_CMD_PEEK:
		if (!arg || copy_from_user(&pr, arg, sizeof(pr)))
			return -EFAULT;
		return gbcap_peek_one(&pr);
	case GBCAP_CMD_DISARM:
		gbcap_disarm_all();
		return 0;
	case GBCAP_CMD_RESET:
		spin_lock_irqsave(&gbcap_lock, flags);
		gbcap_off = 0; gbcap_dropped = 0;
		spin_unlock_irqrestore(&gbcap_lock, flags);
		pr_info("gbcap: ring reset\n");
		return 0;
	default:
		return -ENOSYS;
	}
}

static ssize_t gbcap_proc_read(struct file *f, char __user *ubuf, size_t count, loff_t *ppos)
{
	u32 avail;
	unsigned long flags;
	ssize_t n;

	spin_lock_irqsave(&gbcap_lock, flags);
	avail = gbcap_off;
	spin_unlock_irqrestore(&gbcap_lock, flags);
	if (*ppos >= avail)
		return 0;
	n = min_t(size_t, count, avail - (u32)*ppos);
	if (copy_to_user(ubuf, gbcap_ring + *ppos, n))
		return -EFAULT;
	*ppos += n;
	return n;
}

// COMPAT proc fops: >=5.6 proc_ops, else file_operations.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops gbcap_proc_ops = { .proc_read = gbcap_proc_read };
#define GBCAP_PROC_OPS (&gbcap_proc_ops)
#else
static const struct file_operations gbcap_proc_ops = { .owner = THIS_MODULE, .read = gbcap_proc_read };
#define GBCAP_PROC_OPS (&gbcap_proc_ops)
#endif

/* /proc/gbcap_ctl — write control channel (root 0200). DISPATCH-AGNOSTIC: needs no reboot(2)/
 * prctl/ksud hook, so it works on any fork regardless of its susfs CMD plumbing (raven's dispatch
 * differs from merlin's). Payload = [u32 cmd][req struct]. */
static ssize_t gbcap_ctl_write(struct file *f, const char __user *ubuf, size_t count, loff_t *ppos)
{
	u8 kbuf[4 + sizeof(struct gbcap_watch_req)];   /* the largest req */
	unsigned long flags;
	u32 cmd;
	int rc;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (count < 4 || count > sizeof(kbuf))
		return -EINVAL;
	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;
	memcpy(&cmd, kbuf, 4);

	switch (cmd) {
	case GBCAP_CMD_ARM: {
		struct gbcap_arm_req req;
		if (count < 4 + sizeof(req))
			return -EINVAL;
		memcpy(&req, kbuf + 4, sizeof(req));
		rc = gbcap_arm_one(&req);
		return rc ? rc : (ssize_t)count;
	}
	case GBCAP_CMD_PEEK: {
		struct gbcap_peek_req pr;
		if (count < 4 + sizeof(pr))
			return -EINVAL;
		memcpy(&pr, kbuf + 4, sizeof(pr));
		rc = gbcap_peek_one(&pr);
		return rc ? rc : (ssize_t)count;
	}
	case GBCAP_CMD_WATCH: {
		struct gbcap_watch_req wr;
		if (count < 4 + sizeof(wr))
			return -EINVAL;
		memcpy(&wr, kbuf + 4, sizeof(wr));
		rc = gbcap_watch_start(&wr);
		return rc ? rc : (ssize_t)count;
	}
	case GBCAP_CMD_UNWATCH:
		gbcap_watch_stop();
		return count;
	case GBCAP_CMD_DISARM:
		gbcap_disarm_all();
		return count;
	case GBCAP_CMD_RESET:
		spin_lock_irqsave(&gbcap_lock, flags);
		gbcap_off = 0; gbcap_dropped = 0;
		spin_unlock_irqrestore(&gbcap_lock, flags);
		return count;
	default:
		return -ENOSYS;
	}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops gbcap_ctl_ops = { .proc_write = gbcap_ctl_write };
#define GBCAP_CTL_OPS (&gbcap_ctl_ops)
#else
static const struct file_operations gbcap_ctl_ops = { .owner = THIS_MODULE, .write = gbcap_ctl_write };
#define GBCAP_CTL_OPS (&gbcap_ctl_ops)
#endif

/* Self-registered via late_initcall below — no susfs-init edit needed (removes the one
 * tree-specific wiring point; raven's init fn name differs from merlin's). Idempotent. */
int gb_capture_init(void)
{
	if (gbcap_ring)
		return 0;                       /* already initialized (idempotent) */
	gbcap_ring = vzalloc(GBCAP_RING_BYTES);
	if (!gbcap_ring)
		return -ENOMEM;
	gbcap_proc = proc_create("gbcap", 0400, NULL, GBCAP_PROC_OPS);
	gbcap_ctl = proc_create("gbcap_ctl", 0200, NULL, GBCAP_CTL_OPS);
	if (!gbcap_proc || !gbcap_ctl) {
		if (gbcap_proc) remove_proc_entry("gbcap", NULL);
		if (gbcap_ctl) remove_proc_entry("gbcap_ctl", NULL);
		vfree(gbcap_ring);
		gbcap_ring = NULL;
		return -ENOMEM;
	}
	INIT_WORK(&gbcap_watch_work, gbcap_watch_work_fn);
	/* mmap-watch for AUTO-ARM (best-effort — if the symbol/signature differs the rest still works
	 * via manual arm/peek). ⚠ VERIFY "mmap_region" + its arg regs on raven's kernel. */
	gbcap_krp.kp.symbol_name = "mmap_region";
	if (register_kretprobe(&gbcap_krp))
		pr_warn("gbcap: kretprobe on mmap_region failed — WATCH auto-arm disabled (manual arm/peek OK)\n");

	pr_info("gbcap: ready (ring=%u, /proc/gbcap read, /proc/gbcap_ctl write, cmds arm/disarm/reset/peek/watch/unwatch)\n",
		GBCAP_RING_BYTES);
	return 0;
}

/* auto-run at boot when built-in (obj-y). No manual call from susfs init required. */
late_initcall(gb_capture_init);
