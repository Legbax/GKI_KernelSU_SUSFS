// gb_capture_arm.c — userspace trigger for the gb_capture kernel instrument.
// Control channel = write [u32 cmd][req] to /proc/gbcap_ctl (root). DISPATCH-AGNOSTIC: no
// reboot(2)/prctl/ksud hook, so it works on raven (WildKernels GKI) whose susfs dispatch differs
// from merlin's — the kernel side owns the proc file, nothing to wire into the fork's CMD plumbing.
// Build (VPS NATIVE aarch64 gcc, static — NOT the x86_64 NDK):
//   aarch64-linux-gnu-gcc -O2 -static -o gb_capture gb_capture_arm.c
// Run as ROOT on the device (the susfs path gates on current_uid()==0).
//
// Subcommands:
//   arm   --uid U --trap exec|dataw|datar --bp 0xVA
//         [--addr reg|abs|deref] [--base-reg N|sp] [--off-ptr 0xX] [--cap-addr 0xVA]
//         [--len fixed|deref] [--len-reg N|sp] [--off-len 0xX] [--len-fixed N] [--max-len N]
//   peek  --pid P --addr 0xVA [--deref] [--off 0xX] --len N [--max-len N]
//   disarm
//   reset
//
// Reads the ring with:  cat /proc/gbcap > dump.bin   (root)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <stdint.h>
#include <fcntl.h>

#define GBCAP_CTL_PATH "/proc/gbcap_ctl"

#define GBCAP_CMD_ARM     0x60141u
#define GBCAP_CMD_DISARM  0x60142u
#define GBCAP_CMD_RESET   0x60143u
#define GBCAP_CMD_PEEK    0x60144u
#define GBCAP_CMD_WATCH   0x60145u
#define GBCAP_CMD_UNWATCH 0x60146u

#define TRAP_EXEC 0u
#define TRAP_DATAW 1u
#define TRAP_DATAR 2u
#define ADDR_REG 0u
#define ADDR_ABS 1u
#define ADDR_DEREF 2u
#define LEN_FIXED 0u
#define LEN_DEREF 1u
#define REGSP 31u

struct gbcap_arm_req {
	uint32_t target_uid, trap;
	uint64_t bp_addr;
	uint32_t addr_mode, base_reg;
	uint64_t off_ptr, capture_addr;
	uint32_t len_mode, len_reg;
	uint64_t off_len;
	uint32_t len_fixed, max_len;
	uint32_t cap_stack_len, cap_fp_depth;
} __attribute__((packed));

struct gbcap_peek_req {
	uint32_t target_pid, deref;
	uint64_t addr, off;
	uint32_t len, max_len;
} __attribute__((packed));

struct gbcap_watch_req {
	uint32_t target_uid, _pad;
	uint64_t build_off;
	char     lib[32];
	uint32_t addr_mode, base_reg;
	uint64_t off_ptr;
	uint32_t len_mode, len_reg;
	uint64_t off_len;
	uint32_t len_fixed, max_len;
	uint32_t cap_stack_len, cap_fp_depth;
} __attribute__((packed));

static int do_ctl(unsigned int cmd, const void *s, size_t slen)
{
	unsigned char buf[4 + 128];
	ssize_t w;
	int fd, e;

	if (slen > sizeof(buf) - 4) {
		fprintf(stderr, "payload too big\n");
		return -1;
	}
	memcpy(buf, &cmd, 4);
	if (s && slen)
		memcpy(buf + 4, s, slen);
	fd = open(GBCAP_CTL_PATH, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s (run as root; is gb_capture built in?)\n",
			GBCAP_CTL_PATH, strerror(errno));
		return -1;
	}
	errno = 0;
	w = write(fd, buf, 4 + slen);
	e = errno;
	close(fd);
	if (w < 0)
		fprintf(stderr, "cmd=0x%x write FAILED: %s\n", cmd, strerror(e));
	else
		fprintf(stderr, "cmd=0x%x ok (wrote %zd bytes)\n", cmd, w);
	return (w < 0) ? -1 : 0;
}

static uint32_t parse_reg(const char *s)
{ return (!strcmp(s, "sp") || !strcmp(s, "SP")) ? REGSP : (uint32_t)strtoul(s, NULL, 0); }

static int cmd_arm(int argc, char **argv)
{
	struct gbcap_arm_req q;
	memset(&q, 0, sizeof(q));
	q.addr_mode = ADDR_REG; q.len_mode = LEN_FIXED; q.max_len = 8192;
	static struct option o[] = {
		{"uid", 1, 0, 1}, {"trap", 1, 0, 2}, {"bp", 1, 0, 3}, {"addr", 1, 0, 4},
		{"base-reg", 1, 0, 5}, {"off-ptr", 1, 0, 6}, {"cap-addr", 1, 0, 7},
		{"len", 1, 0, 8}, {"len-reg", 1, 0, 9}, {"off-len", 1, 0, 10},
		{"len-fixed", 1, 0, 11}, {"max-len", 1, 0, 12},
		{"stack-len", 1, 0, 13}, {"fp-depth", 1, 0, 14}, {0, 0, 0, 0}
	};
	int c;
	while ((c = getopt_long(argc, argv, "", o, NULL)) != -1) {
		switch (c) {
		case 1: q.target_uid = strtoul(optarg, NULL, 0); break;
		case 2: q.trap = !strcmp(optarg, "dataw") ? TRAP_DATAW :
				 !strcmp(optarg, "datar") ? TRAP_DATAR : TRAP_EXEC; break;
		case 3: q.bp_addr = strtoull(optarg, NULL, 0); break;
		case 4: q.addr_mode = !strcmp(optarg, "abs") ? ADDR_ABS :
					!strcmp(optarg, "deref") ? ADDR_DEREF : ADDR_REG; break;
		case 5: q.base_reg = parse_reg(optarg); break;
		case 6: q.off_ptr = strtoull(optarg, NULL, 0); break;
		case 7: q.capture_addr = strtoull(optarg, NULL, 0); break;
		case 8: q.len_mode = !strcmp(optarg, "deref") ? LEN_DEREF : LEN_FIXED; break;
		case 9: q.len_reg = parse_reg(optarg); break;
		case 10: q.off_len = strtoull(optarg, NULL, 0); break;
		case 11: q.len_fixed = strtoul(optarg, NULL, 0); break;
		case 12: q.max_len = strtoul(optarg, NULL, 0); break;
		case 13: q.cap_stack_len = strtoul(optarg, NULL, 0); break;
		case 14: q.cap_fp_depth = strtoul(optarg, NULL, 0); break;
		}
	}
	if (!q.target_uid || !q.bp_addr) {
		fprintf(stderr, "arm: --uid and --bp are required\n");
		return 2;
	}
	printf("arm uid=%u trap=%u bp=0x%llx addr=%u base=%u offp=0x%llx len=%u lreg=%u offl=0x%llx fix=%u max=%u\n",
	       q.target_uid, q.trap, (unsigned long long)q.bp_addr, q.addr_mode, q.base_reg,
	       (unsigned long long)q.off_ptr, q.len_mode, q.len_reg,
	       (unsigned long long)q.off_len, q.len_fixed, q.max_len);
	do_ctl(GBCAP_CMD_ARM, &q, sizeof(q));
	return 0;
}

static int cmd_peek(int argc, char **argv)
{
	struct gbcap_peek_req q;
	memset(&q, 0, sizeof(q));
	q.len = 4096; q.max_len = 8192;
	static struct option o[] = {
		{"pid", 1, 0, 1}, {"addr", 1, 0, 2}, {"deref", 0, 0, 3},
		{"off", 1, 0, 4}, {"len", 1, 0, 5}, {"max-len", 1, 0, 6}, {0, 0, 0, 0}
	};
	int c;
	while ((c = getopt_long(argc, argv, "", o, NULL)) != -1) {
		switch (c) {
		case 1: q.target_pid = strtoul(optarg, NULL, 0); break;
		case 2: q.addr = strtoull(optarg, NULL, 0); break;
		case 3: q.deref = 1; break;
		case 4: q.off = strtoull(optarg, NULL, 0); break;
		case 5: q.len = strtoul(optarg, NULL, 0); break;
		case 6: q.max_len = strtoul(optarg, NULL, 0); break;
		}
	}
	if (!q.target_pid || !q.addr) {
		fprintf(stderr, "peek: --pid and --addr are required\n");
		return 2;
	}
	printf("peek pid=%u addr=0x%llx deref=%u off=0x%llx len=%u max=%u\n",
	       q.target_pid, (unsigned long long)q.addr, q.deref,
	       (unsigned long long)q.off, q.len, q.max_len);
	do_ctl(GBCAP_CMD_PEEK, &q, sizeof(q));
	return 0;
}

/* watch = AUTO-ARM the init-build EXEC bp on libscplugin's mmap (kernel resolves base). */
static int cmd_watch(int argc, char **argv)
{
	struct gbcap_watch_req q;
	memset(&q, 0, sizeof(q));
	q.addr_mode = ADDR_REG; q.len_mode = LEN_FIXED; q.max_len = 8192;
	static struct option o[] = {
		{"uid", 1, 0, 1}, {"lib", 1, 0, 2}, {"build-off", 1, 0, 3}, {"addr", 1, 0, 4},
		{"base-reg", 1, 0, 5}, {"off-ptr", 1, 0, 6}, {"len", 1, 0, 7}, {"len-reg", 1, 0, 8},
		{"off-len", 1, 0, 9}, {"len-fixed", 1, 0, 10}, {"max-len", 1, 0, 11},
		{"stack-len", 1, 0, 12}, {"fp-depth", 1, 0, 13}, {0, 0, 0, 0}
	};
	int c;
	while ((c = getopt_long(argc, argv, "", o, NULL)) != -1) {
		switch (c) {
		case 1: q.target_uid = strtoul(optarg, NULL, 0); break;
		case 2: strncpy(q.lib, optarg, sizeof(q.lib) - 1); break;
		case 3: q.build_off = strtoull(optarg, NULL, 0); break;
		case 4: q.addr_mode = !strcmp(optarg, "abs") ? ADDR_ABS :
					!strcmp(optarg, "deref") ? ADDR_DEREF : ADDR_REG; break;
		case 5: q.base_reg = parse_reg(optarg); break;
		case 6: q.off_ptr = strtoull(optarg, NULL, 0); break;
		case 7: q.len_mode = !strcmp(optarg, "deref") ? LEN_DEREF : LEN_FIXED; break;
		case 8: q.len_reg = parse_reg(optarg); break;
		case 9: q.off_len = strtoull(optarg, NULL, 0); break;
		case 10: q.len_fixed = strtoul(optarg, NULL, 0); break;
		case 11: q.max_len = strtoul(optarg, NULL, 0); break;
		case 12: q.cap_stack_len = strtoul(optarg, NULL, 0); break;
		case 13: q.cap_fp_depth = strtoul(optarg, NULL, 0); break;
		}
	}
	if (!q.target_uid || !q.lib[0] || !q.build_off) {
		fprintf(stderr, "watch: --uid, --lib and --build-off are required\n");
		return 2;
	}
	printf("watch uid=%u lib=%s build_off=0x%llx addr=%u base=%u offp=0x%llx len=%u lreg=%u offl=0x%llx fix=%u max=%u\n",
	       q.target_uid, q.lib, (unsigned long long)q.build_off, q.addr_mode, q.base_reg,
	       (unsigned long long)q.off_ptr, q.len_mode, q.len_reg,
	       (unsigned long long)q.off_len, q.len_fixed, q.max_len);
	do_ctl(GBCAP_CMD_WATCH, &q, sizeof(q));
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s arm|peek|watch|unwatch|disarm|reset [opts]\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "arm"))    return cmd_arm(argc - 1, argv + 1);
	if (!strcmp(argv[1], "peek"))   return cmd_peek(argc - 1, argv + 1);
	if (!strcmp(argv[1], "watch"))  return cmd_watch(argc - 1, argv + 1);
	if (!strcmp(argv[1], "unwatch")) { do_ctl(GBCAP_CMD_UNWATCH, NULL, 0); return 0; }
	if (!strcmp(argv[1], "disarm")) { do_ctl(GBCAP_CMD_DISARM, NULL, 0); return 0; }
	if (!strcmp(argv[1], "reset"))  { do_ctl(GBCAP_CMD_RESET, NULL, 0); return 0; }
	fprintf(stderr, "unknown subcommand '%s'\n", argv[1]);
	return 2;
}
