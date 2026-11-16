// SPDX-License-Identifier: GPL-2.0-only
/*
 * MC SS Sentinel — Vanguard-Grade Ephemeral Ring-0 Kernel Forensic Driver
 *
 * Lifecycle model:
 *   1. Loaded transiently by user-authorized root elevation for SS verification.
 *   2. Exposes root-only (0400) read-only snapshots under /proc/mc_ss_sentinel/:
 *      - status     : driver version, session nonce, taint flags, trace counters
 *      - integrity  : kernel function prologues, CR3 PTE RW/NX audit, VFS/net
 *                     hooks, active tracepoints, visible modules & orphan ELF carve
 *      - tasks_vma  : authoritative init_task tree, ptrace tracers, exe paths,
 *                     VMA RWX/memfd/anon-exec detection + access_process_vm byte scan
 *      - pci_iommu  : Ring-0 PCIe config space (256B + extended caps/DSN/link),
 *                     Bus Master check & hardware IOMMU domain inspection
 *      - events     : bounded lock-safe ring buffer of ephemeral syscall/exec/
 *                     module/uinput activity observed while driver is loaded
 *   3. Unregisters all tracepoints/kprobes/notifiers, synchronizes RCU & SRCU,
 *      removes /proc/mc_ss_sentinel, and unloads cleanly (`rmmod`).
 *
 * Safety invariants:
 *   - Never call sleeping operations (mmap_read_lock, kvcalloc GFP_KERNEL,
 *     file_path, access_process_vm) under rcu_read_lock().
 *   - Never call access_process_vm() while holding mmap_read_lock().
 *   - Always read raw kernel memory through copy_from_kernel_nofault().
 */

#define pr_fmt(fmt) "mc_ss_kmod: " fmt

#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/notifier.h>
#include <linux/panic.h>
#include <linux/pci.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/string.h>
#include <linux/tracepoint.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#if !defined(CONFIG_X86_64)
#error "mc_ss_kmod requires Linux x86_64 architecture (MSR_LSTAR, lookup_address, x86 pt_regs)"
#endif

#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/syscall.h>
#include <asm/unistd_64.h>
#include <uapi/linux/input.h>
#include <uapi/linux/pci_regs.h>
#include <uapi/linux/uinput.h>

/* 32-bit IA32 compat syscall numbers for x86_64 emulation detection */
#define SS_IA32_NR_ptrace		26L
#define SS_IA32_NR_ioctl		54L
#define SS_IA32_NR_ioperm		101L
#define SS_IA32_NR_iopl			110L
#define SS_IA32_NR_init_module		128L
#define SS_IA32_NR_process_vm_readv	347L
#define SS_IA32_NR_process_vm_writev	348L
#define SS_IA32_NR_finit_module		350L
#define SS_IA32_NR_memfd_create		356L
#define SS_IA32_NR_bpf			357L
#define SS_IA32_NR_execveat		358L

#include "mc_ss_kmod.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CmdSuv (MC SS Sentinel)");
MODULE_DESCRIPTION("Ephemeral Ring-0 Forensic, DMA/IOMMU & Integrity Auditor");
MODULE_VERSION(SS_KMOD_VERSION);

static char *session_nonce = "none";
module_param(session_nonce, charp, 0400);
MODULE_PARM_DESC(session_nonce, "Single-use forensic session nonce");

static bool enable_live_probes = true;
module_param(enable_live_probes, bool, 0400);
MODULE_PARM_DESC(enable_live_probes, "Attach ephemeral tracepoints/kprobes during scan window");

static unsigned int max_vma_bytes = SS_DEFAULT_VMA_SCAN;
module_param(max_vma_bytes, uint, 0400);
MODULE_PARM_DESC(max_vma_bytes, "Max bytes scanned per anomalous VMA (capped at 256KB)");

/* /proc directory entries */
static struct proc_dir_entry *g_proc_root;

/* Resolved kernel integrity target table */
struct ss_target_sym {
	const char *name;
	unsigned long addr;
};

static struct ss_target_sym g_integrity_targets[] = {
	/* do_syscall_64 lives in .noinstr.text; verified via MSR_LSTAR instead */
	{ "x64_sys_call", 0 },
	{ "ptrace_attach", 0 },
	{ "security_ptrace_access_check", 0 },
	{ "__x64_sys_ptrace", 0 },
	{ "__x64_sys_process_vm_writev", 0 },
	{ "__x64_sys_process_vm_readv", 0 },
	{ "__x64_sys_memfd_create", 0 },
	{ "__x64_sys_execveat", 0 },
	{ "__x64_sys_init_module", 0 },
	{ "__x64_sys_finit_module", 0 },
	{ "__x64_sys_getdents64", 0 },
	{ "do_sys_openat2", 0 },
	{ "filldir64", 0 },
	{ "iterate_dir", 0 },
	{ "proc_pid_readdir", 0 },
	{ "tcp4_seq_show", 0 },
	{ "tcp6_seq_show", 0 },
	{ "input_event", 0 },
};

/* Ephemeral live ring-buffer + sys_enter/sys_exit correlation */
struct ss_inflight_slot {
	bool active;
	pid_t pid;
	long syscall_nr;
	unsigned int ring_seq;
};

static struct ss_kprobe_event *g_event_ring;
static unsigned int g_ring_slot_seq[SS_EVENT_RING_CAP];
static struct ss_inflight_slot g_inflight[SS_INFLIGHT_CAP];
static DEFINE_RAW_SPINLOCK(g_ring_lock);
static unsigned int g_ring_write_idx;
static atomic_t g_inflight_cnt = ATOMIC_INIT(0);
static atomic64_t g_ring_total_events = ATOMIC64_INIT(0);

/* Active tracepoint / kprobe / notifier registration state */
static struct tracepoint *g_tp_sys_enter;
static struct tracepoint *g_tp_sys_exit;
static struct tracepoint *g_tp_sched_exec;
static bool g_tp_sys_enter_active;
static bool g_tp_sys_exit_active;
static bool g_tp_sched_exec_active;
static bool g_kp_input_active;
static bool g_mod_notifier_active;
static atomic_t g_active_readers = ATOMIC_INIT(0);

/* ---------- Helpers ---------- */

static void ss_sanitize_str(char *dst, const char *src, size_t max_len)
{
	size_t i;

	if (!dst || max_len == 0)
		return;
	if (!src) {
		dst[0] = '\0';
		return;
	}
	for (i = 0; i < max_len - 1 && src[i] != '\0'; i++) {
		unsigned char c = (unsigned char)src[i];

		if (c < 0x20 || c == 0x7f || c == '|' || c == '\n' || c == '\r' || c == '\t')
			dst[i] = '_';
		else
			dst[i] = (char)c;
	}
	dst[i] = '\0';
}

static bool ss_buf_contains(const u8 *hay, size_t hlen, const void *needle, size_t nlen)
{
	size_t i;

	if (!hay || !needle || nlen == 0 || hlen < nlen)
		return false;
	for (i = 0; i <= hlen - nlen; i++) {
		if (hay[i] == ((const u8 *)needle)[0] &&
		    memcmp(hay + i, needle, nlen) == 0)
			return true;
	}
	return false;
}

static bool ss_is_interesting_comm(const char *comm)
{
	static const char *const kw[] = {
		"java", "javaw", "prism", "lunar", "badlion", "feather",
		"modrinth", "minecraft", "wine", "proton", "Xwayland",
		"gamescope", "ydotool", "input-remapper", "python",
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(kw); i++) {
		if (strnstr(comm, kw[i], TASK_COMM_LEN) != NULL)
			return true;
	}
	return false;
}

static bool ss_is_interesting_path(const char *path)
{
	if (!path || !path[0])
		return false;
	if (strncmp(path, "memfd:", 6) == 0 ||
	    strncmp(path, "/memfd:", 7) == 0 ||
	    strncmp(path, "/dev/shm/", 9) == 0 ||
	    strncmp(path, "/tmp/", 5) == 0 ||
	    strncmp(path, "/var/tmp/", 9) == 0 ||
	    strncmp(path, "/home/", 6) == 0 ||
	    strncmp(path, "/var/home/", 10) == 0 ||
	    strncmp(path, "/run/user/", 10) == 0 ||
	    strncmp(path, "/run/media/", 11) == 0)
		return true;
	if (strnstr(path, "(deleted)", 256) != NULL)
		return true;
	return false;
}

static inline void *ss_mod_text_base(const struct module *mod)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return mod->mem[MOD_TEXT].base;
#else
	return mod->core_layout.base;
#endif
}

static inline unsigned int ss_mod_text_size(const struct module *mod)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return mod->mem[MOD_TEXT].size;
#else
	return mod->core_layout.text_size;
#endif
}

static inline void *ss_mod_init_base(const struct module *mod)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return mod->mem[MOD_INIT_TEXT].base;
#else
	return mod->init_layout.base;
#endif
}

static inline unsigned int ss_mod_init_size(const struct module *mod)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return mod->mem[MOD_INIT_TEXT].size;
#else
	return mod->init_layout.text_size;
#endif
}

static bool ss_pid_in_event_ring(pid_t tgid)
{
	unsigned long flags;
	unsigned int i;
	bool found = false;

	if (!g_event_ring || tgid <= 0)
		return false;
	raw_spin_lock_irqsave(&g_ring_lock, flags);
	for (i = 0; i < SS_EVENT_RING_CAP; i++) {
		u32 tp = g_event_ring[i].type;

		if (tp != SS_EVT_NONE && tp != SS_EVT_PROCESS_EXEC &&
		    g_event_ring[i].tgid == tgid) {
			found = true;
			break;
		}
	}
	raw_spin_unlock_irqrestore(&g_ring_lock, flags);
	return found;
}

static void ss_push_event_track(enum ss_event_type type, unsigned long arg0,
				unsigned long arg1, const char *detail,
				bool track_exit, long syscall_nr)
{
	unsigned long flags;
	struct ss_kprobe_event *slot;
	unsigned int idx;
	unsigned int seq;

	if (!g_event_ring)
		return;

	raw_spin_lock_irqsave(&g_ring_lock, flags);
	seq = g_ring_write_idx;
	idx = seq % SS_EVENT_RING_CAP;
	g_ring_write_idx++;
	g_ring_slot_seq[idx] = seq;
	slot = &g_event_ring[idx];
	slot->ts_ns = ktime_get_boottime_ns();
	slot->start_ns = current->start_boottime;
	slot->type = (u32)type;
	slot->pid = current->pid;
	slot->tgid = current->tgid;
	slot->uid = from_kuid_munged(&init_user_ns, current_uid());
	memcpy(slot->comm, current->comm, TASK_COMM_LEN);
	slot->comm[TASK_COMM_LEN - 1] = '\0';
	slot->arg0 = arg0;
	slot->arg1 = arg1;
	slot->ret = 0;
	slot->has_ret = 0;
	ss_sanitize_str(slot->detail, detail ? detail : "", SS_EVENT_DETAIL_LEN);

	if (track_exit && g_tp_sys_exit_active) {
		unsigned int k;
		pid_t cur_pid = current->pid;

		for (k = 0; k < SS_INFLIGHT_CAP; k++) {
			if (g_inflight[k].active && g_inflight[k].pid == cur_pid) {
				g_inflight[k].syscall_nr = syscall_nr;
				g_inflight[k].ring_seq = seq;
				break;
			}
		}
		if (k == SS_INFLIGHT_CAP) {
			unsigned int empty_idx = SS_INFLIGHT_CAP;
			unsigned int oldest_idx = 0;
			u32 max_age = 0;

			for (k = 0; k < SS_INFLIGHT_CAP; k++) {
				if (!g_inflight[k].active) {
					empty_idx = k;
					break;
				} else {
					u32 age = (u32)(seq - g_inflight[k].ring_seq);

					if (age >= max_age) {
						max_age = age;
						oldest_idx = k;
					}
				}
			}
			if (empty_idx < SS_INFLIGHT_CAP) {
				g_inflight[empty_idx].active = true;
				g_inflight[empty_idx].pid = cur_pid;
				g_inflight[empty_idx].syscall_nr = syscall_nr;
				g_inflight[empty_idx].ring_seq = seq;
				atomic_inc(&g_inflight_cnt);
			} else {
				g_inflight[oldest_idx].pid = cur_pid;
				g_inflight[oldest_idx].syscall_nr = syscall_nr;
				g_inflight[oldest_idx].ring_seq = seq;
			}
		}
	}
	atomic64_inc(&g_ring_total_events);
	raw_spin_unlock_irqrestore(&g_ring_lock, flags);
}

static void ss_push_event(enum ss_event_type type, unsigned long arg0,
			  unsigned long arg1, const char *detail)
{
	ss_push_event_track(type, arg0, arg1, detail, false, -1L);
}

/* Safe one-shot symbol lookup using standard kprobes (registered + unregistered in init) */
static unsigned long ss_resolve_symbol_via_kprobe(const char *sym_name)
{
	struct kprobe kp;
	unsigned long addr = 0;
	int ret;

	memset(&kp, 0, sizeof(kp));
	kp.symbol_name = sym_name;
	ret = register_kprobe(&kp);
	if (ret == 0) {
		addr = (unsigned long)kp.addr;
		unregister_kprobe(&kp);
	}
	return addr;
}

/* ---------- Ephemeral Live Probes ---------- */

static void ss_tp_sys_enter_cb(void *data, struct pt_regs *regs, long id)
{
	unsigned long args[6] = { 0 };
	bool compat = in_compat_syscall();

	(void)data;

	if (regs)
		syscall_get_arguments(current, regs, args);

	if (compat) {
		switch (id) {
		case SS_IA32_NR_ptrace:
			ss_push_event_track(SS_EVT_SYSCALL_PTRACE, args[0], args[1], "sys32_ptrace", true, id);
			break;
		case SS_IA32_NR_process_vm_writev:
			ss_push_event_track(SS_EVT_SYSCALL_VM_WRITEV, args[0], args[2], "sys32_process_vm_writev", true, id);
			break;
		case SS_IA32_NR_process_vm_readv:
			ss_push_event_track(SS_EVT_SYSCALL_VM_READV, args[0], args[2], "sys32_process_vm_readv", true, id);
			break;
		case SS_IA32_NR_memfd_create:
			ss_push_event_track(SS_EVT_SYSCALL_MEMFD, 0, args[1], "sys32_memfd_create", true, id);
			break;
		case SS_IA32_NR_execveat:
			ss_push_event_track(SS_EVT_SYSCALL_EXECVEAT, args[0], args[4], "sys32_execveat", true, id);
			break;
		case SS_IA32_NR_init_module:
		case SS_IA32_NR_finit_module:
			ss_push_event_track(SS_EVT_SYSCALL_MOD_LOAD, (unsigned long)id, args[0], "sys32_module_load", true, id);
			break;
		case SS_IA32_NR_bpf:
			ss_push_event_track(SS_EVT_SYSCALL_BPF, args[0], 0, "sys32_bpf", true, id);
			break;
		case SS_IA32_NR_iopl:
		case SS_IA32_NR_ioperm:
			ss_push_event_track(SS_EVT_SYSCALL_IOPL, (unsigned long)id, args[0], "sys32_rawio_port", true, id);
			break;
		case SS_IA32_NR_ioctl:
			if ((unsigned int)args[1] == (unsigned int)UI_DEV_CREATE)
				ss_push_event_track(SS_EVT_SYSCALL_UINPUT_CREATE, args[0], args[1],
						    "sys32_ioctl_ui_dev_create", true, id);
			break;
		default:
			break;
		}
		return;
	}

	/* Fast path: immediately exit for 99.99% of routine 64-bit syscalls */
	switch (id) {
	case __NR_ptrace:
		ss_push_event_track(SS_EVT_SYSCALL_PTRACE, args[0], args[1], "sys_ptrace", true, id);
		break;
	case __NR_process_vm_writev:
		ss_push_event_track(SS_EVT_SYSCALL_VM_WRITEV, args[0], args[2], "sys_process_vm_writev", true, id);
		break;
	case __NR_process_vm_readv:
		ss_push_event_track(SS_EVT_SYSCALL_VM_READV, args[0], args[2], "sys_process_vm_readv", true, id);
		break;
	case __NR_memfd_create:
		ss_push_event_track(SS_EVT_SYSCALL_MEMFD, 0, args[1], "sys_memfd_create", true, id);
		break;
	case __NR_execveat:
		ss_push_event_track(SS_EVT_SYSCALL_EXECVEAT, args[0], args[4], "sys_execveat", true, id);
		break;
	case __NR_init_module:
	case __NR_finit_module:
		ss_push_event_track(SS_EVT_SYSCALL_MOD_LOAD, (unsigned long)id, args[0], "sys_module_load", true, id);
		break;
	case __NR_bpf:
		ss_push_event_track(SS_EVT_SYSCALL_BPF, args[0], 0, "sys_bpf", true, id);
		break;
	case __NR_iopl:
	case __NR_ioperm:
		ss_push_event_track(SS_EVT_SYSCALL_IOPL, (unsigned long)id, args[0], "sys_rawio_port", true, id);
		break;
	case __NR_ioctl:
		if ((unsigned int)args[1] == (unsigned int)UI_DEV_CREATE)
			ss_push_event_track(SS_EVT_SYSCALL_UINPUT_CREATE, args[0], args[1],
					    "sys_ioctl_ui_dev_create", true, id);
		break;
	default:
		break;
	}
}

static void ss_tp_sys_exit_cb(void *data, struct pt_regs *regs, long ret)
{
	unsigned long flags;
	unsigned int k;
	pid_t cur_pid;
	long nr;

	(void)data;

	if (atomic_read(&g_inflight_cnt) <= 0 || !g_event_ring || !regs)
		return;

	cur_pid = current->pid;
	nr = syscall_get_nr(current, regs);

	raw_spin_lock_irqsave(&g_ring_lock, flags);
	for (k = 0; k < SS_INFLIGHT_CAP; k++) {
		if (g_inflight[k].active && g_inflight[k].pid == cur_pid &&
		    g_inflight[k].syscall_nr == nr) {
			unsigned int seq = g_inflight[k].ring_seq;
			unsigned int ridx = seq % SS_EVENT_RING_CAP;

			if (g_ring_slot_seq[ridx] == seq && g_event_ring[ridx].pid == cur_pid) {
				g_event_ring[ridx].ret = ret;
				g_event_ring[ridx].has_ret = 1;
			}
			g_inflight[k].active = false;
			atomic_dec(&g_inflight_cnt);
			break;
		}
	}
	raw_spin_unlock_irqrestore(&g_ring_lock, flags);
}

static void ss_tp_sched_exec_cb(void *data, struct task_struct *p,
				pid_t old_pid, struct linux_binprm *bprm)
{
	const char *fname_ptr = NULL;
	char fname_local[SS_EVENT_DETAIL_LEN];
	bool interesting_path = false;

	(void)data;

	memset(fname_local, 0, sizeof(fname_local));
	if (bprm && copy_from_kernel_nofault(&fname_ptr, &bprm->filename, sizeof(fname_ptr)) == 0 &&
	    fname_ptr != NULL) {
		if (copy_from_kernel_nofault(fname_local, fname_ptr, sizeof(fname_local) - 1) == 0) {
			if (strncmp(fname_local, "/tmp/", 5) == 0 ||
			    strncmp(fname_local, "/dev/shm/", 9) == 0 ||
			    strncmp(fname_local, "/var/tmp/", 9) == 0 ||
			    strncmp(fname_local, "/memfd:", 7) == 0 ||
			    strncmp(fname_local, "memfd:", 6) == 0)
				interesting_path = true;
		} else {
			fname_local[0] = '\0';
		}
	}

	if (interesting_path ||
	    strnstr(current->comm, "memfd", TASK_COMM_LEN) ||
	    strnstr(current->comm, "sh", TASK_COMM_LEN) ||
	    strnstr(current->comm, "java", TASK_COMM_LEN) ||
	    strnstr(current->comm, "python", TASK_COMM_LEN)) {
		ss_push_event(SS_EVT_PROCESS_EXEC, (unsigned long)old_pid,
			      (unsigned long)(p ? p->tgid : 0),
			      fname_local[0] ? fname_local : current->comm);
	}
}

static int ss_kp_input_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct input_dev *idev = (struct input_dev *)regs->di;
	char buf[SS_EVENT_DETAIL_LEN];
	const char *name_ptr = NULL;
	char name_local[48];
	struct input_id id_local;

	(void)p;

	if (!idev)
		return 0;
	memset(&id_local, 0, sizeof(id_local));
	if (copy_from_kernel_nofault(&id_local, &idev->id, sizeof(id_local)) != 0)
		return 0;
	if (id_local.bustype == BUS_VIRTUAL || id_local.bustype == BUS_USB) {
		memset(name_local, 0, sizeof(name_local));
		if (copy_from_kernel_nofault(&name_ptr, &idev->name, sizeof(name_ptr)) == 0 &&
		    name_ptr != NULL) {
			if (copy_from_kernel_nofault(name_local, name_ptr, sizeof(name_local) - 1) != 0)
				name_local[0] = '\0';
		}
		scnprintf(buf, sizeof(buf), "bus=0x%x vid=0x%04x pid=0x%04x name=%s",
			  id_local.bustype, id_local.vendor, id_local.product, name_local);
		ss_push_event(SS_EVT_INPUT_REGISTER, id_local.bustype,
			      ((unsigned long)id_local.vendor << 16) | id_local.product, buf);
	}
	return 0;
}

static struct kprobe g_kp_input = {
	.symbol_name = "input_register_device",
	.pre_handler = ss_kp_input_pre,
};

static int ss_mod_notifier_cb(struct notifier_block *nb, unsigned long action, void *data)
{
	struct module *mod = data;
	char buf[SS_EVENT_DETAIL_LEN];
	const char *st = "OTHER";

	(void)nb;

	if (!mod || mod == THIS_MODULE)
		return NOTIFY_DONE;

	if (action == MODULE_STATE_COMING)
		st = "COMING";
	else if (action == MODULE_STATE_LIVE)
		st = "LIVE";
	else if (action == MODULE_STATE_GOING)
		st = "GOING";

	scnprintf(buf, sizeof(buf), "state=%s name=%s taints=0x%lx", st, mod->name, mod->taints);
	ss_push_event(SS_EVT_MODULE_NOTIFY, action, mod->taints, buf);
	return NOTIFY_DONE;
}

static struct notifier_block g_mod_nb = {
	.notifier_call = ss_mod_notifier_cb,
	.priority = 0,
};

/* ---------- Tracepoint Discovery & Registry Audit ---------- */

struct ss_tp_audit_ctx {
	struct ss_tp_cb_snap *items;
	unsigned int count;
	unsigned int max_items;
	struct tracepoint *found_sys_enter;
	struct tracepoint *found_sys_exit;
	struct tracepoint *found_sched_exec;
};

static void ss_visit_kernel_tp(struct tracepoint *tp, void *priv)
{
	struct ss_tp_audit_ctx *actx = priv;
	struct tracepoint_func *funcs;
	int i;

	if (!tp || !tp->name)
		return;
	if (!actx->found_sys_enter && strcmp(tp->name, "sys_enter") == 0)
		actx->found_sys_enter = tp;
	if (!actx->found_sys_exit && strcmp(tp->name, "sys_exit") == 0)
		actx->found_sys_exit = tp;
	if (!actx->found_sched_exec && strcmp(tp->name, "sched_process_exec") == 0)
		actx->found_sched_exec = tp;

	if (!actx->items || actx->count >= actx->max_items)
		return;

	rcu_read_lock();
	funcs = rcu_dereference_raw(tp->funcs);
	if (funcs) {
		for (i = 0; i < 16 && funcs[i].func != NULL; i++) {
			if (actx->count >= actx->max_items)
				break;
			actx->items[actx->count].tp_name = tp->name;
			actx->items[actx->count].idx = i;
			actx->items[actx->count].prio = funcs[i].prio;
			actx->items[actx->count].func_addr = (unsigned long)funcs[i].func;
			actx->count++;
		}
	}
	rcu_read_unlock();
}

/* ---------- Module & Page-Table Helpers ---------- */

static const char *ss_classify_prologue(const u8 *code, size_t len, unsigned long fn_addr,
					unsigned long *out_target)
{
	size_t off = 0;
	s32 disp = 0;
	u64 imm64 = 0;

	*out_target = 0;
	if (len < 6)
		return "SHORT_READ";

	/* Skip optional ENDBR64 (f3 0f 1e fa) */
	if (code[0] == 0xf3 && code[1] == 0x0f && code[2] == 0x1e && code[3] == 0xfa)
		off = 4;

	if (code[off] == 0xcc || code[0] == 0xcc)
		return "INT3_BREAKPOINT";
	if (code[off] == 0xe9 && off + 5 <= len) {
		memcpy(&disp, code + off + 1, 4);
		*out_target = fn_addr + off + 5 + (long)disp;
		return "JMP_REL32_HOOK";
	}
	if (code[off] == 0xeb && off + 2 <= len) {
		*out_target = fn_addr + off + 2 + (long)(s8)code[off + 1];
		return "JMP_SHORT_HOOK";
	}
	if (code[off] == 0xff && off + 6 <= len && code[off + 1] == 0x25) {
		memcpy(&disp, code + off + 2, 4);
		*out_target = fn_addr + off + 6 + (long)disp;
		return "JMP_IND_RIP_HOOK";
	}
	/*
	 * Verify actual mov reg, imm64 + indirect jmp/call/push-ret on the SAME register
	 * AND canonical kernel-half address before classifying as a trampoline.
	 */
	if ((code[off] == 0x48 || code[off] == 0x49) &&
	    (code[off + 1] >= 0xb8 && code[off + 1] <= 0xbf) &&
	    off + 10 <= len) {
		u8 rex_b = code[off] & 0x01;
		u8 reg = (u8)(code[off + 1] - 0xb8);
		size_t tail = off + 10;
		bool is_branch = false;

		memcpy(&imm64, code + off + 2, 8);
		if (!rex_b && tail + 2 <= len) {
			if ((code[tail] == 0xff && (code[tail + 1] == (u8)(0xe0 + reg) ||
						    code[tail + 1] == (u8)(0xd0 + reg))) ||
			    (code[tail] == (u8)(0x50 + reg) && code[tail + 1] == 0xc3))
				is_branch = true;
		} else if (rex_b && tail + 3 <= len && code[tail] == 0x41) {
			if ((code[tail + 1] == 0xff && (code[tail + 2] == (u8)(0xe0 + reg) ||
							code[tail + 2] == (u8)(0xd0 + reg))) ||
			    (code[tail + 1] == (u8)(0x50 + reg) && code[tail + 2] == 0xc3))
				is_branch = true;
		}
		if (is_branch && imm64 >= 0xffff800000000000ULL) {
			*out_target = (unsigned long)imm64;
			return "MOV_IMM64_TRAMPOLINE";
		}
		return "MOV_IMM64_DATA";
	}
	if (code[off] == 0xe8 && off + 5 <= len) {
		memcpy(&disp, code + off + 1, 4);
		*out_target = fn_addr + off + 5 + (long)disp;
		return "CALL_REL32";
	}
	if ((off + 3 <= len && code[off] == 0x0f && code[off + 1] == 0x1f &&
	     (code[off + 2] == 0x44 || code[off + 2] == 0x40 || code[off + 2] == 0x80 ||
	      code[off + 2] == 0x84 || code[off + 2] == 0x00)) ||
	    (off + 4 <= len && code[off] == 0x66 && code[off + 1] == 0x0f && code[off + 2] == 0x1f))
		return "CANONICAL_FENTRY_NOP";
	return "STANDARD";
}

static bool ss_check_range_rw(unsigned long start, unsigned long size)
{
	unsigned long addr;
	unsigned long end = start + size;

	for (addr = start; addr < end && addr >= start;) {
		unsigned int level = PG_LEVEL_NONE;
		pte_t *ptep = lookup_address(addr, &level);
		unsigned long step = PAGE_SIZE;

		if (level == PG_LEVEL_2M)
			step = PMD_SIZE;
		else if (level == PG_LEVEL_1G)
			step = PUD_SIZE;

		if (ptep && pte_present(*ptep) && pte_write(*ptep))
			return true;

		if (ULONG_MAX - addr < step)
			break;
		addr += step;
	}
	return false;
}

static inline bool ss_is_vmalloc_or_module_addr(const void *x)
{
	unsigned long addr = (unsigned long)x;
#if defined(MODULES_VADDR) && defined(MODULES_END)
	if (addr >= MODULES_VADDR && addr < MODULES_END)
		return true;
#endif
	return is_vmalloc_addr(x);
}

static unsigned int ss_snapshot_modules(struct ss_mod_snap *out,
					  unsigned int max_cnt,
					  bool *truncated_out)
{
	struct module *mod;
	unsigned int cnt = 0;
	unsigned int steps = 0;
	unsigned int i;
	struct list_head *head = &THIS_MODULE->list;
	struct list_head *cur;

	if (truncated_out)
		*truncated_out = false;
	if (!out || max_cnt == 0)
		return 0;

	/* Record self first */
	ss_sanitize_str(out[cnt].name, THIS_MODULE->name, MODULE_NAME_LEN);
	out[cnt].state = THIS_MODULE->state;
	out[cnt].taints = THIS_MODULE->taints;
#ifdef CONFIG_MODULE_SIG
	out[cnt].sig_ok = THIS_MODULE->sig_ok;
#else
	out[cnt].sig_ok = false;
#endif
	out[cnt].text_start = (unsigned long)ss_mod_text_base(THIS_MODULE);
	out[cnt].text_end = out[cnt].text_start + ss_mod_text_size(THIS_MODULE);
	out[cnt].init_start = (unsigned long)ss_mod_init_base(THIS_MODULE);
	out[cnt].init_end = out[cnt].init_start + ss_mod_init_size(THIS_MODULE);
	out[cnt].text_rw_anomaly = false;
	cnt++;

	rcu_read_lock();
	cur = rcu_dereference(head->next);
	while (cur && cur != head && cnt < max_cnt && steps < max_cnt * 4U) {
		unsigned long next_ptr = 0;
		char name_tmp[MODULE_NAME_LEN];
		enum module_state st = MODULE_STATE_UNFORMED;
		unsigned long taints_val = 0;
		void *text_base = NULL, *init_base = NULL;
		unsigned int text_sz = 0, init_sz = 0;
		bool sig_val = false;

		steps++;
		mod = list_entry(cur, struct module, list);
		/* Real struct module nodes live in vmalloc/module space, unlike the &modules core sentinel */
		if (ss_is_vmalloc_or_module_addr((const void *)cur)) {
			/* Safely validate sibling nodes via nofault reads */
			if (copy_from_kernel_nofault(&st, &mod->state, sizeof(st)) != 0 ||
			    copy_from_kernel_nofault(name_tmp, mod->name, MODULE_NAME_LEN) != 0)
				break;
			name_tmp[MODULE_NAME_LEN - 1] = '\0';

			/* Validate printable module name & state */
			if (name_tmp[0] != '\0' &&
			    ((name_tmp[0] >= 'a' && name_tmp[0] <= 'z') ||
			     (name_tmp[0] >= 'A' && name_tmp[0] <= 'Z') ||
			     (name_tmp[0] >= '0' && name_tmp[0] <= '9') ||
			     name_tmp[0] == '_') &&
			    st >= MODULE_STATE_LIVE && st <= MODULE_STATE_GOING) {
				copy_from_kernel_nofault(&taints_val, &mod->taints, sizeof(taints_val));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
				copy_from_kernel_nofault(&text_base, &mod->mem[MOD_TEXT].base, sizeof(text_base));
				copy_from_kernel_nofault(&text_sz, &mod->mem[MOD_TEXT].size, sizeof(text_sz));
				copy_from_kernel_nofault(&init_base, &mod->mem[MOD_INIT_TEXT].base, sizeof(init_base));
				copy_from_kernel_nofault(&init_sz, &mod->mem[MOD_INIT_TEXT].size, sizeof(init_sz));
#else
				copy_from_kernel_nofault(&text_base, &mod->core_layout.base, sizeof(text_base));
				copy_from_kernel_nofault(&text_sz, &mod->core_layout.text_size, sizeof(text_sz));
				copy_from_kernel_nofault(&init_base, &mod->init_layout.base, sizeof(init_base));
				copy_from_kernel_nofault(&init_sz, &mod->init_layout.text_size, sizeof(init_sz));
#endif
#ifdef CONFIG_MODULE_SIG
				copy_from_kernel_nofault(&sig_val, &mod->sig_ok, sizeof(sig_val));
#endif
				if (text_sz > 64U * 1024U * 1024U)
					text_sz = 0;
				if (init_sz > 16U * 1024U * 1024U)
					init_sz = 0;

				ss_sanitize_str(out[cnt].name, name_tmp, MODULE_NAME_LEN);
				out[cnt].state = st;
				out[cnt].taints = taints_val;
				out[cnt].sig_ok = sig_val;
				out[cnt].text_start = text_base ? (unsigned long)text_base : 0;
				out[cnt].text_end = (text_base && text_sz) ? ((unsigned long)text_base + text_sz) : 0;
				out[cnt].init_start = init_base ? (unsigned long)init_base : 0;
				out[cnt].init_end = (init_base && init_sz) ? ((unsigned long)init_base + init_sz) : 0;
				out[cnt].text_rw_anomaly = false;
				cnt++;
			}
		}

		if (copy_from_kernel_nofault(&next_ptr, &cur->next, sizeof(next_ptr)) != 0 ||
		    next_ptr == 0)
			break;
		cur = (struct list_head *)next_ptr;
	}
	if (truncated_out && cur && cur != head && (cnt >= max_cnt || steps >= max_cnt * 4U))
		*truncated_out = true;
	rcu_read_unlock();

	for (i = 0; i < cnt; i++) {
		if (out[i].text_start && out[i].text_end > out[i].text_start)
			out[i].text_rw_anomaly = ss_check_range_rw(
				out[i].text_start,
				min_t(unsigned long, out[i].text_end - out[i].text_start, 4UL * 1024 * 1024));
	}
	return cnt;
}

static const struct ss_mod_snap *ss_find_mod_covering(const struct ss_mod_snap *mods,
						       unsigned int mod_cnt,
						       unsigned long addr)
{
	unsigned int i;

	for (i = 0; i < mod_cnt; i++) {
		if (addr >= mods[i].text_start && addr < mods[i].text_end)
			return &mods[i];
		if (addr >= mods[i].init_start && addr < mods[i].init_end)
			return &mods[i];
	}
	return NULL;
}

/* ---------- /proc/mc_ss_sentinel/status ---------- */

struct ss_taint_entry {
	char ch;
	const char *desc;
};

static const struct ss_taint_entry ss_taint_tbl[] = {
	[0]  = { 'P', "proprietary module" },
	[1]  = { 'F', "module force loaded" },
	[2]  = { 'S', "SMP out-of-spec CPU" },
	[3]  = { 'R', "module force unloaded" },
	[4]  = { 'M', "machine check exception" },
	[5]  = { 'B', "bad page reference" },
	[6]  = { 'U', "user tainted kernel" },
	[7]  = { 'D', "kernel died recently" },
	[8]  = { 'A', "ACPI table overridden" },
	[9]  = { 'W', "kernel warning occurred" },
	[10] = { 'C', "staging driver loaded" },
	[11] = { 'I', "platform firmware bug" },
	[12] = { 'O', "out-of-tree module loaded" },
	[13] = { 'E', "unsigned module loaded" },
	[14] = { 'L', "soft lockup occurred" },
	[15] = { 'K', "kernel live patched" },
	[16] = { 'X', "auxiliary taint" },
	[17] = { 'T', "randstruct plugin" },
	[18] = { 'N', "in-kernel test run" },
};

static int ss_status_show(struct seq_file *m, void *v)
{
	unsigned int bit;
	unsigned int max_bits;
	size_t pos = 0;
	bool any_taint = false;
	char nonce_safe[64];
	char taint_buf[48];

	ss_sanitize_str(nonce_safe, session_nonce, sizeof(nonce_safe));
	max_bits = min_t(unsigned int, TAINT_FLAGS_COUNT,
			 (unsigned int)ARRAY_SIZE(ss_taint_tbl));
	for (bit = 0; bit < max_bits; bit++) {
		if (test_taint(bit)) {
			if (!any_taint) {
				pos = scnprintf(taint_buf, sizeof(taint_buf), "Tainted: ");
				any_taint = true;
			}
			if (pos + 1 < sizeof(taint_buf))
				taint_buf[pos++] = ss_taint_tbl[bit].ch;
		}
	}
	if (!any_taint)
		strscpy(taint_buf, "Not tainted", sizeof(taint_buf));
	else
		taint_buf[pos] = '\0';

	seq_printf(m,
		   "STATUS|version=%s|kernel=%s|nonce=%s|taint_str=%s|"
		   "live_probes=%d|tp_sys_enter=%d|tp_sys_exit=%d|tp_exec=%d|kp_input=%d|"
		   "mod_notifier=%d|events_total=%lld|active_readers=%d|"
		   "self_text_start=0x%px|self_text_end=0x%px\n",
		   SS_KMOD_VERSION, utsname()->release, nonce_safe, taint_buf,
		   enable_live_probes ? 1 : 0,
		   g_tp_sys_enter_active ? 1 : 0,
		   g_tp_sys_exit_active ? 1 : 0,
		   g_tp_sched_exec_active ? 1 : 0,
		   g_kp_input_active ? 1 : 0,
		   g_mod_notifier_active ? 1 : 0,
		   (long long)atomic64_read(&g_ring_total_events),
		   atomic_read(&g_active_readers),
		   ss_mod_text_base(THIS_MODULE),
		   (u8 *)ss_mod_text_base(THIS_MODULE) + ss_mod_text_size(THIS_MODULE));

	for (bit = 0; bit < max_bits; bit++) {
		if (test_taint(bit)) {
			seq_printf(m, "TAINT|bit=%u|char=%c|desc=%s\n",
				   bit, ss_taint_tbl[bit].ch,
				   ss_taint_tbl[bit].desc ? ss_taint_tbl[bit].desc : "taint");
		}
	}
	return 0;
}

/* ---------- /proc/mc_ss_sentinel/integrity ---------- */

static void ss_audit_vfs_mount(struct seq_file *m, const char *path)
{
	struct file *f;
	char *sym_buf;
	char *sym_iter;
	char *sym_open;
	const void *iter_fn = NULL;
	const void *open_fn = NULL;

	f = filp_open(path, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(f)) {
		seq_printf(m, "VFSHOOK|mount=%s|err=%ld\n", path, PTR_ERR(f));
		return;
	}
	sym_buf = kmalloc(2 * KSYM_SYMBOL_LEN, GFP_KERNEL);
	if (!sym_buf) {
		filp_close(f, NULL);
		seq_printf(m, "VFSHOOK|mount=%s|err=-ENOMEM\n", path);
		return;
	}
	sym_iter = sym_buf;
	sym_open = sym_buf + KSYM_SYMBOL_LEN;

	if (f->f_op) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
		iter_fn = f->f_op->iterate_shared;
#else
		iter_fn = f->f_op->iterate_shared ? f->f_op->iterate_shared : f->f_op->iterate;
#endif
		open_fn = f->f_op->open;
	}
	if (iter_fn)
		sprint_symbol(sym_iter, (unsigned long)iter_fn);
	else
		scnprintf(sym_iter, KSYM_SYMBOL_LEN, "NULL");

	if (open_fn)
		sprint_symbol(sym_open, (unsigned long)open_fn);
	else
		scnprintf(sym_open, KSYM_SYMBOL_LEN, "NULL");

	seq_printf(m, "VFSHOOK|mount=%s|iterate_shared=0x%lx|iter_sym=%s|open=0x%lx|open_sym=%s\n",
		   path, (unsigned long)iter_fn, sym_iter, (unsigned long)open_fn, sym_open);
	kfree(sym_buf);
	filp_close(f, NULL);
}

static void ss_emit_modxscan_region(struct seq_file *m,
				    unsigned long reg_start,
				    unsigned long reg_end,
				    bool reg_rw,
				    const struct ss_mod_snap *owner,
				    u8 *sample)
{
	char sym[KSYM_SYMBOL_LEN];
	bool elf_hit = false;
	bool vermagic_hit = false;
	u8 head[16];

	sprint_symbol(sym, reg_start);
	memset(head, 0, sizeof(head));
	copy_from_kernel_nofault(head, (void *)reg_start, sizeof(head));

	if (!owner) {
		unsigned long p;

		for (p = reg_start; p < reg_end && p - reg_start < (4UL * 1024 * 1024); p += PAGE_SIZE) {
			if (((p - reg_start) & ((64UL << PAGE_SHIFT) - 1)) == 0)
				cond_resched();
			if (copy_from_kernel_nofault(sample, (void *)p, PAGE_SIZE) == 0) {
				if (ss_buf_contains(sample, PAGE_SIZE, "\x7f" "ELF", 4))
					elf_hit = true;
				if (ss_buf_contains(sample, PAGE_SIZE, "vermagic=", 9))
					vermagic_hit = true;
				if (elf_hit && vermagic_hit)
					break;
			}
		}
	}
	seq_printf(m,
		   "MODXSCAN|start=0x%lx|end=0x%lx|pages=%lu|rw=%d|covered=%d|mod=%s|sym=%s|elf_carve=%d|vermagic_carve=%d|head=%16phN\n",
		   reg_start, reg_end, (reg_end - reg_start) >> PAGE_SHIFT,
		   reg_rw ? 1 : 0, owner ? 1 : 0,
		   owner ? owner->name : "ORPHAN", sym,
		   elf_hit ? 1 : 0, vermagic_hit ? 1 : 0, head);
}

static void ss_scan_modules_vaddr_exec(struct seq_file *m,
				       const struct ss_mod_snap *mods,
				       unsigned int mod_cnt)
{
	unsigned long addr;
	bool in_region = false;
	unsigned long reg_start = 0, reg_end = 0;
	bool reg_rw = false;
	const struct ss_mod_snap *reg_owner = NULL;
	u8 *sample;
	unsigned int emitted = 0;
	unsigned int iter = 0;

	sample = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sample)
		return;

	/* Step across MODULES_VADDR..MODULES_END at page resolution */
	for (addr = MODULES_VADDR; addr < MODULES_END && emitted < 256; ) {
		unsigned int level = PG_LEVEL_NONE;
		pte_t *ptep;
		unsigned long step = PAGE_SIZE;
		bool present_exec = false;
		bool rw = false;
		const struct ss_mod_snap *cur_owner = NULL;

		if (seq_has_overflowed(m))
			break;
		ptep = lookup_address(addr, &level);
		if ((++iter & 1023U) == 0)
			cond_resched();

		if (level == PG_LEVEL_2M)
			step = PMD_SIZE;
		else if (level == PG_LEVEL_1G)
			step = PUD_SIZE;

		if (ptep && pte_present(*ptep)) {
			pteval_t pv = pte_flags(*ptep);

			if (!(pv & _PAGE_NX)) {
				present_exec = true;
				rw = (pv & _PAGE_RW) != 0;
				/* Walk present executable hugepages at 4KB granularity so modules & orphans inside execmem PMDs split accurately */
				step = PAGE_SIZE;
			}
		}

		if (present_exec)
			cur_owner = ss_find_mod_covering(mods, mod_cnt, addr);

		if (in_region && (!present_exec || cur_owner != reg_owner)) {
			ss_emit_modxscan_region(m, reg_start, reg_end, reg_rw, reg_owner, sample);
			emitted++;
			in_region = false;
			reg_owner = NULL;
			if (emitted >= 256 || seq_has_overflowed(m))
				break;
		}

		if (present_exec) {
			if (!in_region) {
				in_region = true;
				reg_start = addr;
				reg_end = addr + step;
				reg_rw = rw;
				reg_owner = cur_owner;
			} else {
				reg_end = addr + step;
				if (rw)
					reg_rw = true;
			}
		}

		if (ULONG_MAX - addr < step)
			break;
		addr += step;
	}

	if (in_region && emitted < 256 && !seq_has_overflowed(m))
		ss_emit_modxscan_region(m, reg_start, reg_end, reg_rw, reg_owner, sample);

	kfree(sample);
}

static int ss_integrity_show(struct seq_file *m, void *v)
{
	struct ss_mod_snap *mods;
	unsigned int mod_cnt, i;
	struct ss_tp_audit_ctx tp_ctx;
	u8 bytes[SS_PROLOGUE_BYTES];
	char *sym_alloc;
	char *sym_buf;
	char *jmp_sym;
	u32 lstar_lo = 0, lstar_hi = 0;

	sym_alloc = kmalloc(2 * KSYM_SYMBOL_LEN, GFP_KERNEL);
	if (!sym_alloc)
		return -ENOMEM;
	sym_buf = sym_alloc;
	jmp_sym = sym_alloc + KSYM_SYMBOL_LEN;

	/* 0. x86_64 MSR_LSTAR syscall entry integrity (covers .noinstr entry hooks) */
	if (rdmsr_safe(MSR_LSTAR, &lstar_lo, &lstar_hi) == 0) {
		u64 lstar = ((u64)lstar_hi << 32) | lstar_lo;

		sprint_symbol(sym_buf, (unsigned long)lstar);
		seq_printf(m, "SYSCALL_ENTRY|msr_lstar=0x%llx|lstar_sym=%s\n",
			   (unsigned long long)lstar, sym_buf);
	}

	/* 1. Critical kernel function prologues + page table permissions */
	for (i = 0; i < ARRAY_SIZE(g_integrity_targets); i++) {
		unsigned long addr = g_integrity_targets[i].addr;
		unsigned int level = PG_LEVEL_NONE;
		pte_t *ptep;
		int pte_rw = -1, pte_x = -1;
		unsigned long jmp_target = 0;
		const char *hook_cls = "UNRESOLVED";

		if (seq_has_overflowed(m))
			break;
		if (!addr) {
			seq_printf(m, "KHOOK|sym=%s|addr=0x0|hook_class=UNRESOLVED\n",
				   g_integrity_targets[i].name);
			continue;
		}
		memset(bytes, 0, sizeof(bytes));
		if (copy_from_kernel_nofault(bytes, (void *)addr, sizeof(bytes)) != 0) {
			seq_printf(m, "KHOOK|sym=%s|addr=0x%lx|hook_class=READ_FAULT\n",
				   g_integrity_targets[i].name, addr);
			continue;
		}
		ptep = lookup_address(addr, &level);
		if (ptep && pte_present(*ptep)) {
			pte_rw = pte_write(*ptep) ? 1 : 0;
			pte_x = pte_exec(*ptep) ? 1 : 0;
		}
		sprint_symbol(sym_buf, addr);
		hook_cls = ss_classify_prologue(bytes, sizeof(bytes), addr, &jmp_target);
		if (jmp_target)
			sprint_symbol(jmp_sym, jmp_target);
		else
			scnprintf(jmp_sym, KSYM_SYMBOL_LEN, "NONE");

		seq_printf(m,
			   "KHOOK|sym=%s|addr=0x%lx|resolved=%s|pte_lvl=%u|pte_rw=%d|pte_exec=%d|hook_class=%s|jmp_target=0x%lx|jmp_sym=%s|bytes=%32phN\n",
			   g_integrity_targets[i].name, addr, sym_buf, level, pte_rw, pte_x,
			   hook_cls, jmp_target, jmp_sym, bytes);
	}

	/* 2. Live VFS directory iterator hooks (/proc and /) */
	if (!seq_has_overflowed(m)) {
		ss_audit_vfs_mount(m, "/proc");
		ss_audit_vfs_mount(m, "/");
	}

	/* 3. Active tracepoint callbacks across whole kernel */
	if (!seq_has_overflowed(m)) {
		memset(&tp_ctx, 0, sizeof(tp_ctx));
		tp_ctx.items = kvcalloc(SS_MAX_TP_CB, sizeof(*tp_ctx.items), GFP_KERNEL);
		tp_ctx.max_items = SS_MAX_TP_CB;
		if (tp_ctx.items) {
			for_each_kernel_tracepoint(ss_visit_kernel_tp, &tp_ctx);
			for (i = 0; i < tp_ctx.count; i++) {
				bool is_self;

				if (seq_has_overflowed(m))
					break;
				is_self = (tp_ctx.items[i].func_addr == (unsigned long)ss_tp_sys_enter_cb ||
					   tp_ctx.items[i].func_addr == (unsigned long)ss_tp_sys_exit_cb ||
					   tp_ctx.items[i].func_addr == (unsigned long)ss_tp_sched_exec_cb);
				sprint_symbol(sym_buf, tp_ctx.items[i].func_addr);
				seq_printf(m, "TPCALLBACK|tp=%s|idx=%d|prio=%d|func=0x%lx|sym=%s|is_self=%d\n",
					   tp_ctx.items[i].tp_name, tp_ctx.items[i].idx,
					   tp_ctx.items[i].prio, tp_ctx.items[i].func_addr,
					   sym_buf, is_self ? 1 : 0);
			}
			kvfree(tp_ctx.items);
		}
	}

	/* 4. Loaded LKM snapshot + MODULES_VADDR executable CR3 scan + orphan ELF carving */
	if (!seq_has_overflowed(m)) {
		bool mods_truncated = false;

		mods = kvcalloc(SS_MAX_MOD_SNAP, sizeof(*mods), GFP_KERNEL);
		if (mods) {
			mod_cnt = ss_snapshot_modules(mods, SS_MAX_MOD_SNAP, &mods_truncated);
			if (mods_truncated && !seq_has_overflowed(m))
				seq_printf(m, "TRUNCATED|mods=1|max_mods=%u\n", SS_MAX_MOD_SNAP);
			for (i = 0; i < mod_cnt; i++) {
				if (seq_has_overflowed(m))
					break;
				seq_printf(m,
					   "MODINFO|name=%s|state=%d|taints=0x%lx|sig_ok=%d|text=0x%lx-0x%lx|init=0x%lx-0x%lx|rw_anom=%d\n",
					   mods[i].name, mods[i].state, mods[i].taints,
					   mods[i].sig_ok ? 1 : 0,
					   mods[i].text_start, mods[i].text_end,
					   mods[i].init_start, mods[i].init_end,
					   mods[i].text_rw_anomaly ? 1 : 0);
			}
			if (!seq_has_overflowed(m))
				ss_scan_modules_vaddr_exec(m, mods, mod_cnt);
			kvfree(mods);
		}
	}
	kfree(sym_alloc);
	return 0;
}

/* ---------- /proc/mc_ss_sentinel/tasks_vma ---------- */

struct ss_task_snap {
	struct task_struct *task;
	pid_t pid;
	pid_t tgid;
	pid_t ppid;
	pid_t real_ppid;
	uid_t uid;
	unsigned int ptrace;
	u64 start_ns;
	char comm[TASK_COMM_LEN];
};

static unsigned int ss_analyze_vma_bytes(const u8 *buf, size_t nbytes,
					 bool *out_elf, bool *out_pe,
					 unsigned int *out_jni_mask)
{
	unsigned int hits = 0;

	if (nbytes >= 4 && memcmp(buf, "\x7f" "ELF", 4) == 0)
		*out_elf = true;
	else if (ss_buf_contains(buf, nbytes, "\x7f" "ELF\x02\x01\x01", 7))
		*out_elf = true;

	if (nbytes >= 256 && buf[0] == 'M' && buf[1] == 'Z') {
		u32 lfanew = 0;

		memcpy(&lfanew, buf + 0x3c, 4);
		if (lfanew >= 0x40 && (size_t)lfanew + 4 <= nbytes &&
		    memcmp(buf + lfanew, "PE\0\0", 4) == 0)
			*out_pe = true;
	}

	if (ss_buf_contains(buf, nbytes, "Agent_OnAttach", 14)) {
		*out_jni_mask |= (1U << 0);
		hits++;
	}
	if (ss_buf_contains(buf, nbytes, "Agent_OnLoad", 12)) {
		*out_jni_mask |= (1U << 1);
		hits++;
	}
	if (ss_buf_contains(buf, nbytes, "JNI_OnLoad", 10)) {
		*out_jni_mask |= (1U << 2);
		hits++;
	}
	if (ss_buf_contains(buf, nbytes, "RedefineClasses", 15) ||
	    ss_buf_contains(buf, nbytes, "RetransformClasses", 18)) {
		*out_jni_mask |= (1U << 3);
		hits++;
	}
	if (ss_buf_contains(buf, nbytes, "jvmtiEnv", 8)) {
		*out_jni_mask |= (1U << 4);
		hits++;
	}
	if (ss_buf_contains(buf, nbytes, "DefineClass", 11) ||
	    ss_buf_contains(buf, nbytes, "RegisterNatives", 15) ||
	    ss_buf_contains(buf, nbytes, "GetCreatedJavaVMs", 17)) {
		*out_jni_mask |= (1U << 5);
		hits++;
	}
	if (ss_buf_contains(buf, nbytes, "UPX!", 4) ||
	    ss_buf_contains(buf, nbytes, ".vmp0", 5) ||
	    ss_buf_contains(buf, nbytes, ".vmp1", 5)) {
		*out_jni_mask |= (1U << 6);
		hits++;
	}
	return hits;
}

static int ss_tasks_vma_show(struct seq_file *m, void *v)
{
	struct ss_task_snap *snaps;
	struct ss_vma_cand *cands;
	u8 *scan_buf;
	char *path_buf;
	unsigned int task_cnt = 0, i;
	struct task_struct *p;
	unsigned int effective_scan_cap;
	bool tasks_truncated = false;

	snaps = kvcalloc(SS_MAX_TASK_SNAP, sizeof(*snaps), GFP_KERNEL);
	cands = kvcalloc(SS_MAX_VMA_CAND, sizeof(*cands), GFP_KERNEL);
	path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
	effective_scan_cap = clamp_t(unsigned int, max_vma_bytes, 4096U, SS_MAX_SCAN_VMA_LIMIT);
	scan_buf = kvmalloc(effective_scan_cap, GFP_KERNEL);

	if (!snaps || !cands || !path_buf || !scan_buf) {
		kvfree(snaps);
		kvfree(cands);
		kfree(path_buf);
		kvfree(scan_buf);
		return -ENOMEM;
	}

	/* Phase 1: Quick RCU task snapshot (zero sleeping inside RCU) */
	rcu_read_lock();
	for_each_process(p) {
		struct task_struct *rp;
		struct task_struct *pr;

		if (p->flags & PF_KTHREAD)
			continue;
		if (task_cnt >= SS_MAX_TASK_SNAP) {
			tasks_truncated = true;
			break;
		}

		get_task_struct(p);
		snaps[task_cnt].task = p;
		snaps[task_cnt].pid = p->pid;
		snaps[task_cnt].tgid = p->tgid;
		pr = rcu_dereference(p->parent);
		rp = rcu_dereference(p->real_parent);
		snaps[task_cnt].ppid = pr ? pr->tgid : 0;
		snaps[task_cnt].real_ppid = rp ? rp->tgid : 0;
		snaps[task_cnt].uid = from_kuid_munged(&init_user_ns, task_uid(p));
		snaps[task_cnt].ptrace = p->ptrace;
		snaps[task_cnt].start_ns = p->start_boottime;
		ss_sanitize_str(snaps[task_cnt].comm, p->comm, TASK_COMM_LEN);
		task_cnt++;
	}
	rcu_read_unlock();

	if (tasks_truncated)
		seq_printf(m, "TRUNCATED|tasks=1|max_tasks=%u\n", SS_MAX_TASK_SNAP);

	/* Phase 2: Safe per-task mm + VMA + out-of-lock access_process_vm inspection */
	for (i = 0; i < task_cnt; i++) {
		struct task_struct *t = snaps[i].task;
		struct mm_struct *mm;
		char exe_safe[256];
		bool deleted_exe = false;
		bool deep_target;
		unsigned int cand_cnt = 0;
		unsigned int ro_cand_cnt = 0;
		bool cands_truncated = false;
		unsigned int total_vmas = 0, exec_vmas = 0, rwx_vmas = 0, anon_exec = 0;

		if (seq_has_overflowed(m)) {
			put_task_struct(t);
			continue;
		}
		mm = get_task_mm(t);
		strscpy(exe_safe, "NONE", sizeof(exe_safe));
		if (mm) {
			struct file *exe_f;

			rcu_read_lock();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
			exe_f = get_file_rcu(&mm->exe_file);
#else
			exe_f = rcu_dereference(mm->exe_file);
			if (exe_f && !get_file_rcu(exe_f))
				exe_f = NULL;
#endif
			rcu_read_unlock();
			if (exe_f) {
				char *ep = file_path(exe_f, path_buf, PATH_MAX);

				if (!IS_ERR(ep)) {
					size_t rem = (size_t)((path_buf + PATH_MAX) - ep);

					if (strnstr(ep, "(deleted)", rem) != NULL)
						deleted_exe = true;
					ss_sanitize_str(exe_safe, ep, sizeof(exe_safe));
				}
				fput(exe_f);
			}
		}

		seq_printf(m,
			   "TASK|pid=%d|tgid=%d|ppid=%d|real_ppid=%d|uid=%u|ptrace=0x%x|start_ns=%llu|comm=%s|exe=%s|deleted=%d\n",
			   snaps[i].pid, snaps[i].tgid, snaps[i].ppid,
			   snaps[i].real_ppid, snaps[i].uid, snaps[i].ptrace,
			   (unsigned long long)snaps[i].start_ns,
			   snaps[i].comm, exe_safe, deleted_exe ? 1 : 0);

		deep_target = mm && !seq_has_overflowed(m) &&
			      (ss_is_interesting_comm(snaps[i].comm) ||
			       ss_is_interesting_path(exe_safe) ||
			       snaps[i].ptrace != 0 || deleted_exe ||
			       ss_pid_in_event_ring(snaps[i].tgid));

		if (deep_target) {
			struct vm_area_struct *vma;
			unsigned int j;

			mmap_read_lock(mm);
			{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
				VMA_ITERATOR(vmi, mm, 0);

				for_each_vma(vmi, vma) {
#else
				for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
#endif
					vm_flags_t f = vma->vm_flags;
					bool is_exec = (f & VM_EXEC) != 0;
					bool is_rwx = (f & (VM_WRITE | VM_EXEC)) == (VM_WRITE | VM_EXEC);
					bool is_vdso = (vma->vm_file == NULL &&
							mm->context.vdso != NULL &&
							vma->vm_start == (unsigned long)mm->context.vdso);
					bool is_anon_x = is_exec && (vma->vm_file == NULL) && !(is_vdso && !is_rwx);
					bool is_memfd = false, is_shm_x = false, is_del = false;
					bool is_ro_susp = false;
					char fpath_safe[256];

					total_vmas++;
					if (is_exec)
						exec_vmas++;
					if (is_rwx)
						rwx_vmas++;
					if (is_anon_x)
						anon_exec++;

					fpath_safe[0] = '\0';
					if (vma->vm_file) {
						char *vp = file_path(vma->vm_file, path_buf, PATH_MAX);

						if (!IS_ERR(vp)) {
							size_t rem = (size_t)((path_buf + PATH_MAX) - vp);
							bool memfd_p = (strncmp(vp, "/memfd:", 7) == 0 ||
									strnstr(vp, "memfd:", rem) != NULL);
							bool shm_p = (strncmp(vp, "/dev/shm/", 9) == 0 ||
								      strncmp(vp, "/tmp/", 5) == 0 ||
								      strncmp(vp, "/var/tmp/", 9) == 0);
							bool del_p = (strnstr(vp, "(deleted)", rem) != NULL);

							is_memfd = memfd_p;
							is_shm_x = shm_p;
							is_del = del_p;
							/* Capture read-only (-z separate-code) ELF headers/rodata */
							is_ro_susp = !is_exec &&
								     ((f & (VM_READ | VM_WRITE | VM_EXEC)) == VM_READ) &&
								     (memfd_p || shm_p || del_p);
							ss_sanitize_str(fpath_safe, vp, sizeof(fpath_safe));
						}
					}

					if (is_rwx || is_anon_x ||
					    (is_exec && (is_memfd || is_shm_x || is_del)) ||
					    (is_ro_susp && ro_cand_cnt < 32U)) {
						if (cand_cnt < SS_MAX_VMA_CAND) {
							cands[cand_cnt].vm_start = vma->vm_start;
							cands[cand_cnt].vm_end = vma->vm_end;
							cands[cand_cnt].vm_flags = f;
							cands[cand_cnt].is_rwx = is_rwx;
							cands[cand_cnt].is_anon_exec = is_anon_x;
							cands[cand_cnt].is_memfd = is_memfd;
							cands[cand_cnt].is_shm_exec = is_shm_x;
							cands[cand_cnt].is_deleted = is_del;
							strscpy(cands[cand_cnt].file_path,
								fpath_safe[0] ? fpath_safe : (is_vdso ? "[vdso]" : "[anon]"),
								sizeof(cands[cand_cnt].file_path));
							cand_cnt++;
							if (is_ro_susp)
								ro_cand_cnt++;
						} else {
							cands_truncated = true;
						}
					}
				}
			}
			/* Release mmap_lock BEFORE access_process_vm() to prevent deadlock */
			mmap_read_unlock(mm);

			seq_printf(m,
				   "TASK_VMA_SUM|pid=%d|comm=%s|vmas=%u|exec=%u|rwx=%u|anon_exec=%u|cands=%u|truncated=%d\n",
				   snaps[i].pid, snaps[i].comm, total_vmas, exec_vmas,
				   rwx_vmas, anon_exec, cand_cnt, cands_truncated ? 1 : 0);

			for (j = 0; j < cand_cnt; j++) {
				unsigned long sz;
				int to_read;
				int got = 0;
				bool elf_hit = false, pe_hit = false;
				bool ro_only;
				unsigned int jni_mask = 0, jni_hits = 0;
				u8 head[SS_VMA_HEAD_BYTES];

				if (seq_has_overflowed(m))
					break;
				sz = cands[j].vm_end - cands[j].vm_start;
				to_read = (int)min_t(unsigned long, sz, effective_scan_cap);
				ro_only = !(cands[j].vm_flags & VM_EXEC) &&
					  !cands[j].is_rwx && !cands[j].is_anon_exec;

				memset(head, 0, sizeof(head));
				if (to_read > 0) {
					got = access_process_vm(t, cands[j].vm_start,
								scan_buf, to_read, 0);
					if (got > 0) {
						memcpy(head, scan_buf,
						       min_t(int, got, SS_VMA_HEAD_BYTES));
						jni_hits = ss_analyze_vma_bytes(
							scan_buf, (size_t)got,
							&elf_hit, &pe_hit, &jni_mask);
					}
				}
				/* Emit detailed record for high-interest or signature-matched VMAs */
				if (cands[j].is_rwx || cands[j].is_memfd || cands[j].is_shm_exec ||
				    cands[j].is_deleted || elf_hit || pe_hit || jni_hits > 0 ||
				    (!ro_only && j < 12)) {
					seq_printf(m,
						   "VMA_ANOM|pid=%d|comm=%s|start=0x%lx|end=0x%lx|size=%lu|flags=0x%lx|"
						   "rwx=%d|anon=%d|memfd=%d|shm=%d|del=%d|read=%d|elf=%d|pe=%d|jni_hits=%u|jni_mask=0x%x|file=%s|head=%32phN\n",
						   snaps[i].pid, snaps[i].comm,
						   cands[j].vm_start, cands[j].vm_end, sz,
						   cands[j].vm_flags,
						   cands[j].is_rwx ? 1 : 0,
						   cands[j].is_anon_exec ? 1 : 0,
						   cands[j].is_memfd ? 1 : 0,
						   cands[j].is_shm_exec ? 1 : 0,
						   cands[j].is_deleted ? 1 : 0,
						   got, elf_hit ? 1 : 0, pe_hit ? 1 : 0,
						   jni_hits, jni_mask,
						   cands[j].file_path, head);
				}
			}
		}

		if (mm)
			mmput(mm);
		put_task_struct(t);
	}

	kvfree(scan_buf);
	kfree(path_buf);
	kvfree(cands);
	kvfree(snaps);
	return 0;
}

/* ---------- /proc/mc_ss_sentinel/pci_iommu ---------- */

static const char *ss_iommu_domain_name(struct iommu_domain *dom)
{
	if (!dom)
		return "NONE";
	switch (dom->type) {
	case IOMMU_DOMAIN_BLOCKED:
		return "BLOCKED";
	case IOMMU_DOMAIN_IDENTITY:
		return "IDENTITY_PASSTHROUGH";
	case IOMMU_DOMAIN_UNMANAGED:
		return "UNMANAGED_VFIO";
	case IOMMU_DOMAIN_DMA:
		return "DMA_STRICT_OR_TRANSLATED";
#ifdef IOMMU_DOMAIN_DMA_FQ
	case IOMMU_DOMAIN_DMA_FQ:
		return "DMA_FQ_TRANSLATED";
#endif
#ifdef IOMMU_DOMAIN_SVA
	case IOMMU_DOMAIN_SVA:
		return "SVA";
#endif
#ifdef IOMMU_DOMAIN_PLATFORM
	case IOMMU_DOMAIN_PLATFORM:
		return "PLATFORM";
#endif
#ifdef IOMMU_DOMAIN_NESTED
	case IOMMU_DOMAIN_NESTED:
		return "NESTED";
#endif
	default:
		return "OTHER";
	}
}

static bool ss_check_pci_cap_loop(struct pci_dev *pdev)
{
	u16 status = 0;
	u8 pos = 0, id = 0, next = 0, next_pos = 0;
	u64 visited = 0;
	int hops = 0;

	if (pci_read_config_word(pdev, PCI_STATUS, &status) != 0 || status == 0xffff)
		return false;
	if (!(status & PCI_STATUS_CAP_LIST))
		return false;
	if (pci_read_config_byte(pdev, PCI_CAPABILITY_LIST, &pos) != 0)
		return false;
	pos &= 0xfc;
	while (pos >= 0x40 && (int)pos + 1 < pdev->cfg_size && hops < 48) {
		unsigned int slot = pos >> 2;

		if (visited & (1ULL << slot))
			return true;
		visited |= (1ULL << slot);

		if (pci_read_config_byte(pdev, pos, &id) != 0 ||
		    pci_read_config_byte(pdev, pos + 1, &next) != 0)
			return false;
		if (id == 0xff)
			return false;

		next_pos = next & 0xfc;
		if (next_pos == pos)
			return true;
		pos = next_pos;
		hops++;
	}
	return hops >= 48;
}

static int ss_pci_visit_dev(struct device *dev, void *data)
{
	struct seq_file *m = data;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct iommu_domain *dom;
	struct iommu_group *grp;
	int grp_id = -1;
	u16 vid_chk = 0xffff, cmd = 0, lnksta = 0;
	int dsn_pos, pcie_pos;
	u32 dsn_lo = 0, dsn_hi = 0;
	u32 bar0 = 0, bar1 = 0;
	bool bme_hw = false, cap_loop = false, d3cold = false;
	u8 cfg_head[64];
	char drv_name[64];
	int off;

	if (seq_has_overflowed(m))
		return 1;

	dom = iommu_get_domain_for_dev(dev);
	grp = iommu_group_get(dev);
	if (grp) {
		grp_id = iommu_group_id(grp);
		iommu_group_put(grp);
	}

	memset(cfg_head, 0, sizeof(cfg_head));
	d3cold = (pdev->current_state == PCI_D3cold) ||
		 (pci_read_config_word(pdev, PCI_VENDOR_ID, &vid_chk) != 0) ||
		 (vid_chk == 0xffff);

	if (!d3cold) {
		int cfg_lim = min_t(int, 64, max_t(int, 0, pdev->cfg_size));

		if (pci_read_config_word(pdev, PCI_COMMAND, &cmd) == 0)
			bme_hw = (cmd & PCI_COMMAND_MASTER) != 0;

		pcie_pos = pci_find_capability(pdev, PCI_CAP_ID_EXP);
		if (pcie_pos > 0)
			pci_read_config_word(pdev, pcie_pos + PCI_EXP_LNKSTA, &lnksta);

		dsn_pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DSN);
		if (dsn_pos > 0 && pdev->cfg_size >= dsn_pos + 12) {
			pci_read_config_dword(pdev, dsn_pos + 4, &dsn_lo);
			pci_read_config_dword(pdev, dsn_pos + 8, &dsn_hi);
		}

		if (cfg_lim >= 0x14)
			pci_read_config_dword(pdev, PCI_BASE_ADDRESS_0, &bar0);
		if (cfg_lim >= 0x18)
			pci_read_config_dword(pdev, PCI_BASE_ADDRESS_1, &bar1);
		cap_loop = ss_check_pci_cap_loop(pdev);

		for (off = 0; off + 4 <= cfg_lim; off += 4) {
			u32 val = 0;

			if (pci_read_config_dword(pdev, off, &val) == 0)
				memcpy(cfg_head + off, &val, 4);
		}
	}

	if (device_trylock(dev)) {
		ss_sanitize_str(drv_name,
				(pdev->driver && pdev->driver->name) ? pdev->driver->name : "unbound",
				sizeof(drv_name));
		device_unlock(dev);
	} else {
		strscpy(drv_name, "probing", sizeof(drv_name));
	}

	seq_printf(m,
		   "PCIDEV|bdf=%04x:%02x:%02x.%u|vid=0x%04x|did=0x%04x|svid=0x%04x|sdid=0x%04x|"
		   "class=0x%06x|rev=0x%02x|hdr=0x%02x|driver=%s|iommu_grp=%d|iommu_dom=%s|"
		   "bme_hw=%d|bme_sw=%d|untrusted=%d|ext_facing=%d|tb=%d|"
		   "pcie_spd=%u|pcie_w=%u|has_dsn=%d|dsn=%08x%08x|bar0=0x%08x|bar1=0x%08x|"
		   "cfg_sz=%d|d3cold=%d|cap_loop=%d|cfg_head=%64phN\n",
		   pci_domain_nr(pdev->bus),
		   pdev->bus ? pdev->bus->number : 0,
		   PCI_SLOT(pdev->devfn),
		   PCI_FUNC(pdev->devfn),
		   pdev->vendor, pdev->device,
		   pdev->subsystem_vendor, pdev->subsystem_device,
		   pdev->class, pdev->revision, pdev->hdr_type,
		   drv_name, grp_id, ss_iommu_domain_name(dom),
		   bme_hw ? 1 : 0,
		   pdev->is_busmaster ? 1 : 0,
		   pdev->untrusted ? 1 : 0,
		   pdev->external_facing ? 1 : 0,
		   pdev->is_thunderbolt ? 1 : 0,
		   lnksta & PCI_EXP_LNKSTA_CLS,
		   (lnksta & PCI_EXP_LNKSTA_NLW) >> 4,
		   dsn_pos > 0 ? 1 : 0,
		   dsn_hi, dsn_lo, bar0, bar1,
		   pdev->cfg_size, d3cold ? 1 : 0, cap_loop ? 1 : 0, cfg_head);
	return 0;
}

static int ss_pci_iommu_show(struct seq_file *m, void *v)
{
	bus_for_each_dev(&pci_bus_type, NULL, m, ss_pci_visit_dev);
	return 0;
}

/* ---------- /proc/mc_ss_sentinel/events ---------- */

static int ss_events_show(struct seq_file *m, void *v)
{
	struct ss_kprobe_event *copy;
	u64 total_events = 0, dropped = 0;
	unsigned int count, start_idx, i;
	unsigned long flags;

	if (!g_event_ring)
		return 0;

	copy = kvcalloc(SS_EVENT_RING_CAP, sizeof(*copy), GFP_KERNEL);
	if (!copy)
		return -ENOMEM;

	raw_spin_lock_irqsave(&g_ring_lock, flags);
	total_events = (u64)atomic64_read(&g_ring_total_events);
	count = (unsigned int)min_t(u64, total_events, (u64)SS_EVENT_RING_CAP);
	dropped = (total_events > SS_EVENT_RING_CAP) ? (total_events - SS_EVENT_RING_CAP) : 0ULL;
	start_idx = (total_events >= SS_EVENT_RING_CAP) ?
		    (unsigned int)((total_events - SS_EVENT_RING_CAP) % SS_EVENT_RING_CAP) : 0U;
	for (i = 0; i < count; i++)
		copy[i] = g_event_ring[(start_idx + i) % SS_EVENT_RING_CAP];
	raw_spin_unlock_irqrestore(&g_ring_lock, flags);

	seq_printf(m, "EVENT_META|cap=%u|total=%llu|dropped=%llu\n",
		   SS_EVENT_RING_CAP,
		   (unsigned long long)total_events,
		   (unsigned long long)dropped);

	for (i = 0; i < count; i++) {
		if (seq_has_overflowed(m))
			break;
		seq_printf(m,
			   "EVENT|ts_ns=%llu|type=%u|pid=%d|tgid=%d|uid=%u|comm=%s|arg0=0x%lx|arg1=0x%lx|ret=%ld|has_ret=%u|start_ns=%llu|detail=%s\n",
			   copy[i].ts_ns, copy[i].type, copy[i].pid, copy[i].tgid,
			   copy[i].uid, copy[i].comm, copy[i].arg0, copy[i].arg1,
			   copy[i].ret, (unsigned int)copy[i].has_ret,
			   copy[i].start_ns, copy[i].detail);
	}
	kvfree(copy);
	return 0;
}

/* ---------- /proc_ops Boilerplate with Refcount Guard ---------- */

static int ss_proc_open_common(struct inode *inode, struct file *file,
			       int (*show_fn)(struct seq_file *, void *))
{
	int ret;
	size_t prealloc = (show_fn == ss_tasks_vma_show || show_fn == ss_integrity_show) ?
			  (512UL * 1024UL) : (64UL * 1024UL);

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	atomic_inc(&g_active_readers);
	ret = single_open_size(file, show_fn, NULL, prealloc);
	if (ret) {
		atomic_dec(&g_active_readers);
		module_put(THIS_MODULE);
	}
	return ret;
}

static int ss_proc_release_common(struct inode *inode, struct file *file)
{
	int ret = single_release(inode, file);

	atomic_dec(&g_active_readers);
	module_put(THIS_MODULE);
	return ret;
}

#define DEFINE_SS_PROC_OPS(opname, showfn)				\
	static int opname##_open(struct inode *inode, struct file *file) \
	{								\
		return ss_proc_open_common(inode, file, (showfn));	\
	}								\
	static const struct proc_ops opname = {				\
		.proc_open    = opname##_open,				\
		.proc_read    = seq_read,				\
		.proc_lseek   = seq_lseek,				\
		.proc_release = ss_proc_release_common,			\
	}

DEFINE_SS_PROC_OPS(g_status_ops, ss_status_show);
DEFINE_SS_PROC_OPS(g_integrity_ops, ss_integrity_show);
DEFINE_SS_PROC_OPS(g_tasks_vma_ops, ss_tasks_vma_show);
DEFINE_SS_PROC_OPS(g_pci_iommu_ops, ss_pci_iommu_show);
DEFINE_SS_PROC_OPS(g_events_ops, ss_events_show);

/* ---------- Init & Exit (Zero-Leak Teardown) ---------- */

static void ss_teardown_probes(void)
{
	if (g_tp_sys_enter_active && g_tp_sys_enter) {
		tracepoint_probe_unregister(g_tp_sys_enter, ss_tp_sys_enter_cb, NULL);
		g_tp_sys_enter_active = false;
	}
	if (g_tp_sys_exit_active && g_tp_sys_exit) {
		tracepoint_probe_unregister(g_tp_sys_exit, ss_tp_sys_exit_cb, NULL);
		g_tp_sys_exit_active = false;
	}
	if (g_tp_sched_exec_active && g_tp_sched_exec) {
		tracepoint_probe_unregister(g_tp_sched_exec, ss_tp_sched_exec_cb, NULL);
		g_tp_sched_exec_active = false;
	}
	if (g_kp_input_active) {
		unregister_kprobe(&g_kp_input);
		g_kp_input_active = false;
	}
	if (g_mod_notifier_active) {
		unregister_module_notifier(&g_mod_nb);
		g_mod_notifier_active = false;
	}
	tracepoint_synchronize_unregister();
	synchronize_rcu();
}

static int __init mc_ss_init(void)
{
	struct ss_tp_audit_ctx tp_ctx;
	unsigned int i;

	pr_info("initializing ephemeral Ring-0 sentinel v%s\n", SS_KMOD_VERSION);

	g_event_ring = kvcalloc(SS_EVENT_RING_CAP, sizeof(*g_event_ring), GFP_KERNEL);
	if (!g_event_ring)
		return -ENOMEM;

	/* Resolve integrity check symbols one-by-one before arming probes */
	for (i = 0; i < ARRAY_SIZE(g_integrity_targets); i++)
		g_integrity_targets[i].addr = ss_resolve_symbol_via_kprobe(g_integrity_targets[i].name);

	g_proc_root = proc_mkdir(SS_PROC_DIR, NULL);
	if (!g_proc_root) {
		kvfree(g_event_ring);
		g_event_ring = NULL;
		return -ENOMEM;
	}

	if (!proc_create_data("status", 0400, g_proc_root, &g_status_ops, NULL) ||
	    !proc_create_data("integrity", 0400, g_proc_root, &g_integrity_ops, NULL) ||
	    !proc_create_data("tasks_vma", 0400, g_proc_root, &g_tasks_vma_ops, NULL) ||
	    !proc_create_data("pci_iommu", 0400, g_proc_root, &g_pci_iommu_ops, NULL) ||
	    !proc_create_data("events", 0400, g_proc_root, &g_events_ops, NULL)) {
		remove_proc_subtree(SS_PROC_DIR, NULL);
		g_proc_root = NULL;
		kvfree(g_event_ring);
		g_event_ring = NULL;
		return -ENOMEM;
	}

	if (enable_live_probes) {
		memset(&tp_ctx, 0, sizeof(tp_ctx));
		for_each_kernel_tracepoint(ss_visit_kernel_tp, &tp_ctx);
		g_tp_sys_enter = tp_ctx.found_sys_enter;
		g_tp_sys_exit = tp_ctx.found_sys_exit;
		g_tp_sched_exec = tp_ctx.found_sched_exec;

		if (g_tp_sys_exit &&
		    tracepoint_probe_register(g_tp_sys_exit, ss_tp_sys_exit_cb, NULL) == 0)
			g_tp_sys_exit_active = true;

		if (g_tp_sys_enter &&
		    tracepoint_probe_register(g_tp_sys_enter, ss_tp_sys_enter_cb, NULL) == 0)
			g_tp_sys_enter_active = true;

		if (g_tp_sched_exec &&
		    tracepoint_probe_register(g_tp_sched_exec, ss_tp_sched_exec_cb, NULL) == 0)
			g_tp_sched_exec_active = true;

		if (register_kprobe(&g_kp_input) == 0)
			g_kp_input_active = true;

		if (register_module_notifier(&g_mod_nb) == 0)
			g_mod_notifier_active = true;
	}

	pr_info("sentinel armed (live_probes=%d tp_sys=%d tp_sys_exit=%d tp_exec=%d kp_input=%d)\n",
		enable_live_probes ? 1 : 0,
		g_tp_sys_enter_active ? 1 : 0,
		g_tp_sys_exit_active ? 1 : 0,
		g_tp_sched_exec_active ? 1 : 0,
		g_kp_input_active ? 1 : 0);
	return 0;
}

static void __exit mc_ss_exit(void)
{
	ss_teardown_probes();
	if (g_proc_root) {
		remove_proc_subtree(SS_PROC_DIR, NULL);
		g_proc_root = NULL;
	}
	kvfree(g_event_ring);
	g_event_ring = NULL;
	pr_info("sentinel cleanly removed from Ring-0\n");
}

module_init(mc_ss_init);
module_exit(mc_ss_exit);
