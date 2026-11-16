/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * MC SS Sentinel — Ring-0 Ephemeral Forensic & Integrity Driver Header
 * Target: Linux x86_64 (verified against kernel 7.3.x Kbuild / EXPORT_SYMBOL APIs)
 */

#ifndef _MC_SS_KMOD_H
#define _MC_SS_KMOD_H

#include <linux/types.h>

#define SS_KMOD_VERSION        "2.0.0-ring0"
#define SS_PROC_DIR            "mc_ss_sentinel"

#define SS_EVENT_RING_CAP      1024U
#define SS_MAX_TASK_SNAP       2048U
#define SS_MAX_VMA_CAND        192U
#define SS_MAX_MOD_SNAP        512U
#define SS_MAX_TP_CB           128U
#define SS_PROLOGUE_BYTES      32U
#define SS_VMA_HEAD_BYTES      32U
#define SS_DEFAULT_VMA_SCAN    65536U
#define SS_MAX_SCAN_VMA_LIMIT  262144U
#define SS_EVENT_DETAIL_LEN    96

enum ss_event_type {
	SS_EVT_NONE = 0,
	SS_EVT_SYSCALL_PTRACE = 1,
	SS_EVT_SYSCALL_VM_WRITEV = 2,
	SS_EVT_SYSCALL_VM_READV = 3,
	SS_EVT_SYSCALL_MEMFD = 4,
	SS_EVT_SYSCALL_EXECVEAT = 5,
	SS_EVT_SYSCALL_MOD_LOAD = 6,
	SS_EVT_SYSCALL_BPF = 7,
	SS_EVT_SYSCALL_IOPL = 8,
	SS_EVT_PROCESS_EXEC = 9,
	SS_EVT_MODULE_NOTIFY = 10,
	SS_EVT_INPUT_REGISTER = 11,
	SS_EVT_SYSCALL_UINPUT_CREATE = 12,
};

struct ss_kprobe_event {
	u64 ts_ns;
	u32 type;
	pid_t pid;
	pid_t tgid;
	uid_t uid;
	char comm[TASK_COMM_LEN];
	unsigned long arg0;
	unsigned long arg1;
	char detail[SS_EVENT_DETAIL_LEN];
};

struct ss_mod_snap {
	char name[MODULE_NAME_LEN];
	int state;
	unsigned long taints;
	bool sig_ok;
	unsigned long text_start;
	unsigned long text_end;
	unsigned long init_start;
	unsigned long init_end;
	bool text_rw_anomaly;
};

struct ss_vma_cand {
	unsigned long vm_start;
	unsigned long vm_end;
	unsigned long vm_flags;
	bool is_rwx;
	bool is_anon_exec;
	bool is_memfd;
	bool is_shm_exec;
	bool is_deleted;
	char file_path[256];
};

struct ss_tp_cb_snap {
	const char *tp_name;
	int idx;
	int prio;
	unsigned long func_addr;
};

#endif /* _MC_SS_KMOD_H */
