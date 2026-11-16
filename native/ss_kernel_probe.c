/*
 * MC SS Sentinel — Native Linux Kernel Surface & eBPF Telemetry Collector
 *
 * Pure C userspace companion (zero external dependencies beyond libc + <linux/bpf.h>):
 *   1. bpf-dump  : Direct sys_bpf() enumeration of all active eBPF progs, maps & links
 *                  (catches Boopkit / ebpfkit / TripleCross without requiring bpftool).
 *   2. pid-cross : Direct readdir("/proc") vs kill(pid, 0) + stat("/proc/<pid>") sweep
 *                  (catches LD_PRELOAD libprocesshider and getdents64 cloaking).
 *   3. pci-dump  : Extended PCIe configuration space (up to 4096B) & Capability walk.
 *   4. all       : Combined JSON telemetry output for Engine 9.
 */

#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/version.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

static void print_json_str(const char *s)
{
	const unsigned char *p = (const unsigned char *)(s ? s : "");

	putchar('"');
	while (*p) {
		unsigned char c = *p++;

		if (c == '"' || c == '\\') {
			putchar('\\');
			putchar((int)c);
		} else if (c < 0x20 || c == 0x7f) {
			printf("\\u%04x", (unsigned int)c);
		} else {
			putchar((int)c);
		}
	}
	putchar('"');
}

static const char *bpf_prog_type_name(uint32_t t)
{
	switch (t) {
	case BPF_PROG_TYPE_SOCKET_FILTER: return "SOCKET_FILTER";
	case BPF_PROG_TYPE_KPROBE: return "KPROBE";
	case BPF_PROG_TYPE_SCHED_CLS: return "SCHED_CLS";
	case BPF_PROG_TYPE_SCHED_ACT: return "SCHED_ACT";
	case BPF_PROG_TYPE_TRACEPOINT: return "TRACEPOINT";
	case BPF_PROG_TYPE_XDP: return "XDP";
	case BPF_PROG_TYPE_PERF_EVENT: return "PERF_EVENT";
	case BPF_PROG_TYPE_CGROUP_SKB: return "CGROUP_SKB";
	case BPF_PROG_TYPE_CGROUP_SOCK: return "CGROUP_SOCK";
	case BPF_PROG_TYPE_SOCK_OPS: return "SOCK_OPS";
	case BPF_PROG_TYPE_SK_SKB: return "SK_SKB";
	case BPF_PROG_TYPE_CGROUP_DEVICE: return "CGROUP_DEVICE";
	case BPF_PROG_TYPE_SK_MSG: return "SK_MSG";
	case BPF_PROG_TYPE_RAW_TRACEPOINT: return "RAW_TRACEPOINT";
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: return "RAW_TRACEPOINT_WRITABLE";
	case BPF_PROG_TYPE_TRACING: return "TRACING";
	case BPF_PROG_TYPE_STRUCT_OPS: return "STRUCT_OPS";
	case BPF_PROG_TYPE_EXT: return "EXT";
	case BPF_PROG_TYPE_LSM: return "LSM";
	case BPF_PROG_TYPE_SK_LOOKUP: return "SK_LOOKUP";
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	case BPF_PROG_TYPE_SYSCALL: return "SYSCALL";
#else
	case 31: return "SYSCALL";
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	case BPF_PROG_TYPE_NETFILTER: return "NETFILTER";
#else
	case 32: return "NETFILTER";
#endif
	default: return "OTHER";
	}
}

static const char *bpf_map_type_name(uint32_t t)
{
	switch (t) {
	case BPF_MAP_TYPE_HASH: return "HASH";
	case BPF_MAP_TYPE_ARRAY: return "ARRAY";
	case BPF_MAP_TYPE_PROG_ARRAY: return "PROG_ARRAY";
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY: return "PERF_EVENT_ARRAY";
	case BPF_MAP_TYPE_PERCPU_HASH: return "PERCPU_HASH";
	case BPF_MAP_TYPE_RINGBUF: return "RINGBUF";
	case BPF_MAP_TYPE_SOCKHASH: return "SOCKHASH";
	case BPF_MAP_TYPE_SOCKMAP: return "SOCKMAP";
	default: return "OTHER";
	}
}

struct vmlinux_btf_index {
	int attempted;
	char *str_sec;
	uint32_t str_len;
	uint32_t *name_offs;
	uint32_t num_types;
};

static struct vmlinux_btf_index g_btf_idx = {0};

static void free_vmlinux_btf(void)
{
	free(g_btf_idx.str_sec);
	free(g_btf_idx.name_offs);
	g_btf_idx.str_sec = NULL;
	g_btf_idx.name_offs = NULL;
	g_btf_idx.str_len = 0;
	g_btf_idx.num_types = 0;
	g_btf_idx.attempted = 0;
}

static int load_vmlinux_btf(void)
{
	int fd;
	struct stat st;
	uint8_t *buf = NULL;
	ssize_t nread;
	size_t total = 0;
	struct btf_header hdr;
	size_t types_start, types_end, strs_start;
	uint32_t pos = 0;
	uint32_t cap = 65536;

	if (g_btf_idx.attempted)
		return g_btf_idx.name_offs != NULL ? 0 : -1;
	g_btf_idx.attempted = 1;

	fd = open("/sys/kernel/btf/vmlinux", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(hdr) ||
	    st.st_size > 32L * 1024L * 1024L) {
		close(fd);
		return -1;
	}
	buf = malloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -1;
	}
	while (total < (size_t)st.st_size) {
		nread = read(fd, buf + total, (size_t)st.st_size - total);
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (nread == 0)
			break;
		total += (size_t)nread;
	}
	close(fd);
	if (total < sizeof(hdr)) {
		free(buf);
		return -1;
	}
	memcpy(&hdr, buf, sizeof(hdr));
	if (hdr.magic != BTF_MAGIC || hdr.version != BTF_VERSION ||
	    hdr.hdr_len < 24 || hdr.hdr_len > total) {
		free(buf);
		return -1;
	}
	types_start = (size_t)hdr.hdr_len + hdr.type_off;
	types_end = types_start + hdr.type_len;
	strs_start = (size_t)hdr.hdr_len + hdr.str_off;
	if (types_start < hdr.hdr_len || types_end < types_start ||
	    types_end > total || strs_start < hdr.hdr_len ||
	    strs_start + hdr.str_len < strs_start ||
	    strs_start + hdr.str_len > total || hdr.str_len == 0) {
		free(buf);
		return -1;
	}

	g_btf_idx.str_sec = malloc(hdr.str_len);
	g_btf_idx.name_offs = calloc(cap, sizeof(uint32_t));
	if (!g_btf_idx.str_sec || !g_btf_idx.name_offs) {
		free(g_btf_idx.str_sec);
		free(g_btf_idx.name_offs);
		g_btf_idx.str_sec = NULL;
		g_btf_idx.name_offs = NULL;
		free(buf);
		return -1;
	}
	memcpy(g_btf_idx.str_sec, buf + strs_start, hdr.str_len);
	g_btf_idx.str_sec[hdr.str_len - 1] = '\0';
	g_btf_idx.str_len = hdr.str_len;
	g_btf_idx.name_offs[0] = 0;
	g_btf_idx.num_types = 1; /* Type IDs start at 1 */

	while (pos + sizeof(struct btf_type) <= hdr.type_len) {
		struct btf_type t;
		uint32_t kind, vlen;
		size_t extra = 0;

		memcpy(&t, buf + types_start + pos, sizeof(t));
		kind = BTF_INFO_KIND(t.info);
		vlen = BTF_INFO_VLEN(t.info);

		switch (kind) {
		case BTF_KIND_INT:
			extra = 4;
			break;
		case BTF_KIND_ARRAY:
			extra = sizeof(struct btf_array);
			break;
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
			if (vlen > 65535U)
				goto done_walk;
			extra = (size_t)vlen * sizeof(struct btf_member);
			break;
		case BTF_KIND_ENUM:
			if (vlen > 65535U)
				goto done_walk;
			extra = (size_t)vlen * sizeof(struct btf_enum);
			break;
		case BTF_KIND_FUNC_PROTO:
			if (vlen > 65535U)
				goto done_walk;
			extra = (size_t)vlen * sizeof(struct btf_param);
			break;
		case BTF_KIND_VAR:
			extra = sizeof(struct btf_var);
			break;
		case BTF_KIND_DATASEC:
			if (vlen > 65535U)
				goto done_walk;
			extra = (size_t)vlen * sizeof(struct btf_var_secinfo);
			break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
		case BTF_KIND_DECL_TAG:
			extra = sizeof(struct btf_decl_tag);
			break;
#else
		case 17:
			extra = sizeof(int32_t);
			break;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
		case BTF_KIND_ENUM64:
			if (vlen > 65535U)
				goto done_walk;
			extra = (size_t)vlen * sizeof(struct btf_enum64);
			break;
#else
		case 19:
			if (vlen > 65535U)
				goto done_walk;
			extra = (size_t)vlen * (3U * sizeof(uint32_t));
			break;
#endif
		case BTF_KIND_UNKN:
		case BTF_KIND_PTR:
		case BTF_KIND_FWD:
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_FUNC:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 13, 0)
		case BTF_KIND_FLOAT:
#else
		case 16:
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
		case BTF_KIND_TYPE_TAG:
#else
		case 18:
#endif
			extra = 0;
			break;
		default:
			goto done_walk;
		}

		if (pos + sizeof(struct btf_type) + extra > hdr.type_len)
			break;

		if (g_btf_idx.num_types >= cap) {
			uint32_t new_cap = cap * 2U;
			uint32_t *tmp;

			if (new_cap > 524288U)
				break;
			tmp = realloc(g_btf_idx.name_offs, (size_t)new_cap * sizeof(uint32_t));
			if (!tmp)
				break;
			g_btf_idx.name_offs = tmp;
			cap = new_cap;
		}
		g_btf_idx.name_offs[g_btf_idx.num_types++] = t.name_off;
		pos += (uint32_t)(sizeof(struct btf_type) + extra);
	}
done_walk:
	free(buf);
	return 0;
}

static void resolve_vmlinux_btf_name(uint32_t btf_id, char *out, size_t out_sz)
{
	uint32_t noff;

	if (!out || out_sz == 0)
		return;
	out[0] = '\0';
	if (btf_id == 0 || load_vmlinux_btf() != 0)
		return;
	if (btf_id >= g_btf_idx.num_types)
		return;
	noff = g_btf_idx.name_offs[btf_id];
	if (noff < g_btf_idx.str_len)
		snprintf(out, out_sz, "%s", g_btf_idx.str_sec + noff);
}

static void emit_bpf_section(void)
{
	union bpf_attr attr;
	uint32_t id = 0;
	int first = 1;
	int err_code = 0;

	printf("  \"bpf\": {\n");
	printf("    \"progs\": [");

	for (;;) {
		struct bpf_prog_info info;
		uint32_t len = sizeof(info);
		int fd;

		memset(&attr, 0, sizeof(attr));
		attr.start_id = id;
		if (sys_bpf(BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr)) < 0) {
			if (errno != ENOENT)
				err_code = errno;
			break;
		}
		id = attr.next_id;

		memset(&attr, 0, sizeof(attr));
		attr.prog_id = id;
		fd = sys_bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
		if (fd < 0)
			continue;

		memset(&info, 0, sizeof(info));
		memset(&attr, 0, sizeof(attr));
		attr.info.bpf_fd = (uint32_t)fd;
		attr.info.info_len = len;
		attr.info.info = (uint64_t)(uintptr_t)&info;

		if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0) {
			char attach_target[128];
			uint32_t attach_btf_obj_id = 0;
			uint32_t attach_btf_id = 0;

			attach_target[0] = '\0';
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
			attach_btf_obj_id = info.attach_btf_obj_id;
			attach_btf_id = info.attach_btf_id;
			if (attach_btf_obj_id == 0 && attach_btf_id > 0)
				resolve_vmlinux_btf_name(attach_btf_id,
							 attach_target, sizeof(attach_target));
#endif
			if (!first)
				putchar(',');
			first = 0;
			printf("\n      {\"id\": %u, \"type\": \"%s\", \"type_id\": %u, \"name\": ",
			       info.id, bpf_prog_type_name(info.type), info.type);
			info.name[sizeof(info.name) - 1] = '\0';
			print_json_str(info.name);
			printf(", \"uid\": %u, \"gpl\": %u, \"jited_len\": %u, \"xlated_len\": %u, \"btf_id\": %u, \"attach_btf_obj_id\": %u, \"attach_btf_id\": %u, \"attach_target\": ",
			       info.created_by_uid, info.gpl_compatible,
			       info.jited_prog_len, info.xlated_prog_len,
			       info.btf_id, attach_btf_obj_id, attach_btf_id);
			print_json_str(attach_target);
			printf(", \"run_cnt\": %llu, \"run_ns\": %llu, \"tag\": \"%02x%02x%02x%02x%02x%02x%02x%02x\"}",
			       (unsigned long long)info.run_cnt,
			       (unsigned long long)info.run_time_ns,
			       info.tag[0], info.tag[1], info.tag[2], info.tag[3],
			       info.tag[4], info.tag[5], info.tag[6], info.tag[7]);
		}
		close(fd);
	}
	printf("\n    ],\n");

	/* Maps */
	printf("    \"maps\": [");
	id = 0;
	first = 1;
	for (;;) {
		struct bpf_map_info minfo;
		int fd;

		memset(&attr, 0, sizeof(attr));
		attr.start_id = id;
		if (sys_bpf(BPF_MAP_GET_NEXT_ID, &attr, sizeof(attr)) < 0) {
			if (errno != ENOENT && err_code == 0)
				err_code = errno;
			break;
		}
		id = attr.next_id;

		memset(&attr, 0, sizeof(attr));
		attr.map_id = id;
		fd = sys_bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
		if (fd < 0)
			continue;

		memset(&minfo, 0, sizeof(minfo));
		memset(&attr, 0, sizeof(attr));
		attr.info.bpf_fd = (uint32_t)fd;
		attr.info.info_len = sizeof(minfo);
		attr.info.info = (uint64_t)(uintptr_t)&minfo;
		if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0) {
			if (!first)
				putchar(',');
			first = 0;
			minfo.name[sizeof(minfo.name) - 1] = '\0';
			printf("\n      {\"id\": %u, \"type\": \"%s\", \"name\": ",
			       minfo.id, bpf_map_type_name(minfo.type));
			print_json_str(minfo.name);
			printf(", \"key_sz\": %u, \"val_sz\": %u, \"max_entries\": %u}",
			       minfo.key_size, minfo.value_size, minfo.max_entries);
		}
		close(fd);
	}
	printf("\n    ],\n");

	/* Links */
	printf("    \"links\": [");
	id = 0;
	first = 1;
	for (;;) {
		struct bpf_link_info linfo;
		char tp_name[128];
		int fd;

		memset(&attr, 0, sizeof(attr));
		attr.start_id = id;
		if (sys_bpf(BPF_LINK_GET_NEXT_ID, &attr, sizeof(attr)) < 0) {
			if (errno != ENOENT && err_code == 0)
				err_code = errno;
			break;
		}
		id = attr.next_id;

		memset(&attr, 0, sizeof(attr));
		attr.link_id = id;
		fd = sys_bpf(BPF_LINK_GET_FD_BY_ID, &attr, sizeof(attr));
		if (fd < 0)
			continue;

		uint32_t attach_type = 0, target_obj_id = 0, target_btf_id = 0;

		memset(&linfo, 0, sizeof(linfo));
		memset(tp_name, 0, sizeof(tp_name));

		memset(&attr, 0, sizeof(attr));
		attr.info.bpf_fd = (uint32_t)fd;
		attr.info.info_len = sizeof(linfo);
		attr.info.info = (uint64_t)(uintptr_t)&linfo;
		if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0) {
			uint32_t link_id = linfo.id;
			uint32_t ltype = linfo.type;
			uint32_t prog_id = linfo.prog_id;

			if (ltype == BPF_LINK_TYPE_TRACING) {
				attach_type = linfo.tracing.attach_type;
				target_obj_id = linfo.tracing.target_obj_id;
				target_btf_id = linfo.tracing.target_btf_id;
				if (target_obj_id == 0 && target_btf_id > 0)
					resolve_vmlinux_btf_name(target_btf_id, tp_name, sizeof(tp_name));
			} else if (ltype == BPF_LINK_TYPE_RAW_TRACEPOINT) {
				memset(&linfo, 0, sizeof(linfo));
				linfo.raw_tracepoint.tp_name = (uint64_t)(uintptr_t)tp_name;
				linfo.raw_tracepoint.tp_name_len = sizeof(tp_name) - 1;
				memset(&attr, 0, sizeof(attr));
				attr.info.bpf_fd = (uint32_t)fd;
				attr.info.info_len = sizeof(linfo);
				attr.info.info = (uint64_t)(uintptr_t)&linfo;
				sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
			} else if (ltype == BPF_LINK_TYPE_ITER) {
				memset(&linfo, 0, sizeof(linfo));
				linfo.iter.target_name = (uint64_t)(uintptr_t)tp_name;
				linfo.iter.target_name_len = sizeof(tp_name) - 1;
				memset(&attr, 0, sizeof(attr));
				attr.info.bpf_fd = (uint32_t)fd;
				attr.info.info_len = sizeof(linfo);
				attr.info.info = (uint64_t)(uintptr_t)&linfo;
				sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
			} else if (ltype == BPF_LINK_TYPE_PERF_EVENT) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
				uint32_t pe_type = linfo.perf_event.type;

				if (pe_type == BPF_PERF_EVENT_KPROBE ||
				    pe_type == BPF_PERF_EVENT_KRETPROBE) {
					memset(&linfo, 0, sizeof(linfo));
					linfo.perf_event.kprobe.func_name = (uint64_t)(uintptr_t)tp_name;
					linfo.perf_event.kprobe.name_len = sizeof(tp_name) - 1;
					memset(&attr, 0, sizeof(attr));
					attr.info.bpf_fd = (uint32_t)fd;
					attr.info.info_len = sizeof(linfo);
					attr.info.info = (uint64_t)(uintptr_t)&linfo;
					sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
				} else if (pe_type == BPF_PERF_EVENT_TRACEPOINT) {
					memset(&linfo, 0, sizeof(linfo));
					linfo.perf_event.tracepoint.tp_name = (uint64_t)(uintptr_t)tp_name;
					linfo.perf_event.tracepoint.name_len = sizeof(tp_name) - 1;
					memset(&attr, 0, sizeof(attr));
					attr.info.bpf_fd = (uint32_t)fd;
					attr.info.info_len = sizeof(linfo);
					attr.info.info = (uint64_t)(uintptr_t)&linfo;
					sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
				} else if (pe_type == BPF_PERF_EVENT_UPROBE ||
					   pe_type == BPF_PERF_EVENT_URETPROBE) {
					memset(&linfo, 0, sizeof(linfo));
					linfo.perf_event.uprobe.file_name = (uint64_t)(uintptr_t)tp_name;
					linfo.perf_event.uprobe.name_len = sizeof(tp_name) - 1;
					memset(&attr, 0, sizeof(attr));
					attr.info.bpf_fd = (uint32_t)fd;
					attr.info.info_len = sizeof(linfo);
					attr.info.info = (uint64_t)(uintptr_t)&linfo;
					sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
				}
#else
				snprintf(tp_name, sizeof(tp_name), "perf_event");
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
			} else if (ltype == BPF_LINK_TYPE_KPROBE_MULTI) {
				snprintf(tp_name, sizeof(tp_name), "kprobe_multi(count=%u)",
					 linfo.kprobe_multi.count);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 18, 0)
			} else if (ltype == BPF_LINK_TYPE_KPROBE_MULTI) {
				snprintf(tp_name, sizeof(tp_name), "kprobe_multi");
#else
			} else if (ltype == 8) {
				snprintf(tp_name, sizeof(tp_name), "kprobe_multi");
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(7, 0, 0)
			} else if (ltype == BPF_LINK_TYPE_TRACING_MULTI) {
				snprintf(tp_name, sizeof(tp_name), "tracing_multi(count=%u)",
					 linfo.tracing_multi.count);
#else
			} else if (ltype == 15) {
				snprintf(tp_name, sizeof(tp_name), "tracing_multi");
#endif
			}

			if (!first)
				putchar(',');
			first = 0;
			tp_name[sizeof(tp_name) - 1] = '\0';
			printf("\n      {\"id\": %u, \"type_id\": %u, \"prog_id\": %u, \"attach_type\": %u, \"target_obj_id\": %u, \"target_btf_id\": %u, \"tp_name\": ",
			       link_id, ltype, prog_id, attach_type, target_obj_id, target_btf_id);
			print_json_str(tp_name);
			putchar('}');
		}
		close(fd);
	}
	printf("\n    ],\n");
	printf("    \"euid\": %u,\n", (unsigned int)geteuid());
	printf("    \"errno\": %d\n", err_code);
	printf("  }");
}

static long read_pid_max(void)
{
	FILE *fp = fopen("/proc/sys/kernel/pid_max", "r");
	long val = 65536;

	if (fp) {
		if (fscanf(fp, "%ld", &val) != 1 || val < 1024)
			val = 65536;
		fclose(fp);
	}
	/* Raise sweep cap to 1M PIDs; re-checks below are sub-millisecond on zero hits */
	if (val > 1048576)
		val = 1048576;
	return val;
}

struct ss_linux_dirent64 {
	uint64_t d_ino;
	int64_t  d_off;
	uint16_t d_reclen;
	uint8_t  d_type;
	char     d_name[];
};

static bool detect_proc_hidepid(void)
{
	FILE *fp = fopen("/proc/self/mountinfo", "r");
	char line[1024];
	bool hidden = false;

	if (!fp)
		fp = fopen("/proc/mounts", "r");
	if (!fp)
		return false;

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, " /proc ") != NULL) {
			if (strstr(line, "hidepid=1") != NULL ||
			    strstr(line, "hidepid=2") != NULL ||
			    strstr(line, "hidepid=4") != NULL ||
			    strstr(line, "hidepid=ptraceable") != NULL ||
			    strstr(line, "hidepid=invisible") != NULL ||
			    strstr(line, "hidepid=noaccess") != NULL) {
				hidden = true;
				break;
			}
		}
	}
	fclose(fp);
	return hidden;
}

static bool proc_readdir_has_pid(long target_pid)
{
	DIR *d = opendir("/proc");
	struct dirent *de;
	bool found = false;

	if (!d)
		return false;
	while ((de = readdir(d)) != NULL) {
		char *endp = NULL;
		long p;

		if (!isdigit((unsigned char)de->d_name[0]))
			continue;
		p = strtol(de->d_name, &endp, 10);
		if (endp && *endp == '\0' && p == target_pid) {
			found = true;
			break;
		}
	}
	closedir(d);
	return found;
}

static int read_tgid_from_status(const char *status_path)
{
	FILE *sf = fopen(status_path, "r");
	int tgid_check = -1;

	if (sf) {
		char line[128];

		while (fgets(line, sizeof(line), sf)) {
			if (sscanf(line, "Tgid:\t%d", &tgid_check) == 1)
				break;
		}
		fclose(sf);
	}
	return tgid_check;
}

static void emit_pid_cross_section(void)
{
	long pid_cap = read_pid_max();
	uint8_t *seen = calloc((size_t)pid_cap + 1U, 1);
	uint8_t *seen_raw = calloc((size_t)pid_cap + 1U, 1);
	DIR *d;
	struct dirent *de;
	long pid;
	int hidden_first = 1;
	unsigned int readdir_count = 0;
	unsigned int raw_getdents_count = 0;
	unsigned int hidden_count = 0;
	unsigned int euid = (unsigned int)geteuid();
	bool hidepid = detect_proc_hidepid();
	struct stat init_st;
	bool proc_sane;

	printf("  \"pid_cross\": {\n");
	if (!seen || !seen_raw) {
		free(seen);
		free(seen_raw);
		printf("    \"error\": \"oom\"\n  }");
		return;
	}

	proc_sane = (stat("/proc/1/status", &init_st) == 0);

	/* 1. Standard libc readdir("/proc") pass */
	d = opendir("/proc");
	if (d) {
		while ((de = readdir(d)) != NULL) {
			char *endp = NULL;
			long p;

			if (!isdigit((unsigned char)de->d_name[0]))
				continue;
			p = strtol(de->d_name, &endp, 10);
			if (endp && *endp == '\0' && p > 0 && p <= pid_cap) {
				seen[p] = 1;
				readdir_count++;
			}
		}
		closedir(d);
	}

	/* 2. Direct SYS_getdents64("/proc") pass to defeat LD_PRELOAD readdir() wrappers */
	{
		int pfd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);

		if (pfd >= 0) {
			_Alignas(8) char gbuf[16384];

			for (;;) {
				long nread = syscall(__NR_getdents64, pfd, gbuf, sizeof(gbuf));
				long bpos = 0;

				if (nread < 0) {
					if (errno == EINTR)
						continue;
					break;
				}
				if (nread == 0)
					break;
				while (bpos + (long)sizeof(struct ss_linux_dirent64) <= nread) {
					struct ss_linux_dirent64 hdr;
					const char *name_ptr;
					size_t name_off = offsetof(struct ss_linux_dirent64, d_name);
					size_t max_name;
					const void *nul;

					memcpy(&hdr, gbuf + bpos, sizeof(hdr));
					if (hdr.d_reclen < name_off + 1U ||
					    bpos + (long)hdr.d_reclen > nread)
						break;

					name_ptr = gbuf + bpos + (long)name_off;
					max_name = (size_t)hdr.d_reclen - name_off;
					nul = memchr(name_ptr, '\0', max_name);
					if (nul && isdigit((unsigned char)name_ptr[0])) {
						char *endp = NULL;
						long p = strtol(name_ptr, &endp, 10);

						if (endp && *endp == '\0' && p > 0 && p <= pid_cap) {
							seen_raw[p] = 1;
							raw_getdents_count++;
						}
					}
					bpos += (long)hdr.d_reclen;
				}
			}
			close(pfd);
		}
	}

	printf("    \"euid\": %u,\n", euid);
	printf("    \"hidepid_detected\": %d,\n", hidepid ? 1 : 0);
	printf("    \"readdir_count\": %u,\n", readdir_count);
	printf("    \"raw_getdents_count\": %u,\n", raw_getdents_count);
	printf("    \"pid_sweep_cap\": %ld,\n", pid_cap);
	printf("    \"hidden_candidates\": [");

	for (pid = 1; proc_sane && readdir_count > 10 && pid <= pid_cap; pid++) {
		char pbuf[64];
		struct stat st;
		int k_rc;
		int k_err;
		int s_rc;
		int s_err;
		int tgid_check = -1;
		bool raw_only = (seen_raw[pid] && !seen[pid]);

		if (seen[pid] && seen_raw[pid])
			continue;

		errno = 0;
		k_rc = kill((pid_t)pid, 0);
		k_err = errno;
		if (k_rc != 0 && k_err != EPERM)
			continue;

		snprintf(pbuf, sizeof(pbuf), "/proc/%ld/status", pid);
		errno = 0;
		s_rc = stat(pbuf, &st);
		s_err = errno;
		if (s_rc == 0)
			tgid_check = read_tgid_from_status(pbuf);

		if (raw_only || (s_rc == 0 && tgid_check == (int)pid)) {
			/* Case A: LD_PRELOAD readdir cloak or LKM /proc readdir cloak while /proc/<pid> exists */
			usleep(200);
			if (!proc_readdir_has_pid(pid) &&
			    (kill((pid_t)pid, 0) == 0 || errno == EPERM)) {
				char dirbuf[64];

				snprintf(dirbuf, sizeof(dirbuf), "/proc/%ld", pid);
				if (stat(dirbuf, &st) == 0 &&
				    (raw_only || read_tgid_from_status(pbuf) == (int)pid)) {
					if (!hidden_first)
						putchar(',');
					hidden_first = 0;
					hidden_count++;
					printf("\n      {\"pid\": %ld, \"stat_ok\": 1, \"tgid\": %d, \"raw_only\": %d}",
					       pid, tgid_check, raw_only ? 1 : 0);
				}
			}
		} else if (s_rc != 0 && s_err == ENOENT) {
			/* Skip Case B for unprivileged scans under hidepid=1/2 where /proc/<other-uid> returns ENOENT */
			if (hidepid && euid != 0 && k_rc != 0)
				continue;
			/* Case B: Hooked BOTH readdir AND /proc/<pid>/status ENOENT while kill(pid,0) succeeds */
			usleep(200);
			if (!proc_readdir_has_pid(pid) &&
			    (kill((pid_t)pid, 0) == 0 || errno == EPERM)) {
				struct stat st2;
				int s_rc2;

				errno = 0;
				s_rc2 = stat(pbuf, &st2);
				if (s_rc2 != 0 && errno == ENOENT) {
					if (!hidden_first)
						putchar(',');
					hidden_first = 0;
					hidden_count++;
					printf("\n      {\"pid\": %ld, \"stat_ok\": 0, \"tgid\": -1, \"raw_only\": 0}",
					       pid);
				}
			}
		}
	}
	printf("\n    ],\n");
	printf("    \"hidden_count\": %u\n", hidden_count);
	printf("  }");
	free(seen_raw);
	free(seen);
}

static ssize_t read_all_fd(int fd, uint8_t *buf, size_t cap)
{
	size_t total = 0;

	while (total < cap) {
		ssize_t r = read(fd, buf + total, cap - total);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (r == 0)
			break;
		total += (size_t)r;
	}
	return (ssize_t)total;
}

static void emit_pci_extended_section(void)
{
	DIR *d = opendir("/sys/bus/pci/devices");
	struct dirent *de;
	int first = 1;

	printf("  \"pci_ext\": [");
	if (d) {
		while ((de = readdir(d)) != NULL) {
			char cfg_path[320];
			uint8_t cfg[4096];
			ssize_t nread;
			int fd;
			int path_len;
			uint16_t vid, did, cmd, status;
			uint8_t cap_pos, hops = 0;
			int cap_loop = 0;
			int ext_cap_loop = 0;
			uint16_t ext_pos = 0x100;
			uint16_t ext_caps[32];
			int ext_cnt = 0;
			int ec;

			if (de->d_name[0] == '.')
				continue;
			path_len = snprintf(cfg_path, sizeof(cfg_path),
					    "/sys/bus/pci/devices/%s/config", de->d_name);
			if (path_len < 0 || (size_t)path_len >= sizeof(cfg_path))
				continue;
			fd = open(cfg_path, O_RDONLY | O_CLOEXEC);
			if (fd < 0)
				continue;

			memset(cfg, 0, sizeof(cfg));
			nread = read_all_fd(fd, cfg, sizeof(cfg));
			close(fd);
			if (nread < 64)
				continue;

			memcpy(&vid, cfg + 0x00, 2);
			memcpy(&did, cfg + 0x02, 2);
			memcpy(&cmd, cfg + 0x04, 2);
			memcpy(&status, cfg + 0x06, 2);

			/* Skip config capability walking if device is powered down in D3cold (all-ones) */
			if (vid != 0xffffU && status != 0xffffU && (status & 0x10U)) {
				uint8_t cap_visited[64] = { 0 };

				cap_pos = (uint8_t)(cfg[0x34] & 0xfc);
				while (cap_pos >= 0x40 && (size_t)cap_pos + 1 < (size_t)nread && hops < 48) {
					uint8_t cap_id = cfg[cap_pos];
					uint8_t next_pos = (uint8_t)(cfg[cap_pos + 1] & 0xfc);
					unsigned int slot = cap_pos >> 2;

					if (cap_id == 0xffU)
						break;
					if (cap_visited[slot] || next_pos == cap_pos) {
						cap_loop = 1;
						break;
					}
					cap_visited[slot] = 1;
					cap_pos = next_pos;
					hops++;
				}
				if (hops >= 48)
					cap_loop = 1;
			}

			/* Walk PCIe Extended Capabilities (offsets 0x100..0xFFC) */
			if (vid != 0xffffU && nread >= 0x104) {
				uint8_t ext_visited[120] = { 0 }; /* covers (0x100..0xffc) >> 2 */
				int e_hops = 0;

				while (ext_pos >= 0x100 && (size_t)ext_pos + 4 <= (size_t)nread && e_hops < 64) {
					uint32_t hdr = 0;
					uint16_t ec_id, ec_next;
					unsigned int eslot = (unsigned int)(ext_pos - 0x100U) >> 2;

					if (eslot >= 960U)
						break;
					if (ext_visited[eslot >> 3] & (uint8_t)(1U << (eslot & 7U))) {
						ext_cap_loop = 1;
						break;
					}
					ext_visited[eslot >> 3] |= (uint8_t)(1U << (eslot & 7U));

					memcpy(&hdr, cfg + ext_pos, 4);
					if (hdr == 0 || hdr == 0xffffffffU)
						break;
					ec_id = (uint16_t)(hdr & 0xffffU);
					ec_next = (uint16_t)((hdr >> 20) & 0xffcU);
					if (ext_cnt < 32)
						ext_caps[ext_cnt++] = ec_id;
					if (ec_next == 0)
						break;
					if (ec_next == ext_pos || ec_next < 0x100U) {
						ext_cap_loop = 1;
						break;
					}
					ext_pos = ec_next;
					e_hops++;
				}
				if (e_hops >= 64)
					ext_cap_loop = 1;
			}

			if (!first)
				putchar(',');
			first = 0;
			printf("\n    {\"bdf\": ");
			print_json_str(de->d_name);
			printf(", \"cfg_bytes\": %zd, \"vid\": \"0x%04x\", \"did\": \"0x%04x\", \"cmd\": \"0x%04x\", \"cap_loop\": %d, \"ext_cap_loop\": %d, \"ext_cap_ids\": [",
			       nread, vid, did, cmd, cap_loop, ext_cap_loop);
			for (ec = 0; ec < ext_cnt; ec++)
				printf("%s%u", ec ? "," : "", ext_caps[ec]);
			printf("]}");
		}
		closedir(d);
	}
	printf("\n  ]");
}

int main(int argc, char **argv)
{
	const char *mode = (argc > 1) ? argv[1] : "all";

	if (strcmp(mode, "bpf-dump") == 0 || strcmp(mode, "bpf_dump") == 0) {
		printf("{\n");
		emit_bpf_section();
		printf("\n}\n");
		free_vmlinux_btf();
		return 0;
	}
	if (strcmp(mode, "pid-cross") == 0 || strcmp(mode, "pid_cross") == 0) {
		printf("{\n");
		emit_pid_cross_section();
		printf("\n}\n");
		free_vmlinux_btf();
		return 0;
	}
	if (strcmp(mode, "pci-dump") == 0 || strcmp(mode, "pci_dump") == 0) {
		printf("{\n");
		emit_pci_extended_section();
		printf("\n}\n");
		free_vmlinux_btf();
		return 0;
	}

	printf("{\n");
	emit_bpf_section();
	printf(",\n");
	emit_pid_cross_section();
	printf(",\n");
	emit_pci_extended_section();
	printf("\n}\n");
	free_vmlinux_btf();
	return 0;
}
