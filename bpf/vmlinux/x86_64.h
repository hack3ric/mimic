#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

enum show_regs_mode {
	SHOW_REGS_SHORT = 0,
	SHOW_REGS_USER = 1,
	SHOW_REGS_ALL = 2,
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

enum writeback_sync_modes {
	WB_SYNC_NONE = 0,
	WB_SYNC_ALL = 1,
};

enum memory_type {
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_COHERENT = 2,
	MEMORY_DEVICE_FS_DAX = 3,
	MEMORY_DEVICE_GENERIC = 4,
	MEMORY_DEVICE_PCI_P2PDMA = 5,
};

enum fault_flag {
	FAULT_FLAG_WRITE = 1,
	FAULT_FLAG_MKWRITE = 2,
	FAULT_FLAG_ALLOW_RETRY = 4,
	FAULT_FLAG_RETRY_NOWAIT = 8,
	FAULT_FLAG_KILLABLE = 16,
	FAULT_FLAG_TRIED = 32,
	FAULT_FLAG_USER = 64,
	FAULT_FLAG_REMOTE = 128,
	FAULT_FLAG_INSTRUCTION = 256,
	FAULT_FLAG_INTERRUPTIBLE = 512,
	FAULT_FLAG_UNSHARE = 1024,
	FAULT_FLAG_ORIG_PTE_VALID = 2048,
	FAULT_FLAG_VMA_LOCK = 4096,
};

enum migrate_mode {
	MIGRATE_ASYNC = 0,
	MIGRATE_SYNC_LIGHT = 1,
	MIGRATE_SYNC = 2,
	MIGRATE_SYNC_NO_COPY = 3,
};

enum freeze_holder {
	FREEZE_HOLDER_KERNEL = 1,
	FREEZE_HOLDER_USERSPACE = 2,
	FREEZE_MAY_NEST = 4,
};

enum quota_type {
	USRQUOTA = 0,
	GRPQUOTA = 1,
	PRJQUOTA = 2,
};

enum kobj_ns_type {
	KOBJ_NS_TYPE_NONE = 0,
	KOBJ_NS_TYPE_NET = 1,
	KOBJ_NS_TYPES = 2,
};

enum probe_type {
	PROBE_DEFAULT_STRATEGY = 0,
	PROBE_PREFER_ASYNCHRONOUS = 1,
	PROBE_FORCE_SYNCHRONOUS = 2,
};

enum dl_dev_state {
	DL_DEV_NO_DRIVER = 0,
	DL_DEV_PROBING = 1,
	DL_DEV_DRIVER_BOUND = 2,
	DL_DEV_UNBINDING = 3,
};

enum dev_dma_attr {
	DEV_DMA_NOT_SUPPORTED = 0,
	DEV_DMA_NON_COHERENT = 1,
	DEV_DMA_COHERENT = 2,
};

enum device_physical_location_panel {
	DEVICE_PANEL_TOP = 0,
	DEVICE_PANEL_BOTTOM = 1,
	DEVICE_PANEL_LEFT = 2,
	DEVICE_PANEL_RIGHT = 3,
	DEVICE_PANEL_FRONT = 4,
	DEVICE_PANEL_BACK = 5,
	DEVICE_PANEL_UNKNOWN = 6,
};

enum device_physical_location_vertical_position {
	DEVICE_VERT_POS_UPPER = 0,
	DEVICE_VERT_POS_CENTER = 1,
	DEVICE_VERT_POS_LOWER = 2,
};

enum device_physical_location_horizontal_position {
	DEVICE_HORI_POS_LEFT = 0,
	DEVICE_HORI_POS_CENTER = 1,
	DEVICE_HORI_POS_RIGHT = 2,
};

enum device_removable {
	DEVICE_REMOVABLE_NOT_SUPPORTED = 0,
	DEVICE_REMOVABLE_UNKNOWN = 1,
	DEVICE_FIXED = 2,
	DEVICE_REMOVABLE = 3,
};

enum wb_reason {
	WB_REASON_BACKGROUND = 0,
	WB_REASON_VMSCAN = 1,
	WB_REASON_SYNC = 2,
	WB_REASON_PERIODIC = 3,
	WB_REASON_LAPTOP_TIMER = 4,
	WB_REASON_FS_FREE_SPACE = 5,
	WB_REASON_FORKER_THREAD = 6,
	WB_REASON_FOREIGN_FLUSH = 7,
	WB_REASON_MAX = 8,
};

enum d_real_type {
	D_REAL_DATA = 0,
	D_REAL_METADATA = 1,
};

enum rw_hint {
	WRITE_LIFE_NOT_SET = 0,
	WRITE_LIFE_NONE = 1,
	WRITE_LIFE_SHORT = 2,
	WRITE_LIFE_MEDIUM = 3,
	WRITE_LIFE_LONG = 4,
	WRITE_LIFE_EXTREME = 5,
} __attribute__((mode(byte)));

enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};

enum timespec_type {
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};

enum perf_event_state {
	PERF_EVENT_STATE_DEAD = -4,
	PERF_EVENT_STATE_EXIT = -3,
	PERF_EVENT_STATE_ERROR = -2,
	PERF_EVENT_STATE_OFF = -1,
	PERF_EVENT_STATE_INACTIVE = 0,
	PERF_EVENT_STATE_ACTIVE = 1,
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC = 0,
	BPF_PROG_TYPE_SOCKET_FILTER = 1,
	BPF_PROG_TYPE_KPROBE = 2,
	BPF_PROG_TYPE_SCHED_CLS = 3,
	BPF_PROG_TYPE_SCHED_ACT = 4,
	BPF_PROG_TYPE_TRACEPOINT = 5,
	BPF_PROG_TYPE_XDP = 6,
	BPF_PROG_TYPE_PERF_EVENT = 7,
	BPF_PROG_TYPE_CGROUP_SKB = 8,
	BPF_PROG_TYPE_CGROUP_SOCK = 9,
	BPF_PROG_TYPE_LWT_IN = 10,
	BPF_PROG_TYPE_LWT_OUT = 11,
	BPF_PROG_TYPE_LWT_XMIT = 12,
	BPF_PROG_TYPE_SOCK_OPS = 13,
	BPF_PROG_TYPE_SK_SKB = 14,
	BPF_PROG_TYPE_CGROUP_DEVICE = 15,
	BPF_PROG_TYPE_SK_MSG = 16,
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
	BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
	BPF_PROG_TYPE_LIRC_MODE2 = 20,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_TRACING = 26,
	BPF_PROG_TYPE_STRUCT_OPS = 27,
	BPF_PROG_TYPE_EXT = 28,
	BPF_PROG_TYPE_LSM = 29,
	BPF_PROG_TYPE_SK_LOOKUP = 30,
	BPF_PROG_TYPE_SYSCALL = 31,
	BPF_PROG_TYPE_NETFILTER = 32,
	__MAX_BPF_PROG_TYPE = 33,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS = 0,
	BPF_CGROUP_INET_EGRESS = 1,
	BPF_CGROUP_INET_SOCK_CREATE = 2,
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_SKB_STREAM_PARSER = 4,
	BPF_SK_SKB_STREAM_VERDICT = 5,
	BPF_CGROUP_DEVICE = 6,
	BPF_SK_MSG_VERDICT = 7,
	BPF_CGROUP_INET4_BIND = 8,
	BPF_CGROUP_INET6_BIND = 9,
	BPF_CGROUP_INET4_CONNECT = 10,
	BPF_CGROUP_INET6_CONNECT = 11,
	BPF_CGROUP_INET4_POST_BIND = 12,
	BPF_CGROUP_INET6_POST_BIND = 13,
	BPF_CGROUP_UDP4_SENDMSG = 14,
	BPF_CGROUP_UDP6_SENDMSG = 15,
	BPF_LIRC_MODE2 = 16,
	BPF_FLOW_DISSECTOR = 17,
	BPF_CGROUP_SYSCTL = 18,
	BPF_CGROUP_UDP4_RECVMSG = 19,
	BPF_CGROUP_UDP6_RECVMSG = 20,
	BPF_CGROUP_GETSOCKOPT = 21,
	BPF_CGROUP_SETSOCKOPT = 22,
	BPF_TRACE_RAW_TP = 23,
	BPF_TRACE_FENTRY = 24,
	BPF_TRACE_FEXIT = 25,
	BPF_MODIFY_RETURN = 26,
	BPF_LSM_MAC = 27,
	BPF_TRACE_ITER = 28,
	BPF_CGROUP_INET4_GETPEERNAME = 29,
	BPF_CGROUP_INET6_GETPEERNAME = 30,
	BPF_CGROUP_INET4_GETSOCKNAME = 31,
	BPF_CGROUP_INET6_GETSOCKNAME = 32,
	BPF_XDP_DEVMAP = 33,
	BPF_CGROUP_INET_SOCK_RELEASE = 34,
	BPF_XDP_CPUMAP = 35,
	BPF_SK_LOOKUP = 36,
	BPF_XDP = 37,
	BPF_SK_SKB_VERDICT = 38,
	BPF_SK_REUSEPORT_SELECT = 39,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40,
	BPF_PERF_EVENT = 41,
	BPF_TRACE_KPROBE_MULTI = 42,
	BPF_LSM_CGROUP = 43,
	BPF_STRUCT_OPS = 44,
	BPF_NETFILTER = 45,
	BPF_TCX_INGRESS = 46,
	BPF_TCX_EGRESS = 47,
	BPF_TRACE_UPROBE_MULTI = 48,
	BPF_CGROUP_UNIX_CONNECT = 49,
	BPF_CGROUP_UNIX_SENDMSG = 50,
	BPF_CGROUP_UNIX_RECVMSG = 51,
	BPF_CGROUP_UNIX_GETPEERNAME = 52,
	BPF_CGROUP_UNIX_GETSOCKNAME = 53,
	BPF_NETKIT_PRIMARY = 54,
	BPF_NETKIT_PEER = 55,
	__MAX_BPF_ATTACH_TYPE = 56,
};

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE = 1,
	PTR_TO_CTX = 2,
	CONST_PTR_TO_MAP = 3,
	PTR_TO_MAP_VALUE = 4,
	PTR_TO_MAP_KEY = 5,
	PTR_TO_STACK = 6,
	PTR_TO_PACKET_META = 7,
	PTR_TO_PACKET = 8,
	PTR_TO_PACKET_END = 9,
	PTR_TO_FLOW_KEYS = 10,
	PTR_TO_SOCKET = 11,
	PTR_TO_SOCK_COMMON = 12,
	PTR_TO_TCP_SOCK = 13,
	PTR_TO_TP_BUFFER = 14,
	PTR_TO_XDP_SOCK = 15,
	PTR_TO_BTF_ID = 16,
	PTR_TO_MEM = 17,
	PTR_TO_ARENA = 18,
	PTR_TO_BUF = 19,
	PTR_TO_FUNC = 20,
	CONST_PTR_TO_DYNPTR = 21,
	__BPF_REG_TYPE_MAX = 22,
	PTR_TO_MAP_VALUE_OR_NULL = 260,
	PTR_TO_SOCKET_OR_NULL = 267,
	PTR_TO_SOCK_COMMON_OR_NULL = 268,
	PTR_TO_TCP_SOCK_OR_NULL = 269,
	PTR_TO_BTF_ID_OR_NULL = 272,
	__BPF_REG_TYPE_LIMIT = 33554431,
};

enum bpf_cgroup_iter_order {
	BPF_CGROUP_ITER_ORDER_UNSPEC = 0,
	BPF_CGROUP_ITER_SELF_ONLY = 1,
	BPF_CGROUP_ITER_DESCENDANTS_PRE = 2,
	BPF_CGROUP_ITER_DESCENDANTS_POST = 3,
	BPF_CGROUP_ITER_ANCESTORS_UP = 4,
};

enum bpf_iter_task_type {
	BPF_TASK_ITER_ALL = 0,
	BPF_TASK_ITER_TID = 1,
	BPF_TASK_ITER_TGID = 2,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED = 21,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
	BPF_MAP_TYPE_ARENA = 33,
	__MAX_BPF_MAP_TYPE = 34,
};

enum btf_field_type {
	BPF_SPIN_LOCK = 1,
	BPF_TIMER = 2,
	BPF_KPTR_UNREF = 4,
	BPF_KPTR_REF = 8,
	BPF_KPTR_PERCPU = 16,
	BPF_KPTR = 28,
	BPF_LIST_HEAD = 32,
	BPF_LIST_NODE = 64,
	BPF_RB_ROOT = 128,
	BPF_RB_NODE = 256,
	BPF_GRAPH_NODE = 320,
	BPF_GRAPH_ROOT = 160,
	BPF_REFCOUNT = 512,
};

enum {
	UNAME26 = 131072,
	ADDR_NO_RANDOMIZE = 262144,
	FDPIC_FUNCPTRS = 524288,
	MMAP_PAGE_ZERO = 1048576,
	ADDR_COMPAT_LAYOUT = 2097152,
	READ_IMPLIES_EXEC = 4194304,
	ADDR_LIMIT_32BIT = 8388608,
	SHORT_INODE = 16777216,
	WHOLE_SECONDS = 33554432,
	STICKY_TIMEOUTS = 67108864,
	ADDR_LIMIT_3GB = 134217728,
};

enum which_selector {
	FS = 0,
	GS = 1,
};

enum {
	false = 0,
	true = 1,
};

typedef unsigned int __u32;

typedef __u32 u32;

struct thread_info {
	unsigned long flags;
	unsigned long syscall_work;
	u32 status;
};

typedef struct {
	int counter;
} atomic_t;

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct load_weight {
	unsigned long weight;
	u32 inv_weight;
};

struct rb_node {
	unsigned long __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

typedef unsigned long long __u64;

typedef __u64 u64;

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

typedef long long __s64;

typedef __s64 s64;

struct sched_entity {
	struct load_weight load;
	struct rb_node run_node;
	u64 deadline;
	u64 min_vruntime;
	struct list_head group_node;
	unsigned int on_rq;
	u64 exec_start;
	u64 sum_exec_runtime;
	u64 prev_sum_exec_runtime;
	u64 vruntime;
	s64 vlag;
	u64 slice;
	u64 nr_migrations;
};

struct sched_rt_entity {
	struct list_head run_list;
	unsigned long timeout;
	unsigned long watchdog_stamp;
	unsigned int time_slice;
	unsigned short on_rq;
	unsigned short on_list;
	struct sched_rt_entity *back;
};

typedef s64 ktime_t;

struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};

typedef unsigned char __u8;

typedef __u8 u8;

struct hrtimer_clock_base;

struct hrtimer {
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
};

typedef _Bool bool;

struct sched_dl_entity;

typedef bool (*dl_server_has_tasks_f)(struct sched_dl_entity *);

struct task_struct;

typedef struct task_struct * (*dl_server_pick_f)(struct sched_dl_entity *);

struct rq;

struct sched_dl_entity {
	struct rb_node rb_node;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled: 1;
	unsigned int dl_yielded: 1;
	unsigned int dl_non_contending: 1;
	unsigned int dl_overrun: 1;
	unsigned int dl_server: 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
	struct rq *rq;
	dl_server_has_tasks_f server_has_tasks;
	dl_server_pick_f server_pick;
};

struct sched_statistics {};

struct cpumask {
	unsigned long bits[1];
};

typedef struct cpumask cpumask_t;

union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_hint;
		u8 need_mb;
	} b;
	u32 s;
};

struct sched_info {};

typedef int __kernel_clockid_t;

typedef __kernel_clockid_t clockid_t;

struct __kernel_timespec;

struct old_timespec32;

struct pollfd;

struct restart_block {
	unsigned long arch_data;
	long (*fn)(struct restart_block *);
	union {
		struct {
			u32 __attribute__((btf_type_tag("user"))) *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 __attribute__((btf_type_tag("user"))) *uaddr2;
		} futex;
		struct {
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct __kernel_timespec __attribute__((btf_type_tag("user"))) *rmtp;
				struct old_timespec32 __attribute__((btf_type_tag("user"))) *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct {
			struct pollfd __attribute__((btf_type_tag("user"))) *ufds;
			int nfds;
			int has_timeout;
			unsigned long tv_sec;
			unsigned long tv_nsec;
		} poll;
	};
};

typedef int __kernel_pid_t;

typedef __kernel_pid_t pid_t;

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

typedef struct {} arch_spinlock_t;

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

typedef struct raw_spinlock raw_spinlock_t;

struct prev_cputime {
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};

struct posix_cputimers {};

typedef struct {
	unsigned long sig[1];
} sigset_t;

struct sigpending {
	struct list_head list;
	sigset_t signal;
};

typedef unsigned long __kernel_ulong_t;

typedef __kernel_ulong_t __kernel_size_t;

typedef __kernel_size_t size_t;

struct seccomp {};

struct syscall_user_dispatch {
	char __attribute__((btf_type_tag("user"))) *selector;
	unsigned long offset;
	unsigned long len;
	bool on_dispatch;
};

struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};

typedef struct spinlock spinlock_t;

struct wake_q_node {
	struct wake_q_node *next;
};

struct task_io_accounting {};

typedef struct {
	s64 counter;
} atomic64_t;

typedef atomic64_t atomic_long_t;

struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct arch_tlbflush_unmap_batch {
	struct cpumask cpumask;
};

struct tlbflush_unmap_batch {
	struct arch_tlbflush_unmap_batch arch;
	bool flush_required;
	bool writable;
};

struct page;

struct page_frag {
	struct page *page;
	__u32 offset;
	__u32 size;
};

struct kmap_ctrl {};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

struct timer_list {
	struct hlist_node entry;
	unsigned long expires;
	void (*function)(struct timer_list *);
	u32 flags;
};

typedef unsigned short __u16;

typedef __u16 u16;

struct desc_struct {
	u16 limit0;
	u16 base0;
	u16 base1: 8;
	u16 type: 4;
	u16 s: 1;
	u16 dpl: 2;
	u16 p: 1;
	u16 limit1: 4;
	u16 avl: 1;
	u16 l: 1;
	u16 d: 1;
	u16 g: 1;
	u16 base2: 8;
};

struct fpu_state_perm {
	u64 __state_perm;
	unsigned int __state_size;
	unsigned int __user_state_size;
};

struct fregs_state {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u32 status;
};

struct fxregs_state {
	u16 cwd;
	u16 swd;
	u16 twd;
	u16 fop;
	union {
		struct {
			u64 rip;
			u64 rdp;
		};
		struct {
			u32 fip;
			u32 fcs;
			u32 foo;
			u32 fos;
		};
	};
	u32 mxcsr;
	u32 mxcsr_mask;
	u32 st_space[32];
	u32 xmm_space[64];
	u32 padding[12];
	union {
		u32 padding1[12];
		u32 sw_reserved[12];
	};
};

struct math_emu_info;

struct swregs_state {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
	u8 ftop;
	u8 changed;
	u8 lookahead;
	u8 no_update;
	u8 rm;
	u8 alimit;
	struct math_emu_info *info;
	u32 entry_eip;
};

struct xstate_header {
	u64 xfeatures;
	u64 xcomp_bv;
	u64 reserved[6];
};

struct xregs_state {
	struct fxregs_state i387;
	struct xstate_header header;
	u8 extended_state_area[0];
};

union fpregs_state {
	struct fregs_state fsave;
	struct fxregs_state fxsave;
	struct swregs_state soft;
	struct xregs_state xsave;
	u8 __padding[4096];
};

struct fpstate {
	unsigned int size;
	unsigned int user_size;
	u64 xfeatures;
	u64 user_xfeatures;
	u64 xfd;
	unsigned int is_valloc: 1;
	unsigned int is_guest: 1;
	unsigned int is_confidential: 1;
	unsigned int in_use: 1;
	long: 64;
	long: 64;
	long: 64;
	union fpregs_state regs;
};

struct fpu {
	unsigned int last_cpu;
	unsigned long avx512_timestamp;
	struct fpstate *fpstate;
	struct fpstate *__task_fpstate;
	struct fpu_state_perm perm;
	struct fpu_state_perm guest_perm;
	struct fpstate __fpstate;
};

struct perf_event;

struct io_bitmap;

struct thread_struct {
	struct desc_struct tls_array[3];
	unsigned long sp;
	unsigned short es;
	unsigned short ds;
	unsigned short fsindex;
	unsigned short gsindex;
	unsigned long fsbase;
	unsigned long gsbase;
	struct perf_event *ptrace_bps[4];
	unsigned long virtual_dr6;
	unsigned long ptrace_dr7;
	unsigned long cr2;
	unsigned long trap_nr;
	unsigned long error_code;
	struct io_bitmap *io_bitmap;
	unsigned long iopl_emul;
	unsigned int iopl_warn: 1;
	u32 pkru;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct fpu fpu;
};

struct sched_class;

struct mm_struct;

struct address_space;

struct pid;

struct completion;

struct cred;

struct nameidata;

struct fs_struct;

struct files_struct;

struct nsproxy;

struct signal_struct;

struct sighand_struct;

struct bio_list;

struct blk_plug;

struct reclaim_state;

struct io_context;

struct kernel_siginfo;

typedef struct kernel_siginfo kernel_siginfo_t;

struct perf_event_context;

struct pipe_inode_info;

struct vm_struct;

struct bpf_local_storage;

struct bpf_run_ctx;

struct task_struct {
	struct thread_info thread_info;
	unsigned int __state;
	unsigned int saved_state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	struct sched_dl_entity *dl_server;
	const struct sched_class *sched_class;
	struct sched_statistics stats;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	unsigned short migration_flags;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct address_space *faults_disabled_mapping;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	unsigned long jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	long: 29;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int reported_split_lock: 1;
	unsigned long atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	struct task_struct __attribute__((btf_type_tag("rcu"))) *real_parent;
	struct task_struct __attribute__((btf_type_tag("rcu"))) *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_node;
	struct completion *vfork_done;
	int __attribute__((btf_type_tag("user"))) *set_child_tid;
	int __attribute__((btf_type_tag("user"))) *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	unsigned long nvcsw;
	unsigned long nivcsw;
	u64 start_time;
	u64 start_boottime;
	unsigned long min_flt;
	unsigned long maj_flt;
	struct posix_cputimers posix_cputimers;
	const struct cred __attribute__((btf_type_tag("rcu"))) *ptracer_cred;
	const struct cred __attribute__((btf_type_tag("rcu"))) *real_cred;
	const struct cred __attribute__((btf_type_tag("rcu"))) *cred;
	char comm[16];
	struct nameidata *nameidata;
	struct fs_struct *fs;
	struct files_struct *files;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct __attribute__((btf_type_tag("rcu"))) *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	unsigned long sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct io_context *io_context;
	unsigned long ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	struct perf_event_context *perf_event_ctxp;
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	struct tlbflush_unmap_batch tlb_ubc;
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	int nr_dirtied;
	int nr_dirtied_pause;
	unsigned long dirty_paused_when;
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	struct kmap_ctrl kmap_ctrl;
	struct callback_head rcu;
	refcount_t rcu_users;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct *stack_vm_area;
	refcount_t stack_refcount;
	struct bpf_local_storage __attribute__((btf_type_tag("rcu"))) *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	struct callback_head l1d_flush_kill;
	long: 64;
	long: 64;
	long: 64;
	struct thread_struct thread;
};

struct seqcount {
	unsigned int sequence;
};

typedef struct seqcount seqcount_t;

struct seqcount_raw_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;

struct rb_root {
	struct rb_node *rb_node;
};

struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

struct timerqueue_head {
	struct rb_root_cached rb_root;
};

struct hrtimer_cpu_base;

struct hrtimer_clock_base {
	struct hrtimer_cpu_base *cpu_base;
	unsigned int index;
	clockid_t clockid;
	seqcount_raw_spinlock_t seq;
	struct hrtimer *running;
	struct timerqueue_head active;
	ktime_t (*get_time)();
	ktime_t offset;
};

struct hrtimer_cpu_base {
	raw_spinlock_t lock;
	unsigned int cpu;
	unsigned int active_bases;
	unsigned int clock_was_set_seq;
	unsigned int hres_active: 1;
	unsigned int in_hrtirq: 1;
	unsigned int hang_detected: 1;
	unsigned int softirq_activated: 1;
	unsigned int online: 1;
	ktime_t expires_next;
	struct hrtimer *next_timer;
	ktime_t softirq_expires_next;
	struct hrtimer *softirq_next_timer;
	long: 64;
	long: 64;
	struct hrtimer_clock_base clock_base[8];
};

struct sched_class {
	void (*enqueue_task)(struct rq *, struct task_struct *, int);
	void (*dequeue_task)(struct rq *, struct task_struct *, int);
	void (*yield_task)(struct rq *);
	bool (*yield_to_task)(struct rq *, struct task_struct *);
	void (*wakeup_preempt)(struct rq *, struct task_struct *, int);
	struct task_struct * (*pick_next_task)(struct rq *);
	void (*put_prev_task)(struct rq *, struct task_struct *);
	void (*set_next_task)(struct rq *, struct task_struct *, bool);
	void (*task_tick)(struct rq *, struct task_struct *, int);
	void (*task_fork)(struct task_struct *);
	void (*task_dead)(struct task_struct *);
	void (*switched_from)(struct rq *, struct task_struct *);
	void (*switched_to)(struct rq *, struct task_struct *);
	void (*prio_changed)(struct rq *, struct task_struct *, int);
	unsigned int (*get_rr_interval)(struct rq *, struct task_struct *);
	void (*update_curr)(struct rq *);
};

typedef struct {} lockdep_map_p;

struct maple_tree {
	union {
		spinlock_t ma_lock;
		lockdep_map_p ma_external_lock;
	};
	unsigned int ma_flags;
	void __attribute__((btf_type_tag("rcu"))) *ma_root;
};

typedef unsigned long pgdval_t;

typedef struct {
	pgdval_t pgd;
} pgd_t;

struct rw_semaphore {
	atomic_long_t count;
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct percpu_counter {
	s64 count;
};

typedef short __s16;

typedef __s16 s16;

struct vdso_image;

typedef struct {
	u64 ctx_id;
	atomic64_t tlb_gen;
	unsigned long flags;
	struct mutex lock;
	void __attribute__((btf_type_tag("user"))) *vdso;
	const struct vdso_image *vdso_image;
	atomic_t perf_rdpmc_allowed;
	u16 pkey_allocation_map;
	s16 execute_only_pkey;
} mm_context_t;

struct uprobes_state {};

struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
};

struct file;

struct linux_binfmt;

struct user_namespace;

struct mm_struct {
	struct {
		struct {
			atomic_t mm_count;
		};
		struct maple_tree mm_mt;
		unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
		unsigned long mmap_base;
		unsigned long mmap_legacy_base;
		unsigned long task_size;
		pgd_t *pgd;
		atomic_t mm_users;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		unsigned long hiwater_rss;
		unsigned long hiwater_vm;
		unsigned long total_vm;
		unsigned long locked_vm;
		atomic64_t pinned_vm;
		unsigned long data_vm;
		unsigned long exec_vm;
		unsigned long stack_vm;
		unsigned long def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		unsigned long start_code;
		unsigned long end_code;
		unsigned long start_data;
		unsigned long end_data;
		unsigned long start_brk;
		unsigned long brk;
		unsigned long start_stack;
		unsigned long arg_start;
		unsigned long arg_end;
		unsigned long env_start;
		unsigned long env_end;
		unsigned long saved_auxv[50];
		struct percpu_counter rss_stat[4];
		struct linux_binfmt *binfmt;
		mm_context_t context;
		unsigned long flags;
		struct user_namespace *user_ns;
		struct file __attribute__((btf_type_tag("rcu"))) *exe_file;
		atomic_t tlb_flush_pending;
		atomic_t tlb_flush_batched;
		struct uprobes_state uprobes_state;
		struct work_struct async_put_work;
	};
	unsigned long cpu_bitmap[0];
};

struct llist_node {
	struct llist_node *next;
};

typedef unsigned int fmode_t;

typedef long long __kernel_loff_t;

typedef __kernel_loff_t loff_t;

typedef struct {} arch_rwlock_t;

typedef struct {
	arch_rwlock_t raw_lock;
} rwlock_t;

typedef unsigned int __kernel_uid32_t;

typedef __kernel_uid32_t uid_t;

typedef struct {
	uid_t val;
} kuid_t;

struct fown_struct {
	rwlock_t lock;
	struct pid *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

struct file_ra_state {
	unsigned long start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	loff_t prev_pos;
};

struct vfsmount;

struct dentry;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

typedef u32 errseq_t;

struct inode;

struct file_operations;

struct file {
	union {
		struct callback_head f_task_work;
		struct llist_node f_llist;
		unsigned int f_iocb_flags;
	};
	spinlock_t f_lock;
	fmode_t f_mode;
	atomic_long_t f_count;
	struct mutex f_pos_lock;
	loff_t f_pos;
	unsigned int f_flags;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	struct path f_path;
	struct inode *f_inode;
	const struct file_operations *f_op;
	u64 f_version;
	void *private_data;
	struct address_space *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct hlist_head {
	struct hlist_node *first;
};

struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};

typedef struct wait_queue_head wait_queue_head_t;

struct pid_namespace;

struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct pid {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct dentry *stashed;
	u64 ino;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid numbers[0];
};

struct hlist_bl_node {
	struct hlist_bl_node *next;
	struct hlist_bl_node **pprev;
};

struct seqcount_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

struct lockref {
	union {
		struct {
			spinlock_t lock;
			int count;
		};
	};
};

struct dentry_operations;

struct super_block;

struct dentry {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	unsigned char d_iname[40];
	struct lockref d_lockref;
	const struct dentry_operations *d_op;
	struct super_block *d_sb;
	unsigned long d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct hlist_node d_sib;
	struct hlist_head d_children;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

typedef unsigned short umode_t;

typedef unsigned int __kernel_gid32_t;

typedef __kernel_gid32_t gid_t;

typedef struct {
	gid_t val;
} kgid_t;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

typedef __s64 time64_t;

struct timespec64 {
	time64_t tv_sec;
	long tv_nsec;
};

typedef u64 blkcnt_t;

typedef unsigned int gfp_t;

struct xarray {
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void __attribute__((btf_type_tag("rcu"))) *xa_head;
};

struct address_space_operations;

struct address_space {
	struct inode *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	unsigned long nrpages;
	unsigned long writeback_index;
	const struct address_space_operations *a_ops;
	unsigned long flags;
	errseq_t wb_err;
	spinlock_t i_private_lock;
	struct list_head i_private_list;
	struct rw_semaphore i_mmap_rwsem;
	void *i_private_data;
};

struct inode_operations;

struct file_lock_context;

struct cdev;

struct inode {
	umode_t i_mode;
	unsigned short i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	unsigned long i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 __i_atime;
	struct timespec64 __i_mtime;
	struct timespec64 __i_ctime;
	spinlock_t i_lock;
	unsigned short i_bytes;
	u8 i_blkbits;
	enum rw_hint i_write_hint;
	blkcnt_t i_blocks;
	unsigned long i_state;
	struct rw_semaphore i_rwsem;
	unsigned long dirtied_when;
	unsigned long dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	union {
		const struct file_operations *i_fop;
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	void *i_private;
};

typedef long __kernel_long_t;

typedef __kernel_long_t __kernel_ssize_t;

typedef __kernel_ssize_t ssize_t;

struct delayed_call;

struct mnt_idmap;

struct posix_acl;

struct iattr;

struct kstat;

struct fiemap_extent_info;

struct fileattr;

struct offset_ctx;

struct inode_operations {
	struct dentry * (*lookup)(struct inode *, struct dentry *, unsigned int);
	const char * (*get_link)(struct dentry *, struct inode *, struct delayed_call *);
	int (*permission)(struct mnt_idmap *, struct inode *, int);
	struct posix_acl * (*get_inode_acl)(struct inode *, int, bool);
	int (*readlink)(struct dentry *, char __attribute__((btf_type_tag("user"))) *, int);
	int (*create)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, bool);
	int (*link)(struct dentry *, struct inode *, struct dentry *);
	int (*unlink)(struct inode *, struct dentry *);
	int (*symlink)(struct mnt_idmap *, struct inode *, struct dentry *, const char *);
	int (*mkdir)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
	int (*rmdir)(struct inode *, struct dentry *);
	int (*mknod)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, dev_t);
	int (*rename)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int);
	int (*setattr)(struct mnt_idmap *, struct dentry *, struct iattr *);
	int (*getattr)(struct mnt_idmap *, const struct path *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode *, int);
	int (*atomic_open)(struct inode *, struct dentry *, struct file *, unsigned int, umode_t);
	int (*tmpfile)(struct mnt_idmap *, struct inode *, struct file *, umode_t);
	struct posix_acl * (*get_acl)(struct mnt_idmap *, struct dentry *, int);
	int (*set_acl)(struct mnt_idmap *, struct dentry *, struct posix_acl *, int);
	int (*fileattr_set)(struct mnt_idmap *, struct dentry *, struct fileattr *);
	int (*fileattr_get)(struct dentry *, struct fileattr *);
	struct offset_ctx * (*get_offset_ctx)(struct inode *);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct delayed_call {
	void (*fn)(void *);
	void *arg;
};

typedef struct {
	uid_t val;
} vfsuid_t;

typedef struct {
	gid_t val;
} vfsgid_t;

struct iattr {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file *ia_file;
};

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
	int mnt_flags;
	struct mnt_idmap *mnt_idmap;
};

struct hlist_bl_head {
	struct hlist_bl_node *first;
};

struct mtd_info;

typedef long long qsize_t;

struct quota_format_type;

struct mem_dqinfo {
	struct quota_format_type *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	unsigned long dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops;

struct quota_info {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode *files[3];
	struct mem_dqinfo info[3];
	const struct quota_format_ops *ops[3];
};

struct rcu_sync {
	int gp_state;
	int gp_count;
	wait_queue_head_t gp_wait;
	struct callback_head cb_head;
};

struct rcuwait {
	struct task_struct __attribute__((btf_type_tag("rcu"))) *task;
};

struct percpu_rw_semaphore {
	struct rcu_sync rss;
	unsigned int __attribute__((btf_type_tag("percpu"))) *read_count;
	struct rcuwait writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers {
	unsigned short frozen;
	int freeze_kcount;
	int freeze_ucount;
	struct percpu_rw_semaphore rw_sem[3];
};

typedef struct {
	__u8 b[16];
} uuid_t;

struct list_lru_node;

struct list_lru {
	struct list_lru_node *node;
};

struct file_system_type;

struct super_operations;

struct dquot_operations;

struct quotactl_ops;

struct export_operations;

struct xattr_handler;

struct block_device;

struct backing_dev_info;

struct shrinker;

struct workqueue_struct;

struct super_block {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	unsigned long s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type *s_type;
	const struct super_operations *s_op;
	const struct dquot_operations *dq_op;
	const struct quotactl_ops *s_qcop;
	const struct export_operations *s_export_op;
	unsigned long s_flags;
	unsigned long s_iflags;
	unsigned long s_magic;
	struct dentry *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	const struct xattr_handler * const *s_xattr;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device *s_bdev;
	struct file *s_bdev_file;
	struct backing_dev_info *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info s_dquot;
	struct sb_writers s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	char s_id[32];
	uuid_t s_uuid;
	u8 s_uuid_len;
	char s_sysfs_name[37];
	unsigned int s_max_links;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations *s_d_op;
	struct shrinker *s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
};

struct module;

struct lock_class_key {};

struct fs_context;

struct fs_parameter_spec;

struct file_system_type {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry * (*mount)(struct file_system_type *, int, const char *, void *);
	void (*kill_sb)(struct super_block *);
	struct module *owner;
	struct file_system_type *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct p_log;

struct fs_parameter;

struct fs_parse_result;

typedef int fs_param_type(struct p_log *, const struct fs_parameter_spec *, struct fs_parameter *, struct fs_parse_result *);

struct fs_parameter_spec {
	const char *name;
	fs_param_type *type;
	u8 opt;
	unsigned short flags;
	const void *data;
};

struct writeback_control;

struct kstatfs;

struct seq_file;

struct shrink_control;

struct super_operations {
	struct inode * (*alloc_inode)(struct super_block *);
	void (*destroy_inode)(struct inode *);
	void (*free_inode)(struct inode *);
	void (*dirty_inode)(struct inode *, int);
	int (*write_inode)(struct inode *, struct writeback_control *);
	int (*drop_inode)(struct inode *);
	void (*evict_inode)(struct inode *);
	void (*put_super)(struct super_block *);
	int (*sync_fs)(struct super_block *, int);
	int (*freeze_super)(struct super_block *, enum freeze_holder);
	int (*freeze_fs)(struct super_block *);
	int (*thaw_super)(struct super_block *, enum freeze_holder);
	int (*unfreeze_fs)(struct super_block *);
	int (*statfs)(struct dentry *, struct kstatfs *);
	int (*remount_fs)(struct super_block *, int *, char *);
	void (*umount_begin)(struct super_block *);
	int (*show_options)(struct seq_file *, struct dentry *);
	int (*show_devname)(struct seq_file *, struct dentry *);
	int (*show_path)(struct seq_file *, struct dentry *);
	int (*show_stats)(struct seq_file *, struct dentry *);
	long (*nr_cached_objects)(struct super_block *, struct shrink_control *);
	long (*free_cached_objects)(struct super_block *, struct shrink_control *);
	void (*shutdown)(struct super_block *);
};

struct swap_iocb;

struct folio;

struct folio_batch {
	unsigned char nr;
	unsigned char i;
	bool percpu_pvec_drained;
	struct folio *folios[31];
};

struct writeback_control {
	long nr_to_write;
	long pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_netfs_wb: 1;
	unsigned int no_cgroup_owner: 1;
	struct swap_iocb **swap_plug;
	struct folio_batch fbatch;
	unsigned long index;
	int saved_err;
};

typedef struct {
	unsigned long val;
} swp_entry_t;

struct page_pool;

struct dev_pagemap;

struct page {
	unsigned long flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space *mapping;
			union {
				unsigned long index;
				unsigned long share;
			};
			unsigned long private;
		};
		struct {
			unsigned long pp_magic;
			struct page_pool *pp;
			unsigned long _pp_mapping_pad;
			unsigned long dma_addr;
			atomic_long_t pp_ref_count;
		};
		struct {
			unsigned long compound_head;
		};
		struct {
			struct dev_pagemap *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long: 64;
};

struct folio {
	union {
		struct {
			unsigned long flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			unsigned long index;
			union {
				void *private;
				swp_entry_t swap;
			};
			atomic_t _mapcount;
			atomic_t _refcount;
		};
		struct page page;
	};
	union {
		struct {
			unsigned long _flags_1;
			unsigned long _head_1;
			unsigned long _folio_avail;
			atomic_t _entire_mapcount;
			atomic_t _nr_pages_mapped;
			atomic_t _pincount;
			unsigned int _folio_nr_pages;
		};
		struct page __page_1;
	};
	union {
		struct {
			unsigned long _flags_2;
			unsigned long _head_2;
			void *_hugetlb_subpool;
			void *_hugetlb_cgroup;
			void *_hugetlb_cgroup_rsvd;
			void *_hugetlb_hwpoison;
		};
		struct {
			unsigned long _flags_2a;
			unsigned long _head_2a;
			struct list_head _deferred_list;
		};
		struct page __page_2;
	};
};

typedef u64 sector_t;

struct readahead_control;

struct kiocb;

struct iov_iter;

struct swap_info_struct;

struct address_space_operations {
	int (*writepage)(struct page *, struct writeback_control *);
	int (*read_folio)(struct file *, struct folio *);
	int (*writepages)(struct address_space *, struct writeback_control *);
	bool (*dirty_folio)(struct address_space *, struct folio *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file *, struct address_space *, loff_t, unsigned int, struct page **, void **);
	int (*write_end)(struct file *, struct address_space *, loff_t, unsigned int, unsigned int, struct page *, void *);
	sector_t (*bmap)(struct address_space *, sector_t);
	void (*invalidate_folio)(struct folio *, size_t, size_t);
	bool (*release_folio)(struct folio *, gfp_t);
	void (*free_folio)(struct folio *);
	ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *);
	int (*migrate_folio)(struct address_space *, struct folio *, struct folio *, enum migrate_mode);
	int (*launder_folio)(struct folio *);
	bool (*is_partially_uptodate)(struct folio *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio *, bool *, bool *);
	int (*error_remove_folio)(struct address_space *, struct folio *);
	int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
	void (*swap_deactivate)(struct file *);
	int (*swap_rw)(struct kiocb *, struct iov_iter *);
};

struct range {
	u64 start;
	u64 end;
};

struct vmem_altmap {
	unsigned long base_pfn;
	const unsigned long end_pfn;
	const unsigned long reserve;
	unsigned long free;
	unsigned long align;
	unsigned long alloc;
	bool inaccessible;
};

struct percpu_ref_data;

struct percpu_ref {
	unsigned long percpu_count_ptr;
	struct percpu_ref_data *data;
};

struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};

struct dev_pagemap_ops;

struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	unsigned long vmemmap_shift;
	const struct dev_pagemap_ops *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct {
			struct {} __empty_ranges;
			struct range ranges[0];
		};
	};
};

typedef void percpu_ref_func_t(struct percpu_ref *);

struct percpu_ref_data {
	atomic_long_t count;
	percpu_ref_func_t *release;
	percpu_ref_func_t *confirm_switch;
	bool force_atomic: 1;
	bool allow_reinit: 1;
	struct callback_head rcu;
	struct percpu_ref *ref;
};

typedef unsigned int vm_fault_t;

struct vm_fault;

struct dev_pagemap_ops {
	void (*page_free)(struct page *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault *);
	int (*memory_failure)(struct dev_pagemap *, unsigned long, unsigned long, int);
};

typedef unsigned long pteval_t;

typedef struct {
	pteval_t pte;
} pte_t;

typedef unsigned long pmdval_t;

typedef struct {
	pmdval_t pmd;
} pmd_t;

typedef unsigned long pudval_t;

typedef struct {
	pudval_t pud;
} pud_t;

typedef struct page *pgtable_t;

struct vm_area_struct;

struct vm_fault {
	struct {
		struct vm_area_struct *vma;
		gfp_t gfp_mask;
		unsigned long pgoff;
		unsigned long address;
		unsigned long real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page *cow_page;
	struct page *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t prealloc_pte;
};

typedef unsigned long vm_flags_t;

typedef unsigned long pgprotval_t;

struct pgprot {
	pgprotval_t pgprot;
};

typedef struct pgprot pgprot_t;

struct vm_userfaultfd_ctx {};

struct anon_vma;

struct vm_operations_struct;

struct vm_area_struct {
	union {
		struct {
			unsigned long vm_start;
			unsigned long vm_end;
		};
	};
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	union {
		const vm_flags_t vm_flags;
		vm_flags_t __vm_flags;
	};
	struct {
		struct rb_node rb;
		unsigned long rb_subtree_last;
	} shared;
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	unsigned long vm_pgoff;
	struct file *vm_file;
	void *vm_private_data;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct vm_operations_struct {
	void (*open)(struct vm_area_struct *);
	void (*close)(struct vm_area_struct *);
	int (*may_split)(struct vm_area_struct *, unsigned long);
	int (*mremap)(struct vm_area_struct *);
	int (*mprotect)(struct vm_area_struct *, unsigned long, unsigned long, unsigned long);
	vm_fault_t (*fault)(struct vm_fault *);
	vm_fault_t (*huge_fault)(struct vm_fault *, unsigned int);
	vm_fault_t (*map_pages)(struct vm_fault *, unsigned long, unsigned long);
	unsigned long (*pagesize)(struct vm_area_struct *);
	vm_fault_t (*page_mkwrite)(struct vm_fault *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *);
	int (*access)(struct vm_area_struct *, unsigned long, void *, int, int);
	const char * (*name)(struct vm_area_struct *);
	struct page * (*find_special_page)(struct vm_area_struct *, unsigned long);
};

struct wait_page_queue;

struct kiocb {
	struct file *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb *, long);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	union {
		struct wait_page_queue *ki_waitq;
		ssize_t (*dio_complete)(void *);
	};
};

struct seq_operations;

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

struct seq_operations {
	void * (*start)(struct seq_file *, loff_t *);
	void (*stop)(struct seq_file *, void *);
	void * (*next)(struct seq_file *, void *, loff_t *);
	int (*show)(struct seq_file *, void *);
};

struct mem_cgroup;

struct shrink_control {
	gfp_t gfp_mask;
	int nid;
	unsigned long nr_to_scan;
	unsigned long nr_scanned;
	struct mem_cgroup *memcg;
};

typedef __kernel_uid32_t projid_t;

typedef struct {
	projid_t val;
} kprojid_t;

struct dquot;

struct kqid;

struct dquot_operations {
	int (*write_dquot)(struct dquot *);
	struct dquot * (*alloc_dquot)(struct super_block *, int);
	void (*destroy_dquot)(struct dquot *);
	int (*acquire_dquot)(struct dquot *);
	int (*release_dquot)(struct dquot *);
	int (*mark_dirty)(struct dquot *);
	int (*write_info)(struct super_block *, int);
	qsize_t * (*get_reserved_space)(struct inode *);
	int (*get_projid)(struct inode *, kprojid_t *);
	int (*get_inode_usage)(struct inode *, qsize_t *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct kqid {
	union {
		kuid_t uid;
		kgid_t gid;
		kprojid_t projid;
	};
	enum quota_type type;
};

struct mem_dqblk {
	qsize_t dqb_bhardlimit;
	qsize_t dqb_bsoftlimit;
	qsize_t dqb_curspace;
	qsize_t dqb_rsvspace;
	qsize_t dqb_ihardlimit;
	qsize_t dqb_isoftlimit;
	qsize_t dqb_curinodes;
	time64_t dqb_btime;
	time64_t dqb_itime;
};

struct dquot {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	unsigned long dq_flags;
	struct mem_dqblk dq_dqb;
};

struct qc_info;

struct qc_dqblk;

struct qc_state;

struct quotactl_ops {
	int (*quota_on)(struct super_block *, int, int, const struct path *);
	int (*quota_off)(struct super_block *, int);
	int (*quota_enable)(struct super_block *, unsigned int);
	int (*quota_disable)(struct super_block *, unsigned int);
	int (*quota_sync)(struct super_block *, int);
	int (*set_info)(struct super_block *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block *, struct qc_state *);
	int (*rm_xquota)(struct super_block *, unsigned int);
};

struct qc_info {
	int i_fieldmask;
	unsigned int i_flags;
	unsigned int i_spc_timelimit;
	unsigned int i_ino_timelimit;
	unsigned int i_rt_spc_timelimit;
	unsigned int i_spc_warnlimit;
	unsigned int i_ino_warnlimit;
	unsigned int i_rt_spc_warnlimit;
};

struct qc_dqblk {
	int d_fieldmask;
	u64 d_spc_hardlimit;
	u64 d_spc_softlimit;
	u64 d_ino_hardlimit;
	u64 d_ino_softlimit;
	u64 d_space;
	u64 d_ino_count;
	s64 d_ino_timer;
	s64 d_spc_timer;
	int d_ino_warns;
	int d_spc_warns;
	u64 d_rt_spc_hardlimit;
	u64 d_rt_spc_softlimit;
	u64 d_rt_space;
	s64 d_rt_spc_timer;
	int d_rt_spc_warns;
};

struct qc_type_state {
	unsigned int flags;
	unsigned int spc_timelimit;
	unsigned int ino_timelimit;
	unsigned int rt_spc_timelimit;
	unsigned int spc_warnlimit;
	unsigned int ino_warnlimit;
	unsigned int rt_spc_warnlimit;
	unsigned long long ino;
	blkcnt_t blocks;
	blkcnt_t nextents;
};

struct qc_state {
	unsigned int s_incoredqs;
	struct qc_type_state s_state[3];
};

struct iomap;

struct fid;

struct export_operations {
	int (*encode_fh)(struct inode *, __u32 *, int *, struct inode *);
	struct dentry * (*fh_to_dentry)(struct super_block *, struct fid *, int, int);
	struct dentry * (*fh_to_parent)(struct super_block *, struct fid *, int, int);
	int (*get_name)(struct dentry *, char *, struct dentry *);
	struct dentry * (*get_parent)(struct dentry *);
	int (*commit_metadata)(struct inode *);
	int (*get_uuid)(struct super_block *, u8 *, u32 *, u64 *);
	int (*map_blocks)(struct inode *, loff_t, u64, struct iomap *, bool, u32 *);
	int (*commit_blocks)(struct inode *, struct iomap *, int, struct iattr *);
	unsigned long flags;
};

struct xattr_handler {
	const char *name;
	const char *prefix;
	int flags;
	bool (*list)(struct dentry *);
	int (*get)(const struct xattr_handler *, struct dentry *, struct inode *, const char *, void *, size_t);
	int (*set)(const struct xattr_handler *, struct mnt_idmap *, struct dentry *, struct inode *, const char *, const void *, size_t, int);
};

struct disk_stats;

struct kref {
	refcount_t refcount;
};

struct kset;

struct kobj_type;

struct kernfs_node;

struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	const struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct dev_links_info {
	struct list_head suppliers;
	struct list_head consumers;
	struct list_head defer_sync;
	enum dl_dev_state status;
};

struct pm_message {
	int event;
};

typedef struct pm_message pm_message_t;

typedef int __s32;

typedef __s32 s32;

struct pm_subsys_data;

struct device;

struct dev_pm_qos;

struct dev_pm_info {
	pm_message_t power_state;
	bool can_wakeup: 1;
	bool async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	bool should_wakeup: 1;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device *, s32);
	struct dev_pm_qos *qos;
};

struct dev_msi_info {};

struct dev_archdata {};

struct dev_iommu;

struct device_private;

struct device_type;

struct bus_type;

struct device_driver;

struct dev_pm_domain;

struct bus_dma_region;

struct device_dma_parameters;

struct io_tlb_mem;

struct device_node;

struct fwnode_handle;

struct class;

struct attribute_group;

struct iommu_group;

struct device_physical_location;

struct device {
	struct kobject kobj;
	struct device *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type *type;
	const struct bus_type *bus;
	struct device_driver *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info power;
	struct dev_pm_domain *pm_domain;
	struct dev_msi_info msi;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	const struct class *class;
	const struct attribute_group **groups;
	void (*release)(struct device *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
};

struct gendisk;

struct request_queue;

struct blk_holder_ops;

struct partition_meta_info;

struct block_device {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	struct disk_stats __attribute__((btf_type_tag("percpu"))) *bd_stats;
	unsigned long bd_stamp;
	bool bd_read_only;
	u8 bd_partno;
	bool bd_write_holder;
	bool bd_has_submit_bio;
	dev_t bd_dev;
	struct inode *bd_inode;
	atomic_t bd_openers;
	spinlock_t bd_size_lock;
	void *bd_claiming;
	void *bd_holder;
	const struct blk_holder_ops *bd_holder_ops;
	struct mutex bd_holder_lock;
	int bd_holders;
	struct kobject *bd_holder_dir;
	atomic_t bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct partition_meta_info *bd_meta_info;
	bool bd_ro_warned;
	int bd_writers;
	struct device bd_device;
};

struct blk_holder_ops {
	void (*mark_dead)(struct block_device *, bool);
	void (*sync)(struct block_device *);
	int (*freeze)(struct block_device *);
	int (*thaw)(struct block_device *);
};

struct kset_uevent_ops;

struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
	const struct kset_uevent_ops *uevent_ops;
};

struct kobj_uevent_env;

struct kset_uevent_ops {
	int (* const filter)(const struct kobject *);
	const char * (* const name)(const struct kobject *);
	int (* const uevent)(const struct kobject *, struct kobj_uevent_env *);
};

struct kobj_uevent_env {
	char *argv[3];
	char *envp[64];
	int envp_idx;
	char buf[2048];
	int buflen;
};

struct sysfs_ops;

struct kobj_ns_type_operations;

struct kobj_type {
	void (*release)(struct kobject *);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations * (*child_ns_type)(const struct kobject *);
	const void * (*namespace)(const struct kobject *);
	void (*get_ownership)(const struct kobject *, kuid_t *, kgid_t *);
};

struct attribute;

struct sysfs_ops {
	ssize_t (*show)(struct kobject *, struct attribute *, char *);
	ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};

struct attribute {
	const char *name;
	umode_t mode;
};

struct bin_attribute;

struct attribute_group {
	const char *name;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int);
	struct attribute **attrs;
	struct bin_attribute **bin_attrs;
};

struct bin_attribute {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space * (*f_mapping)();
	ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	ssize_t (*write)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	loff_t (*llseek)(struct file *, struct kobject *, struct bin_attribute *, loff_t, int);
	int (*mmap)(struct file *, struct kobject *, struct bin_attribute *, struct vm_area_struct *);
};

struct sock;

struct kobj_ns_type_operations {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct kernfs_root;

struct kernfs_elem_dir {
	unsigned long subdirs;
	struct rb_root children;
	struct kernfs_root *root;
	unsigned long rev;
};

struct kernfs_elem_symlink {
	struct kernfs_node *target_kn;
};

struct kernfs_open_node;

struct kernfs_ops;

struct kernfs_elem_attr {
	const struct kernfs_ops *ops;
	struct kernfs_open_node __attribute__((btf_type_tag("rcu"))) *open;
	loff_t size;
	struct kernfs_node *notify_next;
};

struct kernfs_iattrs;

struct kernfs_node {
	atomic_t count;
	atomic_t active;
	struct kernfs_node *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	unsigned short flags;
	umode_t mode;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink symlink;
		struct kernfs_elem_attr attr;
	};
	u64 id;
	void *priv;
	struct kernfs_iattrs *iattr;
	struct callback_head rcu;
};

typedef unsigned int __poll_t;

struct kernfs_open_file;

struct poll_table_struct;

struct kernfs_ops {
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	ssize_t (*read)(struct kernfs_open_file *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
	int (*mmap)(struct kernfs_open_file *, struct vm_area_struct *);
	loff_t (*llseek)(struct kernfs_open_file *, loff_t, int);
};

struct kernfs_open_file {
	struct kernfs_node *kn;
	struct file *file;
	struct seq_file *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct *vm_ops;
};

typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
};

struct dev_pm_ops;

struct device_type {
	const char *name;
	const struct attribute_group **groups;
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device *);
	const struct dev_pm_ops *pm;
};

struct dev_pm_ops {
	int (*prepare)(struct device *);
	void (*complete)(struct device *);
	int (*suspend)(struct device *);
	int (*resume)(struct device *);
	int (*freeze)(struct device *);
	int (*thaw)(struct device *);
	int (*poweroff)(struct device *);
	int (*restore)(struct device *);
	int (*suspend_late)(struct device *);
	int (*resume_early)(struct device *);
	int (*freeze_late)(struct device *);
	int (*thaw_early)(struct device *);
	int (*poweroff_late)(struct device *);
	int (*restore_early)(struct device *);
	int (*suspend_noirq)(struct device *);
	int (*resume_noirq)(struct device *);
	int (*freeze_noirq)(struct device *);
	int (*thaw_noirq)(struct device *);
	int (*poweroff_noirq)(struct device *);
	int (*restore_noirq)(struct device *);
	int (*runtime_suspend)(struct device *);
	int (*runtime_resume)(struct device *);
	int (*runtime_idle)(struct device *);
};

struct bus_type {
	const char *name;
	const char *dev_name;
	const struct attribute_group **bus_groups;
	const struct attribute_group **dev_groups;
	const struct attribute_group **drv_groups;
	int (*match)(struct device *, struct device_driver *);
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	void (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*online)(struct device *);
	int (*offline)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	int (*num_vf)(struct device *);
	int (*dma_configure)(struct device *);
	void (*dma_cleanup)(struct device *);
	const struct dev_pm_ops *pm;
	bool need_parent_lock;
};

struct of_device_id;

struct acpi_device_id;

struct driver_private;

struct device_driver {
	const char *name;
	const struct bus_type *bus;
	struct module *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	int (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	const struct dev_pm_ops *pm;
	void (*coredump)(struct device *);
	struct driver_private *p;
};

struct of_device_id {
	char name[32];
	char type[32];
	char compatible[128];
	const void *data;
};

typedef unsigned long kernel_ulong_t;

struct acpi_device_id {
	__u8 id[16];
	kernel_ulong_t driver_data;
	__u32 cls;
	__u32 cls_msk;
};

struct pm_subsys_data {
	spinlock_t lock;
	unsigned int refcount;
};

struct dev_pm_domain {
	struct dev_pm_ops ops;
	int (*start)(struct device *);
	void (*detach)(struct device *, bool);
	int (*activate)(struct device *);
	void (*sync)(struct device *);
	void (*dismiss)(struct device *);
	int (*set_performance_state)(struct device *, unsigned int);
};

typedef u64 phys_addr_t;

typedef u64 dma_addr_t;

struct bus_dma_region {
	phys_addr_t cpu_start;
	dma_addr_t dma_start;
	u64 size;
};

struct device_dma_parameters {
	unsigned int max_segment_size;
	unsigned int min_align_mask;
	unsigned long segment_boundary_mask;
};

typedef u32 phandle;

struct fwnode_operations;

struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct property;

struct device_node {
	const char *name;
	phandle phandle;
	const char *full_name;
	struct fwnode_handle fwnode;
	struct property *properties;
	struct property *deadprops;
	struct device_node *parent;
	struct device_node *child;
	struct device_node *sibling;
	unsigned long _flags;
	void *data;
};

struct fwnode_reference_args;

struct fwnode_endpoint;

struct fwnode_operations {
	struct fwnode_handle * (*get)(struct fwnode_handle *);
	void (*put)(struct fwnode_handle *);
	bool (*device_is_available)(const struct fwnode_handle *);
	const void * (*device_get_match_data)(const struct fwnode_handle *, const struct device *);
	bool (*device_dma_supported)(const struct fwnode_handle *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle *);
	bool (*property_present)(const struct fwnode_handle *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle *);
	const char * (*get_name_prefix)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_parent)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_next_child_node)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*get_named_child_node)(const struct fwnode_handle *, const char *);
	int (*get_reference_args)(const struct fwnode_handle *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args *);
	struct fwnode_handle * (*graph_get_next_endpoint)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_remote_endpoint)(const struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_port_parent)(struct fwnode_handle *);
	int (*graph_parse_endpoint)(const struct fwnode_handle *, struct fwnode_endpoint *);
	void * (*iomap)(struct fwnode_handle *, int);
	int (*irq_get)(const struct fwnode_handle *, unsigned int);
	int (*add_links)(struct fwnode_handle *);
};

struct fwnode_reference_args {
	struct fwnode_handle *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct fwnode_endpoint {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle *local_fwnode;
};

struct property {
	char *name;
	int length;
	void *value;
	struct property *next;
};

struct class {
	const char *name;
	const struct attribute_group **class_groups;
	const struct attribute_group **dev_groups;
	int (*dev_uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *);
	void (*class_release)(const struct class *);
	void (*dev_release)(struct device *);
	int (*shutdown_pre)(struct device *);
	const struct kobj_ns_type_operations *ns_type;
	const void * (*namespace)(const struct device *);
	void (*get_ownership)(const struct device *, kuid_t *, kgid_t *);
	const struct dev_pm_ops *pm;
};

struct iommu_group {};

struct device_physical_location {
	enum device_physical_location_panel panel;
	enum device_physical_location_vertical_position vertical_position;
	enum device_physical_location_horizontal_position horizontal_position;
	bool dock;
	bool lid;
};

struct fprop_local_percpu {
	struct percpu_counter events;
	unsigned int period;
	raw_spinlock_t lock;
};

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
};

struct bdi_writeback {
	struct backing_dev_info *bdi;
	unsigned long state;
	unsigned long last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	unsigned long bw_time_stamp;
	unsigned long dirtied_stamp;
	unsigned long written_stamp;
	unsigned long write_bandwidth;
	unsigned long avg_write_bandwidth;
	unsigned long dirty_ratelimit;
	unsigned long balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	struct list_head bdi_node;
};

struct backing_dev_info {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	unsigned long ra_pages;
	unsigned long io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	unsigned long last_bdp_sleep;
	struct bdi_writeback wb;
	struct list_head wb_list;
	wait_queue_head_t wb_waitq;
	struct device *dev;
	char dev_name[64];
	struct device *owner;
	struct timer_list laptop_mode_wb_timer;
};

struct quota_format_type {
	int qf_fmt_id;
	const struct quota_format_ops *qf_ops;
	struct module *qf_owner;
	struct quota_format_type *qf_next;
};

struct quota_format_ops {
	int (*check_quota_file)(struct super_block *, int);
	int (*read_file_info)(struct super_block *, int);
	int (*write_file_info)(struct super_block *, int);
	int (*free_file_info)(struct super_block *, int);
	int (*read_dqblk)(struct dquot *);
	int (*commit_dqblk)(struct dquot *);
	int (*release_dqblk)(struct dquot *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct dentry_operations {
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	int (*d_hash)(const struct dentry *, struct qstr *);
	int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char * (*d_dname)(struct dentry *, char *, int);
	struct vfsmount * (*d_automount)(struct path *);
	int (*d_manage)(const struct path *, bool);
	struct dentry * (*d_real)(struct dentry *, enum d_real_type);
	long: 64;
	long: 64;
	long: 64;
};

struct shrinker {
	unsigned long (*count_objects)(struct shrinker *, struct shrink_control *);
	unsigned long (*scan_objects)(struct shrinker *, struct shrink_control *);
	long batch;
	int seeks;
	unsigned int flags;
	refcount_t refcount;
	struct completion done;
	struct callback_head rcu;
	void *private_data;
	struct list_head list;
	atomic_long_t *nr_deferred;
};

struct uid_gid_extent {
	u32 first;
	u32 lower_first;
	u32 count;
};

struct uid_gid_map {
	u32 nr_extents;
	union {
		struct uid_gid_extent extent[5];
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};

struct proc_ns_operations;

struct ns_common {
	struct dentry *stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	refcount_t count;
};

struct ucounts;

struct user_namespace {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	struct uid_gid_map projid_map;
	struct user_namespace *parent;
	int level;
	kuid_t owner;
	kgid_t group;
	struct ns_common ns;
	unsigned long flags;
	bool parent_could_setfcap;
	struct work_struct work;
	struct ucounts *ucounts;
	long ucount_max[8];
	long rlimit_max[4];
};

struct nsset;

struct proc_ns_operations {
	const char *name;
	const char *real_ns_name;
	int type;
	struct ns_common * (*get)(struct task_struct *);
	void (*put)(struct ns_common *);
	int (*install)(struct nsset *, struct ns_common *);
	struct user_namespace * (*owner)(struct ns_common *);
	struct ns_common * (*get_parent)(struct ns_common *);
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[8];
	atomic_long_t rlimit[4];
};

struct list_lru_one {
	struct list_head list;
	long nr_items;
};

struct list_lru_node {
	spinlock_t lock;
	struct list_lru_one lru;
	long nr_items;
};

typedef u32 uint32_t;

struct kstat {
	u32 result_mask;
	umode_t mode;
	unsigned int nlink;
	uint32_t blksize;
	u64 attributes;
	u64 attributes_mask;
	u64 ino;
	dev_t dev;
	dev_t rdev;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	struct timespec64 btime;
	u64 blocks;
	u64 mnt_id;
	u32 dio_mem_align;
	u32 dio_offset_align;
	u64 change_cookie;
};

struct offset_ctx {
	struct maple_tree mt;
	unsigned long next_offset;
};

typedef void *fl_owner_t;

struct io_uring_cmd;

struct io_comp_batch;

struct dir_context;

struct file_lock;

struct file_lease;

struct file_operations {
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char __attribute__((btf_type_tag("user"))) *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char __attribute__((btf_type_tag("user"))) *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
	int (*iterate_shared)(struct file *, struct dir_context *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
	long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
	int (*mmap)(struct file *, struct vm_area_struct *);
	unsigned long mmap_supported_flags;
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, fl_owner_t);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int);
	int (*fasync)(int, struct file *, int);
	int (*lock)(struct file *, int, struct file_lock *);
	unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*splice_eof)(struct file *);
	int (*setlease)(struct file *, int, struct file_lease **, void **);
	long (*fallocate)(struct file *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file *, struct file *);
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);

struct dir_context {
	filldir_t actor;
	loff_t pos;
};

struct idr {
	struct xarray idr_rt;
	unsigned int idr_base;
	unsigned int idr_next;
};

struct kmem_cache;

struct pid_namespace {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
};

typedef struct {
	u64 val;
} kernel_cap_t;

struct user_struct;

struct group_info;

struct cred {
	atomic_long_t usage;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
	unsigned int securebits;
	kernel_cap_t cap_inheritable;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	kernel_cap_t cap_bset;
	kernel_cap_t cap_ambient;
	struct user_struct *user;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct group_info *group_info;
	union {
		int non_rcu;
		struct callback_head rcu;
	};
};

struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	unsigned long begin;
	unsigned long flags;
};

struct user_struct {
	refcount_t __count;
	unsigned long unix_inflight;
	atomic_long_t pipe_bufs;
	struct hlist_node uidhash_node;
	kuid_t uid;
	atomic_long_t locked_vm;
	struct ratelimit_state ratelimit;
};

struct group_info {
	refcount_t usage;
	int ngroups;
	kgid_t gid[0];
};

struct vdso_image {
	void *data;
	unsigned long size;
	unsigned long alt;
	unsigned long alt_len;
	unsigned long extable_base;
	unsigned long extable_len;
	const void *extable;
	long sym_vvar_start;
	long sym_vvar_page;
	long sym_pvclock_page;
	long sym_hvclock_page;
	long sym_timens_page;
	long sym_VDSO32_NOTE_MASK;
	long sym___kernel_sigreturn;
	long sym___kernel_rt_sigreturn;
	long sym___kernel_vsyscall;
	long sym_int80_landing_pad;
	long sym_vdso32_sigreturn_landing_pad;
	long sym_vdso32_rt_sigreturn_landing_pad;
};

typedef long long __kernel_time64_t;

struct __kernel_timespec {
	__kernel_time64_t tv_sec;
	long long tv_nsec;
};

typedef s32 old_time32_t;

struct old_timespec32 {
	old_time32_t tv_sec;
	s32 tv_nsec;
};

struct pollfd {
	int fd;
	short events;
	short revents;
};

struct uts_namespace;

struct ipc_namespace;

struct mnt_namespace;

struct net;

struct time_namespace;

struct cgroup_namespace;

struct nsproxy {
	refcount_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct css_set;

struct cgroup_namespace {
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct css_set *root_cset;
};

typedef struct {
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

struct rlimit {
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
};

struct core_state;

struct tty_struct;

struct signal_struct {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct *tty;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	unsigned long nvcsw;
	unsigned long nivcsw;
	unsigned long cnvcsw;
	unsigned long cnivcsw;
	unsigned long min_flt;
	unsigned long maj_flt;
	unsigned long cmin_flt;
	unsigned long cmaj_flt;
	unsigned long inblock;
	unsigned long oublock;
	unsigned long cinblock;
	unsigned long coublock;
	unsigned long maxrss;
	unsigned long cmaxrss;
	struct task_io_accounting ioac;
	unsigned long long sum_sched_runtime;
	struct rlimit rlim[16];
	bool oom_flag_origin;
	short oom_score_adj;
	short oom_score_adj_min;
	struct mm_struct *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

typedef void __signalfn_t(int);

typedef __signalfn_t __attribute__((btf_type_tag("user"))) *__sighandler_t;

typedef void __restorefn_t();

typedef __restorefn_t __attribute__((btf_type_tag("user"))) *__sigrestore_t;

struct sigaction {
	__sighandler_t sa_handler;
	unsigned long sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;
};

struct k_sigaction {
	struct sigaction sa;
};

struct sighand_struct {
	spinlock_t siglock;
	refcount_t count;
	wait_queue_head_t signalfd_wqh;
	struct k_sigaction action[64];
};

struct io_context {
	atomic_long_t refcount;
	atomic_t active_ref;
	unsigned short ioprio;
};

typedef int __kernel_timer_t;

union sigval {
	int sival_int;
	void __attribute__((btf_type_tag("user"))) *sival_ptr;
};

typedef union sigval sigval_t;

typedef __kernel_long_t __kernel_clock_t;

union __sifields {
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
	} _kill;
	struct {
		__kernel_timer_t _tid;
		int _overrun;
		sigval_t _sigval;
		int _sys_private;
	} _timer;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		sigval_t _sigval;
	} _rt;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		int _status;
		__kernel_clock_t _utime;
		__kernel_clock_t _stime;
	} _sigchld;
	struct {
		void __attribute__((btf_type_tag("user"))) *_addr;
		union {
			int _trapno;
			short _addr_lsb;
			struct {
				char _dummy_bnd[8];
				void __attribute__((btf_type_tag("user"))) *_lower;
				void __attribute__((btf_type_tag("user"))) *_upper;
			} _addr_bnd;
			struct {
				char _dummy_pkey[8];
				__u32 _pkey;
			} _addr_pkey;
			struct {
				unsigned long _data;
				__u32 _type;
				__u32 _flags;
			} _perf;
		};
	} _sigfault;
	struct {
		long _band;
		int _fd;
	} _sigpoll;
	struct {
		void __attribute__((btf_type_tag("user"))) *_call_addr;
		int _syscall;
		unsigned int _arch;
	} _sigsys;
};

struct kernel_siginfo {
	struct {
		int si_signo;
		int si_errno;
		int si_code;
		union __sifields _sifields;
	};
};

struct perf_event_groups {
	struct rb_root tree;
	u64 index;
};

typedef struct {
	atomic_long_t a;
} local_t;

struct perf_event_context {
	raw_spinlock_t lock;
	struct mutex mutex;
	struct list_head pmu_ctx_list;
	struct perf_event_groups pinned_groups;
	struct perf_event_groups flexible_groups;
	struct list_head event_list;
	int nr_events;
	int nr_user;
	int is_active;
	int nr_task_data;
	int nr_stat;
	int nr_freq;
	int rotate_disable;
	refcount_t refcount;
	struct task_struct *task;
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	struct perf_event_context *parent_ctx;
	u64 parent_gen;
	u64 generation;
	int pin_count;
	struct callback_head callback_head;
	local_t nr_pending;
};

struct vm_struct {
	struct vm_struct *next;
	void *addr;
	unsigned long size;
	unsigned long flags;
	struct page **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct bpf_local_storage_data;

struct bpf_local_storage_map;

struct bpf_local_storage {
	struct bpf_local_storage_data __attribute__((btf_type_tag("rcu"))) *cache[16];
	struct bpf_local_storage_map __attribute__((btf_type_tag("rcu"))) *smap;
	struct hlist_head list;
	void *owner;
	struct callback_head rcu;
	raw_spinlock_t lock;
};

struct bpf_run_ctx {};

typedef struct {
	local_t a;
} local64_t;

struct perf_event_attr {
	__u32 type;
	__u32 size;
	__u64 config;
	union {
		__u64 sample_period;
		__u64 sample_freq;
	};
	__u64 sample_type;
	__u64 read_format;
	__u64 disabled: 1;
	__u64 inherit: 1;
	__u64 pinned: 1;
	__u64 exclusive: 1;
	__u64 exclude_user: 1;
	__u64 exclude_kernel: 1;
	__u64 exclude_hv: 1;
	__u64 exclude_idle: 1;
	__u64 mmap: 1;
	__u64 comm: 1;
	__u64 freq: 1;
	__u64 inherit_stat: 1;
	__u64 enable_on_exec: 1;
	__u64 task: 1;
	__u64 watermark: 1;
	__u64 precise_ip: 2;
	__u64 mmap_data: 1;
	__u64 sample_id_all: 1;
	__u64 exclude_host: 1;
	__u64 exclude_guest: 1;
	__u64 exclude_callchain_kernel: 1;
	__u64 exclude_callchain_user: 1;
	__u64 mmap2: 1;
	__u64 comm_exec: 1;
	__u64 use_clockid: 1;
	__u64 context_switch: 1;
	__u64 write_backward: 1;
	__u64 namespaces: 1;
	__u64 ksymbol: 1;
	__u64 bpf_event: 1;
	__u64 aux_output: 1;
	__u64 cgroup: 1;
	__u64 text_poke: 1;
	__u64 build_id: 1;
	__u64 inherit_thread: 1;
	__u64 remove_on_exec: 1;
	__u64 sigtrap: 1;
	__u64 __reserved_1: 26;
	union {
		__u32 wakeup_events;
		__u32 wakeup_watermark;
	};
	__u32 bp_type;
	union {
		__u64 bp_addr;
		__u64 kprobe_func;
		__u64 uprobe_path;
		__u64 config1;
	};
	union {
		__u64 bp_len;
		__u64 kprobe_addr;
		__u64 probe_offset;
		__u64 config2;
	};
	__u64 branch_sample_type;
	__u64 sample_regs_user;
	__u32 sample_stack_user;
	__s32 clockid;
	__u64 sample_regs_intr;
	__u32 aux_watermark;
	__u16 sample_max_stack;
	__u16 __reserved_2;
	__u32 aux_sample_size;
	__u32 __reserved_3;
	__u64 sig_data;
	__u64 config3;
};

struct hw_perf_event_extra {
	u64 config;
	unsigned int reg;
	int alloc;
	int idx;
};

struct arch_hw_breakpoint {
	unsigned long address;
	unsigned long mask;
	u8 len;
	u8 type;
};

struct rhash_head {
	struct rhash_head __attribute__((btf_type_tag("rcu"))) *next;
};

struct rhlist_head {
	struct rhash_head rhead;
	struct rhlist_head __attribute__((btf_type_tag("rcu"))) *next;
};

struct hw_perf_event {
	union {
		struct {
			u64 config;
			u64 last_tag;
			unsigned long config_base;
			unsigned long event_base;
			int event_base_rdpmc;
			int idx;
			int last_cpu;
			int flags;
			struct hw_perf_event_extra extra_reg;
			struct hw_perf_event_extra branch_reg;
		};
		struct {
			struct hrtimer hrtimer;
		};
		struct {
			struct list_head tp_list;
		};
		struct {
			u64 pwr_acc;
			u64 ptsc;
		};
		struct {
			struct arch_hw_breakpoint info;
			struct rhlist_head bp_list;
		};
		struct {
			u8 iommu_bank;
			u8 iommu_cntr;
			u16 padding;
			u64 conf;
			u64 conf1;
		};
	};
	struct task_struct *target;
	void *addr_filters;
	unsigned long addr_filters_gen;
	int state;
	local64_t prev_count;
	u64 sample_period;
	union {
		struct {
			u64 last_period;
			local64_t period_left;
		};
		struct {
			u64 saved_metric;
			u64 saved_slots;
		};
	};
	u64 interrupts_seq;
	u64 interrupts;
	u64 freq_time_stamp;
	u64 freq_count_stamp;
};

struct __call_single_node {
	struct llist_node llist;
	union {
		unsigned int u_flags;
		atomic_t a_flags;
	};
	u16 src;
	u16 dst;
};

struct irq_work {
	struct __call_single_node node;
	void (*func)(struct irq_work *);
	struct rcuwait irqwait;
};

struct perf_addr_filters_head {
	struct list_head list;
	raw_spinlock_t lock;
	unsigned int nr_file_filters;
};

struct perf_sample_data;

struct pt_regs;

typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *);

struct pmu;

struct perf_event_pmu_context;

struct perf_buffer;

struct fasync_struct;

struct perf_addr_filter_range;

struct bpf_prog;

struct perf_event {
	struct list_head event_entry;
	struct list_head sibling_list;
	struct list_head active_list;
	struct rb_node group_node;
	u64 group_index;
	struct list_head migrate_entry;
	struct hlist_node hlist_entry;
	struct list_head active_entry;
	int nr_siblings;
	int event_caps;
	int group_caps;
	unsigned int group_generation;
	struct perf_event *group_leader;
	struct pmu *pmu;
	void *pmu_private;
	enum perf_event_state state;
	unsigned int attach_state;
	local64_t count;
	atomic64_t child_count;
	u64 total_time_enabled;
	u64 total_time_running;
	u64 tstamp;
	struct perf_event_attr attr;
	u16 header_size;
	u16 id_header_size;
	u16 read_size;
	struct hw_perf_event hw;
	struct perf_event_context *ctx;
	struct perf_event_pmu_context *pmu_ctx;
	atomic_long_t refcount;
	atomic64_t child_total_time_enabled;
	atomic64_t child_total_time_running;
	struct mutex child_mutex;
	struct list_head child_list;
	struct perf_event *parent;
	int oncpu;
	int cpu;
	struct list_head owner_entry;
	struct task_struct *owner;
	struct mutex mmap_mutex;
	atomic_t mmap_count;
	struct perf_buffer *rb;
	struct list_head rb_entry;
	unsigned long rcu_batches;
	int rcu_pending;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
	unsigned int pending_wakeup;
	unsigned int pending_kill;
	unsigned int pending_disable;
	unsigned int pending_sigtrap;
	unsigned long pending_addr;
	struct irq_work pending_irq;
	struct callback_head pending_task;
	unsigned int pending_work;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	unsigned long addr_filters_gen;
	struct perf_event *aux_event;
	void (*destroy)(struct perf_event *);
	struct callback_head callback_head;
	struct pid_namespace *ns;
	u64 id;
	atomic64_t lost_samples;
	u64 (*clock)();
	perf_overflow_handler_t overflow_handler;
	void *overflow_handler_context;
	perf_overflow_handler_t orig_overflow_handler;
	struct bpf_prog *prog;
	u64 bpf_cookie;
	struct list_head sb_list;
	__u32 orig_type;
};

struct perf_cpu_pmu_context;

struct perf_output_handle;

struct pmu {
	struct list_head entry;
	struct module *module;
	struct device *dev;
	struct device *parent;
	const struct attribute_group **attr_groups;
	const struct attribute_group **attr_update;
	const char *name;
	int type;
	int capabilities;
	int __attribute__((btf_type_tag("percpu"))) *pmu_disable_count;
	struct perf_cpu_pmu_context __attribute__((btf_type_tag("percpu"))) *cpu_pmu_context;
	atomic_t exclusive_cnt;
	int task_ctx_nr;
	int hrtimer_interval_ms;
	unsigned int nr_addr_filters;
	void (*pmu_enable)(struct pmu *);
	void (*pmu_disable)(struct pmu *);
	int (*event_init)(struct perf_event *);
	void (*event_mapped)(struct perf_event *, struct mm_struct *);
	void (*event_unmapped)(struct perf_event *, struct mm_struct *);
	int (*add)(struct perf_event *, int);
	void (*del)(struct perf_event *, int);
	void (*start)(struct perf_event *, int);
	void (*stop)(struct perf_event *, int);
	void (*read)(struct perf_event *);
	void (*start_txn)(struct pmu *, unsigned int);
	int (*commit_txn)(struct pmu *);
	void (*cancel_txn)(struct pmu *);
	int (*event_idx)(struct perf_event *);
	void (*sched_task)(struct perf_event_pmu_context *, bool);
	struct kmem_cache *task_ctx_cache;
	void (*swap_task_ctx)(struct perf_event_pmu_context *, struct perf_event_pmu_context *);
	void * (*setup_aux)(struct perf_event *, void **, int, bool);
	void (*free_aux)(void *);
	long (*snapshot_aux)(struct perf_event *, struct perf_output_handle *, unsigned long);
	int (*addr_filters_validate)(struct list_head *);
	void (*addr_filters_sync)(struct perf_event *);
	int (*aux_output_match)(struct perf_event *);
	bool (*filter)(struct pmu *, int);
	int (*check_period)(struct perf_event *, u64);
};

struct perf_event_pmu_context {
	struct pmu *pmu;
	struct perf_event_context *ctx;
	struct list_head pmu_ctx_entry;
	struct list_head pinned_active;
	struct list_head flexible_active;
	unsigned int embedded: 1;
	unsigned int nr_events;
	unsigned int nr_cgroups;
	atomic_t refcount;
	struct callback_head callback_head;
	void *task_ctx_data;
	int rotate_necessary;
};

struct perf_cpu_pmu_context {
	struct perf_event_pmu_context epc;
	struct perf_event_pmu_context *task_epc;
	struct list_head sched_cb_entry;
	int sched_cb_usage;
	int active_oncpu;
	int exclusive;
	raw_spinlock_t hrtimer_lock;
	struct hrtimer hrtimer;
	ktime_t hrtimer_interval;
	unsigned int hrtimer_active;
};

struct perf_output_handle {
	struct perf_event *event;
	struct perf_buffer *rb;
	unsigned long wakeup;
	unsigned long size;
	u64 aux_flags;
	union {
		void *addr;
		unsigned long head;
	};
	int page;
};

struct fasync_struct {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct *fa_next;
	struct file *fa_file;
	struct callback_head fa_rcu;
};

struct perf_addr_filter_range {
	unsigned long start;
	unsigned long size;
};

union perf_sample_weight {
	__u64 full;
	struct {
		__u32 var1_dw;
		__u16 var2_w;
		__u16 var3_w;
	};
};

union perf_mem_data_src {
	__u64 val;
	struct {
		__u64 mem_op: 5;
		__u64 mem_lvl: 14;
		__u64 mem_snoop: 5;
		__u64 mem_lock: 2;
		__u64 mem_dtlb: 7;
		__u64 mem_lvl_num: 4;
		__u64 mem_remote: 1;
		__u64 mem_snoopx: 2;
		__u64 mem_blk: 3;
		__u64 mem_hops: 3;
		__u64 mem_rsvd: 18;
	};
};

struct perf_regs {
	__u64 abi;
	struct pt_regs *regs;
};

struct perf_callchain_entry;

struct perf_raw_record;

struct perf_branch_stack;

struct perf_sample_data {
	u64 sample_flags;
	u64 period;
	u64 dyn_size;
	u64 type;
	struct {
		u32 pid;
		u32 tid;
	} tid_entry;
	u64 time;
	u64 id;
	struct {
		u32 cpu;
		u32 reserved;
	} cpu_entry;
	u64 ip;
	struct perf_callchain_entry *callchain;
	struct perf_raw_record *raw;
	struct perf_branch_stack *br_stack;
	u64 *br_stack_cntr;
	union perf_sample_weight weight;
	union perf_mem_data_src data_src;
	u64 txn;
	struct perf_regs regs_user;
	struct perf_regs regs_intr;
	u64 stack_user_size;
	u64 stream_id;
	u64 cgroup;
	u64 addr;
	u64 phys_addr;
	u64 data_page_size;
	u64 code_page_size;
	u64 aux_size;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct perf_callchain_entry {
	__u64 nr;
	__u64 ip[0];
};

typedef unsigned long (*perf_copy_f)(void *, const void *, unsigned long, unsigned long);

struct perf_raw_frag {
	union {
		struct perf_raw_frag *next;
		unsigned long pad;
	};
	perf_copy_f copy;
	void *data;
	u32 size;
} __attribute__((packed));

struct perf_raw_record {
	struct perf_raw_frag frag;
	u32 size;
};

struct perf_branch_entry {
	__u64 from;
	__u64 to;
	__u64 mispred: 1;
	__u64 predicted: 1;
	__u64 in_tx: 1;
	__u64 abort: 1;
	__u64 cycles: 16;
	__u64 type: 4;
	__u64 spec: 2;
	__u64 new_type: 4;
	__u64 priv: 3;
	__u64 reserved: 31;
};

struct perf_branch_stack {
	__u64 nr;
	__u64 hw_idx;
	struct perf_branch_entry entries[0];
};

struct fred_cs {
	u64 cs: 16;
	u64 sl: 2;
	u64 wfe: 1;
};

struct fred_ss {
	u64 ss: 16;
	u64 sti: 1;
	u64 swevent: 1;
	u64 nmi: 1;
	int: 13;
	u64 vector: 8;
	short: 8;
	u64 type: 4;
	char: 4;
	u64 enclave: 1;
	u64 lm: 1;
	u64 nested: 1;
	char: 1;
	u64 insnlen: 4;
};

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	union {
		u16 cs;
		u64 csx;
		struct fred_cs fred_cs;
	};
	unsigned long flags;
	unsigned long sp;
	union {
		u16 ss;
		u64 ssx;
		struct fred_ss fred_ss;
	};
};

struct sock_filter {
	__u16 code;
	__u8 jt;
	__u8 jf;
	__u32 k;
};

struct bpf_insn {
	__u8 code;
	__u8 dst_reg: 4;
	__u8 src_reg: 4;
	__s16 off;
	__s32 imm;
};

struct bpf_prog_stats;

struct bpf_prog_aux;

struct sock_fprog_kern;

struct bpf_prog {
	u16 pages;
	u16 jited: 1;
	u16 jit_requested: 1;
	u16 gpl_compatible: 1;
	u16 cb_access: 1;
	u16 dst_needed: 1;
	u16 blinding_requested: 1;
	u16 blinded: 1;
	u16 is_func: 1;
	u16 kprobe_override: 1;
	u16 has_callchain_buf: 1;
	u16 enforce_expected_attach_type: 1;
	u16 call_get_stack: 1;
	u16 call_get_func_ip: 1;
	u16 tstamp_type_access: 1;
	u16 sleepable: 1;
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	u32 len;
	u32 jited_len;
	u8 tag[8];
	struct bpf_prog_stats __attribute__((btf_type_tag("percpu"))) *stats;
	int __attribute__((btf_type_tag("percpu"))) *active;
	unsigned int (*bpf_func)(const void *, const struct bpf_insn *);
	struct bpf_prog_aux *aux;
	struct sock_fprog_kern *orig_prog;
	union {
		struct {
			struct {} __empty_insns;
			struct sock_filter insns[0];
		};
		struct {
			struct {} __empty_insnsi;
			struct bpf_insn insnsi[0];
		};
	};
};

typedef struct {
	local64_t v;
} u64_stats_t;

struct u64_stats_sync {};

struct bpf_prog_stats {
	u64_stats_t cnt;
	u64_stats_t nsecs;
	u64_stats_t misses;
	struct u64_stats_sync syncp;
	long: 64;
};

struct latch_tree_node {
	struct rb_node node[2];
};

struct bpf_ksym {
	unsigned long start;
	unsigned long end;
	char name[512];
	struct list_head lnode;
	struct latch_tree_node tnode;
	bool prog;
};

struct btf;

struct bpf_ctx_arg_aux;

struct bpf_trampoline;

struct bpf_arena;

struct btf_type;

struct bpf_jit_poke_descriptor;

struct bpf_kfunc_desc_tab;

struct bpf_kfunc_btf_tab;

struct bpf_prog_ops;

struct bpf_map;

struct btf_mod_pair;

struct bpf_token;

struct bpf_prog_offload;

struct bpf_func_info;

struct bpf_func_info_aux;

struct bpf_line_info;

struct exception_table_entry;

struct bpf_prog_aux {
	atomic64_t refcnt;
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 max_ctx_offset;
	u32 max_pkt_offset;
	u32 max_tp_access;
	u32 stack_depth;
	u32 id;
	u32 func_cnt;
	u32 real_func_cnt;
	u32 func_idx;
	u32 attach_btf_id;
	u32 ctx_arg_info_size;
	u32 max_rdonly_access;
	u32 max_rdwr_access;
	struct btf *attach_btf;
	const struct bpf_ctx_arg_aux *ctx_arg_info;
	struct mutex dst_mutex;
	struct bpf_prog *dst_prog;
	struct bpf_trampoline *dst_trampoline;
	enum bpf_prog_type saved_dst_prog_type;
	enum bpf_attach_type saved_dst_attach_type;
	bool verifier_zext;
	bool dev_bound;
	bool offload_requested;
	bool attach_btf_trace;
	bool attach_tracing_prog;
	bool func_proto_unreliable;
	bool tail_call_reachable;
	bool xdp_has_frags;
	bool exception_cb;
	bool exception_boundary;
	struct bpf_arena *arena;
	const struct btf_type *attach_func_proto;
	const char *attach_func_name;
	struct bpf_prog **func;
	void *jit_data;
	struct bpf_jit_poke_descriptor *poke_tab;
	struct bpf_kfunc_desc_tab *kfunc_tab;
	struct bpf_kfunc_btf_tab *kfunc_btf_tab;
	u32 size_poke_tab;
	struct bpf_ksym ksym;
	const struct bpf_prog_ops *ops;
	struct bpf_map **used_maps;
	struct mutex used_maps_mutex;
	struct btf_mod_pair *used_btfs;
	struct bpf_prog *prog;
	struct user_struct *user;
	u64 load_time;
	u32 verified_insns;
	int cgroup_atype;
	struct bpf_map *cgroup_storage[2];
	char name[16];
	u64 (*bpf_exception_cb)(u64, u64, u64, u64, u64);
	struct bpf_token *token;
	struct bpf_prog_offload *offload;
	struct btf *btf;
	struct bpf_func_info *func_info;
	struct bpf_func_info_aux *func_info_aux;
	struct bpf_line_info *linfo;
	void **jited_linfo;
	u32 func_info_cnt;
	u32 nr_linfo;
	u32 linfo_idx;
	struct module *mod;
	u32 num_exentries;
	struct exception_table_entry *extable;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
};

struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	struct btf *btf;
	u32 btf_id;
};

struct btf_func_model {
	u8 ret_size;
	u8 ret_flags;
	u8 nr_args;
	u8 arg_size[12];
	u8 arg_flags[12];
};

struct ftrace_ops;

struct bpf_tramp_image;

struct bpf_trampoline {
	struct hlist_node hlist;
	struct ftrace_ops *fops;
	struct mutex mutex;
	refcount_t refcnt;
	u32 flags;
	u64 key;
	struct {
		struct btf_func_model model;
		void *addr;
		bool ftrace_managed;
	} func;
	struct bpf_prog *extension_prog;
	struct hlist_head progs_hlist[3];
	int progs_cnt[3];
	struct bpf_tramp_image *cur_image;
};

struct bpf_tramp_image {
	void *image;
	int size;
	struct bpf_ksym ksym;
	struct percpu_ref pcref;
	void *ip_after_call;
	void *ip_epilogue;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};

struct bpf_jit_poke_descriptor {
	void *tailcall_target;
	void *tailcall_bypass;
	void *bypass_addr;
	void *aux;
	union {
		struct {
			struct bpf_map *map;
			u32 key;
		} tail_call;
	};
	bool tailcall_target_stable;
	u8 adj_off;
	u16 reason;
	u32 insn_idx;
};

struct bpf_map_ops;

struct btf_record;

struct bpf_map {
	const struct bpf_map_ops *ops;
	struct bpf_map *inner_map_meta;
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u64 map_extra;
	u32 map_flags;
	u32 id;
	struct btf_record *record;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	struct btf *btf;
	char name[16];
	struct mutex freeze_mutex;
	atomic64_t refcnt;
	atomic64_t usercnt;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
	atomic64_t writecnt;
	struct {
		spinlock_t lock;
		enum bpf_prog_type type;
		bool jited;
		bool xdp_has_frags;
	} owner;
	bool bypass_spec_v1;
	bool frozen;
	bool free_after_mult_rcu_gp;
	bool free_after_rcu_gp;
	atomic64_t sleepable_refcnt;
	s64 __attribute__((btf_type_tag("percpu"))) *elem_count;
};

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

union bpf_attr;

struct bpf_verifier_env;

struct bpf_func_state;

struct bpf_iter_seq_info;

struct bpf_map_ops {
	int (*map_alloc_check)(union bpf_attr *);
	struct bpf_map * (*map_alloc)(union bpf_attr *);
	void (*map_release)(struct bpf_map *, struct file *);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *, void *, void *);
	void (*map_release_uref)(struct bpf_map *);
	void * (*map_lookup_elem_sys_only)(struct bpf_map *, void *);
	int (*map_lookup_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr __attribute__((btf_type_tag("user"))) *);
	int (*map_lookup_and_delete_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_lookup_and_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr __attribute__((btf_type_tag("user"))) *);
	int (*map_update_batch)(struct bpf_map *, struct file *, const union bpf_attr *, union bpf_attr __attribute__((btf_type_tag("user"))) *);
	int (*map_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr __attribute__((btf_type_tag("user"))) *);
	void * (*map_lookup_elem)(struct bpf_map *, void *);
	long (*map_update_elem)(struct bpf_map *, void *, void *, u64);
	long (*map_delete_elem)(struct bpf_map *, void *);
	long (*map_push_elem)(struct bpf_map *, void *, u64);
	long (*map_pop_elem)(struct bpf_map *, void *);
	long (*map_peek_elem)(struct bpf_map *, void *);
	void * (*map_lookup_percpu_elem)(struct bpf_map *, void *, u32);
	void * (*map_fd_get_ptr)(struct bpf_map *, struct file *, int);
	void (*map_fd_put_ptr)(struct bpf_map *, void *, bool);
	int (*map_gen_lookup)(struct bpf_map *, struct bpf_insn *);
	u32 (*map_fd_sys_lookup_elem)(void *);
	void (*map_seq_show_elem)(struct bpf_map *, void *, struct seq_file *);
	int (*map_check_btf)(const struct bpf_map *, const struct btf *, const struct btf_type *, const struct btf_type *);
	int (*map_poke_track)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_untrack)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_run)(struct bpf_map *, u32, struct bpf_prog *, struct bpf_prog *);
	int (*map_direct_value_addr)(const struct bpf_map *, u64 *, u32);
	int (*map_direct_value_meta)(const struct bpf_map *, u64, u32 *);
	int (*map_mmap)(struct bpf_map *, struct vm_area_struct *);
	__poll_t (*map_poll)(struct bpf_map *, struct file *, struct poll_table_struct *);
	unsigned long (*map_get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
	int (*map_local_storage_charge)(struct bpf_local_storage_map *, void *, u32);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *, void *, u32);
	struct bpf_local_storage __attribute__((btf_type_tag("rcu"))) ** (*map_owner_storage_ptr)(void *);
	long (*map_redirect)(struct bpf_map *, u64, u64);
	bool (*map_meta_equal)(const struct bpf_map *, const struct bpf_map *);
	int (*map_set_for_each_callback_args)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *);
	long (*map_for_each_callback)(struct bpf_map *, bpf_callback_t, void *, u64);
	u64 (*map_mem_usage)(const struct bpf_map *);
	int *map_btf_id;
	const struct bpf_iter_seq_info *iter_seq_info;
};

union bpf_attr {
	struct {
		__u32 map_type;
		__u32 key_size;
		__u32 value_size;
		__u32 max_entries;
		__u32 map_flags;
		__u32 inner_map_fd;
		__u32 numa_node;
		char map_name[16];
		__u32 map_ifindex;
		__u32 btf_fd;
		__u32 btf_key_type_id;
		__u32 btf_value_type_id;
		__u32 btf_vmlinux_value_type_id;
		__u64 map_extra;
		__s32 value_type_btf_obj_fd;
		__s32 map_token_fd;
	};
	struct {
		__u32 map_fd;
		__u64 key;
		union {
			__u64 value;
			__u64 next_key;
		};
		__u64 flags;
	};
	struct {
		__u64 in_batch;
		__u64 out_batch;
		__u64 keys;
		__u64 values;
		__u32 count;
		__u32 map_fd;
		__u64 elem_flags;
		__u64 flags;
	} batch;
	struct {
		__u32 prog_type;
		__u32 insn_cnt;
		__u64 insns;
		__u64 license;
		__u32 log_level;
		__u32 log_size;
		__u64 log_buf;
		__u32 kern_version;
		__u32 prog_flags;
		char prog_name[16];
		__u32 prog_ifindex;
		__u32 expected_attach_type;
		__u32 prog_btf_fd;
		__u32 func_info_rec_size;
		__u64 func_info;
		__u32 func_info_cnt;
		__u32 line_info_rec_size;
		__u64 line_info;
		__u32 line_info_cnt;
		__u32 attach_btf_id;
		union {
			__u32 attach_prog_fd;
			__u32 attach_btf_obj_fd;
		};
		__u32 core_relo_cnt;
		__u64 fd_array;
		__u64 core_relos;
		__u32 core_relo_rec_size;
		__u32 log_true_size;
		__s32 prog_token_fd;
	};
	struct {
		__u64 pathname;
		__u32 bpf_fd;
		__u32 file_flags;
		__s32 path_fd;
	};
	struct {
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_bpf_fd;
		__u32 attach_type;
		__u32 attach_flags;
		__u32 replace_bpf_fd;
		union {
			__u32 relative_fd;
			__u32 relative_id;
		};
		__u64 expected_revision;
	};
	struct {
		__u32 prog_fd;
		__u32 retval;
		__u32 data_size_in;
		__u32 data_size_out;
		__u64 data_in;
		__u64 data_out;
		__u32 repeat;
		__u32 duration;
		__u32 ctx_size_in;
		__u32 ctx_size_out;
		__u64 ctx_in;
		__u64 ctx_out;
		__u32 flags;
		__u32 cpu;
		__u32 batch_size;
	} test;
	struct {
		union {
			__u32 start_id;
			__u32 prog_id;
			__u32 map_id;
			__u32 btf_id;
			__u32 link_id;
		};
		__u32 next_id;
		__u32 open_flags;
	};
	struct {
		__u32 bpf_fd;
		__u32 info_len;
		__u64 info;
	} info;
	struct {
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 query_flags;
		__u32 attach_flags;
		__u64 prog_ids;
		union {
			__u32 prog_cnt;
			__u32 count;
		};
		__u64 prog_attach_flags;
		__u64 link_ids;
		__u64 link_attach_flags;
		__u64 revision;
	} query;
	struct {
		__u64 name;
		__u32 prog_fd;
	} raw_tracepoint;
	struct {
		__u64 btf;
		__u64 btf_log_buf;
		__u32 btf_size;
		__u32 btf_log_size;
		__u32 btf_log_level;
		__u32 btf_log_true_size;
		__u32 btf_flags;
		__s32 btf_token_fd;
	};
	struct {
		__u32 pid;
		__u32 fd;
		__u32 flags;
		__u32 buf_len;
		__u64 buf;
		__u32 prog_id;
		__u32 fd_type;
		__u64 probe_offset;
		__u64 probe_addr;
	} task_fd_query;
	struct {
		union {
			__u32 prog_fd;
			__u32 map_fd;
		};
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 flags;
		union {
			__u32 target_btf_id;
			struct {
				__u64 iter_info;
				__u32 iter_info_len;
			};
			struct {
				__u64 bpf_cookie;
			} perf_event;
			struct {
				__u32 flags;
				__u32 cnt;
				__u64 syms;
				__u64 addrs;
				__u64 cookies;
			} kprobe_multi;
			struct {
				__u32 target_btf_id;
				__u64 cookie;
			} tracing;
			struct {
				__u32 pf;
				__u32 hooknum;
				__s32 priority;
				__u32 flags;
			} netfilter;
			struct {
				union {
					__u32 relative_fd;
					__u32 relative_id;
				};
				__u64 expected_revision;
			} tcx;
			struct {
				__u64 path;
				__u64 offsets;
				__u64 ref_ctr_offsets;
				__u64 cookies;
				__u32 cnt;
				__u32 flags;
				__u32 pid;
			} uprobe_multi;
			struct {
				union {
					__u32 relative_fd;
					__u32 relative_id;
				};
				__u64 expected_revision;
			} netkit;
		};
	} link_create;
	struct {
		__u32 link_fd;
		union {
			__u32 new_prog_fd;
			__u32 new_map_fd;
		};
		__u32 flags;
		union {
			__u32 old_prog_fd;
			__u32 old_map_fd;
		};
	} link_update;
	struct {
		__u32 link_fd;
	} link_detach;
	struct {
		__u32 type;
	} enable_stats;
	struct {
		__u32 link_fd;
		__u32 flags;
	} iter_create;
	struct {
		__u32 prog_fd;
		__u32 map_fd;
		__u32 flags;
	} prog_bind_map;
	struct {
		__u32 flags;
		__u32 bpffs_fd;
	} token_create;
};

struct btf_header {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;
	__u32 type_off;
	__u32 type_len;
	__u32 str_off;
	__u32 str_len;
};

struct btf_kfunc_set_tab;

struct btf_id_dtor_kfunc_tab;

struct btf_struct_metas;

struct btf_struct_ops_tab;

struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct callback_head rcu;
	struct btf_kfunc_set_tab *kfunc_set_tab;
	struct btf_id_dtor_kfunc_tab *dtor_kfunc_tab;
	struct btf_struct_metas *struct_meta_tab;
	struct btf_struct_ops_tab *struct_ops_tab;
	struct btf *base_btf;
	u32 start_id;
	u32 start_str_off;
	char name[56];
	bool kernel_btf;
};

struct bpf_iter_aux_info;

typedef int (*bpf_iter_init_seq_priv_t)(void *, struct bpf_iter_aux_info *);

typedef void (*bpf_iter_fini_seq_priv_t)(void *);

struct bpf_iter_seq_info {
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
};

struct cgroup;

struct bpf_iter_aux_info {
	struct bpf_map *map;
	struct {
		struct cgroup *start;
		enum bpf_cgroup_iter_order order;
	} cgroup;
	struct {
		enum bpf_iter_task_type type;
		u32 pid;
	} task;
};

typedef void (*btf_dtor_kfunc_t)(void *);

struct btf_field_kptr {
	struct btf *btf;
	struct module *module;
	btf_dtor_kfunc_t dtor;
	u32 btf_id;
};

struct btf_field_graph_root {
	struct btf *btf;
	u32 value_btf_id;
	u32 node_offset;
	struct btf_record *value_rec;
};

struct btf_field {
	u32 offset;
	u32 size;
	enum btf_field_type type;
	union {
		struct btf_field_kptr kptr;
		struct btf_field_graph_root graph_root;
	};
};

struct btf_record {
	u32 cnt;
	u32 field_mask;
	int spin_lock_off;
	int timer_off;
	int refcount_off;
	struct btf_field fields[0];
};

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *, const union bpf_attr *, union bpf_attr __attribute__((btf_type_tag("user"))) *);
};

struct btf_mod_pair {
	struct btf *btf;
	struct module *module;
};

struct bpf_token {
	struct work_struct work;
	atomic64_t refcnt;
	struct user_namespace *userns;
	u64 allowed_cmds;
	u64 allowed_maps;
	u64 allowed_progs;
	u64 allowed_attachs;
};

struct bpf_offload_dev;

struct net_device;

struct bpf_prog_offload {
	struct bpf_prog *prog;
	struct net_device *netdev;
	struct bpf_offload_dev *offdev;
	void *dev_priv;
	struct list_head offloads;
	bool dev_state;
	bool opt_failed;
	void *jited_image;
	u32 jited_len;
};

struct bpf_func_info {
	__u32 insn_off;
	__u32 type_id;
};

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
	bool called: 1;
	bool verified: 1;
};

struct bpf_line_info {
	__u32 insn_off;
	__u32 file_name_off;
	__u32 line_off;
	__u32 line_col;
};

struct exception_table_entry {
	int insn;
	int fixup;
	int data;
};

struct math_emu_info {
	long ___orig_eip;
	struct pt_regs *regs;
};

typedef unsigned long uintptr_t;

struct gdt_page {
	struct desc_struct gdt[16];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct x86_init_resources {
	void (*probe_roms)();
	void (*reserve_resources)();
	char * (*memory_setup)();
	void (*dmi_setup)();
};

struct x86_init_mpparse {
	void (*setup_ioapic_ids)();
	void (*find_mptable)();
	void (*early_parse_smp_cfg)();
	void (*parse_smp_cfg)();
};

struct irq_domain;

struct x86_init_irqs {
	void (*pre_vector_init)();
	void (*intr_init)();
	void (*intr_mode_select)();
	void (*intr_mode_init)();
	struct irq_domain * (*create_pci_msi_domain)();
};

struct x86_init_oem {
	void (*arch_setup)();
	void (*banner)();
};

struct x86_init_paging {
	void (*pagetable_init)();
};

struct x86_init_timers {
	void (*setup_percpu_clockev)();
	void (*timer_init)();
	void (*wallclock_init)();
};

struct x86_init_iommu {
	int (*iommu_init)();
};

struct x86_init_pci {
	int (*arch_init)();
	int (*init)();
	void (*init_irq)();
	void (*fixup_irqs)();
};

struct x86_hyper_init {
	void (*init_platform)();
	void (*guest_late_init)();
	bool (*x2apic_available)();
	bool (*msi_ext_dest_id)();
	void (*init_mem_mapping)();
	void (*init_after_bootmem)();
};

struct x86_init_acpi {
	void (*set_root_pointer)(u64);
	u64 (*get_root_pointer)();
	void (*reduced_hw_early_init)();
};

struct x86_init_ops {
	struct x86_init_resources resources;
	struct x86_init_mpparse mpparse;
	struct x86_init_irqs irqs;
	struct x86_init_oem oem;
	struct x86_init_paging paging;
	struct x86_init_timers timers;
	struct x86_init_iommu iommu;
	struct x86_init_pci pci;
	struct x86_hyper_init hyper;
	struct x86_init_acpi acpi;
};

enum irq_domain_bus_token {
	DOMAIN_BUS_ANY = 0,
	DOMAIN_BUS_WIRED = 1,
	DOMAIN_BUS_GENERIC_MSI = 2,
	DOMAIN_BUS_PCI_MSI = 3,
	DOMAIN_BUS_PLATFORM_MSI = 4,
	DOMAIN_BUS_NEXUS = 5,
	DOMAIN_BUS_IPI = 6,
	DOMAIN_BUS_FSL_MC_MSI = 7,
	DOMAIN_BUS_TI_SCI_INTA_MSI = 8,
	DOMAIN_BUS_WAKEUP = 9,
	DOMAIN_BUS_VMD_MSI = 10,
	DOMAIN_BUS_PCI_DEVICE_MSI = 11,
	DOMAIN_BUS_PCI_DEVICE_MSIX = 12,
	DOMAIN_BUS_DMAR = 13,
	DOMAIN_BUS_AMDVI = 14,
	DOMAIN_BUS_PCI_DEVICE_IMS = 15,
	DOMAIN_BUS_DEVICE_MSI = 16,
	DOMAIN_BUS_WIRED_TO_MSI = 17,
};

typedef unsigned long irq_hw_number_t;

struct irq_domain_ops;

struct irq_domain_chip_generic;

struct irq_data;

struct irq_domain {
	struct list_head link;
	const char *name;
	const struct irq_domain_ops *ops;
	void *host_data;
	unsigned int flags;
	unsigned int mapcount;
	struct mutex mutex;
	struct irq_domain *root;
	struct fwnode_handle *fwnode;
	enum irq_domain_bus_token bus_token;
	struct irq_domain_chip_generic *gc;
	struct device *dev;
	struct device *pm_dev;
	struct irq_domain *parent;
	irq_hw_number_t hwirq_max;
	unsigned int revmap_size;
	struct xarray revmap_tree;
	struct irq_data __attribute__((btf_type_tag("rcu"))) *revmap[0];
};

struct irq_fwspec;

struct irq_domain_ops {
	int (*match)(struct irq_domain *, struct device_node *, enum irq_domain_bus_token);
	int (*select)(struct irq_domain *, struct irq_fwspec *, enum irq_domain_bus_token);
	int (*map)(struct irq_domain *, unsigned int, irq_hw_number_t);
	void (*unmap)(struct irq_domain *, unsigned int);
	int (*xlate)(struct irq_domain *, struct device_node *, const u32 *, unsigned int, unsigned long *, unsigned int *);
	int (*alloc)(struct irq_domain *, unsigned int, unsigned int, void *);
	void (*free)(struct irq_domain *, unsigned int, unsigned int);
	int (*activate)(struct irq_domain *, struct irq_data *, bool);
	void (*deactivate)(struct irq_domain *, struct irq_data *);
	int (*translate)(struct irq_domain *, struct irq_fwspec *, unsigned long *, unsigned int *);
};

struct irq_fwspec {
	struct fwnode_handle *fwnode;
	int param_count;
	u32 param[16];
};

struct irq_common_data;

struct irq_chip;

struct irq_data {
	u32 mask;
	unsigned int irq;
	irq_hw_number_t hwirq;
	struct irq_common_data *common;
	struct irq_chip *chip;
	struct irq_domain *domain;
	struct irq_data *parent_data;
	void *chip_data;
};

struct msi_desc;

struct irq_common_data {
	unsigned int state_use_accessors;
	void *handler_data;
	struct msi_desc *msi_desc;
};

struct pci_msi_desc {
	union {
		u32 msi_mask;
		u32 msix_ctrl;
	};
	struct {
		u8 is_msix: 1;
		u8 multiple: 3;
		u8 multi_cap: 3;
		u8 can_mask: 1;
		u8 is_64: 1;
		u8 is_virtual: 1;
		unsigned int default_irq;
	} msi_attrib;
	union {
		u8 mask_pos;
		void *mask_base;
	};
};

union msi_domain_cookie {
	u64 value;
	void *ptr;
	void *iobase;
};

union msi_instance_cookie {
	u64 value;
	void *ptr;
};

struct msi_desc_data {
	union msi_domain_cookie dcookie;
	union msi_instance_cookie icookie;
};

struct x86_msi_addr_lo {
	union {
		struct {
			u32 reserved_0: 2;
			u32 dest_mode_logical: 1;
			u32 redirect_hint: 1;
			u32 reserved_1: 1;
			u32 virt_destid_8_14: 7;
			u32 destid_0_7: 8;
			u32 base_address: 12;
		};
		struct {
			u32 dmar_reserved_0: 2;
			u32 dmar_index_15: 1;
			u32 dmar_subhandle_valid: 1;
			u32 dmar_format: 1;
			u32 dmar_index_0_14: 15;
			u32 dmar_base_address: 12;
		};
	};
};

typedef struct x86_msi_addr_lo arch_msi_msg_addr_lo_t;

struct x86_msi_addr_hi {
	u32 reserved: 8;
	u32 destid_8_31: 24;
};

typedef struct x86_msi_addr_hi arch_msi_msg_addr_hi_t;

struct x86_msi_data {
	union {
		struct {
			u32 vector: 8;
			u32 delivery_mode: 3;
			u32 dest_mode_logical: 1;
			u32 reserved: 2;
			u32 active_low: 1;
			u32 is_level: 1;
		};
		u32 dmar_subhandle;
	};
};

typedef struct x86_msi_data arch_msi_msg_data_t;

struct msi_msg {
	union {
		u32 address_lo;
		arch_msi_msg_addr_lo_t arch_addr_lo;
	};
	union {
		u32 address_hi;
		arch_msi_msg_addr_hi_t arch_addr_hi;
	};
	union {
		u32 data;
		arch_msi_msg_data_t arch_data;
	};
};

struct irq_affinity_desc;

struct msi_desc {
	unsigned int irq;
	unsigned int nvec_used;
	struct device *dev;
	struct msi_msg msg;
	struct irq_affinity_desc *affinity;
	void (*write_msi_msg)(struct msi_desc *, void *);
	void *write_msi_msg_data;
	u16 msi_index;
	union {
		struct pci_msi_desc pci;
		struct msi_desc_data data;
	};
};

struct irq_affinity_desc {
	struct cpumask mask;
	unsigned int is_managed: 1;
};

enum irqchip_irq_state {
	IRQCHIP_STATE_PENDING = 0,
	IRQCHIP_STATE_ACTIVE = 1,
	IRQCHIP_STATE_MASKED = 2,
	IRQCHIP_STATE_LINE_LEVEL = 3,
};

struct irq_chip {
	const char *name;
	unsigned int (*irq_startup)(struct irq_data *);
	void (*irq_shutdown)(struct irq_data *);
	void (*irq_enable)(struct irq_data *);
	void (*irq_disable)(struct irq_data *);
	void (*irq_ack)(struct irq_data *);
	void (*irq_mask)(struct irq_data *);
	void (*irq_mask_ack)(struct irq_data *);
	void (*irq_unmask)(struct irq_data *);
	void (*irq_eoi)(struct irq_data *);
	int (*irq_set_affinity)(struct irq_data *, const struct cpumask *, bool);
	int (*irq_retrigger)(struct irq_data *);
	int (*irq_set_type)(struct irq_data *, unsigned int);
	int (*irq_set_wake)(struct irq_data *, unsigned int);
	void (*irq_bus_lock)(struct irq_data *);
	void (*irq_bus_sync_unlock)(struct irq_data *);
	void (*irq_suspend)(struct irq_data *);
	void (*irq_resume)(struct irq_data *);
	void (*irq_pm_shutdown)(struct irq_data *);
	void (*irq_calc_mask)(struct irq_data *);
	void (*irq_print_chip)(struct irq_data *, struct seq_file *);
	int (*irq_request_resources)(struct irq_data *);
	void (*irq_release_resources)(struct irq_data *);
	void (*irq_compose_msi_msg)(struct irq_data *, struct msi_msg *);
	void (*irq_write_msi_msg)(struct irq_data *, struct msi_msg *);
	int (*irq_get_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool *);
	int (*irq_set_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool);
	int (*irq_set_vcpu_affinity)(struct irq_data *, void *);
	void (*ipi_send_single)(struct irq_data *, unsigned int);
	void (*ipi_send_mask)(struct irq_data *, const struct cpumask *);
	int (*irq_nmi_setup)(struct irq_data *);
	void (*irq_nmi_teardown)(struct irq_data *);
	unsigned long flags;
};

enum irq_gc_flags {
	IRQ_GC_INIT_MASK_CACHE = 1,
	IRQ_GC_INIT_NESTED_LOCK = 2,
	IRQ_GC_MASK_CACHE_PER_TYPE = 4,
	IRQ_GC_NO_MASK = 8,
	IRQ_GC_BE_IO = 16,
};

struct irq_chip_generic;

struct irq_domain_chip_generic {
	unsigned int irqs_per_chip;
	unsigned int num_chips;
	unsigned int irq_flags_to_clear;
	unsigned int irq_flags_to_set;
	enum irq_gc_flags gc_flags;
	struct irq_chip_generic *gc[0];
};

struct irq_chip_regs {
	unsigned long enable;
	unsigned long disable;
	unsigned long mask;
	unsigned long ack;
	unsigned long eoi;
	unsigned long type;
	unsigned long polarity;
};

struct irq_desc;

typedef void (*irq_flow_handler_t)(struct irq_desc *);

struct irq_chip_type {
	struct irq_chip chip;
	struct irq_chip_regs regs;
	irq_flow_handler_t handler;
	u32 type;
	u32 mask_cache_priv;
	u32 *mask_cache;
};

struct irq_chip_generic {
	raw_spinlock_t lock;
	void *reg_base;
	u32 (*reg_readl)(void *);
	void (*reg_writel)(u32, void *);
	void (*suspend)(struct irq_chip_generic *);
	void (*resume)(struct irq_chip_generic *);
	unsigned int irq_base;
	unsigned int irq_cnt;
	u32 mask_cache;
	u32 type_cache;
	u32 polarity_cache;
	u32 wake_enabled;
	u32 wake_active;
	unsigned int num_ct;
	void *private;
	unsigned long installed;
	unsigned long unused;
	struct irq_domain *domain;
	struct list_head list;
	struct irq_chip_type chip_types[0];
};

struct irqaction;

struct irq_desc {
	struct irq_common_data irq_common_data;
	struct irq_data irq_data;
	unsigned int __attribute__((btf_type_tag("percpu"))) *kstat_irqs;
	irq_flow_handler_t handle_irq;
	struct irqaction *action;
	unsigned int status_use_accessors;
	unsigned int core_internal_state__do_not_mess_with_it;
	unsigned int depth;
	unsigned int wake_depth;
	unsigned int tot_count;
	unsigned int irq_count;
	unsigned long last_unhandled;
	unsigned int irqs_unhandled;
	atomic_t threads_handled;
	int threads_handled_last;
	raw_spinlock_t lock;
	struct cpumask *percpu_enabled;
	const struct cpumask *percpu_affinity;
	unsigned long threads_oneshot;
	atomic_t threads_active;
	wait_queue_head_t wait_for_threads;
	struct callback_head rcu;
	struct kobject kobj;
	struct mutex request_mutex;
	int parent_irq;
	struct module *owner;
	const char *name;
	struct hlist_node resend_node;
};

enum irqreturn {
	IRQ_NONE = 0,
	IRQ_HANDLED = 1,
	IRQ_WAKE_THREAD = 2,
};

typedef enum irqreturn irqreturn_t;

typedef irqreturn_t (*irq_handler_t)(int, void *);

struct proc_dir_entry;

struct irqaction {
	irq_handler_t handler;
	void *dev_id;
	void __attribute__((btf_type_tag("percpu"))) *percpu_dev_id;
	struct irqaction *next;
	irq_handler_t thread_fn;
	struct task_struct *thread;
	struct irqaction *secondary;
	unsigned int irq;
	unsigned int flags;
	unsigned long thread_flags;
	unsigned long thread_mask;
	const char *name;
	struct proc_dir_entry *dir;
};

struct cpuinfo_x86;

struct x86_cpuinit_ops {
	void (*setup_percpu_clockev)();
	void (*early_percpu_clock_init)();
	void (*fixup_cpu_id)(struct cpuinfo_x86 *, int);
	bool parallel_bringup;
};

struct cpuinfo_topology {
	u32 apicid;
	u32 initial_apicid;
	u32 pkg_id;
	u32 die_id;
	u32 cu_id;
	u32 core_id;
	u32 logical_pkg_id;
	u32 logical_die_id;
	u32 amd_node_id;
	u32 llc_id;
	u32 l2c_id;
};

struct cpuinfo_x86 {
	__u8 x86;
	__u8 x86_vendor;
	__u8 x86_model;
	__u8 x86_stepping;
	int x86_tlbsize;
	__u32 vmx_capability[5];
	__u8 x86_virt_bits;
	__u8 x86_phys_bits;
	__u32 extended_cpuid_level;
	int cpuid_level;
	union {
		__u32 x86_capability[24];
		unsigned long x86_capability_alignment;
	};
	char x86_vendor_id[16];
	char x86_model_id[64];
	struct cpuinfo_topology topo;
	unsigned int x86_cache_size;
	int x86_cache_alignment;
	int x86_cache_max_rmid;
	int x86_cache_occ_scale;
	int x86_cache_mbm_width_offset;
	int x86_power;
	unsigned long loops_per_jiffy;
	u64 ppin;
	u16 x86_clflush_size;
	u16 booted_cores;
	u16 cpu_index;
	bool smt_active;
	u32 microcode;
	u8 x86_cache_bits;
	unsigned int initialized: 1;
};

enum x86_legacy_i8042_state {
	X86_LEGACY_I8042_PLATFORM_ABSENT = 0,
	X86_LEGACY_I8042_FIRMWARE_ABSENT = 1,
	X86_LEGACY_I8042_EXPECTED_PRESENT = 2,
};

struct x86_legacy_devices {
	int pnpbios;
};

struct x86_legacy_features {
	enum x86_legacy_i8042_state i8042;
	int rtc;
	int warm_reset;
	int no_vga;
	int reserve_bios_regions;
	struct x86_legacy_devices devices;
};

struct ghcb;

struct x86_hyper_runtime {
	void (*pin_vcpu)(int);
	void (*sev_es_hcall_prepare)(struct ghcb *, struct pt_regs *);
	bool (*sev_es_hcall_finish)(struct ghcb *, struct pt_regs *);
	bool (*is_private_mmio)(u64);
};

struct x86_guest {
	bool (*enc_status_change_prepare)(unsigned long, int, bool);
	bool (*enc_status_change_finish)(unsigned long, int, bool);
	bool (*enc_tlb_flush_required)(bool);
	bool (*enc_cache_flush_required)();
};

struct x86_platform_ops {
	unsigned long (*calibrate_cpu)();
	unsigned long (*calibrate_tsc)();
	void (*get_wallclock)(struct timespec64 *);
	int (*set_wallclock)(const struct timespec64 *);
	void (*iommu_shutdown)();
	bool (*is_untracked_pat_range)(u64, u64);
	void (*nmi_init)();
	unsigned char (*get_nmi_reason)();
	void (*save_sched_clock_state)();
	void (*restore_sched_clock_state)();
	void (*apic_post_init)();
	struct x86_legacy_features legacy;
	void (*set_legacy_features)();
	void (*realmode_reserve)();
	void (*realmode_init)();
	struct x86_hyper_runtime hyper;
	struct x86_guest guest;
};

struct x86_apic_ops {
	unsigned int (*io_apic_read)(unsigned int, unsigned int);
	void (*restore)();
};

enum xfeature {
	XFEATURE_FP = 0,
	XFEATURE_SSE = 1,
	XFEATURE_YMM = 2,
	XFEATURE_BNDREGS = 3,
	XFEATURE_BNDCSR = 4,
	XFEATURE_OPMASK = 5,
	XFEATURE_ZMM_Hi256 = 6,
	XFEATURE_Hi16_ZMM = 7,
	XFEATURE_PT_UNIMPLEMENTED_SO_FAR = 8,
	XFEATURE_PKRU = 9,
	XFEATURE_PASID = 10,
	XFEATURE_CET_USER = 11,
	XFEATURE_CET_KERNEL_UNUSED = 12,
	XFEATURE_RSRVD_COMP_13 = 13,
	XFEATURE_RSRVD_COMP_14 = 14,
	XFEATURE_LBR = 15,
	XFEATURE_RSRVD_COMP_16 = 16,
	XFEATURE_XTILE_CFG = 17,
	XFEATURE_XTILE_DATA = 18,
	XFEATURE_MAX = 19,
};

enum xstate_copy_mode {
	XSTATE_COPY_FP = 0,
	XSTATE_COPY_FX = 1,
	XSTATE_COPY_XSAVE = 2,
};

struct iovec {
	void __attribute__((btf_type_tag("user"))) *iov_base;
	__kernel_size_t iov_len;
};

struct kvec;

struct bio_vec;

struct iov_iter {
	u8 iter_type;
	bool nofault;
	bool data_source;
	size_t iov_offset;
	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				struct xarray *xarray;
				void __attribute__((btf_type_tag("user"))) *ubuf;
			};
			size_t count;
		};
	};
	union {
		unsigned long nr_segs;
		loff_t xarray_start;
	};
};

struct kvec {
	void *iov_base;
	size_t iov_len;
};

struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct static_key {
	atomic_t enabled;
};

struct membuf {
	void *p;
	size_t left;
};

struct fpu_guest {
	u64 xfeatures;
	u64 perm;
	u64 xfd_err;
	unsigned int uabi_size;
	struct fpstate *fpstate;
};

struct pkru_state {
	u32 pkru;
	u32 pad;
};

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

struct io_bitmap {
	u64 sequence;
	refcount_t refcnt;
	unsigned int max;
	unsigned long bitmap[1024];
};

typedef struct cpumask cpumask_var_t[1];

enum irq_alloc_type {
	X86_IRQ_ALLOC_TYPE_IOAPIC = 1,
	X86_IRQ_ALLOC_TYPE_HPET = 2,
	X86_IRQ_ALLOC_TYPE_PCI_MSI = 3,
	X86_IRQ_ALLOC_TYPE_PCI_MSIX = 4,
	X86_IRQ_ALLOC_TYPE_DMAR = 5,
	X86_IRQ_ALLOC_TYPE_AMDVI = 6,
	X86_IRQ_ALLOC_TYPE_UV = 7,
};

enum {
	___GFP_DMA_BIT = 0,
	___GFP_HIGHMEM_BIT = 1,
	___GFP_DMA32_BIT = 2,
	___GFP_MOVABLE_BIT = 3,
	___GFP_RECLAIMABLE_BIT = 4,
	___GFP_HIGH_BIT = 5,
	___GFP_IO_BIT = 6,
	___GFP_FS_BIT = 7,
	___GFP_ZERO_BIT = 8,
	___GFP_UNUSED_BIT = 9,
	___GFP_DIRECT_RECLAIM_BIT = 10,
	___GFP_KSWAPD_RECLAIM_BIT = 11,
	___GFP_WRITE_BIT = 12,
	___GFP_NOWARN_BIT = 13,
	___GFP_RETRY_MAYFAIL_BIT = 14,
	___GFP_NOFAIL_BIT = 15,
	___GFP_NORETRY_BIT = 16,
	___GFP_MEMALLOC_BIT = 17,
	___GFP_COMP_BIT = 18,
	___GFP_NOMEMALLOC_BIT = 19,
	___GFP_HARDWALL_BIT = 20,
	___GFP_THISNODE_BIT = 21,
	___GFP_ACCOUNT_BIT = 22,
	___GFP_ZEROTAGS_BIT = 23,
	___GFP_LAST_BIT = 24,
};

enum {
	IRQCHIP_FWNODE_REAL = 0,
	IRQCHIP_FWNODE_NAMED = 1,
	IRQCHIP_FWNODE_NAMED_ID = 2,
};

enum {
	X86_IRQ_ALLOC_LEGACY = 1,
};

enum kmalloc_cache_type {
	KMALLOC_NORMAL = 0,
	KMALLOC_DMA = 0,
	KMALLOC_CGROUP = 0,
	KMALLOC_RANDOM_START = 0,
	KMALLOC_RANDOM_END = 0,
	KMALLOC_RECLAIM = 0,
	NR_KMALLOC_TYPES = 1,
};

enum {
	IRQD_TRIGGER_MASK = 15,
	IRQD_SETAFFINITY_PENDING = 256,
	IRQD_ACTIVATED = 512,
	IRQD_NO_BALANCING = 1024,
	IRQD_PER_CPU = 2048,
	IRQD_AFFINITY_SET = 4096,
	IRQD_LEVEL = 8192,
	IRQD_WAKEUP_STATE = 16384,
	IRQD_MOVE_PCNTXT = 32768,
	IRQD_IRQ_DISABLED = 65536,
	IRQD_IRQ_MASKED = 131072,
	IRQD_IRQ_INPROGRESS = 262144,
	IRQD_WAKEUP_ARMED = 524288,
	IRQD_FORWARDED_TO_VCPU = 1048576,
	IRQD_AFFINITY_MANAGED = 2097152,
	IRQD_IRQ_STARTED = 4194304,
	IRQD_MANAGED_SHUTDOWN = 8388608,
	IRQD_SINGLE_TARGET = 16777216,
	IRQD_DEFAULT_TRIGGER_SET = 33554432,
	IRQD_CAN_RESERVE = 67108864,
	IRQD_HANDLE_ENFORCE_IRQCTX = 134217728,
	IRQD_AFFINITY_ON_ACTIVATE = 268435456,
	IRQD_IRQ_ENABLED_ON_SUSPEND = 536870912,
	IRQD_RESEND_WHEN_IN_PROGRESS = 1073741824,
};

typedef struct irq_desc *vector_irq_t[256];

struct irq_cfg {
	unsigned int dest_apicid;
	unsigned int vector;
};

struct apic_chip_data {
	struct irq_cfg hw_irq_cfg;
	unsigned int vector;
	unsigned int prev_vector;
	unsigned int cpu;
	unsigned int prev_cpu;
	unsigned int irq;
	struct hlist_node clist;
	unsigned int move_in_progress: 1;
	unsigned int is_managed: 1;
	unsigned int can_reserve: 1;
	unsigned int has_reserved: 1;
};

typedef void (*smp_call_func_t)(void *);

struct ioapic_alloc_info {
	int pin;
	int node;
	u32 is_level: 1;
	u32 active_low: 1;
	u32 valid: 1;
};

struct uv_alloc_info {
	int limit;
	int blade;
	unsigned long offset;
	char *name;
};

struct irq_alloc_info {
	enum irq_alloc_type type;
	u32 flags;
	u32 devid;
	irq_hw_number_t hwirq;
	const struct cpumask *mask;
	struct msi_desc *desc;
	void *data;
	union {
		struct ioapic_alloc_info ioapic;
		struct uv_alloc_info uv;
	};
};

struct ww_acquire_ctx;

struct mutex_waiter {
	struct list_head list;
	struct task_struct *task;
	struct ww_acquire_ctx *ww_ctx;
};

struct ww_acquire_ctx {
	struct task_struct *task;
	unsigned long stamp;
	unsigned int acquired;
	unsigned short wounded;
	unsigned short is_wait_die;
};

struct ww_mutex {
	struct mutex base;
	struct ww_acquire_ctx *ctx;
};

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

struct lockdep_map {};

struct rcu_ctrlblk {
	struct callback_head *rcucblist;
	struct callback_head **donetail;
	struct callback_head **curtail;
	unsigned long gp_seq;
};

enum {
	HI_SOFTIRQ = 0,
	TIMER_SOFTIRQ = 1,
	NET_TX_SOFTIRQ = 2,
	NET_RX_SOFTIRQ = 3,
	BLOCK_SOFTIRQ = 4,
	IRQ_POLL_SOFTIRQ = 5,
	TASKLET_SOFTIRQ = 6,
	SCHED_SOFTIRQ = 7,
	HRTIMER_SOFTIRQ = 8,
	RCU_SOFTIRQ = 9,
	NR_SOFTIRQS = 10,
};

typedef void (*rcu_callback_t)(struct callback_head *);

typedef void (*call_rcu_func_t)(struct callback_head *, rcu_callback_t);

struct rcu_synchronize {
	struct callback_head head;
	struct completion completion;
};

struct softirq_action {
	void (*action)(struct softirq_action *);
};

struct rcu_gp_oldstate {
	unsigned long rgos_norm;
};

struct llist_head {
	struct llist_node *first;
};

enum {
	CSD_FLAG_LOCK = 1,
	IRQ_WORK_PENDING = 1,
	IRQ_WORK_BUSY = 2,
	IRQ_WORK_LAZY = 4,
	IRQ_WORK_HARD_IRQ = 8,
	IRQ_WORK_CLAIMED = 3,
	CSD_TYPE_ASYNC = 0,
	CSD_TYPE_SYNC = 16,
	CSD_TYPE_IRQ_WORK = 32,
	CSD_TYPE_TTWU = 48,
	CSD_FLAG_TYPE_MASK = 240,
};

struct ref_tracker_dir {};

struct notifier_block;

struct raw_notifier_head {
	struct notifier_block __attribute__((btf_type_tag("rcu"))) *head;
};

struct ctl_table_header;

struct netns_core {
	struct ctl_table_header *sysctl_hdr;
	int sysctl_somaxconn;
	int sysctl_optmem_max;
	u8 sysctl_txrehash;
};

struct ipstats_mib;

struct tcp_mib;

struct linux_mib;

struct udp_mib;

struct icmp_mib;

struct icmpmsg_mib;

struct netns_mib {
	struct ipstats_mib __attribute__((btf_type_tag("percpu"))) *ip_statistics;
	struct tcp_mib __attribute__((btf_type_tag("percpu"))) *tcp_statistics;
	struct linux_mib __attribute__((btf_type_tag("percpu"))) *net_statistics;
	struct udp_mib __attribute__((btf_type_tag("percpu"))) *udp_statistics;
	struct udp_mib __attribute__((btf_type_tag("percpu"))) *udplite_statistics;
	struct icmp_mib __attribute__((btf_type_tag("percpu"))) *icmp_statistics;
	struct icmpmsg_mib *icmpmsg_statistics;
};

struct netns_packet {
	struct mutex sklist_lock;
	struct hlist_head sklist;
};

struct blocking_notifier_head {
	struct rw_semaphore rwsem;
	struct notifier_block __attribute__((btf_type_tag("rcu"))) *head;
};

struct netns_nexthop {
	struct rb_root rb_root;
	struct hlist_head *devhash;
	unsigned int seq;
	u32 last_id_allocated;
	struct blocking_notifier_head notifier_chain;
};

struct inet_hashinfo;

struct inet_timewait_death_row {
	refcount_t tw_refcount;
	struct inet_hashinfo *hashinfo;
	int sysctl_max_tw_buckets;
};

struct udp_table;

struct ipv4_devconf;

struct local_ports {
	u32 range;
	bool warned;
};

struct ping_group_range {
	seqlock_t lock;
	kgid_t range[2];
};

typedef struct {
	u64 key[2];
} siphash_key_t;

struct ip_ra_chain;

struct inet_peer_base;

struct fqdir;

struct tcp_congestion_ops;

struct tcp_fastopen_context;

struct fib_notifier_ops;

struct netns_ipv4 {
	__u8 __cacheline_group_begin__netns_ipv4_read_tx[0];
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	int sysctl_tcp_min_snd_mss;
	unsigned int sysctl_tcp_notsent_lowat;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_min_rtt_wlen;
	int sysctl_tcp_wmem[3];
	u8 sysctl_ip_fwd_use_pmtu;
	__u8 __cacheline_group_end__netns_ipv4_read_tx[0];
	__u8 __cacheline_group_begin__netns_ipv4_read_txrx[0];
	u8 sysctl_tcp_moderate_rcvbuf;
	__u8 __cacheline_group_end__netns_ipv4_read_txrx[0];
	__u8 __cacheline_group_begin__netns_ipv4_read_rx[0];
	u8 sysctl_ip_early_demux;
	u8 sysctl_tcp_early_demux;
	int sysctl_tcp_reordering;
	int sysctl_tcp_rmem[3];
	__u8 __cacheline_group_end__netns_ipv4_read_rx[0];
	struct inet_timewait_death_row tcp_death_row;
	struct udp_table *udp_table;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain __attribute__((btf_type_tag("rcu"))) *ra_chain;
	struct mutex ra_mutex;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	u8 sysctl_tcp_shrink_window;
	struct hlist_head *fib_table_hash;
	struct sock *fibnl;
	struct sock *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	u8 sysctl_tcp_backlog_ack_defer;
	u8 sysctl_tcp_pingpong_thresh;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_challenge_ack_limit;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	unsigned int sysctl_tcp_child_ehash_entries;
	unsigned long sysctl_tcp_comp_sack_delay_ns;
	unsigned long sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops __attribute__((btf_type_tag("rcu"))) *tcp_congestion_control;
	struct tcp_fastopen_context __attribute__((btf_type_tag("rcu"))) *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	unsigned long tfo_active_disable_stamp;
	u32 tcp_challenge_timestamp;
	u32 tcp_challenge_count;
	u8 sysctl_tcp_plb_enabled;
	u8 sysctl_tcp_plb_idle_rehash_rounds;
	u8 sysctl_tcp_plb_rehash_rounds;
	u8 sysctl_tcp_plb_suspend_rto_sec;
	int sysctl_tcp_plb_cong_thresh;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_tcp_syn_linear_timeouts;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	unsigned int sysctl_udp_child_hash_entries;
	struct fib_notifier_ops *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
};

struct net_generic;

struct bpf_prog_array;

struct netns_bpf {
	struct bpf_prog_array __attribute__((btf_type_tag("rcu"))) *run_array[2];
	struct bpf_prog *progs[2];
	struct list_head links[2];
};

struct uevent_sock;

struct net {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	unsigned int dev_base_seq;
	u32 ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct ref_tracker_dir notrefcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct sock *rtnl;
	struct sock *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct xarray dev_by_index;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_nexthop nexthop;
	struct netns_ipv4 ipv4;
	struct net_generic __attribute__((btf_type_tag("rcu"))) *gen;
	struct netns_bpf bpf;
	u64 net_cookie;
	struct sock *diag_nlsk;
};

typedef int (*notifier_fn_t)(struct notifier_block *, unsigned long, void *);

struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block __attribute__((btf_type_tag("rcu"))) *next;
	int priority;
};

typedef u64 netdev_features_t;

struct netdev_tc_txq {
	u16 count;
	u16 offset;
};

struct netdev_rx_queue;

enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER = 1,
	RX_HANDLER_EXACT = 2,
	RX_HANDLER_PASS = 3,
};

typedef enum rx_handler_result rx_handler_result_t;

struct sk_buff;

typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **);

typedef struct {} possible_net_t;

struct netdev_name_node;

typedef u32 xdp_features_t;

struct xsk_tx_metadata_ops;

struct net_device_stats {
	union {
		unsigned long rx_packets;
		atomic_long_t __rx_packets;
	};
	union {
		unsigned long tx_packets;
		atomic_long_t __tx_packets;
	};
	union {
		unsigned long rx_bytes;
		atomic_long_t __rx_bytes;
	};
	union {
		unsigned long tx_bytes;
		atomic_long_t __tx_bytes;
	};
	union {
		unsigned long rx_errors;
		atomic_long_t __rx_errors;
	};
	union {
		unsigned long tx_errors;
		atomic_long_t __tx_errors;
	};
	union {
		unsigned long rx_dropped;
		atomic_long_t __rx_dropped;
	};
	union {
		unsigned long tx_dropped;
		atomic_long_t __tx_dropped;
	};
	union {
		unsigned long multicast;
		atomic_long_t __multicast;
	};
	union {
		unsigned long collisions;
		atomic_long_t __collisions;
	};
	union {
		unsigned long rx_length_errors;
		atomic_long_t __rx_length_errors;
	};
	union {
		unsigned long rx_over_errors;
		atomic_long_t __rx_over_errors;
	};
	union {
		unsigned long rx_crc_errors;
		atomic_long_t __rx_crc_errors;
	};
	union {
		unsigned long rx_frame_errors;
		atomic_long_t __rx_frame_errors;
	};
	union {
		unsigned long rx_fifo_errors;
		atomic_long_t __rx_fifo_errors;
	};
	union {
		unsigned long rx_missed_errors;
		atomic_long_t __rx_missed_errors;
	};
	union {
		unsigned long tx_aborted_errors;
		atomic_long_t __tx_aborted_errors;
	};
	union {
		unsigned long tx_carrier_errors;
		atomic_long_t __tx_carrier_errors;
	};
	union {
		unsigned long tx_fifo_errors;
		atomic_long_t __tx_fifo_errors;
	};
	union {
		unsigned long tx_heartbeat_errors;
		atomic_long_t __tx_heartbeat_errors;
	};
	union {
		unsigned long tx_window_errors;
		atomic_long_t __tx_window_errors;
	};
	union {
		unsigned long rx_compressed;
		atomic_long_t __rx_compressed;
	};
	union {
		unsigned long tx_compressed;
		atomic_long_t __tx_compressed;
	};
};

struct ethtool_ops;

struct netdev_hw_addr_list {
	struct list_head list;
	int count;
	struct rb_root tree;
};

struct in_device;

struct xdp_dev_bulk_queue;

enum netdev_ml_priv_type {
	ML_PRIV_NONE = 0,
	ML_PRIV_CAN = 1,
};

enum netdev_stat_type {
	NETDEV_PCPU_STAT_NONE = 0,
	NETDEV_PCPU_STAT_LSTATS = 1,
	NETDEV_PCPU_STAT_TSTATS = 2,
	NETDEV_PCPU_STAT_DSTATS = 3,
};

struct netdev_stat_ops;

struct phy_device;

struct sfp_bus;

struct udp_tunnel_nic_info;

struct udp_tunnel_nic;

struct bpf_xdp_link;

struct bpf_xdp_entity {
	struct bpf_prog *prog;
	struct bpf_xdp_link *link;
};

typedef struct {} netdevice_tracker;

struct devlink_port;

struct net_device_ops;

struct header_ops;

struct netdev_queue;

struct pcpu_lstats;

struct pcpu_sw_netstats;

struct pcpu_dstats;

struct inet6_dev;

struct dev_ifalias;

struct xdp_metadata_ops;

struct net_device_core_stats;

struct Qdisc;

struct rtnl_link_ops;

struct rtnl_hw_stats64;

struct net_device {
	__u8 __cacheline_group_begin__net_device_read_tx[0];
	unsigned long long priv_flags;
	const struct net_device_ops *netdev_ops;
	const struct header_ops *header_ops;
	struct netdev_queue *_tx;
	netdev_features_t gso_partial_features;
	unsigned int real_num_tx_queues;
	unsigned int gso_max_size;
	unsigned int gso_ipv4_max_size;
	u16 gso_max_segs;
	s16 num_tc;
	unsigned int mtu;
	unsigned short needed_headroom;
	struct netdev_tc_txq tc_to_txq[16];
	__u8 __cacheline_group_end__net_device_read_tx[0];
	__u8 __cacheline_group_begin__net_device_read_txrx[0];
	union {
		struct pcpu_lstats __attribute__((btf_type_tag("percpu"))) *lstats;
		struct pcpu_sw_netstats __attribute__((btf_type_tag("percpu"))) *tstats;
		struct pcpu_dstats __attribute__((btf_type_tag("percpu"))) *dstats;
	};
	unsigned long state;
	unsigned int flags;
	unsigned short hard_header_len;
	netdev_features_t features;
	struct inet6_dev __attribute__((btf_type_tag("rcu"))) *ip6_ptr;
	__u8 __cacheline_group_end__net_device_read_txrx[0];
	__u8 __cacheline_group_begin__net_device_read_rx[0];
	struct bpf_prog __attribute__((btf_type_tag("rcu"))) *xdp_prog;
	struct list_head ptype_specific;
	int ifindex;
	unsigned int real_num_rx_queues;
	struct netdev_rx_queue *_rx;
	unsigned long gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	unsigned int gro_ipv4_max_size;
	rx_handler_func_t __attribute__((btf_type_tag("rcu"))) *rx_handler;
	void __attribute__((btf_type_tag("rcu"))) *rx_handler_data;
	possible_net_t nd_net;
	__u8 __cacheline_group_end__net_device_read_rx[0];
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias __attribute__((btf_type_tag("rcu"))) *ifalias;
	unsigned long mem_end;
	unsigned long mem_start;
	unsigned long base_addr;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	xdp_features_t xdp_features;
	const struct xdp_metadata_ops *xdp_metadata_ops;
	const struct xsk_tx_metadata_ops *xsk_tx_metadata_ops;
	unsigned short gflags;
	unsigned short needed_tailroom;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	unsigned short type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats __attribute__((btf_type_tag("percpu"))) *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct ethtool_ops *ethtool_ops;
	unsigned int operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	unsigned short neigh_priv_len;
	unsigned short dev_id;
	unsigned short dev_port;
	unsigned short padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device __attribute__((btf_type_tag("rcu"))) *ip_ptr;
	const unsigned char *dev_addr;
	unsigned int num_rx_queues;
	unsigned int xdp_zc_max_segs;
	struct netdev_queue __attribute__((btf_type_tag("rcu"))) *ingress_queue;
	unsigned char broadcast[32];
	struct hlist_node index_hlist;
	unsigned int num_tx_queues;
	struct Qdisc __attribute__((btf_type_tag("rcu"))) *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue __attribute__((btf_type_tag("percpu"))) *xdp_bulkq;
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	refcount_t dev_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	u8 reg_state;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED = 0,
		RTNL_LINK_INITIALIZING = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device *);
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	enum netdev_stat_type pcpu_stat_type: 8;
	struct device dev;
	const struct attribute_group *sysfs_groups[4];
	const struct attribute_group *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	const struct netdev_stat_ops *stat_ops;
	unsigned int tso_max_size;
	u16 tso_max_segs;
	u8 prio_tc_map[16];
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	struct devlink_port *devlink_port;
};

enum netdev_tx {
	__NETDEV_TX_MIN = -2147483648,
	NETDEV_TX_OK = 0,
	NETDEV_TX_BUSY = 16,
};

typedef enum netdev_tx netdev_tx_t;

typedef __u16 __be16;

enum tc_setup_type {
	TC_QUERY_CAPS = 0,
	TC_SETUP_QDISC_MQPRIO = 1,
	TC_SETUP_CLSU32 = 2,
	TC_SETUP_CLSFLOWER = 3,
	TC_SETUP_CLSMATCHALL = 4,
	TC_SETUP_CLSBPF = 5,
	TC_SETUP_BLOCK = 6,
	TC_SETUP_QDISC_CBS = 7,
	TC_SETUP_QDISC_RED = 8,
	TC_SETUP_QDISC_PRIO = 9,
	TC_SETUP_QDISC_MQ = 10,
	TC_SETUP_QDISC_ETF = 11,
	TC_SETUP_ROOT_QDISC = 12,
	TC_SETUP_QDISC_GRED = 13,
	TC_SETUP_QDISC_TAPRIO = 14,
	TC_SETUP_FT = 15,
	TC_SETUP_QDISC_ETS = 16,
	TC_SETUP_QDISC_TBF = 17,
	TC_SETUP_QDISC_FIFO = 18,
	TC_SETUP_QDISC_HTB = 19,
	TC_SETUP_ACT = 20,
};

struct ip_tunnel_parm;

struct ifreq;

struct if_settings;

struct ifmap;

struct neigh_parms;

struct rtnl_link_stats64;

struct ifla_vf_info;

struct ifla_vf_stats;

struct nlattr;

struct ifla_vf_guid;

struct netlink_ext_ack;

struct neighbour;

struct ndmsg;

struct nlmsghdr;

struct netlink_callback;

struct netdev_phys_item_id;

struct netdev_bpf;

struct xdp_frame;

struct xdp_buff;

struct net_device_path_ctx;

struct net_device_path;

struct skb_shared_hwtstamps;

struct kernel_hwtstamp_config;

struct net_device_ops {
	int (*ndo_init)(struct net_device *);
	void (*ndo_uninit)(struct net_device *);
	int (*ndo_open)(struct net_device *);
	int (*ndo_stop)(struct net_device *);
	netdev_tx_t (*ndo_start_xmit)(struct sk_buff *, struct net_device *);
	netdev_features_t (*ndo_features_check)(struct sk_buff *, struct net_device *, netdev_features_t);
	u16 (*ndo_select_queue)(struct net_device *, struct sk_buff *, struct net_device *);
	void (*ndo_change_rx_flags)(struct net_device *, int);
	void (*ndo_set_rx_mode)(struct net_device *);
	int (*ndo_set_mac_address)(struct net_device *, void *);
	int (*ndo_validate_addr)(struct net_device *);
	int (*ndo_do_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_eth_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocbond)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocwandev)(struct net_device *, struct if_settings *);
	int (*ndo_siocdevprivate)(struct net_device *, struct ifreq *, void __attribute__((btf_type_tag("user"))) *, int);
	int (*ndo_set_config)(struct net_device *, struct ifmap *);
	int (*ndo_change_mtu)(struct net_device *, int);
	int (*ndo_neigh_setup)(struct net_device *, struct neigh_parms *);
	void (*ndo_tx_timeout)(struct net_device *, unsigned int);
	void (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *);
	bool (*ndo_has_offload_stats)(const struct net_device *, int);
	int (*ndo_get_offload_stats)(int, const struct net_device *, void *);
	struct net_device_stats * (*ndo_get_stats)(struct net_device *);
	int (*ndo_vlan_rx_add_vid)(struct net_device *, __be16, u16);
	int (*ndo_vlan_rx_kill_vid)(struct net_device *, __be16, u16);
	int (*ndo_set_vf_mac)(struct net_device *, int, u8 *);
	int (*ndo_set_vf_vlan)(struct net_device *, int, u16, u8, __be16);
	int (*ndo_set_vf_rate)(struct net_device *, int, int, int);
	int (*ndo_set_vf_spoofchk)(struct net_device *, int, bool);
	int (*ndo_set_vf_trust)(struct net_device *, int, bool);
	int (*ndo_get_vf_config)(struct net_device *, int, struct ifla_vf_info *);
	int (*ndo_set_vf_link_state)(struct net_device *, int, int);
	int (*ndo_get_vf_stats)(struct net_device *, int, struct ifla_vf_stats *);
	int (*ndo_set_vf_port)(struct net_device *, int, struct nlattr **);
	int (*ndo_get_vf_port)(struct net_device *, int, struct sk_buff *);
	int (*ndo_get_vf_guid)(struct net_device *, int, struct ifla_vf_guid *, struct ifla_vf_guid *);
	int (*ndo_set_vf_guid)(struct net_device *, int, u64, int);
	int (*ndo_set_vf_rss_query_en)(struct net_device *, int, bool);
	int (*ndo_setup_tc)(struct net_device *, enum tc_setup_type, void *);
	int (*ndo_add_slave)(struct net_device *, struct net_device *, struct netlink_ext_ack *);
	int (*ndo_del_slave)(struct net_device *, struct net_device *);
	struct net_device * (*ndo_get_xmit_slave)(struct net_device *, struct sk_buff *, bool);
	struct net_device * (*ndo_sk_get_lower_dev)(struct net_device *, struct sock *);
	netdev_features_t (*ndo_fix_features)(struct net_device *, netdev_features_t);
	int (*ndo_set_features)(struct net_device *, netdev_features_t);
	int (*ndo_neigh_construct)(struct net_device *, struct neighbour *);
	void (*ndo_neigh_destroy)(struct net_device *, struct neighbour *);
	int (*ndo_fdb_add)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_del)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_del_bulk)(struct nlmsghdr *, struct net_device *, struct netlink_ext_ack *);
	int (*ndo_fdb_dump)(struct sk_buff *, struct netlink_callback *, struct net_device *, struct net_device *, int *);
	int (*ndo_fdb_get)(struct sk_buff *, struct nlattr **, struct net_device *, const unsigned char *, u16, u32, u32, struct netlink_ext_ack *);
	int (*ndo_mdb_add)(struct net_device *, struct nlattr **, u16, struct netlink_ext_ack *);
	int (*ndo_mdb_del)(struct net_device *, struct nlattr **, struct netlink_ext_ack *);
	int (*ndo_mdb_del_bulk)(struct net_device *, struct nlattr **, struct netlink_ext_ack *);
	int (*ndo_mdb_dump)(struct net_device *, struct sk_buff *, struct netlink_callback *);
	int (*ndo_mdb_get)(struct net_device *, struct nlattr **, u32, u32, struct netlink_ext_ack *);
	int (*ndo_bridge_setlink)(struct net_device *, struct nlmsghdr *, u16, struct netlink_ext_ack *);
	int (*ndo_bridge_getlink)(struct sk_buff *, u32, u32, struct net_device *, u32, int);
	int (*ndo_bridge_dellink)(struct net_device *, struct nlmsghdr *, u16);
	int (*ndo_change_carrier)(struct net_device *, bool);
	int (*ndo_get_phys_port_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_port_parent_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_phys_port_name)(struct net_device *, char *, size_t);
	void * (*ndo_dfwd_add_station)(struct net_device *, struct net_device *);
	void (*ndo_dfwd_del_station)(struct net_device *, void *);
	int (*ndo_set_tx_maxrate)(struct net_device *, int, u32);
	int (*ndo_get_iflink)(const struct net_device *);
	int (*ndo_fill_metadata_dst)(struct net_device *, struct sk_buff *);
	void (*ndo_set_rx_headroom)(struct net_device *, int);
	int (*ndo_bpf)(struct net_device *, struct netdev_bpf *);
	int (*ndo_xdp_xmit)(struct net_device *, int, struct xdp_frame **, u32);
	struct net_device * (*ndo_xdp_get_xmit_slave)(struct net_device *, struct xdp_buff *);
	int (*ndo_xsk_wakeup)(struct net_device *, u32, u32);
	int (*ndo_tunnel_ctl)(struct net_device *, struct ip_tunnel_parm *, int);
	struct net_device * (*ndo_get_peer_dev)(struct net_device *);
	int (*ndo_fill_forward_path)(struct net_device_path_ctx *, struct net_device_path *);
	ktime_t (*ndo_get_tstamp)(struct net_device *, const struct skb_shared_hwtstamps *, bool);
	int (*ndo_hwtstamp_get)(struct net_device *, struct kernel_hwtstamp_config *);
	int (*ndo_hwtstamp_set)(struct net_device *, struct kernel_hwtstamp_config *, struct netlink_ext_ack *);
};

typedef __u32 __wsum;

typedef unsigned int sk_buff_data_t;

struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				struct net_device *dev;
				unsigned long dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	struct sock *sk;
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			unsigned long _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
	};
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 mono_delivery_time: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 redirected: 1;
			__u8 slow_gro: 1;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 mono_delivery_time: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 redirected: 1;
			__u8 slow_gro: 1;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
};

typedef unsigned short __kernel_sa_family_t;

typedef __kernel_sa_family_t sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	union {
		char sa_data_min[14];
		struct {
			struct {} __empty_sa_data;
			char sa_data[0];
		};
	};
};

struct ifmap {
	unsigned long mem_start;
	unsigned long mem_end;
	unsigned short base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

typedef struct {
	unsigned short encoding;
	unsigned short parity;
} raw_hdlc_proto;

typedef struct {
	unsigned int interval;
	unsigned int timeout;
} cisco_proto;

typedef struct {
	unsigned int t391;
	unsigned int t392;
	unsigned int n391;
	unsigned int n392;
	unsigned int n393;
	unsigned short lmi;
	unsigned short dce;
} fr_proto;

typedef struct {
	unsigned int dlci;
} fr_proto_pvc;

typedef struct {
	unsigned int dlci;
	char master[16];
} fr_proto_pvc_info;

typedef struct {
	unsigned short dce;
	unsigned int modulo;
	unsigned int window;
	unsigned int t1;
	unsigned int t2;
	unsigned int n2;
} x25_hdlc_proto;

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	unsigned short loopback;
} sync_serial_settings;

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	unsigned short loopback;
	unsigned int slot_map;
} te1_settings;

struct if_settings {
	unsigned int type;
	unsigned int size;
	union {
		raw_hdlc_proto __attribute__((btf_type_tag("user"))) *raw_hdlc;
		cisco_proto __attribute__((btf_type_tag("user"))) *cisco;
		fr_proto __attribute__((btf_type_tag("user"))) *fr;
		fr_proto_pvc __attribute__((btf_type_tag("user"))) *fr_pvc;
		fr_proto_pvc_info __attribute__((btf_type_tag("user"))) *fr_pvc_info;
		x25_hdlc_proto __attribute__((btf_type_tag("user"))) *x25;
		sync_serial_settings __attribute__((btf_type_tag("user"))) *sync;
		te1_settings __attribute__((btf_type_tag("user"))) *te1;
	} ifs_ifsu;
};

struct ifreq {
	union {
		char ifrn_name[16];
	} ifr_ifrn;
	union {
		struct sockaddr ifru_addr;
		struct sockaddr ifru_dstaddr;
		struct sockaddr ifru_broadaddr;
		struct sockaddr ifru_netmask;
		struct sockaddr ifru_hwaddr;
		short ifru_flags;
		int ifru_ivalue;
		int ifru_mtu;
		struct ifmap ifru_map;
		char ifru_slave[16];
		char ifru_newname[16];
		void __attribute__((btf_type_tag("user"))) *ifru_data;
		struct if_settings ifru_settings;
	} ifr_ifru;
};

struct rtnl_link_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
	__u64 collisions;
	__u64 rx_length_errors;
	__u64 rx_over_errors;
	__u64 rx_crc_errors;
	__u64 rx_frame_errors;
	__u64 rx_fifo_errors;
	__u64 rx_missed_errors;
	__u64 tx_aborted_errors;
	__u64 tx_carrier_errors;
	__u64 tx_fifo_errors;
	__u64 tx_heartbeat_errors;
	__u64 tx_window_errors;
	__u64 rx_compressed;
	__u64 tx_compressed;
	__u64 rx_nohandler;
	__u64 rx_otherhost_dropped;
};

struct ifla_vf_info {
	__u32 vf;
	__u8 mac[32];
	__u32 vlan;
	__u32 qos;
	__u32 spoofchk;
	__u32 linkstate;
	__u32 min_tx_rate;
	__u32 max_tx_rate;
	__u32 rss_query_en;
	__u32 trusted;
	__be16 vlan_proto;
};

struct ifla_vf_stats {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 broadcast;
	__u64 multicast;
	__u64 rx_dropped;
	__u64 tx_dropped;
};

struct nlattr {
	__u16 nla_len;
	__u16 nla_type;
};

struct ifla_vf_guid {
	__u32 vf;
	__u64 guid;
};

struct nla_policy;

struct netlink_ext_ack {
	const char *_msg;
	const struct nlattr *bad_attr;
	const struct nla_policy *policy;
	const struct nlattr *miss_nest;
	u16 miss_type;
	u8 cookie[20];
	u8 cookie_len;
	char _msg_buf[80];
};

struct netlink_range_validation;

struct netlink_range_validation_signed;

struct nla_policy {
	u8 type;
	u8 validation_type;
	u16 len;
	union {
		u16 strict_start_type;
		const u32 bitfield32_valid;
		const u32 mask;
		const char *reject_message;
		const struct nla_policy *nested_policy;
		const struct netlink_range_validation *range;
		const struct netlink_range_validation_signed *range_signed;
		struct {
			s16 min;
			s16 max;
		};
		int (*validate)(const struct nlattr *, struct netlink_ext_ack *);
	};
};

struct netlink_range_validation {
	u64 min;
	u64 max;
};

struct netlink_range_validation_signed {
	s64 min;
	s64 max;
};

struct ndmsg {
	__u8 ndm_family;
	__u8 ndm_pad1;
	__u16 ndm_pad2;
	__s32 ndm_ifindex;
	__u16 ndm_state;
	__u8 ndm_flags;
	__u8 ndm_type;
};

struct nlmsghdr {
	__u32 nlmsg_len;
	__u16 nlmsg_type;
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

struct netlink_callback {
	struct sk_buff *skb;
	const struct nlmsghdr *nlh;
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	void *data;
	struct module *module;
	struct netlink_ext_ack *extack;
	u16 family;
	u16 answer_flags;
	u32 min_dump_alloc;
	unsigned int prev_seq;
	unsigned int seq;
	int flags;
	bool strict_check;
	union {
		u8 ctx[48];
		long args[6];
	};
};

struct netdev_phys_item_id {
	unsigned char id[32];
	unsigned char id_len;
};

struct xsk_buff_pool;

enum bpf_netdev_command {
	XDP_SETUP_PROG = 0,
	XDP_SETUP_PROG_HW = 1,
	BPF_OFFLOAD_MAP_ALLOC = 2,
	BPF_OFFLOAD_MAP_FREE = 3,
	XDP_SETUP_XSK_POOL = 4,
};

struct bpf_offloaded_map;

struct netdev_bpf {
	enum bpf_netdev_command command;
	union {
		struct {
			u32 flags;
			struct bpf_prog *prog;
			struct netlink_ext_ack *extack;
		};
		struct {
			struct bpf_offloaded_map *offmap;
		};
		struct {
			struct xsk_buff_pool *pool;
			u16 queue_id;
		} xsk;
	};
};

struct sock_fprog_kern {
	u16 len;
	struct sock_filter *filter;
};

struct bpf_map_dev_ops;

struct bpf_offloaded_map {
	struct bpf_map map;
	struct net_device *netdev;
	const struct bpf_map_dev_ops *dev_ops;
	void *dev_priv;
	struct list_head offloads;
};

struct bpf_map_dev_ops {
	int (*map_get_next_key)(struct bpf_offloaded_map *, void *, void *);
	int (*map_lookup_elem)(struct bpf_offloaded_map *, void *, void *);
	int (*map_update_elem)(struct bpf_offloaded_map *, void *, void *, u64);
	int (*map_delete_elem)(struct bpf_offloaded_map *, void *);
};

struct net_device_path_ctx {
	const struct net_device *dev;
	u8 daddr[6];
	int num_vlans;
	struct {
		u16 id;
		__be16 proto;
	} vlan[2];
};

enum net_device_path_type {
	DEV_PATH_ETHERNET = 0,
	DEV_PATH_VLAN = 1,
	DEV_PATH_BRIDGE = 2,
	DEV_PATH_PPPOE = 3,
	DEV_PATH_DSA = 4,
	DEV_PATH_MTK_WDMA = 5,
};

struct net_device_path {
	enum net_device_path_type type;
	const struct net_device *dev;
	union {
		struct {
			u16 id;
			__be16 proto;
			u8 h_dest[6];
		} encap;
		struct {
			enum {
				DEV_PATH_BR_VLAN_KEEP = 0,
				DEV_PATH_BR_VLAN_TAG = 1,
				DEV_PATH_BR_VLAN_UNTAG = 2,
				DEV_PATH_BR_VLAN_UNTAG_HW = 3,
			} vlan_mode;
			u16 vlan_id;
			__be16 vlan_proto;
		} bridge;
		struct {
			int port;
			u16 proto;
		} dsa;
		struct {
			u8 wdma_idx;
			u8 queue;
			u16 wcid;
			u8 bss;
			u8 amsdu;
		} mtk_wdma;
	};
};

struct skb_shared_hwtstamps {
	union {
		ktime_t hwtstamp;
		void *netdev_data;
	};
};

struct hh_cache;

struct header_ops {
	int (*create)(struct sk_buff *, struct net_device *, unsigned short, const void *, const void *, unsigned int);
	int (*parse)(const struct sk_buff *, unsigned char *);
	int (*cache)(const struct neighbour *, struct hh_cache *, __be16);
	void (*cache_update)(struct hh_cache *, const struct net_device *, const unsigned char *);
	bool (*validate)(const char *, unsigned int);
	__be16 (*parse_protocol)(const struct sk_buff *);
};

struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};

struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	__u32 qlen;
	spinlock_t lock;
};

struct hh_cache {
	unsigned int hh_len;
	seqlock_t hh_lock;
	unsigned long hh_data[4];
};

struct neigh_table;

struct neigh_ops;

struct neighbour {
	struct neighbour __attribute__((btf_type_tag("rcu"))) *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	unsigned long confirmed;
	unsigned long updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head arp_queue;
	struct timer_list timer;
	unsigned long used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour *, struct sk_buff *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
};

struct napi_struct;

struct netdev_queue {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct Qdisc __attribute__((btf_type_tag("rcu"))) *qdisc;
	struct Qdisc __attribute__((btf_type_tag("rcu"))) *qdisc_sleeping;
	unsigned long tx_maxrate;
	atomic_long_t trans_timeout;
	struct net_device *sb_dev;
	struct napi_struct *napi;
	spinlock_t _xmit_lock;
	int xmit_lock_owner;
	unsigned long trans_start;
	unsigned long state;
};

struct net_rate_estimator;

struct qdisc_skb_head {
	struct sk_buff *head;
	struct sk_buff *tail;
	__u32 qlen;
	spinlock_t lock;
};

struct gnet_stats_basic_sync {
	u64_stats_t bytes;
	u64_stats_t packets;
	struct u64_stats_sync syncp;
};

struct gnet_stats_queue {
	__u32 qlen;
	__u32 backlog;
	__u32 drops;
	__u32 requeues;
	__u32 overlimits;
};

struct Qdisc_ops;

struct qdisc_size_table;

struct Qdisc {
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	unsigned int flags;
	u32 limit;
	const struct Qdisc_ops *ops;
	struct qdisc_size_table __attribute__((btf_type_tag("rcu"))) *stab;
	struct hlist_node hash;
	u32 handle;
	u32 parent;
	struct netdev_queue *dev_queue;
	struct net_rate_estimator __attribute__((btf_type_tag("rcu"))) *rate_est;
	struct gnet_stats_basic_sync __attribute__((btf_type_tag("percpu"))) *cpu_bstats;
	struct gnet_stats_queue __attribute__((btf_type_tag("percpu"))) *cpu_qstats;
	int pad;
	refcount_t refcnt;
	struct sk_buff_head gso_skb;
	struct qdisc_skb_head q;
	long: 64;
	struct gnet_stats_basic_sync bstats;
	struct gnet_stats_queue qstats;
	int owner;
	unsigned long state;
	unsigned long state2;
	struct Qdisc *next_sched;
	struct sk_buff_head skb_bad_txq;
	spinlock_t busylock;
	spinlock_t seqlock;
	struct callback_head rcu;
	netdevice_tracker dev_tracker;
	struct lock_class_key root_lock_key;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long privdata[0];
};

struct Qdisc_class_ops;

struct gnet_dump;

struct Qdisc_ops {
	struct Qdisc_ops *next;
	const struct Qdisc_class_ops *cl_ops;
	char id[16];
	int priv_size;
	unsigned int static_flags;
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	struct sk_buff * (*peek)(struct Qdisc *);
	int (*init)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*reset)(struct Qdisc *);
	void (*destroy)(struct Qdisc *);
	int (*change)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*attach)(struct Qdisc *);
	int (*change_tx_queue_len)(struct Qdisc *, unsigned int);
	void (*change_real_num_tx)(struct Qdisc *, unsigned int);
	int (*dump)(struct Qdisc *, struct sk_buff *);
	int (*dump_stats)(struct Qdisc *, struct gnet_dump *);
	void (*ingress_block_set)(struct Qdisc *, u32);
	void (*egress_block_set)(struct Qdisc *, u32);
	u32 (*ingress_block_get)(struct Qdisc *);
	u32 (*egress_block_get)(struct Qdisc *);
	struct module *owner;
};

struct qdisc_walker;

struct tcmsg;

struct tcf_block;

struct Qdisc_class_ops {
	unsigned int flags;
	struct netdev_queue * (*select_queue)(struct Qdisc *, struct tcmsg *);
	int (*graft)(struct Qdisc *, unsigned long, struct Qdisc *, struct Qdisc **, struct netlink_ext_ack *);
	struct Qdisc * (*leaf)(struct Qdisc *, unsigned long);
	void (*qlen_notify)(struct Qdisc *, unsigned long);
	unsigned long (*find)(struct Qdisc *, u32);
	int (*change)(struct Qdisc *, u32, u32, struct nlattr **, unsigned long *, struct netlink_ext_ack *);
	int (*delete)(struct Qdisc *, unsigned long, struct netlink_ext_ack *);
	void (*walk)(struct Qdisc *, struct qdisc_walker *);
	struct tcf_block * (*tcf_block)(struct Qdisc *, unsigned long, struct netlink_ext_ack *);
	unsigned long (*bind_tcf)(struct Qdisc *, unsigned long, u32);
	void (*unbind_tcf)(struct Qdisc *, unsigned long);
	int (*dump)(struct Qdisc *, unsigned long, struct sk_buff *, struct tcmsg *);
	int (*dump_stats)(struct Qdisc *, unsigned long, struct gnet_dump *);
};

struct tcmsg {
	unsigned char tcm_family;
	unsigned char tcm__pad1;
	unsigned short tcm__pad2;
	int tcm_ifindex;
	__u32 tcm_handle;
	__u32 tcm_parent;
	__u32 tcm_info;
};

struct flow_block {
	struct list_head cb_list;
};

struct tcf_chain;

struct tcf_block {
	struct xarray ports;
	struct mutex lock;
	struct list_head chain_list;
	u32 index;
	u32 classid;
	refcount_t refcnt;
	struct net *net;
	struct Qdisc *q;
	struct rw_semaphore cb_lock;
	struct flow_block flow_block;
	struct list_head owner_list;
	bool keep_dst;
	atomic_t offloadcnt;
	unsigned int nooffloaddevcnt;
	unsigned int lockeddevcnt;
	struct {
		struct tcf_chain *chain;
		struct list_head filter_chain_list;
	} chain0;
	struct callback_head rcu;
	struct hlist_head proto_destroy_ht[128];
	struct mutex proto_destroy_lock;
};

struct tcf_proto;

struct tcf_proto_ops;

struct tcf_chain {
	struct mutex filter_chain_lock;
	struct tcf_proto __attribute__((btf_type_tag("rcu"))) *filter_chain;
	struct list_head list;
	struct tcf_block *block;
	u32 index;
	unsigned int refcnt;
	unsigned int action_refcnt;
	bool explicitly_created;
	bool flushing;
	const struct tcf_proto_ops *tmplt_ops;
	void *tmplt_priv;
	struct callback_head rcu;
};

struct tcf_result;

struct tcf_proto {
	struct tcf_proto __attribute__((btf_type_tag("rcu"))) *next;
	void __attribute__((btf_type_tag("rcu"))) *root;
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	__be16 protocol;
	u32 prio;
	void *data;
	const struct tcf_proto_ops *ops;
	struct tcf_chain *chain;
	spinlock_t lock;
	bool deleting;
	refcount_t refcnt;
	struct callback_head rcu;
	struct hlist_node destroy_ht_node;
};

struct tcf_result {
	union {
		struct {
			unsigned long class;
			u32 classid;
		};
		const struct tcf_proto *goto_tp;
	};
};

struct tcf_walker;

typedef int flow_setup_cb_t(enum tc_setup_type, void *, void *);

struct tcf_exts;

struct tcf_proto_ops {
	struct list_head head;
	char kind[16];
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	int (*init)(struct tcf_proto *);
	void (*destroy)(struct tcf_proto *, bool, struct netlink_ext_ack *);
	void * (*get)(struct tcf_proto *, u32);
	void (*put)(struct tcf_proto *, void *);
	int (*change)(struct net *, struct sk_buff *, struct tcf_proto *, unsigned long, u32, struct nlattr **, void **, u32, struct netlink_ext_ack *);
	int (*delete)(struct tcf_proto *, void *, bool *, bool, struct netlink_ext_ack *);
	bool (*delete_empty)(struct tcf_proto *);
	void (*walk)(struct tcf_proto *, struct tcf_walker *, bool);
	int (*reoffload)(struct tcf_proto *, bool, flow_setup_cb_t *, void *, struct netlink_ext_ack *);
	void (*hw_add)(struct tcf_proto *, void *);
	void (*hw_del)(struct tcf_proto *, void *);
	void (*bind_class)(void *, u32, unsigned long, void *, unsigned long);
	void * (*tmplt_create)(struct net *, struct tcf_chain *, struct nlattr **, struct netlink_ext_ack *);
	void (*tmplt_destroy)(void *);
	void (*tmplt_reoffload)(struct tcf_chain *, bool, flow_setup_cb_t *, void *);
	struct tcf_exts * (*get_exts)(const struct tcf_proto *, u32);
	int (*dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*terse_dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*tmplt_dump)(struct sk_buff *, struct net *, void *);
	struct module *owner;
	int flags;
};

struct tc_stats {
	__u64 bytes;
	__u32 packets;
	__u32 drops;
	__u32 overlimits;
	__u32 bps;
	__u32 pps;
	__u32 qlen;
	__u32 backlog;
};

struct gnet_dump {
	spinlock_t *lock;
	struct sk_buff *skb;
	struct nlattr *tail;
	int compat_tc_stats;
	int compat_xstats;
	int padattr;
	void *xstats;
	int xstats_len;
	struct tc_stats tc_stats;
};

struct tc_sizespec {
	unsigned char cell_log;
	unsigned char size_log;
	short cell_align;
	int overhead;
	unsigned int linklayer;
	unsigned int mpu;
	unsigned int mtu;
	unsigned int tsize;
};

struct qdisc_size_table {
	struct callback_head rcu;
	struct list_head list;
	struct tc_sizespec szopts;
	int refcnt;
	u16 data[0];
};

struct gro_list {
	struct list_head list;
	int count;
};

struct napi_struct {
	struct list_head poll_list;
	unsigned long state;
	int weight;
	int defer_hard_irqs_count;
	unsigned long gro_bitmask;
	int (*poll)(struct napi_struct *, int);
	int list_owner;
	struct net_device *dev;
	struct gro_list gro_hash[8];
	struct sk_buff *skb;
	struct list_head rx_list;
	int rx_count;
	unsigned int napi_id;
	struct hrtimer timer;
	struct task_struct *thread;
	struct list_head dev_list;
	struct hlist_node napi_hash_node;
	int irq;
};

struct pcpu_lstats {
	u64_stats_t packets;
	u64_stats_t bytes;
	struct u64_stats_sync syncp;
};

struct pcpu_sw_netstats {
	u64_stats_t rx_packets;
	u64_stats_t rx_bytes;
	u64_stats_t tx_packets;
	u64_stats_t tx_bytes;
	struct u64_stats_sync syncp;
};

struct pcpu_dstats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 rx_drops;
	u64 tx_packets;
	u64 tx_bytes;
	u64 tx_drops;
	struct u64_stats_sync syncp;
	long: 64;
	long: 64;
};

typedef __u32 __be32;

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct ipv6_stable_secret {
	bool initialized;
	struct in6_addr secret;
};

struct ipv6_devconf {
	__u8 __cacheline_group_begin__ipv6_devconf_read_txrx[0];
	__s32 disable_ipv6;
	__s32 hop_limit;
	__s32 mtu6;
	__s32 forwarding;
	__s32 disable_policy;
	__s32 proxy_ndp;
	__u8 __cacheline_group_end__ipv6_devconf_read_txrx[0];
	__s32 accept_ra;
	__s32 accept_redirects;
	__s32 autoconf;
	__s32 dad_transmits;
	__s32 rtr_solicits;
	__s32 rtr_solicit_interval;
	__s32 rtr_solicit_max_interval;
	__s32 rtr_solicit_delay;
	__s32 force_mld_version;
	__s32 mldv1_unsolicited_report_interval;
	__s32 mldv2_unsolicited_report_interval;
	__s32 use_tempaddr;
	__s32 temp_valid_lft;
	__s32 temp_prefered_lft;
	__s32 regen_min_advance;
	__s32 regen_max_retry;
	__s32 max_desync_factor;
	__s32 max_addresses;
	__s32 accept_ra_defrtr;
	__u32 ra_defrtr_metric;
	__s32 accept_ra_min_hop_limit;
	__s32 accept_ra_min_lft;
	__s32 accept_ra_pinfo;
	__s32 ignore_routes_with_linkdown;
	__s32 accept_source_route;
	__s32 accept_ra_from_local;
	__s32 drop_unicast_in_l2_multicast;
	__s32 accept_dad;
	__s32 force_tllao;
	__s32 ndisc_notify;
	__s32 suppress_frag_ndisc;
	__s32 accept_ra_mtu;
	__s32 drop_unsolicited_na;
	__s32 accept_untracked_na;
	struct ipv6_stable_secret stable_secret;
	__s32 use_oif_addrs_only;
	__s32 keep_addr_on_down;
	__s32 seg6_enabled;
	__u32 enhanced_dad;
	__u32 addr_gen_mode;
	__s32 ndisc_tclass;
	__s32 rpl_seg_enabled;
	__u32 ioam6_id;
	__u32 ioam6_id_wide;
	__u8 ioam6_enabled;
	__u8 ndisc_evict_nocarrier;
	__u8 ra_honor_pio_life;
	struct ctl_table_header *sysctl_header;
};

struct icmpv6_mib_device;

struct icmpv6msg_mib_device;

struct ipv6_devstat {
	struct proc_dir_entry *proc_dir_entry;
	struct ipstats_mib __attribute__((btf_type_tag("percpu"))) *ipv6;
	struct icmpv6_mib_device *icmpv6dev;
	struct icmpv6msg_mib_device *icmpv6msgdev;
};

struct ifmcaddr6;

struct ifacaddr6;

struct inet6_dev {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head addr_list;
	struct ifmcaddr6 __attribute__((btf_type_tag("rcu"))) *mc_list;
	struct ifmcaddr6 __attribute__((btf_type_tag("rcu"))) *mc_tomb;
	unsigned char mc_qrv;
	unsigned char mc_gq_running;
	unsigned char mc_ifc_count;
	unsigned char mc_dad_count;
	unsigned long mc_v1_seen;
	unsigned long mc_qi;
	unsigned long mc_qri;
	unsigned long mc_maxdelay;
	struct delayed_work mc_gq_work;
	struct delayed_work mc_ifc_work;
	struct delayed_work mc_dad_work;
	struct delayed_work mc_query_work;
	struct delayed_work mc_report_work;
	struct sk_buff_head mc_query_queue;
	struct sk_buff_head mc_report_queue;
	spinlock_t mc_query_lock;
	spinlock_t mc_report_lock;
	struct mutex mc_lock;
	struct ifacaddr6 __attribute__((btf_type_tag("rcu"))) *ac_list;
	rwlock_t lock;
	refcount_t refcnt;
	__u32 if_flags;
	int dead;
	u32 desync_factor;
	struct list_head tempaddr_list;
	struct in6_addr token;
	struct neigh_parms *nd_parms;
	struct ipv6_devconf cnf;
	struct ipv6_devstat stats;
	struct timer_list rs_timer;
	__s32 rs_interval;
	__u8 rs_probes;
	unsigned long tstamp;
	struct callback_head rcu;
	unsigned int ra_mtu;
};

struct dev_ifalias {
	struct callback_head rcuhead;
	char ifalias[0];
};

enum xdp_rss_hash_type {
	XDP_RSS_L3_IPV4 = 1,
	XDP_RSS_L3_IPV6 = 2,
	XDP_RSS_L3_DYNHDR = 4,
	XDP_RSS_L4 = 8,
	XDP_RSS_L4_TCP = 16,
	XDP_RSS_L4_UDP = 32,
	XDP_RSS_L4_SCTP = 64,
	XDP_RSS_L4_IPSEC = 128,
	XDP_RSS_L4_ICMP = 256,
	XDP_RSS_TYPE_NONE = 0,
	XDP_RSS_TYPE_L2 = 0,
	XDP_RSS_TYPE_L3_IPV4 = 1,
	XDP_RSS_TYPE_L3_IPV6 = 2,
	XDP_RSS_TYPE_L3_IPV4_OPT = 5,
	XDP_RSS_TYPE_L3_IPV6_EX = 6,
	XDP_RSS_TYPE_L4_ANY = 8,
	XDP_RSS_TYPE_L4_IPV4_TCP = 25,
	XDP_RSS_TYPE_L4_IPV4_UDP = 41,
	XDP_RSS_TYPE_L4_IPV4_SCTP = 73,
	XDP_RSS_TYPE_L4_IPV4_IPSEC = 137,
	XDP_RSS_TYPE_L4_IPV4_ICMP = 265,
	XDP_RSS_TYPE_L4_IPV6_TCP = 26,
	XDP_RSS_TYPE_L4_IPV6_UDP = 42,
	XDP_RSS_TYPE_L4_IPV6_SCTP = 74,
	XDP_RSS_TYPE_L4_IPV6_IPSEC = 138,
	XDP_RSS_TYPE_L4_IPV6_ICMP = 266,
	XDP_RSS_TYPE_L4_IPV6_TCP_EX = 30,
	XDP_RSS_TYPE_L4_IPV6_UDP_EX = 46,
	XDP_RSS_TYPE_L4_IPV6_SCTP_EX = 78,
};

struct xdp_md;

struct xdp_metadata_ops {
	int (*xmo_rx_timestamp)(const struct xdp_md *, u64 *);
	int (*xmo_rx_hash)(const struct xdp_md *, u32 *, enum xdp_rss_hash_type *);
	int (*xmo_rx_vlan_tag)(const struct xdp_md *, __be16 *, u16 *);
};

struct net_device_core_stats {
	unsigned long rx_dropped;
	unsigned long tx_dropped;
	unsigned long rx_nohandler;
	unsigned long rx_otherhost_dropped;
};

struct rtnl_link_ops {
	struct list_head list;
	const char *kind;
	size_t priv_size;
	struct net_device * (*alloc)(struct nlattr **, const char *, unsigned char, unsigned int, unsigned int);
	void (*setup)(struct net_device *);
	bool netns_refund;
	unsigned int maxtype;
	const struct nla_policy *policy;
	int (*validate)(struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*newlink)(struct net *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*changelink)(struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	void (*dellink)(struct net_device *, struct list_head *);
	size_t (*get_size)(const struct net_device *);
	int (*fill_info)(struct sk_buff *, const struct net_device *);
	size_t (*get_xstats_size)(const struct net_device *);
	int (*fill_xstats)(struct sk_buff *, const struct net_device *);
	unsigned int (*get_num_tx_queues)();
	unsigned int (*get_num_rx_queues)();
	unsigned int slave_maxtype;
	const struct nla_policy *slave_policy;
	int (*slave_changelink)(struct net_device *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	size_t (*get_slave_size)(const struct net_device *, const struct net_device *);
	int (*fill_slave_info)(struct sk_buff *, const struct net_device *, const struct net_device *);
	struct net * (*get_link_net)(const struct net_device *);
	size_t (*get_linkxstats_size)(const struct net_device *, int);
	int (*fill_linkxstats)(struct sk_buff *, const struct net_device *, int *, int);
};

struct rtnl_hw_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
};

struct ctl_table;

struct ctl_table_root;

struct ctl_table_set;

struct ctl_dir;

struct ctl_node;

struct ctl_table_header {
	union {
		struct {
			struct ctl_table *ctl_table;
			int ctl_table_size;
			int used;
			int count;
			int nreg;
		};
		struct callback_head rcu;
	};
	struct completion *unregistering;
	struct ctl_table *ctl_table_arg;
	struct ctl_table_root *root;
	struct ctl_table_set *set;
	struct ctl_dir *parent;
	struct ctl_node *node;
	struct hlist_head inodes;
};

typedef int proc_handler(struct ctl_table *, int, void *, size_t *, loff_t *);

struct ctl_table_poll;

struct ctl_table {
	const char *procname;
	void *data;
	int maxlen;
	umode_t mode;
	enum {
		SYSCTL_TABLE_TYPE_DEFAULT = 0,
		SYSCTL_TABLE_TYPE_PERMANENTLY_EMPTY = 1,
	} type;
	proc_handler *proc_handler;
	struct ctl_table_poll *poll;
	void *extra1;
	void *extra2;
};

struct ctl_table_poll {
	atomic_t event;
	wait_queue_head_t wait;
};

struct ctl_dir {
	struct ctl_table_header header;
	struct rb_root root;
};

struct ctl_table_set {
	int (*is_seen)(struct ctl_table_set *);
	struct ctl_dir dir;
};

struct ctl_table_root {
	struct ctl_table_set default_set;
	struct ctl_table_set * (*lookup)(struct ctl_table_root *);
	void (*set_ownership)(struct ctl_table_header *, struct ctl_table *, kuid_t *, kgid_t *);
	int (*permissions)(struct ctl_table_header *, struct ctl_table *);
};

struct ctl_node {
	struct rb_node node;
	struct ctl_table_header *header;
};

struct ipstats_mib {
	u64 mibs[38];
	struct u64_stats_sync syncp;
};

struct tcp_mib {
	unsigned long mibs[16];
};

struct linux_mib {
	unsigned long mibs[132];
};

struct udp_mib {
	unsigned long mibs[10];
};

struct icmp_mib {
	unsigned long mibs[30];
};

struct icmpmsg_mib {
	atomic_long_t mibs[512];
};

struct ip_ra_chain {
	struct ip_ra_chain __attribute__((btf_type_tag("rcu"))) *next;
	struct sock *sk;
	union {
		void (*destructor)(struct sock *);
		struct sock *saved_sk;
	};
	struct callback_head rcu;
};

typedef u32 (*rht_hashfn_t)(const void *, u32, u32);

typedef u32 (*rht_obj_hashfn_t)(const void *, u32, u32);

struct rhashtable_compare_arg;

typedef int (*rht_obj_cmpfn_t)(struct rhashtable_compare_arg *, const void *);

struct rhashtable_params {
	u16 nelem_hint;
	u16 key_len;
	u16 key_offset;
	u16 head_offset;
	unsigned int max_size;
	u16 min_size;
	bool automatic_shrinking;
	rht_hashfn_t hashfn;
	rht_obj_hashfn_t obj_hashfn;
	rht_obj_cmpfn_t obj_cmpfn;
};

struct bucket_table;

struct rhashtable {
	struct bucket_table __attribute__((btf_type_tag("rcu"))) *tbl;
	unsigned int key_len;
	unsigned int max_elems;
	struct rhashtable_params p;
	bool rhlist;
	struct work_struct run_work;
	struct mutex mutex;
	spinlock_t lock;
	atomic_t nelems;
};

struct inet_frags;

struct fqdir {
	long high_thresh;
	long low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags *f;
	struct net *net;
	bool dead;
	struct rhashtable rhashtable;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
};

struct inet_frag_queue;

struct inet_frags {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue *, const void *);
	void (*destructor)(struct inet_frag_queue *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};

struct frag_v4_compare_key {
	__be32 saddr;
	__be32 daddr;
	u32 user;
	u32 vif;
	__be16 id;
	u16 protocol;
};

struct frag_v6_compare_key {
	struct in6_addr saddr;
	struct in6_addr daddr;
	u32 user;
	__be32 id;
	u32 iif;
};

struct inet_frag_queue {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff *fragments_tail;
	struct sk_buff *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 mono_delivery_time;
	__u8 flags;
	u16 max_size;
	struct fqdir *fqdir;
	struct callback_head rcu;
};

struct rhashtable_compare_arg {
	struct rhashtable *ht;
	const void *key;
};

struct rhash_lock_head;

struct bucket_table {
	unsigned int size;
	unsigned int nest;
	u32 hash_rnd;
	struct list_head walkers;
	struct callback_head rcu;
	struct bucket_table __attribute__((btf_type_tag("rcu"))) *future_tbl;
	struct lockdep_map dep_map;
	struct rhash_lock_head __attribute__((btf_type_tag("rcu"))) *buckets[0];
};

enum tcp_ca_event {
	CA_EVENT_TX_START = 0,
	CA_EVENT_CWND_RESTART = 1,
	CA_EVENT_COMPLETE_CWR = 2,
	CA_EVENT_LOSS = 3,
	CA_EVENT_ECN_NO_CE = 4,
	CA_EVENT_ECN_IS_CE = 5,
};

union tcp_cc_info;

struct ack_sample;

struct rate_sample;

struct tcp_congestion_ops {
	u32 (*ssthresh)(struct sock *);
	void (*cong_avoid)(struct sock *, u32, u32);
	void (*set_state)(struct sock *, u8);
	void (*cwnd_event)(struct sock *, enum tcp_ca_event);
	void (*in_ack_event)(struct sock *, u32);
	void (*pkts_acked)(struct sock *, const struct ack_sample *);
	u32 (*min_tso_segs)(struct sock *);
	void (*cong_control)(struct sock *, const struct rate_sample *);
	u32 (*undo_cwnd)(struct sock *);
	u32 (*sndbuf_expand)(struct sock *);
	size_t (*get_info)(struct sock *, u32, int *, union tcp_cc_info *);
	char name[16];
	struct module *owner;
	struct list_head list;
	u32 key;
	u32 flags;
	void (*init)(struct sock *);
	void (*release)(struct sock *);
};

struct tcp_fastopen_context {
	siphash_key_t key[2];
	int num;
	struct callback_head rcu;
};

struct bpf_cgroup_storage;

struct bpf_prog_array_item {
	struct bpf_prog *prog;
	union {
		struct bpf_cgroup_storage *cgroup_storage[2];
		u64 bpf_cookie;
	};
};

struct bpf_prog_array {
	struct callback_head rcu;
	struct bpf_prog_array_item items[0];
};

enum {
	BPF_F_NO_PREALLOC = 1,
	BPF_F_NO_COMMON_LRU = 2,
	BPF_F_NUMA_NODE = 4,
	BPF_F_RDONLY = 8,
	BPF_F_WRONLY = 16,
	BPF_F_STACK_BUILD_ID = 32,
	BPF_F_ZERO_SEED = 64,
	BPF_F_RDONLY_PROG = 128,
	BPF_F_WRONLY_PROG = 256,
	BPF_F_CLONE = 512,
	BPF_F_MMAPABLE = 1024,
	BPF_F_PRESERVE_ELEMS = 2048,
	BPF_F_INNER_MAP = 4096,
	BPF_F_LINK = 8192,
	BPF_F_PATH_FD = 16384,
	BPF_F_VTYPE_BTF_OBJ_FD = 32768,
	BPF_F_TOKEN_FD = 65536,
	BPF_F_SEGV_ON_FAULT = 131072,
	BPF_F_NO_USER_CONV = 262144,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
	BPF_F_LOCK = 4,
};

enum {
	BPF_REG_0 = 0,
	BPF_REG_1 = 1,
	BPF_REG_2 = 2,
	BPF_REG_3 = 3,
	BPF_REG_4 = 4,
	BPF_REG_5 = 5,
	BPF_REG_6 = 6,
	BPF_REG_7 = 7,
	BPF_REG_8 = 8,
	BPF_REG_9 = 9,
	BPF_REG_10 = 10,
	__MAX_BPF_REG = 11,
};

struct pcpu_freelist_node;

struct pcpu_freelist_head {
	struct pcpu_freelist_node *first;
	raw_spinlock_t lock;
};

struct pcpu_freelist {
	struct pcpu_freelist_head __attribute__((btf_type_tag("percpu"))) *freelist;
	struct pcpu_freelist_head extralist;
};

struct bpf_lru_list {
	struct list_head lists[3];
	unsigned int counts[2];
	struct list_head *next_inactive_rotation;
	raw_spinlock_t lock;
};

struct bpf_lru_locallist;

struct bpf_common_lru {
	struct bpf_lru_list lru_list;
	struct bpf_lru_locallist __attribute__((btf_type_tag("percpu"))) *local_list;
};

struct bpf_lru_node;

typedef bool (*del_from_htab_func)(void *, struct bpf_lru_node *);

struct bpf_lru {
	union {
		struct bpf_common_lru common_lru;
		struct bpf_lru_list __attribute__((btf_type_tag("percpu"))) *percpu_lru;
	};
	del_from_htab_func del_from_htab;
	void *del_arg;
	unsigned int hash_offset;
	unsigned int nr_scans;
	bool percpu;
};

struct obj_cgroup;

struct bpf_mem_caches;

struct bpf_mem_cache;

struct bpf_mem_alloc {
	struct bpf_mem_caches __attribute__((btf_type_tag("percpu"))) *caches;
	struct bpf_mem_cache __attribute__((btf_type_tag("percpu"))) *cache;
	struct obj_cgroup *objcg;
	bool percpu;
	struct work_struct work;
};

struct bucket;

struct htab_elem;

struct bpf_htab {
	struct bpf_map map;
	struct bpf_mem_alloc ma;
	struct bpf_mem_alloc pcpu_ma;
	struct bucket *buckets;
	void *elems;
	union {
		struct pcpu_freelist freelist;
		struct bpf_lru lru;
	};
	struct htab_elem * __attribute__((btf_type_tag("percpu"))) *extra_elems;
	struct percpu_counter pcount;
	atomic_t count;
	bool use_percpu_counter;
	u32 n_buckets;
	u32 elem_size;
	u32 hashrnd;
	struct lock_class_key lockdep_key;
	int __attribute__((btf_type_tag("percpu"))) *map_locked[8];
};

struct bpf_mem_cache {
	struct llist_head free_llist;
	local_t active;
	struct llist_head free_llist_extra;
	struct irq_work refill_work;
	struct obj_cgroup *objcg;
	int unit_size;
	int free_cnt;
	int low_watermark;
	int high_watermark;
	int batch;
	int percpu_size;
	bool draining;
	struct bpf_mem_cache *tgt;
	struct llist_head free_by_rcu;
	struct llist_node *free_by_rcu_tail;
	struct llist_head waiting_for_gp;
	struct llist_node *waiting_for_gp_tail;
	struct callback_head rcu;
	atomic_t call_rcu_in_progress;
	struct llist_head free_llist_extra_rcu;
	struct llist_head free_by_rcu_ttrace;
	struct llist_head waiting_for_gp_ttrace;
	struct callback_head rcu_ttrace;
	atomic_t call_rcu_ttrace_in_progress;
};

struct bpf_mem_caches {
	struct bpf_mem_cache cache[11];
};

struct hlist_nulls_node;

struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};

struct bucket {
	struct hlist_nulls_head head;
	raw_spinlock_t raw_lock;
};

struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
};

struct pcpu_freelist_node {
	struct pcpu_freelist_node *next;
};

struct bpf_lru_locallist {
	struct list_head lists[2];
	u16 next_steal;
	raw_spinlock_t lock;
};

struct bpf_lru_node {
	struct list_head list;
	u16 cpu;
	u8 type;
	u8 ref;
};

struct htab_elem {
	union {
		struct hlist_nulls_node hash_node;
		struct {
			void *padding;
			union {
				struct pcpu_freelist_node fnode;
				struct htab_elem *batch_flink;
			};
		};
	};
	union {
		void *ptr_to_pptr;
		struct bpf_lru_node lru_node;
	};
	u32 hash;
	long: 0;
	char key[0];
};

struct __una_u32 {
	u32 x;
};

struct bpf_iter_meta {
	union {
		struct seq_file *seq;
	};
	u64 session_id;
	u64 seq_num;
};

struct bpf_iter_seq_hash_map_info {
	struct bpf_map *map;
	struct bpf_htab *htab;
	void *percpu_value_buf;
	u32 bucket_id;
	u32 skip_elems;
};

struct bpf_iter__bpf_map_elem {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_map *map;
	};
	union {
		void *key;
	};
	union {
		void *value;
	};
};

struct files_stat_struct {
	unsigned long nr_files;
	unsigned long nr_free_files;
	unsigned long max_files;
};

enum task_work_notify_mode {
	TWA_NONE = 0,
	TWA_RESUME = 1,
	TWA_SIGNAL = 2,
	TWA_SIGNAL_NO_IPI = 3,
};

enum _slab_flag_bits {
	_SLAB_CONSISTENCY_CHECKS = 0,
	_SLAB_RED_ZONE = 1,
	_SLAB_POISON = 2,
	_SLAB_KMALLOC = 3,
	_SLAB_HWCACHE_ALIGN = 4,
	_SLAB_CACHE_DMA = 5,
	_SLAB_CACHE_DMA32 = 6,
	_SLAB_STORE_USER = 7,
	_SLAB_PANIC = 8,
	_SLAB_TYPESAFE_BY_RCU = 9,
	_SLAB_TRACE = 10,
	_SLAB_NOLEAKTRACE = 11,
	_SLAB_NO_MERGE = 12,
	_SLAB_NO_USER_FLAGS = 13,
	_SLAB_OBJECT_POISON = 14,
	_SLAB_CMPXCHG_DOUBLE = 15,
	_SLAB_FLAGS_LAST_BIT = 16,
};

enum zone_stat_item {
	NR_FREE_PAGES = 0,
	NR_ZONE_LRU_BASE = 1,
	NR_ZONE_INACTIVE_ANON = 1,
	NR_ZONE_ACTIVE_ANON = 2,
	NR_ZONE_INACTIVE_FILE = 3,
	NR_ZONE_ACTIVE_FILE = 4,
	NR_ZONE_UNEVICTABLE = 5,
	NR_ZONE_WRITE_PENDING = 6,
	NR_MLOCK = 7,
	NR_BOUNCE = 8,
	NR_FREE_CMA_PAGES = 9,
	NR_VM_ZONE_STAT_ITEMS = 10,
};

enum wq_misc_consts {
	WORK_NR_COLORS = 16,
	WORK_CPU_UNBOUND = 1,
	WORK_BUSY_PENDING = 1,
	WORK_BUSY_RUNNING = 2,
	WORKER_DESC_LEN = 32,
};

enum fsnotify_data_type {
	FSNOTIFY_EVENT_NONE = 0,
	FSNOTIFY_EVENT_PATH = 1,
	FSNOTIFY_EVENT_INODE = 2,
	FSNOTIFY_EVENT_DENTRY = 3,
	FSNOTIFY_EVENT_ERROR = 4,
};

struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	unsigned long _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
	bool _workingset;
	unsigned long _pflags;
};

struct wait_queue_entry;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *, unsigned int, int, void *);

struct wait_queue_entry {
	unsigned int flags;
	void *private;
	wait_queue_func_t func;
	struct list_head entry;
};

typedef struct wait_queue_entry wait_queue_entry_t;

struct wait_page_queue {
	struct folio *folio;
	int bit_nr;
	wait_queue_entry_t wait;
};

struct plist_node {
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};

struct swap_cluster_info {
	spinlock_t lock;
	unsigned int data: 24;
	unsigned int flags: 8;
};

struct swap_cluster_list {
	struct swap_cluster_info head;
	struct swap_cluster_info tail;
};

struct percpu_cluster;

struct swap_info_struct {
	struct percpu_ref users;
	unsigned long flags;
	short prio;
	struct plist_node list;
	signed char type;
	unsigned int max;
	unsigned char *swap_map;
	struct swap_cluster_info *cluster_info;
	struct swap_cluster_list free_clusters;
	unsigned int lowest_bit;
	unsigned int highest_bit;
	unsigned int pages;
	unsigned int inuse_pages;
	unsigned int cluster_next;
	unsigned int cluster_nr;
	unsigned int __attribute__((btf_type_tag("percpu"))) *cluster_next_cpu;
	struct percpu_cluster __attribute__((btf_type_tag("percpu"))) *percpu_cluster;
	struct rb_root swap_extent_root;
	struct file *bdev_file;
	struct block_device *bdev;
	struct file *swap_file;
	unsigned int old_block_size;
	struct completion comp;
	spinlock_t lock;
	spinlock_t cont_lock;
	struct work_struct discard_work;
	struct swap_cluster_list discard_clusters;
	struct plist_node avail_lists[0];
};

struct percpu_cluster {
	struct swap_cluster_info index;
	unsigned int next;
};

struct fdtable {
	unsigned int max_fds;
	struct file __attribute__((btf_type_tag("rcu"))) **fd;
	unsigned long *close_on_exec;
	unsigned long *open_fds;
	unsigned long *full_fds_bits;
	struct callback_head rcu;
};

struct files_struct {
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;
	struct fdtable __attribute__((btf_type_tag("rcu"))) *fdt;
	struct fdtable fdtab;
	spinlock_t file_lock;
	unsigned int next_fd;
	unsigned long close_on_exec_init[1];
	unsigned long open_fds_init[1];
	unsigned long full_fds_bits_init[1];
	struct file __attribute__((btf_type_tag("rcu"))) *fd_array[64];
};

struct reclaim_state {
	unsigned long reclaimed;
};

struct nlm_lockowner;

struct nfs_lock_info {
	u32 state;
	struct nlm_lockowner *owner;
	struct list_head list;
};

struct nfs4_lock_state;

struct nfs4_lock_info {
	struct nfs4_lock_state *owner;
};

struct file_lock_core {
	struct file_lock_core *flc_blocker;
	struct list_head flc_list;
	struct hlist_node flc_link;
	struct list_head flc_blocked_requests;
	struct list_head flc_blocked_member;
	fl_owner_t flc_owner;
	unsigned int flc_flags;
	unsigned char flc_type;
	pid_t flc_pid;
	int flc_link_cpu;
	wait_queue_head_t flc_wait;
	struct file *flc_file;
};

struct file_lock_operations;

struct lock_manager_operations;

struct file_lock {
	struct file_lock_core c;
	loff_t fl_start;
	loff_t fl_end;
	const struct file_lock_operations *fl_ops;
	const struct lock_manager_operations *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
		struct {
			struct inode *inode;
		} ceph;
	} fl_u;
};

struct file_lock_operations {
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
};

struct lock_manager_operations {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock *);
	int (*lm_grant)(struct file_lock *, int);
	bool (*lm_lock_expirable)(struct file_lock *);
	void (*lm_expire_lock)();
};

struct lease_manager_operations;

struct file_lease {
	struct file_lock_core c;
	struct fasync_struct *fl_fasync;
	unsigned long fl_break_time;
	unsigned long fl_downgrade_time;
	const struct lease_manager_operations *fl_lmops;
};

struct lease_manager_operations {
	bool (*lm_break)(struct file_lease *);
	int (*lm_change)(struct file_lease *, int, struct list_head *);
	void (*lm_setup)(struct file_lease *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lease *);
};

struct file_lock_context {
	spinlock_t flc_lock;
	struct list_head flc_flock;
	struct list_head flc_posix;
	struct list_head flc_lease;
};

struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops;
	struct list_head list;
	dev_t dev;
	unsigned int count;
};

typedef unsigned int slab_flags_t;

struct backing_file {
	struct file file;
	struct path user_path;
};

typedef int __kernel_rwf_t;

typedef void (*task_work_func_t)(struct callback_head *);

struct pipe_buffer;

struct pipe_buf_operations {
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
};

struct pipe_buffer {
	struct page *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};

enum pageflags {
	PG_locked = 0,
	PG_writeback = 1,
	PG_referenced = 2,
	PG_uptodate = 3,
	PG_dirty = 4,
	PG_lru = 5,
	PG_head = 6,
	PG_waiters = 7,
	PG_active = 8,
	PG_workingset = 9,
	PG_error = 10,
	PG_slab = 11,
	PG_owner_priv_1 = 12,
	PG_arch_1 = 13,
	PG_reserved = 14,
	PG_private = 15,
	PG_private_2 = 16,
	PG_mappedtodisk = 17,
	PG_reclaim = 18,
	PG_swapbacked = 19,
	PG_unevictable = 20,
	PG_mlocked = 21,
	__NR_PAGEFLAGS = 22,
	PG_readahead = 18,
	PG_anon_exclusive = 17,
	PG_checked = 12,
	PG_swapcache = 12,
	PG_fscache = 16,
	PG_pinned = 12,
	PG_savepinned = 4,
	PG_foreign = 12,
	PG_xen_remapped = 12,
	PG_isolated = 18,
	PG_reported = 3,
	PG_has_hwpoisoned = 10,
	PG_large_rmappable = 9,
};

enum {
	IOPRIO_CLASS_NONE = 0,
	IOPRIO_CLASS_RT = 1,
	IOPRIO_CLASS_BE = 2,
	IOPRIO_CLASS_IDLE = 3,
	IOPRIO_CLASS_INVALID = 7,
};

enum {
	IOPRIO_HINT_NONE = 0,
	IOPRIO_HINT_DEV_DURATION_LIMIT_1 = 1,
	IOPRIO_HINT_DEV_DURATION_LIMIT_2 = 2,
	IOPRIO_HINT_DEV_DURATION_LIMIT_3 = 3,
	IOPRIO_HINT_DEV_DURATION_LIMIT_4 = 4,
	IOPRIO_HINT_DEV_DURATION_LIMIT_5 = 5,
	IOPRIO_HINT_DEV_DURATION_LIMIT_6 = 6,
	IOPRIO_HINT_DEV_DURATION_LIMIT_7 = 7,
};

enum {
	SB_UNFROZEN = 0,
	SB_FREEZE_WRITE = 1,
	SB_FREEZE_PAGEFAULT = 2,
	SB_FREEZE_FS = 3,
	SB_FREEZE_COMPLETE = 4,
};

typedef struct {
	unsigned long bits[1];
} nodemask_t;

struct encoded_page;

typedef union {
	struct page **pages;
	struct folio **folios;
	struct encoded_page **encoded_pages;
} release_pages_arg;

struct splice_desc {
	size_t total_len;
	unsigned int len;
	unsigned int flags;
	union {
		void __attribute__((btf_type_tag("user"))) *userptr;
		struct file *file;
		void *data;
	} u;
	void (*splice_eof)(struct splice_desc *);
	loff_t pos;
	loff_t *opos;
	size_t num_spliced;
	bool need_wakeup;
};

typedef int splice_actor(struct pipe_inode_info *, struct pipe_buffer *, struct splice_desc *);

struct fd {
	struct file *file;
	unsigned int flags;
};

struct partial_page;

struct splice_pipe_desc {
	struct page **pages;
	struct partial_page *partial;
	int nr_pages;
	unsigned int nr_pages_max;
	const struct pipe_buf_operations *ops;
	void (*spd_release)(struct splice_pipe_desc *, unsigned int);
};

struct partial_page {
	unsigned int offset;
	unsigned int len;
	unsigned long private;
};

typedef int splice_direct_actor(struct pipe_inode_info *, struct splice_desc *);

struct __large_struct {
	unsigned long buf[100];
};

enum blake2s_lengths {
	BLAKE2S_BLOCK_SIZE = 64,
	BLAKE2S_HASH_SIZE = 32,
	BLAKE2S_KEY_SIZE = 32,
	BLAKE2S_128_HASH_SIZE = 16,
	BLAKE2S_160_HASH_SIZE = 20,
	BLAKE2S_224_HASH_SIZE = 28,
	BLAKE2S_256_HASH_SIZE = 32,
};

struct blake2s_state {
	u32 h[8];
	u32 t[2];
	u32 f[2];
	u8 buf[64];
	unsigned int buflen;
	unsigned int outlen;
};

typedef __u16 Elf32_Half;

typedef __u32 Elf32_Word;

typedef __u32 Elf32_Addr;

typedef __u32 Elf32_Off;

struct elf32_hdr {
	unsigned char e_ident[16];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
};

typedef struct elf32_hdr Elf32_Ehdr;

struct elf32_phdr {
	Elf32_Word p_type;
	Elf32_Off p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
};

typedef struct elf32_phdr Elf32_Phdr;

typedef __u16 Elf64_Half;

typedef __u32 Elf64_Word;

typedef __u64 Elf64_Addr;

typedef __u64 Elf64_Off;

struct elf64_hdr {
	unsigned char e_ident[16];
	Elf64_Half e_type;
	Elf64_Half e_machine;
	Elf64_Word e_version;
	Elf64_Addr e_entry;
	Elf64_Off e_phoff;
	Elf64_Off e_shoff;
	Elf64_Word e_flags;
	Elf64_Half e_ehsize;
	Elf64_Half e_phentsize;
	Elf64_Half e_phnum;
	Elf64_Half e_shentsize;
	Elf64_Half e_shnum;
	Elf64_Half e_shstrndx;
};

typedef struct elf64_hdr Elf64_Ehdr;

typedef __u64 Elf64_Xword;

struct elf64_phdr {
	Elf64_Word p_type;
	Elf64_Word p_flags;
	Elf64_Off p_offset;
	Elf64_Addr p_vaddr;
	Elf64_Addr p_paddr;
	Elf64_Xword p_filesz;
	Elf64_Xword p_memsz;
	Elf64_Xword p_align;
};

typedef struct elf64_phdr Elf64_Phdr;

struct elf32_note {
	Elf32_Word n_namesz;
	Elf32_Word n_descsz;
	Elf32_Word n_type;
};

typedef struct elf32_note Elf32_Nhdr;

typedef unsigned int fgf_t;

struct perf_guest_switch_msr {
	unsigned int msr;
	u64 host;
	u64 guest;
};

struct event_constraint;

struct debug_store;

struct er_account;

struct intel_shared_regs;

struct intel_excl_cntrs;

struct amd_nb;

struct cpu_hw_events {
	struct perf_event *events[64];
	unsigned long active_mask[1];
	unsigned long dirty[1];
	int enabled;
	int n_events;
	int n_added;
	int n_txn;
	int n_txn_pair;
	int n_txn_metric;
	int assign[64];
	u64 tags[64];
	struct perf_event *event_list[64];
	struct event_constraint *event_constraint[64];
	int n_excl;
	unsigned int txn_flags;
	int is_fake;
	struct debug_store *ds;
	void *ds_pebs_vaddr;
	void *ds_bts_vaddr;
	u64 pebs_enabled;
	int n_pebs;
	int n_large_pebs;
	int n_pebs_via_pt;
	int pebs_output;
	u64 pebs_data_cfg;
	u64 active_pebs_data_cfg;
	int pebs_record_size;
	u64 fixed_ctrl_val;
	u64 active_fixed_ctrl_val;
	int lbr_users;
	int lbr_pebs_users;
	struct perf_branch_stack lbr_stack;
	struct perf_branch_entry lbr_entries[32];
	u64 lbr_counters[32];
	union {
		struct er_account *lbr_sel;
		struct er_account *lbr_ctl;
	};
	u64 br_sel;
	void *last_task_ctx;
	int last_log_id;
	int lbr_select;
	void *lbr_xsave;
	u64 intel_ctrl_guest_mask;
	u64 intel_ctrl_host_mask;
	struct perf_guest_switch_msr guest_switch_msrs[64];
	u64 intel_cp_status;
	struct intel_shared_regs *shared_regs;
	struct event_constraint *constraint_list;
	struct intel_excl_cntrs *excl_cntrs;
	int excl_thread_id;
	u64 tfa_shadow;
	int n_metric;
	struct amd_nb *amd_nb;
	int brs_active;
	u64 perf_ctr_virt_mask;
	int n_pair;
	void *kfree_on_online[2];
	struct pmu *pmu;
};

struct event_constraint {
	union {
		unsigned long idxmsk[1];
		u64 idxmsk64;
	};
	u64 code;
	u64 cmask;
	int weight;
	int overlap;
	int flags;
	unsigned int size;
};

struct debug_store {
	u64 bts_buffer_base;
	u64 bts_index;
	u64 bts_absolute_maximum;
	u64 bts_interrupt_threshold;
	u64 pebs_buffer_base;
	u64 pebs_index;
	u64 pebs_absolute_maximum;
	u64 pebs_interrupt_threshold;
	u64 pebs_event_reset[48];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct er_account {
	raw_spinlock_t lock;
	u64 config;
	u64 reg;
	atomic_t ref;
};

struct intel_shared_regs {
	struct er_account regs[7];
	int refcnt;
	unsigned int core_id;
};

enum intel_excl_state_type {
	INTEL_EXCL_UNUSED = 0,
	INTEL_EXCL_SHARED = 1,
	INTEL_EXCL_EXCLUSIVE = 2,
};

struct intel_excl_states {
	enum intel_excl_state_type state[64];
	bool sched_started;
};

struct intel_excl_cntrs {
	raw_spinlock_t lock;
	struct intel_excl_states states[2];
	union {
		u16 has_exclusive[2];
		u32 exclusive_present;
	};
	int refcnt;
	unsigned int core_id;
};

struct amd_nb {
	int nb_id;
	int refcnt;
	struct perf_event *owners[64];
	struct event_constraint event_constraints[64];
};

struct static_key_false {
	struct static_key key;
};

struct static_call_mod;

struct static_call_site;

struct static_call_key {
	void *func;
	union {
		unsigned long type;
		struct static_call_mod *mods;
		struct static_call_site *sites;
	};
};

struct static_call_mod {
	struct static_call_mod *next;
	struct module *mod;
	struct static_call_site *sites;
};

struct static_call_site {
	s32 addr;
	s32 key;
};

union perf_capabilities {
	struct {
		u64 lbr_format: 6;
		u64 pebs_trap: 1;
		u64 pebs_arch_reg: 1;
		u64 pebs_format: 4;
		u64 smm_freeze: 1;
		u64 full_width_write: 1;
		u64 pebs_baseline: 1;
		u64 perf_metrics: 1;
		u64 pebs_output_pt_available: 1;
		u64 pebs_timing_info: 1;
		u64 anythread_deprecated: 1;
	};
	u64 capabilities;
};

enum hybrid_cpu_type {
	HYBRID_INTEL_NONE = 0,
	HYBRID_INTEL_ATOM = 32,
	HYBRID_INTEL_CORE = 64,
};

struct x86_pmu_quirk;

struct extra_reg;

struct x86_hybrid_pmu;

struct x86_pmu {
	const char *name;
	int version;
	int (*handle_irq)(struct pt_regs *);
	void (*disable_all)();
	void (*enable_all)(int);
	void (*enable)(struct perf_event *);
	void (*disable)(struct perf_event *);
	void (*assign)(struct perf_event *, int);
	void (*add)(struct perf_event *);
	void (*del)(struct perf_event *);
	void (*read)(struct perf_event *);
	int (*set_period)(struct perf_event *);
	u64 (*update)(struct perf_event *);
	int (*hw_config)(struct perf_event *);
	int (*schedule_events)(struct cpu_hw_events *, int, int *);
	unsigned int eventsel;
	unsigned int perfctr;
	int (*addr_offset)(int, bool);
	int (*rdpmc_index)(int);
	u64 (*event_map)(int);
	int max_events;
	int num_counters;
	int num_counters_fixed;
	int cntval_bits;
	u64 cntval_mask;
	union {
		unsigned long events_maskl;
		unsigned long events_mask[1];
	};
	int events_mask_len;
	int apic;
	u64 max_period;
	struct event_constraint * (*get_event_constraints)(struct cpu_hw_events *, int, struct perf_event *);
	void (*put_event_constraints)(struct cpu_hw_events *, struct perf_event *);
	void (*start_scheduling)(struct cpu_hw_events *);
	void (*commit_scheduling)(struct cpu_hw_events *, int, int);
	void (*stop_scheduling)(struct cpu_hw_events *);
	struct event_constraint *event_constraints;
	struct x86_pmu_quirk *quirks;
	void (*limit_period)(struct perf_event *, s64 *);
	unsigned int late_ack: 1;
	unsigned int mid_ack: 1;
	unsigned int enabled_ack: 1;
	int attr_rdpmc_broken;
	int attr_rdpmc;
	struct attribute **format_attrs;
	ssize_t (*events_sysfs_show)(char *, u64);
	const struct attribute_group **attr_update;
	unsigned long attr_freeze_on_smi;
	int (*cpu_prepare)(int);
	void (*cpu_starting)(int);
	void (*cpu_dying)(int);
	void (*cpu_dead)(int);
	void (*check_microcode)();
	void (*sched_task)(struct perf_event_pmu_context *, bool);
	u64 intel_ctrl;
	union perf_capabilities intel_cap;
	unsigned int bts: 1;
	unsigned int bts_active: 1;
	unsigned int pebs: 1;
	unsigned int pebs_active: 1;
	unsigned int pebs_broken: 1;
	unsigned int pebs_prec_dist: 1;
	unsigned int pebs_no_tlb: 1;
	unsigned int pebs_no_isolation: 1;
	unsigned int pebs_block: 1;
	unsigned int pebs_ept: 1;
	int pebs_record_size;
	int pebs_buffer_size;
	int max_pebs_events;
	void (*drain_pebs)(struct pt_regs *, struct perf_sample_data *);
	struct event_constraint *pebs_constraints;
	void (*pebs_aliases)(struct perf_event *);
	u64 (*pebs_latency_data)(struct perf_event *, u64);
	unsigned long large_pebs_flags;
	u64 rtm_abort_event;
	u64 pebs_capable;
	unsigned int lbr_tos;
	unsigned int lbr_from;
	unsigned int lbr_to;
	unsigned int lbr_info;
	unsigned int lbr_nr;
	union {
		u64 lbr_sel_mask;
		u64 lbr_ctl_mask;
	};
	union {
		const int *lbr_sel_map;
		int *lbr_ctl_map;
	};
	bool lbr_double_abort;
	bool lbr_pt_coexist;
	unsigned int lbr_has_info: 1;
	unsigned int lbr_has_tsx: 1;
	unsigned int lbr_from_flags: 1;
	unsigned int lbr_to_cycles: 1;
	unsigned int lbr_depth_mask: 8;
	unsigned int lbr_deep_c_reset: 1;
	unsigned int lbr_lip: 1;
	unsigned int lbr_cpl: 1;
	unsigned int lbr_filter: 1;
	unsigned int lbr_call_stack: 1;
	unsigned int lbr_mispred: 1;
	unsigned int lbr_timed_lbr: 1;
	unsigned int lbr_br_type: 1;
	unsigned int lbr_counters: 4;
	void (*lbr_reset)();
	void (*lbr_read)(struct cpu_hw_events *);
	void (*lbr_save)(void *);
	void (*lbr_restore)(void *);
	atomic_t lbr_exclusive[3];
	int num_topdown_events;
	void (*swap_task_ctx)(struct perf_event_pmu_context *, struct perf_event_pmu_context *);
	unsigned int amd_nb_constraints: 1;
	u64 perf_ctr_pair_en;
	struct extra_reg *extra_regs;
	unsigned int flags;
	struct perf_guest_switch_msr * (*guest_get_msrs)(int *, void *);
	int (*check_period)(struct perf_event *, u64);
	int (*aux_output_match)(struct perf_event *);
	void (*filter)(struct pmu *, int, bool *);
	int num_hybrid_pmus;
	struct x86_hybrid_pmu *hybrid_pmu;
	enum hybrid_cpu_type (*get_hybrid_cpu_type)();
};

struct x86_pmu_quirk {
	struct x86_pmu_quirk *next;
	void (*func)();
};

struct extra_reg {
	unsigned int event;
	unsigned int msr;
	u64 config_mask;
	u64 valid_mask;
	int idx;
	bool extra_msr_access;
};

enum hybrid_pmu_type {
	not_hybrid = 0,
	hybrid_small = 1,
	hybrid_big = 2,
	hybrid_big_small = 3,
};

struct x86_hybrid_pmu {
	struct pmu pmu;
	const char *name;
	enum hybrid_pmu_type pmu_type;
	cpumask_t supported_cpus;
	union perf_capabilities intel_cap;
	u64 intel_ctrl;
	int max_pebs_events;
	int num_counters;
	int num_counters_fixed;
	struct event_constraint unconstrained;
	u64 hw_cache_event_ids[42];
	u64 hw_cache_extra_regs[42];
	struct event_constraint *event_constraints;
	struct event_constraint *pebs_constraints;
	struct extra_reg *extra_regs;
	unsigned int late_ack: 1;
	unsigned int mid_ack: 1;
	unsigned int enabled_ack: 1;
	u64 pebs_data_source[16];
};

typedef int (*nmi_handler_t)(unsigned int, struct pt_regs *);

struct nmiaction {
	struct list_head list;
	nmi_handler_t handler;
	u64 max_duration;
	unsigned long flags;
	const char *name;
};

struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *, struct device_attribute *, char *);
	ssize_t (*store)(struct device *, struct device_attribute *, const char *, size_t);
};

struct perf_pmu_events_attr {
	struct device_attribute attr;
	u64 id;
	const char *event_str;
};

enum {
	x86_lbr_exclusive_lbr = 0,
	x86_lbr_exclusive_bts = 1,
	x86_lbr_exclusive_pt = 2,
	x86_lbr_exclusive_max = 3,
};

enum perf_type_id {
	PERF_TYPE_HARDWARE = 0,
	PERF_TYPE_SOFTWARE = 1,
	PERF_TYPE_TRACEPOINT = 2,
	PERF_TYPE_HW_CACHE = 3,
	PERF_TYPE_RAW = 4,
	PERF_TYPE_BREAKPOINT = 5,
	PERF_TYPE_MAX = 6,
};

enum perf_branch_sample_type {
	PERF_SAMPLE_BRANCH_USER = 1,
	PERF_SAMPLE_BRANCH_KERNEL = 2,
	PERF_SAMPLE_BRANCH_HV = 4,
	PERF_SAMPLE_BRANCH_ANY = 8,
	PERF_SAMPLE_BRANCH_ANY_CALL = 16,
	PERF_SAMPLE_BRANCH_ANY_RETURN = 32,
	PERF_SAMPLE_BRANCH_IND_CALL = 64,
	PERF_SAMPLE_BRANCH_ABORT_TX = 128,
	PERF_SAMPLE_BRANCH_IN_TX = 256,
	PERF_SAMPLE_BRANCH_NO_TX = 512,
	PERF_SAMPLE_BRANCH_COND = 1024,
	PERF_SAMPLE_BRANCH_CALL_STACK = 2048,
	PERF_SAMPLE_BRANCH_IND_JUMP = 4096,
	PERF_SAMPLE_BRANCH_CALL = 8192,
	PERF_SAMPLE_BRANCH_NO_FLAGS = 16384,
	PERF_SAMPLE_BRANCH_NO_CYCLES = 32768,
	PERF_SAMPLE_BRANCH_TYPE_SAVE = 65536,
	PERF_SAMPLE_BRANCH_HW_INDEX = 131072,
	PERF_SAMPLE_BRANCH_PRIV_SAVE = 262144,
	PERF_SAMPLE_BRANCH_COUNTERS = 524288,
	PERF_SAMPLE_BRANCH_MAX = 1048576,
};

enum perf_event_x86_regs {
	PERF_REG_X86_AX = 0,
	PERF_REG_X86_BX = 1,
	PERF_REG_X86_CX = 2,
	PERF_REG_X86_DX = 3,
	PERF_REG_X86_SI = 4,
	PERF_REG_X86_DI = 5,
	PERF_REG_X86_BP = 6,
	PERF_REG_X86_SP = 7,
	PERF_REG_X86_IP = 8,
	PERF_REG_X86_FLAGS = 9,
	PERF_REG_X86_CS = 10,
	PERF_REG_X86_SS = 11,
	PERF_REG_X86_DS = 12,
	PERF_REG_X86_ES = 13,
	PERF_REG_X86_FS = 14,
	PERF_REG_X86_GS = 15,
	PERF_REG_X86_R8 = 16,
	PERF_REG_X86_R9 = 17,
	PERF_REG_X86_R10 = 18,
	PERF_REG_X86_R11 = 19,
	PERF_REG_X86_R12 = 20,
	PERF_REG_X86_R13 = 21,
	PERF_REG_X86_R14 = 22,
	PERF_REG_X86_R15 = 23,
	PERF_REG_X86_32_MAX = 16,
	PERF_REG_X86_64_MAX = 24,
	PERF_REG_X86_XMM0 = 32,
	PERF_REG_X86_XMM1 = 34,
	PERF_REG_X86_XMM2 = 36,
	PERF_REG_X86_XMM3 = 38,
	PERF_REG_X86_XMM4 = 40,
	PERF_REG_X86_XMM5 = 42,
	PERF_REG_X86_XMM6 = 44,
	PERF_REG_X86_XMM7 = 46,
	PERF_REG_X86_XMM8 = 48,
	PERF_REG_X86_XMM9 = 50,
	PERF_REG_X86_XMM10 = 52,
	PERF_REG_X86_XMM11 = 54,
	PERF_REG_X86_XMM12 = 56,
	PERF_REG_X86_XMM13 = 58,
	PERF_REG_X86_XMM14 = 60,
	PERF_REG_X86_XMM15 = 62,
	PERF_REG_X86_XMM_MAX = 64,
};

enum {
	PERF_X86_EVENT_PEBS_LDLAT = 1,
	PERF_X86_EVENT_PEBS_ST = 2,
	PERF_X86_EVENT_PEBS_ST_HSW = 4,
	PERF_X86_EVENT_PEBS_LD_HSW = 8,
	PERF_X86_EVENT_PEBS_NA_HSW = 16,
	PERF_X86_EVENT_EXCL = 32,
	PERF_X86_EVENT_DYNAMIC = 64,
	PERF_X86_EVENT_EXCL_ACCT = 256,
	PERF_X86_EVENT_AUTO_RELOAD = 512,
	PERF_X86_EVENT_LARGE_PEBS = 1024,
	PERF_X86_EVENT_PEBS_VIA_PT = 2048,
	PERF_X86_EVENT_PAIR = 4096,
	PERF_X86_EVENT_LBR_SELECT = 8192,
	PERF_X86_EVENT_TOPDOWN = 16384,
	PERF_X86_EVENT_PEBS_STLAT = 32768,
	PERF_X86_EVENT_AMD_BRS = 65536,
	PERF_X86_EVENT_PEBS_LAT_HYBRID = 131072,
	PERF_X86_EVENT_NEEDS_BRANCH_STACK = 262144,
	PERF_X86_EVENT_BRANCH_COUNTERS = 524288,
};

enum stack_type {
	STACK_TYPE_UNKNOWN = 0,
	STACK_TYPE_TASK = 1,
	STACK_TYPE_IRQ = 2,
	STACK_TYPE_SOFTIRQ = 3,
	STACK_TYPE_ENTRY = 4,
	STACK_TYPE_EXCEPTION = 5,
	STACK_TYPE_EXCEPTION_LAST = 10,
};

enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D = 0,
	PERF_COUNT_HW_CACHE_L1I = 1,
	PERF_COUNT_HW_CACHE_LL = 2,
	PERF_COUNT_HW_CACHE_DTLB = 3,
	PERF_COUNT_HW_CACHE_ITLB = 4,
	PERF_COUNT_HW_CACHE_BPU = 5,
	PERF_COUNT_HW_CACHE_NODE = 6,
	PERF_COUNT_HW_CACHE_MAX = 7,
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ = 0,
	PERF_COUNT_HW_CACHE_OP_WRITE = 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH = 2,
	PERF_COUNT_HW_CACHE_OP_MAX = 3,
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS = 1,
	PERF_COUNT_HW_CACHE_RESULT_MAX = 2,
};

enum perf_event_sample_format {
	PERF_SAMPLE_IP = 1,
	PERF_SAMPLE_TID = 2,
	PERF_SAMPLE_TIME = 4,
	PERF_SAMPLE_ADDR = 8,
	PERF_SAMPLE_READ = 16,
	PERF_SAMPLE_CALLCHAIN = 32,
	PERF_SAMPLE_ID = 64,
	PERF_SAMPLE_CPU = 128,
	PERF_SAMPLE_PERIOD = 256,
	PERF_SAMPLE_STREAM_ID = 512,
	PERF_SAMPLE_RAW = 1024,
	PERF_SAMPLE_BRANCH_STACK = 2048,
	PERF_SAMPLE_REGS_USER = 4096,
	PERF_SAMPLE_STACK_USER = 8192,
	PERF_SAMPLE_WEIGHT = 16384,
	PERF_SAMPLE_DATA_SRC = 32768,
	PERF_SAMPLE_IDENTIFIER = 65536,
	PERF_SAMPLE_TRANSACTION = 131072,
	PERF_SAMPLE_REGS_INTR = 262144,
	PERF_SAMPLE_PHYS_ADDR = 524288,
	PERF_SAMPLE_AUX = 1048576,
	PERF_SAMPLE_CGROUP = 2097152,
	PERF_SAMPLE_DATA_PAGE_SIZE = 4194304,
	PERF_SAMPLE_CODE_PAGE_SIZE = 8388608,
	PERF_SAMPLE_WEIGHT_STRUCT = 16777216,
	PERF_SAMPLE_MAX = 33554432,
};

enum {
	NMI_LOCAL = 0,
	NMI_UNKNOWN = 1,
	NMI_SERR = 2,
	NMI_IO_CHECK = 3,
	NMI_MAX = 4,
};

enum cpuhp_state {
	CPUHP_INVALID = -1,
	CPUHP_OFFLINE = 0,
	CPUHP_CREATE_THREADS = 1,
	CPUHP_PERF_PREPARE = 2,
	CPUHP_PERF_X86_PREPARE = 3,
	CPUHP_PERF_X86_AMD_UNCORE_PREP = 4,
	CPUHP_PERF_POWER = 5,
	CPUHP_PERF_SUPERH = 6,
	CPUHP_X86_HPET_DEAD = 7,
	CPUHP_X86_MCE_DEAD = 8,
	CPUHP_VIRT_NET_DEAD = 9,
	CPUHP_IBMVNIC_DEAD = 10,
	CPUHP_SLUB_DEAD = 11,
	CPUHP_DEBUG_OBJ_DEAD = 12,
	CPUHP_MM_WRITEBACK_DEAD = 13,
	CPUHP_MM_VMSTAT_DEAD = 14,
	CPUHP_SOFTIRQ_DEAD = 15,
	CPUHP_NET_MVNETA_DEAD = 16,
	CPUHP_CPUIDLE_DEAD = 17,
	CPUHP_ARM64_FPSIMD_DEAD = 18,
	CPUHP_ARM_OMAP_WAKE_DEAD = 19,
	CPUHP_IRQ_POLL_DEAD = 20,
	CPUHP_BLOCK_SOFTIRQ_DEAD = 21,
	CPUHP_BIO_DEAD = 22,
	CPUHP_ACPI_CPUDRV_DEAD = 23,
	CPUHP_S390_PFAULT_DEAD = 24,
	CPUHP_BLK_MQ_DEAD = 25,
	CPUHP_FS_BUFF_DEAD = 26,
	CPUHP_PRINTK_DEAD = 27,
	CPUHP_MM_MEMCQ_DEAD = 28,
	CPUHP_PERCPU_CNT_DEAD = 29,
	CPUHP_RADIX_DEAD = 30,
	CPUHP_PAGE_ALLOC = 31,
	CPUHP_NET_DEV_DEAD = 32,
	CPUHP_PCI_XGENE_DEAD = 33,
	CPUHP_IOMMU_IOVA_DEAD = 34,
	CPUHP_AP_ARM_CACHE_B15_RAC_DEAD = 35,
	CPUHP_PADATA_DEAD = 36,
	CPUHP_AP_DTPM_CPU_DEAD = 37,
	CPUHP_RANDOM_PREPARE = 38,
	CPUHP_WORKQUEUE_PREP = 39,
	CPUHP_POWER_NUMA_PREPARE = 40,
	CPUHP_HRTIMERS_PREPARE = 41,
	CPUHP_PROFILE_PREPARE = 42,
	CPUHP_X2APIC_PREPARE = 43,
	CPUHP_SMPCFD_PREPARE = 44,
	CPUHP_RELAY_PREPARE = 45,
	CPUHP_MD_RAID5_PREPARE = 46,
	CPUHP_RCUTREE_PREP = 47,
	CPUHP_CPUIDLE_COUPLED_PREPARE = 48,
	CPUHP_POWERPC_PMAC_PREPARE = 49,
	CPUHP_POWERPC_MMU_CTX_PREPARE = 50,
	CPUHP_XEN_PREPARE = 51,
	CPUHP_XEN_EVTCHN_PREPARE = 52,
	CPUHP_ARM_SHMOBILE_SCU_PREPARE = 53,
	CPUHP_SH_SH3X_PREPARE = 54,
	CPUHP_TOPOLOGY_PREPARE = 55,
	CPUHP_NET_IUCV_PREPARE = 56,
	CPUHP_ARM_BL_PREPARE = 57,
	CPUHP_TRACE_RB_PREPARE = 58,
	CPUHP_MM_ZS_PREPARE = 59,
	CPUHP_MM_ZSWP_POOL_PREPARE = 60,
	CPUHP_KVM_PPC_BOOK3S_PREPARE = 61,
	CPUHP_ZCOMP_PREPARE = 62,
	CPUHP_TIMERS_PREPARE = 63,
	CPUHP_MIPS_SOC_PREPARE = 64,
	CPUHP_BP_PREPARE_DYN = 65,
	CPUHP_BP_PREPARE_DYN_END = 85,
	CPUHP_BP_KICK_AP = 86,
	CPUHP_BRINGUP_CPU = 87,
	CPUHP_AP_IDLE_DEAD = 88,
	CPUHP_AP_OFFLINE = 89,
	CPUHP_AP_CACHECTRL_STARTING = 90,
	CPUHP_AP_SCHED_STARTING = 91,
	CPUHP_AP_RCUTREE_DYING = 92,
	CPUHP_AP_CPU_PM_STARTING = 93,
	CPUHP_AP_IRQ_GIC_STARTING = 94,
	CPUHP_AP_IRQ_HIP04_STARTING = 95,
	CPUHP_AP_IRQ_APPLE_AIC_STARTING = 96,
	CPUHP_AP_IRQ_ARMADA_XP_STARTING = 97,
	CPUHP_AP_IRQ_BCM2836_STARTING = 98,
	CPUHP_AP_IRQ_MIPS_GIC_STARTING = 99,
	CPUHP_AP_IRQ_LOONGARCH_STARTING = 100,
	CPUHP_AP_IRQ_SIFIVE_PLIC_STARTING = 101,
	CPUHP_AP_ARM_MVEBU_COHERENCY = 102,
	CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING = 103,
	CPUHP_AP_PERF_X86_STARTING = 104,
	CPUHP_AP_PERF_X86_AMD_IBS_STARTING = 105,
	CPUHP_AP_PERF_X86_CSTATE_STARTING = 106,
	CPUHP_AP_PERF_XTENSA_STARTING = 107,
	CPUHP_AP_ARM_VFP_STARTING = 108,
	CPUHP_AP_ARM64_DEBUG_MONITORS_STARTING = 109,
	CPUHP_AP_PERF_ARM_HW_BREAKPOINT_STARTING = 110,
	CPUHP_AP_PERF_ARM_ACPI_STARTING = 111,
	CPUHP_AP_PERF_ARM_STARTING = 112,
	CPUHP_AP_PERF_RISCV_STARTING = 113,
	CPUHP_AP_ARM_L2X0_STARTING = 114,
	CPUHP_AP_EXYNOS4_MCT_TIMER_STARTING = 115,
	CPUHP_AP_ARM_ARCH_TIMER_STARTING = 116,
	CPUHP_AP_ARM_ARCH_TIMER_EVTSTRM_STARTING = 117,
	CPUHP_AP_ARM_GLOBAL_TIMER_STARTING = 118,
	CPUHP_AP_JCORE_TIMER_STARTING = 119,
	CPUHP_AP_ARM_TWD_STARTING = 120,
	CPUHP_AP_QCOM_TIMER_STARTING = 121,
	CPUHP_AP_TEGRA_TIMER_STARTING = 122,
	CPUHP_AP_ARMADA_TIMER_STARTING = 123,
	CPUHP_AP_MIPS_GIC_TIMER_STARTING = 124,
	CPUHP_AP_ARC_TIMER_STARTING = 125,
	CPUHP_AP_RISCV_TIMER_STARTING = 126,
	CPUHP_AP_CLINT_TIMER_STARTING = 127,
	CPUHP_AP_CSKY_TIMER_STARTING = 128,
	CPUHP_AP_TI_GP_TIMER_STARTING = 129,
	CPUHP_AP_HYPERV_TIMER_STARTING = 130,
	CPUHP_AP_DUMMY_TIMER_STARTING = 131,
	CPUHP_AP_ARM_XEN_STARTING = 132,
	CPUHP_AP_ARM_XEN_RUNSTATE_STARTING = 133,
	CPUHP_AP_ARM_CORESIGHT_STARTING = 134,
	CPUHP_AP_ARM_CORESIGHT_CTI_STARTING = 135,
	CPUHP_AP_ARM64_ISNDEP_STARTING = 136,
	CPUHP_AP_SMPCFD_DYING = 137,
	CPUHP_AP_HRTIMERS_DYING = 138,
	CPUHP_AP_TICK_DYING = 139,
	CPUHP_AP_X86_TBOOT_DYING = 140,
	CPUHP_AP_ARM_CACHE_B15_RAC_DYING = 141,
	CPUHP_AP_ONLINE = 142,
	CPUHP_TEARDOWN_CPU = 143,
	CPUHP_AP_ONLINE_IDLE = 144,
	CPUHP_AP_HYPERV_ONLINE = 145,
	CPUHP_AP_KVM_ONLINE = 146,
	CPUHP_AP_SCHED_WAIT_EMPTY = 147,
	CPUHP_AP_SMPBOOT_THREADS = 148,
	CPUHP_AP_IRQ_AFFINITY_ONLINE = 149,
	CPUHP_AP_BLK_MQ_ONLINE = 150,
	CPUHP_AP_ARM_MVEBU_SYNC_CLOCKS = 151,
	CPUHP_AP_X86_INTEL_EPB_ONLINE = 152,
	CPUHP_AP_PERF_ONLINE = 153,
	CPUHP_AP_PERF_X86_ONLINE = 154,
	CPUHP_AP_PERF_X86_UNCORE_ONLINE = 155,
	CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE = 156,
	CPUHP_AP_PERF_X86_AMD_POWER_ONLINE = 157,
	CPUHP_AP_PERF_X86_RAPL_ONLINE = 158,
	CPUHP_AP_PERF_X86_CSTATE_ONLINE = 159,
	CPUHP_AP_PERF_S390_CF_ONLINE = 160,
	CPUHP_AP_PERF_S390_SF_ONLINE = 161,
	CPUHP_AP_PERF_ARM_CCI_ONLINE = 162,
	CPUHP_AP_PERF_ARM_CCN_ONLINE = 163,
	CPUHP_AP_PERF_ARM_HISI_CPA_ONLINE = 164,
	CPUHP_AP_PERF_ARM_HISI_DDRC_ONLINE = 165,
	CPUHP_AP_PERF_ARM_HISI_HHA_ONLINE = 166,
	CPUHP_AP_PERF_ARM_HISI_L3_ONLINE = 167,
	CPUHP_AP_PERF_ARM_HISI_PA_ONLINE = 168,
	CPUHP_AP_PERF_ARM_HISI_SLLC_ONLINE = 169,
	CPUHP_AP_PERF_ARM_HISI_PCIE_PMU_ONLINE = 170,
	CPUHP_AP_PERF_ARM_HNS3_PMU_ONLINE = 171,
	CPUHP_AP_PERF_ARM_L2X0_ONLINE = 172,
	CPUHP_AP_PERF_ARM_QCOM_L2_ONLINE = 173,
	CPUHP_AP_PERF_ARM_QCOM_L3_ONLINE = 174,
	CPUHP_AP_PERF_ARM_APM_XGENE_ONLINE = 175,
	CPUHP_AP_PERF_ARM_CAVIUM_TX2_UNCORE_ONLINE = 176,
	CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE = 177,
	CPUHP_AP_PERF_POWERPC_NEST_IMC_ONLINE = 178,
	CPUHP_AP_PERF_POWERPC_CORE_IMC_ONLINE = 179,
	CPUHP_AP_PERF_POWERPC_THREAD_IMC_ONLINE = 180,
	CPUHP_AP_PERF_POWERPC_TRACE_IMC_ONLINE = 181,
	CPUHP_AP_PERF_POWERPC_HV_24x7_ONLINE = 182,
	CPUHP_AP_PERF_POWERPC_HV_GPCI_ONLINE = 183,
	CPUHP_AP_PERF_CSKY_ONLINE = 184,
	CPUHP_AP_TMIGR_ONLINE = 185,
	CPUHP_AP_WATCHDOG_ONLINE = 186,
	CPUHP_AP_WORKQUEUE_ONLINE = 187,
	CPUHP_AP_RANDOM_ONLINE = 188,
	CPUHP_AP_RCUTREE_ONLINE = 189,
	CPUHP_AP_BASE_CACHEINFO_ONLINE = 190,
	CPUHP_AP_ONLINE_DYN = 191,
	CPUHP_AP_ONLINE_DYN_END = 231,
	CPUHP_AP_X86_HPET_ONLINE = 232,
	CPUHP_AP_X86_KVM_CLK_ONLINE = 233,
	CPUHP_AP_ACTIVE = 234,
	CPUHP_ONLINE = 235,
};

enum {
	X86_PERF_KFREE_SHARED = 0,
	X86_PERF_KFREE_EXCL = 1,
	X86_PERF_KFREE_MAX = 2,
};

enum extra_reg_type {
	EXTRA_REG_NONE = -1,
	EXTRA_REG_RSP_0 = 0,
	EXTRA_REG_RSP_1 = 1,
	EXTRA_REG_LBR = 2,
	EXTRA_REG_LDLAT = 3,
	EXTRA_REG_FE = 4,
	EXTRA_REG_SNOOP_0 = 5,
	EXTRA_REG_SNOOP_1 = 6,
	EXTRA_REG_MAX = 7,
};

struct perf_pmu_events_ht_attr {
	struct device_attribute attr;
	u64 id;
	const char *event_str_ht;
	const char *event_str_noht;
};

struct perf_pmu_events_hybrid_attr {
	struct device_attribute attr;
	u64 id;
	const char *event_str;
	u64 pmu_type;
};

struct stack_frame {
	struct stack_frame *next_frame;
	unsigned long return_address;
};

struct sched_state {
	int weight;
	int event;
	int counter;
	int unassigned;
	int nr_gp;
	u64 used;
};

struct perf_sched {
	int max_weight;
	int max_events;
	int max_gp;
	int saved_states;
	struct event_constraint **constraints;
	struct sched_state state;
	struct sched_state saved[2];
};

struct cyc2ns_data {
	u32 cyc2ns_mul;
	u32 cyc2ns_shift;
	u64 cyc2ns_offset;
};

struct perf_callchain_entry_ctx {
	struct perf_callchain_entry *entry;
	u32 max_stack;
	u32 nr;
	short contexts;
	bool contexts_maxed;
};

struct stack_info {
	enum stack_type type;
	unsigned long *begin;
	unsigned long *end;
	unsigned long *next_sp;
};

struct unwind_state {
	struct stack_info stack_info;
	unsigned long stack_mask;
	struct task_struct *task;
	int graph_idx;
	bool error;
	unsigned long *sp;
};

typedef bool (*smp_cond_func_t)(int, void *);

struct perf_event_mmap_page {
	__u32 version;
	__u32 compat_version;
	__u32 lock;
	__u32 index;
	__s64 offset;
	__u64 time_enabled;
	__u64 time_running;
	union {
		__u64 capabilities;
		struct {
			__u64 cap_bit0: 1;
			__u64 cap_bit0_is_deprecated: 1;
			__u64 cap_user_rdpmc: 1;
			__u64 cap_user_time: 1;
			__u64 cap_user_time_zero: 1;
			__u64 cap_user_time_short: 1;
			__u64 cap_____res: 58;
		};
	};
	__u16 pmc_width;
	__u16 time_shift;
	__u32 time_mult;
	__u64 time_offset;
	__u64 time_zero;
	__u32 size;
	__u32 __reserved_1;
	__u64 time_cycles;
	__u64 time_mask;
	__u8 __reserved[928];
	__u64 data_head;
	__u64 data_tail;
	__u64 data_offset;
	__u64 data_size;
	__u64 aux_head;
	__u64 aux_tail;
	__u64 aux_offset;
	__u64 aux_size;
};

struct x86_pmu_capability {
	int version;
	int num_counters_gp;
	int num_counters_fixed;
	int bit_width_gp;
	int bit_width_fixed;
	unsigned int events_mask;
	int events_mask_len;
	unsigned int pebs_ept: 1;
};

enum {
	IRQ_DOMAIN_FLAG_HIERARCHY = 1,
	IRQ_DOMAIN_NAME_ALLOCATED = 2,
	IRQ_DOMAIN_FLAG_IPI_PER_CPU = 4,
	IRQ_DOMAIN_FLAG_IPI_SINGLE = 8,
	IRQ_DOMAIN_FLAG_MSI = 16,
	IRQ_DOMAIN_FLAG_ISOLATED_MSI = 32,
	IRQ_DOMAIN_FLAG_NO_MAP = 64,
	IRQ_DOMAIN_FLAG_MSI_PARENT = 256,
	IRQ_DOMAIN_FLAG_MSI_DEVICE = 512,
	IRQ_DOMAIN_FLAG_NONCORE = 65536,
};

enum {
	IRQ_TYPE_NONE = 0,
	IRQ_TYPE_EDGE_RISING = 1,
	IRQ_TYPE_EDGE_FALLING = 2,
	IRQ_TYPE_EDGE_BOTH = 3,
	IRQ_TYPE_LEVEL_HIGH = 4,
	IRQ_TYPE_LEVEL_LOW = 8,
	IRQ_TYPE_LEVEL_MASK = 12,
	IRQ_TYPE_SENSE_MASK = 15,
	IRQ_TYPE_DEFAULT = 15,
	IRQ_TYPE_PROBE = 16,
	IRQ_LEVEL = 256,
	IRQ_PER_CPU = 512,
	IRQ_NOPROBE = 1024,
	IRQ_NOREQUEST = 2048,
	IRQ_NOAUTOEN = 4096,
	IRQ_NO_BALANCING = 8192,
	IRQ_MOVE_PCNTXT = 16384,
	IRQ_NESTED_THREAD = 32768,
	IRQ_NOTHREAD = 65536,
	IRQ_PER_CPU_DEVID = 131072,
	IRQ_IS_POLLED = 262144,
	IRQ_DISABLE_UNLAZY = 524288,
	IRQ_HIDDEN = 1048576,
	IRQ_NO_DEBUG = 2097152,
};

struct irqchip_fwid {
	struct fwnode_handle fwnode;
	unsigned int type;
	char *name;
	phys_addr_t *pa;
};

struct of_phandle_args {
	struct device_node *np;
	int args_count;
	uint32_t args[16];
};

enum {
	BTF_KIND_UNKN = 0,
	BTF_KIND_INT = 1,
	BTF_KIND_PTR = 2,
	BTF_KIND_ARRAY = 3,
	BTF_KIND_STRUCT = 4,
	BTF_KIND_UNION = 5,
	BTF_KIND_ENUM = 6,
	BTF_KIND_FWD = 7,
	BTF_KIND_TYPEDEF = 8,
	BTF_KIND_VOLATILE = 9,
	BTF_KIND_CONST = 10,
	BTF_KIND_RESTRICT = 11,
	BTF_KIND_FUNC = 12,
	BTF_KIND_FUNC_PROTO = 13,
	BTF_KIND_VAR = 14,
	BTF_KIND_DATASEC = 15,
	BTF_KIND_FLOAT = 16,
	BTF_KIND_DECL_TAG = 17,
	BTF_KIND_TYPE_TAG = 18,
	BTF_KIND_ENUM64 = 19,
	NR_BTF_KINDS = 20,
	BTF_KIND_MAX = 19,
};

enum work_bits {
	WORK_STRUCT_PENDING_BIT = 0,
	WORK_STRUCT_INACTIVE_BIT = 1,
	WORK_STRUCT_PWQ_BIT = 2,
	WORK_STRUCT_LINKED_BIT = 3,
	WORK_STRUCT_FLAG_BITS = 4,
	WORK_STRUCT_COLOR_SHIFT = 4,
	WORK_STRUCT_COLOR_BITS = 4,
	WORK_STRUCT_PWQ_SHIFT = 8,
	WORK_OFFQ_FLAG_SHIFT = 4,
	WORK_OFFQ_CANCELING_BIT = 4,
	WORK_OFFQ_FLAG_END = 5,
	WORK_OFFQ_FLAG_BITS = 1,
	WORK_OFFQ_POOL_SHIFT = 5,
	WORK_OFFQ_LEFT = 59,
	WORK_OFFQ_POOL_BITS = 31,
};

enum bpf_jit_poke_reason {
	BPF_POKE_REASON_TAIL_CALL = 0,
};

struct bpf_array_aux;

struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	u32 index_mask;
	struct bpf_array_aux *aux;
	union {
		struct {
			struct {} __empty_value;
			char value[0];
		};
		struct {
			struct {} __empty_ptrs;
			void *ptrs[0];
		};
		struct {
			struct {} __empty_pptrs;
			void __attribute__((btf_type_tag("percpu"))) *pptrs[0];
		};
	};
};

struct bpf_array_aux {
	struct list_head poke_progs;
	struct bpf_map *map;
	struct mutex poke_mutex;
	struct work_struct work;
};

struct prog_poke_elem {
	struct list_head list;
	struct bpf_prog_aux *aux;
};

struct bpf_event_entry {
	struct perf_event *event;
	struct file *perf_file;
	struct file *map_file;
	struct callback_head rcu;
};

struct bpf_iter_seq_array_map_info {
	struct bpf_map *map;
	void *percpu_value_buf;
	u32 index;
};

enum fs_value_type {
	fs_value_is_undefined = 0,
	fs_value_is_flag = 1,
	fs_value_is_string = 2,
	fs_value_is_blob = 3,
	fs_value_is_filename = 4,
	fs_value_is_file = 5,
};

enum fs_context_purpose {
	FS_CONTEXT_FOR_MOUNT = 0,
	FS_CONTEXT_FOR_SUBMOUNT = 1,
	FS_CONTEXT_FOR_RECONFIGURE = 2,
};

enum fs_context_phase {
	FS_CONTEXT_CREATE_PARAMS = 0,
	FS_CONTEXT_CREATING = 1,
	FS_CONTEXT_AWAITING_MOUNT = 2,
	FS_CONTEXT_AWAITING_RECONF = 3,
	FS_CONTEXT_RECONF_PARAMS = 4,
	FS_CONTEXT_RECONFIGURING = 5,
	FS_CONTEXT_FAILED = 6,
};

enum zone_type {
	ZONE_DMA32 = 0,
	ZONE_NORMAL = 1,
	ZONE_MOVABLE = 2,
	__MAX_NR_ZONES = 3,
};

enum node_stat_item {
	NR_LRU_BASE = 0,
	NR_INACTIVE_ANON = 0,
	NR_ACTIVE_ANON = 1,
	NR_INACTIVE_FILE = 2,
	NR_ACTIVE_FILE = 3,
	NR_UNEVICTABLE = 4,
	NR_SLAB_RECLAIMABLE_B = 5,
	NR_SLAB_UNRECLAIMABLE_B = 6,
	NR_ISOLATED_ANON = 7,
	NR_ISOLATED_FILE = 8,
	WORKINGSET_NODES = 9,
	WORKINGSET_REFAULT_BASE = 10,
	WORKINGSET_REFAULT_ANON = 10,
	WORKINGSET_REFAULT_FILE = 11,
	WORKINGSET_ACTIVATE_BASE = 12,
	WORKINGSET_ACTIVATE_ANON = 12,
	WORKINGSET_ACTIVATE_FILE = 13,
	WORKINGSET_RESTORE_BASE = 14,
	WORKINGSET_RESTORE_ANON = 14,
	WORKINGSET_RESTORE_FILE = 15,
	WORKINGSET_NODERECLAIM = 16,
	NR_ANON_MAPPED = 17,
	NR_FILE_MAPPED = 18,
	NR_FILE_PAGES = 19,
	NR_FILE_DIRTY = 20,
	NR_WRITEBACK = 21,
	NR_WRITEBACK_TEMP = 22,
	NR_SHMEM = 23,
	NR_SHMEM_THPS = 24,
	NR_SHMEM_PMDMAPPED = 25,
	NR_FILE_THPS = 26,
	NR_FILE_PMDMAPPED = 27,
	NR_ANON_THPS = 28,
	NR_VMSCAN_WRITE = 29,
	NR_VMSCAN_IMMEDIATE = 30,
	NR_DIRTIED = 31,
	NR_WRITTEN = 32,
	NR_THROTTLED_WRITTEN = 33,
	NR_KERNEL_MISC_RECLAIMABLE = 34,
	NR_FOLL_PIN_ACQUIRED = 35,
	NR_FOLL_PIN_RELEASED = 36,
	NR_KERNEL_STACK_KB = 37,
	NR_PAGETABLE = 38,
	NR_SECONDARY_PAGETABLE = 39,
	PGDEMOTE_KSWAPD = 40,
	PGDEMOTE_DIRECT = 41,
	PGDEMOTE_KHUGEPAGED = 42,
	NR_VM_NODE_STAT_ITEMS = 43,
};

enum lru_status {
	LRU_REMOVED = 0,
	LRU_REMOVED_RETRY = 1,
	LRU_ROTATE = 2,
	LRU_SKIP = 3,
	LRU_RETRY = 4,
	LRU_STOP = 5,
};

struct fc_log;

struct p_log {
	const char *prefix;
	struct fc_log *log;
};

struct fs_context_operations;

struct fs_context {
	const struct fs_context_operations *ops;
	struct mutex uapi_mutex;
	struct file_system_type *fs_type;
	void *fs_private;
	void *sget_key;
	struct dentry *root;
	struct user_namespace *user_ns;
	struct net *net_ns;
	const struct cred *cred;
	struct p_log log;
	const char *source;
	void *security;
	void *s_fs_info;
	unsigned int sb_flags;
	unsigned int sb_flags_mask;
	unsigned int s_iflags;
	enum fs_context_purpose purpose: 8;
	enum fs_context_phase phase: 8;
	bool need_free: 1;
	bool global: 1;
	bool oldapi: 1;
	bool exclusive: 1;
};

struct fs_context_operations {
	void (*free)(struct fs_context *);
	int (*dup)(struct fs_context *, struct fs_context *);
	int (*parse_param)(struct fs_context *, struct fs_parameter *);
	int (*parse_monolithic)(struct fs_context *, void *);
	int (*get_tree)(struct fs_context *);
	int (*reconfigure)(struct fs_context *);
};

struct filename;

struct fs_parameter {
	const char *key;
	enum fs_value_type type: 8;
	union {
		char *string;
		void *blob;
		struct filename *name;
		struct file *file;
	};
	size_t size;
	int dirfd;
};

struct audit_names;

struct filename {
	const char *name;
	const char __attribute__((btf_type_tag("user"))) *uptr;
	atomic_t refcnt;
	struct audit_names *aname;
	const char iname[0];
};

struct anon_vma {
	struct anon_vma *root;
	struct rw_semaphore rwsem;
	atomic_t refcount;
	unsigned long num_children;
	unsigned long num_active_vmas;
	struct anon_vma *parent;
	struct rb_root_cached rb_root;
};

struct fc_log {
	refcount_t usage;
	u8 head;
	u8 tail;
	u8 need_free;
	struct module *owner;
	char *buffer[8];
};

struct fs_parse_result {
	bool negated;
	union {
		bool boolean;
		int int_32;
		unsigned int uint_32;
		u64 uint_64;
	};
};

struct free_area {
	struct list_head free_list[4];
	unsigned long nr_free;
};

struct pglist_data;

struct per_cpu_pages;

struct per_cpu_zonestat;

struct zone {
	unsigned long _watermark[4];
	unsigned long watermark_boost;
	unsigned long nr_reserved_highatomic;
	long lowmem_reserve[3];
	struct pglist_data *zone_pgdat;
	struct per_cpu_pages __attribute__((btf_type_tag("percpu"))) *per_cpu_pageset;
	struct per_cpu_zonestat __attribute__((btf_type_tag("percpu"))) *per_cpu_zonestats;
	int pageset_high_min;
	int pageset_high_max;
	int pageset_batch;
	unsigned long zone_start_pfn;
	atomic_long_t managed_pages;
	unsigned long spanned_pages;
	unsigned long present_pages;
	const char *name;
	int initialized;
	struct free_area free_area[11];
	unsigned long flags;
	spinlock_t lock;
	unsigned long percpu_drift_mark;
	bool contiguous;
	atomic_long_t vm_stat[10];
	atomic_long_t vm_numa_event[0];
};

struct zoneref {
	struct zone *zone;
	int zone_idx;
};

struct zonelist {
	struct zoneref _zonerefs[4];
};

struct zswap_lruvec_state {};

struct lruvec {
	struct list_head lists[5];
	spinlock_t lru_lock;
	unsigned long anon_cost;
	unsigned long file_cost;
	atomic_long_t nonresident_age;
	unsigned long refaults[2];
	unsigned long flags;
	struct zswap_lruvec_state zswap_lruvec_state;
};

struct per_cpu_nodestat;

struct pglist_data {
	struct zone node_zones[3];
	struct zonelist node_zonelists[1];
	int nr_zones;
	unsigned long node_start_pfn;
	unsigned long node_present_pages;
	unsigned long node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	unsigned long nr_reclaim_start;
	struct task_struct *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	unsigned long totalreserve_pages;
	struct lruvec __lruvec;
	unsigned long flags;
	struct per_cpu_nodestat __attribute__((btf_type_tag("percpu"))) *per_cpu_nodestats;
	atomic_long_t vm_stat[43];
};

struct per_cpu_pages {
	spinlock_t lock;
	int count;
	int high;
	int high_min;
	int high_max;
	int batch;
	u8 flags;
	u8 alloc_factor;
	short free_count;
	struct list_head lists[12];
};

struct per_cpu_zonestat {};

typedef signed char __s8;

typedef __s8 s8;

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[43];
};

struct xa_node {
	unsigned char shift;
	unsigned char offset;
	unsigned char count;
	unsigned char nr_values;
	struct xa_node __attribute__((btf_type_tag("rcu"))) *parent;
	struct xarray *array;
	union {
		struct list_head private_list;
		struct callback_head callback_head;
	};
	void __attribute__((btf_type_tag("rcu"))) *slots[16];
	union {
		unsigned long tags[3];
		unsigned long marks[3];
	};
};

typedef struct pglist_data pg_data_t;

typedef enum lru_status (*list_lru_walk_cb)(struct list_head *, struct list_lru_one *, spinlock_t *, void *);

typedef void (*xa_update_node_t)(struct xa_node *);

struct dma_page {
	struct list_head page_list;
	void *vaddr;
	dma_addr_t dma;
};

struct dma_block;

struct dma_pool {
	struct list_head page_list;
	spinlock_t lock;
	struct dma_block *next_block;
	size_t nr_blocks;
	size_t nr_active;
	size_t nr_pages;
	struct device *dev;
	unsigned int size;
	unsigned int allocation;
	unsigned int boundary;
	char name[32];
	struct list_head pools;
};

struct dma_block {
	struct dma_block *next_block;
	dma_addr_t dma;
};

typedef void (*dr_release_t)(struct device *, void *);

typedef int (*dr_match_t)(struct device *, void *, void *);

struct fiemap_extent;

struct fiemap_extent_info {
	unsigned int fi_flags;
	unsigned int fi_extents_mapped;
	unsigned int fi_extents_max;
	struct fiemap_extent __attribute__((btf_type_tag("user"))) *fi_extents_start;
};

struct fiemap_extent {
	__u64 fe_logical;
	__u64 fe_physical;
	__u64 fe_length;
	__u64 fe_reserved64[2];
	__u32 fe_flags;
	__u32 fe_reserved[3];
};

struct nsset {
	unsigned int flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
};

struct stashed_operations {
	void (*put_data)(void *);
	int (*init_inode)(struct inode *, void *);
};

struct ns_get_path_task_args {
	const struct proc_ns_operations *ns_ops;
	struct task_struct *task;
};

typedef struct ns_common *ns_get_path_helper_t(void *);

struct pseudo_fs_context {
	const struct super_operations *ops;
	const struct xattr_handler * const *xattr;
	const struct dentry_operations *dops;
	unsigned long magic;
};

typedef __kernel_ulong_t ino_t;

enum devm_ioremap_type {
	DEVM_IOREMAP = 0,
	DEVM_IOREMAP_UC = 1,
	DEVM_IOREMAP_WC = 2,
	DEVM_IOREMAP_NP = 3,
};

typedef phys_addr_t resource_size_t;

struct resource {
	resource_size_t start;
	resource_size_t end;
	const char *name;
	unsigned long flags;
	unsigned long desc;
	struct resource *parent;
	struct resource *sibling;
	struct resource *child;
};

struct arch_io_reserve_memtype_wc_devres {
	resource_size_t start;
	resource_size_t size;
};

struct rtc_time {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

struct mc146818_get_time_callback_param {
	struct rtc_time *time;
	unsigned char ctrl;
};

typedef struct {} local_lock_t;

struct radix_tree_preload {
	local_lock_t lock;
	unsigned int nr;
	struct xa_node *nodes;
};

enum {
	RADIX_TREE_ITER_TAG_MASK = 15,
	RADIX_TREE_ITER_TAGGED = 16,
	RADIX_TREE_ITER_CONTIG = 32,
};

struct radix_tree_iter {
	unsigned long index;
	unsigned long next_index;
	unsigned long tags;
	struct xa_node *node;
};

struct kernel_param_ops;

struct kparam_string;

struct kparam_array;

struct kernel_param {
	const char *name;
	struct module *mod;
	const struct kernel_param_ops *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array *arr;
	};
};

struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
	void (*free)(void *);
};

struct kparam_string {
	unsigned int maxlen;
	char *string;
};

struct kparam_array {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops *ops;
	void *elem;
};

enum system_states {
	SYSTEM_BOOTING = 0,
	SYSTEM_SCHEDULING = 1,
	SYSTEM_FREEING_INITMEM = 2,
	SYSTEM_RUNNING = 3,
	SYSTEM_HALT = 4,
	SYSTEM_POWER_OFF = 5,
	SYSTEM_RESTART = 6,
	SYSTEM_SUSPEND = 7,
};

typedef int initcall_entry_t;

enum blk_unique_id {
	BLK_UID_T10 = 1,
	BLK_UID_EUI64 = 2,
	BLK_UID_NAA = 3,
};

enum blk_bounce {
	BLK_BOUNCE_NONE = 0,
	BLK_BOUNCE_HIGH = 1,
};

enum node_states {
	N_POSSIBLE = 0,
	N_ONLINE = 1,
	N_NORMAL_MEMORY = 2,
	N_HIGH_MEMORY = 2,
	N_MEMORY = 3,
	N_CPU = 4,
	N_GENERIC_INITIATOR = 5,
	NR_NODE_STATES = 6,
};

enum refcount_saturation_type {
	REFCOUNT_ADD_NOT_ZERO_OVF = 0,
	REFCOUNT_ADD_OVF = 1,
	REFCOUNT_ADD_UAF = 2,
	REFCOUNT_SUB_UAF = 3,
	REFCOUNT_DEC_LEAK = 4,
};

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct uts_namespace {
	struct new_utsname name;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
};

struct bio_alloc_cache;

typedef void *mempool_alloc_t(gfp_t, void *);

typedef void mempool_free_t(void *, void *);

struct mempool_s {
	spinlock_t lock;
	int min_nr;
	int curr_nr;
	void **elements;
	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
};

typedef struct mempool_s mempool_t;

struct bio;

struct bio_list {
	struct bio *head;
	struct bio *tail;
};

struct bio_set {
	struct kmem_cache *bio_slab;
	unsigned int front_pad;
	struct bio_alloc_cache __attribute__((btf_type_tag("percpu"))) *cache;
	mempool_t bio_pool;
	mempool_t bvec_pool;
	unsigned int back_pad;
	spinlock_t rescue_lock;
	struct bio_list rescue_list;
	struct work_struct rescue_work;
	struct workqueue_struct *rescue_workqueue;
	struct hlist_node cpuhp_dead;
};

struct disk_events;

struct badblocks;

typedef unsigned int blk_mode_t;

struct block_device_operations;

struct timer_rand_state;

struct blk_independent_access_ranges;

struct gendisk {
	int major;
	int first_minor;
	int minors;
	char disk_name[32];
	unsigned short events;
	unsigned short event_flags;
	struct xarray part_tbl;
	struct block_device *part0;
	const struct block_device_operations *fops;
	struct request_queue *queue;
	void *private_data;
	struct bio_set bio_split;
	int flags;
	unsigned long state;
	struct mutex open_mutex;
	unsigned int open_partitions;
	struct backing_dev_info *bdi;
	struct kobject queue_kobj;
	struct kobject *slave_dir;
	struct timer_rand_state *random;
	atomic_t sync_io;
	struct disk_events *ev;
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
	u64 diskseq;
	blk_mode_t open_mode;
	struct blk_independent_access_ranges *ia_ranges;
};

struct hd_geometry;

struct blk_zone;

typedef int (*report_zones_cb)(struct blk_zone *, unsigned int, void *);

struct pr_ops;

struct block_device_operations {
	void (*submit_bio)(struct bio *);
	int (*poll_bio)(struct bio *, struct io_comp_batch *, unsigned int);
	int (*open)(struct gendisk *, blk_mode_t);
	void (*release)(struct gendisk *);
	int (*ioctl)(struct block_device *, blk_mode_t, unsigned int, unsigned long);
	int (*compat_ioctl)(struct block_device *, blk_mode_t, unsigned int, unsigned long);
	unsigned int (*check_events)(struct gendisk *, unsigned int);
	void (*unlock_native_capacity)(struct gendisk *);
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	int (*set_read_only)(struct block_device *, bool);
	void (*free_disk)(struct gendisk *);
	void (*swap_slot_free_notify)(struct block_device *, unsigned long);
	int (*report_zones)(struct gendisk *, sector_t, unsigned int, report_zones_cb, void *);
	char * (*devnode)(struct gendisk *, umode_t *);
	int (*get_unique_id)(struct gendisk *, u8 *, enum blk_unique_id);
	struct module *owner;
	const struct pr_ops *pr_ops;
	int (*alternative_gpt_sector)(struct gendisk *, sector_t *);
};

typedef __u32 blk_opf_t;

typedef u8 blk_status_t;

struct bvec_iter {
	sector_t bi_sector;
	unsigned int bi_size;
	unsigned int bi_idx;
	unsigned int bi_bvec_done;
} __attribute__((packed));

typedef unsigned int blk_qc_t;

typedef void bio_end_io_t(struct bio *);

struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	blk_opf_t bi_opf;
	unsigned short bi_flags;
	unsigned short bi_ioprio;
	enum rw_hint bi_write_hint;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t *bi_end_io;
	void *bi_private;
	union {};
	unsigned short bi_vcnt;
	unsigned short bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec bi_inline_vecs[0];
};

struct request;

struct io_comp_batch {
	struct request *req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};

struct blk_zone {
	__u64 start;
	__u64 len;
	__u64 wp;
	__u8 type;
	__u8 cond;
	__u8 non_seq;
	__u8 reset;
	__u8 resv[4];
	__u64 capacity;
	__u8 reserved[24];
};

struct elevator_queue;

struct blk_mq_ops;

struct blk_mq_ctx;

struct queue_limits {
	enum blk_bounce bounce;
	unsigned long seg_boundary_mask;
	unsigned long virt_boundary_mask;
	unsigned int max_hw_sectors;
	unsigned int max_dev_sectors;
	unsigned int chunk_sectors;
	unsigned int max_sectors;
	unsigned int max_user_sectors;
	unsigned int max_segment_size;
	unsigned int physical_block_size;
	unsigned int logical_block_size;
	unsigned int alignment_offset;
	unsigned int io_min;
	unsigned int io_opt;
	unsigned int max_discard_sectors;
	unsigned int max_hw_discard_sectors;
	unsigned int max_user_discard_sectors;
	unsigned int max_secure_erase_sectors;
	unsigned int max_write_zeroes_sectors;
	unsigned int max_zone_append_sectors;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	unsigned int zone_write_granularity;
	unsigned short max_segments;
	unsigned short max_integrity_segments;
	unsigned short max_discard_segments;
	unsigned char misaligned;
	unsigned char discard_misaligned;
	unsigned char raid_partial_stripes_expensive;
	bool zoned;
	unsigned int max_open_zones;
	unsigned int max_active_zones;
	unsigned int dma_alignment;
};

struct blk_queue_stats;

struct rq_qos;

struct blk_mq_tags;

struct blk_flush_queue;

struct blk_mq_tag_set;

struct request_queue {
	void *queuedata;
	struct elevator_queue *elevator;
	const struct blk_mq_ops *mq_ops;
	struct blk_mq_ctx __attribute__((btf_type_tag("percpu"))) *queue_ctx;
	unsigned long queue_flags;
	unsigned int rq_timeout;
	unsigned int queue_depth;
	refcount_t refs;
	unsigned int nr_hw_queues;
	struct xarray hctx_table;
	struct percpu_ref q_usage_counter;
	struct request *last_merge;
	spinlock_t queue_lock;
	int quiesce_depth;
	struct gendisk *disk;
	struct kobject *mq_kobj;
	struct queue_limits limits;
	atomic_t pm_only;
	struct blk_queue_stats *stats;
	struct rq_qos *rq_qos;
	struct mutex rq_qos_mutex;
	int id;
	unsigned int dma_pad_mask;
	unsigned long nr_requests;
	struct timer_list timeout;
	struct work_struct timeout_work;
	atomic_t nr_active_requests_shared_tags;
	unsigned int required_elevator_features;
	struct blk_mq_tags *sched_shared_tags;
	struct list_head icq_list;
	int node;
	spinlock_t requeue_lock;
	struct list_head requeue_list;
	struct delayed_work requeue_work;
	struct blk_flush_queue *fq;
	struct list_head flush_list;
	struct mutex sysfs_lock;
	struct mutex sysfs_dir_lock;
	struct mutex limits_lock;
	struct list_head unused_hctx_list;
	spinlock_t unused_hctx_lock;
	int mq_freeze_depth;
	struct callback_head callback_head;
	wait_queue_head_t mq_freeze_wq;
	struct mutex mq_freeze_lock;
	struct blk_mq_tag_set *tag_set;
	struct list_head tag_set_list;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct dentry *rqos_debugfs_dir;
	struct mutex debugfs_mutex;
	bool mq_sysfs_init_done;
};

struct blk_independent_access_range {
	struct kobject kobj;
	sector_t sector;
	sector_t nr_sectors;
};

struct blk_independent_access_ranges {
	struct kobject kobj;
	bool sysfs_registered;
	unsigned int nr_ia_ranges;
	struct blk_independent_access_range ia_range[0];
};

struct partition_meta_info {
	char uuid[37];
	u8 volname[64];
};

struct linux_binprm;

struct linux_binfmt {
	struct list_head lh;
	struct module *module;
	int (*load_binary)(struct linux_binprm *);
	int (*load_shlib)(struct file *);
};

struct linux_binprm {
	struct vm_area_struct *vma;
	unsigned long vma_pages;
	struct mm_struct *mm;
	unsigned long p;
	unsigned long argmin;
	unsigned int have_execfd: 1;
	unsigned int execfd_creds: 1;
	unsigned int secureexec: 1;
	unsigned int point_of_no_return: 1;
	struct file *executable;
	struct file *interpreter;
	struct file *file;
	struct cred *cred;
	int unsafe;
	unsigned int per_clear;
	int argc;
	int envc;
	const char *filename;
	const char *interp;
	const char *fdpath;
	unsigned int interp_flags;
	int execfd;
	unsigned long loader;
	unsigned long exec;
	struct rlimit rlim_stack;
	char buf[256];
};

struct blk_plug {};

typedef int (*parse_unknown_fn)(char *, char *, const char *, void *);

typedef int (*initcall_t)();

enum perf_sample_regs_abi {
	PERF_SAMPLE_REGS_ABI_NONE = 0,
	PERF_SAMPLE_REGS_ABI_32 = 1,
	PERF_SAMPLE_REGS_ABI_64 = 2,
};

struct x86_perf_regs {
	struct pt_regs regs;
	u64 *xmm_regs;
};

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE = 0,
	RWSEM_WAITING_FOR_READ = 1,
};

enum rwsem_wake_type {
	RWSEM_WAKE_ANY = 0,
	RWSEM_WAKE_READERS = 1,
	RWSEM_WAKE_READ_OWNED = 2,
};

enum owner_state {
	OWNER_NULL = 1,
	OWNER_WRITER = 2,
	OWNER_READER = 4,
	OWNER_NONSPINNABLE = 8,
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
	unsigned long timeout;
	bool handoff_set;
};

enum {
	GP_IDLE = 0,
	GP_ENTER = 1,
	GP_PASSED = 2,
	GP_EXIT = 3,
	GP_REPLAY = 4,
};

struct rcu_cblist {
	struct callback_head *head;
	struct callback_head **tail;
	long len;
};

struct rcu_segcblist {
	struct callback_head *head;
	struct callback_head **tails[4];
	unsigned long gp_seq[4];
	long len;
	long seglen[4];
	u8 flags;
};

enum syscall_work_bit {
	SYSCALL_WORK_BIT_SECCOMP = 0,
	SYSCALL_WORK_BIT_SYSCALL_TRACEPOINT = 1,
	SYSCALL_WORK_BIT_SYSCALL_TRACE = 2,
	SYSCALL_WORK_BIT_SYSCALL_EMU = 3,
	SYSCALL_WORK_BIT_SYSCALL_AUDIT = 4,
	SYSCALL_WORK_BIT_SYSCALL_USER_DISPATCH = 5,
	SYSCALL_WORK_BIT_SYSCALL_EXIT_TRAP = 6,
};

struct ptrace_sud_config {
	__u64 mode;
	__u64 selector;
	__u64 offset;
	__u64 len;
};

union bpf_iter_link_info;

typedef int (*bpf_iter_attach_target_t)(struct bpf_prog *, union bpf_iter_link_info *, struct bpf_iter_aux_info *);

typedef void (*bpf_iter_detach_target_t)(struct bpf_iter_aux_info *);

typedef void (*bpf_iter_show_fdinfo_t)(const struct bpf_iter_aux_info *, struct seq_file *);

struct bpf_link_info;

typedef int (*bpf_iter_fill_link_info_t)(const struct bpf_iter_aux_info *, struct bpf_link_info *);

enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_probe_read = 4,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_get_prandom_u32 = 7,
	BPF_FUNC_get_smp_processor_id = 8,
	BPF_FUNC_skb_store_bytes = 9,
	BPF_FUNC_l3_csum_replace = 10,
	BPF_FUNC_l4_csum_replace = 11,
	BPF_FUNC_tail_call = 12,
	BPF_FUNC_clone_redirect = 13,
	BPF_FUNC_get_current_pid_tgid = 14,
	BPF_FUNC_get_current_uid_gid = 15,
	BPF_FUNC_get_current_comm = 16,
	BPF_FUNC_get_cgroup_classid = 17,
	BPF_FUNC_skb_vlan_push = 18,
	BPF_FUNC_skb_vlan_pop = 19,
	BPF_FUNC_skb_get_tunnel_key = 20,
	BPF_FUNC_skb_set_tunnel_key = 21,
	BPF_FUNC_perf_event_read = 22,
	BPF_FUNC_redirect = 23,
	BPF_FUNC_get_route_realm = 24,
	BPF_FUNC_perf_event_output = 25,
	BPF_FUNC_skb_load_bytes = 26,
	BPF_FUNC_get_stackid = 27,
	BPF_FUNC_csum_diff = 28,
	BPF_FUNC_skb_get_tunnel_opt = 29,
	BPF_FUNC_skb_set_tunnel_opt = 30,
	BPF_FUNC_skb_change_proto = 31,
	BPF_FUNC_skb_change_type = 32,
	BPF_FUNC_skb_under_cgroup = 33,
	BPF_FUNC_get_hash_recalc = 34,
	BPF_FUNC_get_current_task = 35,
	BPF_FUNC_probe_write_user = 36,
	BPF_FUNC_current_task_under_cgroup = 37,
	BPF_FUNC_skb_change_tail = 38,
	BPF_FUNC_skb_pull_data = 39,
	BPF_FUNC_csum_update = 40,
	BPF_FUNC_set_hash_invalid = 41,
	BPF_FUNC_get_numa_node_id = 42,
	BPF_FUNC_skb_change_head = 43,
	BPF_FUNC_xdp_adjust_head = 44,
	BPF_FUNC_probe_read_str = 45,
	BPF_FUNC_get_socket_cookie = 46,
	BPF_FUNC_get_socket_uid = 47,
	BPF_FUNC_set_hash = 48,
	BPF_FUNC_setsockopt = 49,
	BPF_FUNC_skb_adjust_room = 50,
	BPF_FUNC_redirect_map = 51,
	BPF_FUNC_sk_redirect_map = 52,
	BPF_FUNC_sock_map_update = 53,
	BPF_FUNC_xdp_adjust_meta = 54,
	BPF_FUNC_perf_event_read_value = 55,
	BPF_FUNC_perf_prog_read_value = 56,
	BPF_FUNC_getsockopt = 57,
	BPF_FUNC_override_return = 58,
	BPF_FUNC_sock_ops_cb_flags_set = 59,
	BPF_FUNC_msg_redirect_map = 60,
	BPF_FUNC_msg_apply_bytes = 61,
	BPF_FUNC_msg_cork_bytes = 62,
	BPF_FUNC_msg_pull_data = 63,
	BPF_FUNC_bind = 64,
	BPF_FUNC_xdp_adjust_tail = 65,
	BPF_FUNC_skb_get_xfrm_state = 66,
	BPF_FUNC_get_stack = 67,
	BPF_FUNC_skb_load_bytes_relative = 68,
	BPF_FUNC_fib_lookup = 69,
	BPF_FUNC_sock_hash_update = 70,
	BPF_FUNC_msg_redirect_hash = 71,
	BPF_FUNC_sk_redirect_hash = 72,
	BPF_FUNC_lwt_push_encap = 73,
	BPF_FUNC_lwt_seg6_store_bytes = 74,
	BPF_FUNC_lwt_seg6_adjust_srh = 75,
	BPF_FUNC_lwt_seg6_action = 76,
	BPF_FUNC_rc_repeat = 77,
	BPF_FUNC_rc_keydown = 78,
	BPF_FUNC_skb_cgroup_id = 79,
	BPF_FUNC_get_current_cgroup_id = 80,
	BPF_FUNC_get_local_storage = 81,
	BPF_FUNC_sk_select_reuseport = 82,
	BPF_FUNC_skb_ancestor_cgroup_id = 83,
	BPF_FUNC_sk_lookup_tcp = 84,
	BPF_FUNC_sk_lookup_udp = 85,
	BPF_FUNC_sk_release = 86,
	BPF_FUNC_map_push_elem = 87,
	BPF_FUNC_map_pop_elem = 88,
	BPF_FUNC_map_peek_elem = 89,
	BPF_FUNC_msg_push_data = 90,
	BPF_FUNC_msg_pop_data = 91,
	BPF_FUNC_rc_pointer_rel = 92,
	BPF_FUNC_spin_lock = 93,
	BPF_FUNC_spin_unlock = 94,
	BPF_FUNC_sk_fullsock = 95,
	BPF_FUNC_tcp_sock = 96,
	BPF_FUNC_skb_ecn_set_ce = 97,
	BPF_FUNC_get_listener_sock = 98,
	BPF_FUNC_skc_lookup_tcp = 99,
	BPF_FUNC_tcp_check_syncookie = 100,
	BPF_FUNC_sysctl_get_name = 101,
	BPF_FUNC_sysctl_get_current_value = 102,
	BPF_FUNC_sysctl_get_new_value = 103,
	BPF_FUNC_sysctl_set_new_value = 104,
	BPF_FUNC_strtol = 105,
	BPF_FUNC_strtoul = 106,
	BPF_FUNC_sk_storage_get = 107,
	BPF_FUNC_sk_storage_delete = 108,
	BPF_FUNC_send_signal = 109,
	BPF_FUNC_tcp_gen_syncookie = 110,
	BPF_FUNC_skb_output = 111,
	BPF_FUNC_probe_read_user = 112,
	BPF_FUNC_probe_read_kernel = 113,
	BPF_FUNC_probe_read_user_str = 114,
	BPF_FUNC_probe_read_kernel_str = 115,
	BPF_FUNC_tcp_send_ack = 116,
	BPF_FUNC_send_signal_thread = 117,
	BPF_FUNC_jiffies64 = 118,
	BPF_FUNC_read_branch_records = 119,
	BPF_FUNC_get_ns_current_pid_tgid = 120,
	BPF_FUNC_xdp_output = 121,
	BPF_FUNC_get_netns_cookie = 122,
	BPF_FUNC_get_current_ancestor_cgroup_id = 123,
	BPF_FUNC_sk_assign = 124,
	BPF_FUNC_ktime_get_boot_ns = 125,
	BPF_FUNC_seq_printf = 126,
	BPF_FUNC_seq_write = 127,
	BPF_FUNC_sk_cgroup_id = 128,
	BPF_FUNC_sk_ancestor_cgroup_id = 129,
	BPF_FUNC_ringbuf_output = 130,
	BPF_FUNC_ringbuf_reserve = 131,
	BPF_FUNC_ringbuf_submit = 132,
	BPF_FUNC_ringbuf_discard = 133,
	BPF_FUNC_ringbuf_query = 134,
	BPF_FUNC_csum_level = 135,
	BPF_FUNC_skc_to_tcp6_sock = 136,
	BPF_FUNC_skc_to_tcp_sock = 137,
	BPF_FUNC_skc_to_tcp_timewait_sock = 138,
	BPF_FUNC_skc_to_tcp_request_sock = 139,
	BPF_FUNC_skc_to_udp6_sock = 140,
	BPF_FUNC_get_task_stack = 141,
	BPF_FUNC_load_hdr_opt = 142,
	BPF_FUNC_store_hdr_opt = 143,
	BPF_FUNC_reserve_hdr_opt = 144,
	BPF_FUNC_inode_storage_get = 145,
	BPF_FUNC_inode_storage_delete = 146,
	BPF_FUNC_d_path = 147,
	BPF_FUNC_copy_from_user = 148,
	BPF_FUNC_snprintf_btf = 149,
	BPF_FUNC_seq_printf_btf = 150,
	BPF_FUNC_skb_cgroup_classid = 151,
	BPF_FUNC_redirect_neigh = 152,
	BPF_FUNC_per_cpu_ptr = 153,
	BPF_FUNC_this_cpu_ptr = 154,
	BPF_FUNC_redirect_peer = 155,
	BPF_FUNC_task_storage_get = 156,
	BPF_FUNC_task_storage_delete = 157,
	BPF_FUNC_get_current_task_btf = 158,
	BPF_FUNC_bprm_opts_set = 159,
	BPF_FUNC_ktime_get_coarse_ns = 160,
	BPF_FUNC_ima_inode_hash = 161,
	BPF_FUNC_sock_from_file = 162,
	BPF_FUNC_check_mtu = 163,
	BPF_FUNC_for_each_map_elem = 164,
	BPF_FUNC_snprintf = 165,
	BPF_FUNC_sys_bpf = 166,
	BPF_FUNC_btf_find_by_name_kind = 167,
	BPF_FUNC_sys_close = 168,
	BPF_FUNC_timer_init = 169,
	BPF_FUNC_timer_set_callback = 170,
	BPF_FUNC_timer_start = 171,
	BPF_FUNC_timer_cancel = 172,
	BPF_FUNC_get_func_ip = 173,
	BPF_FUNC_get_attach_cookie = 174,
	BPF_FUNC_task_pt_regs = 175,
	BPF_FUNC_get_branch_snapshot = 176,
	BPF_FUNC_trace_vprintk = 177,
	BPF_FUNC_skc_to_unix_sock = 178,
	BPF_FUNC_kallsyms_lookup_name = 179,
	BPF_FUNC_find_vma = 180,
	BPF_FUNC_loop = 181,
	BPF_FUNC_strncmp = 182,
	BPF_FUNC_get_func_arg = 183,
	BPF_FUNC_get_func_ret = 184,
	BPF_FUNC_get_func_arg_cnt = 185,
	BPF_FUNC_get_retval = 186,
	BPF_FUNC_set_retval = 187,
	BPF_FUNC_xdp_get_buff_len = 188,
	BPF_FUNC_xdp_load_bytes = 189,
	BPF_FUNC_xdp_store_bytes = 190,
	BPF_FUNC_copy_from_user_task = 191,
	BPF_FUNC_skb_set_tstamp = 192,
	BPF_FUNC_ima_file_hash = 193,
	BPF_FUNC_kptr_xchg = 194,
	BPF_FUNC_map_lookup_percpu_elem = 195,
	BPF_FUNC_skc_to_mptcp_sock = 196,
	BPF_FUNC_dynptr_from_mem = 197,
	BPF_FUNC_ringbuf_reserve_dynptr = 198,
	BPF_FUNC_ringbuf_submit_dynptr = 199,
	BPF_FUNC_ringbuf_discard_dynptr = 200,
	BPF_FUNC_dynptr_read = 201,
	BPF_FUNC_dynptr_write = 202,
	BPF_FUNC_dynptr_data = 203,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv4 = 204,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv6 = 205,
	BPF_FUNC_tcp_raw_check_syncookie_ipv4 = 206,
	BPF_FUNC_tcp_raw_check_syncookie_ipv6 = 207,
	BPF_FUNC_ktime_get_tai_ns = 208,
	BPF_FUNC_user_ringbuf_drain = 209,
	BPF_FUNC_cgrp_storage_get = 210,
	BPF_FUNC_cgrp_storage_delete = 211,
	__BPF_FUNC_MAX_ID = 212,
};

struct bpf_func_proto;

typedef const struct bpf_func_proto * (*bpf_iter_get_func_proto_t)(enum bpf_func_id, const struct bpf_prog *);

struct bpf_iter_reg {
	const char *target;
	bpf_iter_attach_target_t attach_target;
	bpf_iter_detach_target_t detach_target;
	bpf_iter_show_fdinfo_t show_fdinfo;
	bpf_iter_fill_link_info_t fill_link_info;
	bpf_iter_get_func_proto_t get_func_proto;
	u32 ctx_arg_info_size;
	u32 feature;
	struct bpf_ctx_arg_aux ctx_arg_info[2];
	const struct bpf_iter_seq_info *seq_info;
};

union bpf_iter_link_info {
	struct {
		__u32 map_fd;
	} map;
	struct {
		enum bpf_cgroup_iter_order order;
		__u32 cgroup_fd;
		__u64 cgroup_id;
	} cgroup;
	struct {
		__u32 tid;
		__u32 pid;
		__u32 pid_fd;
	} task;
};

struct bpf_link_info {
	__u32 type;
	__u32 id;
	__u32 prog_id;
	union {
		struct {
			__u64 tp_name;
			__u32 tp_name_len;
		} raw_tracepoint;
		struct {
			__u32 attach_type;
			__u32 target_obj_id;
			__u32 target_btf_id;
		} tracing;
		struct {
			__u64 cgroup_id;
			__u32 attach_type;
		} cgroup;
		struct {
			__u64 target_name;
			__u32 target_name_len;
			union {
				struct {
					__u32 map_id;
				} map;
			};
			union {
				struct {
					__u64 cgroup_id;
					__u32 order;
				} cgroup;
				struct {
					__u32 tid;
					__u32 pid;
				} task;
			};
		} iter;
		struct {
			__u32 netns_ino;
			__u32 attach_type;
		} netns;
		struct {
			__u32 ifindex;
		} xdp;
		struct {
			__u32 map_id;
		} struct_ops;
		struct {
			__u32 pf;
			__u32 hooknum;
			__s32 priority;
			__u32 flags;
		} netfilter;
		struct {
			__u64 addrs;
			__u32 count;
			__u32 flags;
			__u64 missed;
			__u64 cookies;
		} kprobe_multi;
		struct {
			__u64 path;
			__u64 offsets;
			__u64 ref_ctr_offsets;
			__u64 cookies;
			__u32 path_size;
			__u32 count;
			__u32 flags;
			__u32 pid;
		} uprobe_multi;
		struct {
			__u32 type;
			union {
				struct {
					__u64 file_name;
					__u32 name_len;
					__u32 offset;
					__u64 cookie;
				} uprobe;
				struct {
					__u64 func_name;
					__u32 name_len;
					__u32 offset;
					__u64 addr;
					__u64 missed;
					__u64 cookie;
				} kprobe;
				struct {
					__u64 tp_name;
					__u32 name_len;
					__u64 cookie;
				} tracepoint;
				struct {
					__u64 config;
					__u32 type;
					__u64 cookie;
				} event;
			};
		} perf_event;
		struct {
			__u32 ifindex;
			__u32 attach_type;
		} tcx;
		struct {
			__u32 ifindex;
			__u32 attach_type;
		} netkit;
	};
};

enum bpf_return_type {
	RET_INTEGER = 0,
	RET_VOID = 1,
	RET_PTR_TO_MAP_VALUE = 2,
	RET_PTR_TO_SOCKET = 3,
	RET_PTR_TO_TCP_SOCK = 4,
	RET_PTR_TO_SOCK_COMMON = 5,
	RET_PTR_TO_MEM = 6,
	RET_PTR_TO_MEM_OR_BTF_ID = 7,
	RET_PTR_TO_BTF_ID = 8,
	__BPF_RET_TYPE_MAX = 9,
	RET_PTR_TO_MAP_VALUE_OR_NULL = 258,
	RET_PTR_TO_SOCKET_OR_NULL = 259,
	RET_PTR_TO_TCP_SOCK_OR_NULL = 260,
	RET_PTR_TO_SOCK_COMMON_OR_NULL = 261,
	RET_PTR_TO_RINGBUF_MEM_OR_NULL = 1286,
	RET_PTR_TO_DYNPTR_MEM_OR_NULL = 262,
	RET_PTR_TO_BTF_ID_OR_NULL = 264,
	RET_PTR_TO_BTF_ID_TRUSTED = 1048584,
	__BPF_RET_TYPE_LIMIT = 33554431,
};

enum bpf_arg_type {
	ARG_DONTCARE = 0,
	ARG_CONST_MAP_PTR = 1,
	ARG_PTR_TO_MAP_KEY = 2,
	ARG_PTR_TO_MAP_VALUE = 3,
	ARG_PTR_TO_MEM = 4,
	ARG_PTR_TO_ARENA = 5,
	ARG_CONST_SIZE = 6,
	ARG_CONST_SIZE_OR_ZERO = 7,
	ARG_PTR_TO_CTX = 8,
	ARG_ANYTHING = 9,
	ARG_PTR_TO_SPIN_LOCK = 10,
	ARG_PTR_TO_SOCK_COMMON = 11,
	ARG_PTR_TO_INT = 12,
	ARG_PTR_TO_LONG = 13,
	ARG_PTR_TO_SOCKET = 14,
	ARG_PTR_TO_BTF_ID = 15,
	ARG_PTR_TO_RINGBUF_MEM = 16,
	ARG_CONST_ALLOC_SIZE_OR_ZERO = 17,
	ARG_PTR_TO_BTF_ID_SOCK_COMMON = 18,
	ARG_PTR_TO_PERCPU_BTF_ID = 19,
	ARG_PTR_TO_FUNC = 20,
	ARG_PTR_TO_STACK = 21,
	ARG_PTR_TO_CONST_STR = 22,
	ARG_PTR_TO_TIMER = 23,
	ARG_PTR_TO_KPTR = 24,
	ARG_PTR_TO_DYNPTR = 25,
	__BPF_ARG_TYPE_MAX = 26,
	ARG_PTR_TO_MAP_VALUE_OR_NULL = 259,
	ARG_PTR_TO_MEM_OR_NULL = 260,
	ARG_PTR_TO_CTX_OR_NULL = 264,
	ARG_PTR_TO_SOCKET_OR_NULL = 270,
	ARG_PTR_TO_STACK_OR_NULL = 277,
	ARG_PTR_TO_BTF_ID_OR_NULL = 271,
	ARG_PTR_TO_UNINIT_MEM = 32772,
	ARG_PTR_TO_FIXED_SIZE_MEM = 262148,
	__BPF_ARG_TYPE_LIMIT = 33554431,
};

struct bpf_func_proto {
	u64 (*func)(u64, u64, u64, u64, u64);
	bool gpl_only;
	bool pkt_access;
	bool might_sleep;
	enum bpf_return_type ret_type;
	union {
		struct {
			enum bpf_arg_type arg1_type;
			enum bpf_arg_type arg2_type;
			enum bpf_arg_type arg3_type;
			enum bpf_arg_type arg4_type;
			enum bpf_arg_type arg5_type;
		};
		enum bpf_arg_type arg_type[5];
	};
	union {
		struct {
			u32 *arg1_btf_id;
			u32 *arg2_btf_id;
			u32 *arg3_btf_id;
			u32 *arg4_btf_id;
			u32 *arg5_btf_id;
		};
		u32 *arg_btf_id[5];
		struct {
			size_t arg1_size;
			size_t arg2_size;
			size_t arg3_size;
			size_t arg4_size;
			size_t arg5_size;
		};
		size_t arg_size[5];
	};
	int *ret_btf_id;
	bool (*allowed)(const struct bpf_prog *);
};

typedef int (*btf_kfunc_filter_t)(const struct bpf_prog *, u32);

struct btf_id_set8;

struct btf_kfunc_id_set {
	struct module *owner;
	struct btf_id_set8 *set;
	btf_kfunc_filter_t filter;
};

struct btf_id_set8 {
	u32 cnt;
	u32 flags;
	struct {
		u32 id;
		u32 flags;
	} pairs[0];
};

struct bpf_iter_seq_map_info {
	u32 map_id;
};

struct bpf_iter__bpf_map {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_map *map;
	};
};

enum {
	FOLL_WRITE = 1,
	FOLL_GET = 2,
	FOLL_DUMP = 4,
	FOLL_FORCE = 8,
	FOLL_NOWAIT = 16,
	FOLL_NOFAULT = 32,
	FOLL_HWPOISON = 64,
	FOLL_ANON = 128,
	FOLL_LONGTERM = 256,
	FOLL_SPLIT_PMD = 512,
	FOLL_PCI_P2PDMA = 1024,
	FOLL_INTERRUPTIBLE = 2048,
	FOLL_HONOR_NUMA_FAULT = 4096,
};

enum {
	FOLL_TOUCH = 65536,
	FOLL_TRIED = 131072,
	FOLL_REMOTE = 262144,
	FOLL_PIN = 524288,
	FOLL_FAST_ONLY = 1048576,
	FOLL_UNLOCKABLE = 2097152,
	FOLL_MADV_POPULATE = 4194304,
};

enum vm_fault_reason {
	VM_FAULT_OOM = 1,
	VM_FAULT_SIGBUS = 2,
	VM_FAULT_MAJOR = 4,
	VM_FAULT_HWPOISON = 16,
	VM_FAULT_HWPOISON_LARGE = 32,
	VM_FAULT_SIGSEGV = 64,
	VM_FAULT_NOPAGE = 256,
	VM_FAULT_LOCKED = 512,
	VM_FAULT_RETRY = 1024,
	VM_FAULT_FALLBACK = 2048,
	VM_FAULT_DONE_COW = 4096,
	VM_FAULT_NEEDDSYNC = 8192,
	VM_FAULT_COMPLETED = 16384,
	VM_FAULT_HINDEX_MASK = 983040,
};

enum {
	__PERCPU_REF_ATOMIC = 1,
	__PERCPU_REF_DEAD = 2,
	__PERCPU_REF_ATOMIC_DEAD = 3,
	__PERCPU_REF_FLAG_BITS = 2,
};

typedef unsigned long p4dval_t;

typedef struct {
	p4dval_t p4d;
} p4d_t;

struct follow_page_context {
	struct dev_pagemap *pgmap;
	unsigned int page_mask;
};

typedef u64 uint64_t;

typedef int filler_t(struct file *, struct folio *);

struct iomap_ops;

struct file_dedupe_range_info {
	__s64 dest_fd;
	__u64 dest_offset;
	__u64 bytes_deduped;
	__s32 status;
	__u32 reserved;
};

struct file_dedupe_range {
	__u64 src_offset;
	__u64 src_length;
	__u16 dest_count;
	__u16 reserved1;
	__u32 reserved2;
	struct file_dedupe_range_info info[0];
};

struct screen_info {
	__u8 orig_x;
	__u8 orig_y;
	__u16 ext_mem_k;
	__u16 orig_video_page;
	__u8 orig_video_mode;
	__u8 orig_video_cols;
	__u8 flags;
	__u8 unused2;
	__u16 orig_video_ega_bx;
	__u16 unused3;
	__u8 orig_video_lines;
	__u8 orig_video_isVGA;
	__u16 orig_video_points;
	__u16 lfb_width;
	__u16 lfb_height;
	__u16 lfb_depth;
	__u32 lfb_base;
	__u32 lfb_size;
	__u16 cl_magic;
	__u16 cl_offset;
	__u16 lfb_linelength;
	__u8 red_size;
	__u8 red_pos;
	__u8 green_size;
	__u8 green_pos;
	__u8 blue_size;
	__u8 blue_pos;
	__u8 rsvd_size;
	__u8 rsvd_pos;
	__u16 vesapm_seg;
	__u16 vesapm_off;
	__u16 pages;
	__u16 vesa_attributes;
	__u32 capabilities;
	__u32 ext_lfb_base;
	__u8 _reserved[2];
} __attribute__((packed));

struct apm_bios_info {
	__u16 version;
	__u16 cseg;
	__u32 offset;
	__u16 cseg_16;
	__u16 dseg;
	__u16 flags;
	__u16 cseg_len;
	__u16 cseg_16_len;
	__u16 dseg_len;
};

struct ist_info {
	__u32 signature;
	__u32 command;
	__u32 event;
	__u32 perf_level;
};

struct sys_desc_table {
	__u16 length;
	__u8 table[14];
};

struct olpc_ofw_header {
	__u32 ofw_magic;
	__u32 ofw_version;
	__u32 cif_handler;
	__u32 irq_desc_table;
};

struct edid_info {
	unsigned char dummy[128];
};

struct efi_info {
	__u32 efi_loader_signature;
	__u32 efi_systab;
	__u32 efi_memdesc_size;
	__u32 efi_memdesc_version;
	__u32 efi_memmap;
	__u32 efi_memmap_size;
	__u32 efi_systab_hi;
	__u32 efi_memmap_hi;
};

struct setup_header {
	__u8 setup_sects;
	__u16 root_flags;
	__u32 syssize;
	__u16 ram_size;
	__u16 vid_mode;
	__u16 root_dev;
	__u16 boot_flag;
	__u16 jump;
	__u32 header;
	__u16 version;
	__u32 realmode_swtch;
	__u16 start_sys_seg;
	__u16 kernel_version;
	__u8 type_of_loader;
	__u8 loadflags;
	__u16 setup_move_size;
	__u32 code32_start;
	__u32 ramdisk_image;
	__u32 ramdisk_size;
	__u32 bootsect_kludge;
	__u16 heap_end_ptr;
	__u8 ext_loader_ver;
	__u8 ext_loader_type;
	__u32 cmd_line_ptr;
	__u32 initrd_addr_max;
	__u32 kernel_alignment;
	__u8 relocatable_kernel;
	__u8 min_alignment;
	__u16 xloadflags;
	__u32 cmdline_size;
	__u32 hardware_subarch;
	__u64 hardware_subarch_data;
	__u32 payload_offset;
	__u32 payload_length;
	__u64 setup_data;
	__u64 pref_address;
	__u32 init_size;
	__u32 handover_offset;
	__u32 kernel_info_offset;
} __attribute__((packed));

struct boot_e820_entry {
	__u64 addr;
	__u64 size;
	__u32 type;
} __attribute__((packed));

struct edd_device_params {
	__u16 length;
	__u16 info_flags;
	__u32 num_default_cylinders;
	__u32 num_default_heads;
	__u32 sectors_per_track;
	__u64 number_of_sectors;
	__u16 bytes_per_sector;
	__u32 dpte_ptr;
	__u16 key;
	__u8 device_path_info_length;
	__u8 reserved2;
	__u16 reserved3;
	__u8 host_bus_type[4];
	__u8 interface_type[8];
	union {
		struct {
			__u16 base_address;
			__u16 reserved1;
			__u32 reserved2;
		} isa;
		struct {
			__u8 bus;
			__u8 slot;
			__u8 function;
			__u8 channel;
			__u32 reserved;
		} pci;
		struct {
			__u64 reserved;
		} ibnd;
		struct {
			__u64 reserved;
		} xprs;
		struct {
			__u64 reserved;
		} htpt;
		struct {
			__u64 reserved;
		} unknown;
	} interface_path;
	union {
		struct {
			__u8 device;
			__u8 reserved1;
			__u16 reserved2;
			__u32 reserved3;
			__u64 reserved4;
		} ata;
		struct {
			__u8 device;
			__u8 lun;
			__u8 reserved1;
			__u8 reserved2;
			__u32 reserved3;
			__u64 reserved4;
		} atapi;
		struct {
			__u16 id;
			__u64 lun;
			__u16 reserved1;
			__u32 reserved2;
		} __attribute__((packed)) scsi;
		struct {
			__u64 serial_number;
			__u64 reserved;
		} usb;
		struct {
			__u64 eui;
			__u64 reserved;
		} i1394;
		struct {
			__u64 wwid;
			__u64 lun;
		} fibre;
		struct {
			__u64 identity_tag;
			__u64 reserved;
		} i2o;
		struct {
			__u32 array_number;
			__u32 reserved1;
			__u64 reserved2;
		} raid;
		struct {
			__u8 device;
			__u8 reserved1;
			__u16 reserved2;
			__u32 reserved3;
			__u64 reserved4;
		} sata;
		struct {
			__u64 reserved1;
			__u64 reserved2;
		} unknown;
	} device_path;
	__u8 reserved4;
	__u8 checksum;
} __attribute__((packed));

struct edd_info {
	__u8 device;
	__u8 version;
	__u16 interface_support;
	__u16 legacy_max_cylinder;
	__u8 legacy_max_head;
	__u8 legacy_sectors_per_track;
	struct edd_device_params params;
};

struct boot_params {
	struct screen_info screen_info;
	struct apm_bios_info apm_bios_info;
	__u8 _pad2[4];
	__u64 tboot_addr;
	struct ist_info ist_info;
	__u64 acpi_rsdp_addr;
	__u8 _pad3[8];
	__u8 hd0_info[16];
	__u8 hd1_info[16];
	struct sys_desc_table sys_desc_table;
	struct olpc_ofw_header olpc_ofw_header;
	__u32 ext_ramdisk_image;
	__u32 ext_ramdisk_size;
	__u32 ext_cmd_line_ptr;
	__u8 _pad4[112];
	__u32 cc_blob_address;
	struct edid_info edid_info;
	struct efi_info efi_info;
	__u32 alt_mem_k;
	__u32 scratch;
	__u8 e820_entries;
	__u8 eddbuf_entries;
	__u8 edd_mbr_sig_buf_entries;
	__u8 kbd_status;
	__u8 secure_boot;
	__u8 _pad5[2];
	__u8 sentinel;
	__u8 _pad6[1];
	struct setup_header hdr;
	__u8 _pad7[36];
	__u32 edd_mbr_sig_buffer[16];
	struct boot_e820_entry e820_table[128];
	__u8 _pad8[48];
	struct edd_info eddbuf[6];
	__u8 _pad9[276];
};

enum efi_secureboot_mode {
	efi_secureboot_mode_unset = 0,
	efi_secureboot_mode_unknown = 1,
	efi_secureboot_mode_disabled = 2,
	efi_secureboot_mode_enabled = 3,
};

enum e820_type {
	E820_TYPE_RAM = 1,
	E820_TYPE_RESERVED = 2,
	E820_TYPE_ACPI = 3,
	E820_TYPE_NVS = 4,
	E820_TYPE_UNUSABLE = 5,
	E820_TYPE_PMEM = 7,
	E820_TYPE_PRAM = 12,
	E820_TYPE_SOFT_RESERVED = 4026531839,
	E820_TYPE_RESERVED_KERN = 128,
};

struct setup_indirect {
	__u32 type;
	__u32 reserved;
	__u64 len;
	__u64 addr;
};

struct e820_entry {
	u64 addr;
	u64 size;
	enum e820_type type;
} __attribute__((packed));

struct e820_table {
	__u32 nr_entries;
	struct e820_entry entries[131];
};

struct atomic_notifier_head {
	spinlock_t lock;
	struct notifier_block __attribute__((btf_type_tag("rcu"))) *head;
};

struct setup_data {
	__u64 next;
	__u32 type;
	__u32 len;
	__u8 data[0];
};

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

struct sg_table;

struct scatterlist;

struct dma_map_ops {
	unsigned int flags;
	void * (*alloc)(struct device *, size_t, dma_addr_t *, gfp_t, unsigned long);
	void (*free)(struct device *, size_t, void *, dma_addr_t, unsigned long);
	struct page * (*alloc_pages)(struct device *, size_t, dma_addr_t *, enum dma_data_direction, gfp_t);
	void (*free_pages)(struct device *, size_t, struct page *, dma_addr_t, enum dma_data_direction);
	struct sg_table * (*alloc_noncontiguous)(struct device *, size_t, enum dma_data_direction, gfp_t, unsigned long);
	void (*free_noncontiguous)(struct device *, size_t, struct sg_table *, enum dma_data_direction);
	int (*mmap)(struct device *, struct vm_area_struct *, void *, dma_addr_t, size_t, unsigned long);
	int (*get_sgtable)(struct device *, struct sg_table *, void *, dma_addr_t, size_t, unsigned long);
	dma_addr_t (*map_page)(struct device *, struct page *, unsigned long, size_t, enum dma_data_direction, unsigned long);
	void (*unmap_page)(struct device *, dma_addr_t, size_t, enum dma_data_direction, unsigned long);
	int (*map_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, unsigned long);
	void (*unmap_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, unsigned long);
	dma_addr_t (*map_resource)(struct device *, phys_addr_t, size_t, enum dma_data_direction, unsigned long);
	void (*unmap_resource)(struct device *, dma_addr_t, size_t, enum dma_data_direction, unsigned long);
	void (*sync_single_for_cpu)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_single_for_device)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_sg_for_cpu)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*sync_sg_for_device)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*cache_sync)(struct device *, void *, size_t, enum dma_data_direction);
	int (*dma_supported)(struct device *, u64);
	u64 (*get_required_mask)(struct device *);
	size_t (*max_mapping_size)(struct device *);
	size_t (*opt_mapping_size)();
	unsigned long (*get_merge_boundary)(struct device *);
};

struct io_tlb_area;

struct io_tlb_slot;

struct io_tlb_pool {
	phys_addr_t start;
	phys_addr_t end;
	void *vaddr;
	unsigned long nslabs;
	bool late_alloc;
	unsigned int nareas;
	unsigned int area_nslabs;
	struct io_tlb_area *areas;
	struct io_tlb_slot *slots;
};

struct io_tlb_mem {
	struct io_tlb_pool defpool;
	unsigned long nslabs;
	struct dentry *debugfs;
	bool force_bounce;
	bool for_alloc;
};

struct sg_table {
	struct scatterlist *sgl;
	unsigned int nents;
	unsigned int orig_nents;
};

struct scatterlist {
	unsigned long page_link;
	unsigned int offset;
	unsigned int length;
	dma_addr_t dma_address;
	unsigned int dma_length;
};

enum cc_attr {
	CC_ATTR_MEM_ENCRYPT = 0,
	CC_ATTR_HOST_MEM_ENCRYPT = 1,
	CC_ATTR_GUEST_MEM_ENCRYPT = 2,
	CC_ATTR_GUEST_STATE_ENCRYPT = 3,
	CC_ATTR_GUEST_UNROLL_STRING_IO = 4,
	CC_ATTR_GUEST_SEV_SNP = 5,
	CC_ATTR_HOTPLUG_DISABLED = 6,
	CC_ATTR_HOST_SEV_SNP = 7,
};

enum x86_topology_domains {
	TOPO_SMT_DOMAIN = 0,
	TOPO_CORE_DOMAIN = 1,
	TOPO_MODULE_DOMAIN = 2,
	TOPO_TILE_DOMAIN = 3,
	TOPO_DIE_DOMAIN = 4,
	TOPO_DIEGRP_DOMAIN = 5,
	TOPO_PKG_DOMAIN = 6,
	TOPO_MAX_DOMAIN = 7,
};

enum cpuid_regs_idx {
	CPUID_EAX = 0,
	CPUID_EBX = 1,
	CPUID_ECX = 2,
	CPUID_EDX = 3,
};

struct topo_scan {
	struct cpuinfo_x86 *c;
	unsigned int dom_shifts[7];
	unsigned int dom_ncpus[7];
	unsigned int ebx1_nproc_shift;
	u16 amd_nodes_per_pkg;
	u16 amd_node_id;
};

enum {
	SAMPLES = 8,
	MIN_CHANGE = 5,
};

struct x86_cpu_desc {
	u8 x86_family;
	u8 x86_vendor;
	u8 x86_model;
	u8 x86_stepping;
	u32 x86_microcode_rev;
};

struct x86_cpu_id {
	__u16 vendor;
	__u16 family;
	__u16 model;
	__u16 steppings;
	__u16 feature;
	__u16 flags;
	kernel_ulong_t driver_data;
};

struct cpu_dev {
	const char *c_vendor;
	const char *c_ident[2];
	void (*c_early_init)(struct cpuinfo_x86 *);
	void (*c_bsp_init)(struct cpuinfo_x86 *);
	void (*c_init)(struct cpuinfo_x86 *);
	void (*c_identify)(struct cpuinfo_x86 *);
	void (*c_detect_tlb)(struct cpuinfo_x86 *);
	int c_x86_vendor;
};

enum cpuid_leafs {
	CPUID_1_EDX = 0,
	CPUID_8000_0001_EDX = 1,
	CPUID_8086_0001_EDX = 2,
	CPUID_LNX_1 = 3,
	CPUID_1_ECX = 4,
	CPUID_C000_0001_EDX = 5,
	CPUID_8000_0001_ECX = 6,
	CPUID_LNX_2 = 7,
	CPUID_LNX_3 = 8,
	CPUID_7_0_EBX = 9,
	CPUID_D_1_EAX = 10,
	CPUID_LNX_4 = 11,
	CPUID_7_1_EAX = 12,
	CPUID_8000_0008_EBX = 13,
	CPUID_6_EAX = 14,
	CPUID_8000_000A_EDX = 15,
	CPUID_7_ECX = 16,
	CPUID_8000_0007_EBX = 17,
	CPUID_7_EDX = 18,
	CPUID_8000_001F_EAX = 19,
	CPUID_8000_0021_EAX = 20,
	CPUID_LNX_5 = 21,
	NR_CPUID_WORDS = 22,
};

struct apic_override {
	void (*eoi)();
	void (*native_eoi)();
	void (*write)(u32, u32);
	u32 (*read)(u32);
	void (*send_IPI)(int, int);
	void (*send_IPI_mask)(const struct cpumask *, int);
	void (*send_IPI_mask_allbutself)(const struct cpumask *, int);
	void (*send_IPI_allbutself)(int);
	void (*send_IPI_all)(int);
	void (*send_IPI_self)(int);
	u64 (*icr_read)();
	void (*icr_write)(u32, u32);
	int (*wakeup_secondary_cpu)(u32, unsigned long);
	int (*wakeup_secondary_cpu_64)(u32, unsigned long);
};

struct apic {
	void (*eoi)();
	void (*native_eoi)();
	void (*write)(u32, u32);
	u32 (*read)(u32);
	void (*wait_icr_idle)();
	u32 (*safe_wait_icr_idle)();
	void (*send_IPI)(int, int);
	void (*send_IPI_mask)(const struct cpumask *, int);
	void (*send_IPI_mask_allbutself)(const struct cpumask *, int);
	void (*send_IPI_allbutself)(int);
	void (*send_IPI_all)(int);
	void (*send_IPI_self)(int);
	u32 disable_esr: 1;
	u32 dest_mode_logical: 1;
	u32 x2apic_set_max_apicid: 1;
	u32 nmi_to_offline_cpu: 1;
	u32 (*calc_dest_apicid)(unsigned int);
	u64 (*icr_read)();
	void (*icr_write)(u32, u32);
	u32 max_apic_id;
	int (*probe)();
	int (*acpi_madt_oem_check)(char *, char *);
	void (*init_apic_ldr)();
	u32 (*cpu_present_to_apicid)(int);
	u32 (*get_apic_id)(u32);
	int (*wakeup_secondary_cpu)(u32, unsigned long);
	int (*wakeup_secondary_cpu_64)(u32, unsigned long);
	char *name;
};

enum page_cache_mode {
	_PAGE_CACHE_MODE_WB = 0,
	_PAGE_CACHE_MODE_WC = 1,
	_PAGE_CACHE_MODE_UC_MINUS = 2,
	_PAGE_CACHE_MODE_UC = 3,
	_PAGE_CACHE_MODE_WT = 4,
	_PAGE_CACHE_MODE_WP = 5,
	_PAGE_CACHE_MODE_NUM = 8,
};

enum {
	MEMREMAP_WB = 1,
	MEMREMAP_WT = 2,
	MEMREMAP_WC = 4,
	MEMREMAP_ENC = 8,
	MEMREMAP_DEC = 16,
};

enum fixed_addresses {
	VSYSCALL_PAGE = 511,
	FIX_DBGP_BASE = 512,
	FIX_EARLYCON_MEM_BASE = 513,
	FIX_APIC_BASE = 514,
	FIX_IO_APIC_BASE_0 = 515,
	FIX_IO_APIC_BASE_END = 642,
	__end_of_permanent_fixed_addresses = 643,
	FIX_BTMAP_END = 1024,
	FIX_BTMAP_BEGIN = 1535,
	__end_of_fixed_addresses = 1536,
};

enum {
	IORES_MAP_SYSTEM_RAM = 1,
	IORES_MAP_ENCRYPTED = 2,
};

enum {
	SECTION_MARKED_PRESENT_BIT = 0,
	SECTION_HAS_MEM_MAP_BIT = 1,
	SECTION_IS_ONLINE_BIT = 2,
	SECTION_IS_EARLY_BIT = 3,
	SECTION_MAP_LAST_BIT = 4,
};

enum {
	IORES_DESC_NONE = 0,
	IORES_DESC_CRASH_KERNEL = 1,
	IORES_DESC_ACPI_TABLES = 2,
	IORES_DESC_ACPI_NV_STORAGE = 3,
	IORES_DESC_PERSISTENT_MEMORY = 4,
	IORES_DESC_PERSISTENT_MEMORY_LEGACY = 5,
	IORES_DESC_DEVICE_PRIVATE_MEMORY = 6,
	IORES_DESC_RESERVED = 7,
	IORES_DESC_SOFT_RESERVED = 8,
	IORES_DESC_CXL = 9,
};

struct mem_section_usage {
	struct callback_head rcu;
	unsigned long subsection_map[1];
	unsigned long pageblock_flags[0];
};

struct ioremap_desc {
	unsigned int flags;
};

struct mem_section {
	unsigned long section_mem_map;
	struct mem_section_usage *usage;
};

struct cfs_rq {
	struct load_weight load;
	unsigned int nr_running;
	unsigned int h_nr_running;
	unsigned int idle_nr_running;
	unsigned int idle_h_nr_running;
	s64 avg_vruntime;
	u64 avg_load;
	u64 exec_clock;
	u64 min_vruntime;
	struct rb_root_cached tasks_timeline;
	struct sched_entity *curr;
	struct sched_entity *next;
};

struct rt_prio_array {
	unsigned long bitmap[2];
	struct list_head queue[100];
};

struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
	int rt_queued;
	int rt_throttled;
	u64 rt_time;
	u64 rt_runtime;
	raw_spinlock_t rt_runtime_lock;
};

struct dl_bw {
	raw_spinlock_t lock;
	u64 bw;
	u64 total_bw;
};

struct dl_rq {
	struct rb_root_cached root;
	unsigned int dl_nr_running;
	struct dl_bw dl_bw;
	u64 running_bw;
	u64 this_bw;
	u64 extra_bw;
	u64 max_bw;
	u64 bw_ratio;
};

typedef int (*cpu_stop_fn_t)(void *);

struct cpu_stop_work {
	struct work_struct work;
	cpu_stop_fn_t fn;
	void *arg;
};

struct rq {
	raw_spinlock_t __lock;
	unsigned int nr_running;
	u64 nr_switches;
	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;
	unsigned int nr_uninterruptible;
	struct task_struct __attribute__((btf_type_tag("rcu"))) *curr;
	struct task_struct *idle;
	struct task_struct *stop;
	unsigned long next_balance;
	struct mm_struct *prev_mm;
	unsigned int clock_update_flags;
	u64 clock;
	long: 64;
	long: 64;
	u64 clock_task;
	u64 clock_pelt;
	unsigned long lost_idle_time;
	u64 clock_pelt_idle;
	u64 clock_idle;
	atomic_t nr_iowait;
	unsigned long calc_load_update;
	long calc_load_active;
	unsigned int push_busy;
	struct cpu_stop_work push_work;
	cpumask_var_t scratch_mask;
};

struct plist_head {
	struct list_head node_list;
};

enum pm_qos_type {
	PM_QOS_UNITIALIZED = 0,
	PM_QOS_MAX = 1,
	PM_QOS_MIN = 2,
};

struct pm_qos_constraints {
	struct plist_head list;
	s32 target_value;
	s32 default_value;
	s32 no_constraint_value;
	enum pm_qos_type type;
	struct blocking_notifier_head *notifiers;
};

struct freq_constraints {
	struct pm_qos_constraints min_freq;
	struct blocking_notifier_head min_freq_notifiers;
	struct pm_qos_constraints max_freq;
	struct blocking_notifier_head max_freq_notifiers;
};

struct pm_qos_flags {
	struct list_head list;
	s32 effective_flags;
};

struct dev_pm_qos_request;

struct dev_pm_qos {
	struct pm_qos_constraints resume_latency;
	struct pm_qos_constraints latency_tolerance;
	struct freq_constraints freq;
	struct pm_qos_flags flags;
	struct dev_pm_qos_request *resume_latency_req;
	struct dev_pm_qos_request *latency_tolerance_req;
	struct dev_pm_qos_request *flags_req;
};

struct pm_qos_flags_request {
	struct list_head node;
	s32 flags;
};

enum freq_qos_req_type {
	FREQ_QOS_MIN = 1,
	FREQ_QOS_MAX = 2,
};

struct freq_qos_request {
	enum freq_qos_req_type type;
	struct plist_node pnode;
	struct freq_constraints *qos;
};

enum dev_pm_qos_req_type {
	DEV_PM_QOS_RESUME_LATENCY = 1,
	DEV_PM_QOS_LATENCY_TOLERANCE = 2,
	DEV_PM_QOS_MIN_FREQUENCY = 3,
	DEV_PM_QOS_MAX_FREQUENCY = 4,
	DEV_PM_QOS_FLAGS = 5,
};

struct dev_pm_qos_request {
	enum dev_pm_qos_req_type type;
	union {
		struct plist_node pnode;
		struct pm_qos_flags_request flr;
		struct freq_qos_request freq;
	} data;
	struct device *dev;
};

struct rb_augment_callbacks {
	void (*propagate)(struct rb_node *, struct rb_node *);
	void (*copy)(struct rb_node *, struct rb_node *);
	void (*rotate)(struct rb_node *, struct rb_node *);
};

enum sched_tunable_scaling {
	SCHED_TUNABLESCALING_NONE = 0,
	SCHED_TUNABLESCALING_LOG = 1,
	SCHED_TUNABLESCALING_LINEAR = 2,
	SCHED_TUNABLESCALING_END = 3,
};

struct pin_cookie {};

struct rq_flags {
	unsigned long flags;
	struct pin_cookie cookie;
};

struct tnum {
	u64 value;
	u64 mask;
};

enum bpf_cmd {
	BPF_MAP_CREATE = 0,
	BPF_MAP_LOOKUP_ELEM = 1,
	BPF_MAP_UPDATE_ELEM = 2,
	BPF_MAP_DELETE_ELEM = 3,
	BPF_MAP_GET_NEXT_KEY = 4,
	BPF_PROG_LOAD = 5,
	BPF_OBJ_PIN = 6,
	BPF_OBJ_GET = 7,
	BPF_PROG_ATTACH = 8,
	BPF_PROG_DETACH = 9,
	BPF_PROG_TEST_RUN = 10,
	BPF_PROG_RUN = 10,
	BPF_PROG_GET_NEXT_ID = 11,
	BPF_MAP_GET_NEXT_ID = 12,
	BPF_PROG_GET_FD_BY_ID = 13,
	BPF_MAP_GET_FD_BY_ID = 14,
	BPF_OBJ_GET_INFO_BY_FD = 15,
	BPF_PROG_QUERY = 16,
	BPF_RAW_TRACEPOINT_OPEN = 17,
	BPF_BTF_LOAD = 18,
	BPF_BTF_GET_FD_BY_ID = 19,
	BPF_TASK_FD_QUERY = 20,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21,
	BPF_MAP_FREEZE = 22,
	BPF_BTF_GET_NEXT_ID = 23,
	BPF_MAP_LOOKUP_BATCH = 24,
	BPF_MAP_LOOKUP_AND_DELETE_BATCH = 25,
	BPF_MAP_UPDATE_BATCH = 26,
	BPF_MAP_DELETE_BATCH = 27,
	BPF_LINK_CREATE = 28,
	BPF_LINK_UPDATE = 29,
	BPF_LINK_GET_FD_BY_ID = 30,
	BPF_LINK_GET_NEXT_ID = 31,
	BPF_ENABLE_STATS = 32,
	BPF_ITER_CREATE = 33,
	BPF_LINK_DETACH = 34,
	BPF_PROG_BIND_MAP = 35,
	BPF_TOKEN_CREATE = 36,
	__MAX_BPF_CMD = 37,
};

struct bpf_mount_opts {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	u64 delegate_cmds;
	u64 delegate_maps;
	u64 delegate_progs;
	u64 delegate_attachs;
};

struct callchain_cpus_entries {
	struct callback_head callback_head;
	struct perf_callchain_entry *cpu_entries[0];
};

enum perf_callchain_context {
	PERF_CONTEXT_HV = 18446744073709551584ULL,
	PERF_CONTEXT_KERNEL = 18446744073709551488ULL,
	PERF_CONTEXT_USER = 18446744073709551104ULL,
	PERF_CONTEXT_GUEST = 18446744073709549568ULL,
	PERF_CONTEXT_GUEST_KERNEL = 18446744073709549440ULL,
	PERF_CONTEXT_GUEST_USER = 18446744073709549056ULL,
	PERF_CONTEXT_MAX = 18446744073709547521ULL,
};

struct perf_buffer {
	refcount_t refcount;
	struct callback_head callback_head;
	int nr_pages;
	int overwrite;
	int paused;
	atomic_t poll;
	local_t head;
	unsigned int nest;
	local_t events;
	local_t wakeup;
	local_t lost;
	long watermark;
	long aux_watermark;
	spinlock_t event_lock;
	struct list_head event_list;
	atomic_t mmap_count;
	unsigned long mmap_locked;
	struct user_struct *mmap_user;
	long aux_head;
	unsigned int aux_nest;
	long aux_wakeup;
	unsigned long aux_pgoff;
	int aux_nr_pages;
	int aux_overwrite;
	atomic_t aux_mmap_count;
	unsigned long aux_mmap_locked;
	void (*free_aux)(void *);
	refcount_t aux_refcount;
	int aux_in_sampling;
	void **aux_pages;
	void *aux_priv;
	struct perf_event_mmap_page *user_page;
	void *data_pages[0];
};

enum lru_list {
	LRU_INACTIVE_ANON = 0,
	LRU_ACTIVE_ANON = 1,
	LRU_INACTIVE_FILE = 2,
	LRU_ACTIVE_FILE = 3,
	LRU_UNEVICTABLE = 4,
	NR_LRU_LISTS = 5,
};

enum page_walk_lock {
	PGWALK_RDLOCK = 0,
	PGWALK_WRLOCK = 1,
	PGWALK_WRLOCK_VERIFY = 2,
};

struct mm_walk;

struct mm_walk_ops {
	int (*pgd_entry)(pgd_t *, unsigned long, unsigned long, struct mm_walk *);
	int (*p4d_entry)(p4d_t *, unsigned long, unsigned long, struct mm_walk *);
	int (*pud_entry)(pud_t *, unsigned long, unsigned long, struct mm_walk *);
	int (*pmd_entry)(pmd_t *, unsigned long, unsigned long, struct mm_walk *);
	int (*pte_entry)(pte_t *, unsigned long, unsigned long, struct mm_walk *);
	int (*pte_hole)(unsigned long, unsigned long, int, struct mm_walk *);
	int (*hugetlb_entry)(pte_t *, unsigned long, unsigned long, unsigned long, struct mm_walk *);
	int (*test_walk)(unsigned long, unsigned long, struct mm_walk *);
	int (*pre_vma)(unsigned long, unsigned long, struct mm_walk *);
	void (*post_vma)(struct mm_walk *);
	enum page_walk_lock walk_lock;
};

enum page_walk_action {
	ACTION_SUBTREE = 0,
	ACTION_CONTINUE = 1,
	ACTION_AGAIN = 2,
};

struct mm_walk {
	const struct mm_walk_ops *ops;
	struct mm_struct *mm;
	pgd_t *pgd;
	struct vm_area_struct *vma;
	enum page_walk_action action;
	bool no_vma;
	void *private;
};

struct old_linux_dirent {
	unsigned long d_ino;
	unsigned long d_offset;
	unsigned short d_namlen;
	char d_name[0];
};

struct readdir_callback {
	struct dir_context ctx;
	struct old_linux_dirent __attribute__((btf_type_tag("user"))) *dirent;
	int result;
};

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[0];
};

struct getdents_callback {
	struct dir_context ctx;
	struct linux_dirent __attribute__((btf_type_tag("user"))) *current_dir;
	int prev_reclen;
	int count;
	int error;
};

struct linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[0];
};

struct getdents_callback64 {
	struct dir_context ctx;
	struct linux_dirent64 __attribute__((btf_type_tag("user"))) *current_dir;
	int prev_reclen;
	int count;
	int error;
};

enum {
	MAX_OPT_ARGS = 3,
};

typedef struct {
	char *from;
	char *to;
} substring_t;

struct match_token {
	int token;
	const char *pattern;
};

struct ida {
	struct xarray xa;
};

struct ld_semaphore {
	atomic_long_t count;
	raw_spinlock_t wait_lock;
	unsigned int wait_readers;
	struct list_head read_wait;
	struct list_head write_wait;
};

typedef unsigned int tcflag_t;

typedef unsigned char cc_t;

typedef unsigned int speed_t;

struct ktermios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[19];
	speed_t c_ispeed;
	speed_t c_ospeed;
};

struct winsize {
	unsigned short ws_row;
	unsigned short ws_col;
	unsigned short ws_xpixel;
	unsigned short ws_ypixel;
};

struct tty_driver;

struct tty_port;

struct tty_operations;

struct tty_ldisc;

struct tty_struct {
	struct kref kref;
	int index;
	struct device *dev;
	struct tty_driver *driver;
	struct tty_port *port;
	const struct tty_operations *ops;
	struct tty_ldisc *ldisc;
	struct ld_semaphore ldisc_sem;
	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	struct ktermios termios;
	struct ktermios termios_locked;
	char name[64];
	unsigned long flags;
	int count;
	unsigned int receive_room;
	struct winsize winsize;
	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
		unsigned long unused[0];
	} flow;
	struct {
		struct pid *pgrp;
		struct pid *session;
		spinlock_t lock;
		unsigned char pktstatus;
		bool packet;
		unsigned long unused[0];
	} ctrl;
	bool hw_stopped;
	bool closing;
	int flow_change;
	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;
	int write_cnt;
	u8 *write_buf;
	struct list_head tty_files;
	struct work_struct SAK_work;
};

struct tty_driver {
	struct kref kref;
	struct cdev **cdevs;
	struct module *owner;
	const char *driver_name;
	const char *name;
	int name_base;
	int major;
	int minor_start;
	unsigned int num;
	short type;
	short subtype;
	struct ktermios init_termios;
	unsigned long flags;
	struct proc_dir_entry *proc_entry;
	struct tty_driver *other;
	struct tty_struct **ttys;
	struct tty_port **ports;
	struct ktermios **termios;
	void *driver_state;
	const struct tty_operations *ops;
	struct list_head tty_drivers;
};

struct __kfifo {
	unsigned int in;
	unsigned int out;
	unsigned int mask;
	unsigned int esize;
	void *data;
};

struct tty_buffer {
	union {
		struct tty_buffer *next;
		struct llist_node free;
	};
	unsigned int used;
	unsigned int size;
	unsigned int commit;
	unsigned int lookahead;
	unsigned int read;
	bool flags;
	long: 0;
	u8 data[0];
};

struct tty_bufhead {
	struct tty_buffer *head;
	struct work_struct work;
	struct mutex lock;
	atomic_t priority;
	struct tty_buffer sentinel;
	struct llist_head free;
	atomic_t mem_used;
	int mem_limit;
	struct tty_buffer *tail;
};

struct tty_port_operations;

struct tty_port_client_operations;

struct tty_port {
	struct tty_bufhead buf;
	struct tty_struct *tty;
	struct tty_struct *itty;
	const struct tty_port_operations *ops;
	const struct tty_port_client_operations *client_ops;
	spinlock_t lock;
	int blocked_open;
	int count;
	wait_queue_head_t open_wait;
	wait_queue_head_t delta_msr_wait;
	unsigned long flags;
	unsigned long iflags;
	unsigned char console: 1;
	struct mutex mutex;
	struct mutex buf_mutex;
	u8 *xmit_buf;
	struct {
		union {
			struct __kfifo kfifo;
			u8 *type;
			const u8 *const_type;
			char (*rectype)[0];
			u8 *ptr;
			const u8 *ptr_const;
		};
		u8 buf[0];
	} xmit_fifo;
	unsigned int close_delay;
	unsigned int closing_wait;
	int drain_delay;
	struct kref kref;
	void *client_data;
};

struct tty_port_operations {
	bool (*carrier_raised)(struct tty_port *);
	void (*dtr_rts)(struct tty_port *, bool);
	void (*shutdown)(struct tty_port *);
	int (*activate)(struct tty_port *, struct tty_struct *);
	void (*destruct)(struct tty_port *);
};

struct tty_port_client_operations {
	size_t (*receive_buf)(struct tty_port *, const u8 *, const u8 *, size_t);
	void (*lookahead_buf)(struct tty_port *, const u8 *, const u8 *, size_t);
	void (*write_wakeup)(struct tty_port *);
};

struct serial_icounter_struct;

struct serial_struct;

struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *, struct file *, int);
	int (*install)(struct tty_driver *, struct tty_struct *);
	void (*remove)(struct tty_driver *, struct tty_struct *);
	int (*open)(struct tty_struct *, struct file *);
	void (*close)(struct tty_struct *, struct file *);
	void (*shutdown)(struct tty_struct *);
	void (*cleanup)(struct tty_struct *);
	ssize_t (*write)(struct tty_struct *, const u8 *, size_t);
	int (*put_char)(struct tty_struct *, u8);
	void (*flush_chars)(struct tty_struct *);
	unsigned int (*write_room)(struct tty_struct *);
	unsigned int (*chars_in_buffer)(struct tty_struct *);
	int (*ioctl)(struct tty_struct *, unsigned int, unsigned long);
	long (*compat_ioctl)(struct tty_struct *, unsigned int, unsigned long);
	void (*set_termios)(struct tty_struct *, const struct ktermios *);
	void (*throttle)(struct tty_struct *);
	void (*unthrottle)(struct tty_struct *);
	void (*stop)(struct tty_struct *);
	void (*start)(struct tty_struct *);
	void (*hangup)(struct tty_struct *);
	int (*break_ctl)(struct tty_struct *, int);
	void (*flush_buffer)(struct tty_struct *);
	int (*ldisc_ok)(struct tty_struct *, int);
	void (*set_ldisc)(struct tty_struct *);
	void (*wait_until_sent)(struct tty_struct *, int);
	void (*send_xchar)(struct tty_struct *, u8);
	int (*tiocmget)(struct tty_struct *);
	int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);
	int (*resize)(struct tty_struct *, struct winsize *);
	int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *);
	int (*get_serial)(struct tty_struct *, struct serial_struct *);
	int (*set_serial)(struct tty_struct *, struct serial_struct *);
	void (*show_fdinfo)(struct tty_struct *, struct seq_file *);
	int (*proc_show)(struct seq_file *, void *);
};

struct tty_ldisc_ops;

struct tty_ldisc {
	struct tty_ldisc_ops *ops;
	struct tty_struct *tty;
};

struct tty_ldisc_ops {
	char *name;
	int num;
	int (*open)(struct tty_struct *);
	void (*close)(struct tty_struct *);
	void (*flush_buffer)(struct tty_struct *);
	ssize_t (*read)(struct tty_struct *, struct file *, u8 *, size_t, void **, unsigned long);
	ssize_t (*write)(struct tty_struct *, struct file *, const u8 *, size_t);
	int (*ioctl)(struct tty_struct *, unsigned int, unsigned long);
	int (*compat_ioctl)(struct tty_struct *, unsigned int, unsigned long);
	void (*set_termios)(struct tty_struct *, const struct ktermios *);
	__poll_t (*poll)(struct tty_struct *, struct file *, struct poll_table_struct *);
	void (*hangup)(struct tty_struct *);
	void (*receive_buf)(struct tty_struct *, const u8 *, const u8 *, size_t);
	void (*write_wakeup)(struct tty_struct *);
	void (*dcd_change)(struct tty_struct *, bool);
	size_t (*receive_buf2)(struct tty_struct *, const u8 *, const u8 *, size_t);
	void (*lookahead_buf)(struct tty_struct *, const u8 *, const u8 *, size_t);
	struct module *owner;
};

struct miscdevice {
	int minor;
	const char *name;
	const struct file_operations *fops;
	struct list_head list;
	struct device *parent;
	struct device *this_device;
	const struct attribute_group **groups;
	const char *nodename;
	umode_t mode;
};

struct perf_pmu_format_hybrid_attr {
	struct device_attribute attr;
	u64 pmu_type;
};

enum {
	LBR_FORMAT_32 = 0,
	LBR_FORMAT_LIP = 1,
	LBR_FORMAT_EIP = 2,
	LBR_FORMAT_EIP_FLAGS = 3,
	LBR_FORMAT_EIP_FLAGS2 = 4,
	LBR_FORMAT_INFO = 5,
	LBR_FORMAT_TIME = 6,
	LBR_FORMAT_INFO2 = 7,
	LBR_FORMAT_MAX_KNOWN = 7,
};

enum perf_hw_id {
	PERF_COUNT_HW_CPU_CYCLES = 0,
	PERF_COUNT_HW_INSTRUCTIONS = 1,
	PERF_COUNT_HW_CACHE_REFERENCES = 2,
	PERF_COUNT_HW_CACHE_MISSES = 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4,
	PERF_COUNT_HW_BRANCH_MISSES = 5,
	PERF_COUNT_HW_BUS_CYCLES = 6,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 7,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 8,
	PERF_COUNT_HW_REF_CPU_CYCLES = 9,
	PERF_COUNT_HW_MAX = 10,
};

enum pmc_type {
	KVM_PMC_GP = 0,
	KVM_PMC_FIXED = 1,
};

enum kvm_apic_logical_mode {
	KVM_APIC_MODE_SW_DISABLED = 0,
	KVM_APIC_MODE_XAPIC_CLUSTER = 1,
	KVM_APIC_MODE_XAPIC_FLAT = 2,
	KVM_APIC_MODE_X2APIC = 3,
	KVM_APIC_MODE_MAP_DISABLED = 4,
};

enum kvm_irqchip_mode {
	KVM_IRQCHIP_NONE = 0,
	KVM_IRQCHIP_KERNEL = 1,
	KVM_IRQCHIP_SPLIT = 2,
};

enum kvm_stat_kind {
	KVM_STAT_VM = 0,
	KVM_STAT_VCPU = 1,
};

struct kvm_vcpu;

struct kvm_pmc {
	enum pmc_type type;
	u8 idx;
	bool is_paused;
	bool intr;
	u64 counter;
	u64 emulated_counter;
	u64 eventsel;
	struct perf_event *perf_event;
	struct kvm_vcpu *vcpu;
	u64 current_config;
};

struct kvm_pmu {
	u8 version;
	unsigned int nr_arch_gp_counters;
	unsigned int nr_arch_fixed_counters;
	unsigned int available_event_types;
	u64 fixed_ctr_ctrl;
	u64 fixed_ctr_ctrl_mask;
	u64 global_ctrl;
	u64 global_status;
	u64 counter_bitmask[2];
	u64 global_ctrl_mask;
	u64 global_status_mask;
	u64 reserved_bits;
	u64 raw_event_mask;
	struct kvm_pmc gp_counters[8];
	struct kvm_pmc fixed_counters[3];
	union {
		unsigned long reprogram_pmi[1];
		atomic64_t __reprogram_pmi;
	};
	unsigned long all_valid_pmc_idx[1];
	unsigned long pmc_in_use[1];
	u64 ds_area;
	u64 pebs_enable;
	u64 pebs_enable_mask;
	u64 pebs_data_cfg;
	u64 pebs_data_cfg_mask;
	u64 host_cross_mapped_mask;
	bool need_cleanup;
	u8 event_count;
};

typedef u64 gpa_t;

struct kvm_mmio_fragment {
	gpa_t gpa;
	void *data;
	unsigned int len;
};

struct kvm_lapic;

typedef s32 int32_t;

struct kvm_page_fault;

struct x86_exception;

struct kvm_mmu_page;

typedef u64 hpa_t;

struct kvm_mmu_root_info {
	gpa_t pgd;
	hpa_t hpa;
};

union kvm_mmu_page_role {
	u32 word;
	struct {
		unsigned int level: 4;
		unsigned int has_4_byte_gpte: 1;
		unsigned int quadrant: 2;
		unsigned int direct: 1;
		unsigned int access: 3;
		unsigned int invalid: 1;
		unsigned int efer_nx: 1;
		unsigned int cr0_wp: 1;
		unsigned int smep_andnot_wp: 1;
		unsigned int smap_andnot_wp: 1;
		unsigned int ad_disabled: 1;
		unsigned int guest_mode: 1;
		unsigned int passthrough: 1;
		char: 5;
		unsigned int smm: 8;
	};
};

union kvm_mmu_extended_role {
	u32 word;
	struct {
		unsigned int valid: 1;
		unsigned int execonly: 1;
		unsigned int cr4_pse: 1;
		unsigned int cr4_pke: 1;
		unsigned int cr4_smap: 1;
		unsigned int cr4_smep: 1;
		unsigned int cr4_la57: 1;
		unsigned int efer_lma: 1;
	};
};

union kvm_cpu_role {
	u64 as_u64;
	struct {
		union kvm_mmu_page_role base;
		union kvm_mmu_extended_role ext;
	};
};

struct rsvd_bits_validate {
	u64 rsvd_bits_mask[10];
	u64 bad_mt_xwr;
};

struct kvm_mmu {
	unsigned long (*get_guest_pgd)(struct kvm_vcpu *);
	u64 (*get_pdptr)(struct kvm_vcpu *, int);
	int (*page_fault)(struct kvm_vcpu *, struct kvm_page_fault *);
	void (*inject_page_fault)(struct kvm_vcpu *, struct x86_exception *);
	gpa_t (*gva_to_gpa)(struct kvm_vcpu *, struct kvm_mmu *, gpa_t, u64, struct x86_exception *);
	int (*sync_spte)(struct kvm_vcpu *, struct kvm_mmu_page *, int);
	struct kvm_mmu_root_info root;
	union kvm_cpu_role cpu_role;
	union kvm_mmu_page_role root_role;
	u32 pkru_mask;
	struct kvm_mmu_root_info prev_roots[3];
	u8 permissions[16];
	u64 *pae_root;
	u64 *pml4_root;
	u64 *pml5_root;
	struct rsvd_bits_validate shadow_zero_check;
	struct rsvd_bits_validate guest_rsvd_check;
	u64 pdptrs[4];
};

struct kvm_mmu_memory_cache {
	gfp_t gfp_zero;
	gfp_t gfp_custom;
	struct kmem_cache *kmem_cache;
	int capacity;
	int nobjs;
	void **objects;
};

struct kvm_pio_request {
	unsigned long linear_rip;
	unsigned long count;
	int in;
	int port;
	int size;
};

struct kvm_queued_exception {
	bool pending;
	bool injected;
	bool has_error_code;
	u8 vector;
	u32 error_code;
	unsigned long payload;
	bool has_payload;
};

struct kvm_queued_interrupt {
	bool injected;
	bool soft;
	u8 nr;
};

struct kvm_hypervisor_cpuid {
	u32 base;
	u32 limit;
};

struct x86_emulate_ctxt;

struct pvclock_vcpu_time_info {
	u32 version;
	u32 pad0;
	u64 tsc_timestamp;
	u64 system_time;
	u32 tsc_to_system_mul;
	s8 tsc_shift;
	u8 flags;
	u8 pad[2];
};

typedef u64 hfn_t;

typedef hfn_t kvm_pfn_t;

struct kvm_memory_slot;

struct kvm;

struct gfn_to_pfn_cache {
	u64 generation;
	gpa_t gpa;
	unsigned long uhva;
	struct kvm_memory_slot *memslot;
	struct kvm *kvm;
	struct list_head list;
	rwlock_t lock;
	struct mutex refresh_lock;
	void *khva;
	kvm_pfn_t pfn;
	bool active;
	bool valid;
};

struct gfn_to_hva_cache {
	u64 generation;
	gpa_t gpa;
	unsigned long hva;
	unsigned long len;
	struct kvm_memory_slot *memslot;
};

struct kvm_mtrr_range {
	u64 base;
	u64 mask;
	struct list_head node;
};

typedef __u8 mtrr_type;

struct kvm_mtrr {
	struct kvm_mtrr_range var_ranges[8];
	mtrr_type fixed_ranges[88];
	u64 deftype;
	struct list_head head;
};

typedef u64 gfn_t;

struct kvm_cpuid_entry2;

struct kvm_vcpu_arch {
	unsigned long regs[17];
	u32 regs_avail;
	u32 regs_dirty;
	unsigned long cr0;
	unsigned long cr0_guest_owned_bits;
	unsigned long cr2;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long cr4_guest_owned_bits;
	unsigned long cr4_guest_rsvd_bits;
	unsigned long cr8;
	u32 host_pkru;
	u32 pkru;
	u32 hflags;
	u64 efer;
	u64 apic_base;
	struct kvm_lapic *apic;
	bool load_eoi_exitmap_pending;
	unsigned long ioapic_handled_vectors[4];
	unsigned long apic_attention;
	int32_t apic_arb_prio;
	int mp_state;
	u64 ia32_misc_enable_msr;
	u64 smbase;
	u64 smi_count;
	bool at_instruction_boundary;
	bool tpr_access_reporting;
	bool xfd_no_write_intercept;
	u64 ia32_xss;
	u64 microcode_version;
	u64 arch_capabilities;
	u64 perf_capabilities;
	struct kvm_mmu *mmu;
	struct kvm_mmu root_mmu;
	struct kvm_mmu guest_mmu;
	struct kvm_mmu nested_mmu;
	struct kvm_mmu *walk_mmu;
	struct kvm_mmu_memory_cache mmu_pte_list_desc_cache;
	struct kvm_mmu_memory_cache mmu_shadow_page_cache;
	struct kvm_mmu_memory_cache mmu_shadowed_info_cache;
	struct kvm_mmu_memory_cache mmu_page_header_cache;
	struct fpu_guest guest_fpu;
	u64 xcr0;
	u64 guest_supported_xcr0;
	struct kvm_pio_request pio;
	void *pio_data;
	void *sev_pio_data;
	unsigned int sev_pio_count;
	u8 event_exit_inst_len;
	bool exception_from_userspace;
	struct kvm_queued_exception exception;
	struct kvm_queued_exception exception_vmexit;
	struct kvm_queued_interrupt interrupt;
	int halt_request;
	int cpuid_nent;
	struct kvm_cpuid_entry2 *cpuid_entries;
	struct kvm_hypervisor_cpuid kvm_cpuid;
	bool is_amd_compatible;
	struct {
		unsigned long enabled[1];
	} governed_features;
	u64 reserved_gpa_bits;
	int maxphyaddr;
	struct x86_emulate_ctxt *emulate_ctxt;
	bool emulate_regs_need_sync_to_vcpu;
	bool emulate_regs_need_sync_from_vcpu;
	int (*complete_userspace_io)(struct kvm_vcpu *);
	gpa_t time;
	struct pvclock_vcpu_time_info hv_clock;
	unsigned int hw_tsc_khz;
	struct gfn_to_pfn_cache pv_time;
	bool pvclock_set_guest_stopped_request;
	struct {
		u8 preempted;
		u64 msr_val;
		u64 last_steal;
		struct gfn_to_hva_cache cache;
	} st;
	u64 l1_tsc_offset;
	u64 tsc_offset;
	u64 last_guest_tsc;
	u64 last_host_tsc;
	u64 tsc_offset_adjustment;
	u64 this_tsc_nsec;
	u64 this_tsc_write;
	u64 this_tsc_generation;
	bool tsc_catchup;
	bool tsc_always_catchup;
	s8 virtual_tsc_shift;
	u32 virtual_tsc_mult;
	u32 virtual_tsc_khz;
	s64 ia32_tsc_adjust_msr;
	u64 msr_ia32_power_ctl;
	u64 l1_tsc_scaling_ratio;
	u64 tsc_scaling_ratio;
	atomic_t nmi_queued;
	unsigned int nmi_pending;
	bool nmi_injected;
	bool smi_pending;
	u8 handling_intr_from_guest;
	struct kvm_mtrr mtrr_state;
	u64 pat;
	unsigned int switch_db_regs;
	unsigned long db[4];
	unsigned long dr6;
	unsigned long dr7;
	unsigned long eff_db[4];
	unsigned long guest_debug_dr7;
	u64 msr_platform_info;
	u64 msr_misc_features_enables;
	u64 mcg_cap;
	u64 mcg_status;
	u64 mcg_ctl;
	u64 mcg_ext_ctl;
	u64 *mce_banks;
	u64 *mci_ctl2_banks;
	u64 mmio_gva;
	unsigned int mmio_access;
	gfn_t mmio_gfn;
	u64 mmio_gen;
	struct kvm_pmu pmu;
	unsigned long singlestep_rip;
	cpumask_var_t wbinvd_dirty_mask;
	unsigned long last_retry_eip;
	unsigned long last_retry_addr;
	struct {
		bool halted;
		gfn_t gfns[64];
		struct gfn_to_hva_cache data;
		u64 msr_en_val;
		u64 msr_int_val;
		u16 vec;
		u32 id;
		bool send_user_only;
		u32 host_apf_flags;
		bool delivery_as_pf_vmexit;
		bool pageready_pending;
	} apf;
	struct {
		u64 length;
		u64 status;
	} osvw;
	struct {
		u64 msr_val;
		struct gfn_to_hva_cache data;
	} pv_eoi;
	u64 msr_kvm_poll_control;
	unsigned long exit_qualification;
	struct {
		bool pv_unhalted;
	} pv;
	int pending_ioapic_eoi;
	int pending_external_vector;
	bool preempted_in_kernel;
	bool l1tf_flush_l1d;
	int last_vmentry_cpu;
	u64 msr_hwcr;
	struct {
		u32 features;
		bool enforce;
	} pv_cpuid;
	bool guest_state_protected;
	bool pdptrs_from_userspace;
};

struct kvm_vcpu_stat_generic {
	u64 halt_successful_poll;
	u64 halt_attempted_poll;
	u64 halt_poll_invalid;
	u64 halt_wakeup;
	u64 halt_poll_success_ns;
	u64 halt_poll_fail_ns;
	u64 halt_wait_ns;
	u64 halt_poll_success_hist[32];
	u64 halt_poll_fail_hist[32];
	u64 halt_wait_hist[32];
	u64 blocking;
};

struct kvm_vcpu_stat {
	struct kvm_vcpu_stat_generic generic;
	u64 pf_taken;
	u64 pf_fixed;
	u64 pf_emulate;
	u64 pf_spurious;
	u64 pf_fast;
	u64 pf_mmio_spte_created;
	u64 pf_guest;
	u64 tlb_flush;
	u64 invlpg;
	u64 exits;
	u64 io_exits;
	u64 mmio_exits;
	u64 signal_exits;
	u64 irq_window_exits;
	u64 nmi_window_exits;
	u64 l1d_flush;
	u64 halt_exits;
	u64 request_irq_exits;
	u64 irq_exits;
	u64 host_state_reload;
	u64 fpu_reload;
	u64 insn_emulation;
	u64 insn_emulation_fail;
	u64 hypercalls;
	u64 irq_injections;
	u64 nmi_injections;
	u64 req_event;
	u64 nested_run;
	u64 directed_yield_attempted;
	u64 directed_yield_successful;
	u64 preemption_reported;
	u64 preemption_other;
	u64 guest_mode;
	u64 notify_window_exits;
};

struct kvm_dirty_gfn;

struct kvm_dirty_ring {
	u32 dirty_index;
	u32 reset_index;
	u32 size;
	u32 soft_limit;
	struct kvm_dirty_gfn *dirty_gfns;
	int index;
};

struct kvm_run;

struct kvm_vcpu {
	struct kvm *kvm;
	int cpu;
	int vcpu_id;
	int vcpu_idx;
	int ____srcu_idx;
	int mode;
	u64 requests;
	unsigned long guest_debug;
	struct mutex mutex;
	struct kvm_run *run;
	struct rcuwait wait;
	struct pid __attribute__((btf_type_tag("rcu"))) *pid;
	int sigset_active;
	sigset_t sigset;
	unsigned int halt_poll_ns;
	bool valid_wakeup;
	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_cur_fragment;
	int mmio_nr_fragments;
	struct kvm_mmio_fragment mmio_fragments[2];
	bool preempted;
	bool ready;
	struct kvm_vcpu_arch arch;
	struct kvm_vcpu_stat stat;
	char stats_id[48];
	struct kvm_dirty_ring dirty_ring;
	struct kvm_memory_slot *last_used_slot;
	u64 last_used_slot_gen;
};

struct kvm_memslots {
	u64 generation;
	atomic_long_t last_used_slot;
	struct rb_root_cached hva_tree;
	struct rb_root gfn_tree;
	struct hlist_head id_hash[128];
	int node_idx;
};

struct kvm_vm_stat_generic {
	u64 remote_tlb_flush;
	u64 remote_tlb_flush_requests;
};

struct kvm_vm_stat {
	struct kvm_vm_stat_generic generic;
	u64 mmu_shadow_zapped;
	u64 mmu_pte_write;
	u64 mmu_pde_zapped;
	u64 mmu_flooded;
	u64 mmu_recycled;
	u64 mmu_cache_miss;
	u64 mmu_unsync;
	union {
		struct {
			atomic64_t pages_4k;
			atomic64_t pages_2m;
			atomic64_t pages_1g;
		};
		atomic64_t pages[3];
	};
	u64 nx_lpage_splits;
	u64 max_mmu_page_hash_collisions;
	u64 max_mmu_rmap_size;
};

struct iommu_domain;

struct kvm_pic;

struct kvm_ioapic;

struct kvm_pit;

struct kvm_xen_hvm_config {
	__u32 flags;
	__u32 msr;
	__u64 blob_addr_32;
	__u64 blob_addr_64;
	__u8 blob_size_32;
	__u8 blob_size_64;
	__u8 pad2[30];
};

struct kvm_apic_map;

struct kvm_x86_msr_filter;

struct kvm_x86_pmu_event_filter;

struct kvm_arch {
	unsigned long vm_type;
	unsigned long n_used_mmu_pages;
	unsigned long n_requested_mmu_pages;
	unsigned long n_max_mmu_pages;
	unsigned int indirect_shadow_pages;
	u8 mmu_valid_gen;
	struct hlist_head mmu_page_hash[4096];
	struct list_head active_mmu_pages;
	struct list_head zapped_obsolete_pages;
	struct list_head possible_nx_huge_pages;
	spinlock_t mmu_unsync_pages_lock;
	struct iommu_domain *iommu_domain;
	bool iommu_noncoherent;
	atomic_t noncoherent_dma_count;
	atomic_t assigned_device_count;
	struct kvm_pic *vpic;
	struct kvm_ioapic *vioapic;
	struct kvm_pit *vpit;
	atomic_t vapics_in_nmi_mode;
	struct mutex apic_map_lock;
	struct kvm_apic_map __attribute__((btf_type_tag("rcu"))) *apic_map;
	atomic_t apic_map_dirty;
	bool apic_access_memslot_enabled;
	bool apic_access_memslot_inhibited;
	struct rw_semaphore apicv_update_lock;
	unsigned long apicv_inhibit_reasons;
	gpa_t wall_clock;
	bool mwait_in_guest;
	bool hlt_in_guest;
	bool pause_in_guest;
	bool cstate_in_guest;
	unsigned long irq_sources_bitmap;
	s64 kvmclock_offset;
	raw_spinlock_t tsc_write_lock;
	u64 last_tsc_nsec;
	u64 last_tsc_write;
	u32 last_tsc_khz;
	u64 last_tsc_offset;
	u64 cur_tsc_nsec;
	u64 cur_tsc_write;
	u64 cur_tsc_offset;
	u64 cur_tsc_generation;
	int nr_vcpus_matched_tsc;
	u32 default_tsc_khz;
	bool user_set_tsc;
	seqcount_raw_spinlock_t pvclock_sc;
	bool use_master_clock;
	u64 master_kernel_ns;
	u64 master_cycle_now;
	struct delayed_work kvmclock_update_work;
	struct delayed_work kvmclock_sync_work;
	struct kvm_xen_hvm_config xen_hvm_config;
	struct hlist_head mask_notifier_list;
	bool backwards_tsc_observed;
	bool boot_vcpu_runs_old_kvmclock;
	u32 bsp_vcpu_id;
	u64 disabled_quirks;
	enum kvm_irqchip_mode irqchip_mode;
	u8 nr_reserved_ioapic_pins;
	bool disabled_lapic_found;
	bool x2apic_format;
	bool x2apic_broadcast_quirk_disabled;
	bool guest_can_read_msr_platform_info;
	bool exception_payload_enabled;
	bool triple_fault_event;
	bool bus_lock_detection_enabled;
	bool enable_pmu;
	u32 notify_window;
	u32 notify_vmexit_flags;
	bool exit_on_emulation_error;
	u32 user_space_msr_mask;
	struct kvm_x86_msr_filter __attribute__((btf_type_tag("rcu"))) *msr_filter;
	u32 hypercall_exit_enabled;
	bool sgx_provisioning_allowed;
	struct kvm_x86_pmu_event_filter __attribute__((btf_type_tag("rcu"))) *pmu_event_filter;
	struct task_struct *nx_huge_page_recovery_thread;
	atomic64_t tdp_mmu_pages;
	struct list_head tdp_mmu_roots;
	spinlock_t tdp_mmu_pages_lock;
	bool shadow_root_allocated;
	u32 max_vcpu_ids;
	bool disable_nx_huge_pages;
	struct kvm_mmu_memory_cache split_shadow_page_cache;
	struct kvm_mmu_memory_cache split_page_header_cache;
	struct kvm_mmu_memory_cache split_desc_cache;
};

struct srcu_struct {
	short srcu_lock_nesting[2];
	u8 srcu_gp_running;
	u8 srcu_gp_waiting;
	unsigned long srcu_idx;
	unsigned long srcu_idx_max;
	struct swait_queue_head srcu_wq;
	struct callback_head *srcu_cb_head;
	struct callback_head **srcu_cb_tail;
	struct work_struct srcu_work;
};

struct kvm_io_bus;

struct kvm_stat_data;

struct kvm {
	rwlock_t mmu_lock;
	struct mutex slots_lock;
	struct mutex slots_arch_lock;
	struct mm_struct *mm;
	unsigned long nr_memslot_pages;
	struct kvm_memslots __memslots[2];
	struct kvm_memslots __attribute__((btf_type_tag("rcu"))) *memslots[1];
	struct xarray vcpu_array;
	atomic_t nr_memslots_dirty_logging;
	spinlock_t mn_invalidate_lock;
	unsigned long mn_active_invalidate_count;
	struct rcuwait mn_memslots_update_rcuwait;
	spinlock_t gpc_lock;
	struct list_head gpc_list;
	atomic_t online_vcpus;
	int max_vcpus;
	int created_vcpus;
	int last_boosted_vcpu;
	struct list_head vm_list;
	struct mutex lock;
	struct kvm_io_bus __attribute__((btf_type_tag("rcu"))) *buses[4];
	struct list_head ioeventfds;
	struct kvm_vm_stat stat;
	struct kvm_arch arch;
	refcount_t users_count;
	struct mutex irq_lock;
	struct list_head devices;
	u64 manual_dirty_log_protect;
	struct dentry *debugfs_dentry;
	struct kvm_stat_data **debugfs_stat_data;
	struct srcu_struct srcu;
	struct srcu_struct irq_srcu;
	pid_t userspace_pid;
	bool override_halt_poll_ns;
	unsigned int max_halt_poll_ns;
	u32 dirty_ring_size;
	bool dirty_ring_with_bitmap;
	bool vm_bugged;
	bool vm_dead;
	char stats_id[48];
};

struct kvm_io_device;

struct kvm_io_range {
	gpa_t addr;
	int len;
	struct kvm_io_device *dev;
};

struct kvm_io_bus {
	int dev_count;
	int ioeventfd_count;
	struct kvm_io_range range[0];
};

struct kvm_apic_map {
	struct callback_head rcu;
	enum kvm_apic_logical_mode logical_mode;
	u32 max_apic_id;
	union {
		struct kvm_lapic *xapic_flat_map[8];
		struct kvm_lapic *xapic_cluster_map[64];
	};
	struct kvm_lapic *phys_map[0];
};

struct msr_bitmap_range {
	u32 flags;
	u32 nmsrs;
	u32 base;
	unsigned long *bitmap;
};

struct kvm_x86_msr_filter {
	u8 count;
	bool default_allow: 1;
	struct msr_bitmap_range ranges[16];
};

struct kvm_x86_pmu_event_filter {
	__u32 action;
	__u32 nevents;
	__u32 fixed_counter_bitmap;
	__u32 flags;
	__u32 nr_includes;
	__u32 nr_excludes;
	__u64 *includes;
	__u64 *excludes;
	__u64 events[0];
};

struct _kvm_stats_desc;

struct kvm_stat_data {
	struct kvm *kvm;
	const struct _kvm_stats_desc *desc;
	enum kvm_stat_kind kind;
};

struct kvm_stats_desc {
	__u32 flags;
	__s16 exponent;
	__u16 size;
	__u32 offset;
	__u32 bucket_size;
	char name[0];
};

struct _kvm_stats_desc {
	struct kvm_stats_desc desc;
	char name[48];
};

struct kvm_debug_exit_arch {
	__u32 exception;
	__u32 pad;
	__u64 pc;
	__u64 dr6;
	__u64 dr7;
};

struct kvm_hyperv_exit {
	__u32 type;
	__u32 pad1;
	union {
		struct {
			__u32 msr;
			__u32 pad2;
			__u64 control;
			__u64 evt_page;
			__u64 msg_page;
		} synic;
		struct {
			__u64 input;
			__u64 result;
			__u64 params[2];
		} hcall;
		struct {
			__u32 msr;
			__u32 pad2;
			__u64 control;
			__u64 status;
			__u64 send_page;
			__u64 recv_page;
			__u64 pending_page;
		} syndbg;
	} u;
};

struct kvm_xen_exit {
	__u32 type;
	union {
		struct {
			__u32 longmode;
			__u32 cpl;
			__u64 input;
			__u64 result;
			__u64 params[6];
		} hcall;
	} u;
};

struct kvm_regs {
	__u64 rax;
	__u64 rbx;
	__u64 rcx;
	__u64 rdx;
	__u64 rsi;
	__u64 rdi;
	__u64 rsp;
	__u64 rbp;
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
	__u64 rip;
	__u64 rflags;
};

struct kvm_segment {
	__u64 base;
	__u32 limit;
	__u16 selector;
	__u8 type;
	__u8 present;
	__u8 dpl;
	__u8 db;
	__u8 s;
	__u8 l;
	__u8 g;
	__u8 avl;
	__u8 unusable;
	__u8 padding;
};

struct kvm_dtable {
	__u64 base;
	__u16 limit;
	__u16 padding[3];
};

struct kvm_sregs {
	struct kvm_segment cs;
	struct kvm_segment ds;
	struct kvm_segment es;
	struct kvm_segment fs;
	struct kvm_segment gs;
	struct kvm_segment ss;
	struct kvm_segment tr;
	struct kvm_segment ldt;
	struct kvm_dtable gdt;
	struct kvm_dtable idt;
	__u64 cr0;
	__u64 cr2;
	__u64 cr3;
	__u64 cr4;
	__u64 cr8;
	__u64 efer;
	__u64 apic_base;
	__u64 interrupt_bitmap[4];
};

struct kvm_vcpu_events {
	struct {
		__u8 injected;
		__u8 nr;
		__u8 has_error_code;
		__u8 pending;
		__u32 error_code;
	} exception;
	struct {
		__u8 injected;
		__u8 nr;
		__u8 soft;
		__u8 shadow;
	} interrupt;
	struct {
		__u8 injected;
		__u8 pending;
		__u8 masked;
		__u8 pad;
	} nmi;
	__u32 sipi_vector;
	__u32 flags;
	struct {
		__u8 smm;
		__u8 pending;
		__u8 smm_inside_nmi;
		__u8 latched_init;
	} smi;
	struct {
		__u8 pending;
	} triple_fault;
	__u8 reserved[26];
	__u8 exception_has_payload;
	__u64 exception_payload;
};

struct kvm_sync_regs {
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	struct kvm_vcpu_events events;
};

struct kvm_run {
	__u8 request_interrupt_window;
	__u8 immediate_exit;
	__u8 padding1[6];
	__u32 exit_reason;
	__u8 ready_for_interrupt_injection;
	__u8 if_flag;
	__u16 flags;
	__u64 cr8;
	__u64 apic_base;
	union {
		struct {
			__u64 hardware_exit_reason;
		} hw;
		struct {
			__u64 hardware_entry_failure_reason;
			__u32 cpu;
		} fail_entry;
		struct {
			__u32 exception;
			__u32 error_code;
		} ex;
		struct {
			__u8 direction;
			__u8 size;
			__u16 port;
			__u32 count;
			__u64 data_offset;
		} io;
		struct {
			struct kvm_debug_exit_arch arch;
		} debug;
		struct {
			__u64 phys_addr;
			__u8 data[8];
			__u32 len;
			__u8 is_write;
		} mmio;
		struct {
			__u64 phys_addr;
			__u8 data[8];
			__u32 len;
			__u8 is_write;
		} iocsr_io;
		struct {
			__u64 nr;
			__u64 args[6];
			__u64 ret;
			union {
				__u64 flags;
			};
		} hypercall;
		struct {
			__u64 rip;
			__u32 is_write;
			__u32 pad;
		} tpr_access;
		struct {
			__u8 icptcode;
			__u16 ipa;
			__u32 ipb;
		} s390_sieic;
		__u64 s390_reset_flags;
		struct {
			__u64 trans_exc_code;
			__u32 pgm_code;
		} s390_ucontrol;
		struct {
			__u32 dcrn;
			__u32 data;
			__u8 is_write;
		} dcr;
		struct {
			__u32 suberror;
			__u32 ndata;
			__u64 data[16];
		} internal;
		struct {
			__u32 suberror;
			__u32 ndata;
			__u64 flags;
			union {
				struct {
					__u8 insn_size;
					__u8 insn_bytes[15];
				};
			};
		} emulation_failure;
		struct {
			__u64 gprs[32];
		} osi;
		struct {
			__u64 nr;
			__u64 ret;
			__u64 args[9];
		} papr_hcall;
		struct {
			__u16 subchannel_id;
			__u16 subchannel_nr;
			__u32 io_int_parm;
			__u32 io_int_word;
			__u32 ipb;
			__u8 dequeued;
		} s390_tsch;
		struct {
			__u32 epr;
		} epr;
		struct {
			__u32 type;
			__u32 ndata;
			union {
				__u64 data[16];
			};
		} system_event;
		struct {
			__u64 addr;
			__u8 ar;
			__u8 reserved;
			__u8 fc;
			__u8 sel1;
			__u16 sel2;
		} s390_stsi;
		struct {
			__u8 vector;
		} eoi;
		struct kvm_hyperv_exit hyperv;
		struct {
			__u64 esr_iss;
			__u64 fault_ipa;
		} arm_nisv;
		struct {
			__u8 error;
			__u8 pad[7];
			__u32 reason;
			__u32 index;
			__u64 data;
		} msr;
		struct kvm_xen_exit xen;
		struct {
			unsigned long extension_id;
			unsigned long function_id;
			unsigned long args[6];
			unsigned long ret[2];
		} riscv_sbi;
		struct {
			unsigned long csr_num;
			unsigned long new_value;
			unsigned long write_mask;
			unsigned long ret_value;
		} riscv_csr;
		struct {
			__u32 flags;
		} notify;
		struct {
			__u64 flags;
			__u64 gpa;
			__u64 size;
		} memory_fault;
		char padding[256];
	};
	__u64 kvm_valid_regs;
	__u64 kvm_dirty_regs;
	union {
		struct kvm_sync_regs regs;
		char padding[2048];
	} s;
};

struct kvm_cpuid_entry2 {
	__u32 function;
	__u32 index;
	__u32 flags;
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
	__u32 padding[3];
};

struct interval_tree_node {
	struct rb_node rb;
	unsigned long start;
	unsigned long last;
	unsigned long __subtree_last;
};

struct kvm_rmap_head;

struct kvm_lpage_info;

struct kvm_arch_memory_slot {
	struct kvm_rmap_head *rmap[3];
	struct kvm_lpage_info *lpage_info[2];
	unsigned short *gfn_write_track;
};

struct kvm_memory_slot {
	struct hlist_node id_node[2];
	struct interval_tree_node hva_node[2];
	struct rb_node gfn_node[2];
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long *dirty_bitmap;
	struct kvm_arch_memory_slot arch;
	unsigned long userspace_addr;
	u32 flags;
	short id;
	u16 as_id;
};

struct kvm_rmap_head {
	unsigned long val;
};

struct kvm_lpage_info {
	int disallow_lpage;
};

struct kvm_dirty_gfn {
	__u32 flags;
	__u32 slot;
	__u64 offset;
};

union cpuid10_edx {
	struct {
		unsigned int num_counters_fixed: 5;
		unsigned int bit_width_fixed: 8;
		unsigned int reserved1: 2;
		unsigned int anythread_deprecated: 1;
		unsigned int reserved2: 16;
	} split;
	unsigned int full;
};

union cpuid10_eax {
	struct {
		unsigned int version_id: 8;
		unsigned int num_counters: 8;
		unsigned int bit_width: 8;
		unsigned int mask_length: 8;
	} split;
	unsigned int full;
};

union cpuid10_ebx {
	struct {
		unsigned int no_unhalted_core_cycles: 1;
		unsigned int no_instructions_retired: 1;
		unsigned int no_unhalted_reference_cycles: 1;
		unsigned int no_llc_reference: 1;
		unsigned int no_llc_misses: 1;
		unsigned int no_branch_instruction_retired: 1;
		unsigned int no_branch_misses_retired: 1;
	} split;
	unsigned int full;
};

typedef int perf_snapshot_branch_stack_t(struct perf_branch_entry *, unsigned int);

enum {
	KERNEL_PARAM_OPS_FL_NOARG = 1,
};

enum {
	KERNEL_PARAM_FL_UNSAFE = 1,
	KERNEL_PARAM_FL_HWPARAM = 2,
};

enum lockdown_reason {
	LOCKDOWN_NONE = 0,
	LOCKDOWN_MODULE_SIGNATURE = 1,
	LOCKDOWN_DEV_MEM = 2,
	LOCKDOWN_EFI_TEST = 3,
	LOCKDOWN_KEXEC = 4,
	LOCKDOWN_HIBERNATION = 5,
	LOCKDOWN_PCI_ACCESS = 6,
	LOCKDOWN_IOPORT = 7,
	LOCKDOWN_MSR = 8,
	LOCKDOWN_ACPI_TABLES = 9,
	LOCKDOWN_DEVICE_TREE = 10,
	LOCKDOWN_PCMCIA_CIS = 11,
	LOCKDOWN_TIOCSSERIAL = 12,
	LOCKDOWN_MODULE_PARAMETERS = 13,
	LOCKDOWN_MMIOTRACE = 14,
	LOCKDOWN_DEBUGFS = 15,
	LOCKDOWN_XMON_WR = 16,
	LOCKDOWN_BPF_WRITE_USER = 17,
	LOCKDOWN_DBG_WRITE_KERNEL = 18,
	LOCKDOWN_RTAS_ERROR_INJECTION = 19,
	LOCKDOWN_INTEGRITY_MAX = 20,
	LOCKDOWN_KCORE = 21,
	LOCKDOWN_KPROBES = 22,
	LOCKDOWN_BPF_READ_KERNEL = 23,
	LOCKDOWN_DBG_READ_KERNEL = 24,
	LOCKDOWN_PERF = 25,
	LOCKDOWN_TRACEFS = 26,
	LOCKDOWN_XMON_RW = 27,
	LOCKDOWN_XFRM_SECRET = 28,
	LOCKDOWN_CONFIDENTIALITY_MAX = 29,
};

enum lockdep_ok {
	LOCKDEP_STILL_OK = 0,
	LOCKDEP_NOW_UNRELIABLE = 1,
};

struct kmalloced_param {
	struct list_head list;
	char val[0];
};

enum reboot_mode {
	REBOOT_UNDEFINED = -1,
	REBOOT_COLD = 0,
	REBOOT_WARM = 1,
	REBOOT_HARD = 2,
	REBOOT_SOFT = 3,
	REBOOT_GPIO = 4,
};

enum reboot_type {
	BOOT_TRIPLE = 116,
	BOOT_KBD = 107,
	BOOT_BIOS = 98,
	BOOT_ACPI = 97,
	BOOT_EFI = 101,
	BOOT_CF9_FORCE = 112,
	BOOT_CF9_SAFE = 113,
};

enum sys_off_mode {
	SYS_OFF_MODE_POWER_OFF_PREPARE = 0,
	SYS_OFF_MODE_POWER_OFF = 1,
	SYS_OFF_MODE_RESTART_PREPARE = 2,
	SYS_OFF_MODE_RESTART = 3,
};

struct sys_off_data;

struct sys_off_handler {
	struct notifier_block nb;
	int (*sys_off_cb)(struct sys_off_data *);
	void *cb_data;
	enum sys_off_mode mode;
	bool blocking;
	void *list;
	struct device *dev;
};

struct sys_off_data {
	int mode;
	void *cb_data;
	const char *cmd;
	struct device *dev;
};

enum kmsg_dump_reason {
	KMSG_DUMP_UNDEF = 0,
	KMSG_DUMP_PANIC = 1,
	KMSG_DUMP_OOPS = 2,
	KMSG_DUMP_EMERG = 3,
	KMSG_DUMP_SHUTDOWN = 4,
	KMSG_DUMP_MAX = 5,
};

enum umh_disable_depth {
	UMH_ENABLED = 0,
	UMH_FREEZING = 1,
	UMH_DISABLED = 2,
};

enum clock_event_state {
	CLOCK_EVT_STATE_DETACHED = 0,
	CLOCK_EVT_STATE_SHUTDOWN = 1,
	CLOCK_EVT_STATE_PERIODIC = 2,
	CLOCK_EVT_STATE_ONESHOT = 3,
	CLOCK_EVT_STATE_ONESHOT_STOPPED = 4,
};

enum tick_device_mode {
	TICKDEV_MODE_PERIODIC = 0,
	TICKDEV_MODE_ONESHOT = 1,
};

enum hrtimer_base_type {
	HRTIMER_BASE_MONOTONIC = 0,
	HRTIMER_BASE_REALTIME = 1,
	HRTIMER_BASE_BOOTTIME = 2,
	HRTIMER_BASE_TAI = 3,
	HRTIMER_BASE_MONOTONIC_SOFT = 4,
	HRTIMER_BASE_REALTIME_SOFT = 5,
	HRTIMER_BASE_BOOTTIME_SOFT = 6,
	HRTIMER_BASE_TAI_SOFT = 7,
	HRTIMER_MAX_CLOCK_BASES = 8,
};

struct clock_event_device;

struct tick_device {
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};

struct clock_event_device {
	void (*event_handler)(struct clock_event_device *);
	int (*set_next_event)(unsigned long, struct clock_event_device *);
	int (*set_next_ktime)(ktime_t, struct clock_event_device *);
	ktime_t next_event;
	u64 max_delta_ns;
	u64 min_delta_ns;
	u32 mult;
	u32 shift;
	enum clock_event_state state_use_accessors;
	unsigned int features;
	unsigned long retries;
	int (*set_state_periodic)(struct clock_event_device *);
	int (*set_state_oneshot)(struct clock_event_device *);
	int (*set_state_oneshot_stopped)(struct clock_event_device *);
	int (*set_state_shutdown)(struct clock_event_device *);
	int (*tick_resume)(struct clock_event_device *);
	void (*broadcast)(const struct cpumask *);
	void (*suspend)(struct clock_event_device *);
	void (*resume)(struct clock_event_device *);
	unsigned long min_delta_ticks;
	unsigned long max_delta_ticks;
	const char *name;
	int rating;
	int irq;
	int bound_on;
	const struct cpumask *cpumask;
	struct list_head list;
	struct module *owner;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum {
	BPF_RINGBUF_BUSY_BIT = 2147483648,
	BPF_RINGBUF_DISCARD_BIT = 1073741824,
	BPF_RINGBUF_HDR_SZ = 8,
};

enum {
	BPF_RB_NO_WAKEUP = 1,
	BPF_RB_FORCE_WAKEUP = 2,
};

enum {
	BPF_RB_AVAIL_DATA = 0,
	BPF_RB_RING_SIZE = 1,
	BPF_RB_CONS_POS = 2,
	BPF_RB_PROD_POS = 3,
};

enum bpf_dynptr_type {
	BPF_DYNPTR_TYPE_INVALID = 0,
	BPF_DYNPTR_TYPE_LOCAL = 1,
	BPF_DYNPTR_TYPE_RINGBUF = 2,
	BPF_DYNPTR_TYPE_SKB = 3,
	BPF_DYNPTR_TYPE_XDP = 4,
};

typedef u64 (*btf_bpf_ringbuf_reserve)(struct bpf_map *, u64, u64);

typedef u64 (*btf_bpf_ringbuf_submit)(void *, u64);

typedef u64 (*btf_bpf_ringbuf_discard)(void *, u64);

typedef u64 (*btf_bpf_ringbuf_output)(struct bpf_map *, void *, u64, u64);

typedef u64 (*btf_bpf_ringbuf_query)(struct bpf_map *, u64);

struct bpf_dynptr_kern;

typedef u64 (*btf_bpf_ringbuf_reserve_dynptr)(struct bpf_map *, u32, u64, struct bpf_dynptr_kern *);

struct bpf_dynptr_kern {
	void *data;
	u32 size;
	u32 offset;
};

typedef u64 (*btf_bpf_ringbuf_submit_dynptr)(struct bpf_dynptr_kern *, u64);

typedef u64 (*btf_bpf_ringbuf_discard_dynptr)(struct bpf_dynptr_kern *, u64);

typedef u64 (*btf_bpf_user_ringbuf_drain)(struct bpf_map *, void *, void *, u64);

struct bpf_ringbuf {
	wait_queue_head_t waitq;
	struct irq_work work;
	u64 mask;
	struct page **pages;
	int nr_pages;
	spinlock_t spinlock;
	atomic_t busy;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	unsigned long consumer_pos;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	unsigned long producer_pos;
	unsigned long pending_pos;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	char data[0];
};

struct bpf_ringbuf_map {
	struct bpf_map map;
	struct bpf_ringbuf *rb;
};

typedef struct poll_table_struct poll_table;

struct bpf_ringbuf_hdr {
	u32 len;
	u32 pg_off;
};

struct lru_rotate {
	local_lock_t lock;
	struct folio_batch fbatch;
};

struct cpu_fbatches {
	local_lock_t lock;
	struct folio_batch lru_add;
	struct folio_batch lru_deactivate_file;
	struct folio_batch lru_deactivate;
	struct folio_batch lru_lazyfree;
};

enum vm_event_item {
	PGPGIN = 0,
	PGPGOUT = 1,
	PSWPIN = 2,
	PSWPOUT = 3,
	PGALLOC_DMA32 = 4,
	PGALLOC_NORMAL = 5,
	PGALLOC_MOVABLE = 6,
	ALLOCSTALL_DMA32 = 7,
	ALLOCSTALL_NORMAL = 8,
	ALLOCSTALL_MOVABLE = 9,
	PGSCAN_SKIP_DMA32 = 10,
	PGSCAN_SKIP_NORMAL = 11,
	PGSCAN_SKIP_MOVABLE = 12,
	PGFREE = 13,
	PGACTIVATE = 14,
	PGDEACTIVATE = 15,
	PGLAZYFREE = 16,
	PGFAULT = 17,
	PGMAJFAULT = 18,
	PGLAZYFREED = 19,
	PGREFILL = 20,
	PGREUSE = 21,
	PGSTEAL_KSWAPD = 22,
	PGSTEAL_DIRECT = 23,
	PGSTEAL_KHUGEPAGED = 24,
	PGSCAN_KSWAPD = 25,
	PGSCAN_DIRECT = 26,
	PGSCAN_KHUGEPAGED = 27,
	PGSCAN_DIRECT_THROTTLE = 28,
	PGSCAN_ANON = 29,
	PGSCAN_FILE = 30,
	PGSTEAL_ANON = 31,
	PGSTEAL_FILE = 32,
	PGINODESTEAL = 33,
	SLABS_SCANNED = 34,
	KSWAPD_INODESTEAL = 35,
	KSWAPD_LOW_WMARK_HIT_QUICKLY = 36,
	KSWAPD_HIGH_WMARK_HIT_QUICKLY = 37,
	PAGEOUTRUN = 38,
	PGROTATED = 39,
	DROP_PAGECACHE = 40,
	DROP_SLAB = 41,
	OOM_KILL = 42,
	UNEVICTABLE_PGCULLED = 43,
	UNEVICTABLE_PGSCANNED = 44,
	UNEVICTABLE_PGRESCUED = 45,
	UNEVICTABLE_PGMLOCKED = 46,
	UNEVICTABLE_PGMUNLOCKED = 47,
	UNEVICTABLE_PGCLEARED = 48,
	UNEVICTABLE_PGSTRANDED = 49,
	DIRECT_MAP_LEVEL2_SPLIT = 50,
	DIRECT_MAP_LEVEL3_SPLIT = 51,
	NR_VM_EVENT_ITEMS = 52,
};

enum mapping_flags {
	AS_EIO = 0,
	AS_ENOSPC = 1,
	AS_MM_ALL_LOCKS = 2,
	AS_UNEVICTABLE = 3,
	AS_EXITING = 4,
	AS_NO_WRITEBACK_TAGS = 5,
	AS_LARGE_FOLIO_SUPPORT = 6,
	AS_RELEASE_ALWAYS = 7,
	AS_STABLE_WRITES = 8,
	AS_UNMOVABLE = 9,
};

typedef void (*move_fn_t)(struct lruvec *, struct folio *);

typedef __u64 __addrpair;

typedef __u32 __portpair;

struct proto;

struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		unsigned int skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		__portpair skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	unsigned short skc_family;
	volatile unsigned char skc_state;
	unsigned char skc_reuse: 4;
	unsigned char skc_reuseport: 1;
	unsigned char skc_ipv6only: 1;
	unsigned char skc_net_refcnt: 1;
	int skc_bound_dev_if;
	union {
		struct hlist_node skc_bind_node;
		struct hlist_node skc_portaddr_node;
	};
	struct proto *skc_prot;
	possible_net_t skc_net;
	atomic64_t skc_cookie;
	union {
		unsigned long skc_flags;
		struct sock *skc_listener;
		struct inet_timewait_death_row *skc_tw_dr;
	};
	int skc_dontcopy_begin[0];
	union {
		struct hlist_node skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	unsigned short skc_tx_queue_mapping;
	union {
		int skc_incoming_cpu;
		u32 skc_rcv_wnd;
		u32 skc_tw_rcv_nxt;
	};
	refcount_t skc_refcnt;
	int skc_dontcopy_end[0];
	union {
		u32 skc_rxhash;
		u32 skc_window_clamp;
		u32 skc_tw_snd_nxt;
	};
};

typedef struct {
	spinlock_t slock;
	int owned;
	wait_queue_head_t wq;
} socket_lock_t;

struct sock_cgroup_data {};

typedef struct {} netns_tracker;

struct dst_entry;

struct sk_filter;

struct socket_wq;

struct socket;

struct sock_reuseport;

struct sock {
	struct sock_common __sk_common;
	__u8 __cacheline_group_begin__sock_write_rx[0];
	atomic_t sk_drops;
	__s32 sk_peek_off;
	struct sk_buff_head sk_error_queue;
	struct sk_buff_head sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	__u8 __cacheline_group_end__sock_write_rx[0];
	__u8 __cacheline_group_begin__sock_read_rx[0];
	struct dst_entry __attribute__((btf_type_tag("rcu"))) *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	u8 sk_userlocks;
	int sk_rcvbuf;
	struct sk_filter __attribute__((btf_type_tag("rcu"))) *sk_filter;
	union {
		struct socket_wq __attribute__((btf_type_tag("rcu"))) *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	void (*sk_data_ready)(struct sock *);
	long sk_rcvtimeo;
	int sk_rcvlowat;
	__u8 __cacheline_group_end__sock_read_rx[0];
	__u8 __cacheline_group_begin__sock_read_rxtx[0];
	int sk_err;
	struct socket *sk_socket;
	struct mem_cgroup *sk_memcg;
	__u8 __cacheline_group_end__sock_read_rxtx[0];
	__u8 __cacheline_group_begin__sock_write_rxtx[0];
	socket_lock_t sk_lock;
	u32 sk_reserved_mem;
	int sk_forward_alloc;
	u32 sk_tsflags;
	__u8 __cacheline_group_end__sock_write_rxtx[0];
	__u8 __cacheline_group_begin__sock_write_tx[0];
	int sk_write_pending;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	unsigned long sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head sk_write_queue;
	u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	struct page_frag sk_frag;
	struct timer_list sk_timer;
	unsigned long sk_pacing_rate;
	atomic_t sk_zckey;
	atomic_t sk_tskey;
	__u8 __cacheline_group_end__sock_write_tx[0];
	__u8 __cacheline_group_begin__sock_read_tx[0];
	unsigned long sk_max_pacing_rate;
	long sk_sndtimeo;
	u32 sk_priority;
	u32 sk_mark;
	struct dst_entry __attribute__((btf_type_tag("rcu"))) *sk_dst_cache;
	netdev_features_t sk_route_caps;
	u16 sk_gso_type;
	u16 sk_gso_max_segs;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	u32 sk_txhash;
	u8 sk_pacing_shift;
	bool sk_use_task_frag;
	__u8 __cacheline_group_end__sock_read_tx[0];
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_shutdown;
	u16 sk_type;
	u16 sk_protocol;
	unsigned long sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid *sk_peer_pid;
	const struct cred *sk_peer_cred;
	ktime_t sk_stamp;
	int sk_disconnects;
	u8 sk_txrehash;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	void *sk_user_data;
	struct sock_cgroup_data sk_cgrp_data;
	void (*sk_state_change)(struct sock *);
	void (*sk_write_space)(struct sock *);
	void (*sk_error_report)(struct sock *);
	int (*sk_backlog_rcv)(struct sock *, struct sk_buff *);
	void (*sk_destruct)(struct sock *);
	struct sock_reuseport __attribute__((btf_type_tag("rcu"))) *sk_reuseport_cb;
	struct bpf_local_storage __attribute__((btf_type_tag("rcu"))) *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
};

struct raw_hashinfo;

struct smc_hashinfo;

typedef struct {
	union {
		void *kernel;
		void __attribute__((btf_type_tag("user"))) *user;
	};
	bool is_kernel: 1;
} sockptr_t;

struct msghdr;

struct sk_psock;

struct request_sock_ops;

struct timewait_sock_ops;

struct proto {
	void (*close)(struct sock *, long);
	int (*pre_connect)(struct sock *, struct sockaddr *, int);
	int (*connect)(struct sock *, struct sockaddr *, int);
	int (*disconnect)(struct sock *, int);
	struct sock * (*accept)(struct sock *, int, int *, bool);
	int (*ioctl)(struct sock *, int, int *);
	int (*init)(struct sock *);
	void (*destroy)(struct sock *);
	void (*shutdown)(struct sock *, int);
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char __attribute__((btf_type_tag("user"))) *, int __attribute__((btf_type_tag("user"))) *);
	void (*keepalive)(struct sock *, int);
	int (*sendmsg)(struct sock *, struct msghdr *, size_t);
	int (*recvmsg)(struct sock *, struct msghdr *, size_t, int, int *);
	void (*splice_eof)(struct socket *);
	int (*bind)(struct sock *, struct sockaddr *, int);
	int (*bind_add)(struct sock *, struct sockaddr *, int);
	int (*backlog_rcv)(struct sock *, struct sk_buff *);
	bool (*bpf_bypass_getsockopt)(int, int);
	void (*release_cb)(struct sock *);
	int (*hash)(struct sock *);
	void (*unhash)(struct sock *);
	void (*rehash)(struct sock *);
	int (*get_port)(struct sock *, unsigned short);
	void (*put_port)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	bool (*stream_memory_free)(const struct sock *, int);
	bool (*sock_is_readable)(struct sock *);
	void (*enter_memory_pressure)(struct sock *);
	void (*leave_memory_pressure)(struct sock *);
	atomic_long_t *memory_allocated;
	int __attribute__((btf_type_tag("percpu"))) *per_cpu_fw_alloc;
	struct percpu_counter *sockets_allocated;
	unsigned long *memory_pressure;
	long *sysctl_mem;
	int *sysctl_wmem;
	int *sysctl_rmem;
	u32 sysctl_wmem_offset;
	u32 sysctl_rmem_offset;
	int max_header;
	bool no_autobind;
	struct kmem_cache *slab;
	unsigned int obj_size;
	unsigned int ipv6_pinfo_offset;
	slab_flags_t slab_flags;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int __attribute__((btf_type_tag("percpu"))) *orphan_count;
	struct request_sock_ops *rsk_prot;
	struct timewait_sock_ops *twsk_prot;
	union {
		struct inet_hashinfo *hashinfo;
		struct udp_table *udp_table;
		struct raw_hashinfo *raw_hash;
		struct smc_hashinfo *smc_hash;
	} h;
	struct module *owner;
	char name[32];
	struct list_head node;
	int (*diag_destroy)(struct sock *, int);
};

struct ubuf_info;

struct msghdr {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter msg_iter;
	union {
		void *msg_control;
		void __attribute__((btf_type_tag("user"))) *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb *msg_iocb;
	struct ubuf_info *msg_ubuf;
	int (*sg_from_iter)(struct sock *, struct sk_buff *, struct iov_iter *, size_t);
};

struct inet_peer_base {
	struct rb_root rb_root;
	seqlock_t lock;
	int total;
};

struct fib_notifier_ops {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net *);
	int (*fib_dump)(struct net *, struct notifier_block *, struct netlink_ext_ack *);
	struct module *owner;
	struct callback_head rcu;
};

struct ubuf_info {
	void (*callback)(struct sk_buff *, struct ubuf_info *, bool);
	refcount_t refcnt;
	u8 flags;
};

typedef enum {
	SS_FREE = 0,
	SS_UNCONNECTED = 1,
	SS_CONNECTING = 2,
	SS_CONNECTED = 3,
	SS_DISCONNECTING = 4,
} socket_state;

struct socket_wq {
	wait_queue_head_t wait;
	struct fasync_struct *fasync_list;
	unsigned long flags;
	struct callback_head rcu;
};

struct proto_ops;

struct socket {
	socket_state state;
	short type;
	unsigned long flags;
	struct file *file;
	struct sock *sk;
	const struct proto_ops *ops;
	struct socket_wq wq;
};

typedef struct {
	size_t written;
	size_t count;
	union {
		char __attribute__((btf_type_tag("user"))) *buf;
		void *data;
	} arg;
	int error;
} read_descriptor_t;

typedef int (*sk_read_actor_t)(read_descriptor_t *, struct sk_buff *, unsigned int, size_t);

typedef int (*skb_read_actor_t)(struct sock *, struct sk_buff *);

struct proto_ops {
	int family;
	struct module *owner;
	int (*release)(struct socket *);
	int (*bind)(struct socket *, struct sockaddr *, int);
	int (*connect)(struct socket *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket *, struct socket *);
	int (*accept)(struct socket *, struct socket *, int, bool);
	int (*getname)(struct socket *, struct sockaddr *, int);
	__poll_t (*poll)(struct file *, struct socket *, struct poll_table_struct *);
	int (*ioctl)(struct socket *, unsigned int, unsigned long);
	int (*gettstamp)(struct socket *, void __attribute__((btf_type_tag("user"))) *, bool, bool);
	int (*listen)(struct socket *, int);
	int (*shutdown)(struct socket *, int);
	int (*setsockopt)(struct socket *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket *, int, int, char __attribute__((btf_type_tag("user"))) *, int __attribute__((btf_type_tag("user"))) *);
	void (*show_fdinfo)(struct seq_file *, struct socket *);
	int (*sendmsg)(struct socket *, struct msghdr *, size_t);
	int (*recvmsg)(struct socket *, struct msghdr *, size_t, int);
	int (*mmap)(struct file *, struct socket *, struct vm_area_struct *);
	ssize_t (*splice_read)(struct socket *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*splice_eof)(struct socket *);
	int (*set_peek_off)(struct sock *, int);
	int (*peek_len)(struct socket *);
	int (*read_sock)(struct sock *, read_descriptor_t *, sk_read_actor_t);
	int (*read_skb)(struct sock *, skb_read_actor_t);
	int (*sendmsg_locked)(struct sock *, struct msghdr *, size_t);
	int (*set_rcvlowat)(struct sock *, int);
};

struct request_sock;

struct request_sock_ops {
	int family;
	unsigned int obj_size;
	struct kmem_cache *slab;
	char *slab_name;
	int (*rtx_syn_ack)(const struct sock *, struct request_sock *);
	void (*send_ack)(const struct sock *, struct sk_buff *, struct request_sock *);
	void (*send_reset)(const struct sock *, struct sk_buff *);
	void (*destructor)(struct request_sock *);
	void (*syn_ack_timeout)(const struct request_sock *);
};

struct saved_syn;

struct request_sock {
	struct sock_common __req_common;
	struct request_sock *dl_next;
	u16 mss;
	u8 num_retrans;
	u8 syncookie: 1;
	u8 num_timeout: 7;
	u32 ts_recent;
	struct timer_list rsk_timer;
	const struct request_sock_ops *rsk_ops;
	struct sock *sk;
	struct saved_syn *saved_syn;
	u32 secid;
	u32 peer_secid;
	u32 timeout;
};

struct saved_syn {
	u32 mac_hdrlen;
	u32 network_hdrlen;
	u32 tcp_hdrlen;
	u8 data[0];
};

struct timewait_sock_ops {
	struct kmem_cache *twsk_slab;
	char *twsk_slab_name;
	unsigned int twsk_obj_size;
	int (*twsk_unique)(struct sock *, struct sock *, void *);
	void (*twsk_destructor)(struct sock *);
};

typedef struct {
	atomic_t refcnt;
} rcuref_t;

struct uncached_list;

struct dst_ops;

struct lwtunnel_state;

struct dst_entry {
	struct net_device *dev;
	struct dst_ops *ops;
	unsigned long _metrics;
	unsigned long expires;
	void *__pad1;
	int (*input)(struct sk_buff *);
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	unsigned short flags;
	short obsolete;
	unsigned short header_len;
	unsigned short trailer_len;
	rcuref_t __rcuref;
	int __use;
	unsigned long lastuse;
	struct callback_head callback_head;
	short error;
	short __pad;
	__u32 tclassid;
	netdevice_tracker dev_tracker;
	struct list_head rt_uncached;
	struct uncached_list *rt_uncached_list;
	struct lwtunnel_state *lwtstate;
};

struct dst_ops {
	unsigned short family;
	unsigned int gc_thresh;
	void (*gc)(struct dst_ops *);
	struct dst_entry * (*check)(struct dst_entry *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry *);
	unsigned int (*mtu)(const struct dst_entry *);
	u32 * (*cow_metrics)(struct dst_entry *, unsigned long);
	void (*destroy)(struct dst_entry *);
	void (*ifdown)(struct dst_entry *, struct net_device *);
	void (*negative_advice)(struct sock *, struct dst_entry *);
	void (*link_failure)(struct sk_buff *);
	void (*update_pmtu)(struct dst_entry *, struct sock *, struct sk_buff *, u32, bool);
	void (*redirect)(struct dst_entry *, struct sock *, struct sk_buff *);
	int (*local_out)(struct net *, struct sock *, struct sk_buff *);
	struct neighbour * (*neigh_lookup)(const struct dst_entry *, struct sk_buff *, const void *);
	void (*confirm_neigh)(const struct dst_entry *, const void *);
	struct kmem_cache *kmem_cachep;
	struct percpu_counter pcpuc_entries;
};

struct neigh_parms {
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head list;
	int (*neigh_setup)(struct neighbour *);
	struct neigh_table *tbl;
	void *sysctl_table;
	int dead;
	refcount_t refcnt;
	struct callback_head callback_head;
	int reachable_time;
	u32 qlen;
	int data[14];
	unsigned long data_state[1];
};

struct pneigh_entry;

struct neigh_statistics;

struct neigh_hash_table;

struct neigh_table {
	int family;
	unsigned int entry_size;
	unsigned int key_len;
	__be16 protocol;
	__u32 (*hash)(const void *, const struct net_device *, __u32 *);
	bool (*key_eq)(const struct neighbour *, const void *);
	int (*constructor)(struct neighbour *);
	int (*pconstructor)(struct pneigh_entry *);
	void (*pdestructor)(struct pneigh_entry *);
	void (*proxy_redo)(struct sk_buff *);
	int (*is_multicast)(const void *);
	bool (*allow_add)(const struct net_device *, struct netlink_ext_ack *);
	char *id;
	struct neigh_parms parms;
	struct list_head parms_list;
	int gc_interval;
	int gc_thresh1;
	int gc_thresh2;
	int gc_thresh3;
	unsigned long last_flush;
	struct delayed_work gc_work;
	struct delayed_work managed_work;
	struct timer_list proxy_timer;
	struct sk_buff_head proxy_queue;
	atomic_t entries;
	atomic_t gc_entries;
	struct list_head gc_list;
	struct list_head managed_list;
	rwlock_t lock;
	unsigned long last_rand;
	struct neigh_statistics __attribute__((btf_type_tag("percpu"))) *stats;
	struct neigh_hash_table __attribute__((btf_type_tag("rcu"))) *nht;
	struct pneigh_entry **phash_buckets;
};

struct pneigh_entry {
	struct pneigh_entry *next;
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u32 flags;
	u8 protocol;
	u32 key[0];
};

struct neigh_statistics {
	unsigned long allocs;
	unsigned long destroys;
	unsigned long hash_grows;
	unsigned long res_failed;
	unsigned long lookups;
	unsigned long hits;
	unsigned long rcv_probes_mcast;
	unsigned long rcv_probes_ucast;
	unsigned long periodic_gc_runs;
	unsigned long forced_gc_runs;
	unsigned long unres_discards;
	unsigned long table_fulls;
};

struct neigh_hash_table {
	struct neighbour __attribute__((btf_type_tag("rcu"))) **hash_buckets;
	unsigned int hash_shift;
	__u32 hash_rnd[4];
	struct callback_head rcu;
};

struct neigh_ops {
	int family;
	void (*solicit)(struct neighbour *, struct sk_buff *);
	void (*error_report)(struct neighbour *, struct sk_buff *);
	int (*output)(struct neighbour *, struct sk_buff *);
	int (*connected_output)(struct neighbour *, struct sk_buff *);
};

struct lwtunnel_state {
	__u16 type;
	__u16 flags;
	__u16 headroom;
	atomic_t refcnt;
	int (*orig_output)(struct net *, struct sock *, struct sk_buff *);
	int (*orig_input)(struct sk_buff *);
	struct callback_head rcu;
	__u8 data[0];
};

struct sk_filter {
	refcount_t refcnt;
	struct callback_head rcu;
	struct bpf_prog *prog;
};

struct sock_reuseport {
	struct callback_head rcu;
	u16 max_socks;
	u16 num_socks;
	u16 num_closed_socks;
	u16 incoming_cpu;
	unsigned int synq_overflow_ts;
	unsigned int reuseport_id;
	unsigned int bind_inany: 1;
	unsigned int has_conns: 1;
	struct bpf_prog __attribute__((btf_type_tag("rcu"))) *prog;
	struct sock *socks[0];
};

struct xdp_mem_info {
	u32 type;
	u32 id;
};

struct xdp_frame {
	void *data;
	u16 len;
	u16 headroom;
	u32 metasize;
	struct xdp_mem_info mem;
	struct net_device *dev_rx;
	u32 frame_sz;
	u32 flags;
};

struct xdp_rxq_info;

struct xdp_txq_info;

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	struct xdp_rxq_info *rxq;
	struct xdp_txq_info *txq;
	u32 frame_sz;
	u32 flags;
};

struct xdp_rxq_info {
	struct net_device *dev;
	u32 queue_index;
	u32 reg_state;
	struct xdp_mem_info mem;
	unsigned int napi_id;
	u32 frag_size;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct xdp_txq_info {
	struct net_device *dev;
};

enum hwtstamp_source {
	HWTSTAMP_SOURCE_NETDEV = 0,
	HWTSTAMP_SOURCE_PHYLIB = 1,
};

struct kernel_hwtstamp_config {
	int flags;
	int tx_type;
	int rx_filter;
	struct ifreq *ifr;
	bool copied_to_user;
	enum hwtstamp_source source;
};

struct ip6_sf_list;

struct ifmcaddr6 {
	struct in6_addr mca_addr;
	struct inet6_dev *idev;
	struct ifmcaddr6 __attribute__((btf_type_tag("rcu"))) *next;
	struct ip6_sf_list __attribute__((btf_type_tag("rcu"))) *mca_sources;
	struct ip6_sf_list __attribute__((btf_type_tag("rcu"))) *mca_tomb;
	unsigned int mca_sfmode;
	unsigned char mca_crcount;
	unsigned long mca_sfcount[2];
	struct delayed_work mca_work;
	unsigned int mca_flags;
	int mca_users;
	refcount_t mca_refcnt;
	unsigned long mca_cstamp;
	unsigned long mca_tstamp;
	struct callback_head rcu;
};

struct ip6_sf_list {
	struct ip6_sf_list __attribute__((btf_type_tag("rcu"))) *sf_next;
	struct in6_addr sf_addr;
	unsigned long sf_count[2];
	unsigned char sf_gsresp;
	unsigned char sf_oldin;
	unsigned char sf_crcount;
	struct callback_head rcu;
};

struct fib6_info;

struct ifacaddr6 {
	struct in6_addr aca_addr;
	struct fib6_info *aca_rt;
	struct ifacaddr6 __attribute__((btf_type_tag("rcu"))) *aca_next;
	struct hlist_node aca_addr_lst;
	int aca_users;
	refcount_t aca_refcnt;
	unsigned long aca_cstamp;
	unsigned long aca_tstamp;
	struct callback_head rcu;
};

struct icmpv6_mib_device {
	atomic_long_t mibs[7];
};

struct icmpv6msg_mib_device {
	atomic_long_t mibs[512];
};

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

enum hrtimer_mode {
	HRTIMER_MODE_ABS = 0,
	HRTIMER_MODE_REL = 1,
	HRTIMER_MODE_PINNED = 2,
	HRTIMER_MODE_SOFT = 4,
	HRTIMER_MODE_HARD = 8,
	HRTIMER_MODE_ABS_PINNED = 2,
	HRTIMER_MODE_REL_PINNED = 3,
	HRTIMER_MODE_ABS_SOFT = 4,
	HRTIMER_MODE_REL_SOFT = 5,
	HRTIMER_MODE_ABS_PINNED_SOFT = 6,
	HRTIMER_MODE_REL_PINNED_SOFT = 7,
	HRTIMER_MODE_ABS_HARD = 8,
	HRTIMER_MODE_REL_HARD = 9,
	HRTIMER_MODE_ABS_PINNED_HARD = 10,
	HRTIMER_MODE_REL_PINNED_HARD = 11,
};

enum poll_time_type {
	PT_TIMEVAL = 0,
	PT_OLD_TIMEVAL = 1,
	PT_TIMESPEC = 2,
	PT_OLD_TIMESPEC = 3,
};

struct poll_table_entry {
	struct file *filp;
	__poll_t key;
	wait_queue_entry_t wait;
	wait_queue_head_t *wait_address;
};

struct poll_table_page;

struct poll_wqueues {
	poll_table pt;
	struct poll_table_page *table;
	struct task_struct *polling_task;
	int triggered;
	int error;
	int inline_index;
	struct poll_table_entry inline_entries[9];
};

struct poll_table_page {
	struct poll_table_page *next;
	struct poll_table_entry *entry;
	struct poll_table_entry entries[0];
};

typedef struct {
	unsigned long fds_bits[16];
} __kernel_fd_set;

typedef __kernel_fd_set fd_set;

struct __kernel_old_timeval {
	__kernel_long_t tv_sec;
	__kernel_long_t tv_usec;
};

struct poll_list {
	struct poll_list *next;
	unsigned int len;
	struct pollfd entries[0];
};

typedef struct {
	unsigned long *in;
	unsigned long *out;
	unsigned long *ex;
	unsigned long *res_in;
	unsigned long *res_out;
	unsigned long *res_ex;
} fd_set_bits;

struct sigset_argpack {
	sigset_t __attribute__((btf_type_tag("user"))) *p;
	size_t size;
};

struct old_timeval32 {
	old_time32_t tv_sec;
	s32 tv_usec;
};

struct klist_node;

struct klist {
	spinlock_t k_lock;
	struct list_head k_list;
	void (*get)(struct klist_node *);
	void (*put)(struct klist_node *);
};

struct klist_node {
	void *n_klist;
	struct list_head n_node;
	struct kref n_ref;
};

struct device_private {
	struct klist klist_children;
	struct klist_node knode_parent;
	struct klist_node knode_driver;
	struct klist_node knode_bus;
	struct klist_node knode_class;
	struct list_head deferred_probe;
	struct device_driver *async_driver;
	char *deferred_probe_reason;
	struct device *device;
	u8 dead: 1;
};

struct module_kobject;

struct driver_private {
	struct kobject kobj;
	struct klist klist_devices;
	struct klist_node knode_bus;
	struct module_kobject *mkobj;
	struct device_driver *driver;
};

struct module_param_attrs;

struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct cpu {
	int node_id;
	int hotpluggable;
	struct device dev;
};

struct cpu_attr {
	struct device_attribute attr;
	const struct cpumask * const map;
};

enum hk_type {
	HK_TYPE_TIMER = 0,
	HK_TYPE_RCU = 1,
	HK_TYPE_MISC = 2,
	HK_TYPE_SCHED = 3,
	HK_TYPE_TICK = 4,
	HK_TYPE_DOMAIN = 5,
	HK_TYPE_WQ = 6,
	HK_TYPE_MANAGED_IRQ = 7,
	HK_TYPE_KTHREAD = 8,
	HK_TYPE_MAX = 9,
};

struct __va_list_tag {
	unsigned int gp_offset;
	unsigned int fp_offset;
	void *overflow_arg_area;
	void *reg_save_area;
};

typedef __builtin_va_list va_list;

struct p4_event_bind {
	unsigned int opcode;
	unsigned int escr_msr[2];
	unsigned int escr_emask;
	unsigned int shared;
	signed char cntr[6];
};

struct p4_pebs_bind {
	unsigned int metric_pebs;
	unsigned int metric_vert;
};

struct p4_event_alias {
	u64 original;
	u64 alternative;
};

enum P4_PEBS_METRIC {
	P4_PEBS_METRIC__none = 0,
	P4_PEBS_METRIC__1stl_cache_load_miss_retired = 1,
	P4_PEBS_METRIC__2ndl_cache_load_miss_retired = 2,
	P4_PEBS_METRIC__dtlb_load_miss_retired = 3,
	P4_PEBS_METRIC__dtlb_store_miss_retired = 4,
	P4_PEBS_METRIC__dtlb_all_miss_retired = 5,
	P4_PEBS_METRIC__tagged_mispred_branch = 6,
	P4_PEBS_METRIC__mob_load_replay_retired = 7,
	P4_PEBS_METRIC__split_load_retired = 8,
	P4_PEBS_METRIC__split_store_retired = 9,
	P4_PEBS_METRIC__max = 10,
};

enum P4_EVENTS {
	P4_EVENT_TC_DELIVER_MODE = 0,
	P4_EVENT_BPU_FETCH_REQUEST = 1,
	P4_EVENT_ITLB_REFERENCE = 2,
	P4_EVENT_MEMORY_CANCEL = 3,
	P4_EVENT_MEMORY_COMPLETE = 4,
	P4_EVENT_LOAD_PORT_REPLAY = 5,
	P4_EVENT_STORE_PORT_REPLAY = 6,
	P4_EVENT_MOB_LOAD_REPLAY = 7,
	P4_EVENT_PAGE_WALK_TYPE = 8,
	P4_EVENT_BSQ_CACHE_REFERENCE = 9,
	P4_EVENT_IOQ_ALLOCATION = 10,
	P4_EVENT_IOQ_ACTIVE_ENTRIES = 11,
	P4_EVENT_FSB_DATA_ACTIVITY = 12,
	P4_EVENT_BSQ_ALLOCATION = 13,
	P4_EVENT_BSQ_ACTIVE_ENTRIES = 14,
	P4_EVENT_SSE_INPUT_ASSIST = 15,
	P4_EVENT_PACKED_SP_UOP = 16,
	P4_EVENT_PACKED_DP_UOP = 17,
	P4_EVENT_SCALAR_SP_UOP = 18,
	P4_EVENT_SCALAR_DP_UOP = 19,
	P4_EVENT_64BIT_MMX_UOP = 20,
	P4_EVENT_128BIT_MMX_UOP = 21,
	P4_EVENT_X87_FP_UOP = 22,
	P4_EVENT_TC_MISC = 23,
	P4_EVENT_GLOBAL_POWER_EVENTS = 24,
	P4_EVENT_TC_MS_XFER = 25,
	P4_EVENT_UOP_QUEUE_WRITES = 26,
	P4_EVENT_RETIRED_MISPRED_BRANCH_TYPE = 27,
	P4_EVENT_RETIRED_BRANCH_TYPE = 28,
	P4_EVENT_RESOURCE_STALL = 29,
	P4_EVENT_WC_BUFFER = 30,
	P4_EVENT_B2B_CYCLES = 31,
	P4_EVENT_BNR = 32,
	P4_EVENT_SNOOP = 33,
	P4_EVENT_RESPONSE = 34,
	P4_EVENT_FRONT_END_EVENT = 35,
	P4_EVENT_EXECUTION_EVENT = 36,
	P4_EVENT_REPLAY_EVENT = 37,
	P4_EVENT_INSTR_RETIRED = 38,
	P4_EVENT_UOPS_RETIRED = 39,
	P4_EVENT_UOP_TYPE = 40,
	P4_EVENT_BRANCH_RETIRED = 41,
	P4_EVENT_MISPRED_BRANCH_RETIRED = 42,
	P4_EVENT_X87_ASSIST = 43,
	P4_EVENT_MACHINE_CLEAR = 44,
	P4_EVENT_INSTR_COMPLETED = 45,
};

struct tlb_state_shared {
	bool is_lazy;
};

struct flush_tlb_info {
	struct mm_struct *mm;
	unsigned long start;
	unsigned long end;
	u64 new_tlb_gen;
	unsigned int initiating_cpu;
	u8 stride_shift;
	u8 freed_tables;
};

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH = 0,
	TLB_REMOTE_SHOOTDOWN = 1,
	TLB_LOCAL_SHOOTDOWN = 2,
	TLB_LOCAL_MM_SHOOTDOWN = 3,
	TLB_REMOTE_SEND_IPI = 4,
	NR_TLB_FLUSH_REASONS = 5,
};

struct rt_bandwidth {
	raw_spinlock_t rt_runtime_lock;
	ktime_t rt_period;
	u64 rt_runtime;
	struct hrtimer rt_period_timer;
	unsigned int rt_period_active;
};

enum cpu_usage_stat {
	CPUTIME_USER = 0,
	CPUTIME_NICE = 1,
	CPUTIME_SYSTEM = 2,
	CPUTIME_SOFTIRQ = 3,
	CPUTIME_IRQ = 4,
	CPUTIME_IDLE = 5,
	CPUTIME_IOWAIT = 6,
	CPUTIME_STEAL = 7,
	CPUTIME_GUEST = 8,
	CPUTIME_GUEST_NICE = 9,
	NR_STATS = 10,
};

enum tick_broadcast_state {
	TICK_BROADCAST_EXIT = 0,
	TICK_BROADCAST_ENTER = 1,
};

struct kernel_cpustat {
	u64 cpustat[10];
};

struct idle_timer {
	struct hrtimer timer;
	int done;
};

struct cpuidle_state_usage {
	unsigned long long disable;
	unsigned long long usage;
	u64 time_ns;
	unsigned long long above;
	unsigned long long below;
	unsigned long long rejected;
};

struct cpuidle_state_kobj;

struct cpuidle_driver_kobj;

struct cpuidle_device_kobj;

struct cpuidle_device {
	unsigned int registered: 1;
	unsigned int enabled: 1;
	unsigned int poll_time_limit: 1;
	unsigned int cpu;
	ktime_t next_hrtimer;
	int last_state_idx;
	u64 last_residency_ns;
	u64 poll_limit_ns;
	u64 forced_idle_latency_limit_ns;
	struct cpuidle_state_usage states_usage[10];
	struct cpuidle_state_kobj *kobjs[10];
	struct cpuidle_driver_kobj *kobj_driver;
	struct cpuidle_device_kobj *kobj_dev;
	struct list_head device_list;
};

struct cpuidle_driver;

struct cpuidle_state {
	char name[16];
	char desc[32];
	s64 exit_latency_ns;
	s64 target_residency_ns;
	unsigned int flags;
	unsigned int exit_latency;
	int power_usage;
	unsigned int target_residency;
	int (*enter)(struct cpuidle_device *, struct cpuidle_driver *, int);
	int (*enter_dead)(struct cpuidle_device *, int);
	int (*enter_s2idle)(struct cpuidle_device *, struct cpuidle_driver *, int);
};

struct cpuidle_driver {
	const char *name;
	struct module *owner;
	unsigned int bctimer: 1;
	struct cpuidle_state states[10];
	int state_count;
	int safe_state_index;
	struct cpumask *cpumask;
	const char *governor;
};

struct task_group;

struct task_cputime {
	u64 stime;
	u64 utime;
	unsigned long long sum_exec_runtime;
};

struct sched_attr {
	__u32 size;
	__u32 sched_policy;
	__u64 sched_flags;
	__s32 sched_nice;
	__u32 sched_priority;
	__u64 sched_runtime;
	__u64 sched_deadline;
	__u64 sched_period;
	__u32 sched_util_min;
	__u32 sched_util_max;
};

struct bp_slots_histogram {
	atomic_t count[4];
};

struct rhltable {
	struct rhashtable ht;
};

struct rhash_lock_head {};

struct bp_cpuinfo {
	unsigned int cpu_pinned;
	struct bp_slots_histogram tsk_pinned;
};

enum bp_type_idx {
	TYPE_INST = 0,
	TYPE_DATA = 0,
	TYPE_MAX = 1,
};

enum {
	HW_BREAKPOINT_EMPTY = 0,
	HW_BREAKPOINT_R = 1,
	HW_BREAKPOINT_W = 2,
	HW_BREAKPOINT_RW = 3,
	HW_BREAKPOINT_X = 4,
	HW_BREAKPOINT_INVALID = 7,
};

struct reciprocal_value {
	u32 m;
	u8 sh1;
	u8 sh2;
};

struct kmem_cache_order_objects {
	unsigned int x;
};

struct kmem_cache_node;

struct kmem_cache {
	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;
	unsigned int object_size;
	struct reciprocal_value reciprocal_size;
	unsigned int offset;
	struct kmem_cache_order_objects oo;
	struct kmem_cache_order_objects min;
	gfp_t allocflags;
	int refcount;
	void (*ctor)(void *);
	unsigned int inuse;
	unsigned int align;
	unsigned int red_left_pad;
	const char *name;
	struct list_head list;
	struct kmem_cache_node *node[1];
};

struct kmalloc_info_struct {
	const char *name[1];
	unsigned int size;
};

enum slab_state {
	DOWN = 0,
	PARTIAL = 1,
	UP = 2,
	FULL = 3,
};

typedef unsigned __int128 __u128;

typedef __u128 u128;

typedef u128 freelist_full_t;

typedef union {
	struct {
		void *freelist;
		unsigned long counter;
	};
	freelist_full_t full;
} freelist_aba_t;

struct slab {
	unsigned long __page_flags;
	struct kmem_cache *slab_cache;
	union {
		struct {
			union {
				struct list_head slab_list;
			};
			union {
				struct {
					void *freelist;
					union {
						unsigned long counters;
						struct {
							unsigned int inuse: 16;
							unsigned int objects: 15;
							unsigned int frozen: 1;
						};
					};
				};
				freelist_aba_t freelist_counter;
			};
		};
		struct callback_head callback_head;
	};
	unsigned int __unused;
	atomic_t __page_refcount;
	long: 64;
};

struct kmem_cache_node {
	spinlock_t list_lock;
	unsigned long nr_partial;
	struct list_head partial;
};

enum stat_item {
	ALLOC_FASTPATH = 0,
	ALLOC_SLOWPATH = 1,
	FREE_FASTPATH = 2,
	FREE_SLOWPATH = 3,
	FREE_FROZEN = 4,
	FREE_ADD_PARTIAL = 5,
	FREE_REMOVE_PARTIAL = 6,
	ALLOC_FROM_PARTIAL = 7,
	ALLOC_SLAB = 8,
	ALLOC_REFILL = 9,
	ALLOC_NODE_MISMATCH = 10,
	FREE_SLAB = 11,
	CPUSLAB_FLUSH = 12,
	DEACTIVATE_FULL = 13,
	DEACTIVATE_EMPTY = 14,
	DEACTIVATE_TO_HEAD = 15,
	DEACTIVATE_TO_TAIL = 16,
	DEACTIVATE_REMOTE_FREES = 17,
	DEACTIVATE_BYPASS = 18,
	ORDER_FALLBACK = 19,
	CMPXCHG_DOUBLE_CPU_FAIL = 20,
	CMPXCHG_DOUBLE_FAIL = 21,
	CPU_PARTIAL_ALLOC = 22,
	CPU_PARTIAL_FREE = 23,
	CPU_PARTIAL_NODE = 24,
	CPU_PARTIAL_DRAIN = 25,
	NR_SLUB_STAT_ITEMS = 26,
};

typedef struct {
	unsigned long v;
} freeptr_t;

struct detached_freelist {
	struct slab *slab;
	void *tail;
	void *freelist;
	int cnt;
	struct kmem_cache *s;
};

struct partial_context {
	gfp_t flags;
	unsigned int orig_size;
	void *object;
};

typedef u32 depot_stack_handle_t;

enum iter_type {
	ITER_UBUF = 0,
	ITER_IOVEC = 1,
	ITER_BVEC = 2,
	ITER_KVEC = 3,
	ITER_XARRAY = 4,
	ITER_DISCARD = 5,
};

typedef __kernel_long_t __kernel_off_t;

typedef __kernel_off_t off_t;

typedef void sg_free_fn(struct scatterlist *, unsigned int);

struct sg_append_table {
	struct sg_table sgt;
	struct scatterlist *prv;
	unsigned int total_nents;
};

struct sg_page_iter {
	struct scatterlist *sg;
	unsigned int sg_pgoffset;
	unsigned int __nents;
	int __pg_advance;
};

struct sg_mapping_iter {
	struct page *page;
	void *addr;
	size_t length;
	size_t consumed;
	struct sg_page_iter piter;
	unsigned int __offset;
	unsigned int __remaining;
	unsigned int __flags;
};

typedef unsigned int iov_iter_extraction_t;

struct xa_state {
	struct xarray *xa;
	unsigned long xa_index;
	unsigned char xa_shift;
	unsigned char xa_sibs;
	unsigned char xa_offset;
	unsigned char xa_pad;
	struct xa_node *xa_node;
	struct xa_node *xa_alloc;
	xa_update_node_t xa_update;
	struct list_lru *xa_lru;
};

typedef struct scatterlist *sg_alloc_fn(unsigned int, gfp_t);

struct sg_dma_page_iter {
	struct sg_page_iter base;
};

struct kernel_vm86_regs {
	struct pt_regs pt;
	unsigned short es;
	unsigned short __esh;
	unsigned short ds;
	unsigned short __dsh;
	unsigned short fs;
	unsigned short __fsh;
	unsigned short gs;
	unsigned short __gsh;
};

struct ksignal {
	struct k_sigaction ka;
	kernel_siginfo_t info;
	int sig;
};

enum die_val {
	DIE_OOPS = 1,
	DIE_INT3 = 2,
	DIE_DEBUG = 3,
	DIE_PANIC = 4,
	DIE_NMI = 5,
	DIE_DIE = 6,
	DIE_KERNELDEBUG = 7,
	DIE_TRAP = 8,
	DIE_GPF = 9,
	DIE_CALL = 10,
	DIE_PAGE_FAULT = 11,
	DIE_NMIUNKNOWN = 12,
};

enum {
	HW_BREAKPOINT_LEN_1 = 1,
	HW_BREAKPOINT_LEN_2 = 2,
	HW_BREAKPOINT_LEN_3 = 3,
	HW_BREAKPOINT_LEN_4 = 4,
	HW_BREAKPOINT_LEN_5 = 5,
	HW_BREAKPOINT_LEN_6 = 6,
	HW_BREAKPOINT_LEN_7 = 7,
	HW_BREAKPOINT_LEN_8 = 8,
};

struct x86_hw_tss {
	u32 reserved1;
	u64 sp0;
	u64 sp1;
	u64 sp2;
	u64 reserved2;
	u64 ist[7];
	u32 reserved3;
	u32 reserved4;
	u16 reserved5;
	u16 io_bitmap_base;
} __attribute__((packed));

struct x86_io_bitmap {
	u64 prev_sequence;
	unsigned int prev_max;
	unsigned long bitmap[1025];
	unsigned long mapall[1025];
};

struct tss_struct {
	struct x86_hw_tss x86_tss;
	struct x86_io_bitmap io_bitmap;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct tlb_context {
	u64 ctx_id;
	u64 tlb_gen;
};

struct tlb_state {
	struct mm_struct *loaded_mm;
	union {
		struct mm_struct *last_user_mm;
		unsigned long last_user_mm_spec;
	};
	u16 loaded_mm_asid;
	u16 next_asid;
	bool invalidate_other;
	unsigned short user_pcid_flush_mask;
	unsigned long cr4;
	struct tlb_context ctxs[6];
};

struct die_args {
	struct pt_regs *regs;
	const char *str;
	long err;
	int trapnr;
	int signr;
};

struct cea_exception_stacks {
	char DF_stack_guard[4096];
	char DF_stack[8192];
	char NMI_stack_guard[4096];
	char NMI_stack[8192];
	char DB_stack_guard[4096];
	char DB_stack[8192];
	char MCE_stack_guard[4096];
	char MCE_stack[8192];
	char VC_stack_guard[4096];
	char VC_stack[8192];
	char VC2_stack_guard[4096];
	char VC2_stack[8192];
	char IST_top_guard[4096];
};

struct entry_stack {
	char stack[4096];
};

struct entry_stack_page {
	struct entry_stack stack;
};

struct exception_stacks {
	char DF_stack_guard[0];
	char DF_stack[8192];
	char NMI_stack_guard[0];
	char NMI_stack[8192];
	char DB_stack_guard[0];
	char DB_stack[8192];
	char MCE_stack_guard[0];
	char MCE_stack[8192];
	char VC_stack_guard[0];
	char VC_stack[0];
	char VC2_stack_guard[0];
	char VC2_stack[0];
	char IST_top_guard[0];
};

struct debug_store_buffers {
	char bts_buffer[65536];
	char pebs_buffer[65536];
};

struct cpu_entry_area {
	char gdt[4096];
	struct entry_stack_page entry_stack_page;
	struct tss_struct tss;
	struct cea_exception_stacks estacks;
	struct debug_store cpu_debug_store;
	struct debug_store_buffers cpu_debug_buffers;
};

enum rlimit_type {
	UCOUNT_RLIMIT_NPROC = 0,
	UCOUNT_RLIMIT_MSGQUEUE = 1,
	UCOUNT_RLIMIT_SIGPENDING = 2,
	UCOUNT_RLIMIT_MEMLOCK = 3,
	UCOUNT_RLIMIT_COUNTS = 4,
};

enum proc_cn_event {
	PROC_EVENT_NONE = 0,
	PROC_EVENT_FORK = 1,
	PROC_EVENT_EXEC = 2,
	PROC_EVENT_UID = 4,
	PROC_EVENT_GID = 64,
	PROC_EVENT_SID = 128,
	PROC_EVENT_PTRACE = 256,
	PROC_EVENT_COMM = 512,
	PROC_EVENT_NONZERO_EXIT = 536870912,
	PROC_EVENT_COREDUMP = 1073741824,
	PROC_EVENT_EXIT = 2147483648,
};

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,
	BPF_LINK_TYPE_XDP = 6,
	BPF_LINK_TYPE_PERF_EVENT = 7,
	BPF_LINK_TYPE_KPROBE_MULTI = 8,
	BPF_LINK_TYPE_STRUCT_OPS = 9,
	BPF_LINK_TYPE_NETFILTER = 10,
	BPF_LINK_TYPE_TCX = 11,
	BPF_LINK_TYPE_UPROBE_MULTI = 12,
	BPF_LINK_TYPE_NETKIT = 13,
	__MAX_BPF_LINK_TYPE = 14,
};

struct bpf_link_ops;

struct bpf_link {
	atomic64_t refcnt;
	u32 id;
	enum bpf_link_type type;
	const struct bpf_link_ops *ops;
	struct bpf_prog *prog;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct bpf_link_ops {
	void (*release)(struct bpf_link *);
	void (*dealloc)(struct bpf_link *);
	void (*dealloc_deferred)(struct bpf_link *);
	int (*detach)(struct bpf_link *);
	int (*update_prog)(struct bpf_link *, struct bpf_prog *, struct bpf_prog *);
	void (*show_fdinfo)(const struct bpf_link *, struct seq_file *);
	int (*fill_link_info)(const struct bpf_link *, struct bpf_link_info *);
	int (*update_map)(struct bpf_link *, struct bpf_map *, struct bpf_map *);
};

struct bpf_iter_seq_link_info {
	u32 link_id;
};

struct bpf_iter__bpf_link {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_link *link;
	};
};

struct saved {
	struct path link;
	struct delayed_call done;
	const char *name;
	unsigned int seq;
};

struct nameidata {
	struct path path;
	struct qstr last;
	struct path root;
	struct inode *inode;
	unsigned int flags;
	unsigned int state;
	unsigned int seq;
	unsigned int next_seq;
	unsigned int m_seq;
	unsigned int r_seq;
	int last_type;
	unsigned int depth;
	int total_link_count;
	struct saved *stack;
	struct saved internal[2];
	struct filename *name;
	struct nameidata *saved;
	unsigned int root_seq;
	int dfd;
	vfsuid_t dir_vfsuid;
	umode_t dir_mode;
};

struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_spinlock_t seq;
	int umask;
	int in_exec;
	struct path root;
	struct path pwd;
};

struct mount;

struct mnt_namespace {
	struct ns_common ns;
	struct mount *root;
	struct rb_root mounts;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	u64 seq;
	wait_queue_head_t poll;
	u64 event;
	unsigned int nr_mounts;
	unsigned int pending_mounts;
};

struct mountpoint;

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct callback_head mnt_rcu;
		struct llist_node mnt_llist;
	};
	int mnt_count;
	int mnt_writers;
	struct list_head mnt_mounts;
	struct list_head mnt_child;
	struct list_head mnt_instance;
	const char *mnt_devname;
	union {
		struct rb_node mnt_node;
		struct list_head mnt_list;
	};
	struct list_head mnt_expire;
	struct list_head mnt_share;
	struct list_head mnt_slave_list;
	struct list_head mnt_slave;
	struct mount *mnt_master;
	struct mnt_namespace *mnt_ns;
	struct mountpoint *mnt_mp;
	union {
		struct hlist_node mnt_mp_list;
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting;
	int mnt_id;
	u64 mnt_id_unique;
	int mnt_group_id;
	int mnt_expiry_mark;
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

struct posix_acl_entry {
	short e_tag;
	unsigned short e_perm;
	union {
		kuid_t e_uid;
		kgid_t e_gid;
	};
};

struct posix_acl {
	refcount_t a_refcount;
	struct callback_head a_rcu;
	unsigned int a_count;
	struct posix_acl_entry a_entries[0];
};

enum inode_i_mutex_lock_class {
	I_MUTEX_NORMAL = 0,
	I_MUTEX_PARENT = 1,
	I_MUTEX_CHILD = 2,
	I_MUTEX_XATTR = 3,
	I_MUTEX_NONDIR2 = 4,
	I_MUTEX_PARENT2 = 5,
};

enum {
	LAST_NORM = 0,
	LAST_ROOT = 1,
	LAST_DOT = 2,
	LAST_DOTDOT = 3,
};

enum {
	WALK_TRAILING = 1,
	WALK_MORE = 2,
	WALK_NOFOLLOW = 4,
};

struct word_at_a_time {
	const unsigned long one_bits;
	const unsigned long high_bits;
};

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

struct name_snapshot {
	struct qstr name;
	unsigned char inline_name[40];
};

struct renamedata {
	struct mnt_idmap *old_mnt_idmap;
	struct inode *old_dir;
	struct dentry *old_dentry;
	struct mnt_idmap *new_mnt_idmap;
	struct inode *new_dir;
	struct dentry *new_dentry;
	struct inode **delegated_inode;
	unsigned int flags;
};

struct cacheinfo;

struct cpu_cacheinfo {
	struct cacheinfo *info_list;
	unsigned int per_cpu_data_slice_size;
	unsigned int num_levels;
	unsigned int num_leaves;
	bool cpu_map_populated;
	bool early_ci_levels;
};

enum cache_type {
	CACHE_TYPE_NOCACHE = 0,
	CACHE_TYPE_INST = 1,
	CACHE_TYPE_DATA = 2,
	CACHE_TYPE_SEPARATE = 3,
	CACHE_TYPE_UNIFIED = 4,
};

struct cacheinfo {
	unsigned int id;
	enum cache_type type;
	unsigned int level;
	unsigned int coherency_line_size;
	unsigned int number_of_sets;
	unsigned int ways_of_associativity;
	unsigned int physical_line_partition;
	unsigned int size;
	cpumask_t shared_cpu_map;
	unsigned int attributes;
	void *fw_token;
	bool disable_sysfs;
	void *priv;
};

struct ptdesc {
	unsigned long __page_flags;
	union {
		struct callback_head pt_rcu_head;
		struct list_head pt_list;
		struct {
			unsigned long _pt_pad_1;
			pgtable_t pmd_huge_pte;
		};
	};
	unsigned long __page_mapping;
	union {
		unsigned long pt_index;
		struct mm_struct *pt_mm;
		atomic_t pt_frag_refcount;
	};
	union {
		unsigned long _pt_pad_2;
		spinlock_t ptl;
	};
	unsigned int __page_type;
	atomic_t __page_refcount;
};

struct mmu_gather_batch {
	struct mmu_gather_batch *next;
	unsigned int nr;
	unsigned int max;
	struct encoded_page *encoded_pages[0];
};

struct mmu_gather {
	struct mm_struct *mm;
	unsigned long start;
	unsigned long end;
	unsigned int fullmm: 1;
	unsigned int need_flush_all: 1;
	unsigned int freed_tables: 1;
	unsigned int delayed_rmap: 1;
	unsigned int cleared_ptes: 1;
	unsigned int cleared_pmds: 1;
	unsigned int cleared_puds: 1;
	unsigned int cleared_p4ds: 1;
	unsigned int vma_exec: 1;
	unsigned int vma_huge: 1;
	unsigned int vma_pfn: 1;
	unsigned int batch_count;
	struct mmu_gather_batch *active;
	struct mmu_gather_batch local;
	struct page *__pages[8];
};

enum pm_qos_req_action {
	PM_QOS_ADD_REQ = 0,
	PM_QOS_UPDATE_REQ = 1,
	PM_QOS_REMOVE_REQ = 2,
};

enum {
	IRQS_AUTODETECT = 1,
	IRQS_SPURIOUS_DISABLED = 2,
	IRQS_POLL_INPROGRESS = 8,
	IRQS_ONESHOT = 32,
	IRQS_REPLAY = 64,
	IRQS_WAITING = 128,
	IRQS_PENDING = 512,
	IRQS_SUSPENDED = 2048,
	IRQS_TIMINGS = 4096,
	IRQS_NMI = 8192,
	IRQS_SYSFS = 16384,
};

enum {
	IRQCHIP_SET_TYPE_MASKED = 1,
	IRQCHIP_EOI_IF_HANDLED = 2,
	IRQCHIP_MASK_ON_SUSPEND = 4,
	IRQCHIP_ONOFFLINE_ENABLED = 8,
	IRQCHIP_SKIP_SET_WAKE = 16,
	IRQCHIP_ONESHOT_SAFE = 32,
	IRQCHIP_EOI_THREADED = 64,
	IRQCHIP_SUPPORTS_LEVEL_MSI = 128,
	IRQCHIP_SUPPORTS_NMI = 256,
	IRQCHIP_ENABLE_WAKEUP_ON_SUSPEND = 512,
	IRQCHIP_AFFINITY_PRE_STARTUP = 1024,
	IRQCHIP_IMMUTABLE = 2048,
};

enum {
	IRQ_SET_MASK_OK = 0,
	IRQ_SET_MASK_OK_NOCOPY = 1,
	IRQ_SET_MASK_OK_DONE = 2,
};

enum {
	IRQC_IS_HARDIRQ = 0,
	IRQC_IS_NESTED = 1,
};

enum {
	_IRQ_DEFAULT_INIT_FLAGS = 0,
	_IRQ_PER_CPU = 512,
	_IRQ_LEVEL = 256,
	_IRQ_NOPROBE = 1024,
	_IRQ_NOREQUEST = 2048,
	_IRQ_NOTHREAD = 65536,
	_IRQ_NOAUTOEN = 4096,
	_IRQ_MOVE_PCNTXT = 16384,
	_IRQ_NO_BALANCING = 8192,
	_IRQ_NESTED_THREAD = 32768,
	_IRQ_PER_CPU_DEVID = 131072,
	_IRQ_IS_POLLED = 262144,
	_IRQ_DISABLE_UNLAZY = 524288,
	_IRQ_HIDDEN = 1048576,
	_IRQ_NO_DEBUG = 2097152,
	_IRQF_MODIFY_MASK = 2096911,
};

enum {
	IRQTF_RUNTHREAD = 0,
	IRQTF_WARNED = 1,
	IRQTF_AFFINITY = 2,
	IRQTF_FORCED_THREAD = 3,
	IRQTF_READY = 4,
};

struct btf_kfunc_hook_filter {
	btf_kfunc_filter_t filters[16];
	u32 nr_filters;
};

struct btf_kfunc_set_tab {
	struct btf_id_set8 *sets[13];
	struct btf_kfunc_hook_filter hook_filters[13];
};

struct btf_id_dtor_kfunc {
	u32 btf_id;
	u32 kfunc_btf_id;
};

struct btf_id_dtor_kfunc_tab {
	u32 cnt;
	struct btf_id_dtor_kfunc dtors[0];
};

struct btf_struct_meta {
	u32 btf_id;
	struct btf_record *record;
};

struct btf_struct_metas {
	u32 cnt;
	struct btf_struct_meta types[0];
};

struct bpf_struct_ops;

struct bpf_struct_ops_arg_info;

struct bpf_struct_ops_desc {
	struct bpf_struct_ops *st_ops;
	const struct btf_type *type;
	const struct btf_type *value_type;
	u32 type_id;
	u32 value_id;
	struct bpf_struct_ops_arg_info *arg_info;
};

struct btf_struct_ops_tab {
	u32 cnt;
	u32 capacity;
	struct bpf_struct_ops_desc ops[0];
};

struct bpf_verifier_ops;

struct btf_member;

struct bpf_struct_ops {
	const struct bpf_verifier_ops *verifier_ops;
	int (*init)(struct btf *);
	int (*check_member)(const struct btf_type *, const struct btf_member *, const struct bpf_prog *);
	int (*init_member)(const struct btf_type *, const struct btf_member *, void *, const void *);
	int (*reg)(void *);
	void (*unreg)(void *);
	int (*update)(void *, void *);
	int (*validate)(void *);
	void *cfi_stubs;
	struct module *owner;
	const char *name;
	struct btf_func_model func_models[64];
};

enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2,
};

struct bpf_insn_access_aux;

struct bpf_verifier_log;

struct bpf_reg_state;

struct bpf_verifier_ops {
	const struct bpf_func_proto * (*get_func_proto)(enum bpf_func_id, const struct bpf_prog *);
	bool (*is_valid_access)(int, int, enum bpf_access_type, const struct bpf_prog *, struct bpf_insn_access_aux *);
	int (*gen_prologue)(struct bpf_insn *, bool, const struct bpf_prog *);
	int (*gen_ld_abs)(const struct bpf_insn *, struct bpf_insn *);
	u32 (*convert_ctx_access)(enum bpf_access_type, const struct bpf_insn *, struct bpf_insn *, struct bpf_prog *, u32 *);
	int (*btf_struct_access)(struct bpf_verifier_log *, const struct bpf_reg_state *, int, int);
};

struct bpf_insn_access_aux {
	enum bpf_reg_type reg_type;
	union {
		int ctx_field_size;
		struct {
			struct btf *btf;
			u32 btf_id;
		};
	};
	struct bpf_verifier_log *log;
};

struct bpf_verifier_log {
	u64 start_pos;
	u64 end_pos;
	char __attribute__((btf_type_tag("user"))) *ubuf;
	u32 level;
	u32 len_total;
	u32 len_max;
	char kbuf[1024];
};

enum bpf_iter_state {
	BPF_ITER_STATE_INVALID = 0,
	BPF_ITER_STATE_ACTIVE = 1,
	BPF_ITER_STATE_DRAINED = 2,
};

enum bpf_reg_liveness {
	REG_LIVE_NONE = 0,
	REG_LIVE_READ32 = 1,
	REG_LIVE_READ64 = 2,
	REG_LIVE_READ = 3,
	REG_LIVE_WRITTEN = 4,
	REG_LIVE_DONE = 8,
};

struct bpf_reg_state {
	enum bpf_reg_type type;
	s32 off;
	union {
		int range;
		struct {
			struct bpf_map *map_ptr;
			u32 map_uid;
		};
		struct {
			struct btf *btf;
			u32 btf_id;
		};
		struct {
			u32 mem_size;
			u32 dynptr_id;
		};
		struct {
			enum bpf_dynptr_type type;
			bool first_slot;
		} dynptr;
		struct {
			struct btf *btf;
			u32 btf_id;
			enum bpf_iter_state state: 2;
			int depth: 30;
		} iter;
		struct {
			unsigned long raw1;
			unsigned long raw2;
		} raw;
		u32 subprogno;
	};
	struct tnum var_off;
	s64 smin_value;
	s64 smax_value;
	u64 umin_value;
	u64 umax_value;
	s32 s32_min_value;
	s32 s32_max_value;
	u32 u32_min_value;
	u32 u32_max_value;
	u32 id;
	u32 ref_obj_id;
	struct bpf_reg_state *parent;
	u32 frameno;
	s32 subreg_def;
	enum bpf_reg_liveness live;
	bool precise;
};

struct bpf_id_pair {
	u32 old;
	u32 cur;
};

struct bpf_idmap {
	u32 tmp_id_gen;
	struct bpf_id_pair map[600];
};

struct bpf_idset {
	u32 count;
	u32 ids[600];
};

struct bpf_subprog_arg_info {
	enum bpf_arg_type arg_type;
	union {
		u32 mem_size;
		u32 btf_id;
	};
};

struct bpf_subprog_info {
	u32 start;
	u32 linfo_idx;
	u16 stack_depth;
	u16 stack_extra;
	bool has_tail_call: 1;
	bool tail_call_reachable: 1;
	bool has_ld_abs: 1;
	bool is_cb: 1;
	bool is_async_cb: 1;
	bool is_exception_cb: 1;
	bool args_cached: 1;
	u8 arg_cnt;
	struct bpf_subprog_arg_info args[5];
};

struct backtrack_state {
	struct bpf_verifier_env *env;
	u32 frame;
	u32 reg_masks[8];
	u64 stack_masks[8];
};

typedef sockptr_t bpfptr_t;

struct bpf_verifier_stack_elem;

struct bpf_verifier_state;

struct bpf_verifier_state_list;

struct bpf_insn_aux_data;

struct bpf_jmp_history_entry;

struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;
	const struct bpf_verifier_ops *ops;
	struct module *attach_btf_mod;
	struct bpf_verifier_stack_elem *head;
	int stack_size;
	bool strict_alignment;
	bool test_state_freq;
	bool test_reg_invariants;
	struct bpf_verifier_state *cur_state;
	struct bpf_verifier_state_list **explored_states;
	struct bpf_verifier_state_list *free_list;
	struct bpf_map *used_maps[64];
	struct btf_mod_pair used_btfs[64];
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 id_gen;
	u32 hidden_subprog_cnt;
	int exception_callback_subprog;
	bool explore_alu_limits;
	bool allow_ptr_leaks;
	bool allow_uninit_stack;
	bool bpf_capable;
	bool bypass_spec_v1;
	bool bypass_spec_v4;
	bool seen_direct_write;
	bool seen_exception;
	struct bpf_insn_aux_data *insn_aux_data;
	const struct bpf_line_info *prev_linfo;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[258];
	union {
		struct bpf_idmap idmap_scratch;
		struct bpf_idset idset_scratch;
	};
	struct {
		int *insn_state;
		int *insn_stack;
		int cur_stack;
	} cfg;
	struct backtrack_state bt;
	struct bpf_jmp_history_entry *cur_hist_ent;
	u32 pass_cnt;
	u32 subprog_cnt;
	u32 prev_insn_processed;
	u32 insn_processed;
	u32 prev_jmps_processed;
	u32 jmps_processed;
	u64 verification_time;
	u32 max_states_per_insn;
	u32 total_states;
	u32 peak_states;
	u32 longest_mark_read_walk;
	bpfptr_t fd_array;
	u32 scratched_regs;
	u64 scratched_stack_slots;
	u64 prev_log_pos;
	u64 prev_insn_print_pos;
	struct bpf_reg_state fake_reg[2];
	char tmp_str_buf[320];
};

struct bpf_active_lock {
	void *ptr;
	u32 id;
};

struct bpf_verifier_state {
	struct bpf_func_state *frame[8];
	struct bpf_verifier_state *parent;
	u32 branches;
	u32 insn_idx;
	u32 curframe;
	struct bpf_active_lock active_lock;
	bool speculative;
	bool active_rcu_lock;
	bool used_as_loop_entry;
	u32 first_insn_idx;
	u32 last_insn_idx;
	struct bpf_verifier_state *loop_entry;
	struct bpf_jmp_history_entry *jmp_history;
	u32 jmp_history_cnt;
	u32 dfs_depth;
	u32 callback_unroll_depth;
	u32 may_goto_depth;
};

struct bpf_retval_range {
	s32 minval;
	s32 maxval;
};

struct bpf_reference_state;

struct bpf_stack_state;

struct bpf_func_state {
	struct bpf_reg_state regs[11];
	int callsite;
	u32 frameno;
	u32 subprogno;
	u32 async_entry_cnt;
	struct bpf_retval_range callback_ret_range;
	bool in_callback_fn;
	bool in_async_callback_fn;
	bool in_exception_callback_fn;
	u32 callback_depth;
	int acquired_refs;
	struct bpf_reference_state *refs;
	struct bpf_stack_state *stack;
	int allocated_stack;
};

struct bpf_reference_state {
	int id;
	int insn_idx;
	int callback_ref;
};

struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[8];
};

struct bpf_jmp_history_entry {
	u32 idx;
	u32 prev_idx: 22;
	u32 flags: 10;
};

struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
	int miss_cnt;
	int hit_cnt;
};

struct bpf_loop_inline_state {
	unsigned int initialized: 1;
	unsigned int fit_for_inline: 1;
	u32 callback_subprogno;
};

struct bpf_insn_aux_data {
	union {
		enum bpf_reg_type ptr_type;
		unsigned long map_ptr_state;
		s32 call_imm;
		u32 alu_limit;
		struct {
			u32 map_index;
			u32 map_off;
		};
		struct {
			enum bpf_reg_type reg_type;
			union {
				struct {
					struct btf *btf;
					u32 btf_id;
				};
				u32 mem_size;
			};
		} btf_var;
		struct bpf_loop_inline_state loop_inline_state;
	};
	union {
		u64 obj_new_size;
		u64 insert_off;
	};
	struct btf_struct_meta *kptr_struct_meta;
	u64 map_key_state;
	int ctx_field_size;
	u32 seen;
	bool sanitize_stack_spill;
	bool zext_dst;
	bool needs_zext;
	bool storage_get_func_atomic;
	bool is_iter_next;
	bool call_with_percpu_alloc_ptr;
	u8 alu_state;
	unsigned int orig_idx;
	bool jmp_point;
	bool prune_point;
	bool force_checkpoint;
	bool calls_callback;
};

struct btf_member {
	__u32 name_off;
	__u32 type;
	__u32 offset;
};

struct bpf_struct_ops_arg_info {
	struct bpf_ctx_arg_aux *info;
	u32 cnt;
};

struct inet_ehash_bucket;

struct inet_bind_hashbucket;

struct inet_listen_hashbucket;

struct inet_hashinfo {
	struct inet_ehash_bucket *ehash;
	spinlock_t *ehash_locks;
	unsigned int ehash_mask;
	unsigned int ehash_locks_mask;
	struct kmem_cache *bind_bucket_cachep;
	struct inet_bind_hashbucket *bhash;
	struct kmem_cache *bind2_bucket_cachep;
	struct inet_bind_hashbucket *bhash2;
	unsigned int bhash_size;
	unsigned int lhash2_mask;
	struct inet_listen_hashbucket *lhash2;
	bool pernet;
};

struct inet_ehash_bucket {
	struct hlist_nulls_head chain;
};

struct inet_bind_hashbucket {
	spinlock_t lock;
	struct hlist_head chain;
};

struct inet_listen_hashbucket {
	spinlock_t lock;
	struct hlist_nulls_head nulls_head;
};

struct ack_sample {
	u32 pkts_acked;
	s32 rtt_us;
	u32 in_flight;
};

struct rate_sample {
	u64 prior_mstamp;
	u32 prior_delivered;
	u32 prior_delivered_ce;
	s32 delivered;
	s32 delivered_ce;
	long interval_us;
	u32 snd_interval_us;
	u32 rcv_interval_us;
	long rtt_us;
	int losses;
	u32 acked_sacked;
	u32 prior_in_flight;
	u32 last_end_seq;
	bool is_app_limited;
	bool is_retrans;
	bool is_ack_delayed;
};

struct sk_psock_progs {
	struct bpf_prog *msg_parser;
	struct bpf_prog *stream_parser;
	struct bpf_prog *stream_verdict;
	struct bpf_prog *skb_verdict;
};

struct sk_psock_work_state {
	u32 len;
	u32 off;
};

struct rcu_work {
	struct work_struct work;
	struct callback_head rcu;
	struct workqueue_struct *wq;
};

struct sk_msg;

struct sk_psock {
	struct sock *sk;
	struct sock *sk_redir;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 eval;
	bool redir_ingress;
	struct sk_msg *cork;
	struct sk_psock_progs progs;
	struct sk_buff_head ingress_skb;
	struct list_head ingress_msg;
	spinlock_t ingress_lock;
	unsigned long state;
	struct list_head link;
	spinlock_t link_lock;
	refcount_t refcnt;
	void (*saved_unhash)(struct sock *);
	void (*saved_destroy)(struct sock *);
	void (*saved_close)(struct sock *, long);
	void (*saved_write_space)(struct sock *);
	void (*saved_data_ready)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	struct proto *sk_proto;
	struct mutex work_mutex;
	struct sk_psock_work_state work_state;
	struct delayed_work work;
	struct sock *sk_pair;
	struct rcu_work rwork;
};

struct sk_msg_sg {
	u32 start;
	u32 curr;
	u32 end;
	u32 size;
	u32 copybreak;
	unsigned long copy[1];
	struct scatterlist data[19];
};

struct sk_msg {
	struct sk_msg_sg sg;
	void *data;
	void *data_end;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 flags;
	struct sk_buff *skb;
	struct sock *sk_redir;
	struct sock *sk;
	struct list_head list;
};

struct bpf_ctx_convert {
	void *BPF_PROG_TYPE_SYSCALL_prog;
	void *BPF_PROG_TYPE_SYSCALL_kern;
};

struct btf_verifier_env;

struct resolve_vertex;

struct btf_show;

struct btf_kind_operations {
	s32 (*check_meta)(struct btf_verifier_env *, const struct btf_type *, u32);
	int (*resolve)(struct btf_verifier_env *, const struct resolve_vertex *);
	int (*check_member)(struct btf_verifier_env *, const struct btf_type *, const struct btf_member *, const struct btf_type *);
	int (*check_kflag_member)(struct btf_verifier_env *, const struct btf_type *, const struct btf_member *, const struct btf_type *);
	void (*log_details)(struct btf_verifier_env *, const struct btf_type *);
	void (*show)(const struct btf *, const struct btf_type *, u32, void *, u8, struct btf_show *);
};

struct resolve_vertex {
	const struct btf_type *t;
	u32 type_id;
	u16 next_member;
};

enum verifier_phase {
	CHECK_META = 0,
	CHECK_TYPE = 1,
};

enum resolve_mode {
	RESOLVE_TBD = 0,
	RESOLVE_PTR = 1,
	RESOLVE_STRUCT_OR_ARRAY = 2,
};

struct btf_verifier_env {
	struct btf *btf;
	u8 *visit_states;
	struct resolve_vertex stack[32];
	struct bpf_verifier_log log;
	u32 log_type_id;
	u32 top_stack;
	enum verifier_phase phase;
	enum resolve_mode resolve_mode;
};

struct btf_show {
	u64 flags;
	void *target;
	void (*showfn)(struct btf_show *, const char *, struct __va_list_tag *);
	const struct btf *btf;
	struct {
		u8 depth;
		u8 depth_to_show;
		u8 depth_check;
		u8 array_member: 1;
		u8 array_terminated: 1;
		u16 array_encoding;
		u32 type_id;
		int status;
		const struct btf_type *type;
		const struct btf_member *member;
		char name[80];
	} state;
	struct {
		u32 size;
		void *head;
		void *data;
		u8 safe[32];
	} obj;
};

struct bpf_cand_cache {
	const char *name;
	u32 name_len;
	u16 kind;
	u16 cnt;
	struct {
		const struct btf *btf;
		u32 id;
	} cands[0];
};

enum bpf_type_flag {
	PTR_MAYBE_NULL = 256,
	MEM_RDONLY = 512,
	MEM_RINGBUF = 1024,
	MEM_USER = 2048,
	MEM_PERCPU = 4096,
	OBJ_RELEASE = 8192,
	PTR_UNTRUSTED = 16384,
	MEM_UNINIT = 32768,
	DYNPTR_TYPE_LOCAL = 65536,
	DYNPTR_TYPE_RINGBUF = 131072,
	MEM_FIXED_SIZE = 262144,
	MEM_ALLOC = 524288,
	PTR_TRUSTED = 1048576,
	MEM_RCU = 2097152,
	NON_OWN_REF = 4194304,
	DYNPTR_TYPE_SKB = 8388608,
	DYNPTR_TYPE_XDP = 16777216,
	__BPF_TYPE_FLAG_MAX = 16777217,
	__BPF_TYPE_LAST_FLAG = 16777216,
};

enum bpf_struct_walk_result {
	WALK_SCALAR = 0,
	WALK_PTR = 1,
	WALK_STRUCT = 2,
};

enum btf_func_linkage {
	BTF_FUNC_STATIC = 0,
	BTF_FUNC_GLOBAL = 1,
	BTF_FUNC_EXTERN = 2,
};

enum btf_arg_tag {
	ARG_TAG_CTX = 1,
	ARG_TAG_NONNULL = 2,
	ARG_TAG_TRUSTED = 4,
	ARG_TAG_NULLABLE = 8,
	ARG_TAG_ARENA = 16,
};

enum {
	BTF_F_COMPACT = 1,
	BTF_F_NONAME = 2,
	BTF_F_PTR_RAW = 4,
	BTF_F_ZERO = 8,
};

enum btf_kfunc_hook {
	BTF_KFUNC_HOOK_COMMON = 0,
	BTF_KFUNC_HOOK_XDP = 1,
	BTF_KFUNC_HOOK_TC = 2,
	BTF_KFUNC_HOOK_STRUCT_OPS = 3,
	BTF_KFUNC_HOOK_TRACING = 4,
	BTF_KFUNC_HOOK_SYSCALL = 5,
	BTF_KFUNC_HOOK_FMODRET = 6,
	BTF_KFUNC_HOOK_CGROUP_SKB = 7,
	BTF_KFUNC_HOOK_SCHED_ACT = 8,
	BTF_KFUNC_HOOK_SK_SKB = 9,
	BTF_KFUNC_HOOK_SOCKET_FILTER = 10,
	BTF_KFUNC_HOOK_LWT = 11,
	BTF_KFUNC_HOOK_NETFILTER = 12,
	BTF_KFUNC_HOOK_MAX = 13,
};

enum {
	BTF_KFUNC_SET_MAX_CNT = 256,
	BTF_DTOR_KFUNC_MAX_CNT = 256,
	BTF_KFUNC_FILTER_MAX_CNT = 16,
};

enum bpf_core_relo_kind {
	BPF_CORE_FIELD_BYTE_OFFSET = 0,
	BPF_CORE_FIELD_BYTE_SIZE = 1,
	BPF_CORE_FIELD_EXISTS = 2,
	BPF_CORE_FIELD_SIGNED = 3,
	BPF_CORE_FIELD_LSHIFT_U64 = 4,
	BPF_CORE_FIELD_RSHIFT_U64 = 5,
	BPF_CORE_TYPE_ID_LOCAL = 6,
	BPF_CORE_TYPE_ID_TARGET = 7,
	BPF_CORE_TYPE_EXISTS = 8,
	BPF_CORE_TYPE_SIZE = 9,
	BPF_CORE_ENUMVAL_EXISTS = 10,
	BPF_CORE_ENUMVAL_VALUE = 11,
	BPF_CORE_TYPE_MATCHES = 12,
};

enum {
	BTF_FIELD_IGNORE = 0,
	BTF_FIELD_FOUND = 1,
};

enum visit_state {
	NOT_VISITED = 0,
	VISITED = 1,
	RESOLVED = 2,
};

enum {
	BTF_VAR_STATIC = 0,
	BTF_VAR_GLOBAL_ALLOCATED = 1,
	BTF_VAR_GLOBAL_EXTERN = 2,
};

struct btf_param {
	__u32 name_off;
	__u32 type;
};

typedef u64 (*btf_bpf_btf_find_by_name_kind)(char *, int, u32, int);

struct btf_array {
	__u32 type;
	__u32 index_type;
	__u32 nelems;
};

struct btf_decl_tag {
	__s32 component_idx;
};

struct btf_var_secinfo {
	__u32 type;
	__u32 offset;
	__u32 size;
};

struct btf_sec_info {
	u32 off;
	u32 len;
};

struct btf_enum {
	__u32 name_off;
	__s32 val;
};

struct btf_var {
	__u32 linkage;
};

struct btf_enum64 {
	__u32 name_off;
	__u32 val_lo32;
	__u32 val_hi32;
};

struct btf_show_snprintf {
	struct btf_show show;
	int len_left;
	int len;
};

struct btf_field_info {
	enum btf_field_type type;
	u32 off;
	union {
		struct {
			u32 type_id;
		} kptr;
		struct {
			const char *node_name;
			u32 value_btf_id;
		} graph_root;
	};
};

typedef int (*cmp_r_func_t)(const void *, const void *, const void *);

typedef void (*swap_r_func_t)(void *, void *, int, const void *);

typedef int (*cmp_func_t)(const void *, const void *);

struct btf_id_set {
	u32 cnt;
	u32 ids[0];
};

typedef void (*swap_func_t)(void *, void *, int);

struct bpf_core_relo {
	__u32 insn_off;
	__u32 type_id;
	__u32 access_str_off;
	enum bpf_core_relo_kind kind;
};

struct bpf_core_cand;

struct bpf_core_cand_list {
	struct bpf_core_cand *cands;
	int len;
};

struct bpf_core_cand {
	const struct btf *btf;
	__u32 id;
};

struct bpf_core_accessor {
	__u32 type_id;
	__u32 idx;
	const char *name;
};

struct bpf_core_spec {
	const struct btf *btf;
	struct bpf_core_accessor spec[64];
	__u32 root_type_id;
	enum bpf_core_relo_kind relo_kind;
	int len;
	int raw_spec[64];
	int raw_len;
	__u32 bit_offset;
};

struct bpf_core_relo_res {
	__u64 orig_val;
	__u64 new_val;
	bool poison;
	bool validate;
	bool fail_memsz_adjust;
	__u32 orig_sz;
	__u32 orig_type_id;
	__u32 new_sz;
	__u32 new_type_id;
};

struct bpf_core_ctx {
	struct bpf_verifier_log *log;
	const struct btf *btf;
};

struct bpf_btf_info {
	__u64 btf;
	__u32 btf_size;
	__u32 id;
	__u64 name;
	__u32 name_len;
	__u32 kernel_btf;
};

enum maple_status {
	ma_active = 0,
	ma_start = 1,
	ma_root = 2,
	ma_none = 3,
	ma_pause = 4,
	ma_overflow = 5,
	ma_underflow = 6,
	ma_error = 7,
};

enum {
	MM_FILEPAGES = 0,
	MM_ANONPAGES = 1,
	MM_SWAPENTS = 2,
	MM_SHMEMPAGES = 3,
	NR_MM_COUNTERS = 4,
};

struct timens_offsets {
	struct timespec64 monotonic;
	struct timespec64 boottime;
};

struct time_namespace {
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
	struct timens_offsets offsets;
	struct page *vvar_page;
	bool frozen_offsets;
};

typedef unsigned short ushort;

struct maple_enode;

struct maple_alloc;

struct ma_state {
	struct maple_tree *tree;
	unsigned long index;
	unsigned long last;
	struct maple_enode *node;
	unsigned long min;
	unsigned long max;
	struct maple_alloc *alloc;
	enum maple_status status;
	unsigned char depth;
	unsigned char offset;
	unsigned char mas_flags;
	unsigned char end;
};

struct vma_iterator {
	struct ma_state mas;
};

struct maple_alloc {
	unsigned long total;
	unsigned char node_count;
	unsigned int request_count;
	struct maple_alloc *slot[30];
};

struct user_arg_ptr {
	union {
		const char __attribute__((btf_type_tag("user"))) * const __attribute__((btf_type_tag("user"))) *native;
	} ptr;
};

typedef int (*list_cmp_func_t)(void *, const struct list_head *, const struct list_head *);

struct genradix_root;

struct genradix_node {
	union {
		struct genradix_node *children[64];
		u8 data[512];
	};
};

struct __genradix {
	struct genradix_root *root;
};

struct genradix_iter {
	size_t offset;
	size_t pos;
};

struct attribute_container;

struct internal_container {
	struct klist_node node;
	struct attribute_container *cont;
	struct device classdev;
};

struct attribute_container {
	struct list_head node;
	struct klist containers;
	struct class *class;
	const struct attribute_group *grp;
	struct device_attribute **attrs;
	int (*match)(struct attribute_container *, struct device *);
	unsigned long flags;
};

struct klist_iter {
	struct klist *i_klist;
	struct klist_node *i_cur;
};

enum {
	st_wordstart = 0,
	st_wordcmp = 1,
	st_wordskip = 2,
};

enum {
	st_wordstart___2 = 0,
	st_wordcmp___2 = 1,
	st_wordskip___2 = 2,
	st_bufcpy = 3,
};

typedef unsigned char insn_byte_t;

enum insn_mode {
	INSN_MODE_32 = 0,
	INSN_MODE_64 = 1,
	INSN_MODE_KERN = 2,
	INSN_NUM_MODES = 3,
};

typedef __u16 __le16;

typedef __u32 __le32;

typedef int insn_value_t;

struct insn_field {
	union {
		insn_value_t value;
		insn_byte_t bytes[4];
	};
	unsigned char got;
	unsigned char nbytes;
};

typedef unsigned int insn_attr_t;

struct insn {
	struct insn_field prefixes;
	struct insn_field rex_prefix;
	struct insn_field vex_prefix;
	struct insn_field opcode;
	struct insn_field modrm;
	struct insn_field sib;
	struct insn_field displacement;
	union {
		struct insn_field immediate;
		struct insn_field moffset1;
		struct insn_field immediate1;
	};
	union {
		struct insn_field moffset2;
		struct insn_field immediate2;
	};
	int emulate_prefix_size;
	insn_attr_t attr;
	unsigned char opnd_bytes;
	unsigned char addr_bytes;
	unsigned char length;
	unsigned char x86_64;
	const insn_byte_t *kaddr;
	const insn_byte_t *end_kaddr;
	const insn_byte_t *next_byte;
};

typedef struct {
	seqcount_t seqcount;
} seqcount_latch_t;

struct cyc2ns {
	struct cyc2ns_data data[2];
	seqcount_latch_t seq;
};

enum clocksource_ids {
	CSID_GENERIC = 0,
	CSID_ARM_ARCH_COUNTER = 1,
	CSID_X86_TSC_EARLY = 2,
	CSID_X86_TSC = 3,
	CSID_X86_KVM_CLK = 4,
	CSID_MAX = 5,
};

enum vdso_clock_mode {
	VDSO_CLOCKMODE_NONE = 0,
	VDSO_CLOCKMODE_TSC = 1,
	VDSO_CLOCKMODE_PVCLOCK = 2,
	VDSO_CLOCKMODE_HVCLOCK = 3,
	VDSO_CLOCKMODE_MAX = 4,
	VDSO_CLOCKMODE_TIMENS = 2147483647,
};

struct clocksource {
	u64 (*read)(struct clocksource *);
	u64 mask;
	u32 mult;
	u32 shift;
	u64 max_idle_ns;
	u32 maxadj;
	u32 uncertainty_margin;
	u64 max_cycles;
	const char *name;
	struct list_head list;
	int rating;
	enum clocksource_ids id;
	enum vdso_clock_mode vdso_clock_mode;
	unsigned long flags;
	int (*enable)(struct clocksource *);
	void (*disable)(struct clocksource *);
	void (*suspend)(struct clocksource *);
	void (*resume)(struct clocksource *);
	void (*mark_unstable)(struct clocksource *);
	void (*tick_stable)(struct clocksource *);
	struct list_head wd_list;
	u64 cs_last;
	u64 wd_last;
	struct module *owner;
};

typedef unsigned long long cycles_t;

typedef unsigned int u_int;

struct system_counterval_t {
	u64 cycles;
	enum clocksource_ids cs_id;
};

struct _fpx_sw_bytes {
	__u32 magic1;
	__u32 extended_size;
	__u64 xfeatures;
	__u32 xstate_size;
	__u32 padding[7];
};

struct user_i387_ia32_struct {
	u32 cwd;
	u32 swd;
	u32 twd;
	u32 fip;
	u32 fcs;
	u32 foo;
	u32 fos;
	u32 st_space[20];
};

struct va_alignment {
	int flags;
	unsigned long mask;
	unsigned long bits;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *, struct kobj_attribute *, char *);
	ssize_t (*store)(struct kobject *, struct kobj_attribute *, const char *, size_t);
};

typedef s64 int64_t;

struct ce_unbind {
	struct clock_event_device *ce;
	int res;
};

struct bpf_preload_info;

struct bpf_preload_ops {
	int (*preload)(struct bpf_preload_info *);
	struct module *owner;
};

struct bpf_preload_info {
	char link_name[16];
	struct bpf_link *link;
};

struct tree_descr {
	const char *name;
	const struct file_operations *ops;
	int mode;
};

enum bpf_type {
	BPF_TYPE_UNSPEC = 0,
	BPF_TYPE_PROG = 1,
	BPF_TYPE_MAP = 2,
	BPF_TYPE_LINK = 3,
};

enum {
	OPT_UID = 0,
	OPT_GID = 1,
	OPT_MODE = 2,
	OPT_DELEGATE_CMDS = 3,
	OPT_DELEGATE_MAPS = 4,
	OPT_DELEGATE_PROGS = 5,
	OPT_DELEGATE_ATTACHS = 6,
};

struct map_iter {
	void *key;
	bool done;
};

struct bpffs_btf_enums {
	const struct btf *btf;
	const struct btf_type *cmd_t;
	const struct btf_type *map_t;
	const struct btf_type *prog_t;
	const struct btf_type *attach_t;
};

struct static_key_true;

struct once_work {
	struct work_struct work;
	struct static_key_true *key;
	struct module *module;
};

struct static_key_true {
	struct static_key key;
};

struct devres_node {
	struct list_head entry;
	dr_release_t release;
	const char *name;
	size_t size;
};

struct devres {
	struct devres_node node;
	u8 data[0];
};

struct devres_group {
	struct devres_node node[2];
	void *id;
	int color;
};

struct action_devres {
	void *data;
	void (*action)(void *);
};

struct pages_devres {
	unsigned long addr;
	unsigned int order;
};

struct vm_special_mapping {
	const char *name;
	struct page **pages;
	vm_fault_t (*fault)(const struct vm_special_mapping *, struct vm_area_struct *, struct vm_fault *);
	int (*mremap)(const struct vm_special_mapping *, struct vm_area_struct *);
};

struct vdso_timestamp {
	u64 sec;
	u64 nsec;
};

struct timens_offset {
	s64 sec;
	u64 nsec;
};

struct arch_vdso_data {};

struct vdso_data {
	u32 seq;
	s32 clock_mode;
	u64 cycle_last;
	u64 mask;
	u32 mult;
	u32 shift;
	union {
		struct vdso_timestamp basetime[12];
		struct timens_offset offset[12];
	};
	s32 tz_minuteswest;
	s32 tz_dsttime;
	u32 hrtimer_res;
	u32 __unused;
	struct arch_vdso_data arch_data;
};

struct alt_instr {
	s32 instr_offset;
	s32 repl_offset;
	union {
		struct {
			u32 cpuid: 16;
			u32 flags: 16;
		};
		u32 ft_flags;
	};
	u8 instrlen;
	u8 replacementlen;
} __attribute__((packed));

struct stack_frame_user {
	const void __attribute__((btf_type_tag("user"))) *next_fp;
	unsigned long ret_addr;
};

typedef bool (*stack_trace_consume_fn)(void *, unsigned long);

enum tlb_infos {
	ENTRIES = 0,
	NR_INFO = 1,
};

enum apic_intr_mode_id {
	APIC_PIC = 0,
	APIC_VIRTUAL_WIRE = 1,
	APIC_VIRTUAL_WIRE_NO_CONFIG = 2,
	APIC_SYMMETRIC_IO = 3,
	APIC_SYMMETRIC_IO_NO_ROUTING = 4,
};

struct dmi_strmatch {
	unsigned char slot: 7;
	unsigned char exact_match: 1;
	char substr[79];
};

struct dmi_system_id {
	int (*callback)(const struct dmi_system_id *);
	const char *ident;
	struct dmi_strmatch matches[4];
	void *driver_data;
};

struct irqentry_state {
	union {
		bool exit_rcu;
		bool lockdep;
	};
};

typedef struct irqentry_state irqentry_state_t;

union apic_ir {
	unsigned long map[4];
	u32 regs[8];
};

struct tasklet_struct;

struct tasklet_head {
	struct tasklet_struct *head;
	struct tasklet_struct **tail;
};

struct tasklet_struct {
	struct tasklet_struct *next;
	unsigned long state;
	atomic_t count;
	bool use_callback;
	union {
		void (*func)(unsigned long);
		void (*callback)(struct tasklet_struct *);
	};
	unsigned long data;
};

struct smp_hotplug_thread {
	struct task_struct * __attribute__((btf_type_tag("percpu"))) *store;
	struct list_head list;
	int (*thread_should_run)(unsigned int);
	void (*thread_fn)(unsigned int);
	void (*create)(unsigned int);
	void (*setup)(unsigned int);
	void (*cleanup)(unsigned int, bool);
	void (*park)(unsigned int);
	void (*unpark)(unsigned int);
	bool selfparking;
	const char *thread_comm;
};

enum {
	TASKLET_STATE_SCHED = 0,
	TASKLET_STATE_RUN = 1,
};

struct wait_bit_key {
	void *flags;
	int bit_nr;
	unsigned long timeout;
};

struct wait_bit_queue_entry {
	struct wait_bit_key key;
	struct wait_queue_entry wq_entry;
};

typedef struct {
	void *lock;
} class_rcu_t;

struct timer_base {
	raw_spinlock_t lock;
	struct timer_list *running_timer;
	unsigned long clk;
	unsigned long next_expiry;
	unsigned int cpu;
	bool next_expiry_recalc;
	bool is_idle;
	bool timers_pending;
	unsigned long pending_map[9];
	struct hlist_head vectors[576];
	long: 64;
	long: 64;
	long: 64;
};

struct process_timer {
	struct timer_list timer;
	struct task_struct *task;
};

enum rmap_level {
	RMAP_LEVEL_PTE = 0,
	RMAP_LEVEL_PMD = 1,
};

enum ttu_flags {
	TTU_SPLIT_HUGE_PMD = 4,
	TTU_IGNORE_MLOCK = 8,
	TTU_SYNC = 16,
	TTU_HWPOISON = 32,
	TTU_BATCH_FLUSH = 64,
	TTU_RMAP_LOCKED = 128,
};

struct anon_vma_chain {
	struct vm_area_struct *vma;
	struct anon_vma *anon_vma;
	struct list_head same_vma;
	struct rb_node rb;
	unsigned long rb_subtree_last;
};

typedef int rmap_t;

struct page_vma_mapped_walk {
	unsigned long pfn;
	unsigned long nr_pages;
	unsigned long pgoff;
	struct vm_area_struct *vma;
	unsigned long address;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned int flags;
};

struct rmap_walk_control {
	void *arg;
	bool try_lock;
	bool contended;
	bool (*rmap_one)(struct folio *, struct vm_area_struct *, unsigned long, void *);
	int (*done)(struct folio *);
	struct anon_vma * (*anon_lock)(struct folio *, struct rmap_walk_control *);
	bool (*invalid_vma)(struct vm_area_struct *, void *);
};

struct folio_referenced_arg {
	int mapcount;
	int referenced;
	unsigned long vm_flags;
	struct mem_cgroup *memcg;
};

struct mmu_notifier_range {
	unsigned long start;
	unsigned long end;
};

struct driver_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device_driver *, char *);
	ssize_t (*store)(struct device_driver *, const char *, size_t);
};

struct bus_attribute {
	struct attribute attr;
	ssize_t (*show)(const struct bus_type *, char *);
	ssize_t (*store)(const struct bus_type *, const char *, size_t);
};

enum bus_notifier_event {
	BUS_NOTIFY_ADD_DEVICE = 0,
	BUS_NOTIFY_DEL_DEVICE = 1,
	BUS_NOTIFY_REMOVED_DEVICE = 2,
	BUS_NOTIFY_BIND_DRIVER = 3,
	BUS_NOTIFY_BOUND_DRIVER = 4,
	BUS_NOTIFY_UNBIND_DRIVER = 5,
	BUS_NOTIFY_UNBOUND_DRIVER = 6,
	BUS_NOTIFY_DRIVER_NOT_BOUND = 7,
};

struct subsys_interface {
	const char *name;
	const struct bus_type *subsys;
	struct list_head node;
	int (*add_dev)(struct device *, struct subsys_interface *);
	void (*remove_dev)(struct device *, struct subsys_interface *);
};

struct subsys_private {
	struct kset subsys;
	struct kset *devices_kset;
	struct list_head interfaces;
	struct mutex mutex;
	struct kset *drivers_kset;
	struct klist klist_devices;
	struct klist klist_drivers;
	struct blocking_notifier_head bus_notifier;
	unsigned int drivers_autoprobe: 1;
	const struct bus_type *bus;
	struct device *dev_root;
	struct kset glue_dirs;
	const struct class *class;
	struct lock_class_key lock_key;
};

struct subsys_dev_iter {
	struct klist_iter ki;
	const struct device_type *type;
};

enum {
	EMULATE = 0,
	XONLY = 1,
	NONE = 2,
};

enum x86_pf_error_code {
	X86_PF_PROT = 1,
	X86_PF_WRITE = 2,
	X86_PF_USER = 4,
	X86_PF_RSVD = 8,
	X86_PF_INSTR = 16,
	X86_PF_PK = 32,
	X86_PF_SHSTK = 64,
	X86_PF_SGX = 32768,
	X86_PF_RMP = 2147483648,
};

union text_poke_insn {
	u8 text[5];
	struct {
		u8 opcode;
		s32 disp;
	} __attribute__((packed));
};

enum insn_type {
	CALL = 0,
	NOP = 1,
	JMP = 2,
	RET = 3,
	JCC = 4,
};

struct fpu_state_config {
	unsigned int max_size;
	unsigned int default_size;
	u64 max_features;
	u64 default_features;
	u64 legacy_features;
};

struct cpuhp_step {
	const char *name;
	union {
		int (*single)(unsigned int);
		int (*multi)(unsigned int, struct hlist_node *);
	} startup;
	union {
		int (*single)(unsigned int);
		int (*multi)(unsigned int, struct hlist_node *);
	} teardown;
	struct hlist_head list;
	bool cant_stop;
	bool multi_instance;
};

struct cpuhp_cpu_state {
	enum cpuhp_state state;
	enum cpuhp_state target;
	enum cpuhp_state fail;
};

struct srcu_usage {};

struct srcu_notifier_head {
	struct mutex mutex;
	struct srcu_usage srcuu;
	struct srcu_struct srcu;
	struct notifier_block __attribute__((btf_type_tag("rcu"))) *head;
};

typedef u64 async_cookie_t;

struct async_domain {
	struct list_head pending;
	unsigned int registered: 1;
};

enum wq_flags {
	WQ_BH = 1,
	WQ_UNBOUND = 2,
	WQ_FREEZABLE = 4,
	WQ_MEM_RECLAIM = 8,
	WQ_HIGHPRI = 16,
	WQ_CPU_INTENSIVE = 32,
	WQ_SYSFS = 64,
	WQ_POWER_EFFICIENT = 128,
	__WQ_DESTROYING = 32768,
	__WQ_DRAINING = 65536,
	__WQ_ORDERED = 131072,
	__WQ_LEGACY = 262144,
	__WQ_BH_ALLOWS = 17,
};

enum wq_consts {
	WQ_MAX_ACTIVE = 512,
	WQ_UNBOUND_MAX_ACTIVE = 512,
	WQ_DFL_ACTIVE = 256,
	WQ_DFL_MIN_ACTIVE = 8,
};

typedef void (*async_func_t)(void *, async_cookie_t);

struct async_entry {
	struct list_head domain_list;
	struct list_head global_list;
	struct work_struct work;
	async_cookie_t cookie;
	async_func_t func;
	void *data;
	struct async_domain *domain;
};

struct pool_workqueue;

struct worker_pool;

struct worker {
	union {
		struct list_head entry;
		struct hlist_node hentry;
	};
	struct work_struct *current_work;
	work_func_t current_func;
	struct pool_workqueue *current_pwq;
	u64 current_at;
	unsigned int current_color;
	int sleeping;
	work_func_t last_func;
	struct list_head scheduled;
	struct task_struct *task;
	struct worker_pool *pool;
	struct list_head node;
	unsigned long last_active;
	unsigned int flags;
	int id;
	char desc[32];
	struct workqueue_struct *rescue_wq;
};

struct lpm_trie_node;

struct lpm_trie {
	struct bpf_map map;
	struct lpm_trie_node __attribute__((btf_type_tag("rcu"))) *root;
	size_t n_entries;
	size_t max_prefixlen;
	size_t data_size;
	spinlock_t lock;
};

struct lpm_trie_node {
	struct callback_head rcu;
	struct lpm_trie_node __attribute__((btf_type_tag("rcu"))) *child[2];
	u32 prefixlen;
	u32 flags;
	u8 data[0];
};

typedef __u64 __be64;

struct bpf_lpm_trie_key_hdr {
	__u32 prefixlen;
};

struct bpf_lpm_trie_key_u8 {
	union {
		struct bpf_lpm_trie_key_hdr hdr;
		__u32 prefixlen;
	};
	__u8 data[0];
};

enum {
	HUGETLB_SHMFS_INODE = 1,
	HUGETLB_ANONHUGE_INODE = 2,
};

struct vma_prepare {
	struct vm_area_struct *vma;
	struct vm_area_struct *adj_next;
	struct file *file;
	struct address_space *mapping;
	struct anon_vma *anon_vma;
	struct vm_area_struct *insert;
	struct vm_area_struct *remove;
	struct vm_area_struct *remove2;
};

struct vm_unmapped_area_info {
	unsigned long flags;
	unsigned long length;
	unsigned long low_limit;
	unsigned long high_limit;
	unsigned long align_mask;
	unsigned long align_offset;
};

struct anon_vma_name {
	struct kref kref;
	char name[0];
};

struct mempolicy {};

enum blake2s_iv {
	BLAKE2S_IV0 = 1779033703,
	BLAKE2S_IV1 = 3144134277,
	BLAKE2S_IV2 = 1013904242,
	BLAKE2S_IV3 = 2773480762,
	BLAKE2S_IV4 = 1359893119,
	BLAKE2S_IV5 = 2600822924,
	BLAKE2S_IV6 = 528734635,
	BLAKE2S_IV7 = 1541459225,
};

enum {
	TEST_ALIGNMENT = 16,
};

struct transport_container;

struct transport_class {
	struct class class;
	int (*setup)(struct transport_container *, struct device *, struct device *);
	int (*configure)(struct transport_container *, struct device *, struct device *);
	int (*remove)(struct transport_container *, struct device *, struct device *);
};

struct transport_container {
	struct attribute_container ac;
	const struct attribute_group *statistics;
};

struct anon_transport_class {
	struct transport_class tclass;
	struct attribute_container container;
};

struct legacy_pic {
	int nr_legacy_irqs;
	struct irq_chip *chip;
	void (*mask)(unsigned int);
	void (*unmask)(unsigned int);
	void (*mask_all)();
	void (*restore_mask)();
	void (*init)(int);
	int (*probe)();
	int (*irq_pending)(unsigned int);
	void (*make_irq)(unsigned int);
};

struct syscore_ops {
	struct list_head node;
	int (*suspend)();
	void (*resume)();
	void (*shutdown)();
};

struct change_member {
	struct e820_entry *entry;
	unsigned long long addr;
};

struct user_regset;

typedef int user_regset_get2_fn(struct task_struct *, const struct user_regset *, struct membuf);

typedef int user_regset_set_fn(struct task_struct *, const struct user_regset *, unsigned int, unsigned int, const void *, const void __attribute__((btf_type_tag("user"))) *);

typedef int user_regset_active_fn(struct task_struct *, const struct user_regset *);

typedef int user_regset_writeback_fn(struct task_struct *, const struct user_regset *, int);

struct user_regset {
	user_regset_get2_fn *regset_get;
	user_regset_set_fn *set;
	user_regset_active_fn *active;
	user_regset_writeback_fn *writeback;
	unsigned int n;
	unsigned int size;
	unsigned int align;
	unsigned int bias;
	unsigned int core_note_type;
};

enum ucode_state {
	UCODE_OK = 0,
	UCODE_NEW = 1,
	UCODE_NEW_SAFE = 2,
	UCODE_UPDATED = 3,
	UCODE_NFOUND = 4,
	UCODE_ERROR = 5,
	UCODE_TIMEOUT = 6,
	UCODE_OFFLINE = 7,
};

struct cpu_signature;

struct microcode_ops {
	enum ucode_state (*request_microcode_fw)(int, struct device *);
	void (*microcode_fini_cpu)(int);
	enum ucode_state (*apply_microcode)(int);
	int (*collect_cpu_info)(int, struct cpu_signature *);
	void (*finalize_late_load)(int);
	unsigned int nmi_safe: 1;
	unsigned int use_nmi: 1;
};

struct cpu_signature {
	unsigned int sig;
	unsigned int pf;
	unsigned int rev;
};

struct ucode_cpu_info {
	struct cpu_signature cpu_sig;
	void *mc;
};

struct early_load_data {
	u32 old_rev;
	u32 new_rev;
};

struct mfd_cell;

struct pdev_archdata {};

struct platform_device_id;

struct platform_device {
	const char *name;
	int id;
	bool id_auto;
	struct device dev;
	u64 platform_dma_mask;
	struct device_dma_parameters dma_parms;
	u32 num_resources;
	struct resource *resource;
	const struct platform_device_id *id_entry;
	const char *driver_override;
	struct mfd_cell *mfd_cell;
	struct pdev_archdata archdata;
};

struct platform_device_id {
	char name[20];
	kernel_ulong_t driver_data;
};

struct property_entry;

struct platform_device_info {
	struct device *parent;
	struct fwnode_handle *fwnode;
	bool of_node_reused;
	const char *name;
	int id;
	const struct resource *res;
	unsigned int num_res;
	const void *data;
	size_t size_data;
	u64 dma_mask;
	const struct property_entry *properties;
};

enum dev_prop_type {
	DEV_PROP_U8 = 0,
	DEV_PROP_U16 = 1,
	DEV_PROP_U32 = 2,
	DEV_PROP_U64 = 3,
	DEV_PROP_STRING = 4,
	DEV_PROP_REF = 5,
};

struct property_entry {
	const char *name;
	size_t length;
	bool is_inline;
	enum dev_prop_type type;
	union {
		const void *pointer;
		union {
			u8 u8_data[8];
			u16 u16_data[4];
			u32 u32_data[2];
			u64 u64_data[1];
			const char *str[1];
		} value;
	};
};

struct cpio_data {
	void *data;
	size_t size;
	char name[18];
};

enum {
	HP_THREAD_NONE = 0,
	HP_THREAD_ACTIVE = 1,
	HP_THREAD_PARKED = 2,
};

struct smpboot_thread_data {
	unsigned int cpu;
	unsigned int status;
	struct smp_hotplug_thread *ht;
};

struct cpumap {
	unsigned int available;
	unsigned int allocated;
	unsigned int managed;
	unsigned int managed_allocated;
	bool initialized;
	bool online;
	unsigned long *managed_map;
	unsigned long alloc_map[0];
};

struct irq_matrix {
	unsigned int matrix_bits;
	unsigned int alloc_start;
	unsigned int alloc_end;
	unsigned int alloc_size;
	unsigned int global_available;
	unsigned int global_reserved;
	unsigned int systembits_inalloc;
	unsigned int total_allocated;
	unsigned int online_maps;
	struct cpumap __attribute__((btf_type_tag("percpu"))) *maps;
	unsigned long *system_map;
	unsigned long scratch_map[0];
};

struct io_tlb_area {
	unsigned long used;
	unsigned int index;
	spinlock_t lock;
};

struct io_tlb_slot {
	phys_addr_t orig_addr;
	size_t alloc_size;
	unsigned short list;
	unsigned short pad_slots;
};

struct perf_cpu_context {
	struct perf_event_context ctx;
	struct perf_event_context *task_ctx;
	int online;
	int heap_size;
	struct perf_event **heap;
	struct perf_event *heap_default[2];
};

struct swevent_hlist;

struct swevent_htable {
	struct swevent_hlist *swevent_hlist;
	struct mutex hlist_mutex;
	int hlist_refcount;
	int recursion[4];
};

struct swevent_hlist {
	struct hlist_head heads[256];
	struct callback_head callback_head;
};

struct min_heap_callbacks {
	int elem_size;
	bool (*less)(const void *, const void *);
	void (*swp)(void *, void *);
};

struct pmu_event_list {
	raw_spinlock_t lock;
	struct list_head list;
};

enum perf_addr_filter_action_t {
	PERF_ADDR_FILTER_ACTION_STOP = 0,
	PERF_ADDR_FILTER_ACTION_START = 1,
	PERF_ADDR_FILTER_ACTION_FILTER = 2,
};

enum event_type_t {
	EVENT_FLEXIBLE = 1,
	EVENT_PINNED = 2,
	EVENT_TIME = 4,
	EVENT_CPU = 8,
	EVENT_CGROUP = 16,
	EVENT_ALL = 3,
};

enum tick_dep_bits {
	TICK_DEP_BIT_POSIX_TIMER = 0,
	TICK_DEP_BIT_PERF_EVENTS = 1,
	TICK_DEP_BIT_SCHED = 2,
	TICK_DEP_BIT_CLOCK_UNSTABLE = 3,
	TICK_DEP_BIT_RCU = 4,
	TICK_DEP_BIT_RCU_EXP = 5,
};

enum perf_event_type {
	PERF_RECORD_MMAP = 1,
	PERF_RECORD_LOST = 2,
	PERF_RECORD_COMM = 3,
	PERF_RECORD_EXIT = 4,
	PERF_RECORD_THROTTLE = 5,
	PERF_RECORD_UNTHROTTLE = 6,
	PERF_RECORD_FORK = 7,
	PERF_RECORD_READ = 8,
	PERF_RECORD_SAMPLE = 9,
	PERF_RECORD_MMAP2 = 10,
	PERF_RECORD_AUX = 11,
	PERF_RECORD_ITRACE_START = 12,
	PERF_RECORD_LOST_SAMPLES = 13,
	PERF_RECORD_SWITCH = 14,
	PERF_RECORD_SWITCH_CPU_WIDE = 15,
	PERF_RECORD_NAMESPACES = 16,
	PERF_RECORD_KSYMBOL = 17,
	PERF_RECORD_BPF_EVENT = 18,
	PERF_RECORD_CGROUP = 19,
	PERF_RECORD_TEXT_POKE = 20,
	PERF_RECORD_AUX_OUTPUT_HW_ID = 21,
	PERF_RECORD_MAX = 22,
};

enum {
	NET_NS_INDEX = 0,
	UTS_NS_INDEX = 1,
	IPC_NS_INDEX = 2,
	PID_NS_INDEX = 3,
	USER_NS_INDEX = 4,
	MNT_NS_INDEX = 5,
	CGROUP_NS_INDEX = 6,
	NR_NAMESPACES = 7,
};

enum perf_record_ksymbol_type {
	PERF_RECORD_KSYMBOL_TYPE_UNKNOWN = 0,
	PERF_RECORD_KSYMBOL_TYPE_BPF = 1,
	PERF_RECORD_KSYMBOL_TYPE_OOL = 2,
	PERF_RECORD_KSYMBOL_TYPE_MAX = 3,
};

enum perf_bpf_event_type {
	PERF_BPF_EVENT_UNKNOWN = 0,
	PERF_BPF_EVENT_PROG_LOAD = 1,
	PERF_BPF_EVENT_PROG_UNLOAD = 2,
	PERF_BPF_EVENT_MAX = 3,
};

enum perf_event_task_context {
	perf_invalid_context = -1,
	perf_hw_context = 0,
	perf_sw_context = 1,
	perf_nr_task_contexts = 2,
};

enum perf_event_read_format {
	PERF_FORMAT_TOTAL_TIME_ENABLED = 1,
	PERF_FORMAT_TOTAL_TIME_RUNNING = 2,
	PERF_FORMAT_ID = 4,
	PERF_FORMAT_GROUP = 8,
	PERF_FORMAT_LOST = 16,
	PERF_FORMAT_MAX = 32,
};

enum tk_offsets {
	TK_OFFS_REAL = 0,
	TK_OFFS_BOOT = 1,
	TK_OFFS_TAI = 2,
	TK_OFFS_MAX = 3,
};

enum perf_event_ioc_flags {
	PERF_IOC_FLAG_GROUP = 1,
};

enum {
	IF_STATE_ACTION = 0,
	IF_STATE_SOURCE = 1,
	IF_STATE_END = 2,
};

enum {
	IF_ACT_NONE = -1,
	IF_ACT_FILTER = 0,
	IF_ACT_START = 1,
	IF_ACT_STOP = 2,
	IF_SRC_FILE = 3,
	IF_SRC_KERNEL = 4,
	IF_SRC_FILEADDR = 5,
	IF_SRC_KERNELADDR = 6,
};

enum perf_sw_ids {
	PERF_COUNT_SW_CPU_CLOCK = 0,
	PERF_COUNT_SW_TASK_CLOCK = 1,
	PERF_COUNT_SW_PAGE_FAULTS = 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
	PERF_COUNT_SW_CPU_MIGRATIONS = 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
	PERF_COUNT_SW_EMULATION_FAULTS = 8,
	PERF_COUNT_SW_DUMMY = 9,
	PERF_COUNT_SW_BPF_OUTPUT = 10,
	PERF_COUNT_SW_CGROUP_SWITCHES = 11,
	PERF_COUNT_SW_MAX = 12,
};

struct perf_addr_filter {
	struct list_head entry;
	struct path path;
	unsigned long offset;
	unsigned long size;
	enum perf_addr_filter_action_t action;
};

typedef void (*event_f)(struct perf_event *, struct perf_cpu_context *, struct perf_event_context *, void *);

struct perf_event_header {
	__u32 type;
	__u16 misc;
	__u16 size;
};

struct perf_switch_event {
	struct task_struct *task;
	struct task_struct *next_prev;
	struct {
		struct perf_event_header header;
		u32 next_prev_pid;
		u32 next_prev_tid;
	} event_id;
};

typedef void perf_iterate_f(struct perf_event *, void *);

struct perf_ns_link_info {
	__u64 dev;
	__u64 ino;
};

struct perf_comm_event {
	struct task_struct *task;
	char *comm;
	int comm_size;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 tid;
	} event_id;
};

struct perf_mmap_event {
	struct vm_area_struct *vma;
	const char *file_name;
	int file_size;
	int maj;
	int min;
	u64 ino;
	u64 ino_generation;
	u32 prot;
	u32 flags;
	u8 build_id[20];
	u32 build_id_size;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 tid;
		u64 start;
		u64 len;
		u64 pgoff;
	} event_id;
};

struct perf_aux_event {
	struct perf_event_header header;
	u64 offset;
	u64 size;
	u64 flags;
};

struct perf_aux_event___2 {
	struct perf_event_header header;
	u64 hw_id;
};

typedef int (*remote_function_f)(void *);

struct remote_function_call {
	struct task_struct *p;
	remote_function_f func;
	void *info;
	int ret;
};

struct min_heap {
	void *data;
	int nr;
	int size;
};

struct __group_key {
	int cpu;
	struct pmu *pmu;
	struct cgroup *cgroup;
};

struct perf_aux_event___3 {
	struct perf_event_header header;
	u32 pid;
	u32 tid;
};

struct perf_read_event {
	struct perf_event_header header;
	u32 pid;
	u32 tid;
};

struct perf_task_event {
	struct task_struct *task;
	struct perf_event_context *task_ctx;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 ppid;
		u32 tid;
		u32 ptid;
		u64 time;
	} event_id;
};

struct perf_namespaces_event {
	struct task_struct *task;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 tid;
		u64 nr_namespaces;
		struct perf_ns_link_info link_info[7];
	} event_id;
};

struct perf_ksymbol_event {
	const char *name;
	int name_len;
	struct {
		struct perf_event_header header;
		u64 addr;
		u32 len;
		u16 ksym_type;
		u16 flags;
	} event_id;
};

struct perf_bpf_event {
	struct bpf_prog *prog;
	struct {
		struct perf_event_header header;
		u16 type;
		u16 flags;
		u32 id;
		u8 tag[8];
	} event_id;
};

struct perf_text_poke_event {
	const void *old_bytes;
	const void *new_bytes;
	size_t pad;
	u16 old_len;
	u16 new_len;
	struct {
		struct perf_event_header header;
		u64 addr;
	} event_id;
};

struct event_function_struct {
	struct perf_event *event;
	event_f func;
	void *data;
};

struct stop_event_data {
	struct perf_event *event;
	unsigned int restart;
};

struct perf_read_data {
	struct perf_event *event;
	bool group;
	int ret;
};

struct remote_output {
	struct perf_buffer *rb;
	int err;
};

enum fsconfig_command {
	FSCONFIG_SET_FLAG = 0,
	FSCONFIG_SET_STRING = 1,
	FSCONFIG_SET_BINARY = 2,
	FSCONFIG_SET_PATH = 3,
	FSCONFIG_SET_PATH_EMPTY = 4,
	FSCONFIG_SET_FD = 5,
	FSCONFIG_CMD_CREATE = 6,
	FSCONFIG_CMD_RECONFIGURE = 7,
	FSCONFIG_CMD_CREATE_EXCL = 8,
};

typedef long (*sys_call_ptr_t)(const struct pt_regs *);

struct estack_pages {
	u32 offs;
	u16 size;
	u16 type;
};

enum tsx_ctrl_states {
	TSX_CTRL_ENABLE = 0,
	TSX_CTRL_DISABLE = 1,
	TSX_CTRL_RTM_ALWAYS_ABORT = 2,
	TSX_CTRL_NOT_SUPPORTED = 3,
};

struct sched_param {
	int sched_priority;
};

enum KTHREAD_BITS {
	KTHREAD_IS_PER_CPU = 0,
	KTHREAD_SHOULD_STOP = 1,
	KTHREAD_SHOULD_PARK = 2,
};

enum {
	KTW_FREEZABLE = 1,
};

struct kthread_create_info {
	char *full_name;
	int (*threadfn)(void *);
	void *data;
	int node;
	struct task_struct *result;
	struct completion *done;
	struct list_head list;
};

struct kthread_work;

typedef void (*kthread_work_func_t)(struct kthread_work *);

struct kthread_worker;

struct kthread_work {
	struct list_head node;
	kthread_work_func_t func;
	struct kthread_worker *worker;
	int canceling;
};

struct kthread_worker {
	unsigned int flags;
	raw_spinlock_t lock;
	struct list_head work_list;
	struct list_head delayed_work_list;
	struct task_struct *task;
	struct kthread_work *current_work;
};

struct kthread_delayed_work {
	struct kthread_work work;
	struct timer_list timer;
};

struct kthread_flush_work {
	struct kthread_work work;
	struct completion done;
};

struct kthread {
	unsigned long flags;
	unsigned int cpu;
	int result;
	int (*threadfn)(void *);
	void *data;
	struct completion parked;
	struct completion exited;
	char *full_name;
};

struct swait_queue {
	struct task_struct *task;
	struct list_head task_list;
};

struct mmap_unlock_irq_work {
	struct irq_work irq_work;
	struct mm_struct *mm;
};

enum {
	BPF_TASK_ITER_ALL_PROCS = 0,
	BPF_TASK_ITER_ALL_THREADS = 1,
	BPF_TASK_ITER_PROC_THREADS = 2,
};

enum {
	BTF_TRACING_TYPE_TASK = 0,
	BTF_TRACING_TYPE_FILE = 1,
	BTF_TRACING_TYPE_VMA = 2,
	MAX_BTF_TRACING_TYPE = 3,
};

enum bpf_task_vma_iter_find_op {
	task_vma_iter_first_vma = 0,
	task_vma_iter_next_vma = 1,
	task_vma_iter_find_vma = 2,
};

typedef u64 (*btf_bpf_find_vma)(struct task_struct *, u64, bpf_callback_t, void *, u64);

struct bpf_iter_seq_task_common {
	struct pid_namespace *ns;
	enum bpf_iter_task_type type;
	u32 pid;
	u32 pid_visiting;
};

struct bpf_iter_task_vma {
	__u64 __opaque[1];
};

struct bpf_iter_task_vma_kern_data;

struct bpf_iter_task_vma_kern {
	struct bpf_iter_task_vma_kern_data *data;
};

struct bpf_iter_task_vma_kern_data {
	struct task_struct *task;
	struct mm_struct *mm;
	struct mmap_unlock_irq_work *work;
	struct vma_iterator vmi;
};

struct bpf_iter_task {
	__u64 __opaque[3];
};

struct bpf_iter_task_kern {
	struct task_struct *task;
	struct task_struct *pos;
	unsigned int flags;
};

struct bpf_iter_seq_task_info {
	struct bpf_iter_seq_task_common common;
	u32 tid;
};

struct bpf_iter__task {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct task_struct *task;
	};
};

struct bpf_iter_seq_task_file_info {
	struct bpf_iter_seq_task_common common;
	struct task_struct *task;
	u32 tid;
	u32 fd;
};

struct bpf_iter__task_file {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct task_struct *task;
	};
	u32 fd;
	union {
		struct file *file;
	};
};

struct bpf_iter_seq_task_vma_info {
	struct bpf_iter_seq_task_common common;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	u32 tid;
	unsigned long prev_vm_start;
	unsigned long prev_vm_end;
};

struct bpf_iter__task_vma {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct task_struct *task;
	};
	union {
		struct vm_area_struct *vma;
	};
};

enum migratetype {
	MIGRATE_UNMOVABLE = 0,
	MIGRATE_MOVABLE = 1,
	MIGRATE_RECLAIMABLE = 2,
	MIGRATE_PCPTYPES = 3,
	MIGRATE_HIGHATOMIC = 3,
	MIGRATE_TYPES = 4,
};

enum zone_watermarks {
	WMARK_MIN = 0,
	WMARK_LOW = 1,
	WMARK_HIGH = 2,
	WMARK_PROMO = 3,
	NR_WMARK = 4,
};

enum pageblock_bits {
	PB_migrate = 0,
	PB_migrate_end = 2,
	PB_migrate_skip = 3,
	NR_PAGEBLOCK_BITS = 4,
};

enum zone_flags {
	ZONE_BOOSTED_WATERMARK = 0,
	ZONE_RECLAIM_ACTIVE = 1,
	ZONE_BELOW_HIGH = 2,
};

enum {
	ZONELIST_FALLBACK = 0,
	MAX_ZONELISTS = 1,
};

enum compact_priority {
	COMPACT_PRIO_SYNC_FULL = 0,
	MIN_COMPACT_PRIORITY = 0,
	COMPACT_PRIO_SYNC_LIGHT = 1,
	MIN_COMPACT_COSTLY_PRIORITY = 1,
	DEF_COMPACT_PRIORITY = 1,
	COMPACT_PRIO_ASYNC = 2,
	INIT_COMPACT_PRIORITY = 2,
};

enum compact_result {
	COMPACT_NOT_SUITABLE_ZONE = 0,
	COMPACT_SKIPPED = 1,
	COMPACT_DEFERRED = 2,
	COMPACT_NO_SUITABLE_PAGE = 3,
	COMPACT_CONTINUE = 4,
	COMPACT_COMPLETE = 5,
	COMPACT_PARTIAL_SKIPPED = 6,
	COMPACT_CONTENDED = 7,
	COMPACT_SUCCESS = 8,
};

enum oom_constraint {
	CONSTRAINT_NONE = 0,
	CONSTRAINT_CPUSET = 1,
	CONSTRAINT_MEMORY_POLICY = 2,
	CONSTRAINT_MEMCG = 3,
};

typedef int fpi_t;

struct capture_control;

struct alloc_context {
	struct zonelist *zonelist;
	nodemask_t *nodemask;
	struct zoneref *preferred_zoneref;
	int migratetype;
	enum zone_type highest_zoneidx;
	bool spread_dirty_pages;
};

struct oom_control {
	struct zonelist *zonelist;
	nodemask_t *nodemask;
	struct mem_cgroup *memcg;
	const gfp_t gfp_mask;
	const int order;
	unsigned long totalpages;
	struct task_struct *chosen;
	long chosen_points;
	enum oom_constraint constraint;
};

struct va_format {
	const char *fmt;
	va_list *va;
};

struct page_frag_cache {
	void *va;
	__u16 offset;
	__u16 size;
	unsigned int pagecnt_bias;
	bool pfmemalloc;
};

struct vfs_cap_data {
	__le32 magic_etc;
	struct {
		__le32 permitted;
		__le32 inheritable;
	} data[2];
};

struct vfs_ns_cap_data {
	__le32 magic_etc;
	struct {
		__le32 permitted;
		__le32 inheritable;
	} data[2];
	__le32 rootid;
};

struct cpu_vfs_cap_data {
	__u32 magic_etc;
	kuid_t rootid;
	kernel_cap_t permitted;
	kernel_cap_t inheritable;
};

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

typedef void (*exitcall_t)();

enum kobject_action {
	KOBJ_ADD = 0,
	KOBJ_REMOVE = 1,
	KOBJ_CHANGE = 2,
	KOBJ_MOVE = 3,
	KOBJ_ONLINE = 4,
	KOBJ_OFFLINE = 5,
	KOBJ_BIND = 6,
	KOBJ_UNBIND = 7,
};

enum xa_lock_type {
	XA_LOCK_IRQ = 1,
	XA_LOCK_BH = 2,
};

struct software_node;

struct swnode {
	struct kobject kobj;
	struct fwnode_handle fwnode;
	const struct software_node *node;
	int id;
	struct ida child_ids;
	struct list_head entry;
	struct list_head children;
	struct swnode *parent;
	unsigned int allocated: 1;
	unsigned int managed: 1;
};

struct software_node {
	const char *name;
	const struct software_node *parent;
	const struct property_entry *properties;
};

typedef unsigned int xa_mark_t;

struct software_node_ref_args {
	const struct software_node *node;
	unsigned int nargs;
	u64 args[8];
};

struct vdso_exception_table_entry {
	int insn;
	int fixup;
};

struct cpuid_bit {
	u16 feature;
	u8 reg;
	u8 bit;
	u32 level;
	u32 sub_leaf;
};

struct x86_topology_system {
	unsigned int dom_shifts[7];
	unsigned int dom_size[7];
};

struct pcpu_hot {
	union {
		struct {
			struct task_struct *current_task;
			int preempt_count;
			int cpu_number;
			unsigned long top_of_stack;
			void *hardirq_stack_ptr;
			u16 softirq_pending;
			bool hardirq_stack_inuse;
		};
		u8 pad[64];
	};
};

struct fixed_percpu_data {
	char gs_base[40];
	unsigned long stack_canary;
};

struct cpuid_dependent_feature {
	u32 feature;
	u32 level;
};

struct ppin_info {
	int feature;
	int msr_ppin_ctl;
	int msr_ppin;
};

enum {
	DESC_TSS = 9,
	DESC_LDT = 2,
	DESCTYPE_S = 16,
};

struct desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed));

struct ldttss_desc {
	u16 limit0;
	u16 base0;
	u16 base1: 8;
	u16 type: 5;
	u16 dpl: 2;
	u16 p: 1;
	u16 limit1: 4;
	u16 zero0: 3;
	u16 g: 1;
	u16 base2: 8;
	u32 base3;
	u32 zero1;
};

typedef struct ldttss_desc tss_desc;

typedef struct ldttss_desc ldt_desc;

enum ucount_type {
	UCOUNT_USER_NAMESPACES = 0,
	UCOUNT_PID_NAMESPACES = 1,
	UCOUNT_UTS_NAMESPACES = 2,
	UCOUNT_IPC_NAMESPACES = 3,
	UCOUNT_NET_NAMESPACES = 4,
	UCOUNT_MNT_NAMESPACES = 5,
	UCOUNT_CGROUP_NAMESPACES = 6,
	UCOUNT_TIME_NAMESPACES = 7,
	UCOUNT_COUNTS = 8,
};

struct irq_devres {
	unsigned int irq;
	void *dev_id;
};

struct irq_desc_devres {
	unsigned int from;
	unsigned int cnt;
};

enum {
	BPF_F_SKIP_FIELD_MASK = 255,
	BPF_F_USER_STACK = 256,
	BPF_F_FAST_STACK_CMP = 512,
	BPF_F_REUSE_STACKID = 1024,
	BPF_F_USER_BUILD_ID = 2048,
};

enum bpf_stack_build_id_status {
	BPF_STACK_BUILD_ID_EMPTY = 0,
	BPF_STACK_BUILD_ID_VALID = 1,
	BPF_STACK_BUILD_ID_IP = 2,
};

typedef u64 (*btf_bpf_get_stackid)(struct pt_regs *, struct bpf_map *, u64);

struct bpf_perf_event_data_kern;

typedef u64 (*btf_bpf_get_stackid_pe)(struct bpf_perf_event_data_kern *, struct bpf_map *, u64);

typedef struct pt_regs bpf_user_pt_regs_t;

struct bpf_perf_event_data_kern {
	bpf_user_pt_regs_t *regs;
	struct perf_sample_data *data;
	struct perf_event *event;
};

typedef u64 (*btf_bpf_get_stack)(struct pt_regs *, void *, u32, u64);

typedef u64 (*btf_bpf_get_task_stack)(struct task_struct *, void *, u32, u64);

typedef u64 (*btf_bpf_get_stack_pe)(struct bpf_perf_event_data_kern *, void *, u32, u64);

struct stack_map_bucket;

struct bpf_stack_map {
	struct bpf_map map;
	void *elems;
	struct pcpu_freelist freelist;
	u32 n_buckets;
	struct stack_map_bucket *buckets[0];
};

struct stack_map_bucket {
	struct pcpu_freelist_node fnode;
	u32 hash;
	u32 nr;
	u64 data[0];
};

struct bpf_stack_build_id {
	__s32 status;
	unsigned char build_id[20];
	union {
		__u64 offset;
		__u64 ip;
	};
};

struct mlock_fbatch {
	local_lock_t lock;
	struct folio_batch fbatch;
};

enum wb_state {
	WB_registered = 0,
	WB_writeback_running = 1,
	WB_has_dirty_io = 2,
	WB_start_all = 3,
};

struct wb_completion;

struct wb_writeback_work {
	long nr_pages;
	struct super_block *sb;
	enum writeback_sync_modes sync_mode;
	unsigned int tagged_writepages: 1;
	unsigned int for_kupdate: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_background: 1;
	unsigned int for_sync: 1;
	unsigned int auto_free: 1;
	enum wb_reason reason;
	struct list_head list;
	struct wb_completion *done;
};

struct wb_completion {
	atomic_t cnt;
	wait_queue_head_t *waitq;
};

typedef int wait_bit_action_f(struct wait_bit_key *, int);

struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};

struct syscall_info {
	__u64 sp;
	struct seccomp_data data;
};

enum maple_type {
	maple_dense = 0,
	maple_leaf_64 = 1,
	maple_range_64 = 2,
	maple_arange_64 = 3,
};

struct maple_pnode;

struct maple_metadata {
	unsigned char end;
	unsigned char gap;
};

struct maple_range_64 {
	struct maple_pnode *parent;
	unsigned long pivot[15];
	union {
		void __attribute__((btf_type_tag("rcu"))) *slot[16];
		struct {
			void __attribute__((btf_type_tag("rcu"))) *pad[15];
			struct maple_metadata meta;
		};
	};
};

struct maple_arange_64 {
	struct maple_pnode *parent;
	unsigned long pivot[9];
	void __attribute__((btf_type_tag("rcu"))) *slot[10];
	unsigned long gap[10];
	struct maple_metadata meta;
};

struct maple_node {
	union {
		struct {
			struct maple_pnode *parent;
			void __attribute__((btf_type_tag("rcu"))) *slot[31];
		};
		struct {
			void *pad;
			struct callback_head rcu;
			struct maple_enode *piv_parent;
			unsigned char parent_slot;
			enum maple_type type;
			unsigned char slot_len;
			unsigned int ma_flags;
		};
		struct maple_range_64 mr64;
		struct maple_arange_64 ma64;
		struct maple_alloc alloc;
	};
};

struct maple_topiary {
	struct maple_pnode *parent;
	struct maple_enode *next;
};

struct ma_wr_state {
	struct ma_state *mas;
	struct maple_node *node;
	unsigned long r_min;
	unsigned long r_max;
	enum maple_type type;
	unsigned char offset_end;
	unsigned long *pivots;
	unsigned long end_piv;
	void __attribute__((btf_type_tag("rcu"))) **slots;
	void *entry;
	void *content;
};

struct maple_big_node {
	struct maple_pnode *parent;
	unsigned long pivot[33];
	union {
		struct maple_enode *slot[34];
		struct {
			unsigned long padding[21];
			unsigned long gap[21];
		};
	};
	unsigned char b_end;
	enum maple_type type;
};

struct ma_topiary;

struct maple_subtree_state {
	struct ma_state *orig_l;
	struct ma_state *orig_r;
	struct ma_state *l;
	struct ma_state *m;
	struct ma_state *r;
	struct ma_topiary *free;
	struct ma_topiary *destroy;
	struct maple_big_node *bn;
};

struct ma_topiary {
	struct maple_enode *head;
	struct maple_enode *tail;
	struct maple_tree *mtree;
};

struct sigaltstack {
	void __attribute__((btf_type_tag("user"))) *ss_sp;
	int ss_flags;
	__kernel_size_t ss_size;
};

typedef struct sigaltstack stack_t;

struct sigcontext_64 {
	__u64 r8;
	__u64 r9;
	__u64 r10;
	__u64 r11;
	__u64 r12;
	__u64 r13;
	__u64 r14;
	__u64 r15;
	__u64 di;
	__u64 si;
	__u64 bp;
	__u64 bx;
	__u64 dx;
	__u64 ax;
	__u64 cx;
	__u64 sp;
	__u64 ip;
	__u64 flags;
	__u16 cs;
	__u16 gs;
	__u16 fs;
	__u16 ss;
	__u64 err;
	__u64 trapno;
	__u64 oldmask;
	__u64 cr2;
	__u64 fpstate;
	__u64 reserved1[8];
};

struct ucontext {
	unsigned long uc_flags;
	struct ucontext *uc_link;
	stack_t uc_stack;
	struct sigcontext_64 uc_mcontext;
	sigset_t uc_sigmask;
};

struct siginfo {
	union {
		struct {
			int si_signo;
			int si_errno;
			int si_code;
			union __sifields _sifields;
		};
		int _si_pad[32];
	};
};

struct rt_sigframe {
	char __attribute__((btf_type_tag("user"))) *pretcode;
	struct ucontext uc;
	struct siginfo info;
};

typedef struct siginfo siginfo_t;

struct _cache_table {
	unsigned char descriptor;
	char cache_type;
	short size;
};

enum _cache_type {
	CTYPE_NULL = 0,
	CTYPE_DATA = 1,
	CTYPE_INST = 2,
	CTYPE_UNIFIED = 3,
};

union _cpuid4_leaf_eax {
	struct {
		enum _cache_type type: 5;
		unsigned int level: 3;
		unsigned int is_self_initializing: 1;
		unsigned int is_fully_associative: 1;
		unsigned int reserved: 4;
		unsigned int num_threads_sharing: 12;
		unsigned int num_cores_on_die: 6;
	} split;
	u32 full;
};

union _cpuid4_leaf_ebx {
	struct {
		unsigned int coherency_line_size: 12;
		unsigned int physical_line_partition: 10;
		unsigned int ways_of_associativity: 10;
	} split;
	u32 full;
};

union _cpuid4_leaf_ecx {
	struct {
		unsigned int number_of_sets: 32;
	} split;
	u32 full;
};

union l1_cache {
	struct {
		unsigned int line_size: 8;
		unsigned int lines_per_tag: 8;
		unsigned int assoc: 8;
		unsigned int size_in_kb: 8;
	};
	unsigned int val;
};

union l2_cache {
	struct {
		unsigned int line_size: 8;
		unsigned int lines_per_tag: 4;
		unsigned int assoc: 4;
		unsigned int size_in_kb: 16;
	};
	unsigned int val;
};

union l3_cache {
	struct {
		unsigned int line_size: 8;
		unsigned int lines_per_tag: 4;
		unsigned int assoc: 4;
		unsigned int res: 2;
		unsigned int size_encoded: 14;
	};
	unsigned int val;
};

struct amd_northbridge;

struct _cpuid4_info_regs {
	union _cpuid4_leaf_eax eax;
	union _cpuid4_leaf_ebx ebx;
	union _cpuid4_leaf_ecx ecx;
	unsigned int id;
	unsigned long size;
	struct amd_northbridge *nb;
};

struct amd_l3_cache {
	unsigned int indices;
	u8 subcaches[4];
};

struct pci_dev;

struct threshold_bank;

struct amd_northbridge {
	struct pci_dev *root;
	struct pci_dev *misc;
	struct pci_dev *link;
	struct amd_l3_cache l3_cache;
	struct threshold_bank *bank4;
};

typedef int pci_power_t;

typedef unsigned int pci_channel_state_t;

typedef unsigned short pci_dev_flags_t;

struct pci_vpd {
	struct mutex lock;
	unsigned int len;
	u8 cap;
};

struct pci_bus;

struct pci_slot;

struct pci_driver;

struct pci_dev {
	struct list_head bus_list;
	struct pci_bus *bus;
	struct pci_bus *subordinate;
	void *sysdata;
	struct proc_dir_entry *procent;
	struct pci_slot *slot;
	unsigned int devfn;
	unsigned short vendor;
	unsigned short device;
	unsigned short subsystem_vendor;
	unsigned short subsystem_device;
	unsigned int class;
	u8 revision;
	u8 hdr_type;
	u32 devcap;
	u8 pcie_cap;
	u8 msi_cap;
	u8 msix_cap;
	u8 pcie_mpss: 3;
	u8 rom_base_reg;
	u8 pin;
	u16 pcie_flags_reg;
	unsigned long *dma_alias_mask;
	struct pci_driver *driver;
	u64 dma_mask;
	struct device_dma_parameters dma_parms;
	pci_power_t current_state;
	u8 pm_cap;
	unsigned int imm_ready: 1;
	unsigned int pme_support: 5;
	unsigned int pme_poll: 1;
	unsigned int d1_support: 1;
	unsigned int d2_support: 1;
	unsigned int no_d1d2: 1;
	unsigned int no_d3cold: 1;
	unsigned int bridge_d3: 1;
	unsigned int d3cold_allowed: 1;
	unsigned int mmio_always_on: 1;
	unsigned int wakeup_prepared: 1;
	unsigned int skip_bus_pm: 1;
	unsigned int ignore_hotplug: 1;
	unsigned int hotplug_user_indicators: 1;
	unsigned int clear_retrain_link: 1;
	unsigned int d3hot_delay;
	unsigned int d3cold_delay;
	u16 l1ss;
	unsigned int pasid_no_tlp: 1;
	unsigned int eetlp_prefix_path: 1;
	pci_channel_state_t error_state;
	struct device dev;
	int cfg_size;
	unsigned int irq;
	struct resource resource[11];
	struct resource driver_exclusive_resource;
	bool match_driver;
	unsigned int transparent: 1;
	unsigned int io_window: 1;
	unsigned int pref_window: 1;
	unsigned int pref_64_window: 1;
	unsigned int multifunction: 1;
	unsigned int is_busmaster: 1;
	unsigned int no_msi: 1;
	unsigned int no_64bit_msi: 1;
	unsigned int block_cfg_access: 1;
	unsigned int broken_parity_status: 1;
	unsigned int irq_reroute_variant: 2;
	unsigned int msi_enabled: 1;
	unsigned int msix_enabled: 1;
	unsigned int ari_enabled: 1;
	unsigned int ats_enabled: 1;
	unsigned int pasid_enabled: 1;
	unsigned int pri_enabled: 1;
	unsigned int is_managed: 1;
	unsigned int is_msi_managed: 1;
	unsigned int needs_freset: 1;
	unsigned int state_saved: 1;
	unsigned int is_physfn: 1;
	unsigned int is_virtfn: 1;
	unsigned int is_hotplug_bridge: 1;
	unsigned int shpc_managed: 1;
	unsigned int is_thunderbolt: 1;
	unsigned int untrusted: 1;
	unsigned int external_facing: 1;
	unsigned int broken_intx_masking: 1;
	unsigned int io_window_1k: 1;
	unsigned int irq_managed: 1;
	unsigned int non_compliant_bars: 1;
	unsigned int is_probed: 1;
	unsigned int link_active_reporting: 1;
	unsigned int no_vf_scan: 1;
	unsigned int no_command_memory: 1;
	unsigned int rom_bar_overlap: 1;
	unsigned int rom_attr_enabled: 1;
	pci_dev_flags_t dev_flags;
	atomic_t enable_cnt;
	spinlock_t pcie_cap_lock;
	u32 saved_config_space[16];
	struct hlist_head saved_cap_space;
	struct bin_attribute *res_attr[11];
	struct bin_attribute *res_attr_wc[11];
	struct pci_vpd vpd;
	u16 acs_cap;
	phys_addr_t rom;
	size_t romlen;
	const char *driver_override;
	unsigned long priv_flags;
	u8 reset_methods[7];
};

typedef unsigned short pci_bus_flags_t;

struct pci_ops;

struct pci_bus {
	struct list_head node;
	struct pci_bus *parent;
	struct list_head children;
	struct list_head devices;
	struct pci_dev *self;
	struct list_head slots;
	struct resource *resource[4];
	struct list_head resources;
	struct resource busn_res;
	struct pci_ops *ops;
	void *sysdata;
	struct proc_dir_entry *procdir;
	unsigned char number;
	unsigned char primary;
	unsigned char max_bus_speed;
	unsigned char cur_bus_speed;
	char name[48];
	unsigned short bridge_ctl;
	pci_bus_flags_t bus_flags;
	struct device *bridge;
	struct device dev;
	struct bin_attribute *legacy_io;
	struct bin_attribute *legacy_mem;
	unsigned int is_added: 1;
	unsigned int unsafe_warn: 1;
};

struct pci_ops {
	int (*add_bus)(struct pci_bus *);
	void (*remove_bus)(struct pci_bus *);
	void * (*map_bus)(struct pci_bus *, unsigned int, int);
	int (*read)(struct pci_bus *, unsigned int, int, int, u32 *);
	int (*write)(struct pci_bus *, unsigned int, int, int, u32);
};

struct hotplug_slot;

struct pci_slot {
	struct pci_bus *bus;
	struct list_head list;
	struct hotplug_slot *hotplug;
	unsigned char number;
	struct kobject kobj;
};

struct pci_dynids {
	spinlock_t lock;
	struct list_head list;
};

struct pci_device_id;

struct pci_error_handlers;

struct pci_driver {
	const char *name;
	const struct pci_device_id *id_table;
	int (*probe)(struct pci_dev *, const struct pci_device_id *);
	void (*remove)(struct pci_dev *);
	int (*suspend)(struct pci_dev *, pm_message_t);
	int (*resume)(struct pci_dev *);
	void (*shutdown)(struct pci_dev *);
	int (*sriov_configure)(struct pci_dev *, int);
	int (*sriov_set_msix_vec_count)(struct pci_dev *, int);
	u32 (*sriov_get_vf_total_msix)(struct pci_dev *);
	const struct pci_error_handlers *err_handler;
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	struct device_driver driver;
	struct pci_dynids dynids;
	bool driver_managed_dma;
};

struct pci_device_id {
	__u32 vendor;
	__u32 device;
	__u32 subvendor;
	__u32 subdevice;
	__u32 class;
	__u32 class_mask;
	kernel_ulong_t driver_data;
	__u32 override_only;
};

typedef unsigned int pci_ers_result_t;

struct pci_error_handlers {
	pci_ers_result_t (*error_detected)(struct pci_dev *, pci_channel_state_t);
	pci_ers_result_t (*mmio_enabled)(struct pci_dev *);
	pci_ers_result_t (*slot_reset)(struct pci_dev *);
	void (*reset_prepare)(struct pci_dev *);
	void (*reset_done)(struct pci_dev *);
	void (*resume)(struct pci_dev *);
	void (*cor_error_detected)(struct pci_dev *);
};

struct threshold_block;

struct threshold_bank {
	struct kobject *kobj;
	struct threshold_block *blocks;
	refcount_t cpus;
	unsigned int shared;
};

struct threshold_block {
	unsigned int block;
	unsigned int bank;
	unsigned int cpu;
	u32 address;
	u16 interrupt_enable;
	bool interrupt_capable;
	u16 threshold_limit;
	struct kobject kobj;
	struct list_head miscj;
};

enum sig_handler {
	HANDLER_CURRENT = 0,
	HANDLER_SIG_DFL = 1,
	HANDLER_EXIT = 2,
};

enum {
	TRACE_SIGNAL_DELIVERED = 0,
	TRACE_SIGNAL_IGNORED = 1,
	TRACE_SIGNAL_ALREADY_PENDING = 2,
	TRACE_SIGNAL_OVERFLOW_FAIL = 3,
	TRACE_SIGNAL_LOSE_INFO = 4,
};

enum siginfo_layout {
	SIL_KILL = 0,
	SIL_TIMER = 1,
	SIL_POLL = 2,
	SIL_FAULT = 3,
	SIL_FAULT_TRAPNO = 4,
	SIL_FAULT_MCEERR = 5,
	SIL_FAULT_BNDERR = 6,
	SIL_FAULT_PKUERR = 7,
	SIL_FAULT_PERF_EVENT = 8,
	SIL_CHLD = 9,
	SIL_RT = 10,
	SIL_SYS = 11,
};

struct sigqueue {
	struct list_head list;
	int flags;
	kernel_siginfo_t info;
	struct ucounts *ucounts;
};

struct multiprocess_signals {
	sigset_t signal;
	struct hlist_node node;
};

typedef unsigned long old_sigset_t;

struct bpf_iter_seq_prog_info {
	u32 prog_id;
};

struct bpf_iter__bpf_prog {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_prog *prog;
	};
};

enum {
	SWP_USED = 1,
	SWP_WRITEOK = 2,
	SWP_DISCARDABLE = 4,
	SWP_DISCARDING = 8,
	SWP_SOLIDSTATE = 16,
	SWP_CONTINUED = 32,
	SWP_BLKDEV = 64,
	SWP_ACTIVATED = 128,
	SWP_FS_OPS = 256,
	SWP_AREA_DISCARD = 512,
	SWP_PAGE_DISCARD = 1024,
	SWP_STABLE_WRITES = 2048,
	SWP_SYNCHRONOUS_IO = 4096,
	SWP_SCANNING = 16384,
};

typedef unsigned int zap_flags_t;

typedef int fpb_t;

typedef unsigned long pte_marker;

struct zap_details {
	struct folio *single_folio;
	bool even_cows;
	zap_flags_t zap_flags;
};

typedef struct {
	u64 val;
} pfn_t;

typedef int (*pte_fn_t)(pte_t *, unsigned long, void *);

typedef unsigned int pgtbl_mod_mask;

enum ramfs_param {
	Opt_mode = 0,
};

struct ramfs_mount_opts {
	umode_t mode;
};

struct ramfs_fs_info {
	struct ramfs_mount_opts mount_opts;
};

enum {
	Root_NFS = 255,
	Root_CIFS = 254,
	Root_Generic = 253,
	Root_RAM0 = 1048576,
};

enum idle_boot_override {
	IDLE_NO_OVERRIDE = 0,
	IDLE_HALT = 1,
	IDLE_NOMWAIT = 2,
	IDLE_POLL = 3,
};

enum tick_broadcast_mode {
	TICK_BROADCAST_OFF = 0,
	TICK_BROADCAST_ON = 1,
	TICK_BROADCAST_FORCE = 2,
};

struct inactive_task_frame {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bx;
	unsigned long bp;
	unsigned long ret_addr;
};

struct fork_frame {
	struct inactive_task_frame frame;
	struct pt_regs regs;
};

struct user_desc {
	unsigned int entry_number;
	unsigned int base_addr;
	unsigned int limit;
	unsigned int seg_32bit: 1;
	unsigned int contents: 2;
	unsigned int read_exec_only: 1;
	unsigned int limit_in_pages: 1;
	unsigned int seg_not_present: 1;
	unsigned int useable: 1;
	unsigned int lm: 1;
};

struct kernel_clone_args {
	u64 flags;
	int __attribute__((btf_type_tag("user"))) *pidfd;
	int __attribute__((btf_type_tag("user"))) *child_tid;
	int __attribute__((btf_type_tag("user"))) *parent_tid;
	const char *name;
	int exit_signal;
	u32 kthread: 1;
	u32 io_thread: 1;
	u32 user_worker: 1;
	u32 no_files: 1;
	unsigned long stack;
	unsigned long stack_size;
	unsigned long tls;
	pid_t *set_tid;
	size_t set_tid_size;
	int cgroup;
	int idle;
	int (*fn)(void *);
	void *fn_arg;
	struct cgroup *cgrp;
	struct css_set *cset;
};

struct wq_pod_type {
	int nr_pods;
	cpumask_var_t *pod_cpus;
	int *pod_node;
	int *cpu_pod;
};

enum wq_affn_scope {
	WQ_AFFN_DFL = 0,
	WQ_AFFN_CPU = 1,
	WQ_AFFN_SMT = 2,
	WQ_AFFN_CACHE = 3,
	WQ_AFFN_NUMA = 4,
	WQ_AFFN_SYSTEM = 5,
	WQ_AFFN_NR_TYPES = 6,
};

struct workqueue_attrs {
	int nice;
	cpumask_var_t cpumask;
	cpumask_var_t __pod_cpumask;
	bool affn_strict;
	enum wq_affn_scope affn_scope;
	bool ordered;
};

struct worker_pool {
	raw_spinlock_t lock;
	int cpu;
	int node;
	int id;
	unsigned int flags;
	unsigned long watchdog_ts;
	bool cpu_stall;
	int nr_running;
	struct list_head worklist;
	int nr_workers;
	int nr_idle;
	struct list_head idle_list;
	struct timer_list idle_timer;
	struct work_struct idle_cull_work;
	struct timer_list mayday_timer;
	struct hlist_head busy_hash[64];
	struct worker *manager;
	struct list_head workers;
	struct list_head dying_workers;
	struct completion *detach_completion;
	struct ida worker_ida;
	struct workqueue_attrs *attrs;
	struct hlist_node hash_node;
	int refcnt;
	struct callback_head rcu;
};

struct pool_workqueue {
	struct worker_pool *pool;
	struct workqueue_struct *wq;
	int work_color;
	int flush_color;
	int refcnt;
	int nr_in_flight[16];
	bool plugged;
	int nr_active;
	struct list_head inactive_works;
	struct list_head pending_node;
	struct list_head pwqs_node;
	struct list_head mayday_node;
	u64 stats[8];
	struct kthread_work release_work;
	struct callback_head rcu;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct wq_flusher;

struct wq_node_nr_active;

struct workqueue_struct {
	struct list_head pwqs;
	struct list_head list;
	struct mutex mutex;
	int work_color;
	int flush_color;
	atomic_t nr_pwqs_to_flush;
	struct wq_flusher *first_flusher;
	struct list_head flusher_queue;
	struct list_head flusher_overflow;
	struct list_head maydays;
	struct worker *rescuer;
	int nr_drainers;
	int max_active;
	int min_active;
	int saved_max_active;
	int saved_min_active;
	struct workqueue_attrs *unbound_attrs;
	struct pool_workqueue __attribute__((btf_type_tag("rcu"))) *dfl_pwq;
	char name[32];
	struct callback_head rcu;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	unsigned int flags;
	struct pool_workqueue __attribute__((btf_type_tag("percpu"))) __attribute__((btf_type_tag("rcu"))) **cpu_pwq;
	struct wq_node_nr_active *node_nr_active[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct wq_flusher {
	struct list_head list;
	int flush_color;
	struct completion done;
};

struct wq_node_nr_active {
	int max;
	atomic_t nr;
	raw_spinlock_t lock;
	struct list_head pending_pwqs;
};

enum worker_flags {
	WORKER_DIE = 2,
	WORKER_IDLE = 4,
	WORKER_PREP = 8,
	WORKER_CPU_INTENSIVE = 64,
	WORKER_UNBOUND = 128,
	WORKER_REBOUND = 256,
	WORKER_NOT_RUNNING = 456,
};

enum pool_workqueue_stats {
	PWQ_STAT_STARTED = 0,
	PWQ_STAT_COMPLETED = 1,
	PWQ_STAT_CPU_TIME = 2,
	PWQ_STAT_CPU_INTENSIVE = 3,
	PWQ_STAT_CM_WAKEUP = 4,
	PWQ_STAT_REPATRIATED = 5,
	PWQ_STAT_MAYDAY = 6,
	PWQ_STAT_RESCUED = 7,
	PWQ_NR_STATS = 8,
};

enum work_cancel_flags {
	WORK_CANCEL_DELAYED = 1,
};

enum wq_internal_consts {
	NR_STD_WORKER_POOLS = 2,
	UNBOUND_POOL_HASH_ORDER = 6,
	BUSY_WORKER_HASH_ORDER = 6,
	MAX_IDLE_WORKERS_RATIO = 4,
	IDLE_WORKER_TIMEOUT = 75000,
	MAYDAY_INITIAL_TIMEOUT = 2,
	MAYDAY_INTERVAL = 25,
	CREATE_COOLDOWN = 250,
	RESCUER_NICE_LEVEL = -20,
	HIGHPRI_NICE_LEVEL = -20,
	WQ_NAME_LEN = 32,
	WORKER_ID_LEN = 42,
};

enum worker_pool_flags {
	POOL_BH = 1,
	POOL_MANAGER_ACTIVE = 2,
	POOL_DISASSOCIATED = 4,
	POOL_BH_DRAINING = 8,
};

enum work_flags {
	WORK_STRUCT_PENDING = 1,
	WORK_STRUCT_INACTIVE = 2,
	WORK_STRUCT_PWQ = 4,
	WORK_STRUCT_LINKED = 8,
	WORK_STRUCT_STATIC = 0,
};

struct wq_drain_dead_softirq_work {
	struct work_struct work;
	struct worker_pool *pool;
	struct completion done;
};

struct wq_barrier {
	struct work_struct work;
	struct completion done;
	struct task_struct *task;
};

struct cwt_wait {
	wait_queue_entry_t wait;
	struct work_struct *work;
};

struct apply_wqattrs_ctx {
	struct workqueue_struct *wq;
	struct workqueue_attrs *attrs;
	struct list_head list;
	struct pool_workqueue *dfl_pwq;
	struct pool_workqueue *pwq_tbl[0];
};

struct pr_cont_work_struct {
	bool comma;
	work_func_t func;
	long ctr;
};

struct execute_work {
	struct work_struct work;
};

enum dentry_d_lock_class {
	DENTRY_D_LOCK_NORMAL = 0,
	DENTRY_D_LOCK_NESTED = 1,
};

enum d_walk_ret {
	D_WALK_CONTINUE = 0,
	D_WALK_QUIT = 1,
	D_WALK_NORETRY = 2,
	D_WALK_SKIP = 3,
};

struct external_name {
	union {
		atomic_t count;
		struct callback_head head;
	} u;
	unsigned char name[0];
};

struct check_mount {
	struct vfsmount *mnt;
	unsigned int mounted;
};

struct select_data {
	struct dentry *start;
	union {
		long found;
		struct dentry *victim;
	};
	struct list_head dispose;
};

typedef u32 compat_uptr_t;

typedef u32 compat_size_t;

struct compat_iovec {
	compat_uptr_t iov_base;
	compat_size_t iov_len;
};

typedef size_t (*iov_ustep_f)(void __attribute__((btf_type_tag("user"))) *, size_t, size_t, void *, void *);

typedef size_t (*iov_step_f)(void *, size_t, size_t, void *, void *);

typedef s32 compat_ssize_t;

struct iov_iter_state {
	size_t iov_offset;
	size_t count;
	unsigned long nr_segs;
};

enum {
	PERF_BR_UNKNOWN = 0,
	PERF_BR_COND = 1,
	PERF_BR_UNCOND = 2,
	PERF_BR_IND = 3,
	PERF_BR_CALL = 4,
	PERF_BR_IND_CALL = 5,
	PERF_BR_RET = 6,
	PERF_BR_SYSCALL = 7,
	PERF_BR_SYSRET = 8,
	PERF_BR_COND_CALL = 9,
	PERF_BR_COND_RET = 10,
	PERF_BR_ERET = 11,
	PERF_BR_IRQ = 12,
	PERF_BR_SERROR = 13,
	PERF_BR_NO_TX = 14,
	PERF_BR_EXTEND_ABI = 15,
	PERF_BR_MAX = 16,
};

enum {
	X86_BR_NONE = 0,
	X86_BR_USER = 1,
	X86_BR_KERNEL = 2,
	X86_BR_CALL = 4,
	X86_BR_RET = 8,
	X86_BR_SYSCALL = 16,
	X86_BR_SYSRET = 32,
	X86_BR_INT = 64,
	X86_BR_IRET = 128,
	X86_BR_JCC = 256,
	X86_BR_JMP = 512,
	X86_BR_IRQ = 1024,
	X86_BR_IND_CALL = 2048,
	X86_BR_ABORT = 4096,
	X86_BR_IN_TX = 8192,
	X86_BR_NO_TX = 16384,
	X86_BR_ZERO_CALL = 32768,
	X86_BR_CALL_STACK = 65536,
	X86_BR_IND_JMP = 131072,
	X86_BR_TYPE_SAVE = 262144,
};

struct mpc_intsrc {
	unsigned char type;
	unsigned char irqtype;
	unsigned short irqflag;
	unsigned char srcbus;
	unsigned char srcbusirq;
	unsigned char dstapic;
	unsigned char dstirq;
};

enum ioapic_domain_type {
	IOAPIC_DOMAIN_INVALID = 0,
	IOAPIC_DOMAIN_LEGACY = 1,
	IOAPIC_DOMAIN_STRICT = 2,
	IOAPIC_DOMAIN_DYNAMIC = 3,
};

enum mp_irq_source_types {
	mp_INT = 0,
	mp_NMI = 1,
	mp_SMI = 2,
	mp_ExtINT = 3,
};

enum {
	DUMP_PREFIX_NONE = 0,
	DUMP_PREFIX_ADDRESS = 1,
	DUMP_PREFIX_OFFSET = 2,
};

struct mpc_cpu {
	unsigned char type;
	unsigned char apicid;
	unsigned char apicver;
	unsigned char cpuflag;
	unsigned int cpufeature;
	unsigned int featureflag;
	unsigned int reserved[2];
};

struct mpc_bus {
	unsigned char type;
	unsigned char busid;
	unsigned char bustype[6];
};

struct mpc_ioapic {
	unsigned char type;
	unsigned char apicid;
	unsigned char apicver;
	unsigned char flags;
	unsigned int apicaddr;
};

struct mpc_lintsrc {
	unsigned char type;
	unsigned char irqtype;
	unsigned short irqflag;
	unsigned char srcbusid;
	unsigned char srcbusirq;
	unsigned char destapic;
	unsigned char destapiclint;
};

struct mpf_intel {
	char signature[4];
	unsigned int physptr;
	unsigned char length;
	unsigned char specification;
	unsigned char checksum;
	unsigned char feature1;
	unsigned char feature2;
	unsigned char feature3;
	unsigned char feature4;
	unsigned char feature5;
};

struct ioapic_domain_cfg {
	enum ioapic_domain_type type;
	const struct irq_domain_ops *ops;
	struct device_node *dev;
};

struct mpc_table {
	char signature[4];
	unsigned short length;
	char spec;
	char checksum;
	char oem[8];
	char productid[12];
	unsigned int oemptr;
	unsigned short oemsize;
	unsigned short oemcount;
	unsigned int lapic;
	unsigned int reserved;
};

struct ipc_ids {
	int in_use;
	unsigned short seq;
	struct rw_semaphore rwsem;
	struct idr ipcs_idr;
	int max_idx;
	int last_idx;
	struct rhashtable key_ht;
};

struct ipc_namespace {
	struct ipc_ids ids[3];
	int sem_ctls[4];
	int used_sems;
	unsigned int msg_ctlmax;
	unsigned int msg_ctlmnb;
	unsigned int msg_ctlmni;
	struct percpu_counter percpu_msg_bytes;
	struct percpu_counter percpu_msg_hdrs;
	size_t shm_ctlmax;
	size_t shm_ctlall;
	unsigned long shm_tot;
	int shm_ctlmni;
	int shm_rmid_forced;
	struct notifier_block ipcns_nb;
	struct vfsmount *mq_mnt;
	unsigned int mq_queues_count;
	unsigned int mq_queues_max;
	unsigned int mq_msg_max;
	unsigned int mq_msgsize_max;
	unsigned int mq_msg_default;
	unsigned int mq_msgsize_default;
	struct ctl_table_set mq_set;
	struct ctl_table_header *mq_sysctls;
	struct ctl_table_set ipc_set;
	struct ctl_table_header *ipc_sysctls;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct llist_node mnt_llist;
	struct ns_common ns;
};

struct tm {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	long tm_year;
	int tm_wday;
	int tm_yday;
};

struct cyclecounter;

struct timecounter {
	const struct cyclecounter *cc;
	u64 cycle_last;
	u64 nsec;
	u64 mask;
	u64 frac;
};

struct cyclecounter {
	u64 (*read)(const struct cyclecounter *);
	u64 mask;
	u32 mult;
	u32 shift;
};

enum bpf_stack_slot_type {
	STACK_INVALID = 0,
	STACK_SPILL = 1,
	STACK_MISC = 2,
	STACK_ZERO = 3,
	STACK_DYNPTR = 4,
	STACK_ITER = 5,
};

struct fileattr {
	u32 flags;
	u32 fsx_xflags;
	u32 fsx_extsize;
	u32 fsx_nextents;
	u32 fsx_projid;
	u32 fsx_cowextsize;
	bool flags_valid: 1;
	bool fsx_valid: 1;
};

typedef struct {
	int val[2];
} __kernel_fsid_t;

struct kstatfs {
	long f_type;
	long f_bsize;
	u64 f_blocks;
	u64 f_bfree;
	u64 f_bavail;
	u64 f_files;
	u64 f_ffree;
	__kernel_fsid_t f_fsid;
	long f_namelen;
	long f_frsize;
	long f_flags;
	long f_spare[4];
};

enum umount_tree_flags {
	UMOUNT_SYNC = 1,
	UMOUNT_PROPAGATE = 2,
	UMOUNT_CONNECTED = 4,
};

enum mnt_tree_flags_t {
	MNT_TREE_MOVE = 1,
	MNT_TREE_BENEATH = 2,
};

struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};

struct mnt_id_req {
	__u32 size;
	__u32 spare;
	__u64 mnt_id;
	__u64 param;
};

struct statmount {
	__u32 size;
	__u32 __spare1;
	__u64 mask;
	__u32 sb_dev_major;
	__u32 sb_dev_minor;
	__u64 sb_magic;
	__u32 sb_flags;
	__u32 fs_type;
	__u64 mnt_id;
	__u64 mnt_parent_id;
	__u32 mnt_id_old;
	__u32 mnt_parent_id_old;
	__u64 mnt_attr;
	__u64 mnt_propagation;
	__u64 mnt_peer_group;
	__u64 mnt_master;
	__u64 propagate_from;
	__u32 mnt_root;
	__u32 mnt_point;
	__u64 __spare2[50];
	char str[0];
};

struct mount_kattr {
	unsigned int attr_set;
	unsigned int attr_clr;
	unsigned int propagation;
	unsigned int lookup_flags;
	bool recurse;
	struct user_namespace *mnt_userns;
	struct mnt_idmap *mnt_idmap;
};

struct kstatmount {
	struct statmount __attribute__((btf_type_tag("user"))) *buf;
	size_t bufsize;
	struct vfsmount *mnt;
	u64 mask;
	struct path root;
	struct statmount sm;
	struct seq_file seq;
};

typedef enum {
	PHY_INTERFACE_MODE_NA = 0,
	PHY_INTERFACE_MODE_INTERNAL = 1,
	PHY_INTERFACE_MODE_MII = 2,
	PHY_INTERFACE_MODE_GMII = 3,
	PHY_INTERFACE_MODE_SGMII = 4,
	PHY_INTERFACE_MODE_TBI = 5,
	PHY_INTERFACE_MODE_REVMII = 6,
	PHY_INTERFACE_MODE_RMII = 7,
	PHY_INTERFACE_MODE_REVRMII = 8,
	PHY_INTERFACE_MODE_RGMII = 9,
	PHY_INTERFACE_MODE_RGMII_ID = 10,
	PHY_INTERFACE_MODE_RGMII_RXID = 11,
	PHY_INTERFACE_MODE_RGMII_TXID = 12,
	PHY_INTERFACE_MODE_RTBI = 13,
	PHY_INTERFACE_MODE_SMII = 14,
	PHY_INTERFACE_MODE_XGMII = 15,
	PHY_INTERFACE_MODE_XLGMII = 16,
	PHY_INTERFACE_MODE_MOCA = 17,
	PHY_INTERFACE_MODE_PSGMII = 18,
	PHY_INTERFACE_MODE_QSGMII = 19,
	PHY_INTERFACE_MODE_TRGMII = 20,
	PHY_INTERFACE_MODE_100BASEX = 21,
	PHY_INTERFACE_MODE_1000BASEX = 22,
	PHY_INTERFACE_MODE_2500BASEX = 23,
	PHY_INTERFACE_MODE_5GBASER = 24,
	PHY_INTERFACE_MODE_RXAUI = 25,
	PHY_INTERFACE_MODE_XAUI = 26,
	PHY_INTERFACE_MODE_10GBASER = 27,
	PHY_INTERFACE_MODE_25GBASER = 28,
	PHY_INTERFACE_MODE_USXGMII = 29,
	PHY_INTERFACE_MODE_10GKR = 30,
	PHY_INTERFACE_MODE_QUSGMII = 31,
	PHY_INTERFACE_MODE_1000BASEKX = 32,
	PHY_INTERFACE_MODE_MAX = 33,
} phy_interface_t;

typedef __kernel_long_t __kernel_ptrdiff_t;

typedef __kernel_ptrdiff_t ptrdiff_t;

typedef void * (*devcon_match_fn_t)(const struct fwnode_handle *, const char *, void *);

enum {
	PERF_BR_SPEC_NA = 0,
	PERF_BR_SPEC_WRONG_PATH = 1,
	PERF_BR_NON_SPEC_CORRECT_PATH = 2,
	PERF_BR_SPEC_CORRECT_PATH = 3,
	PERF_BR_SPEC_MAX = 4,
};

enum perf_branch_sample_type_shift {
	PERF_SAMPLE_BRANCH_USER_SHIFT = 0,
	PERF_SAMPLE_BRANCH_KERNEL_SHIFT = 1,
	PERF_SAMPLE_BRANCH_HV_SHIFT = 2,
	PERF_SAMPLE_BRANCH_ANY_SHIFT = 3,
	PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT = 4,
	PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT = 5,
	PERF_SAMPLE_BRANCH_IND_CALL_SHIFT = 6,
	PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT = 7,
	PERF_SAMPLE_BRANCH_IN_TX_SHIFT = 8,
	PERF_SAMPLE_BRANCH_NO_TX_SHIFT = 9,
	PERF_SAMPLE_BRANCH_COND_SHIFT = 10,
	PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT = 11,
	PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT = 12,
	PERF_SAMPLE_BRANCH_CALL_SHIFT = 13,
	PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT = 14,
	PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT = 15,
	PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT = 16,
	PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT = 17,
	PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT = 18,
	PERF_SAMPLE_BRANCH_COUNTERS_SHIFT = 19,
	PERF_SAMPLE_BRANCH_MAX_SHIFT = 20,
};

struct branch_entry {
	union {
		struct {
			u64 ip: 58;
			u64 ip_sign_ext: 5;
			u64 mispredict: 1;
		} split;
		u64 full;
	} from;
	union {
		struct {
			u64 ip: 58;
			u64 ip_sign_ext: 3;
			u64 reserved: 1;
			u64 spec: 1;
			u64 valid: 1;
		} split;
		u64 full;
	} to;
};

union cpuid_0x80000022_ebx {
	struct {
		unsigned int num_core_pmc: 4;
		unsigned int lbr_v2_stack_sz: 6;
		unsigned int num_df_pmc: 6;
		unsigned int num_umc_pmc: 6;
	} split;
	unsigned int full;
};

struct rusage {
	struct __kernel_old_timeval ru_utime;
	struct __kernel_old_timeval ru_stime;
	__kernel_long_t ru_maxrss;
	__kernel_long_t ru_ixrss;
	__kernel_long_t ru_idrss;
	__kernel_long_t ru_isrss;
	__kernel_long_t ru_minflt;
	__kernel_long_t ru_majflt;
	__kernel_long_t ru_nswap;
	__kernel_long_t ru_inblock;
	__kernel_long_t ru_oublock;
	__kernel_long_t ru_msgsnd;
	__kernel_long_t ru_msgrcv;
	__kernel_long_t ru_nsignals;
	__kernel_long_t ru_nvcsw;
	__kernel_long_t ru_nivcsw;
};

struct waitid_info;

struct wait_opts {
	enum pid_type wo_type;
	int wo_flags;
	struct pid *wo_pid;
	struct waitid_info *wo_info;
	int wo_stat;
	struct rusage *wo_rusage;
	wait_queue_entry_t child_wait;
	int notask_error;
};

struct waitid_info {
	pid_t pid;
	uid_t uid;
	int status;
	int cause;
};

enum bpf_audit {
	BPF_AUDIT_LOAD = 0,
	BPF_AUDIT_UNLOAD = 1,
	BPF_AUDIT_MAX = 2,
};

enum bpf_task_fd_type {
	BPF_FD_TYPE_RAW_TRACEPOINT = 0,
	BPF_FD_TYPE_TRACEPOINT = 1,
	BPF_FD_TYPE_KPROBE = 2,
	BPF_FD_TYPE_KRETPROBE = 3,
	BPF_FD_TYPE_UPROBE = 4,
	BPF_FD_TYPE_URETPROBE = 5,
};

enum bpf_perf_event_type {
	BPF_PERF_EVENT_UNSPEC = 0,
	BPF_PERF_EVENT_UPROBE = 1,
	BPF_PERF_EVENT_URETPROBE = 2,
	BPF_PERF_EVENT_KPROBE = 3,
	BPF_PERF_EVENT_KRETPROBE = 4,
	BPF_PERF_EVENT_TRACEPOINT = 5,
	BPF_PERF_EVENT_EVENT = 6,
};

enum bpf_stats_type {
	BPF_STATS_RUN_TIME = 0,
};

typedef u64 (*btf_bpf_sys_bpf)(int, union bpf_attr *, u32);

typedef u64 (*btf_bpf_sys_close)(u32);

typedef u64 (*btf_bpf_kallsyms_lookup_name)(const char *, int, int, u64 *);

struct bpf_tramp_link {
	struct bpf_link link;
	struct hlist_node tramp_hlist;
	u64 cookie;
};

struct bpf_tracing_link {
	struct bpf_tramp_link link;
	enum bpf_attach_type attach_type;
	struct bpf_trampoline *trampoline;
	struct bpf_prog *tgt_prog;
};

struct bpf_raw_event_map;

struct bpf_raw_tp_link {
	struct bpf_link link;
	struct bpf_raw_event_map *btp;
};

struct tracepoint;

struct bpf_raw_event_map {
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};

struct tracepoint_func;

struct tracepoint {
	const char *name;
	struct static_key key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	void *probestub;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func __attribute__((btf_type_tag("rcu"))) *funcs;
};

struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};

struct bpf_perf_link {
	struct bpf_link link;
	struct file *perf_file;
};

struct bpf_spin_lock {
	__u32 val;
};

struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8 tag[8];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__u64 jited_prog_insns;
	__u64 xlated_prog_insns;
	__u64 load_time;
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__u64 map_ids;
	char name[16];
	__u32 ifindex;
	__u32 gpl_compatible: 1;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 nr_jited_ksyms;
	__u32 nr_jited_func_lens;
	__u64 jited_ksyms;
	__u64 jited_func_lens;
	__u32 btf_id;
	__u32 func_info_rec_size;
	__u64 func_info;
	__u32 nr_func_info;
	__u32 nr_line_info;
	__u64 line_info;
	__u64 jited_line_info;
	__u32 nr_jited_line_info;
	__u32 line_info_rec_size;
	__u32 jited_line_info_rec_size;
	__u32 nr_prog_tags;
	__u64 prog_tags;
	__u64 run_time_ns;
	__u64 run_cnt;
	__u64 recursion_misses;
	__u32 verified_insns;
	__u32 attach_btf_obj_id;
	__u32 attach_btf_id;
};

struct bpf_prog_kstats {
	u64 nsecs;
	u64 cnt;
	u64 misses;
};

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char name[16];
	__u32 ifindex;
	__u32 btf_vmlinux_value_type_id;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u32 btf_vmlinux_id;
	__u64 map_extra;
};

struct bpf_attach_target_info {
	struct btf_func_model fmodel;
	long tgt_addr;
	struct module *tgt_mod;
	const char *tgt_name;
	const struct btf_type *tgt_type;
};

struct bpf_link_primer {
	struct bpf_link *link;
	struct file *file;
	int fd;
	u32 id;
};

struct bpf_tramp_run_ctx {
	struct bpf_run_ctx run_ctx;
	u64 bpf_cookie;
	struct bpf_run_ctx *saved_run_ctx;
};

struct prepend_buffer {
	char *buf;
	int len;
};

struct klist_waiter {
	struct list_head list;
	struct klist_node *node;
	struct task_struct *process;
	int woken;
};

struct perf_msr {
	u64 msr;
	struct attribute_group *grp;
	bool (*test)(int, void *);
	bool no_check;
	u64 mask;
};

enum pconfig_target {
	INVALID_TARGET = 0,
	MKTME_TARGET = 1,
	PCONFIG_TARGET_NR = 2,
};

enum {
	PCONFIG_CPUID_SUBLEAF_INVALID = 0,
	PCONFIG_CPUID_SUBLEAF_TARGETID = 1,
};

struct cpuid_regs {
	u32 eax;
	u32 ebx;
	u32 ecx;
	u32 edx;
};

struct microcode_header_intel {
	unsigned int hdrver;
	unsigned int rev;
	unsigned int date;
	unsigned int sig;
	unsigned int cksum;
	unsigned int ldrver;
	unsigned int pf;
	unsigned int datasize;
	unsigned int totalsize;
	unsigned int metasize;
	unsigned int min_req_ver;
	unsigned int reserved;
};

struct microcode_intel {
	struct microcode_header_intel hdr;
	unsigned int bits[0];
};

struct extended_signature {
	unsigned int sig;
	unsigned int pf;
	unsigned int cksum;
};

struct extended_sigtable {
	unsigned int count;
	unsigned int cksum;
	unsigned int reserved[3];
	struct extended_signature sigs[0];
};

struct firmware {
	size_t size;
	const u8 *data;
	void *priv;
};

struct subprocess_info {
	struct work_struct work;
	struct completion *complete;
	const char *path;
	char **argv;
	char **envp;
	int wait;
	int retval;
	int (*init)(struct subprocess_info *, struct cred *);
	void (*cleanup)(struct subprocess_info *);
	void *data;
};

typedef __kernel_long_t __kernel_suseconds_t;

typedef __kernel_suseconds_t suseconds_t;

typedef __u64 timeu64_t;

typedef __kernel_long_t __kernel_old_time_t;

struct __kernel_timex_timeval {
	__kernel_time64_t tv_sec;
	long long tv_usec;
};

struct __kernel_timex {
	unsigned int modes;
	long long offset;
	long long freq;
	long long maxerror;
	long long esterror;
	int status;
	long long constant;
	long long precision;
	long long tolerance;
	struct __kernel_timex_timeval time;
	long long tick;
	long long ppsfreq;
	long long jitter;
	int shift;
	long long stabil;
	long long jitcnt;
	long long calcnt;
	long long errcnt;
	long long stbcnt;
	int tai;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef __kernel_clock_t clock_t;

struct itimerspec64 {
	struct timespec64 it_interval;
	struct timespec64 it_value;
};

struct __kernel_itimerspec {
	struct __kernel_timespec it_interval;
	struct __kernel_timespec it_value;
};

struct old_itimerspec32 {
	struct old_timespec32 it_interval;
	struct old_timespec32 it_value;
};

struct hrtimer_sleeper {
	struct hrtimer timer;
	struct task_struct *task;
};

enum memcg_memory_event {
	MEMCG_LOW = 0,
	MEMCG_HIGH = 1,
	MEMCG_MAX = 2,
	MEMCG_OOM = 3,
	MEMCG_OOM_KILL = 4,
	MEMCG_OOM_GROUP_KILL = 5,
	MEMCG_SWAP_HIGH = 6,
	MEMCG_SWAP_MAX = 7,
	MEMCG_SWAP_FAIL = 8,
	MEMCG_NR_MEMORY_EVENTS = 9,
};

struct __old_kernel_stat {
	unsigned short st_dev;
	unsigned short st_ino;
	unsigned short st_mode;
	unsigned short st_nlink;
	unsigned short st_uid;
	unsigned short st_gid;
	unsigned short st_rdev;
	unsigned int st_size;
	unsigned int st_atime;
	unsigned int st_mtime;
	unsigned int st_ctime;
};

struct stat {
	__kernel_ulong_t st_dev;
	__kernel_ulong_t st_ino;
	__kernel_ulong_t st_nlink;
	unsigned int st_mode;
	unsigned int st_uid;
	unsigned int st_gid;
	unsigned int __pad0;
	__kernel_ulong_t st_rdev;
	__kernel_long_t st_size;
	__kernel_long_t st_blksize;
	__kernel_long_t st_blocks;
	__kernel_ulong_t st_atime;
	__kernel_ulong_t st_atime_nsec;
	__kernel_ulong_t st_mtime;
	__kernel_ulong_t st_mtime_nsec;
	__kernel_ulong_t st_ctime;
	__kernel_ulong_t st_ctime_nsec;
	__kernel_long_t __unused[3];
};

struct statx_timestamp {
	__s64 tv_sec;
	__u32 tv_nsec;
	__s32 __reserved;
};

struct statx {
	__u32 stx_mask;
	__u32 stx_blksize;
	__u64 stx_attributes;
	__u32 stx_nlink;
	__u32 stx_uid;
	__u32 stx_gid;
	__u16 stx_mode;
	__u16 __spare0[1];
	__u64 stx_ino;
	__u64 stx_size;
	__u64 stx_blocks;
	__u64 stx_attributes_mask;
	struct statx_timestamp stx_atime;
	struct statx_timestamp stx_btime;
	struct statx_timestamp stx_ctime;
	struct statx_timestamp stx_mtime;
	__u32 stx_rdev_major;
	__u32 stx_rdev_minor;
	__u32 stx_dev_major;
	__u32 stx_dev_minor;
	__u64 stx_mnt_id;
	__u32 stx_dio_mem_align;
	__u32 stx_dio_offset_align;
	__u64 __spare3[12];
};

struct constant_table {
	const char *name;
	int value;
};

enum legacy_fs_param {
	LEGACY_FS_UNSET_PARAMS = 0,
	LEGACY_FS_MONOLITHIC_PARAMS = 1,
	LEGACY_FS_INDIVIDUAL_PARAMS = 2,
};

struct legacy_fs_context {
	char *legacy_data;
	size_t data_size;
	enum legacy_fs_param param_type;
};

struct ida_bitmap {
	unsigned long bitmap[16];
};

enum reg_type {
	REG_TYPE_RM = 0,
	REG_TYPE_REG = 1,
	REG_TYPE_INDEX = 2,
	REG_TYPE_BASE = 3,
};

enum insn_mmio_type {
	INSN_MMIO_DECODE_FAILED = 0,
	INSN_MMIO_WRITE = 1,
	INSN_MMIO_WRITE_IMM = 2,
	INSN_MMIO_READ = 3,
	INSN_MMIO_READ_ZERO_EXTEND = 4,
	INSN_MMIO_READ_SIGN_EXTEND = 5,
	INSN_MMIO_MOVS = 6,
};

struct cpu_perf_ibs;

struct perf_ibs {
	struct pmu pmu;
	unsigned int msr;
	u64 config_mask;
	u64 cnt_mask;
	u64 enable_mask;
	u64 valid_mask;
	u64 max_period;
	unsigned long offset_mask[1];
	int offset_max;
	unsigned int fetch_count_reset_broken: 1;
	unsigned int fetch_ignore_if_zero_rip: 1;
	struct cpu_perf_ibs __attribute__((btf_type_tag("percpu"))) *pcpu;
	u64 (*get_count)(u64);
};

struct cpu_perf_ibs {
	struct perf_event *event;
	unsigned long state[1];
};

enum ibs_states {
	IBS_ENABLED = 0,
	IBS_STARTED = 1,
	IBS_STOPPING = 2,
	IBS_STOPPED = 3,
	IBS_MAX_STATES = 4,
};

union ibs_fetch_ctl {
	__u64 val;
	struct {
		__u64 fetch_maxcnt: 16;
		__u64 fetch_cnt: 16;
		__u64 fetch_lat: 16;
		__u64 fetch_en: 1;
		__u64 fetch_val: 1;
		__u64 fetch_comp: 1;
		__u64 ic_miss: 1;
		__u64 phy_addr_valid: 1;
		__u64 l1tlb_pgsz: 2;
		__u64 l1tlb_miss: 1;
		__u64 l2tlb_miss: 1;
		__u64 rand_en: 1;
		__u64 fetch_l2_miss: 1;
		__u64 l3_miss_only: 1;
		__u64 fetch_oc_miss: 1;
		__u64 fetch_l3_miss: 1;
		__u64 reserved: 2;
	};
};

union ibs_op_ctl {
	__u64 val;
	struct {
		__u64 opmaxcnt: 16;
		__u64 l3_miss_only: 1;
		__u64 op_en: 1;
		__u64 op_val: 1;
		__u64 cnt_ctl: 1;
		__u64 opmaxcnt_ext: 7;
		__u64 reserved0: 5;
		__u64 opcurcnt: 27;
		__u64 reserved1: 5;
	};
};

struct perf_ibs_data {
	u32 size;
	union {
		u32 data[0];
		u32 caps;
	};
	u64 regs[8];
};

union ibs_op_data3 {
	__u64 val;
	struct {
		__u64 ld_op: 1;
		__u64 st_op: 1;
		__u64 dc_l1tlb_miss: 1;
		__u64 dc_l2tlb_miss: 1;
		__u64 dc_l1tlb_hit_2m: 1;
		__u64 dc_l1tlb_hit_1g: 1;
		__u64 dc_l2tlb_hit_2m: 1;
		__u64 dc_miss: 1;
		__u64 dc_mis_acc: 1;
		__u64 reserved: 4;
		__u64 dc_wc_mem_acc: 1;
		__u64 dc_uc_mem_acc: 1;
		__u64 dc_locked_op: 1;
		__u64 dc_miss_no_mab_alloc: 1;
		__u64 dc_lin_addr_valid: 1;
		__u64 dc_phy_addr_valid: 1;
		__u64 dc_l2_tlb_hit_1g: 1;
		__u64 l2_miss: 1;
		__u64 sw_pf: 1;
		__u64 op_mem_width: 4;
		__u64 op_dc_miss_open_mem_reqs: 6;
		__u64 dc_miss_lat: 16;
		__u64 tlb_refill_lat: 16;
	};
};

union ibs_op_data2 {
	__u64 val;
	struct {
		__u64 data_src_lo: 3;
		__u64 reserved0: 1;
		__u64 rmt_node: 1;
		__u64 cache_hit_st: 1;
		__u64 data_src_hi: 2;
		__u64 reserved1: 56;
	};
};

union ibs_op_data {
	__u64 val;
	struct {
		__u64 comp_to_ret_ctr: 16;
		__u64 tag_to_ret_ctr: 16;
		__u64 reserved1: 2;
		__u64 op_return: 1;
		__u64 op_brn_taken: 1;
		__u64 op_brn_misp: 1;
		__u64 op_brn_ret: 1;
		__u64 op_rip_invalid: 1;
		__u64 op_brn_fuse: 1;
		__u64 op_microcode: 1;
		__u64 reserved2: 23;
	};
};

enum {
	PAT_UC = 0,
	PAT_WC = 1,
	PAT_WT = 4,
	PAT_WP = 5,
	PAT_WB = 6,
	PAT_UC_MINUS = 7,
};

struct memtype {
	u64 start;
	u64 end;
	u64 subtree_max_end;
	enum page_cache_mode type;
	struct rb_node rb;
};

struct pagerange_state {
	unsigned long cur_pfn;
	int ram;
	int not_ram;
};

enum pci_p2pdma_map_type {
	PCI_P2PDMA_MAP_UNKNOWN = 0,
	PCI_P2PDMA_MAP_NOT_SUPPORTED = 1,
	PCI_P2PDMA_MAP_BUS_ADDR = 2,
	PCI_P2PDMA_MAP_THRU_HOST_BRIDGE = 3,
};

struct pci_p2pdma_map_state {
	struct dev_pagemap *pgmap;
	int map;
	u64 bus_off;
};

struct device_attach_data {
	struct device *dev;
	bool check_async;
	bool want_async;
	bool have_async;
};

struct nmi_stats {
	unsigned int normal;
	unsigned int unknown;
	unsigned int external;
	unsigned int swallow;
	unsigned long recv_jiffies;
	unsigned long idt_seq;
	unsigned long idt_nmi_seq;
	unsigned long idt_ignored;
	atomic_long_t idt_calls;
	unsigned long idt_seq_snap;
	unsigned long idt_nmi_seq_snap;
	unsigned long idt_ignored_snap;
	long idt_calls_snap;
};

enum nmi_states {
	NMI_NOT_RUNNING = 0,
	NMI_EXECUTING = 1,
	NMI_LATCHED = 2,
};

struct nmi_desc {
	raw_spinlock_t lock;
	struct list_head head;
};

enum align_flags {
	ALIGN_VA_32 = 1,
	ALIGN_VA_64 = 2,
};

enum bug_trap_type {
	BUG_TRAP_TYPE_NONE = 0,
	BUG_TRAP_TYPE_WARN = 1,
	BUG_TRAP_TYPE_BUG = 2,
};

struct kernel_stat {
	unsigned long irqs_sum;
	unsigned int softirqs[10];
};

enum ctx_state {
	CONTEXT_DISABLED = -1,
	CONTEXT_KERNEL = 0,
	CONTEXT_IDLE = 1,
	CONTEXT_USER = 2,
	CONTEXT_GUEST = 3,
	CONTEXT_MAX = 4,
};

typedef struct {
	raw_spinlock_t *lock;
} class_raw_spinlock_irq_t;

typedef struct {
	void *lock;
} class_preempt_t;

typedef struct {
	raw_spinlock_t *lock;
	unsigned long flags;
} class_raw_spinlock_irqsave_t;

typedef struct {
	struct task_struct *lock;
	struct rq *rq;
	struct rq_flags rf;
} class_task_rq_lock_t;

typedef struct task_struct *class_find_get_task_t;

struct affinity_context {
	const struct cpumask *new_mask;
	struct cpumask *user_mask;
	unsigned int flags;
};

typedef struct {
	void *lock;
	unsigned long flags;
} class_irqsave_t;

typedef struct {
	struct rq *lock;
	struct rq *lock2;
} class_double_rq_lock_t;

typedef int (*task_call_f)(struct task_struct *, void *);

struct balance_callback {
	struct balance_callback *next;
	void (*func)(struct rq *);
};

struct char_device_struct {
	struct char_device_struct *next;
	unsigned int major;
	unsigned int baseminor;
	int minorct;
	char name[64];
	struct cdev *cdev;
};

typedef struct kobject *kobj_probe_t(dev_t, int *, void *);

struct class_attribute {
	struct attribute attr;
	ssize_t (*show)(const struct class *, const struct class_attribute *, char *);
	ssize_t (*store)(const struct class *, const struct class_attribute *, const char *, size_t);
};

struct class_attribute_string {
	struct class_attribute attr;
	char *str;
};

struct class_dev_iter {
	struct klist_iter ki;
	const struct device_type *type;
	struct subsys_private *sp;
};

struct class_compat {
	struct kobject *kobj;
};

struct class_interface {
	struct list_head node;
	const struct class *class;
	int (*add_dev)(struct device *);
	void (*remove_dev)(struct device *);
};

struct tsc_adjust {
	s64 bootval;
	s64 adjusted;
	unsigned long nextcheck;
	bool warned;
};

struct mp_ioapic_gsi {
	u32 gsi_base;
	u32 gsi_end;
};

struct IO_APIC_route_entry;

struct ioapic {
	int nr_registers;
	struct IO_APIC_route_entry *saved_registers;
	struct mpc_ioapic mp_config;
	struct mp_ioapic_gsi gsi_config;
	struct ioapic_domain_cfg irqdomain_cfg;
	struct irq_domain *irqdomain;
	struct resource *iomem_res;
};

struct IO_APIC_route_entry {
	union {
		struct {
			u64 vector: 8;
			u64 delivery_mode: 3;
			u64 dest_mode_logical: 1;
			u64 delivery_status: 1;
			u64 active_low: 1;
			u64 irr: 1;
			u64 is_level: 1;
			u64 masked: 1;
			u64 reserved_0: 15;
			u64 reserved_1: 17;
			u64 virt_destid_8_14: 7;
			u64 destid_0_7: 8;
		};
		struct {
			u64 ir_shared_0: 8;
			u64 ir_zero: 3;
			u64 ir_index_15: 1;
			u64 ir_shared_1: 5;
			u64 ir_reserved_0: 31;
			u64 ir_format: 1;
			u64 ir_index_0_14: 15;
		};
		struct {
			u64 w1: 32;
			u64 w2: 32;
		};
	};
};

struct irq_pin_list {
	struct list_head list;
	int apic;
	int pin;
};

struct io_apic {
	unsigned int index;
	unsigned int unused[3];
	unsigned int data;
	unsigned int unused2[11];
	unsigned int eoi;
};

union IO_APIC_reg_00 {
	u32 raw;
	struct {
		u32 __reserved_2: 14;
		u32 LTS: 1;
		u32 delivery_type: 1;
		u32 __reserved_1: 8;
		u32 ID: 8;
	} bits;
};

union IO_APIC_reg_01 {
	u32 raw;
	struct {
		u32 version: 8;
		u32 __reserved_2: 7;
		u32 PRQ: 1;
		u32 entries: 8;
		u32 __reserved_1: 8;
	} bits;
};

union IO_APIC_reg_02 {
	u32 raw;
	struct {
		u32 __reserved_2: 24;
		u32 arbitration: 4;
		u32 __reserved_1: 4;
	} bits;
};

struct mp_chip_data {
	struct list_head irq_2_pin;
	struct IO_APIC_route_entry entry;
	bool is_level;
	bool active_low;
	bool isa_irq;
	u32 count;
};

union IO_APIC_reg_03 {
	u32 raw;
	struct {
		u32 boot_DT: 1;
		u32 __reserved_1: 31;
	} bits;
};

struct semaphore_waiter {
	struct list_head list;
	struct task_struct *task;
	bool up;
};

struct semaphore {
	raw_spinlock_t lock;
	unsigned int count;
	struct list_head wait_list;
};

struct dma_chan {
	int lock;
	const char *device_id;
};

struct __call_single_data {
	struct __call_single_node node;
	smp_call_func_t func;
	void *info;
};

typedef struct __call_single_data call_single_data_t;

struct bpf_kfunc_desc {
	struct btf_func_model func_model;
	u32 func_id;
	s32 imm;
	u16 offset;
	unsigned long addr;
};

struct bpf_kfunc_desc_tab {
	struct bpf_kfunc_desc descs[256];
	u32 nr_descs;
};

struct bpf_kfunc_btf {
	struct btf *btf;
	struct module *module;
	u16 offset;
};

struct bpf_kfunc_btf_tab {
	struct bpf_kfunc_btf descs[256];
	u32 nr_descs;
};

struct bpf_verifier_stack_elem {
	struct bpf_verifier_state st;
	int insn_idx;
	int prev_insn_idx;
	struct bpf_verifier_stack_elem *next;
	u32 log_pos;
};

struct bpf_reg_types {
	const enum bpf_reg_type types[10];
	u32 *btf_id;
};

enum {
	INSN_F_FRAMENO_MASK = 7,
	INSN_F_SPI_MASK = 63,
	INSN_F_SPI_SHIFT = 3,
	INSN_F_STACK_ACCESS = 512,
};

enum special_kfunc_type {
	KF_bpf_obj_new_impl = 0,
	KF_bpf_obj_drop_impl = 1,
	KF_bpf_refcount_acquire_impl = 2,
	KF_bpf_list_push_front_impl = 3,
	KF_bpf_list_push_back_impl = 4,
	KF_bpf_list_pop_front = 5,
	KF_bpf_list_pop_back = 6,
	KF_bpf_cast_to_kern_ctx = 7,
	KF_bpf_rdonly_cast = 8,
	KF_bpf_rcu_read_lock = 9,
	KF_bpf_rcu_read_unlock = 10,
	KF_bpf_rbtree_remove = 11,
	KF_bpf_rbtree_add_impl = 12,
	KF_bpf_rbtree_first = 13,
	KF_bpf_dynptr_from_skb = 14,
	KF_bpf_dynptr_from_xdp = 15,
	KF_bpf_dynptr_slice = 16,
	KF_bpf_dynptr_slice_rdwr = 17,
	KF_bpf_dynptr_clone = 18,
	KF_bpf_percpu_obj_new_impl = 19,
	KF_bpf_percpu_obj_drop_impl = 20,
	KF_bpf_throw = 21,
	KF_bpf_iter_css_task_new = 22,
};

enum {
	DISCOVERED = 16,
	EXPLORED = 32,
	FALLTHROUGH = 1,
	BRANCH = 2,
};

enum {
	DONE_EXPLORING = 0,
	KEEP_EXPLORING = 1,
};

enum bpf_cond_pseudo_jmp {
	BPF_MAY_GOTO = 0,
};

enum reg_arg_type {
	SRC_OP = 0,
	DST_OP = 1,
	DST_OP_NO_MARK = 2,
};

enum exact_level {
	NOT_EXACT = 0,
	EXACT = 1,
	RANGE_WITHIN = 2,
};

enum bpf_addr_space_cast {
	BPF_ADDR_SPACE_CAST = 1,
};

enum {
	REASON_BOUNDS = -1,
	REASON_TYPE = -2,
	REASON_PATHS = -3,
	REASON_LIMIT = -4,
	REASON_STACK = -5,
};

enum bpf_access_src {
	ACCESS_DIRECT = 1,
	ACCESS_HELPER = 2,
};

enum kfunc_ptr_arg_type {
	KF_ARG_PTR_TO_CTX = 0,
	KF_ARG_PTR_TO_ALLOC_BTF_ID = 1,
	KF_ARG_PTR_TO_REFCOUNTED_KPTR = 2,
	KF_ARG_PTR_TO_DYNPTR = 3,
	KF_ARG_PTR_TO_ITER = 4,
	KF_ARG_PTR_TO_LIST_HEAD = 5,
	KF_ARG_PTR_TO_LIST_NODE = 6,
	KF_ARG_PTR_TO_BTF_ID = 7,
	KF_ARG_PTR_TO_MEM = 8,
	KF_ARG_PTR_TO_MEM_SIZE = 9,
	KF_ARG_PTR_TO_CALLBACK = 10,
	KF_ARG_PTR_TO_RB_ROOT = 11,
	KF_ARG_PTR_TO_RB_NODE = 12,
	KF_ARG_PTR_TO_NULL = 13,
	KF_ARG_PTR_TO_CONST_STR = 14,
	KF_ARG_PTR_TO_MAP = 15,
};

enum {
	KF_ARG_DYNPTR_ID = 0,
	KF_ARG_LIST_HEAD_ID = 1,
	KF_ARG_LIST_NODE_ID = 2,
	KF_ARG_RB_ROOT_ID = 3,
	KF_ARG_RB_NODE_ID = 4,
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS = 1,
};

enum {
	AT_PKT_END = -1,
	BEYOND_PKT_END = -2,
};

enum {
	BPF_MAX_LOOPS = 8388608,
};

struct bpf_iter_meta__safe_trusted {
	struct seq_file *seq;
};

struct bpf_iter__task__safe_trusted {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
};

struct linux_binprm__safe_trusted {
	struct file *file;
};

struct file__safe_trusted {
	struct inode *f_inode;
};

struct dentry__safe_trusted {
	struct inode *d_inode;
};

struct socket__safe_trusted_or_null {
	struct sock *sk;
};

struct task_struct__safe_rcu {
	const cpumask_t *cpus_ptr;
	struct css_set __attribute__((btf_type_tag("rcu"))) *cgroups;
	struct task_struct __attribute__((btf_type_tag("rcu"))) *real_parent;
	struct task_struct *group_leader;
};

struct cgroup__safe_rcu {
	struct kernfs_node *kn;
};

struct css_set__safe_rcu {
	struct cgroup *dfl_cgrp;
};

struct mm_struct__safe_rcu_or_null {
	struct file __attribute__((btf_type_tag("rcu"))) *exe_file;
};

struct sk_buff__safe_rcu_or_null {
	struct sock *sk;
};

struct request_sock__safe_rcu_or_null {
	struct sock *sk;
};

struct bpf_iter;

typedef void (*bpf_insn_print_t)(void *, const char *, ...);

typedef const char * (*bpf_insn_revmap_call_t)(void *, const struct bpf_insn *);

typedef const char * (*bpf_insn_print_imm_t)(void *, const struct bpf_insn *, __u64);

struct bpf_insn_cbs {
	bpf_insn_print_t cb_print;
	bpf_insn_revmap_call_t cb_call;
	bpf_insn_print_imm_t cb_imm;
	void *private_data;
};

typedef u32 (*bpf_convert_ctx_access_t)(enum bpf_access_type, const struct bpf_insn *, struct bpf_insn *, struct bpf_prog *, u32 *);

struct bpf_kfunc_call_arg_meta {
	struct btf *btf;
	u32 func_id;
	u32 kfunc_flags;
	const struct btf_type *func_proto;
	const char *func_name;
	u32 ref_obj_id;
	u8 release_regno;
	bool r0_rdonly;
	u32 ret_btf_id;
	u64 r0_size;
	u32 subprogno;
	struct {
		u64 value;
		bool found;
	} arg_constant;
	struct btf *arg_btf;
	u32 arg_btf_id;
	bool arg_owning_ref;
	struct {
		struct btf_field *field;
	} arg_list_head;
	struct {
		struct btf_field *field;
	} arg_rbtree_root;
	struct {
		enum bpf_dynptr_type type;
		u32 id;
		u32 ref_obj_id;
	} initialized_dynptr;
	struct {
		u8 spi;
		u8 frameno;
	} iter;
	u64 mem_size;
};

struct bpf_call_arg_meta {
	struct bpf_map *map_ptr;
	bool raw_mode;
	bool pkt_access;
	u8 release_regno;
	int regno;
	int access_size;
	int mem_size;
	u64 msize_max_value;
	int ref_obj_id;
	int dynptr_id;
	int map_uid;
	int func_id;
	struct btf *btf;
	u32 btf_id;
	struct btf *ret_btf;
	u32 ret_btf_id;
	u32 subprogno;
	struct btf_field *kptr_field;
};

struct bpf_bprintf_data {
	u32 *bin_args;
	char *buf;
	bool get_bin_args;
	bool get_buf;
};

struct bpf_sanitize_info {
	struct bpf_insn_aux_data aux;
	bool mask_to_left;
};

typedef int (*set_callee_state_fn)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *, int);

struct mnt_idmap {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	refcount_t count;
};

struct msr {
	union {
		struct {
			u32 l;
			u32 h;
		};
		u64 q;
	};
};

struct printf_spec {
	unsigned int type: 8;
	int field_width: 24;
	unsigned int flags: 8;
	unsigned int base: 8;
	int precision: 16;
};

struct page_flags_fields {
	int width;
	int shift;
	int mask;
	const struct printf_spec *spec;
	const char *name;
};

enum format_type {
	FORMAT_TYPE_NONE = 0,
	FORMAT_TYPE_WIDTH = 1,
	FORMAT_TYPE_PRECISION = 2,
	FORMAT_TYPE_CHAR = 3,
	FORMAT_TYPE_STR = 4,
	FORMAT_TYPE_PTR = 5,
	FORMAT_TYPE_PERCENT_CHAR = 6,
	FORMAT_TYPE_INVALID = 7,
	FORMAT_TYPE_LONG_LONG = 8,
	FORMAT_TYPE_ULONG = 9,
	FORMAT_TYPE_LONG = 10,
	FORMAT_TYPE_UBYTE = 11,
	FORMAT_TYPE_BYTE = 12,
	FORMAT_TYPE_USHORT = 13,
	FORMAT_TYPE_SHORT = 14,
	FORMAT_TYPE_UINT = 15,
	FORMAT_TYPE_INT = 16,
	FORMAT_TYPE_SIZE_T = 17,
	FORMAT_TYPE_PTRDIFF = 18,
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};

struct sockaddr_in6 {
	unsigned short sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

struct clk;

struct trace_print_flags {
	unsigned long mask;
	const char *name;
};

struct ptrace_syscall_info {
	__u8 op;
	__u8 pad[3];
	__u32 arch;
	__u64 instruction_pointer;
	__u64 stack_pointer;
	union {
		struct {
			__u64 nr;
			__u64 args[6];
		} entry;
		struct {
			__s64 rval;
			__u8 is_error;
		} exit;
		struct {
			__u64 nr;
			__u64 args[6];
			__u32 ret_data;
		} seccomp;
	};
};

struct ptrace_peeksiginfo_args {
	__u64 off;
	__u32 flags;
	__s32 nr;
};

struct user_regset_view {
	const char *name;
	const struct user_regset *regsets;
	unsigned int n;
	u32 e_flags;
	u16 e_machine;
	u8 ei_osabi;
};

typedef struct mutex *class_mutex_t;

typedef class_mutex_t class_mutex_intr_t;

typedef struct {
	rwlock_t *lock;
} class_write_lock_irq_t;

typedef struct task_struct *class_task_lock_t;

typedef struct {
	spinlock_t *lock;
} class_spinlock_t;

enum memblock_flags {
	MEMBLOCK_NONE = 0,
	MEMBLOCK_HOTPLUG = 1,
	MEMBLOCK_MIRROR = 2,
	MEMBLOCK_NOMAP = 4,
	MEMBLOCK_DRIVER_MANAGED = 8,
	MEMBLOCK_RSRV_NOINIT = 16,
};

struct memblock_region {
	phys_addr_t base;
	phys_addr_t size;
	enum memblock_flags flags;
};

enum meminit_context {
	MEMINIT_EARLY = 0,
	MEMINIT_HOTPLUG = 1,
};

enum mminit_level {
	MMINIT_WARNING = 0,
	MMINIT_VERIFY = 1,
	MMINIT_TRACE = 2,
};

enum vmscan_throttle_state {
	VMSCAN_THROTTLE_WRITEBACK = 0,
	VMSCAN_THROTTLE_ISOLATED = 1,
	VMSCAN_THROTTLE_NOPROGRESS = 2,
	VMSCAN_THROTTLE_CONGESTED = 3,
	NR_VMSCAN_THROTTLE = 4,
};

typedef __kernel_rwf_t rwf_t;

struct timer_rand_state {
	unsigned long last_time;
	long last_delta;
	long last_delta2;
};

enum {
	CRNG_EMPTY = 0,
	CRNG_EARLY = 1,
	CRNG_READY = 2,
};

struct crng {
	u8 key[32];
	unsigned long generation;
	local_lock_t lock;
};

struct batch_u8 {
	u8 entropy[96];
	local_lock_t lock;
	unsigned long generation;
	unsigned int position;
};

struct batch_u16 {
	u16 entropy[48];
	local_lock_t lock;
	unsigned long generation;
	unsigned int position;
};

struct batch_u32 {
	u32 entropy[24];
	local_lock_t lock;
	unsigned long generation;
	unsigned int position;
};

struct batch_u64 {
	u64 entropy[12];
	local_lock_t lock;
	unsigned long generation;
	unsigned int position;
};

struct fast_pool {
	unsigned long pool[4];
	unsigned long last;
	unsigned int count;
	struct timer_list mix;
};

enum {
	MIX_INFLIGHT = 2147483648,
};

enum chacha_constants {
	CHACHA_CONSTANT_EXPA = 1634760805,
	CHACHA_CONSTANT_ND_3 = 857760878,
	CHACHA_CONSTANT_2_BY = 2036477234,
	CHACHA_CONSTANT_TE_K = 1797285236,
};

enum {
	POOL_BITS = 256,
	POOL_READY_BITS = 256,
	POOL_EARLY_BITS = 128,
};

enum {
	CRNG_RESEED_START_INTERVAL = 250,
	CRNG_RESEED_INTERVAL = 15000,
};

enum {
	NUM_TRIAL_SAMPLES = 8192,
	MAX_SAMPLES_PER_BIT = 16,
};

struct entropy_timer_state {
	unsigned long entropy;
	struct timer_list timer;
	atomic_t samples;
	unsigned int samples_per_bit;
};

enum perf_msr_id {
	PERF_MSR_TSC = 0,
	PERF_MSR_APERF = 1,
	PERF_MSR_MPERF = 2,
	PERF_MSR_PPERF = 3,
	PERF_MSR_SMI = 4,
	PERF_MSR_PTSC = 5,
	PERF_MSR_IRPERF = 6,
	PERF_MSR_THERM = 7,
	PERF_MSR_EVENT_MAX = 8,
};

enum topo_types {
	INVALID_TYPE = 0,
	SMT_TYPE = 1,
	CORE_TYPE = 2,
	MAX_TYPE_0B = 3,
	MODULE_TYPE = 3,
	TILE_TYPE = 4,
	DIE_TYPE = 5,
	DIEGRP_TYPE = 6,
	MAX_TYPE_1F = 7,
};

struct aperfmperf {
	seqcount_t seq;
	unsigned long last_update;
	u64 acnt;
	u64 mcnt;
	u64 aperf;
	u64 mperf;
};

struct cpuid_dep {
	unsigned int feature;
	unsigned int depends;
};

enum vmx_feature_leafs {
	MISC_FEATURES = 0,
	PRIMARY_CTLS = 1,
	SECONDARY_CTLS = 2,
	TERTIARY_CTLS_LOW = 3,
	TERTIARY_CTLS_HIGH = 4,
	NR_VMX_FEATURE_WORDS = 5,
};

struct equiv_cpu_entry;

struct equiv_cpu_table {
	unsigned int num_entries;
	struct equiv_cpu_entry *entry;
};

struct equiv_cpu_entry {
	u32 installed_cpu;
	u32 fixed_errata_mask;
	u32 fixed_errata_compare;
	u16 equiv_cpu;
	u16 res;
};

struct microcode_header_amd {
	u32 data_code;
	u32 patch_id;
	u16 mc_patch_data_id;
	u8 mc_patch_data_len;
	u8 init_flag;
	u32 mc_patch_data_checksum;
	u32 nb_dev_id;
	u32 sb_dev_id;
	u16 processor_rev_id;
	u8 nb_rev_id;
	u8 sb_rev_id;
	u8 bios_api_rev;
	u8 reserved1[3];
	u32 match_reg[8];
};

struct microcode_amd {
	struct microcode_header_amd hdr;
	unsigned int mpb[0];
};

struct ucode_patch {
	struct list_head plist;
	void *data;
	unsigned int size;
	u32 patch_id;
	u16 equiv_cpu;
};

struct cont_desc {
	struct microcode_amd *mc;
	u32 cpuid_1_eax;
	u32 psize;
	u8 *data;
	size_t size;
};

enum {
	REGION_INTERSECTS = 0,
	REGION_DISJOINT = 1,
	REGION_MIXED = 2,
};

enum folio_references {
	FOLIOREF_RECLAIM = 0,
	FOLIOREF_RECLAIM_CLEAN = 1,
	FOLIOREF_KEEP = 2,
	FOLIOREF_ACTIVATE = 3,
};

enum pgdat_flags {
	PGDAT_DIRTY = 0,
	PGDAT_WRITEBACK = 1,
	PGDAT_RECLAIM_LOCKED = 2,
};

enum positive_aop_returns {
	AOP_WRITEPAGE_ACTIVATE = 524288,
	AOP_TRUNCATED_PAGE = 524289,
};

enum migrate_reason {
	MR_COMPACTION = 0,
	MR_MEMORY_FAILURE = 1,
	MR_MEMORY_HOTPLUG = 2,
	MR_SYSCALL = 3,
	MR_MEMPOLICY_MBIND = 4,
	MR_NUMA_MISPLACED = 5,
	MR_CONTIG_RANGE = 6,
	MR_LONGTERM_PIN = 7,
	MR_DEMOTION = 8,
	MR_TYPES = 9,
};

enum lruvec_flags {
	LRUVEC_CGROUP_CONGESTED = 0,
	LRUVEC_NODE_CONGESTED = 1,
};

enum scan_balance {
	SCAN_EQUAL = 0,
	SCAN_FRACT = 1,
	SCAN_ANON = 2,
	SCAN_FILE = 3,
};

struct migration_target_control {
	int nid;
	nodemask_t *nmask;
	gfp_t gfp_mask;
};

struct scan_control {
	unsigned long nr_to_reclaim;
	nodemask_t *nodemask;
	struct mem_cgroup *target_mem_cgroup;
	unsigned long anon_cost;
	unsigned long file_cost;
	unsigned int may_deactivate: 2;
	unsigned int force_deactivate: 1;
	unsigned int skipped_deactivate: 1;
	unsigned int may_writepage: 1;
	unsigned int may_unmap: 1;
	unsigned int may_swap: 1;
	unsigned int no_cache_trim_mode: 1;
	unsigned int cache_trim_mode_failed: 1;
	unsigned int proactive: 1;
	unsigned int memcg_low_reclaim: 1;
	unsigned int memcg_low_skipped: 1;
	unsigned int hibernation_mode: 1;
	unsigned int compaction_ready: 1;
	unsigned int cache_trim_mode: 1;
	unsigned int file_is_tiny: 1;
	unsigned int no_demotion: 1;
	s8 order;
	s8 priority;
	s8 reclaim_idx;
	gfp_t gfp_mask;
	unsigned long nr_scanned;
	unsigned long nr_reclaimed;
	struct {
		unsigned int dirty;
		unsigned int unqueued_dirty;
		unsigned int congested;
		unsigned int writeback;
		unsigned int immediate;
		unsigned int file_taken;
		unsigned int taken;
	} nr;
	struct reclaim_state reclaim_state;
};

typedef enum {
	PAGE_KEEP = 0,
	PAGE_ACTIVATE = 1,
	PAGE_SUCCESS = 2,
	PAGE_CLEAN = 3,
} pageout_t;

struct reclaim_stat {
	unsigned int nr_dirty;
	unsigned int nr_unqueued_dirty;
	unsigned int nr_congested;
	unsigned int nr_writeback;
	unsigned int nr_immediate;
	unsigned int nr_pageout;
	unsigned int nr_activate[2];
	unsigned int nr_ref_keep;
	unsigned int nr_unmap_fail;
	unsigned int nr_lazyfree_fail;
};

struct file_clone_range {
	__s64 src_fd;
	__u64 src_offset;
	__u64 src_length;
	__u64 dest_offset;
};

struct fsuuid2 {
	__u8 len;
	__u8 uuid[16];
};

struct fs_sysfs_path {
	__u8 len;
	__u8 name[128];
};

struct fsxattr {
	__u32 fsx_xflags;
	__u32 fsx_extsize;
	__u32 fsx_nextents;
	__u32 fsx_projid;
	__u32 fsx_cowextsize;
	unsigned char fsx_pad[8];
};

struct fiemap {
	__u64 fm_start;
	__u64 fm_length;
	__u32 fm_flags;
	__u32 fm_mapped_extents;
	__u32 fm_extent_count;
	__u32 fm_reserved;
	struct fiemap_extent fm_extents[0];
};

struct space_resv {
	__s16 l_type;
	__s16 l_whence;
	__s64 l_start;
	__s64 l_len;
	__s32 l_sysid;
	__u32 l_pid;
	__s32 l_pad[4];
};

struct probe;

struct kobj_map {
	struct probe *probes[255];
	struct mutex *lock;
};

struct probe {
	struct probe *next;
	dev_t dev;
	unsigned long range;
	struct module *owner;
	kobj_probe_t *get;
	int (*lock)(dev_t, void *);
	void *data;
};

struct pt_filter {
	unsigned long msr_a;
	unsigned long msr_b;
	unsigned long config;
};

struct pt_filters {
	struct pt_filter filter[4];
	unsigned int nr_filters;
};

struct pt {
	struct perf_output_handle handle;
	struct pt_filters filters;
	int handle_nmi;
	int vmx_on;
	u64 output_base;
	u64 output_mask;
};

struct pt_pmu {
	struct pmu pmu;
	u32 caps[8];
	bool vmx;
	bool branch_en_always_on;
	unsigned long max_nonturbo_ratio;
	unsigned int tsc_art_num;
	unsigned int tsc_art_den;
};

struct pt_cap_desc {
	const char *name;
	u32 leaf;
	u8 reg;
	u32 mask;
};

struct pt_address_range {
	unsigned long msr_a;
	unsigned long msr_b;
	unsigned int reg_off;
};

enum pt_capabilities {
	PT_CAP_max_subleaf = 0,
	PT_CAP_cr3_filtering = 1,
	PT_CAP_psb_cyc = 2,
	PT_CAP_ip_filtering = 3,
	PT_CAP_mtc = 4,
	PT_CAP_ptwrite = 5,
	PT_CAP_power_event_trace = 6,
	PT_CAP_event_trace = 7,
	PT_CAP_tnt_disable = 8,
	PT_CAP_topa_output = 9,
	PT_CAP_topa_multiple_entries = 10,
	PT_CAP_single_range_output = 11,
	PT_CAP_output_subsys = 12,
	PT_CAP_payloads_lip = 13,
	PT_CAP_num_address_ranges = 14,
	PT_CAP_mtc_periods = 15,
	PT_CAP_cycle_thresholds = 16,
	PT_CAP_psb_periods = 17,
};

struct topa {
	struct list_head list;
	u64 offset;
	size_t size;
	int last;
	unsigned int z_count;
};

struct topa_entry {
	u64 end: 1;
	u64 rsvd0: 1;
	u64 intr: 1;
	u64 rsvd1: 1;
	u64 stop: 1;
	u64 rsvd2: 1;
	u64 size: 4;
	u64 rsvd3: 2;
	u64 base: 36;
	u64 rsvd4: 16;
};

struct topa_page {
	struct topa_entry table[507];
	struct topa topa;
};

struct dev_ext_attribute {
	struct device_attribute attr;
	void *var;
};

struct pt_buffer {
	struct list_head tables;
	struct topa *first;
	struct topa *last;
	struct topa *cur;
	unsigned int cur_idx;
	size_t output_off;
	unsigned long nr_pages;
	local_t data_size;
	local64_t head;
	bool snapshot;
	bool single;
	long stop_pos;
	long intr_pos;
	struct topa_entry *stop_te;
	struct topa_entry *intr_te;
	void **data_pages;
};

struct vm_stack {
	struct callback_head rcu;
	struct vm_struct *stack_vm_area;
};

struct clone_args {
	__u64 flags;
	__u64 pidfd;
	__u64 child_tid;
	__u64 parent_tid;
	__u64 exit_signal;
	__u64 stack;
	__u64 stack_size;
	__u64 tls;
	__u64 set_tid;
	__u64 set_tid_size;
	__u64 cgroup;
};

typedef int (*proc_visitor)(struct task_struct *, void *);

enum bpf_iter_feature {
	BPF_ITER_RESCHED = 1,
};

struct bpf_iter_target_info {
	struct list_head list;
	const struct bpf_iter_reg *reg_info;
	u32 btf_id;
};

struct bpf_iter_link {
	struct bpf_link link;
	struct bpf_iter_aux_info aux;
	struct bpf_iter_target_info *tinfo;
};

struct bpf_iter_priv_data {
	struct bpf_iter_target_info *tinfo;
	const struct bpf_iter_seq_info *seq_info;
	struct bpf_prog *prog;
	u64 session_id;
	u64 seq_num;
	bool done_stop;
	long: 0;
	u8 target_private[0];
};

typedef u64 (*btf_bpf_for_each_map_elem)(struct bpf_map *, void *, void *, u64);

typedef u64 (*btf_bpf_loop)(u32, void *, void *, u64);

typedef unsigned int (*bpf_dispatcher_fn)(const void *, const struct bpf_insn *, unsigned int (*)(const void *, const struct bpf_insn *));

typedef unsigned int (*bpf_func_t)(const void *, const struct bpf_insn *);

struct bpf_iter_num {
	__u64 __opaque[1];
};

struct bpf_iter_num_kern {
	int cur;
	int end;
};

struct utimbuf {
	__kernel_old_time_t actime;
	__kernel_old_time_t modtime;
};

struct memdev {
	const char *name;
	const struct file_operations *fops;
	fmode_t fmode;
	umode_t mode;
};

struct bts_ctx {
	struct perf_output_handle handle;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct debug_store ds_back;
	int state;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum {
	BTS_STATE_STOPPED = 0,
	BTS_STATE_INACTIVE = 1,
	BTS_STATE_ACTIVE = 2,
};

struct bts_phys {
	struct page *page;
	unsigned long size;
	unsigned long offset;
	unsigned long displacement;
};

struct bts_buffer {
	size_t real_size;
	unsigned int nr_pages;
	unsigned int nr_bufs;
	unsigned int cur_buf;
	bool snapshot;
	local_t data_size;
	local_t head;
	unsigned long end;
	void **data_pages;
	struct bts_phys buf[0];
};

struct rcu_tasks;

typedef void (*rcu_tasks_gp_func_t)(struct rcu_tasks *);

typedef void (*pregp_func_t)(struct list_head *);

typedef void (*pertask_func_t)(struct task_struct *, struct list_head *);

typedef void (*postscan_func_t)(struct list_head *);

typedef void (*holdouts_func_t)(struct list_head *, bool, bool *);

typedef void (*postgp_func_t)(struct rcu_tasks *);

struct rcu_tasks_percpu;

struct rcu_tasks {
	struct rcuwait cbs_wait;
	raw_spinlock_t cbs_gbl_lock;
	struct mutex tasks_gp_mutex;
	int gp_state;
	int gp_sleep;
	int init_fract;
	unsigned long gp_jiffies;
	unsigned long gp_start;
	unsigned long tasks_gp_seq;
	unsigned long n_ipis;
	unsigned long n_ipis_fails;
	struct task_struct *kthread_ptr;
	unsigned long lazy_jiffies;
	rcu_tasks_gp_func_t gp_func;
	pregp_func_t pregp_func;
	pertask_func_t pertask_func;
	postscan_func_t postscan_func;
	holdouts_func_t holdouts_func;
	postgp_func_t postgp_func;
	call_rcu_func_t call_func;
	struct rcu_tasks_percpu __attribute__((btf_type_tag("percpu"))) *rtpcpu;
	int percpu_enqueue_shift;
	int percpu_enqueue_lim;
	int percpu_dequeue_lim;
	unsigned long percpu_dequeue_gpseq;
	struct mutex barrier_q_mutex;
	atomic_t barrier_q_count;
	struct completion barrier_q_completion;
	unsigned long barrier_q_seq;
	char *name;
	char *kname;
};

struct rcu_tasks_percpu {
	struct rcu_segcblist cblist;
	raw_spinlock_t lock;
	unsigned long rtp_jiffies;
	unsigned long rtp_n_lock_retries;
	struct timer_list lazy_timer;
	unsigned int urgent_gp;
	struct work_struct rtp_work;
	struct irq_work rtp_irq_work;
	struct callback_head barrier_q_head;
	struct list_head rtp_blkd_tasks;
	struct list_head rtp_exit_list;
	int cpu;
	struct rcu_tasks *rtpp;
};

struct trc_stall_chk_rdr {
	int nesting;
	int ipi_to_cpu;
	u8 needqs;
};

struct bpf_arena {
	struct bpf_map map;
	u64 user_vm_start;
	u64 user_vm_end;
	struct vm_struct *kern_vm;
	struct maple_tree mt;
	struct list_head vma_list;
	struct mutex lock;
};

struct vma_list {
	struct vm_area_struct *vma;
	struct list_head head;
	atomic_t mmap_count;
};

struct vfree_deferred {
	struct llist_head list;
	struct work_struct wq;
};

struct vmap_block_queue {
	spinlock_t lock;
	struct list_head free;
	struct xarray vmap_blocks;
};

struct vmap_pool {
	struct list_head head;
	unsigned long len;
};

struct rb_list {
	struct rb_root root;
	struct list_head head;
	spinlock_t lock;
};

struct vmap_node {
	struct vmap_pool pool[256];
	spinlock_t pool_lock;
	bool skip_populate;
	struct rb_list busy;
	struct rb_list lazy;
	struct list_head purge_list;
	struct work_struct purge_work;
	unsigned long nr_purged;
};

struct vmap_area {
	unsigned long va_start;
	unsigned long va_end;
	struct rb_node rb_node;
	struct list_head list;
	union {
		unsigned long subtree_max_size;
		struct vm_struct *vm;
	};
	unsigned long flags;
};

enum memcg_stat_item {
	MEMCG_SWAP = 43,
	MEMCG_SOCK = 44,
	MEMCG_PERCPU_B = 45,
	MEMCG_VMALLOC = 46,
	MEMCG_KMEM = 47,
	MEMCG_ZSWAP_B = 48,
	MEMCG_ZSWAPPED = 49,
	MEMCG_NR_STAT = 50,
};

enum fit_type {
	NOTHING_FIT = 0,
	FL_FIT_TYPE = 1,
	LE_FIT_TYPE = 2,
	RE_FIT_TYPE = 3,
	NE_FIT_TYPE = 4,
};

typedef unsigned int kasan_vmalloc_flags_t;

struct vmap_block {
	spinlock_t lock;
	struct vmap_area *va;
	unsigned long free;
	unsigned long dirty;
	unsigned long used_map[16];
	unsigned long dirty_min;
	unsigned long dirty_max;
	struct list_head free_list;
	struct callback_head callback_head;
	struct list_head purge;
	unsigned int cpu;
};

struct fs_pin {
	wait_queue_head_t wait;
	int done;
	struct hlist_node s_list;
	struct hlist_node m_list;
	void (*kill)(struct fs_pin *);
};

struct wrapper {
	cmp_func_t cmp;
	swap_func_t swap;
};

enum {
	PERCPU_REF_INIT_ATOMIC = 1,
	PERCPU_REF_INIT_DEAD = 2,
	PERCPU_REF_ALLOW_REINIT = 4,
};

struct uevent_sock {
	struct list_head list;
	struct sock *sk;
};

enum {
	PERF_TXN_ELISION = 1ULL,
	PERF_TXN_TRANSACTION = 2ULL,
	PERF_TXN_SYNC = 4ULL,
	PERF_TXN_ASYNC = 8ULL,
	PERF_TXN_RETRY = 16ULL,
	PERF_TXN_CONFLICT = 32ULL,
	PERF_TXN_CAPACITY_WRITE = 64ULL,
	PERF_TXN_CAPACITY_READ = 128ULL,
	PERF_TXN_MAX = 256ULL,
	PERF_TXN_ABORT_MASK = 18446744069414584320ULL,
	PERF_TXN_ABORT_SHIFT = 32ULL,
};

struct bts_record {
	u64 from;
	u64 to;
	u64 flags;
};

struct pebs_record_core {
	u64 flags;
	u64 ip;
	u64 ax;
	u64 bx;
	u64 cx;
	u64 dx;
	u64 si;
	u64 di;
	u64 bp;
	u64 sp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

struct pebs_record_nhm {
	u64 flags;
	u64 ip;
	u64 ax;
	u64 bx;
	u64 cx;
	u64 dx;
	u64 si;
	u64 di;
	u64 bp;
	u64 sp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 status;
	u64 dla;
	u64 dse;
	u64 lat;
};

struct pebs_basic {
	u64 format_size;
	u64 ip;
	u64 applicable_counters;
	u64 tsc;
};

union intel_x86_pebs_dse {
	u64 val;
	struct {
		unsigned int ld_dse: 4;
		unsigned int ld_stlb_miss: 1;
		unsigned int ld_locked: 1;
		unsigned int ld_data_blk: 1;
		unsigned int ld_addr_blk: 1;
		unsigned int ld_reserved: 24;
	};
	struct {
		unsigned int st_l1d_hit: 1;
		unsigned int st_reserved1: 3;
		unsigned int st_stlb_miss: 1;
		unsigned int st_locked: 1;
		unsigned int st_reserved2: 26;
	};
	struct {
		unsigned int st_lat_dse: 4;
		unsigned int st_lat_stlb_miss: 1;
		unsigned int st_lat_locked: 1;
		unsigned int ld_reserved3: 26;
	};
	struct {
		unsigned int mtl_dse: 5;
		unsigned int mtl_locked: 1;
		unsigned int mtl_stlb_miss: 1;
		unsigned int mtl_fwd_blk: 1;
		unsigned int ld_reserved4: 24;
	};
};

struct pebs_gprs {
	u64 flags;
	u64 ip;
	u64 ax;
	u64 cx;
	u64 dx;
	u64 bx;
	u64 sp;
	u64 bp;
	u64 si;
	u64 di;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
};

struct lbr_entry {
	u64 from;
	u64 to;
	u64 info;
};

struct pebs_record_skl {
	u64 flags;
	u64 ip;
	u64 ax;
	u64 bx;
	u64 cx;
	u64 dx;
	u64 si;
	u64 di;
	u64 bp;
	u64 sp;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 status;
	u64 dla;
	u64 dse;
	u64 lat;
	u64 real_ip;
	u64 tsx_tuning;
	u64 tsc;
};

struct pebs_meminfo {
	u64 address;
	u64 aux;
	u64 latency;
	u64 tsx_tuning;
};

struct pebs_xmm {
	u64 xmm[32];
};

enum {
	PER_LINUX = 0,
	PER_LINUX_32BIT = 8388608,
	PER_LINUX_FDPIC = 524288,
	PER_SVR4 = 68157441,
	PER_SVR3 = 83886082,
	PER_SCOSVR3 = 117440515,
	PER_OSR5 = 100663299,
	PER_WYSEV386 = 83886084,
	PER_ISCR4 = 67108869,
	PER_BSD = 6,
	PER_SUNOS = 67108870,
	PER_XENIX = 83886087,
	PER_LINUX32 = 8,
	PER_LINUX32_3GB = 134217736,
	PER_IRIX32 = 67108873,
	PER_IRIXN32 = 67108874,
	PER_IRIX64 = 67108875,
	PER_RISCOS = 12,
	PER_SOLARIS = 67108877,
	PER_UW7 = 68157454,
	PER_OSF4 = 15,
	PER_HPUX = 16,
	PER_MASK = 255,
};

enum uts_proc {
	UTS_PROC_ARCH = 0,
	UTS_PROC_OSTYPE = 1,
	UTS_PROC_OSRELEASE = 2,
	UTS_PROC_VERSION = 3,
	UTS_PROC_HOSTNAME = 4,
	UTS_PROC_DOMAINNAME = 5,
};

struct tms {
	__kernel_clock_t tms_utime;
	__kernel_clock_t tms_stime;
	__kernel_clock_t tms_cutime;
	__kernel_clock_t tms_cstime;
};

struct old_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
};

struct oldold_utsname {
	char sysname[9];
	char nodename[9];
	char release[9];
	char version[9];
	char machine[9];
};

struct rlimit64 {
	__u64 rlim_cur;
	__u64 rlim_max;
};

struct getcpu_cache {
	unsigned long blob[16];
};

struct sysinfo {
	__kernel_long_t uptime;
	__kernel_ulong_t loads[3];
	__kernel_ulong_t totalram;
	__kernel_ulong_t freeram;
	__kernel_ulong_t sharedram;
	__kernel_ulong_t bufferram;
	__kernel_ulong_t totalswap;
	__kernel_ulong_t freeswap;
	__u16 procs;
	__u16 pad;
	__kernel_ulong_t totalhigh;
	__kernel_ulong_t freehigh;
	__u32 mem_unit;
	char _f[0];
};

struct prctl_mm_map {
	__u64 start_code;
	__u64 end_code;
	__u64 start_data;
	__u64 end_data;
	__u64 start_brk;
	__u64 brk;
	__u64 start_stack;
	__u64 arg_start;
	__u64 arg_end;
	__u64 env_start;
	__u64 env_end;
	__u64 *auxv;
	__u32 auxv_size;
	__u32 exe_fd;
};

struct bpf_async_cb {
	struct bpf_map *map;
	struct bpf_prog *prog;
	void __attribute__((btf_type_tag("rcu"))) *callback_fn;
	void *value;
	union {
		struct callback_head rcu;
		struct work_struct delete_work;
	};
	u64 flags;
};

struct bpf_hrtimer {
	struct bpf_async_cb cb;
	struct hrtimer timer;
	atomic_t cancelling;
};

struct bpf_bprintf_buffers {
	char bin_args[512];
	char buf[1024];
};

enum {
	BPF_F_INDEX_MASK = 4294967295ULL,
	BPF_F_CURRENT_CPU = 4294967295ULL,
	BPF_F_CTXLEN_MASK = 4503595332403200ULL,
};

enum bpf_async_type {
	BPF_ASYNC_TYPE_TIMER = 0,
};

enum {
	BPF_F_TIMER_ABS = 1,
	BPF_F_TIMER_CPU_PIN = 2,
};

typedef u64 (*btf_bpf_map_lookup_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_update_elem)(struct bpf_map *, void *, void *, u64);

typedef u64 (*btf_bpf_map_delete_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_push_elem)(struct bpf_map *, void *, u64);

typedef u64 (*btf_bpf_map_pop_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_peek_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_lookup_percpu_elem)(struct bpf_map *, void *, u32);

typedef u64 (*btf_bpf_get_smp_processor_id)();

typedef u64 (*btf_bpf_get_numa_node_id)();

typedef u64 (*btf_bpf_ktime_get_ns)();

typedef u64 (*btf_bpf_ktime_get_boot_ns)();

typedef u64 (*btf_bpf_ktime_get_coarse_ns)();

typedef u64 (*btf_bpf_ktime_get_tai_ns)();

typedef u64 (*btf_bpf_get_current_pid_tgid)();

typedef u64 (*btf_bpf_get_current_uid_gid)();

typedef u64 (*btf_bpf_get_current_comm)(char *, u32);

typedef u64 (*btf_bpf_spin_lock)(struct bpf_spin_lock *);

typedef u64 (*btf_bpf_spin_unlock)(struct bpf_spin_lock *);

typedef u64 (*btf_bpf_jiffies64)();

typedef u64 (*btf_bpf_strtol)(const char *, size_t, u64, long *);

typedef u64 (*btf_bpf_strtoul)(const char *, size_t, u64, unsigned long *);

typedef u64 (*btf_bpf_strncmp)(const char *, u32, const char *);

struct bpf_pidns_info;

typedef u64 (*btf_bpf_get_ns_current_pid_tgid)(u64, u64, struct bpf_pidns_info *, u32);

struct bpf_pidns_info {
	__u32 pid;
	__u32 tgid;
};

typedef u64 (*btf_bpf_event_output_data)(void *, struct bpf_map *, u64, void *, u64);

typedef u64 (*btf_bpf_copy_from_user)(void *, u32, const void __attribute__((btf_type_tag("user"))) *);

typedef u64 (*btf_bpf_copy_from_user_task)(void *, u32, const void __attribute__((btf_type_tag("user"))) *, struct task_struct *, u64);

typedef u64 (*btf_bpf_per_cpu_ptr)(const void *, u32);

typedef u64 (*btf_bpf_this_cpu_ptr)(const void *);

typedef u64 (*btf_bpf_snprintf)(char *, u32, char *, const void *, u32);

struct bpf_async_kern;

typedef u64 (*btf_bpf_timer_init)(struct bpf_async_kern *, struct bpf_map *, u64);

struct bpf_async_kern {
	union {
		struct bpf_async_cb *cb;
		struct bpf_hrtimer *timer;
	};
	struct bpf_spin_lock lock;
};

typedef u64 (*btf_bpf_timer_set_callback)(struct bpf_async_kern *, void *, struct bpf_prog_aux *);

typedef u64 (*btf_bpf_timer_start)(struct bpf_async_kern *, u64, u64);

typedef u64 (*btf_bpf_timer_cancel)(struct bpf_async_kern *);

typedef u64 (*btf_bpf_kptr_xchg)(void *, void *);

typedef u64 (*btf_bpf_dynptr_from_mem)(void *, u32, u64, struct bpf_dynptr_kern *);

typedef u64 (*btf_bpf_dynptr_read)(void *, u32, const struct bpf_dynptr_kern *, u32, u64);

typedef u64 (*btf_bpf_dynptr_write)(const struct bpf_dynptr_kern *, u32, void *, u32, u64);

typedef u64 (*btf_bpf_dynptr_data)(const struct bpf_dynptr_kern *, u32, u32);

struct bpf_refcount {
	__u32 __opaque[1];
};

struct bpf_rb_node_kern {
	struct rb_node rb_node;
	void *owner;
};

struct bpf_rb_node {
	__u64 __opaque[4];
};

struct bpf_timer {
	__u64 __opaque[2];
};

struct bpf_dynptr {
	__u64 __opaque[2];
};

struct bpf_list_node_kern {
	struct list_head list_head;
	void *owner;
};

struct bpf_list_node {
	__u64 __opaque[3];
};

typedef unsigned long (*bpf_ctx_copy_t)(void *, const void *, unsigned long, unsigned long);

struct bpf_rb_root {
	__u64 __opaque[2];
};

struct bpf_list_head {
	__u64 __opaque[2];
};

struct bpf_throw_ctx {
	struct bpf_prog_aux *aux;
	u64 sp;
	u64 bp;
	int cnt;
};

struct fid {
	union {
		struct {
			u32 ino;
			u32 gen;
			u32 parent_ino;
			u32 parent_gen;
		} i32;
		struct {
			u64 ino;
			u32 gen;
		} __attribute__((packed)) i64;
		struct {
			u32 block;
			u16 partref;
			u16 parent_partref;
			u32 generation;
			u32 parent_block;
			u32 parent_generation;
		} udf;
		struct {
			struct {} __empty_raw;
			__u32 raw[0];
		};
	};
};

enum {
	DIR_OFFSET_MIN = 2,
};

enum fid_type {
	FILEID_ROOT = 0,
	FILEID_INO32_GEN = 1,
	FILEID_INO32_GEN_PARENT = 2,
	FILEID_BTRFS_WITHOUT_PARENT = 77,
	FILEID_BTRFS_WITH_PARENT = 78,
	FILEID_BTRFS_WITH_PARENT_ROOT = 79,
	FILEID_UDF_WITHOUT_PARENT = 81,
	FILEID_UDF_WITH_PARENT = 82,
	FILEID_NILFS_WITHOUT_PARENT = 97,
	FILEID_NILFS_WITH_PARENT = 98,
	FILEID_FAT_WITHOUT_PARENT = 113,
	FILEID_FAT_WITH_PARENT = 114,
	FILEID_INO64_GEN = 129,
	FILEID_INO64_GEN_PARENT = 130,
	FILEID_LUSTRE = 151,
	FILEID_BCACHEFS_WITHOUT_PARENT = 177,
	FILEID_BCACHEFS_WITH_PARENT = 178,
	FILEID_KERNFS = 254,
	FILEID_INVALID = 255,
};

struct simple_transaction_argresp {
	ssize_t size;
	char data[0];
};

struct simple_attr {
	int (*get)(void *, u64 *);
	int (*set)(void *, u64);
	char get_buf[24];
	char set_buf[24];
	void *data;
	const char *fmt;
	struct mutex mutex;
};

enum {
	LBR_NONE = 0,
	LBR_VALID = 1,
};

enum {
	ARCH_LBR_BR_TYPE_JCC = 0,
	ARCH_LBR_BR_TYPE_NEAR_IND_JMP = 1,
	ARCH_LBR_BR_TYPE_NEAR_REL_JMP = 2,
	ARCH_LBR_BR_TYPE_NEAR_IND_CALL = 3,
	ARCH_LBR_BR_TYPE_NEAR_REL_CALL = 4,
	ARCH_LBR_BR_TYPE_NEAR_RET = 5,
	ARCH_LBR_BR_TYPE_KNOWN_MAX = 5,
	ARCH_LBR_BR_TYPE_MAP_MAX = 16,
};

struct x86_perf_task_context_opt {
	int lbr_callstack_users;
	int lbr_stack_state;
	int log_id;
};

struct x86_perf_task_context_arch_lbr {
	struct x86_perf_task_context_opt opt;
	struct lbr_entry entries[0];
};

struct x86_perf_task_context {
	u64 lbr_sel;
	int tos;
	int valid_lbrs;
	struct x86_perf_task_context_opt opt;
	struct lbr_entry lbr[32];
};

union cpuid28_ebx {
	struct {
		unsigned int lbr_cpl: 1;
		unsigned int lbr_filter: 1;
		unsigned int lbr_call_stack: 1;
	} split;
	unsigned int full;
};

union cpuid28_eax {
	struct {
		unsigned int lbr_depth_mask: 8;
		unsigned int reserved: 22;
		unsigned int lbr_deep_c_reset: 1;
		unsigned int lbr_lip: 1;
	} split;
	unsigned int full;
};

union cpuid28_ecx {
	struct {
		unsigned int lbr_mispred: 1;
		unsigned int lbr_timed_lbr: 1;
		unsigned int lbr_br_type: 1;
		unsigned int reserved: 13;
		unsigned int lbr_counters: 4;
	} split;
	unsigned int full;
};

struct arch_lbr_state {
	u64 lbr_ctl;
	u64 lbr_depth;
	u64 ler_from;
	u64 ler_to;
	u64 ler_info;
	struct lbr_entry entries[0];
};

struct x86_perf_task_context_arch_lbr_xsave {
	struct x86_perf_task_context_opt opt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	union {
		struct xregs_state xsave;
		struct {
			struct fxregs_state i387;
			struct xstate_header header;
			struct arch_lbr_state lbr;
			long: 64;
			long: 64;
			long: 64;
		};
	};
};

struct x86_pmu_lbr {
	unsigned int nr;
	unsigned int from;
	unsigned int to;
	unsigned int info;
	bool has_callstack;
};

enum spectre_v2_mitigation {
	SPECTRE_V2_NONE = 0,
	SPECTRE_V2_RETPOLINE = 1,
	SPECTRE_V2_LFENCE = 2,
	SPECTRE_V2_EIBRS = 3,
	SPECTRE_V2_EIBRS_RETPOLINE = 4,
	SPECTRE_V2_EIBRS_LFENCE = 5,
	SPECTRE_V2_IBRS = 6,
};

typedef u16 uint16_t;

typedef u8 uint8_t;

enum pg_level {
	PG_LEVEL_NONE = 0,
	PG_LEVEL_4K = 1,
	PG_LEVEL_2M = 2,
	PG_LEVEL_1G = 3,
	PG_LEVEL_512G = 4,
	PG_LEVEL_NUM = 5,
};

struct map_range {
	unsigned long start;
	unsigned long end;
	unsigned int page_size_mask;
};

struct memblock_type {
	unsigned long cnt;
	unsigned long max;
	phys_addr_t total_size;
	struct memblock_region *regions;
	char *name;
};

struct sched_clock_data {
	u64 tick_raw;
	u64 tick_gtod;
	u64 clock;
};

struct bpf_bloom_filter {
	struct bpf_map map;
	u32 bitset_mask;
	u32 hash_seed;
	u32 nr_hash_funcs;
	unsigned long bitset[0];
};

struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

enum string_size_units {
	STRING_UNITS_10 = 0,
	STRING_UNITS_2 = 1,
	STRING_UNITS_MASK = 1,
	STRING_UNITS_NO_SPACE = 1073741824,
	STRING_UNITS_NO_BYTES = 2147483648,
};

struct strarray {
	char **array;
	size_t n;
};

struct kcore_list {
	struct list_head list;
	unsigned long addr;
	size_t size;
	int type;
};

enum kcore_type {
	KCORE_TEXT = 0,
	KCORE_VMALLOC = 1,
	KCORE_RAM = 2,
	KCORE_VMEMMAP = 3,
	KCORE_USER = 4,
};

struct x86_mapping_info {
	void * (*alloc_pgt_page)(void *);
	void *context;
	unsigned long page_flag;
	unsigned long offset;
	bool direct_gbpages;
	unsigned long kernpg_flag;
};

struct dma_sgt_handle {
	struct sg_table sgt;
	struct page **pages;
};

struct dma_devres {
	size_t size;
	void *vaddr;
	dma_addr_t dma_handle;
	unsigned long attrs;
};

struct bpf_local_storage_map_bucket;

struct bpf_local_storage_map {
	struct bpf_map map;
	struct bpf_local_storage_map_bucket *buckets;
	u32 bucket_log;
	u16 elem_size;
	u16 cache_idx;
	struct bpf_mem_alloc selem_ma;
	struct bpf_mem_alloc storage_ma;
	bool bpf_ma;
};

struct bpf_local_storage_map_bucket {
	struct hlist_head list;
	raw_spinlock_t lock;
};

struct bpf_local_storage_data {
	struct bpf_local_storage_map __attribute__((btf_type_tag("rcu"))) *smap;
	u8 data[0];
};

struct bpf_local_storage_elem {
	struct hlist_node map_node;
	struct hlist_node snode;
	struct bpf_local_storage __attribute__((btf_type_tag("rcu"))) *local_storage;
	struct callback_head rcu;
	long: 64;
	struct bpf_local_storage_data sdata;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct bpf_local_storage_cache {
	spinlock_t idx_lock;
	u64 idx_usage_counts[16];
};

struct pcpu_block_md {
	int scan_hint;
	int scan_hint_start;
	int contig_hint;
	int contig_hint_start;
	int left_free;
	int right_free;
	int first_free;
	int nr_bits;
};

struct pcpu_chunk {
	struct list_head list;
	int free_bytes;
	struct pcpu_block_md chunk_md;
	unsigned long *bound_map;
	void *base_addr;
	unsigned long *alloc_map;
	struct pcpu_block_md *md_blocks;
	void *data;
	bool immutable;
	bool isolated;
	int start_offset;
	int end_offset;
	int nr_pages;
	int nr_populated;
	int nr_empty_pop_pages;
	unsigned long populated[0];
};

struct pcpu_group_info {
	int nr_units;
	unsigned long base_offset;
	unsigned int *cpu_map;
};

struct pcpu_alloc_info {
	size_t static_size;
	size_t reserved_size;
	size_t dyn_size;
	size_t unit_size;
	size_t atom_size;
	size_t alloc_size;
	size_t __ai_size;
	int nr_groups;
	struct pcpu_group_info groups[0];
};

struct rnd_state {
	__u32 s1;
	__u32 s2;
	__u32 s3;
	__u32 s4;
};

struct region {
	unsigned int start;
	unsigned int off;
	unsigned int group_len;
	unsigned int end;
	unsigned int nbits;
};

struct xa_limit {
	u32 max;
	u32 min;
};

enum cp_error_code {
	CP_EC = 32767,
	CP_RET = 1,
	CP_IRET = 2,
	CP_ENDBR = 3,
	CP_RSTRORSSP = 4,
	CP_SETSSBSY = 5,
	CP_ENCL = 32768,
};

enum {
	IRQ_STARTUP_NORMAL = 0,
	IRQ_STARTUP_MANAGED = 1,
	IRQ_STARTUP_ABORT = 2,
};

enum audit_ntp_type {
	AUDIT_NTP_OFFSET = 0,
	AUDIT_NTP_FREQ = 1,
	AUDIT_NTP_STATUS = 2,
	AUDIT_NTP_TAI = 3,
	AUDIT_NTP_TICK = 4,
	AUDIT_NTP_ADJUST = 5,
	AUDIT_NTP_NVALS = 6,
};

struct audit_ntp_data {};

struct alarm_base {
	spinlock_t lock;
	struct timerqueue_head timerqueue;
	ktime_t (*get_ktime)();
	void (*get_timespec)(struct timespec64 *);
	clockid_t base_clockid;
};

struct platform_driver {
	int (*probe)(struct platform_device *);
	int (*remove)(struct platform_device *);
	void (*remove_new)(struct platform_device *);
	void (*shutdown)(struct platform_device *);
	int (*suspend)(struct platform_device *, pm_message_t);
	int (*resume)(struct platform_device *);
	struct device_driver driver;
	const struct platform_device_id *id_table;
	bool prevent_deferred_probe;
	bool driver_managed_dma;
};

enum alarmtimer_restart {
	ALARMTIMER_NORESTART = 0,
	ALARMTIMER_RESTART = 1,
};

enum alarmtimer_type {
	ALARM_REALTIME = 0,
	ALARM_BOOTTIME = 1,
	ALARM_NUMTYPE = 2,
	ALARM_REALTIME_FREEZER = 3,
	ALARM_BOOTTIME_FREEZER = 4,
};

struct alarm {
	struct timerqueue_node node;
	struct hrtimer timer;
	enum alarmtimer_restart (*function)(struct alarm *, ktime_t);
	enum alarmtimer_type type;
	int state;
	void *data;
};

enum behavior {
	EXCLUSIVE = 0,
	SHARED = 1,
	DROP = 2,
};

struct wait_page_key {
	struct folio *folio;
	int bit_nr;
	int page_match;
};

enum file_time_flags {
	S_ATIME = 1,
	S_MTIME = 2,
	S_CTIME = 4,
	S_VERSION = 8,
};

struct lwq {
	spinlock_t lock;
	struct llist_node *ready;
	struct llist_head new;
};

struct reciprocal_value_adv {
	u32 m;
	u8 sh;
	u8 exp;
	bool is_wide_m;
};

struct container_dev {
	struct device dev;
	int (*offline)(struct container_dev *);
};

typedef __u64 __le64;

typedef struct {
	unsigned long key[2];
} hsiphash_key_t;

struct real_mode_header {
	u32 text_start;
	u32 ro_end;
	u32 trampoline_start;
	u32 trampoline_header;
	u32 trampoline_start64;
	u32 trampoline_pgd;
	u32 machine_real_restart_asm;
	u32 machine_real_restart_seg;
};

struct trampoline_header {
	u64 start;
	u64 efer;
	u32 cr4;
	u32 flags;
	u32 lock;
};

enum kernel_gp_hint {
	GP_NO_HINT = 0,
	GP_NON_CANONICAL = 1,
	GP_CANONICAL = 2,
};

enum x86_hypervisor_type {
	X86_HYPER_NATIVE = 0,
	X86_HYPER_VMWARE = 1,
	X86_HYPER_MS_HYPERV = 2,
	X86_HYPER_XEN_PV = 3,
	X86_HYPER_XEN_HVM = 4,
	X86_HYPER_KVM = 5,
	X86_HYPER_JAILHOUSE = 6,
	X86_HYPER_ACRN = 7,
};

struct machine_ops {
	void (*restart)(char *);
	void (*halt)();
	void (*power_off)();
	void (*shutdown)();
	void (*crash_shutdown)(struct pt_regs *);
	void (*emergency_restart)();
};

typedef void (*nmi_shootdown_cb)(int, struct pt_regs *);

struct hpet_channel;

struct hpet_base {
	unsigned int nr_channels;
	unsigned int nr_clockevents;
	unsigned int boot_cfg;
	struct hpet_channel *channels;
};

enum hpet_mode {
	HPET_MODE_UNUSED = 0,
	HPET_MODE_LEGACY = 1,
	HPET_MODE_CLOCKEVT = 2,
	HPET_MODE_DEVICE = 3,
};

struct hpet_channel {
	struct clock_event_device evt;
	unsigned int num;
	unsigned int cpu;
	unsigned int irq;
	unsigned int in_use;
	enum hpet_mode mode;
	unsigned int boot_cfg;
	char name[10];
	long: 64;
	long: 64;
	long: 64;
};

struct taint_flag {
	char c_true;
	char c_false;
	bool module;
};

enum con_flush_mode {
	CONSOLE_FLUSH_PENDING = 0,
	CONSOLE_REPLAY_ALL = 1,
};

enum error_detector {
	ERROR_DETECTOR_KFENCE = 0,
	ERROR_DETECTOR_KASAN = 1,
	ERROR_DETECTOR_WARN = 2,
};

enum ftrace_dump_mode {
	DUMP_NONE = 0,
	DUMP_ALL = 1,
	DUMP_ORIG = 2,
	DUMP_PARAM = 3,
};

struct warn_args {
	const char *fmt;
	va_list args;
};

struct tk_read_base {
	struct clocksource *clock;
	u64 mask;
	u64 cycle_last;
	u32 mult;
	u32 shift;
	u64 xtime_nsec;
	ktime_t base;
	u64 base_real;
};

struct timekeeper {
	struct tk_read_base tkr_mono;
	struct tk_read_base tkr_raw;
	u64 xtime_sec;
	unsigned long ktime_sec;
	struct timespec64 wall_to_monotonic;
	ktime_t offs_real;
	ktime_t offs_boot;
	ktime_t offs_tai;
	s32 tai_offset;
	unsigned int clock_was_set_seq;
	u8 cs_was_changed_seq;
	ktime_t next_leap_ktime;
	u64 raw_sec;
	struct timespec64 monotonic_to_boot;
	u64 cycle_interval;
	u64 xtime_interval;
	s64 xtime_remainder;
	u64 raw_interval;
	u64 ntp_tick;
	s64 ntp_error;
	u32 ntp_error_shift;
	u32 ntp_err_mult;
	u32 skip_second_overflow;
};

struct bpf_empty_prog_array {
	struct bpf_prog_array hdr;
	struct bpf_prog *null_prog;
};

struct bpf_prog_dummy {
	struct bpf_prog prog;
};

enum page_size_enum {
	__PAGE_SIZE = 4096,
};

enum bpf_text_poke_type {
	BPF_MOD_CALL = 0,
	BPF_MOD_JUMP = 1,
};

typedef u64 (*btf_bpf_user_rnd_u32)();

typedef u64 (*btf_bpf_get_raw_cpu_id)();

struct flock {
	short l_type;
	short l_whence;
	__kernel_off_t l_start;
	__kernel_off_t l_len;
	__kernel_pid_t l_pid;
};

struct f_owner_ex {
	int type;
	__kernel_pid_t pid;
};

typedef struct {
	__u8 b[16];
} guid_t;

struct platform_object {
	struct platform_device pdev;
	char name[0];
};

struct irq_affinity {
	unsigned int pre_vectors;
	unsigned int post_vectors;
	unsigned int nr_sets;
	unsigned int set_size[4];
	void (*calc_sets)(struct irq_affinity *, unsigned int);
	void *priv;
};

struct irq_affinity_devres {
	unsigned int count;
	unsigned int irq[0];
};

struct pt_regs_offset {
	const char *name;
	int offset;
};

enum x86_regset_32 {
	REGSET32_GENERAL = 0,
	REGSET32_FP = 1,
	REGSET32_XFP = 2,
	REGSET32_XSTATE = 3,
	REGSET32_TLS = 4,
	REGSET32_IOPERM = 5,
};

enum x86_regset_64 {
	REGSET64_GENERAL = 0,
	REGSET64_FP = 1,
	REGSET64_IOPERM = 2,
	REGSET64_XSTATE = 3,
	REGSET64_SSP = 4,
};

struct resource_entry {
	struct list_head node;
	struct resource *res;
	resource_size_t offset;
	struct resource __res;
};

struct resource_constraint {
	resource_size_t min;
	resource_size_t max;
	resource_size_t align;
	resource_size_t (*alignf)(void *, const struct resource *, resource_size_t, resource_size_t);
	void *alignf_data;
};

struct region_devres {
	struct resource *parent;
	resource_size_t start;
	resource_size_t n;
};

enum wd_read_status {
	WD_READ_SUCCESS = 0,
	WD_READ_UNSTABLE = 1,
	WD_READ_SKIP = 2,
};

enum bpf_lru_list_type {
	BPF_LRU_LIST_T_ACTIVE = 0,
	BPF_LRU_LIST_T_INACTIVE = 1,
	BPF_LRU_LIST_T_FREE = 2,
	BPF_LRU_LOCAL_LIST_T_FREE = 3,
	BPF_LRU_LOCAL_LIST_T_PENDING = 4,
};

struct bpf_mprog_fp {
	struct bpf_prog *prog;
};

struct bpf_mprog_bundle;

struct bpf_mprog_entry {
	struct bpf_mprog_fp fp_items[64];
	struct bpf_mprog_bundle *parent;
};

struct bpf_mprog_cp {
	struct bpf_link *link;
};

struct bpf_mprog_bundle {
	struct bpf_mprog_entry a;
	struct bpf_mprog_entry b;
	struct bpf_mprog_cp cp_items[64];
	struct bpf_prog *ref;
	atomic64_t revision;
	u32 count;
};

struct bpf_tuple {
	struct bpf_prog *prog;
	struct bpf_link *link;
};

struct fprop_global {
	struct percpu_counter events;
	unsigned int period;
	seqcount_t sequence;
};

struct wb_domain {
	spinlock_t lock;
	struct fprop_global completions;
	struct timer_list period_timer;
	unsigned long period_time;
	unsigned long dirty_limit_tstamp;
	unsigned long dirty_limit;
};

enum wb_stat_item {
	WB_RECLAIMABLE = 0,
	WB_WRITEBACK = 1,
	WB_DIRTIED = 2,
	WB_WRITTEN = 3,
	NR_WB_STAT_ITEMS = 4,
};

enum {
	XA_CHECK_SCHED = 4096,
};

struct dirty_throttle_control {
	struct bdi_writeback *wb;
	struct fprop_local_percpu *wb_completions;
	unsigned long avail;
	unsigned long dirty;
	unsigned long thresh;
	unsigned long bg_thresh;
	unsigned long wb_dirty;
	unsigned long wb_thresh;
	unsigned long wb_bg_thresh;
	unsigned long pos_ratio;
};

struct wb_lock_cookie {
	bool locked;
	unsigned long flags;
};

typedef int (*writepage_t)(struct folio *, struct writeback_control *, void *);

struct simple_xattr {
	struct rb_node rb_node;
	char *name;
	size_t size;
	char value[0];
};

struct xattr_name;

struct xattr_ctx {
	union {
		const void __attribute__((btf_type_tag("user"))) *cvalue;
		void __attribute__((btf_type_tag("user"))) *value;
	};
	void *kvalue;
	size_t size;
	struct xattr_name *kname;
	unsigned int flags;
};

struct xattr_name {
	char name[256];
};

struct simple_xattrs {
	struct rb_root rb_root;
	rwlock_t lock;
};

union nested_table {
	union nested_table __attribute__((btf_type_tag("rcu"))) *table;
	struct rhash_lock_head __attribute__((btf_type_tag("rcu"))) *bucket;
};

struct rhashtable_walker {
	struct list_head list;
	struct bucket_table *tbl;
};

struct rhashtable_iter {
	struct rhashtable *ht;
	struct rhash_head *p;
	struct rhlist_head *list;
	struct rhashtable_walker walker;
	unsigned int slot;
	unsigned int skip;
	bool end_of_table;
};

struct idt_bits {
	u16 ist: 3;
	u16 zero: 5;
	u16 type: 5;
	u16 dpl: 2;
	u16 p: 1;
};

struct gate_struct {
	u16 offset_low;
	u16 segment;
	struct idt_bits bits;
	u16 offset_middle;
	u32 offset_high;
	u32 reserved;
};

typedef struct gate_struct gate_desc;

enum x86_hardware_subarch {
	X86_SUBARCH_PC = 0,
	X86_SUBARCH_LGUEST = 1,
	X86_SUBARCH_XEN = 2,
	X86_SUBARCH_INTEL_MID = 3,
	X86_SUBARCH_CE4100 = 4,
	X86_NR_SUBARCHS = 5,
};

enum {
	GATE_INTERRUPT = 14,
	GATE_TRAP = 15,
	GATE_CALL = 12,
	GATE_TASK = 5,
};

struct boot_params_to_save {
	unsigned int start;
	unsigned int len;
};

struct idt_data {
	unsigned int vector;
	unsigned int segment;
	struct idt_bits bits;
	const void *addr;
};

typedef struct {
	unsigned int __nmi_count;
	unsigned int apic_timer_irqs;
	unsigned int irq_spurious_count;
	unsigned int icr_read_retry_count;
	unsigned int x86_platform_ipis;
	unsigned int apic_perf_irqs;
	unsigned int apic_irq_work_irqs;
	unsigned int irq_tlb_count;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
} irq_cpustat_t;

struct muldiv {
	u32 multiplier;
	u32 divider;
};

struct freq_desc {
	bool use_msr_plat;
	struct muldiv muldiv[16];
	u32 freqs[16];
	u32 mask;
};

struct sku_microcode {
	u8 model;
	u8 stepping;
	u32 microcode;
};

struct _tlb_table {
	unsigned char descriptor;
	char tlb_type;
	unsigned int entries;
	char info[128];
};

enum split_lock_detect_state {
	sld_off = 0,
	sld_warn = 1,
	sld_fatal = 2,
	sld_ratelimit = 3,
};

struct console_cmdline {
	char name[16];
	int index;
	bool user_specified;
	char *options;
};

enum nbcon_prio {
	NBCON_PRIO_NONE = 0,
	NBCON_PRIO_NORMAL = 1,
	NBCON_PRIO_EMERGENCY = 2,
	NBCON_PRIO_PANIC = 3,
	NBCON_PRIO_MAX = 4,
};

enum cons_flags {
	CON_PRINTBUFFER = 1,
	CON_CONSDEV = 2,
	CON_ENABLED = 4,
	CON_BOOT = 8,
	CON_ANYTIME = 16,
	CON_BRL = 32,
	CON_EXTENDED = 64,
	CON_SUSPENDED = 128,
	CON_NBCON = 256,
};

enum devkmsg_log_masks {
	DEVKMSG_LOG_MASK_ON = 1,
	DEVKMSG_LOG_MASK_OFF = 2,
	DEVKMSG_LOG_MASK_LOCK = 4,
};

enum con_msg_format_flags {
	MSG_FORMAT_DEFAULT = 0,
	MSG_FORMAT_SYSLOG = 1,
};

typedef unsigned int uint;

struct nbcon_write_context;

struct printk_buffers;

struct console {
	char name[16];
	void (*write)(struct console *, const char *, unsigned int);
	int (*read)(struct console *, char *, unsigned int);
	struct tty_driver * (*device)(struct console *, int *);
	void (*unblank)();
	int (*setup)(struct console *, char *);
	int (*exit)(struct console *);
	int (*match)(struct console *, char *, int, char *);
	short flags;
	short index;
	int cflag;
	uint ispeed;
	uint ospeed;
	u64 seq;
	unsigned long dropped;
	void *data;
	struct hlist_node node;
	bool (*write_atomic)(struct console *, struct nbcon_write_context *);
	atomic_t nbcon_state;
	atomic_long_t nbcon_seq;
	struct printk_buffers *pbufs;
};

struct nbcon_context {
	struct console *console;
	unsigned int spinwait_max_us;
	enum nbcon_prio prio;
	unsigned int allow_unsafe_takeover: 1;
	unsigned int backlog: 1;
	struct printk_buffers *pbufs;
	u64 seq;
};

struct nbcon_write_context {
	struct nbcon_context ctxt;
	char *outbuf;
	unsigned int len;
	bool unsafe_takeover;
};

struct printk_buffers {
	char outbuf[0];
	char scratchbuf[0];
};

struct bpf_queue_stack {
	struct bpf_map map;
	raw_spinlock_t lock;
	u32 head;
	u32 tail;
	u32 size;
	long: 0;
	char elements[0];
};

enum pgt_entry {
	NORMAL_PMD = 0,
	HPAGE_PMD = 1,
	NORMAL_PUD = 2,
	HPAGE_PUD = 3,
};

struct hstate {};

enum kernel_read_file_id {
	READING_UNKNOWN = 0,
	READING_FIRMWARE = 1,
	READING_MODULE = 2,
	READING_KEXEC_IMAGE = 3,
	READING_KEXEC_INITRAMFS = 4,
	READING_POLICY = 5,
	READING_X509_CERTIFICATE = 6,
	READING_MAX_ID = 7,
};

struct aggregate_device;

struct component_ops;

struct component {
	struct list_head node;
	struct aggregate_device *adev;
	bool bound;
	const struct component_ops *ops;
	int subcomponent;
	struct device *dev;
};

struct component_master_ops;

struct component_match;

struct aggregate_device {
	struct list_head node;
	bool bound;
	const struct component_master_ops *ops;
	struct device *parent;
	struct component_match *match;
};

struct component_master_ops {
	int (*bind)(struct device *);
	void (*unbind)(struct device *);
};

struct component_match_array;

struct component_match {
	size_t alloc;
	size_t num;
	struct component_match_array *compare;
};

struct component_match_array {
	void *data;
	int (*compare)(struct device *, void *);
	int (*compare_typed)(struct device *, int, void *);
	void (*release)(struct device *, void *);
	struct component *component;
	bool duplicate;
};

struct component_ops {
	int (*bind)(struct device *, struct device *, void *);
	void (*unbind)(struct device *, struct device *, void *);
};

enum cfi_mode {
	CFI_DEFAULT = 0,
	CFI_OFF = 1,
	CFI_KCFI = 2,
	CFI_FINEIBT = 3,
};

struct text_poke_loc {
	s32 rel_addr;
	s32 disp;
	u8 len;
	u8 opcode;
	const u8 text[5];
	u8 old;
};

struct bp_patching_desc {
	struct text_poke_loc *vec;
	int nr_entries;
	atomic_t refs;
};

typedef struct {
	struct mm_struct *mm;
} temp_mm_state_t;

typedef void text_poke_f(void *, const void *, size_t);

enum cpa_warn {
	CPA_CONFLICT = 0,
	CPA_PROTECT = 1,
	CPA_DETECT = 2,
};

struct cpa_data {
	unsigned long *vaddr;
	pgd_t *pgd;
	pgprot_t mask_set;
	pgprot_t mask_clr;
	unsigned long numpages;
	unsigned long curpage;
	unsigned long pfn;
	unsigned int flags;
	unsigned int force_split: 1;
	unsigned int force_static_prot: 1;
	unsigned int force_flush_all: 1;
	struct page **pages;
};

struct tk_fast {
	seqcount_latch_t seq;
	struct tk_read_base base[2];
};

enum timekeeping_adv_mode {
	TK_ADV_TICK = 0,
	TK_ADV_FREQ = 1,
};

struct ktime_timestamps {
	u64 mono;
	u64 boot;
	u64 real;
};

struct system_time_snapshot {
	u64 cycles;
	ktime_t real;
	ktime_t raw;
	enum clocksource_ids cs_id;
	unsigned int clock_was_set_seq;
	u8 cs_was_changed_seq;
};

struct system_device_crosststamp {
	ktime_t device;
	ktime_t sys_realtime;
	ktime_t sys_monoraw;
};

struct statfs {
	__kernel_long_t f_type;
	__kernel_long_t f_bsize;
	__kernel_long_t f_blocks;
	__kernel_long_t f_bfree;
	__kernel_long_t f_bavail;
	__kernel_long_t f_files;
	__kernel_long_t f_ffree;
	__kernel_fsid_t f_fsid;
	__kernel_long_t f_namelen;
	__kernel_long_t f_frsize;
	__kernel_long_t f_flags;
	__kernel_long_t f_spare[4];
};

struct statfs64 {
	__kernel_long_t f_type;
	__kernel_long_t f_bsize;
	__u64 f_blocks;
	__u64 f_bfree;
	__u64 f_bavail;
	__u64 f_files;
	__u64 f_ffree;
	__kernel_fsid_t f_fsid;
	__kernel_long_t f_namelen;
	__kernel_long_t f_frsize;
	__kernel_long_t f_flags;
	__kernel_long_t f_spare[4];
};

typedef int __kernel_daddr_t;

struct ustat {
	__kernel_daddr_t f_tfree;
	unsigned long f_tinode;
	char f_fname[6];
	char f_fpack[6];
};

enum device_link_state {
	DL_STATE_NONE = -1,
	DL_STATE_DORMANT = 0,
	DL_STATE_AVAILABLE = 1,
	DL_STATE_CONSUMER_PROBE = 2,
	DL_STATE_ACTIVE = 3,
	DL_STATE_SUPPLIER_UNBIND = 4,
};

enum dpm_order {
	DPM_ORDER_NONE = 0,
	DPM_ORDER_DEV_AFTER_PARENT = 1,
	DPM_ORDER_PARENT_BEFORE_DEV = 2,
	DPM_ORDER_DEV_LAST = 3,
};

struct device_link {
	struct device *supplier;
	struct list_head s_node;
	struct device *consumer;
	struct list_head c_node;
	struct device link_dev;
	enum device_link_state status;
	u32 flags;
	refcount_t rpm_active;
	struct kref kref;
	struct work_struct rm_work;
	bool supplier_preactivated;
};

struct fwnode_link {
	struct fwnode_handle *supplier;
	struct list_head s_hook;
	struct fwnode_handle *consumer;
	struct list_head c_hook;
	u8 flags;
};

struct class_dir {
	struct kobject kobj;
	const struct class *class;
};

struct root_device {
	struct device dev;
	struct module *owner;
};

union device_attr_group_devres {
	const struct attribute_group *group;
	const struct attribute_group **groups;
};

struct irq_stack {
	char stack[16384];
};

enum {
	NONE_FORCE_HPET_RESUME = 0,
	OLD_ICH_FORCE_HPET_RESUME = 1,
	ICH_FORCE_HPET_RESUME = 2,
	VT8237_FORCE_HPET_RESUME = 3,
	NVIDIA_FORCE_HPET_RESUME = 4,
	ATI_FORCE_HPET_RESUME = 5,
};

enum dmi_field {
	DMI_NONE = 0,
	DMI_BIOS_VENDOR = 1,
	DMI_BIOS_VERSION = 2,
	DMI_BIOS_DATE = 3,
	DMI_BIOS_RELEASE = 4,
	DMI_EC_FIRMWARE_RELEASE = 5,
	DMI_SYS_VENDOR = 6,
	DMI_PRODUCT_NAME = 7,
	DMI_PRODUCT_VERSION = 8,
	DMI_PRODUCT_SERIAL = 9,
	DMI_PRODUCT_UUID = 10,
	DMI_PRODUCT_SKU = 11,
	DMI_PRODUCT_FAMILY = 12,
	DMI_BOARD_VENDOR = 13,
	DMI_BOARD_NAME = 14,
	DMI_BOARD_VERSION = 15,
	DMI_BOARD_SERIAL = 16,
	DMI_BOARD_ASSET_TAG = 17,
	DMI_CHASSIS_VENDOR = 18,
	DMI_CHASSIS_TYPE = 19,
	DMI_CHASSIS_VERSION = 20,
	DMI_CHASSIS_SERIAL = 21,
	DMI_CHASSIS_ASSET_TAG = 22,
	DMI_STRING_MAX = 23,
	DMI_OEM_STRING = 24,
};

enum l1tf_mitigations {
	L1TF_MITIGATION_OFF = 0,
	L1TF_MITIGATION_FLUSH_NOWARN = 1,
	L1TF_MITIGATION_FLUSH = 2,
	L1TF_MITIGATION_FLUSH_NOSMT = 3,
	L1TF_MITIGATION_FULL = 4,
	L1TF_MITIGATION_FULL_FORCE = 5,
};

enum vmx_l1d_flush_state {
	VMENTER_L1D_FLUSH_AUTO = 0,
	VMENTER_L1D_FLUSH_NEVER = 1,
	VMENTER_L1D_FLUSH_COND = 2,
	VMENTER_L1D_FLUSH_ALWAYS = 3,
	VMENTER_L1D_FLUSH_EPT_DISABLED = 4,
	VMENTER_L1D_FLUSH_NOT_REQUIRED = 5,
};

enum rfds_mitigations {
	RFDS_MITIGATION_OFF = 0,
	RFDS_MITIGATION_VERW = 1,
	RFDS_MITIGATION_UCODE_NEEDED = 2,
};

enum srbds_mitigations {
	SRBDS_MITIGATION_OFF = 0,
	SRBDS_MITIGATION_UCODE_NEEDED = 1,
	SRBDS_MITIGATION_FULL = 2,
	SRBDS_MITIGATION_TSX_OFF = 3,
	SRBDS_MITIGATION_HYPERVISOR = 4,
};

enum l1d_flush_mitigations {
	L1D_FLUSH_OFF = 0,
	L1D_FLUSH_ON = 1,
};

enum gds_mitigations {
	GDS_MITIGATION_OFF = 0,
	GDS_MITIGATION_UCODE_NEEDED = 1,
	GDS_MITIGATION_FORCE = 2,
	GDS_MITIGATION_FULL = 3,
	GDS_MITIGATION_FULL_LOCKED = 4,
	GDS_MITIGATION_HYPERVISOR = 5,
};

enum spectre_v1_mitigation {
	SPECTRE_V1_MITIGATION_NONE = 0,
	SPECTRE_V1_MITIGATION_AUTO = 1,
};

enum retbleed_mitigation_cmd {
	RETBLEED_CMD_OFF = 0,
	RETBLEED_CMD_AUTO = 1,
	RETBLEED_CMD_UNRET = 2,
	RETBLEED_CMD_IBPB = 3,
	RETBLEED_CMD_STUFF = 4,
};

enum retbleed_mitigation {
	RETBLEED_MITIGATION_NONE = 0,
	RETBLEED_MITIGATION_UNRET = 1,
	RETBLEED_MITIGATION_IBPB = 2,
	RETBLEED_MITIGATION_IBRS = 3,
	RETBLEED_MITIGATION_EIBRS = 4,
	RETBLEED_MITIGATION_STUFF = 5,
};

enum spectre_v2_mitigation_cmd {
	SPECTRE_V2_CMD_NONE = 0,
	SPECTRE_V2_CMD_AUTO = 1,
	SPECTRE_V2_CMD_FORCE = 2,
	SPECTRE_V2_CMD_RETPOLINE = 3,
	SPECTRE_V2_CMD_RETPOLINE_GENERIC = 4,
	SPECTRE_V2_CMD_RETPOLINE_LFENCE = 5,
	SPECTRE_V2_CMD_EIBRS = 6,
	SPECTRE_V2_CMD_EIBRS_RETPOLINE = 7,
	SPECTRE_V2_CMD_EIBRS_LFENCE = 8,
	SPECTRE_V2_CMD_IBRS = 9,
};

enum spectre_v2_user_cmd {
	SPECTRE_V2_USER_CMD_NONE = 0,
	SPECTRE_V2_USER_CMD_AUTO = 1,
	SPECTRE_V2_USER_CMD_FORCE = 2,
	SPECTRE_V2_USER_CMD_PRCTL = 3,
	SPECTRE_V2_USER_CMD_PRCTL_IBPB = 4,
	SPECTRE_V2_USER_CMD_SECCOMP = 5,
	SPECTRE_V2_USER_CMD_SECCOMP_IBPB = 6,
};

enum spectre_v2_user_mitigation {
	SPECTRE_V2_USER_NONE = 0,
	SPECTRE_V2_USER_STRICT = 1,
	SPECTRE_V2_USER_STRICT_PREFERRED = 2,
	SPECTRE_V2_USER_PRCTL = 3,
	SPECTRE_V2_USER_SECCOMP = 4,
};

enum bhi_mitigations {
	BHI_MITIGATION_OFF = 0,
	BHI_MITIGATION_ON = 1,
};

enum mds_mitigations {
	MDS_MITIGATION_OFF = 0,
	MDS_MITIGATION_FULL = 1,
	MDS_MITIGATION_VMWERV = 2,
};

enum taa_mitigations {
	TAA_MITIGATION_OFF = 0,
	TAA_MITIGATION_UCODE_NEEDED = 1,
	TAA_MITIGATION_VERW = 2,
	TAA_MITIGATION_TSX_DISABLED = 3,
};

enum mmio_mitigations {
	MMIO_MITIGATION_OFF = 0,
	MMIO_MITIGATION_UCODE_NEEDED = 1,
	MMIO_MITIGATION_VERW = 2,
};

enum ssb_mitigation_cmd {
	SPEC_STORE_BYPASS_CMD_NONE = 0,
	SPEC_STORE_BYPASS_CMD_AUTO = 1,
	SPEC_STORE_BYPASS_CMD_ON = 2,
	SPEC_STORE_BYPASS_CMD_PRCTL = 3,
	SPEC_STORE_BYPASS_CMD_SECCOMP = 4,
};

enum ssb_mitigation {
	SPEC_STORE_BYPASS_NONE = 0,
	SPEC_STORE_BYPASS_DISABLE = 1,
	SPEC_STORE_BYPASS_PRCTL = 2,
	SPEC_STORE_BYPASS_SECCOMP = 3,
};

enum srso_mitigation_cmd {
	SRSO_CMD_OFF = 0,
	SRSO_CMD_MICROCODE = 1,
	SRSO_CMD_SAFE_RET = 2,
	SRSO_CMD_IBPB = 3,
	SRSO_CMD_IBPB_ON_VMEXIT = 4,
};

enum srso_mitigation {
	SRSO_MITIGATION_NONE = 0,
	SRSO_MITIGATION_UCODE_NEEDED = 1,
	SRSO_MITIGATION_SAFE_RET_UCODE_NEEDED = 2,
	SRSO_MITIGATION_MICROCODE = 3,
	SRSO_MITIGATION_SAFE_RET = 4,
	SRSO_MITIGATION_IBPB = 5,
	SRSO_MITIGATION_IBPB_ON_VMEXIT = 6,
};

enum {
	BPF_LOCAL_STORAGE_GET_F_CREATE = 1,
	BPF_SK_STORAGE_GET_F_CREATE = 1,
};

typedef u64 (*btf_bpf_task_storage_get_recur)(struct bpf_map *, struct task_struct *, void *, u64, gfp_t);

typedef u64 (*btf_bpf_task_storage_get)(struct bpf_map *, struct task_struct *, void *, u64, gfp_t);

typedef u64 (*btf_bpf_task_storage_delete_recur)(struct bpf_map *, struct task_struct *);

typedef u64 (*btf_bpf_task_storage_delete)(struct bpf_map *, struct task_struct *);

struct memblock {
	bool bottom_up;
	phys_addr_t current_limit;
	struct memblock_type memory;
	struct memblock_type reserved;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
