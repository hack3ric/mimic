// Generated using tools/vendor-vmlinux-h from Debian linux-image-6.9.10-powerpc64_6.9.10-1_ppc64.deb
// Do not edit!

#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

typedef struct {
	__u32 u[4];
} __vector128;

typedef __vector128 vector128;

typedef long int __kernel_long_t;

typedef long unsigned int __kernel_ulong_t;

typedef int __kernel_pid_t;

typedef unsigned int __kernel_uid32_t;

typedef unsigned int __kernel_gid32_t;

typedef __kernel_ulong_t __kernel_size_t;

typedef __kernel_long_t __kernel_ssize_t;

typedef long long int __kernel_loff_t;

typedef long long int __kernel_time64_t;

typedef __kernel_long_t __kernel_clock_t;

typedef int __kernel_timer_t;

typedef int __kernel_clockid_t;

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u64 __be64;

typedef unsigned int __poll_t;

typedef short unsigned int umode_t;

typedef __kernel_pid_t pid_t;

typedef __kernel_clockid_t clockid_t;

typedef _Bool bool;

typedef __kernel_uid32_t uid_t;

typedef __kernel_gid32_t gid_t;

typedef long unsigned int uintptr_t;

typedef __kernel_loff_t loff_t;

typedef __kernel_size_t size_t;

typedef __kernel_ssize_t ssize_t;

typedef long unsigned int ulong;

typedef s64 ktime_t;

typedef unsigned int gfp_t;

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	s64 counter;
} atomic64_t;

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct hlist_node;

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

struct user_pt_regs {
	long unsigned int gpr[32];
	long unsigned int nip;
	long unsigned int msr;
	long unsigned int orig_gpr3;
	long unsigned int ctr;
	long unsigned int link;
	long unsigned int xer;
	long unsigned int ccr;
	long unsigned int softe;
	long unsigned int trap;
	long unsigned int dar;
	long unsigned int dsisr;
	long unsigned int result;
};

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			long unsigned int gpr[32];
			long unsigned int nip;
			long unsigned int msr;
			long unsigned int orig_gpr3;
			long unsigned int ctr;
			long unsigned int link;
			long unsigned int xer;
			long unsigned int ccr;
			long unsigned int softe;
			long unsigned int trap;
			union {
				long unsigned int dar;
				long unsigned int dear;
			};
			union {
				long unsigned int dsisr;
				long unsigned int esr;
			};
			long unsigned int result;
		};
	};
	union {
		struct {
			long unsigned int ppr;
			long unsigned int exit_result;
			union {
				long unsigned int kuap;
				long unsigned int amr;
			};
			long unsigned int iamr;
		};
		long unsigned int __pad[4];
	};
};

typedef int (*initcall_t)();

struct qspinlock {
	union {
		u32 val;
		struct {
			u8 reserved[2];
			u16 locked;
		};
	};
};

typedef struct qspinlock arch_spinlock_t;

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

typedef struct raw_spinlock raw_spinlock_t;

struct jump_entry {
	s32 code;
	s32 target;
	long int key;
};

struct static_key_mod;

struct static_key {
	atomic_t enabled;
	union {
		long unsigned int type;
		struct jump_entry *entries;
		struct static_key_mod *next;
	};
};

struct static_key_false {
	struct static_key key;
};

typedef struct {
	__be64 pgd;
} pgd_t;

typedef struct {
	long unsigned int pgprot;
} pgprot_t;

typedef atomic64_t atomic_long_t;

struct address_space;

struct page_pool;

struct dev_pagemap;

struct page {
	long unsigned int flags;
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
				long unsigned int index;
				long unsigned int share;
			};
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			atomic_long_t pp_ref_count;
		};
		struct {
			long unsigned int compound_head;
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
	long unsigned int memcg_data;
};

struct slb_entry {
	u64 esid;
	u64 vsid;
};

struct slice_mask {
	u64 low_slices;
	long unsigned int high_slices[64];
};

struct hash_mm_context {
	u16 user_psize;
	unsigned char low_slices_psize[8];
	unsigned char high_slices_psize[2048];
	long unsigned int slb_addr_limit;
	struct slice_mask mask_64k;
	struct slice_mask mask_4k;
	struct slice_mask mask_16m;
	struct slice_mask mask_16g;
};

typedef long unsigned int mm_context_id_t;

typedef struct {
	union {
		mm_context_id_t id;
		mm_context_id_t extended_id[8];
	};
	atomic_t active_cpus;
	atomic_t copros;
	atomic_t vas_windows;
	struct hash_mm_context *hash_context;
	void *vdso;
	void *pte_frag;
	void *pmd_frag;
	struct list_head iommu_group_mem_list;
	u32 pkey_allocation_map;
	s16 execute_only_pkey;
} mm_context_t;

struct kvmppc_vcore;

struct kvm_split_mode {
	long unsigned int rpr;
	long unsigned int pmmar;
	long unsigned int ldbar;
	u8 subcore_size;
	u8 do_nap;
	u8 napped[8];
	struct kvmppc_vcore *vc[4];
};

struct kvm_vcpu;

struct kvmppc_host_state {
	ulong host_r1;
	ulong host_r2;
	ulong host_msr;
	ulong vmhandler;
	ulong scratch0;
	ulong scratch1;
	ulong scratch2;
	u8 in_guest;
	u8 restore_hid5;
	u8 napping;
	u8 hwthread_req;
	u8 hwthread_state;
	u8 host_ipi;
	u8 ptid;
	u8 fake_suspend;
	struct kvm_vcpu *kvm_vcpu;
	struct kvmppc_vcore *kvm_vcore;
	void *xics_phys;
	void *xive_tima_phys;
	void *xive_tima_virt;
	u32 saved_xirr;
	u64 dabr;
	u64 host_mmcr[7];
	u32 host_pmc[8];
	u64 host_purr;
	u64 host_spurr;
	u64 host_dscr;
	u64 dec_expires;
	struct kvm_split_mode *kvm_split_mode;
	u64 cfar;
	u64 ppr;
	u64 host_fscr;
};

struct cpu_accounting_data {
	long unsigned int utime;
	long unsigned int stime;
	long unsigned int gtime;
	long unsigned int hardirq_time;
	long unsigned int softirq_time;
	long unsigned int steal_time;
	long unsigned int idle_time;
	long unsigned int starttime;
	long unsigned int starttime_user;
};

struct sibling_subcore_state {
	long unsigned int flags;
	u8 in_guest[4];
};

enum MCE_Version {
	MCE_V1 = 1,
};

enum MCE_Severity {
	MCE_SEV_NO_ERROR = 0,
	MCE_SEV_WARNING = 1,
	MCE_SEV_SEVERE = 2,
	MCE_SEV_FATAL = 3,
};

enum MCE_Disposition {
	MCE_DISPOSITION_RECOVERED = 0,
	MCE_DISPOSITION_NOT_RECOVERED = 1,
};

enum MCE_Initiator {
	MCE_INITIATOR_UNKNOWN = 0,
	MCE_INITIATOR_CPU = 1,
	MCE_INITIATOR_PCI = 2,
	MCE_INITIATOR_ISA = 3,
	MCE_INITIATOR_MEMORY = 4,
	MCE_INITIATOR_POWERMGM = 5,
};

enum MCE_ErrorType {
	MCE_ERROR_TYPE_UNKNOWN = 0,
	MCE_ERROR_TYPE_UE = 1,
	MCE_ERROR_TYPE_SLB = 2,
	MCE_ERROR_TYPE_ERAT = 3,
	MCE_ERROR_TYPE_TLB = 4,
	MCE_ERROR_TYPE_USER = 5,
	MCE_ERROR_TYPE_RA = 6,
	MCE_ERROR_TYPE_LINK = 7,
	MCE_ERROR_TYPE_DCACHE = 8,
	MCE_ERROR_TYPE_ICACHE = 9,
};

enum MCE_ErrorClass {
	MCE_ECLASS_UNKNOWN = 0,
	MCE_ECLASS_HARDWARE = 1,
	MCE_ECLASS_HARD_INDETERMINATE = 2,
	MCE_ECLASS_SOFTWARE = 3,
	MCE_ECLASS_SOFT_INDETERMINATE = 4,
};

enum MCE_UeErrorType {
	MCE_UE_ERROR_INDETERMINATE = 0,
	MCE_UE_ERROR_IFETCH = 1,
	MCE_UE_ERROR_PAGE_TABLE_WALK_IFETCH = 2,
	MCE_UE_ERROR_LOAD_STORE = 3,
	MCE_UE_ERROR_PAGE_TABLE_WALK_LOAD_STORE = 4,
};

enum MCE_SlbErrorType {
	MCE_SLB_ERROR_INDETERMINATE = 0,
	MCE_SLB_ERROR_PARITY = 1,
	MCE_SLB_ERROR_MULTIHIT = 2,
};

enum MCE_EratErrorType {
	MCE_ERAT_ERROR_INDETERMINATE = 0,
	MCE_ERAT_ERROR_PARITY = 1,
	MCE_ERAT_ERROR_MULTIHIT = 2,
};

enum MCE_TlbErrorType {
	MCE_TLB_ERROR_INDETERMINATE = 0,
	MCE_TLB_ERROR_PARITY = 1,
	MCE_TLB_ERROR_MULTIHIT = 2,
};

enum MCE_UserErrorType {
	MCE_USER_ERROR_INDETERMINATE = 0,
	MCE_USER_ERROR_TLBIE = 1,
	MCE_USER_ERROR_SCV = 2,
};

enum MCE_RaErrorType {
	MCE_RA_ERROR_INDETERMINATE = 0,
	MCE_RA_ERROR_IFETCH = 1,
	MCE_RA_ERROR_IFETCH_FOREIGN = 2,
	MCE_RA_ERROR_PAGE_TABLE_WALK_IFETCH = 3,
	MCE_RA_ERROR_PAGE_TABLE_WALK_IFETCH_FOREIGN = 4,
	MCE_RA_ERROR_LOAD = 5,
	MCE_RA_ERROR_STORE = 6,
	MCE_RA_ERROR_PAGE_TABLE_WALK_LOAD_STORE = 7,
	MCE_RA_ERROR_PAGE_TABLE_WALK_LOAD_STORE_FOREIGN = 8,
	MCE_RA_ERROR_LOAD_STORE_FOREIGN = 9,
};

enum MCE_LinkErrorType {
	MCE_LINK_ERROR_INDETERMINATE = 0,
	MCE_LINK_ERROR_IFETCH_TIMEOUT = 1,
	MCE_LINK_ERROR_PAGE_TABLE_WALK_IFETCH_TIMEOUT = 2,
	MCE_LINK_ERROR_LOAD_TIMEOUT = 3,
	MCE_LINK_ERROR_STORE_TIMEOUT = 4,
	MCE_LINK_ERROR_PAGE_TABLE_WALK_LOAD_STORE_TIMEOUT = 5,
};

struct machine_check_event {
	enum MCE_Version version: 8;
	u8 in_use;
	enum MCE_Severity severity: 8;
	enum MCE_Initiator initiator: 8;
	enum MCE_ErrorType error_type: 8;
	enum MCE_ErrorClass error_class: 8;
	enum MCE_Disposition disposition: 8;
	bool sync_error;
	u16 cpu;
	u64 gpr3;
	u64 srr0;
	u64 srr1;
	union {
		struct {
			enum MCE_UeErrorType ue_error_type: 8;
			u8 effective_address_provided;
			u8 physical_address_provided;
			u8 ignore_event;
			u8 reserved_1[4];
			u64 effective_address;
			u64 physical_address;
			u8 reserved_2[8];
		} ue_error;
		struct {
			enum MCE_SlbErrorType slb_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} slb_error;
		struct {
			enum MCE_EratErrorType erat_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} erat_error;
		struct {
			enum MCE_TlbErrorType tlb_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} tlb_error;
		struct {
			enum MCE_UserErrorType user_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} user_error;
		struct {
			enum MCE_RaErrorType ra_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} ra_error;
		struct {
			enum MCE_LinkErrorType link_error_type: 8;
			u8 effective_address_provided;
			u8 reserved_1[6];
			u64 effective_address;
			u8 reserved_2[16];
		} link_error;
	} u;
};

struct mce_info {
	int mce_nest_count;
	struct machine_check_event mce_event[10];
	int mce_queue_count;
	struct machine_check_event mce_event_queue[10];
	int mce_ue_count;
	struct machine_check_event mce_ue_event_queue[10];
};

struct mmiowb_state {
	u16 nesting_count;
	u16 mmiowb_pending;
};

struct lppaca;

struct slb_shadow;

struct dtl_entry;

struct task_struct;

struct paca_struct {
	struct lppaca *lppaca_ptr;
	u16 lock_token;
	u16 paca_index;
	u64 kernel_toc;
	u64 kernelbase;
	u64 kernel_msr;
	void *emergency_sp;
	u64 data_offset;
	s16 hw_cpu_id;
	u8 cpu_start;
	u8 kexec_state;
	struct slb_shadow *slb_shadow_ptr;
	struct dtl_entry *dispatch_log;
	struct dtl_entry *dispatch_log_end;
	u64 dscr_default;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u64 exgen[10];
	u16 vmalloc_sllp;
	u8 slb_cache_ptr;
	u8 stab_rr;
	u32 slb_used_bitmap;
	u32 slb_kern_bitmap;
	u32 slb_cache[8];
	unsigned char mm_ctx_low_slices_psize[8];
	unsigned char mm_ctx_high_slices_psize[2048];
	struct task_struct *__current;
	u64 kstack;
	u64 saved_r1;
	u64 saved_msr;
	u64 exit_save_r1;
	u8 hsrr_valid;
	u8 srr_valid;
	u8 irq_soft_mask;
	u8 irq_happened;
	u8 irq_work_pending;
	u8 pmcregs_in_use;
	u64 sprg_vdso;
	long unsigned int idle_lock;
	long unsigned int idle_state;
	union {
		struct {
			u8 thread_idle_state;
			u8 subcore_sibling_mask;
		};
		struct {
			u64 requested_psscr;
			atomic_t dont_stop;
		};
	};
	u64 exnmi[10];
	u64 exmc[10];
	void *nmi_emergency_sp;
	void *mc_emergency_sp;
	u16 in_nmi;
	u16 in_mce;
	u8 hmi_event_available;
	u8 hmi_p9_special_emu;
	u32 hmi_irqs;
	u8 ftrace_enabled;
	struct cpu_accounting_data accounting;
	u64 dtl_ridx;
	struct dtl_entry *dtl_curr;
	struct kvmppc_host_state kvm_hstate;
	struct sibling_subcore_state *sibling_subcore_state;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u64 exrfi[10];
	void *rfi_flush_fallback_area;
	u64 l1d_flush_size;
	u8 *mce_data_buf;
	struct slb_entry *mce_faulty_slbs;
	u16 slb_save_cache_ptr;
	long unsigned int canary;
	struct mmiowb_state mmiowb_state;
	struct mce_info *mce_info;
	u8 mce_pending_irq_work;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct lppaca {
	__be32 desc;
	__be16 size;
	u8 reserved1[3];
	u8 __old_status;
	u8 reserved3[14];
	volatile __be32 dyn_hw_node_id;
	volatile __be32 dyn_hw_proc_id;
	u8 reserved4[56];
	volatile u8 vphn_assoc_counts[8];
	u8 reserved5[32];
	u8 reserved6[48];
	u8 cede_latency_hint;
	u8 ebb_regs_in_use;
	u8 reserved7[6];
	u8 dtl_enable_mask;
	u8 donate_dedicated_cpu;
	u8 fpregs_in_use;
	u8 pmcregs_in_use;
	u8 reserved8[28];
	__be64 wait_state_cycles;
	u8 reserved9[28];
	__be16 slb_count;
	u8 idle;
	u8 vmxregs_in_use;
	volatile __be32 yield_count;
	volatile __be32 dispersion_count;
	volatile __be64 cmo_faults;
	volatile __be64 cmo_fault_time;
	u8 reserved10[64];
	volatile __be64 enqueue_dispatch_tb;
	volatile __be64 ready_enqueue_tb;
	volatile __be64 wait_ready_tb;
	u8 reserved11[16];
	__be32 page_ins;
	u8 reserved12[148];
	volatile __be64 dtl_idx;
	u8 reserved13[96];
};

struct slb_shadow {
	__be32 persistent;
	__be32 buffer_length;
	__be64 reserved;
	struct {
		__be64 esid;
		__be64 vsid;
	} save_area[2];
	long: 64;
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

struct thread_info {
	int preempt_count;
	unsigned int cpu;
	long unsigned int local_flags;
	unsigned char slb_preload_nr;
	unsigned char slb_preload_tail;
	u32 slb_preload_esid[16];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long unsigned int flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct llist_node {
	struct llist_node *next;
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

struct load_weight {
	long unsigned int weight;
	u32 inv_weight;
};

struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct sched_avg {
	u64 last_update_time;
	u64 load_sum;
	u64 runnable_sum;
	u32 util_sum;
	u32 period_contrib;
	long unsigned int load_avg;
	long unsigned int runnable_avg;
	long unsigned int util_avg;
	unsigned int util_est;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct cfs_rq;

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
	int depth;
	struct sched_entity *parent;
	struct cfs_rq *cfs_rq;
	struct cfs_rq *my_q;
	long unsigned int runnable_weight;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg;
};

struct sched_rt_entity {
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
};

struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

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

struct sched_dl_entity;

typedef bool (*dl_server_has_tasks_f)(struct sched_dl_entity *);

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
	struct sched_dl_entity *pi_se;
};

struct sched_statistics {
	u64 wait_start;
	u64 wait_max;
	u64 wait_count;
	u64 wait_sum;
	u64 iowait_count;
	u64 iowait_sum;
	u64 sleep_start;
	u64 sleep_max;
	s64 sum_sleep_runtime;
	u64 block_start;
	u64 block_max;
	s64 sum_block_runtime;
	s64 exec_max;
	u64 slice_max;
	u64 nr_migrations_cold;
	u64 nr_failed_migrations_affine;
	u64 nr_failed_migrations_running;
	u64 nr_failed_migrations_hot;
	u64 nr_forced_migrations;
	u64 nr_wakeups;
	u64 nr_wakeups_sync;
	u64 nr_wakeups_migrate;
	u64 nr_wakeups_local;
	u64 nr_wakeups_remote;
	u64 nr_wakeups_affine;
	u64 nr_wakeups_affine_attempts;
	u64 nr_wakeups_passive;
	u64 nr_wakeups_idle;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct cpumask {
	long unsigned int bits[32];
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

struct sched_info {
	long unsigned int pcount;
	long long unsigned int run_delay;
	long long unsigned int last_arrival;
	long long unsigned int last_queued;
};

struct plist_node {
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};

enum timespec_type {
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};

struct __kernel_timespec;

struct old_timespec32;

struct pollfd;

struct restart_block {
	long unsigned int arch_data;
	long int (*fn)(struct restart_block *);
	union {
		struct {
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
		} futex;
		struct {
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct __kernel_timespec *rmtp;
				struct old_timespec32 *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct {
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			long unsigned int tv_sec;
			long unsigned int tv_nsec;
		} poll;
	};
};

struct prev_cputime {
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};

struct seqcount {
	unsigned int sequence;
};

typedef struct seqcount seqcount_t;

enum vtime_state {
	VTIME_INACTIVE = 0,
	VTIME_IDLE = 1,
	VTIME_SYS = 2,
	VTIME_USER = 3,
	VTIME_GUEST = 4,
};

struct vtime {
	seqcount_t seqcount;
	long long unsigned int starttime;
	enum vtime_state state;
	unsigned int cpu;
	u64 utime;
	u64 stime;
	u64 gtime;
};

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

struct posix_cputimer_base {
	u64 nextevt;
	struct timerqueue_head tqhead;
};

struct posix_cputimers {
	struct posix_cputimer_base bases[3];
	unsigned int timers_active;
	unsigned int expiry_active;
};

struct sem_undo_list;

struct sysv_sem {
	struct sem_undo_list *undo_list;
};

struct sysv_shm {
	struct list_head shm_clist;
};

typedef struct {
	long unsigned int sig[1];
} sigset_t;

struct sigpending {
	struct list_head list;
	sigset_t signal;
};

typedef struct {
	uid_t val;
} kuid_t;

struct seccomp_filter;

struct seccomp {
	int mode;
	atomic_t filter_count;
	struct seccomp_filter *filter;
};

struct syscall_user_dispatch {};

struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};

typedef struct spinlock spinlock_t;

struct wake_q_node {
	struct wake_q_node *next;
};

struct task_io_accounting {
	u64 rchar;
	u64 wchar;
	u64 syscr;
	u64 syscw;
	u64 read_bytes;
	u64 write_bytes;
	u64 cancelled_write_bytes;
};

typedef struct {
	long unsigned int bits[4];
} nodemask_t;

struct seqcount_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

struct optimistic_spin_queue {
	atomic_t tail;
};

struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct optimistic_spin_queue osq;
	struct list_head wait_list;
};

struct tlbflush_unmap_batch {};

struct page_frag {
	struct page *page;
	__u32 offset;
	__u32 size;
};

struct kmap_ctrl {};

struct timer_list {
	struct hlist_node entry;
	long unsigned int expires;
	void (*function)(struct timer_list *);
	u32 flags;
};

struct llist_head {
	struct llist_node *first;
};

struct debug_reg {};

struct thread_fp_state {
	u64 fpr[64];
	u64 fpscr;
	long: 64;
};

struct arch_hw_breakpoint {
	long unsigned int address;
	u16 type;
	u16 len;
	u16 hw_len;
	u8 flags;
	bool perf_single_step;
};

struct thread_vr_state {
	vector128 vr[32];
	vector128 vscr;
};

struct perf_event;

struct thread_struct {
	long unsigned int ksp;
	long unsigned int ksp_vsid;
	struct pt_regs *regs;
	struct debug_reg debug;
	long: 64;
	struct thread_fp_state fp_state;
	struct thread_fp_state *fp_save_area;
	int fpexc_mode;
	unsigned int align_ctl;
	struct perf_event *ptrace_bps[2];
	struct arch_hw_breakpoint hw_brk[2];
	long unsigned int trap_nr;
	u8 load_slb;
	u8 load_fp;
	u8 load_vec;
	long: 0;
	struct thread_vr_state vr_state;
	struct thread_vr_state *vr_save_area;
	long unsigned int vrsave;
	int used_vr;
	int used_vsr;
	long unsigned int dscr;
	long unsigned int fscr;
	int dscr_inherit;
	long unsigned int tidr;
	long unsigned int tar;
	long unsigned int ebbrr;
	long unsigned int ebbhr;
	long unsigned int bescr;
	long unsigned int siar;
	long unsigned int sdar;
	long unsigned int sier;
	long unsigned int mmcr2;
	unsigned int mmcr0;
	unsigned int used_ebb;
	long unsigned int mmcr3;
	long unsigned int sier2;
	long unsigned int sier3;
	long unsigned int hashkeyr;
};

struct sched_class;

struct task_group;

struct mm_struct;

struct pid;

struct completion;

struct cred;

struct key;

struct nameidata;

struct fs_struct;

struct files_struct;

struct io_uring_task;

struct nsproxy;

struct signal_struct;

struct sighand_struct;

struct audit_context;

struct rt_mutex_waiter;

struct bio_list;

struct blk_plug;

struct reclaim_state;

struct io_context;

struct capture_control;

struct kernel_siginfo;

typedef struct kernel_siginfo kernel_siginfo_t;

struct css_set;

struct robust_list_head;

struct compat_robust_list_head;

struct futex_pi_state;

struct perf_event_context;

struct mempolicy;

struct numa_group;

struct rseq;

struct pipe_inode_info;

struct task_delay_info;

struct ftrace_ret_stack;

struct mem_cgroup;

struct obj_cgroup;

struct gendisk;

struct uprobe_task;

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
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	long: 64;
	long: 64;
	long: 64;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	struct sched_dl_entity *dl_server;
	const struct sched_class *sched_class;
	struct task_group *sched_task_group;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	struct hlist_head preempt_notifiers;
	unsigned int btrace_seq;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct address_space *faults_disabled_mapping;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	long: 29;
	unsigned int sched_remote_wakeup: 1;
	unsigned int sched_rt_mutex: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int restore_sigmask: 1;
	unsigned int in_user_fault: 1;
	unsigned int in_lru_fault: 1;
	unsigned int no_cgroup_migration: 1;
	unsigned int frozen: 1;
	unsigned int use_memdelay: 1;
	unsigned int in_memstall: 1;
	unsigned int in_eventfd: 1;
	unsigned int in_thrashing: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	long unsigned int stack_canary;
	struct task_struct *real_parent;
	struct task_struct *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	struct vtime vtime;
	atomic_t tick_dep_mask;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	struct key *cached_requested_key;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	long unsigned int last_switch_count;
	long unsigned int last_switch_time;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct audit_context *audit_context;
	kuid_t loginuid;
	unsigned int sessionid;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct io_context *io_context;
	struct capture_control *capture_control;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	unsigned int psi_flags;
	u64 acct_rss_mem1;
	u64 acct_vm_mem1;
	u64 acct_timexpd;
	nodemask_t mems_allowed;
	seqcount_spinlock_t mems_allowed_seq;
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
	struct css_set *cgroups;
	struct list_head cg_list;
	struct robust_list_head *robust_list;
	struct compat_robust_list_head *compat_robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp;
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	struct mempolicy *mempolicy;
	short int il_prev;
	u8 il_weight;
	short int pref_node_fork;
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	long unsigned int numa_migrate_retry;
	u64 node_stamp;
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct numa_group *numa_group;
	long unsigned int *numa_faults;
	long unsigned int total_numa_faults;
	long unsigned int numa_faults_locality[3];
	long unsigned int numa_pages_migrated;
	struct rseq *rseq;
	u32 rseq_len;
	u32 rseq_sig;
	long unsigned int rseq_event_mask;
	int mm_cid;
	int last_mm_cid;
	int migrate_from_cpu;
	int mm_cid_active;
	struct callback_head cid_work;
	struct tlbflush_unmap_batch tlb_ubc;
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	struct task_delay_info *delays;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct mem_cgroup *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
	unsigned int memcg_nr_pages_over_high;
	struct mem_cgroup *active_memcg;
	struct obj_cgroup *objcg;
	struct gendisk *throttle_disk;
	struct uprobe_task *utask;
	unsigned int sequential_io;
	unsigned int sequential_io_avg;
	struct kmap_ctrl kmap_ctrl;
	struct callback_head rcu;
	refcount_t rcu_users;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	refcount_t stack_refcount;
	void *security;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	struct llist_head kretprobe_instances;
	struct thread_struct thread;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct __kernel_timespec {
	__kernel_time64_t tv_sec;
	long long int tv_nsec;
};

typedef s32 old_time32_t;

struct old_timespec32 {
	old_time32_t tv_sec;
	s32 tv_nsec;
};

enum pcpu_fc {
	PCPU_FC_AUTO = 0,
	PCPU_FC_EMBED = 1,
	PCPU_FC_PAGE = 2,
	PCPU_FC_NR = 3,
};

typedef struct {
	raw_spinlock_t *lock;
} class_raw_spinlock_t;

typedef struct {
	raw_spinlock_t *lock;
} class_raw_spinlock_irq_t;

typedef struct {
	raw_spinlock_t *lock;
	long unsigned int flags;
} class_raw_spinlock_irqsave_t;

typedef struct {
	spinlock_t *lock;
} class_spinlock_t;

typedef struct {
	spinlock_t *lock;
} class_spinlock_irq_t;

typedef struct {
	spinlock_t *lock;
	long unsigned int flags;
} class_spinlock_irqsave_t;

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

enum {
	MM_FILEPAGES = 0,
	MM_ANONPAGES = 1,
	MM_SWAPENTS = 2,
	MM_SHMEMPAGES = 3,
	NR_MM_COUNTERS = 4,
};

struct kref {
	refcount_t refcount;
};

typedef struct {} lockdep_map_p;

struct maple_tree {
	union {
		spinlock_t ma_lock;
		lockdep_map_p ma_external_lock;
	};
	unsigned int ma_flags;
	void *ma_root;
};

struct rw_semaphore {
	atomic_long_t count;
	atomic_long_t owner;
	struct optimistic_spin_queue osq;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};

struct percpu_counter {
	raw_spinlock_t lock;
	s64 count;
	struct list_head list;
	s32 *counters;
};

struct xol_area;

struct uprobes_state {
	struct xol_area *xol_area;
};

struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
};

struct file;

struct mm_cid;

struct linux_binfmt;

struct kioctx_table;

struct user_namespace;

struct mmu_notifier_subscriptions;

struct mm_struct {
	struct {
		struct {
			atomic_t mm_count;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
			long: 64;
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
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		struct mm_cid *pcpu_cid;
		long unsigned int mm_cid_next_scan;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		int mm_lock_seq;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[76];
		struct percpu_counter rss_stat[4];
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct task_struct *owner;
		struct user_namespace *user_ns;
		struct file *exe_file;
		struct mmu_notifier_subscriptions *notifier_subscriptions;
		long unsigned int numa_next_scan;
		long unsigned int numa_scan_offset;
		int numa_scan_seq;
		atomic_t tlb_flush_pending;
		struct uprobes_state uprobes_state;
		atomic_long_t hugetlb_usage;
		struct work_struct async_put_work;
		long unsigned int ksm_merging_pages;
		long unsigned int ksm_rmap_items;
		atomic_long_t ksm_zero_pages;
		long: 64;
		long: 64;
	};
	long unsigned int cpu_bitmap[0];
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

struct arch_uprobe_task {
	long unsigned int saved_trap_nr;
};

enum uprobe_task_state {
	UTASK_RUNNING = 0,
	UTASK_SSTEP = 1,
	UTASK_SSTEP_ACK = 2,
	UTASK_SSTEP_TRAPPED = 3,
};

struct uprobe;

struct return_instance;

struct uprobe_task {
	enum uprobe_task_state state;
	union {
		struct {
			struct arch_uprobe_task autask;
			long unsigned int vaddr;
		};
		struct {
			struct callback_head dup_xol_work;
			long unsigned int dup_xol_addr;
		};
	};
	struct uprobe *active_uprobe;
	long unsigned int xol_vaddr;
	struct return_instance *return_instances;
	unsigned int depth;
};

struct return_instance {
	struct uprobe *uprobe;
	long unsigned int func;
	long unsigned int stack;
	long unsigned int orig_ret_vaddr;
	bool chained;
	struct return_instance *next;
};

typedef long unsigned int vm_flags_t;

struct userfaultfd_ctx;

struct vm_userfaultfd_ctx {
	struct userfaultfd_ctx *ctx;
};

struct vma_lock {
	struct rw_semaphore lock;
};

struct vma_numab_state {
	long unsigned int next_scan;
	long unsigned int pids_active_reset;
	long unsigned int pids_active[2];
	int start_scan_seq;
	int prev_scan_seq;
};

struct anon_vma;

struct vm_operations_struct;

struct vm_area_struct {
	union {
		struct {
			long unsigned int vm_start;
			long unsigned int vm_end;
		};
		struct callback_head vm_rcu;
	};
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	union {
		const vm_flags_t vm_flags;
		vm_flags_t __vm_flags;
	};
	int vm_lock_seq;
	struct vma_lock *vm_lock;
	bool detached;
	struct {
		struct rb_node rb;
		long unsigned int rb_subtree_last;
	} shared;
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	long unsigned int vm_pgoff;
	struct file *vm_file;
	void *vm_private_data;
	atomic_long_t swap_readahead_info;
	struct mempolicy *vm_policy;
	struct vma_numab_state *numab_state;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

typedef unsigned int vm_fault_t;

struct vm_fault;

struct vm_operations_struct {
	void (*open)(struct vm_area_struct *);
	void (*close)(struct vm_area_struct *);
	int (*may_split)(struct vm_area_struct *, long unsigned int);
	int (*mremap)(struct vm_area_struct *);
	int (*mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault *);
	vm_fault_t (*huge_fault)(struct vm_fault *, unsigned int);
	vm_fault_t (*map_pages)(struct vm_fault *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct *);
	vm_fault_t (*page_mkwrite)(struct vm_fault *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *);
	int (*access)(struct vm_area_struct *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct *);
	int (*set_policy)(struct vm_area_struct *, struct mempolicy *);
	struct mempolicy * (*get_policy)(struct vm_area_struct *, long unsigned int, long unsigned int *);
	struct page * (*find_special_page)(struct vm_area_struct *, long unsigned int);
};

struct mm_cid {
	u64 time;
	int cid;
};

enum migratetype {
	MIGRATE_UNMOVABLE = 0,
	MIGRATE_MOVABLE = 1,
	MIGRATE_RECLAIMABLE = 2,
	MIGRATE_PCPTYPES = 3,
	MIGRATE_HIGHATOMIC = 3,
	MIGRATE_CMA = 4,
	MIGRATE_ISOLATE = 5,
	MIGRATE_TYPES = 6,
};

enum numa_stat_item {
	NUMA_HIT = 0,
	NUMA_MISS = 1,
	NUMA_FOREIGN = 2,
	NUMA_INTERLEAVE_HIT = 3,
	NUMA_LOCAL = 4,
	NUMA_OTHER = 5,
	NR_VM_NUMA_EVENT_ITEMS = 6,
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
	NR_ZSPAGES = 9,
	NR_FREE_CMA_PAGES = 10,
	NR_VM_ZONE_STAT_ITEMS = 11,
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
	NR_SWAPCACHE = 40,
	PGPROMOTE_SUCCESS = 41,
	PGPROMOTE_CANDIDATE = 42,
	PGDEMOTE_KSWAPD = 43,
	PGDEMOTE_DIRECT = 44,
	PGDEMOTE_KHUGEPAGED = 45,
	NR_VM_NODE_STAT_ITEMS = 46,
};

enum lru_list {
	LRU_INACTIVE_ANON = 0,
	LRU_ACTIVE_ANON = 1,
	LRU_INACTIVE_FILE = 2,
	LRU_ACTIVE_FILE = 3,
	LRU_UNEVICTABLE = 4,
	NR_LRU_LISTS = 5,
};

enum vmscan_throttle_state {
	VMSCAN_THROTTLE_WRITEBACK = 0,
	VMSCAN_THROTTLE_ISOLATED = 1,
	VMSCAN_THROTTLE_NOPROGRESS = 2,
	VMSCAN_THROTTLE_CONGESTED = 3,
	NR_VMSCAN_THROTTLE = 4,
};

enum {
	MM_LEAF_TOTAL = 0,
	MM_LEAF_OLD = 1,
	MM_LEAF_YOUNG = 2,
	MM_NONLEAF_TOTAL = 3,
	MM_NONLEAF_FOUND = 4,
	MM_NONLEAF_ADDED = 5,
	NR_MM_STATS = 6,
};

enum zone_watermarks {
	WMARK_MIN = 0,
	WMARK_LOW = 1,
	WMARK_HIGH = 2,
	WMARK_PROMO = 3,
	NR_WMARK = 4,
};

enum {
	ZONELIST_FALLBACK = 0,
	ZONELIST_NOFALLBACK = 1,
	MAX_ZONELISTS = 2,
};

enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};

union sigval {
	int sival_int;
	void *sival_ptr;
};

typedef union sigval sigval_t;

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
		void *_addr;
		union {
			int _trapno;
			short int _addr_lsb;
			struct {
				char _dummy_bnd[8];
				void *_lower;
				void *_upper;
			} _addr_bnd;
			struct {
				char _dummy_pkey[8];
				__u32 _pkey;
			} _addr_pkey;
			struct {
				long unsigned int _data;
				__u32 _type;
				__u32 _flags;
			} _perf;
		};
	} _sigfault;
	struct {
		long int _band;
		int _fd;
	} _sigpoll;
	struct {
		void *_call_addr;
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

enum rseq_cs_flags_bit {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT = 0,
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT = 1,
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT = 2,
};

struct rseq {
	__u32 cpu_id_start;
	__u32 cpu_id;
	__u64 rseq_cs;
	__u32 flags;
	__u32 node_id;
	__u32 mm_cid;
	char end[0];
};

typedef struct {
	gid_t val;
} kgid_t;

enum {
	TASK_COMM_LEN = 16,
};

struct rq_flags;

struct affinity_context;

struct sched_class {
	void (*enqueue_task)(struct rq *, struct task_struct *, int);
	void (*dequeue_task)(struct rq *, struct task_struct *, int);
	void (*yield_task)(struct rq *);
	bool (*yield_to_task)(struct rq *, struct task_struct *);
	void (*wakeup_preempt)(struct rq *, struct task_struct *, int);
	struct task_struct * (*pick_next_task)(struct rq *);
	void (*put_prev_task)(struct rq *, struct task_struct *);
	void (*set_next_task)(struct rq *, struct task_struct *, bool);
	int (*balance)(struct rq *, struct task_struct *, struct rq_flags *);
	int (*select_task_rq)(struct task_struct *, int, int);
	struct task_struct * (*pick_task)(struct rq *);
	void (*migrate_task_rq)(struct task_struct *, int);
	void (*task_woken)(struct rq *, struct task_struct *);
	void (*set_cpus_allowed)(struct task_struct *, struct affinity_context *);
	void (*rq_online)(struct rq *);
	void (*rq_offline)(struct rq *);
	struct rq * (*find_lock_rq)(struct task_struct *, struct rq *);
	void (*task_tick)(struct rq *, struct task_struct *, int);
	void (*task_fork)(struct task_struct *);
	void (*task_dead)(struct task_struct *);
	void (*switched_from)(struct rq *, struct task_struct *);
	void (*switched_to)(struct rq *, struct task_struct *);
	void (*prio_changed)(struct rq *, struct task_struct *, int);
	unsigned int (*get_rr_interval)(struct rq *, struct task_struct *);
	void (*update_curr)(struct rq *);
	void (*task_change_group)(struct task_struct *);
};

typedef struct {
	u64 val;
} kernel_cap_t;

struct user_struct;

struct ucounts;

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
	unsigned char jit_keyring;
	struct key *session_keyring;
	struct key *process_keyring;
	struct key *thread_keyring;
	struct key *request_key_auth;
	void *security;
	struct user_struct *user;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct group_info *group_info;
	union {
		int non_rcu;
		struct callback_head rcu;
	};
};

struct kernfs_root;

struct kernfs_elem_dir {
	long unsigned int subdirs;
	struct rb_root children;
	struct kernfs_root *root;
	long unsigned int rev;
};

struct kernfs_node;

struct kernfs_elem_symlink {
	struct kernfs_node *target_kn;
};

struct kernfs_ops;

struct kernfs_open_node;

struct kernfs_elem_attr {
	const struct kernfs_ops *ops;
	struct kernfs_open_node *open;
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
	short unsigned int flags;
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

struct kernfs_open_file;

struct seq_file;

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

enum kobj_ns_type {
	KOBJ_NS_TYPE_NONE = 0,
	KOBJ_NS_TYPE_NET = 1,
	KOBJ_NS_TYPES = 2,
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

struct attribute {
	const char *name;
	umode_t mode;
};

struct kobject;

struct bin_attribute;

struct attribute_group {
	const char *name;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int);
	struct attribute **attrs;
	struct bin_attribute **bin_attrs;
};

struct kset;

struct kobj_type;

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

struct sysfs_ops {
	ssize_t (*show)(struct kobject *, struct attribute *, char *);
	ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops;

struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
	const struct kset_uevent_ops *uevent_ops;
};

struct kobj_type {
	void (*release)(struct kobject *);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations * (*child_ns_type)(const struct kobject *);
	const void * (*namespace)(const struct kobject *);
	void (*get_ownership)(const struct kobject *, kuid_t *, kgid_t *);
};

struct kobj_uevent_env {
	char *argv[3];
	char *envp[64];
	int envp_idx;
	char buf[2048];
	int buflen;
};

struct kset_uevent_ops {
	int (* const filter)(const struct kobject *);
	const char * (* const name)(const struct kobject *);
	int (* const uevent)(const struct kobject *, struct kobj_uevent_env *);
};

enum dev_dma_attr {
	DEV_DMA_NOT_SUPPORTED = 0,
	DEV_DMA_NON_COHERENT = 1,
	DEV_DMA_COHERENT = 2,
};

struct fwnode_operations;

struct device;

struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
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

enum dl_dev_state {
	DL_DEV_NO_DRIVER = 0,
	DL_DEV_PROBING = 1,
	DL_DEV_DRIVER_BOUND = 2,
	DL_DEV_UNBINDING = 3,
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

struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};

typedef struct wait_queue_head wait_queue_head_t;

enum rpm_request {
	RPM_REQ_NONE = 0,
	RPM_REQ_IDLE = 1,
	RPM_REQ_SUSPEND = 2,
	RPM_REQ_AUTOSUSPEND = 3,
	RPM_REQ_RESUME = 4,
};

enum rpm_status {
	RPM_INVALID = -1,
	RPM_ACTIVE = 0,
	RPM_RESUMING = 1,
	RPM_SUSPENDED = 2,
	RPM_SUSPENDING = 3,
};

struct wakeup_source;

struct wake_irq;

struct pm_subsys_data;

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
	struct list_head entry;
	struct completion completion;
	struct wakeup_source *wakeup;
	bool wakeup_path: 1;
	bool syscore: 1;
	bool no_pm_callbacks: 1;
	bool async_in_progress: 1;
	bool must_resume: 1;
	bool may_skip_resume: 1;
	struct hrtimer suspend_timer;
	u64 timer_expires;
	struct work_struct work;
	wait_queue_head_t wait_queue;
	struct wake_irq *wakeirq;
	atomic_t usage_count;
	atomic_t child_count;
	unsigned int disable_depth: 3;
	bool idle_notification: 1;
	bool request_pending: 1;
	bool deferred_resume: 1;
	bool needs_force_resume: 1;
	bool runtime_auto: 1;
	bool ignore_children: 1;
	bool no_callbacks: 1;
	bool irq_safe: 1;
	bool use_autosuspend: 1;
	bool timer_autosuspends: 1;
	bool memalloc_noio: 1;
	unsigned int links_count;
	enum rpm_request request;
	enum rpm_status runtime_status;
	enum rpm_status last_status;
	int runtime_error;
	int autosuspend_delay;
	u64 last_busy;
	u64 active_time;
	u64 suspended_time;
	u64 accounting_timestamp;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device *, s32);
	struct dev_pm_qos *qos;
};

struct irq_domain;

struct msi_device_data;

struct dev_msi_info {
	struct irq_domain *domain;
	struct msi_device_data *data;
};

typedef u64 dma_addr_t;

struct iommu_table;

struct pci_dn;

struct eeh_dev;

struct cxl_context;

struct dev_archdata {
	dma_addr_t dma_offset;
	struct iommu_table *iommu_table_base;
	struct pci_dn *pci_data;
	struct eeh_dev *edev;
	struct cxl_context *cxl_ctx;
	void *iov_data;
};

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

enum device_removable {
	DEVICE_REMOVABLE_NOT_SUPPORTED = 0,
	DEVICE_REMOVABLE_UNKNOWN = 1,
	DEVICE_FIXED = 2,
	DEVICE_REMOVABLE = 3,
};

struct device_private;

struct device_type;

struct bus_type;

struct device_driver;

struct dev_pm_domain;

struct em_perf_domain;

struct dma_map_ops;

struct bus_dma_region;

struct device_dma_parameters;

struct dma_coherent_mem;

struct io_tlb_mem;

struct device_node;

struct class;

struct iommu_group;

struct dev_iommu;

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
	struct em_perf_domain *em_pd;
	struct dev_msi_info msi;
	const struct dma_map_ops *dma_ops;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct dma_coherent_mem *dma_mem;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	int numa_node;
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
	bool dma_ops_bypass: 1;
};

struct fwnode_endpoint {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle *local_fwnode;
};

struct fwnode_reference_args {
	struct fwnode_handle *fwnode;
	unsigned int nargs;
	u64 args[8];
};

typedef u32 phandle;

struct property {
	char *name;
	int length;
	void *value;
	struct property *next;
	long unsigned int _flags;
	struct bin_attribute attr;
};

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
	struct kobject kobj;
	long unsigned int _flags;
	void *data;
};

enum {
	false = 0,
	true = 1,
};

struct static_key_true {
	struct static_key key;
};

struct ppc_cache_info {
	u32 size;
	u32 line_size;
	u32 block_size;
	u32 log_block_size;
	u32 blocks_per_page;
	u32 sets;
	u32 assoc;
};

struct ppc64_caches {
	struct ppc_cache_info l1d;
	struct ppc_cache_info l1i;
	struct ppc_cache_info l2;
	struct ppc_cache_info l3;
};

enum {
	MMU_FTRS_POSSIBLE = 4261477953,
};

typedef struct {
	u32 val;
	u32 suffix;
} ppc_inst_t;

enum instruction_type {
	COMPUTE = 0,
	LOAD = 1,
	LOAD_MULTI = 2,
	LOAD_FP = 3,
	LOAD_VMX = 4,
	LOAD_VSX = 5,
	STORE = 6,
	STORE_MULTI = 7,
	STORE_FP = 8,
	STORE_VMX = 9,
	STORE_VSX = 10,
	LARX = 11,
	STCX = 12,
	BRANCH = 13,
	MFSPR = 14,
	MTSPR = 15,
	CACHEOP = 16,
	BARRIER = 17,
	SYSCALL = 18,
	SYSCALL_VECTORED_0 = 19,
	MFMSR = 20,
	MTMSR = 21,
	RFI = 22,
	INTERRUPT = 23,
	UNKNOWN = 24,
};

struct instruction_op {
	int type;
	int reg;
	long unsigned int val;
	long unsigned int ea;
	int update_reg;
	int spr;
	u32 ccval;
	u32 xerval;
	u8 element_size;
	u8 vsx_flags;
};

typedef signed char __s8;

typedef __s8 s8;

typedef s32 int32_t;

typedef u32 uint32_t;

typedef u64 sector_t;

typedef u64 blkcnt_t;

typedef unsigned int fmode_t;

struct lock_class_key {};

struct fs_context;

struct fs_parameter_spec;

struct dentry;

struct super_block;

struct module;

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

struct qrwlock {
	union {
		atomic_t cnts;
		struct {
			u8 __lstate[3];
			u8 wlocked;
		};
	};
	arch_spinlock_t wait_lock;
};

typedef struct qrwlock arch_rwlock_t;

struct lockdep_map {};

struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	long unsigned int begin;
	long unsigned int flags;
};

struct _ddebug {
	const char *modname;
	const char *function;
	const char *filename;
	const char *format;
	unsigned int lineno: 18;
	unsigned int class_id: 6;
	unsigned int flags: 8;
	union {
		struct static_key_true dd_key_true;
		struct static_key_false dd_key_false;
	} key;
};

enum class_map_type {
	DD_CLASS_TYPE_DISJOINT_BITS = 0,
	DD_CLASS_TYPE_LEVEL_NUM = 1,
	DD_CLASS_TYPE_DISJOINT_NAMES = 2,
	DD_CLASS_TYPE_LEVEL_NAMES = 3,
};

struct ddebug_class_map {
	struct list_head link;
	struct module *mod;
	const char *mod_name;
	const char **class_names;
	const int length;
	const int base;
	enum class_map_type map_type;
};

enum module_state {
	MODULE_STATE_LIVE = 0,
	MODULE_STATE_COMING = 1,
	MODULE_STATE_GOING = 2,
	MODULE_STATE_UNFORMED = 3,
};

struct module_param_attrs;

struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct latch_tree_node {
	struct rb_node node[2];
};

struct mod_tree_node {
	struct module *mod;
	struct latch_tree_node node;
};

struct module_memory {
	void *base;
	unsigned int size;
	struct mod_tree_node mtn;
};

struct bug_entry;

struct mod_arch_specific {
	unsigned int stubs_section;
	unsigned int toc_section;
	bool toc_fixed;
	long unsigned int start_opd;
	long unsigned int end_opd;
	long unsigned int tramp;
	long unsigned int tramp_regs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	unsigned int num_bugs;
};

struct elf64_sym;

typedef struct elf64_sym Elf64_Sym;

struct mod_kallsyms {
	Elf64_Sym *symtab;
	unsigned int num_symtab;
	char *strtab;
	char *typetab;
};

struct _ddebug_info {
	struct _ddebug *descs;
	struct ddebug_class_map *classes;
	unsigned int num_descs;
	unsigned int num_classes;
};

struct module_attribute;

struct kernel_symbol;

struct kernel_param;

struct exception_table_entry;

struct module_sect_attrs;

struct module_notes_attrs;

struct tracepoint;

typedef struct tracepoint * const tracepoint_ptr_t;

struct srcu_struct;

struct bpf_raw_event_map;

struct trace_event_call;

struct trace_eval_map;

struct module {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject mkobj;
	struct module_attribute *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool sig_ok;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct module_memory mem[7];
	struct mod_arch_specific arch;
	long unsigned int taints;
	unsigned int num_bugs;
	struct list_head bug_list;
	struct bug_entry *bug_table;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	struct jump_entry *jump_entries;
	unsigned int num_jump_entries;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	struct list_head source_list;
	struct list_head target_list;
	void (*exit)();
	atomic_t refcnt;
	struct _ddebug_info dyndbg_info;
	long: 64;
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

struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
	void (*free)(void *);
};

typedef void *fl_owner_t;

struct kiocb;

struct iov_iter;

struct io_comp_batch;

struct dir_context;

struct inode;

struct file_lock;

struct file_lease;

struct io_uring_cmd;

struct file_operations {
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
	int (*iterate_shared)(struct file *, struct dir_context *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	long int (*unlocked_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*mmap)(struct file *, struct vm_area_struct *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, fl_owner_t);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int);
	int (*fasync)(int, struct file *, int);
	int (*lock)(struct file *, int, struct file_lock *);
	long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*splice_eof)(struct file *);
	int (*setlease)(struct file *, int, struct file_lease **, void **);
	long int (*fallocate)(struct file *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file *, struct file *);
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct bug_entry {
	int bug_addr_disp;
	int file_disp;
	short unsigned int line;
	short unsigned int flags;
};

struct static_call_key {
	void *func;
};

typedef struct {
	__be64 pte;
} pte_t;

typedef struct {
	__be64 pmd;
} pmd_t;

typedef struct {
	__be64 pud;
} pud_t;

typedef pte_t *pgtable_t;

struct exception_table_entry {
	int insn;
	int fixup;
};

struct xarray {
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void *xa_head;
};

struct idr {
	struct xarray idr_rt;
	unsigned int idr_base;
	unsigned int idr_next;
};

struct proc_ns_operations;

struct ns_common {
	struct dentry *stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	refcount_t count;
};

struct kmem_cache;

struct fs_pin;

struct pid_namespace {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
	struct fs_pin *bacct;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
	int memfd_noexec_scope;
};

typedef struct {
	arch_rwlock_t raw_lock;
} rwlock_t;

struct seqcount_raw_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;

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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct rlimit {
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
};

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t();

typedef __restorefn_t *__sigrestore_t;

struct sigaction {
	__sighandler_t sa_handler;
	long unsigned int sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;
};

struct k_sigaction {
	struct sigaction sa;
};

typedef struct {
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

typedef u32 errseq_t;

struct address_space_operations;

struct address_space {
	struct inode *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t i_private_lock;
	struct list_head i_private_list;
	struct rw_semaphore i_mmap_rwsem;
	void *i_private_data;
};

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

typedef int32_t key_serial_t;

typedef __s64 time64_t;

typedef uint32_t key_perm_t;

struct key_type;

struct key_tag;

struct keyring_index_key {
	long unsigned int hash;
	union {
		struct {
			char desc[6];
			u16 desc_len;
		};
		long unsigned int x;
	};
	struct key_type *type;
	struct key_tag *domain_tag;
	const char *description;
};

union key_payload {
	void *rcu_data0;
	void *data[4];
};

struct assoc_array_ptr;

struct assoc_array {
	struct assoc_array_ptr *root;
	long unsigned int nr_leaves_on_tree;
};

struct key_user;

struct key_restriction;

struct key {
	refcount_t usage;
	key_serial_t serial;
	union {
		struct list_head graveyard_link;
		struct rb_node serial_node;
	};
	struct rw_semaphore sem;
	struct key_user *user;
	void *security;
	union {
		time64_t expiry;
		time64_t revoked_at;
	};
	time64_t last_used_at;
	kuid_t uid;
	kgid_t gid;
	key_perm_t perm;
	short unsigned int quotalen;
	short unsigned int datalen;
	short int state;
	long unsigned int flags;
	union {
		struct keyring_index_key index_key;
		struct {
			long unsigned int hash;
			long unsigned int len_desc;
			struct key_type *type;
			struct key_tag *domain_tag;
			char *description;
		};
	};
	union {
		union key_payload payload;
		struct {
			struct list_head name_link;
			struct assoc_array keys;
		};
	};
	struct key_restriction *restrict_link;
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

struct cpu_itimer {
	u64 expires;
	u64 incr;
};

struct task_cputime_atomic {
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};

struct thread_group_cputimer {
	struct task_cputime_atomic cputime_atomic;
};

struct pacct_struct {
	int ac_flag;
	long int ac_exitcode;
	long unsigned int ac_mem;
	u64 ac_utime;
	u64 ac_stime;
	long unsigned int ac_minflt;
	long unsigned int ac_majflt;
};

struct core_state;

struct tty_struct;

struct autogroup;

struct taskstats;

struct tty_audit_buf;

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
	unsigned int next_posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	atomic_t tick_dep_mask;
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct *tty;
	struct autogroup *autogroup;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	struct pacct_struct pacct;
	struct taskstats *stats;
	unsigned int audit_tty;
	struct tty_audit_buf *tty_audit_buf;
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct sighand_struct {
	spinlock_t siglock;
	refcount_t count;
	wait_queue_head_t signalfd_wqh;
	struct k_sigaction action[64];
};

struct io_cq;

struct io_context {
	atomic_long_t refcount;
	atomic_t active_ref;
	short unsigned int ioprio;
	spinlock_t lock;
	struct xarray icq_tree;
	struct io_cq *icq_hint;
	struct hlist_head icq_list;
	struct work_struct release_work;
};

typedef u32 compat_uptr_t;

struct compat_robust_list {
	compat_uptr_t next;
};

typedef s32 compat_long_t;

struct compat_robust_list_head {
	struct compat_robust_list list;
	compat_long_t futex_offset;
	compat_uptr_t list_op_pending;
};

enum ctx_state {
	CONTEXT_DISABLED = -1,
	CONTEXT_KERNEL = 0,
	CONTEXT_IDLE = 1,
	CONTEXT_USER = 2,
	CONTEXT_GUEST = 3,
	CONTEXT_MAX = 4,
};

struct context_tracking {
	bool active;
	int recursion;
	atomic_t state;
	long int dynticks_nesting;
	long int dynticks_nmi_nesting;
};

struct timespec64 {
	time64_t tv_sec;
	long int tv_nsec;
};

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

struct workqueue_struct;

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
};

struct rcu_segcblist {
	struct callback_head *head;
	struct callback_head **tails[4];
	long unsigned int gp_seq[4];
	atomic_long_t len;
	long int seglen[4];
	u8 flags;
};

struct srcu_node;

struct srcu_data {
	atomic_long_t srcu_lock_count[2];
	atomic_long_t srcu_unlock_count[2];
	int srcu_nmi_safety;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t lock;
	struct rcu_segcblist srcu_cblist;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	bool srcu_cblist_invoking;
	struct timer_list delay_work;
	struct work_struct work;
	struct callback_head srcu_barrier_head;
	struct srcu_node *mynode;
	long unsigned int grpmask;
	int cpu;
	struct srcu_struct *ssp;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct srcu_node {
	spinlock_t lock;
	long unsigned int srcu_have_cbs[4];
	long unsigned int srcu_data_have_cbs[4];
	long unsigned int srcu_gp_seq_needed_exp;
	struct srcu_node *srcu_parent;
	int grplo;
	int grphi;
};

struct srcu_usage;

struct srcu_struct {
	unsigned int srcu_idx;
	struct srcu_data *sda;
	struct lockdep_map dep_map;
	struct srcu_usage *srcu_sup;
};

struct srcu_usage {
	struct srcu_node *node;
	struct srcu_node *level[4];
	int srcu_size_state;
	struct mutex srcu_cb_mutex;
	spinlock_t lock;
	struct mutex srcu_gp_mutex;
	long unsigned int srcu_gp_seq;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	long unsigned int srcu_gp_start;
	long unsigned int srcu_last_gp_end;
	long unsigned int srcu_size_jiffies;
	long unsigned int srcu_n_lock_retries;
	long unsigned int srcu_n_exp_nodelay;
	bool sda_is_static;
	long unsigned int srcu_barrier_seq;
	struct mutex srcu_barrier_mutex;
	struct completion srcu_barrier_completion;
	atomic_t srcu_barrier_cpu_cnt;
	long unsigned int reschedule_jiffies;
	long unsigned int reschedule_count;
	struct delayed_work work;
	struct srcu_struct *srcu_ssp;
};

struct vmem_altmap {
	long unsigned int base_pfn;
	const long unsigned int end_pfn;
	const long unsigned int reserve;
	long unsigned int free;
	long unsigned int align;
	long unsigned int alloc;
	bool inaccessible;
};

struct percpu_ref_data;

struct percpu_ref {
	long unsigned int percpu_count_ptr;
	struct percpu_ref_data *data;
};

enum memory_type {
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_COHERENT = 2,
	MEMORY_DEVICE_FS_DAX = 3,
	MEMORY_DEVICE_GENERIC = 4,
	MEMORY_DEVICE_PCI_P2PDMA = 5,
};

struct range {
	u64 start;
	u64 end;
};

struct dev_pagemap_ops;

struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
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

typedef struct {
	long unsigned int val;
} swp_entry_t;

struct folio {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			union {
				void *private;
				swp_entry_t swap;
			};
			atomic_t _mapcount;
			atomic_t _refcount;
			long unsigned int memcg_data;
		};
		struct page page;
	};
	union {
		struct {
			long unsigned int _flags_1;
			long unsigned int _head_1;
			long unsigned int _folio_avail;
			atomic_t _entire_mapcount;
			atomic_t _nr_pages_mapped;
			atomic_t _pincount;
			unsigned int _folio_nr_pages;
		};
		struct page __page_1;
	};
	union {
		struct {
			long unsigned int _flags_2;
			long unsigned int _head_2;
			void *_hugetlb_subpool;
			void *_hugetlb_cgroup;
			void *_hugetlb_cgroup_rsvd;
			void *_hugetlb_hwpoison;
		};
		struct {
			long unsigned int _flags_2a;
			long unsigned int _head_2a;
			struct list_head _deferred_list;
		};
		struct page __page_2;
	};
};

struct fown_struct {
	rwlock_t lock;
	struct pid *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

struct file_ra_state {
	long unsigned int start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	loff_t prev_pos;
};

struct vfsmount;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

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
	void *f_security;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
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

struct vm_fault {
	const struct {
		struct vm_area_struct *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
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

struct iovec {
	void *iov_base;
	__kernel_size_t iov_len;
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
				void *ubuf;
			};
			size_t count;
		};
	};
	union {
		long unsigned int nr_segs;
		loff_t xarray_start;
	};
};

struct wait_page_queue;

struct kiocb {
	struct file *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	union {
		struct wait_page_queue *ki_waitq;
		ssize_t (*dio_complete)(void *);
	};
};

struct hlist_bl_node;

struct hlist_bl_head {
	struct hlist_bl_node *first;
};

struct hlist_bl_node {
	struct hlist_bl_node *next;
	struct hlist_bl_node **pprev;
};

struct lockref {
	union {
		__u64 lock_count;
		struct {
			spinlock_t lock;
			int count;
		};
	};
};

struct qstr {
	union {
		struct {
			u32 len;
			u32 hash;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

struct dentry_operations;

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
	long unsigned int d_time;
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

enum rw_hint {
	WRITE_LIFE_NOT_SET = 0,
	WRITE_LIFE_NONE = 1,
	WRITE_LIFE_SHORT = 2,
	WRITE_LIFE_MEDIUM = 3,
	WRITE_LIFE_LONG = 4,
	WRITE_LIFE_EXTREME = 5,
} __attribute__((mode(byte)));

struct posix_acl;

struct inode_operations;

struct bdi_writeback;

struct file_lock_context;

struct cdev;

struct fsnotify_mark_connector;

struct fscrypt_inode_info;

struct fsverity_info;

struct inode {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	struct posix_acl *i_acl;
	struct posix_acl *i_default_acl;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	void *i_security;
	long unsigned int i_ino;
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
	short unsigned int i_bytes;
	u8 i_blkbits;
	enum rw_hint i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct bdi_writeback *i_wb;
	int i_wb_frn_winner;
	u16 i_wb_frn_avg_time;
	u16 i_wb_frn_history;
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
	atomic_t i_readcount;
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
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	struct fscrypt_inode_info *i_crypt_info;
	struct fsverity_info *i_verity_info;
	void *i_private;
};

enum d_real_type {
	D_REAL_DATA = 0,
	D_REAL_METADATA = 1,
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

struct mtd_info;

typedef long long int qsize_t;

struct quota_format_type;

struct mem_dqinfo {
	struct quota_format_type *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
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
	struct task_struct *task;
};

struct percpu_rw_semaphore {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers {
	short unsigned int frozen;
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
	struct list_head list;
	int shrinker_id;
	bool memcg_aware;
	struct xarray xa;
};

struct super_operations;

struct dquot_operations;

struct quotactl_ops;

struct export_operations;

struct xattr_handler;

struct fscrypt_operations;

struct fscrypt_keyring;

struct fsverity_operations;

struct unicode_map;

struct block_device;

struct backing_dev_info;

struct shrinker;

struct super_block {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type *s_type;
	const struct super_operations *s_op;
	const struct dquot_operations *dq_op;
	const struct quotactl_ops *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	void *s_security;
	const struct xattr_handler * const *s_xattr;
	const struct fscrypt_operations *s_cop;
	struct fscrypt_keyring *s_master_keys;
	const struct fsverity_operations *s_vop;
	struct unicode_map *s_encoding;
	__u16 s_encoding_flags;
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
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
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

struct mnt_idmap;

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
	int mnt_flags;
	struct mnt_idmap *mnt_idmap;
};

struct shrink_control {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup *memcg;
};

struct shrinker {
	long unsigned int (*count_objects)(struct shrinker *, struct shrink_control *);
	long unsigned int (*scan_objects)(struct shrinker *, struct shrink_control *);
	long int batch;
	int seeks;
	unsigned int flags;
	refcount_t refcount;
	struct completion done;
	struct callback_head rcu;
	void *private_data;
	struct list_head list;
	int id;
	atomic_long_t *nr_deferred;
};

struct list_lru_one {
	struct list_head list;
	long int nr_items;
};

struct list_lru_node {
	spinlock_t lock;
	struct list_lru_one lru;
	long int nr_items;
	long: 64;
	long: 64;
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

enum migrate_mode {
	MIGRATE_ASYNC = 0,
	MIGRATE_SYNC_LIGHT = 1,
	MIGRATE_SYNC = 2,
	MIGRATE_SYNC_NO_COPY = 3,
};

struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};

struct tracepoint {
	const char *name;
	struct static_key key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	void *probestub;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func *funcs;
};

struct bpf_raw_event_map {
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};

struct key_tag {
	struct callback_head rcu;
	refcount_t usage;
	bool removed;
};

typedef int (*request_key_actor_t)(struct key *, void *);

struct key_preparsed_payload;

struct key_match_data;

struct kernel_pkey_params;

struct kernel_pkey_query;

struct key_type {
	const char *name;
	size_t def_datalen;
	unsigned int flags;
	int (*vet_description)(const char *);
	int (*preparse)(struct key_preparsed_payload *);
	void (*free_preparse)(struct key_preparsed_payload *);
	int (*instantiate)(struct key *, struct key_preparsed_payload *);
	int (*update)(struct key *, struct key_preparsed_payload *);
	int (*match_preparse)(struct key_match_data *);
	void (*match_free)(struct key_match_data *);
	void (*revoke)(struct key *);
	void (*destroy)(struct key *);
	void (*describe)(const struct key *, struct seq_file *);
	long int (*read)(const struct key *, char *, size_t);
	request_key_actor_t request_key;
	struct key_restriction * (*lookup_restriction)(const char *);
	int (*asym_query)(const struct kernel_pkey_params *, struct kernel_pkey_query *);
	int (*asym_eds_op)(struct kernel_pkey_params *, const void *, void *);
	int (*asym_verify_signature)(struct kernel_pkey_params *, const void *, const void *);
	struct list_head link;
	struct lock_class_key lock_class;
};

typedef int (*key_restrict_link_func_t)(struct key *, const struct key_type *, const union key_payload *, struct key *);

struct key_restriction {
	key_restrict_link_func_t check;
	struct key *key;
	struct key_type *keytype;
};

struct user_struct {
	refcount_t __count;
	struct percpu_counter epoll_watches;
	long unsigned int unix_inflight;
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
	unsigned int nr_events;
	short unsigned int nr_retries;
	short unsigned int nr_hangs;
	unsigned int max_hang_time;
	ktime_t expires_next;
	struct hrtimer *next_timer;
	ktime_t softirq_expires_next;
	struct hrtimer *softirq_next_timer;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct hrtimer_clock_base clock_base[8];
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

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

struct delayed_call {
	void (*fn)(void *);
	void *arg;
};

struct request_queue;

struct io_cq {
	struct request_queue *q;
	struct io_context *ioc;
	union {
		struct list_head q_node;
		struct kmem_cache *__rcu_icq_cache;
	};
	union {
		struct hlist_node ioc_node;
		struct callback_head __rcu_head;
	};
	unsigned int flags;
};

typedef struct {
	uid_t val;
} vfsuid_t;

typedef struct {
	gid_t val;
} vfsgid_t;

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

enum kmalloc_cache_type {
	KMALLOC_NORMAL = 0,
	KMALLOC_DMA = 0,
	KMALLOC_RANDOM_START = 0,
	KMALLOC_RANDOM_END = 0,
	KMALLOC_RECLAIM = 1,
	KMALLOC_CGROUP = 2,
	NR_KMALLOC_TYPES = 3,
};

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

typedef __kernel_uid32_t projid_t;

typedef struct {
	projid_t val;
} kprojid_t;

enum quota_type {
	USRQUOTA = 0,
	GRPQUOTA = 1,
	PRJQUOTA = 2,
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
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

enum {
	DQF_ROOT_SQUASH_B = 0,
	DQF_SYS_FILE_B = 16,
	DQF_PRIVATE = 17,
};

struct quota_format_type {
	int qf_fmt_id;
	const struct quota_format_ops *qf_ops;
	struct module *qf_owner;
	struct quota_format_type *qf_next;
};

enum {
	DQST_LOOKUPS = 0,
	DQST_DROPS = 1,
	DQST_READS = 2,
	DQST_WRITES = 3,
	DQST_CACHE_HITS = 4,
	DQST_ALLOC_DQUOTS = 5,
	DQST_FREE_DQUOTS = 6,
	DQST_SYNCS = 7,
	_DQST_DQSTAT_LAST = 8,
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
	long long unsigned int ino;
	blkcnt_t blocks;
	blkcnt_t nextents;
};

struct qc_state {
	unsigned int s_incoredqs;
	struct qc_type_state s_state[3];
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

struct writeback_control;

struct readahead_control;

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

struct fiemap_extent_info;

struct fileattr;

struct offset_ctx;

struct inode_operations {
	struct dentry * (*lookup)(struct inode *, struct dentry *, unsigned int);
	const char * (*get_link)(struct dentry *, struct inode *, struct delayed_call *);
	int (*permission)(struct mnt_idmap *, struct inode *, int);
	struct posix_acl * (*get_inode_acl)(struct inode *, int, bool);
	int (*readlink)(struct dentry *, char *, int);
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

enum {
	SB_UNFROZEN = 0,
	SB_FREEZE_WRITE = 1,
	SB_FREEZE_PAGEFAULT = 2,
	SB_FREEZE_FS = 3,
	SB_FREEZE_COMPLETE = 4,
};

enum freeze_holder {
	FREEZE_HOLDER_KERNEL = 1,
	FREEZE_HOLDER_USERSPACE = 2,
	FREEZE_MAY_NEST = 4,
};

struct kstatfs;

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
	ssize_t (*quota_read)(struct super_block *, int, char *, size_t, loff_t);
	ssize_t (*quota_write)(struct super_block *, int, const char *, size_t, loff_t);
	struct dquot ** (*get_dquots)(struct inode *);
	long int (*nr_cached_objects)(struct super_block *, struct shrink_control *);
	long int (*free_cached_objects)(struct super_block *, struct shrink_control *);
	void (*shutdown)(struct super_block *);
};

struct fid;

struct iomap;

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
	long unsigned int flags;
};

struct xattr_handler {
	const char *name;
	const char *prefix;
	int flags;
	bool (*list)(struct dentry *);
	int (*get)(const struct xattr_handler *, struct dentry *, struct inode *, const char *, void *, size_t);
	int (*set)(const struct xattr_handler *, struct mnt_idmap *, struct dentry *, struct inode *, const char *, const void *, size_t, int);
};

union fscrypt_policy;

struct fscrypt_operations {
	unsigned int needs_bounce_pages: 1;
	unsigned int has_32bit_inodes: 1;
	unsigned int supports_subblock_data_units: 1;
	const char *legacy_key_prefix;
	int (*get_context)(struct inode *, void *, size_t);
	int (*set_context)(struct inode *, const void *, size_t, void *);
	const union fscrypt_policy * (*get_dummy_policy)(struct super_block *);
	bool (*empty_dir)(struct inode *);
	bool (*has_stable_inodes)(struct super_block *);
	struct block_device ** (*get_devices)(struct super_block *, unsigned int *);
};

struct fsverity_operations {
	int (*begin_enable_verity)(struct file *);
	int (*end_enable_verity)(struct file *, const void *, size_t, u64);
	int (*get_verity_descriptor)(struct inode *, void *, size_t);
	struct page * (*read_merkle_tree_page)(struct inode *, long unsigned int, long unsigned int);
	int (*write_merkle_tree_block)(struct inode *, const void *, u64, unsigned int);
};

typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);

struct dir_context {
	filldir_t actor;
	loff_t pos;
};

struct offset_ctx {
	struct maple_tree mt;
	long unsigned int next_offset;
};

struct p_log;

struct fs_parameter;

struct fs_parse_result;

typedef int fs_param_type(struct p_log *, const struct fs_parameter_spec *, struct fs_parameter *, struct fs_parse_result *);

struct fs_parameter_spec {
	const char *name;
	fs_param_type *type;
	u8 opt;
	short unsigned int flags;
	const void *data;
};

enum rseq_event_mask_bits {
	RSEQ_EVENT_PREEMPT_BIT = 0,
	RSEQ_EVENT_SIGNAL_BIT = 1,
	RSEQ_EVENT_MIGRATE_BIT = 2,
};

enum cpu_idle_type {
	CPU_IDLE = 0,
	CPU_NOT_IDLE = 1,
	CPU_NEWLY_IDLE = 2,
	CPU_MAX_IDLE_TYPES = 3,
};

enum {
	__SD_BALANCE_NEWIDLE = 0,
	__SD_BALANCE_EXEC = 1,
	__SD_BALANCE_FORK = 2,
	__SD_BALANCE_WAKE = 3,
	__SD_WAKE_AFFINE = 4,
	__SD_ASYM_CPUCAPACITY = 5,
	__SD_ASYM_CPUCAPACITY_FULL = 6,
	__SD_SHARE_CPUCAPACITY = 7,
	__SD_CLUSTER = 8,
	__SD_SHARE_LLC = 9,
	__SD_SERIALIZE = 10,
	__SD_ASYM_PACKING = 11,
	__SD_PREFER_SIBLING = 12,
	__SD_OVERLAP = 13,
	__SD_NUMA = 14,
	__SD_FLAG_CNT = 15,
};

typedef __u64 Elf64_Addr;

typedef __u16 Elf64_Half;

typedef __u32 Elf64_Word;

typedef __u64 Elf64_Xword;

struct elf64_sym {
	Elf64_Word st_name;
	unsigned char st_info;
	unsigned char st_other;
	Elf64_Half st_shndx;
	Elf64_Addr st_value;
	Elf64_Xword st_size;
};

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

struct module_attribute {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute *, struct module_kobject *, char *);
	ssize_t (*store)(struct module_attribute *, struct module_kobject *, const char *, size_t);
	void (*setup)(struct module *, const char *);
	int (*test)(struct module *);
	void (*free)(struct module *);
};

enum mod_mem_type {
	MOD_TEXT = 0,
	MOD_DATA = 1,
	MOD_RODATA = 2,
	MOD_RO_AFTER_INIT = 3,
	MOD_INIT_TEXT = 4,
	MOD_INIT_DATA = 5,
	MOD_INIT_RODATA = 6,
	MOD_MEM_NUM_TYPES = 7,
	MOD_INVALID = -1,
};

struct kernel_symbol {
	long unsigned int value;
	const char *name;
	const char *namespace;
};

struct dev_pagemap_ops {
	void (*page_free)(struct page *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault *);
	int (*memory_failure)(struct dev_pagemap *, long unsigned int, long unsigned int, int);
};

enum vm_event_item {
	PGPGIN = 0,
	PGPGOUT = 1,
	PSWPIN = 2,
	PSWPOUT = 3,
	PGALLOC_NORMAL = 4,
	PGALLOC_MOVABLE = 5,
	ALLOCSTALL_NORMAL = 6,
	ALLOCSTALL_MOVABLE = 7,
	PGSCAN_SKIP_NORMAL = 8,
	PGSCAN_SKIP_MOVABLE = 9,
	PGFREE = 10,
	PGACTIVATE = 11,
	PGDEACTIVATE = 12,
	PGLAZYFREE = 13,
	PGFAULT = 14,
	PGMAJFAULT = 15,
	PGLAZYFREED = 16,
	PGREFILL = 17,
	PGREUSE = 18,
	PGSTEAL_KSWAPD = 19,
	PGSTEAL_DIRECT = 20,
	PGSTEAL_KHUGEPAGED = 21,
	PGSCAN_KSWAPD = 22,
	PGSCAN_DIRECT = 23,
	PGSCAN_KHUGEPAGED = 24,
	PGSCAN_DIRECT_THROTTLE = 25,
	PGSCAN_ANON = 26,
	PGSCAN_FILE = 27,
	PGSTEAL_ANON = 28,
	PGSTEAL_FILE = 29,
	PGSCAN_ZONE_RECLAIM_FAILED = 30,
	PGINODESTEAL = 31,
	SLABS_SCANNED = 32,
	KSWAPD_INODESTEAL = 33,
	KSWAPD_LOW_WMARK_HIT_QUICKLY = 34,
	KSWAPD_HIGH_WMARK_HIT_QUICKLY = 35,
	PAGEOUTRUN = 36,
	PGROTATED = 37,
	DROP_PAGECACHE = 38,
	DROP_SLAB = 39,
	OOM_KILL = 40,
	NUMA_PTE_UPDATES = 41,
	NUMA_HUGE_PTE_UPDATES = 42,
	NUMA_HINT_FAULTS = 43,
	NUMA_HINT_FAULTS_LOCAL = 44,
	NUMA_PAGE_MIGRATE = 45,
	PGMIGRATE_SUCCESS = 46,
	PGMIGRATE_FAIL = 47,
	THP_MIGRATION_SUCCESS = 48,
	THP_MIGRATION_FAIL = 49,
	THP_MIGRATION_SPLIT = 50,
	COMPACTMIGRATE_SCANNED = 51,
	COMPACTFREE_SCANNED = 52,
	COMPACTISOLATED = 53,
	COMPACTSTALL = 54,
	COMPACTFAIL = 55,
	COMPACTSUCCESS = 56,
	KCOMPACTD_WAKE = 57,
	KCOMPACTD_MIGRATE_SCANNED = 58,
	KCOMPACTD_FREE_SCANNED = 59,
	HTLB_BUDDY_PGALLOC = 60,
	HTLB_BUDDY_PGALLOC_FAIL = 61,
	CMA_ALLOC_SUCCESS = 62,
	CMA_ALLOC_FAIL = 63,
	UNEVICTABLE_PGCULLED = 64,
	UNEVICTABLE_PGSCANNED = 65,
	UNEVICTABLE_PGRESCUED = 66,
	UNEVICTABLE_PGMLOCKED = 67,
	UNEVICTABLE_PGMUNLOCKED = 68,
	UNEVICTABLE_PGCLEARED = 69,
	UNEVICTABLE_PGSTRANDED = 70,
	THP_FAULT_ALLOC = 71,
	THP_FAULT_FALLBACK = 72,
	THP_FAULT_FALLBACK_CHARGE = 73,
	THP_COLLAPSE_ALLOC = 74,
	THP_COLLAPSE_ALLOC_FAILED = 75,
	THP_FILE_ALLOC = 76,
	THP_FILE_FALLBACK = 77,
	THP_FILE_FALLBACK_CHARGE = 78,
	THP_FILE_MAPPED = 79,
	THP_SPLIT_PAGE = 80,
	THP_SPLIT_PAGE_FAILED = 81,
	THP_DEFERRED_SPLIT_PAGE = 82,
	THP_SPLIT_PMD = 83,
	THP_SCAN_EXCEED_NONE_PTE = 84,
	THP_SCAN_EXCEED_SWAP_PTE = 85,
	THP_SCAN_EXCEED_SHARED_PTE = 86,
	THP_SPLIT_PUD = 87,
	THP_ZERO_PAGE_ALLOC = 88,
	THP_ZERO_PAGE_ALLOC_FAILED = 89,
	THP_SWPOUT = 90,
	THP_SWPOUT_FALLBACK = 91,
	BALLOON_INFLATE = 92,
	BALLOON_DEFLATE = 93,
	BALLOON_MIGRATE = 94,
	SWAP_RA = 95,
	SWAP_RA_HIT = 96,
	KSM_SWPIN_COPY = 97,
	COW_KSM = 98,
	ZSWPIN = 99,
	ZSWPOUT = 100,
	ZSWPWB = 101,
	NR_VM_EVENT_ITEMS = 102,
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

struct cacheline_padding {
	char x[0];
};

enum fortify_func {
	FORTIFY_FUNC_strncpy = 0,
	FORTIFY_FUNC_strnlen = 1,
	FORTIFY_FUNC_strlen = 2,
	FORTIFY_FUNC_strscpy = 3,
	FORTIFY_FUNC_strlcat = 4,
	FORTIFY_FUNC_strcat = 5,
	FORTIFY_FUNC_strncat = 6,
	FORTIFY_FUNC_memset = 7,
	FORTIFY_FUNC_memcpy = 8,
	FORTIFY_FUNC_memmove = 9,
	FORTIFY_FUNC_memscan = 10,
	FORTIFY_FUNC_memcmp = 11,
	FORTIFY_FUNC_memchr = 12,
	FORTIFY_FUNC_memchr_inv = 13,
	FORTIFY_FUNC_kmemdup = 14,
	FORTIFY_FUNC_strcpy = 15,
	FORTIFY_FUNC_UNKNOWN = 16,
};

struct pollfd {
	int fd;
	short int events;
	short int revents;
};

struct perf_cpu_pmu_context;

struct perf_event_pmu_context;

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
	int *pmu_disable_count;
	struct perf_cpu_pmu_context *cpu_pmu_context;
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
	long int (*snapshot_aux)(struct perf_event *, struct perf_output_handle *, long unsigned int);
	int (*addr_filters_validate)(struct list_head *);
	void (*addr_filters_sync)(struct perf_event *);
	int (*aux_output_match)(struct perf_event *);
	bool (*filter)(struct pmu *, int);
	int (*check_period)(struct perf_event *, u64);
};

enum perf_event_state {
	PERF_EVENT_STATE_DEAD = -4,
	PERF_EVENT_STATE_EXIT = -3,
	PERF_EVENT_STATE_ERROR = -2,
	PERF_EVENT_STATE_OFF = -1,
	PERF_EVENT_STATE_INACTIVE = 0,
	PERF_EVENT_STATE_ACTIVE = 1,
};

typedef struct {
	long int v;
} local_t;

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

struct rhash_head {
	struct rhash_head *next;
};

struct rhlist_head {
	struct rhash_head rhead;
	struct rhlist_head *next;
};

struct hw_perf_event {
	union {
		struct {
			u64 config;
			u64 last_tag;
			long unsigned int config_base;
			long unsigned int event_base;
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
	long unsigned int addr_filters_gen;
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

typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *);

struct ftrace_ops;

struct ftrace_regs;

typedef void (*ftrace_func_t)(long unsigned int, long unsigned int, struct ftrace_ops *, struct ftrace_regs *);

struct ftrace_hash;

struct ftrace_ops_hash {
	struct ftrace_hash *notrace_hash;
	struct ftrace_hash *filter_hash;
	struct mutex regex_lock;
};

enum ftrace_ops_cmd {
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_SELF = 0,
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_PEER = 1,
	FTRACE_OPS_CMD_DISABLE_SHARE_IPMODIFY_PEER = 2,
};

typedef int (*ftrace_ops_func_t)(struct ftrace_ops *, enum ftrace_ops_cmd);

struct ftrace_ops {
	ftrace_func_t func;
	struct ftrace_ops *next;
	long unsigned int flags;
	void *private;
	ftrace_func_t saved_func;
	struct ftrace_ops_hash local_hash;
	struct ftrace_ops_hash *func_hash;
	struct ftrace_ops_hash old_hash;
	long unsigned int trampoline;
	long unsigned int trampoline_size;
	struct list_head list;
	ftrace_ops_func_t ops_func;
};

struct perf_buffer;

struct fasync_struct;

struct perf_addr_filter_range;

struct bpf_prog;

struct event_filter;

struct perf_cgroup;

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
	long unsigned int rcu_batches;
	int rcu_pending;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
	unsigned int pending_wakeup;
	unsigned int pending_kill;
	unsigned int pending_disable;
	unsigned int pending_sigtrap;
	long unsigned int pending_addr;
	struct irq_work pending_irq;
	struct callback_head pending_task;
	unsigned int pending_work;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	long unsigned int addr_filters_gen;
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
	struct trace_event_call *tp_event;
	struct event_filter *filter;
	struct ftrace_ops ftrace_ops;
	struct perf_cgroup *cgrp;
	void *security;
	struct list_head sb_list;
	__u32 orig_type;
};

typedef struct cpumask cpumask_var_t[1];

struct task_cputime {
	u64 stime;
	u64 utime;
	long long unsigned int sum_exec_runtime;
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[12];
	atomic_long_t rlimit[4];
};

struct ksignal {
	struct k_sigaction ka;
	kernel_siginfo_t info;
	int sig;
};

struct bio;

struct bio_list {
	struct bio *head;
	struct bio *tail;
};

struct cgroup_subsys_state;

struct cgroup;

struct css_set {
	struct cgroup_subsys_state *subsys[14];
	refcount_t refcount;
	struct css_set *dom_cset;
	struct cgroup *dfl_cgrp;
	int nr_tasks;
	struct list_head tasks;
	struct list_head mg_tasks;
	struct list_head dying_tasks;
	struct list_head task_iters;
	struct list_head e_cset_node[14];
	struct list_head threaded_csets;
	struct list_head threaded_csets_node;
	struct hlist_node hlist;
	struct list_head cgrp_links;
	struct list_head mg_src_preload_node;
	struct list_head mg_dst_preload_node;
	struct list_head mg_node;
	struct cgroup *mg_src_cgrp;
	struct cgroup *mg_dst_cgrp;
	struct css_set *mg_dst_cset;
	bool dead;
	struct callback_head callback_head;
};

struct perf_event_groups {
	struct rb_root tree;
	u64 index;
};

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
	int nr_cgroups;
	struct callback_head callback_head;
	local_t nr_pending;
};

struct ftrace_ret_stack {
	long unsigned int ret;
	long unsigned int func;
	long long unsigned int calltime;
	long unsigned int *retp;
};

struct rcu_work {
	struct work_struct work;
	struct callback_head rcu;
	struct workqueue_struct *wq;
};

struct cgroup_subsys;

struct cgroup_subsys_state {
	struct cgroup *cgroup;
	struct cgroup_subsys *ss;
	struct percpu_ref refcnt;
	struct list_head sibling;
	struct list_head children;
	struct list_head rstat_css_node;
	int id;
	unsigned int flags;
	u64 serial_nr;
	atomic_t online_cnt;
	struct work_struct destroy_work;
	struct rcu_work destroy_rwork;
	struct cgroup_subsys_state *parent;
};

struct mem_cgroup_id {
	int id;
	refcount_t ref;
};

struct page_counter {
	atomic_long_t usage;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	long unsigned int emin;
	atomic_long_t min_usage;
	atomic_long_t children_min_usage;
	long unsigned int elow;
	atomic_long_t low_usage;
	atomic_long_t children_low_usage;
	long unsigned int watermark;
	long unsigned int failcnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int min;
	long unsigned int low;
	long unsigned int high;
	long unsigned int max;
	struct page_counter *parent;
	long: 64;
	long: 64;
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

struct vmpressure {
	long unsigned int scanned;
	long unsigned int reclaimed;
	long unsigned int tree_scanned;
	long unsigned int tree_reclaimed;
	spinlock_t sr_lock;
	struct list_head events;
	struct mutex events_lock;
	struct work_struct work;
};

struct cgroup_file {
	struct kernfs_node *kn;
	long unsigned int notified_at;
	struct timer_list notify_timer;
};

struct mem_cgroup_threshold_ary;

struct mem_cgroup_thresholds {
	struct mem_cgroup_threshold_ary *primary;
	struct mem_cgroup_threshold_ary *spare;
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
	long unsigned int period_time;
	long unsigned int dirty_limit_tstamp;
	long unsigned int dirty_limit;
};

struct wb_completion {
	atomic_t cnt;
	wait_queue_head_t *waitq;
};

struct memcg_cgwb_frn {
	u64 bdi_id;
	int memcg_id;
	u64 at;
	struct wb_completion done;
};

struct deferred_split {
	spinlock_t split_queue_lock;
	struct list_head split_queue;
	long unsigned int split_queue_len;
};

struct memcg_vmstats;

struct memcg_vmstats_percpu;

struct mem_cgroup_per_node;

struct mem_cgroup {
	struct cgroup_subsys_state css;
	struct mem_cgroup_id id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter memory;
	union {
		struct page_counter swap;
		struct page_counter memsw;
	};
	struct page_counter kmem;
	struct page_counter tcpmem;
	struct work_struct high_work;
	long unsigned int zswap_max;
	bool zswap_writeback;
	long unsigned int soft_limit;
	struct vmpressure vmpressure;
	bool oom_group;
	bool oom_lock;
	int under_oom;
	int swappiness;
	int oom_kill_disable;
	struct cgroup_file events_file;
	struct cgroup_file events_local_file;
	struct cgroup_file swap_events_file;
	struct mutex thresholds_lock;
	struct mem_cgroup_thresholds thresholds;
	struct mem_cgroup_thresholds memsw_thresholds;
	struct list_head oom_notify;
	long unsigned int move_charge_at_immigrate;
	spinlock_t move_lock;
	long unsigned int move_lock_flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct memcg_vmstats *vmstats;
	atomic_long_t memory_events[9];
	atomic_long_t memory_events_local[9];
	long unsigned int socket_pressure;
	bool tcpmem_active;
	int tcpmem_pressure;
	int kmemcg_id;
	struct obj_cgroup *objcg;
	struct obj_cgroup *orig_objcg;
	struct list_head objcg_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	atomic_t moving_account;
	struct task_struct *move_lock_task;
	struct memcg_vmstats_percpu *vmstats_percpu;
	struct list_head cgwb_list;
	struct wb_domain cgwb_domain;
	struct memcg_cgwb_frn cgwb_frn[4];
	struct list_head event_list;
	spinlock_t event_list_lock;
	struct deferred_split deferred_split_queue;
	struct mem_cgroup_per_node *nodeinfo[0];
	long: 64;
};

struct obj_cgroup {
	struct percpu_ref refcnt;
	struct mem_cgroup *memcg;
	atomic_t nr_charged_bytes;
	union {
		struct list_head list;
		struct callback_head rcu;
	};
};

struct bpf_run_ctx {};

struct hlist_nulls_node;

struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};

struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
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

struct ctl_dir {
	struct ctl_table_header header;
	struct rb_root root;
};

struct ctl_table_set {
	int (*is_seen)(struct ctl_table_set *);
	struct ctl_dir dir;
};

struct binfmt_misc;

struct user_namespace {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	struct uid_gid_map projid_map;
	struct user_namespace *parent;
	int level;
	kuid_t owner;
	kgid_t group;
	struct ns_common ns;
	long unsigned int flags;
	bool parent_could_setfcap;
	struct list_head keyring_name_list;
	struct key *user_keyring_register;
	struct rw_semaphore keyring_sem;
	struct key *persistent_keyring_register;
	struct work_struct work;
	struct ctl_table_set set;
	struct ctl_table_header *sysctls;
	struct ucounts *ucounts;
	long int ucount_max[12];
	long int rlimit_max[4];
	struct binfmt_misc *binfmt_misc;
};

struct zswap_lruvec_state {
	atomic_long_t nr_zswap_protected;
};

struct free_area {
	struct list_head free_list[6];
	long unsigned int nr_free;
};

struct lru_gen_folio {
	long unsigned int max_seq;
	long unsigned int min_seq[2];
	long unsigned int timestamps[4];
	struct list_head folios[16];
	long int nr_pages[16];
	long unsigned int avg_refaulted[8];
	long unsigned int avg_total[8];
	long unsigned int protected[6];
	atomic_long_t evicted[8];
	atomic_long_t refaulted[8];
	bool enabled;
	u8 gen;
	u8 seg;
	struct hlist_nulls_node list;
};

struct lruvec;

struct lru_gen_mm_walk {
	struct lruvec *lruvec;
	long unsigned int seq;
	long unsigned int next_addr;
	int nr_pages[16];
	int mm_stats[6];
	int batched;
	bool can_swap;
	bool force_scan;
};

struct pglist_data;

struct lruvec {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
	struct lru_gen_folio lrugen;
	struct pglist_data *pgdat;
	struct zswap_lruvec_state zswap_lruvec_state;
};

struct lru_gen_memcg {
	long unsigned int seq;
	long unsigned int nr_memcgs[3];
	struct hlist_nulls_head fifo[24];
	spinlock_t lock;
};

struct per_cpu_pages;

struct per_cpu_zonestat;

struct zone {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[2];
	int node;
	struct pglist_data *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high_min;
	int pageset_high_max;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	long unsigned int present_early_pages;
	long unsigned int cma_pages;
	const char *name;
	long unsigned int nr_isolate_pageblock;
	seqlock_t span_seqlock;
	int initialized;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[9];
	long unsigned int flags;
	spinlock_t lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	long unsigned int compact_cached_free_pfn;
	long unsigned int compact_cached_migrate_pfn[2];
	long unsigned int compact_init_migrate_pfn;
	long unsigned int compact_init_free_pfn;
	unsigned int compact_considered;
	unsigned int compact_defer_shift;
	int compact_order_failed;
	bool compact_blockskip_flush;
	bool contiguous;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[11];
	atomic_long_t vm_numa_event[6];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct zoneref {
	struct zone *zone;
	int zone_idx;
};

struct zonelist {
	struct zoneref _zonerefs[513];
};

enum zone_type {
	ZONE_NORMAL = 0,
	ZONE_MOVABLE = 1,
	__MAX_NR_ZONES = 2,
};

struct memory_failure_stats {
	long unsigned int total;
	long unsigned int ignored;
	long unsigned int failed;
	long unsigned int delayed;
	long unsigned int recovered;
};

struct per_cpu_nodestat;

struct memory_tier;

struct pglist_data {
	struct zone node_zones[2];
	struct zonelist node_zonelists[2];
	int nr_zones;
	spinlock_t node_size_lock;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct mutex kswapd_lock;
	struct task_struct *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
	bool proactive_compact_trigger;
	long unsigned int totalreserve_pages;
	long unsigned int min_unmapped_pages;
	long unsigned int min_slab_pages;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	long unsigned int first_deferred_pfn;
	struct deferred_split deferred_split_queue;
	unsigned int nbp_rl_start;
	long unsigned int nbp_rl_nr_cand;
	unsigned int nbp_threshold;
	unsigned int nbp_th_start;
	long unsigned int nbp_th_nr_cand;
	struct lruvec __lruvec;
	long unsigned int flags;
	struct lru_gen_mm_walk mm_walk;
	struct lru_gen_memcg memcg_lru;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[46];
	struct memory_tier *memtier;
	struct memory_failure_stats mf_stats;
	long: 64;
	long: 64;
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

struct per_cpu_pages {
	spinlock_t lock;
	int count;
	int high;
	int high_min;
	int high_max;
	int batch;
	u8 flags;
	u8 alloc_factor;
	u8 expire;
	short int free_count;
	struct list_head lists[14];
};

struct per_cpu_zonestat {
	s8 vm_stat_diff[11];
	s8 stat_threshold;
	long unsigned int vm_numa_event[6];
};

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[46];
};

struct shrinker_info_unit {
	atomic_long_t nr_deferred[64];
	long unsigned int map[1];
};

struct shrinker_info {
	struct callback_head rcu;
	int map_nr_max;
	struct shrinker_info_unit *unit[0];
};

struct cgroup_base_stat {
	struct task_cputime cputime;
};

struct bpf_prog_array;

struct cgroup_bpf {
	struct bpf_prog_array *effective[38];
	struct hlist_head progs[38];
	u8 flags[38];
	struct list_head storages;
	struct bpf_prog_array *inactive;
	struct percpu_ref refcnt;
	struct work_struct release_work;
};

struct cgroup_freezer_state {
	bool freeze;
	int e_freeze;
	int nr_frozen_descendants;
	int nr_frozen_tasks;
};

struct cgroup_root;

struct cgroup_rstat_cpu;

struct psi_group;

struct cgroup {
	struct cgroup_subsys_state self;
	long unsigned int flags;
	int level;
	int max_depth;
	int nr_descendants;
	int nr_dying_descendants;
	int max_descendants;
	int nr_populated_csets;
	int nr_populated_domain_children;
	int nr_populated_threaded_children;
	int nr_threaded_children;
	struct kernfs_node *kn;
	struct cgroup_file procs_file;
	struct cgroup_file events_file;
	struct cgroup_file psi_files[3];
	u16 subtree_control;
	u16 subtree_ss_mask;
	u16 old_subtree_control;
	u16 old_subtree_ss_mask;
	struct cgroup_subsys_state *subsys[14];
	struct cgroup_root *root;
	struct list_head cset_links;
	struct list_head e_csets[14];
	struct cgroup *dom_cgrp;
	struct cgroup *old_dom_cgrp;
	struct cgroup_rstat_cpu *rstat_cpu;
	struct list_head rstat_css_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad_;
	struct cgroup *rstat_flush_next;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat bstat;
	struct prev_cputime prev_cputime;
	struct list_head pidlists;
	struct mutex pidlist_mutex;
	wait_queue_head_t offline_waitq;
	struct work_struct release_agent_work;
	struct psi_group *psi;
	struct cgroup_bpf bpf;
	atomic_t congestion_count;
	struct cgroup_freezer_state freezer;
	struct bpf_local_storage *bpf_cgrp_storage;
	struct cgroup *ancestors[0];
	long: 64;
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

struct ctl_node {
	struct rb_node node;
	struct ctl_table_header *header;
};

struct ctl_table_root {
	struct ctl_table_set default_set;
	struct ctl_table_set * (*lookup)(struct ctl_table_root *);
	void (*set_ownership)(struct ctl_table_header *, struct ctl_table *, kuid_t *, kgid_t *);
	int (*permissions)(struct ctl_table_header *, struct ctl_table *);
};

struct taskstats {
	__u16 version;
	__u32 ac_exitcode;
	__u8 ac_flag;
	__u8 ac_nice;
	__u64 cpu_count;
	__u64 cpu_delay_total;
	__u64 blkio_count;
	__u64 blkio_delay_total;
	__u64 swapin_count;
	__u64 swapin_delay_total;
	__u64 cpu_run_real_total;
	__u64 cpu_run_virtual_total;
	char ac_comm[32];
	__u8 ac_sched;
	__u8 ac_pad[3];
	long: 0;
	__u32 ac_uid;
	__u32 ac_gid;
	__u32 ac_pid;
	__u32 ac_ppid;
	__u32 ac_btime;
	__u64 ac_etime;
	__u64 ac_utime;
	__u64 ac_stime;
	__u64 ac_minflt;
	__u64 ac_majflt;
	__u64 coremem;
	__u64 virtmem;
	__u64 hiwater_rss;
	__u64 hiwater_vm;
	__u64 read_char;
	__u64 write_char;
	__u64 read_syscalls;
	__u64 write_syscalls;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 cancelled_write_bytes;
	__u64 nvcsw;
	__u64 nivcsw;
	__u64 ac_utimescaled;
	__u64 ac_stimescaled;
	__u64 cpu_scaled_run_real_total;
	__u64 freepages_count;
	__u64 freepages_delay_total;
	__u64 thrashing_count;
	__u64 thrashing_delay_total;
	__u64 ac_btime64;
	__u64 compact_count;
	__u64 compact_delay_total;
	__u32 ac_tgid;
	__u64 ac_tgetime;
	__u64 ac_exe_dev;
	__u64 ac_exe_inode;
	__u64 wpcopy_count;
	__u64 wpcopy_delay_total;
	__u64 irq_count;
	__u64 irq_delay_total;
};

struct wait_page_queue {
	struct folio *folio;
	int bit_nr;
	wait_queue_entry_t wait;
};

enum writeback_sync_modes {
	WB_SYNC_NONE = 0,
	WB_SYNC_ALL = 1,
};

struct folio_batch {
	unsigned char nr;
	unsigned char i;
	bool percpu_pvec_drained;
	struct folio *folios[31];
};

struct swap_iocb;

struct writeback_control {
	long int nr_to_write;
	long int pages_skipped;
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
	long unsigned int index;
	int saved_err;
	struct bdi_writeback *wb;
	struct inode *inode;
	int wb_id;
	int wb_lcand_id;
	int wb_tcand_id;
	size_t wb_bytes;
	size_t wb_lcand_bytes;
	size_t wb_tcand_bytes;
};

struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	long unsigned int _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
	bool _workingset;
	long unsigned int _pflags;
};

struct fprop_local_percpu {
	struct percpu_counter events;
	unsigned int period;
	raw_spinlock_t lock;
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

struct bdi_writeback {
	struct backing_dev_info *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	struct list_head bdi_node;
	struct percpu_ref refcnt;
	struct fprop_local_percpu memcg_completions;
	struct cgroup_subsys_state *memcg_css;
	struct cgroup_subsys_state *blkcg_css;
	struct list_head memcg_node;
	struct list_head blkcg_node;
	struct list_head b_attached;
	struct list_head offline_node;
	union {
		struct work_struct release_work;
		struct callback_head rcu;
	};
};

struct fasync_struct {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct *fa_next;
	struct file *fa_file;
	struct callback_head fa_rcu;
};

struct disk_stats;

struct blk_holder_ops;

struct partition_meta_info;

struct block_device {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
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

struct backing_dev_info {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	long unsigned int last_bdp_sleep;
	struct bdi_writeback wb;
	struct list_head wb_list;
	struct xarray cgwb_tree;
	struct mutex cgwb_release_mutex;
	struct rw_semaphore wb_switch_rwsem;
	wait_queue_head_t wb_waitq;
	struct device *dev;
	char dev_name[64];
	struct device *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry *debug_dir;
};

typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
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

struct bio_issue {
	u64 value;
};

struct blkcg_gq;

struct bio_integrity_payload;

struct bio_set;

struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	enum rw_hint bi_write_hint;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t *bi_end_io;
	void *bi_private;
	struct blkcg_gq *bi_blkg;
	struct bio_issue bi_issue;
	u64 bi_iocost_cost;
	union {
		struct bio_integrity_payload *bi_integrity;
	};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec bi_inline_vecs[0];
};

typedef long unsigned int elf_greg_t64;

typedef unsigned int elf_greg_t32;

typedef elf_greg_t32 elf_gregset_t32[48];

typedef double elf_fpreg_t;

typedef elf_fpreg_t elf_fpregset_t[33];

typedef __vector128 elf_vrreg_t;

typedef elf_vrreg_t elf_vrregset_t32[33];

typedef elf_fpreg_t elf_vsrreghalf_t32[32];

struct cgroup_namespace {
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct css_set *root_cset;
};

struct em_perf_state {
	long unsigned int performance;
	long unsigned int frequency;
	long unsigned int power;
	long unsigned int cost;
	long unsigned int flags;
};

struct em_perf_table {
	struct callback_head rcu;
	struct kref kref;
	struct em_perf_state state[0];
};

struct em_perf_domain {
	struct em_perf_table *em_table;
	int nr_perf_states;
	long unsigned int flags;
	long unsigned int cpus[0];
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

struct pm_subsys_data {
	spinlock_t lock;
	unsigned int refcount;
};

struct wakeup_source {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
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

enum probe_type {
	PROBE_DEFAULT_STRATEGY = 0,
	PROBE_PREFER_ASYNCHRONOUS = 1,
	PROBE_FORCE_SYNCHRONOUS = 2,
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

struct device_type {
	const char *name;
	const struct attribute_group **groups;
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device *);
	const struct dev_pm_ops *pm;
};

struct trace_event_functions;

struct trace_event {
	struct hlist_node node;
	int type;
	struct trace_event_functions *funcs;
};

struct trace_event_class;

struct trace_event_call {
	struct list_head list;
	struct trace_event_class *class;
	union {
		char *name;
		struct tracepoint *tp;
	};
	struct trace_event event;
	char *print_fmt;
	struct event_filter *filter;
	union {
		void *module;
		atomic_t refcnt;
	};
	void *data;
	int flags;
	int perf_refcount;
	struct hlist_head *perf_events;
	struct bpf_prog_array *prog_array;
	int (*perf_perm)(struct trace_event_call *, struct perf_event *);
};

struct trace_eval_map {
	const char *system;
	const char *eval_string;
	long unsigned int eval_value;
};

struct of_device_id {
	char name[32];
	char type[32];
	char compatible[128];
	const void *data;
};

typedef long unsigned int kernel_ulong_t;

struct acpi_device_id {
	__u8 id[16];
	kernel_ulong_t driver_data;
	__u32 cls;
	__u32 cls_msk;
};

struct pci_controller;

struct eeh_pe;

struct pci_dev;

struct eeh_dev {
	int mode;
	int bdfn;
	struct pci_controller *controller;
	int pe_config_addr;
	u32 config_space[16];
	int pcix_cap;
	int pcie_cap;
	int aer_cap;
	int af_cap;
	struct eeh_pe *pe;
	struct list_head entry;
	struct list_head rmv_entry;
	struct pci_dn *pdn;
	struct pci_dev *pdev;
	bool in_error;
	struct pci_dev *physfn;
	int vf_index;
};

struct device_dma_parameters {
	unsigned int max_segment_size;
	unsigned int min_align_mask;
	long unsigned int segment_boundary_mask;
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

struct device_physical_location {
	enum device_physical_location_panel panel;
	enum device_physical_location_vertical_position vertical_position;
	enum device_physical_location_horizontal_position horizontal_position;
	bool dock;
	bool lid;
};

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

typedef u64 phys_addr_t;

struct sg_table;

struct scatterlist;

struct dma_map_ops {
	unsigned int flags;
	void * (*alloc)(struct device *, size_t, dma_addr_t *, gfp_t, long unsigned int);
	void (*free)(struct device *, size_t, void *, dma_addr_t, long unsigned int);
	struct page * (*alloc_pages)(struct device *, size_t, dma_addr_t *, enum dma_data_direction, gfp_t);
	void (*free_pages)(struct device *, size_t, struct page *, dma_addr_t, enum dma_data_direction);
	struct sg_table * (*alloc_noncontiguous)(struct device *, size_t, enum dma_data_direction, gfp_t, long unsigned int);
	void (*free_noncontiguous)(struct device *, size_t, struct sg_table *, enum dma_data_direction);
	int (*mmap)(struct device *, struct vm_area_struct *, void *, dma_addr_t, size_t, long unsigned int);
	int (*get_sgtable)(struct device *, struct sg_table *, void *, dma_addr_t, size_t, long unsigned int);
	dma_addr_t (*map_page)(struct device *, struct page *, long unsigned int, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_page)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	int (*map_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	void (*unmap_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	dma_addr_t (*map_resource)(struct device *, phys_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_resource)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*sync_single_for_cpu)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_single_for_device)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_sg_for_cpu)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*sync_sg_for_device)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*cache_sync)(struct device *, void *, size_t, enum dma_data_direction);
	int (*dma_supported)(struct device *, u64);
	u64 (*get_required_mask)(struct device *);
	size_t (*max_mapping_size)(struct device *);
	size_t (*opt_mapping_size)();
	long unsigned int (*get_merge_boundary)(struct device *);
};

struct bus_dma_region {
	phys_addr_t cpu_start;
	dma_addr_t dma_start;
	u64 size;
};

struct pci_bus;

struct eeh_pe {
	int type;
	int state;
	int addr;
	struct pci_controller *phb;
	struct pci_bus *bus;
	int check_count;
	int freeze_count;
	time64_t tstamp;
	int false_positives;
	atomic_t pass_dev_cnt;
	struct eeh_pe *parent;
	void *data;
	struct list_head child_list;
	struct list_head child;
	struct list_head edevs;
	long unsigned int stack_trace[64];
	int trace_entries;
};

struct seq_operations {
	void * (*start)(struct seq_file *, loff_t *);
	void (*stop)(struct seq_file *, void *);
	void * (*next)(struct seq_file *, void *, loff_t *);
	int (*show)(struct seq_file *, void *);
};

struct seq_buf {
	char *buffer;
	size_t size;
	size_t len;
};

struct trace_seq {
	char buffer[8156];
	struct seq_buf seq;
	size_t readpos;
	int full;
};

union perf_mem_data_src {
	__u64 val;
	struct {
		__u64 mem_rsvd: 18;
		__u64 mem_hops: 3;
		__u64 mem_blk: 3;
		__u64 mem_snoopx: 2;
		__u64 mem_remote: 1;
		__u64 mem_lvl_num: 4;
		__u64 mem_dtlb: 7;
		__u64 mem_lock: 2;
		__u64 mem_snoop: 5;
		__u64 mem_lvl: 14;
		__u64 mem_op: 5;
	};
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

union perf_sample_weight {
	__u64 full;
	struct {
		__u16 var3_w;
		__u16 var2_w;
		__u32 var1_dw;
	};
};

struct ftrace_regs {
	struct pt_regs regs;
};

struct perf_regs {
	__u64 abi;
	struct pt_regs *regs;
};

struct u64_stats_sync {};

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

struct psi_group_cpu {
	seqcount_t seq;
	unsigned int tasks[4];
	u32 state_mask;
	u32 times[7];
	u64 state_start;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u32 times_prev[14];
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

struct psi_group {
	struct psi_group *parent;
	bool enabled;
	struct mutex avgs_lock;
	struct psi_group_cpu *pcpu;
	u64 avg_total[6];
	u64 avg_last_update;
	u64 avg_next_update;
	struct delayed_work avgs_work;
	struct list_head avg_triggers;
	u32 avg_nr_triggers[6];
	u64 total[12];
	long unsigned int avg[18];
	struct task_struct *rtpoll_task;
	struct timer_list rtpoll_timer;
	wait_queue_head_t rtpoll_wait;
	atomic_t rtpoll_wakeup;
	atomic_t rtpoll_scheduled;
	struct mutex rtpoll_trigger_lock;
	struct list_head rtpoll_triggers;
	u32 rtpoll_nr_triggers[6];
	u32 rtpoll_states;
	u64 rtpoll_min_period;
	u64 rtpoll_total[6];
	u64 rtpoll_next_update;
	u64 rtpoll_until;
};

struct cgroup_taskset;

struct cftype;

struct cgroup_subsys {
	struct cgroup_subsys_state * (*css_alloc)(struct cgroup_subsys_state *);
	int (*css_online)(struct cgroup_subsys_state *);
	void (*css_offline)(struct cgroup_subsys_state *);
	void (*css_released)(struct cgroup_subsys_state *);
	void (*css_free)(struct cgroup_subsys_state *);
	void (*css_reset)(struct cgroup_subsys_state *);
	void (*css_rstat_flush)(struct cgroup_subsys_state *, int);
	int (*css_extra_stat_show)(struct seq_file *, struct cgroup_subsys_state *);
	int (*css_local_stat_show)(struct seq_file *, struct cgroup_subsys_state *);
	int (*can_attach)(struct cgroup_taskset *);
	void (*cancel_attach)(struct cgroup_taskset *);
	void (*attach)(struct cgroup_taskset *);
	void (*post_attach)();
	int (*can_fork)(struct task_struct *, struct css_set *);
	void (*cancel_fork)(struct task_struct *, struct css_set *);
	void (*fork)(struct task_struct *);
	void (*exit)(struct task_struct *);
	void (*release)(struct task_struct *);
	void (*bind)(struct cgroup_subsys_state *);
	bool early_init: 1;
	bool implicit_on_dfl: 1;
	bool threaded: 1;
	int id;
	const char *name;
	const char *legacy_name;
	struct cgroup_root *root;
	struct idr css_idr;
	struct list_head cfts;
	struct cftype *dfl_cftypes;
	struct cftype *legacy_cftypes;
	unsigned int depends_on;
};

struct cgroup_rstat_cpu {
	struct u64_stats_sync bsync;
	struct cgroup_base_stat bstat;
	struct cgroup_base_stat last_bstat;
	struct cgroup_base_stat subtree_bstat;
	struct cgroup_base_stat last_subtree_bstat;
	struct cgroup *updated_children;
	struct cgroup *updated_next;
};

struct cgroup_root {
	struct kernfs_root *kf_root;
	unsigned int subsys_mask;
	int hierarchy_id;
	struct list_head root_list;
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
	struct cgroup cgrp;
	struct cgroup *cgrp_ancestor_storage;
	atomic_t nr_cgrps;
	unsigned int flags;
	char release_agent_path[4096];
	char name[64];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct cftype {
	char name[64];
	long unsigned int private;
	size_t max_write_len;
	unsigned int flags;
	unsigned int file_offset;
	struct cgroup_subsys *ss;
	struct list_head node;
	struct kernfs_ops *kf_ops;
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	u64 (*read_u64)(struct cgroup_subsys_state *, struct cftype *);
	s64 (*read_s64)(struct cgroup_subsys_state *, struct cftype *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	int (*write_u64)(struct cgroup_subsys_state *, struct cftype *, u64);
	int (*write_s64)(struct cgroup_subsys_state *, struct cftype *, s64);
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
};

struct bpf_insn {
	__u8 code;
	__u8 dst_reg: 4;
	__u8 src_reg: 4;
	__s16 off;
	__s32 imm;
};

enum bpf_cgroup_iter_order {
	BPF_CGROUP_ITER_ORDER_UNSPEC = 0,
	BPF_CGROUP_ITER_SELF_ONLY = 1,
	BPF_CGROUP_ITER_DESCENDANTS_PRE = 2,
	BPF_CGROUP_ITER_DESCENDANTS_POST = 3,
	BPF_CGROUP_ITER_ANCESTORS_UP = 4,
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

struct bpf_func_info {
	__u32 insn_off;
	__u32 type_id;
};

struct bpf_line_info {
	__u32 insn_off;
	__u32 file_name_off;
	__u32 line_off;
	__u32 line_col;
};

struct sock_filter {
	__u16 code;
	__u8 jt;
	__u8 jf;
	__u32 k;
};

struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
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
	struct bpf_prog_stats *stats;
	int *active;
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

typedef void (*btf_dtor_kfunc_t)(void *);

struct btf;

struct btf_field_kptr {
	struct btf *btf;
	struct module *module;
	btf_dtor_kfunc_t dtor;
	u32 btf_id;
};

struct btf_record;

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

struct blk_holder_ops {
	void (*mark_dead)(struct block_device *, bool);
	void (*sync)(struct block_device *);
	int (*freeze)(struct block_device *);
	int (*thaw)(struct block_device *);
};

struct bio_integrity_payload {
	struct bio *bip_bio;
	struct bvec_iter bip_iter;
	short unsigned int bip_vcnt;
	short unsigned int bip_max_vcnt;
	short unsigned int bip_flags;
	int: 0;
	struct bvec_iter bio_iter;
	struct work_struct bip_work;
	struct bio_vec *bip_vec;
	struct bio_vec bip_inline_vecs[0];
};

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

struct bio_alloc_cache;

struct bio_set {
	struct kmem_cache *bio_slab;
	unsigned int front_pad;
	struct bio_alloc_cache *cache;
	mempool_t bio_pool;
	mempool_t bvec_pool;
	mempool_t bio_integrity_pool;
	mempool_t bvec_integrity_pool;
	unsigned int back_pad;
	spinlock_t rescue_lock;
	struct bio_list rescue_list;
	struct work_struct rescue_work;
	struct workqueue_struct *rescue_workqueue;
	struct hlist_node cpuhp_dead;
};

struct mem_cgroup_reclaim_iter {
	struct mem_cgroup *position;
	unsigned int generation;
};

struct lruvec_stats_percpu {
	long int state[46];
	long int state_prev[46];
};

struct lruvec_stats {
	long int state[46];
	long int state_local[46];
	long int state_pending[46];
};

struct mem_cgroup_per_node {
	struct lruvec lruvec;
	struct lruvec_stats_percpu *lruvec_stats_percpu;
	struct lruvec_stats lruvec_stats;
	long unsigned int lru_zone_size[10];
	struct mem_cgroup_reclaim_iter iter;
	struct shrinker_info *shrinker_info;
	struct rb_node tree_node;
	long unsigned int usage_in_excess;
	bool on_tree;
	struct mem_cgroup *memcg;
};

struct eventfd_ctx;

struct mem_cgroup_threshold {
	struct eventfd_ctx *eventfd;
	long unsigned int threshold;
};

struct mem_cgroup_threshold_ary {
	int current_threshold;
	unsigned int size;
	struct mem_cgroup_threshold entries[0];
};

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

struct bpf_iter_aux_info;

typedef int (*bpf_iter_init_seq_priv_t)(void *, struct bpf_iter_aux_info *);

enum bpf_iter_task_type {
	BPF_TASK_ITER_ALL = 0,
	BPF_TASK_ITER_TID = 1,
	BPF_TASK_ITER_TGID = 2,
};

struct bpf_map;

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

typedef void (*bpf_iter_fini_seq_priv_t)(void *);

struct bpf_iter_seq_info {
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
};

struct bpf_local_storage_map;

struct bpf_verifier_env;

struct bpf_func_state;

struct bpf_map_ops {
	int (*map_alloc_check)(union bpf_attr *);
	struct bpf_map * (*map_alloc)(union bpf_attr *);
	void (*map_release)(struct bpf_map *, struct file *);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *, void *, void *);
	void (*map_release_uref)(struct bpf_map *);
	void * (*map_lookup_elem_sys_only)(struct bpf_map *, void *);
	int (*map_lookup_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_lookup_and_delete_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_lookup_and_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_update_batch)(struct bpf_map *, struct file *, const union bpf_attr *, union bpf_attr *);
	int (*map_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	void * (*map_lookup_elem)(struct bpf_map *, void *);
	long int (*map_update_elem)(struct bpf_map *, void *, void *, u64);
	long int (*map_delete_elem)(struct bpf_map *, void *);
	long int (*map_push_elem)(struct bpf_map *, void *, u64);
	long int (*map_pop_elem)(struct bpf_map *, void *);
	long int (*map_peek_elem)(struct bpf_map *, void *);
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
	long unsigned int (*map_get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*map_local_storage_charge)(struct bpf_local_storage_map *, void *, u32);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *, void *, u32);
	struct bpf_local_storage ** (*map_owner_storage_ptr)(void *);
	long int (*map_redirect)(struct bpf_map *, u64, u64);
	bool (*map_meta_equal)(const struct bpf_map *, const struct bpf_map *);
	int (*map_set_for_each_callback_args)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *);
	long int (*map_for_each_callback)(struct bpf_map *, bpf_callback_t, void *, u64);
	u64 (*map_mem_usage)(const struct bpf_map *);
	int *map_btf_id;
	const struct bpf_iter_seq_info *iter_seq_info;
};

struct bpf_map {
	const struct bpf_map_ops *ops;
	struct bpf_map *inner_map_meta;
	void *security;
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
	struct obj_cgroup *objcg;
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
	s64 *elem_count;
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

struct bpf_ksym {
	long unsigned int start;
	long unsigned int end;
	char name[512];
	struct list_head lnode;
	struct latch_tree_node tnode;
	bool prog;
};

struct bpf_ctx_arg_aux;

struct bpf_trampoline;

struct bpf_arena;

struct bpf_jit_poke_descriptor;

struct bpf_kfunc_desc_tab;

struct bpf_kfunc_btf_tab;

struct bpf_prog_ops;

struct btf_mod_pair;

struct bpf_token;

struct bpf_prog_offload;

struct bpf_func_info_aux;

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
	void *security;
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

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *, const union bpf_attr *, union bpf_attr *);
};

struct net_device;

struct bpf_offload_dev;

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

struct btf_func_model {
	u8 ret_size;
	u8 ret_flags;
	u8 nr_args;
	u8 arg_size[12];
	u8 arg_flags[12];
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

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
	bool called: 1;
	bool verified: 1;
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

struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	struct btf *btf;
	u32 btf_id;
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
	void *security;
};

struct perf_callchain_entry {
	__u64 nr;
	__u64 ip[0];
};

typedef long unsigned int (*perf_copy_f)(void *, const void *, long unsigned int, long unsigned int);

struct perf_raw_frag {
	union {
		struct perf_raw_frag *next;
		long unsigned int pad;
	};
	perf_copy_f copy;
	void *data;
	u32 size;
} __attribute__((packed));

struct perf_raw_record {
	struct perf_raw_frag frag;
	u32 size;
};

struct perf_branch_stack {
	__u64 nr;
	__u64 hw_idx;
	struct perf_branch_entry entries[0];
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
	long unsigned int wakeup;
	long unsigned int size;
	u64 aux_flags;
	union {
		void *addr;
		long unsigned int head;
	};
	int page;
};

struct perf_addr_filter_range {
	long unsigned int start;
	long unsigned int size;
};

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

struct perf_cgroup_info;

struct perf_cgroup {
	struct cgroup_subsys_state css;
	struct perf_cgroup_info *info;
};

struct perf_cgroup_info {
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	int active;
};

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_array;

struct tracer;

struct array_buffer;

struct ring_buffer_iter;

struct trace_iterator {
	struct trace_array *tr;
	struct tracer *trace;
	struct array_buffer *array_buffer;
	void *private;
	int cpu_file;
	struct mutex mutex;
	struct ring_buffer_iter **buffer_iter;
	long unsigned int iter_flags;
	void *temp;
	unsigned int temp_size;
	char *fmt;
	unsigned int fmt_size;
	atomic_t wait_index;
	struct trace_seq tmp_seq;
	cpumask_var_t started;
	bool closed;
	bool snapshot;
	struct trace_seq seq;
	struct trace_entry *ent;
	long unsigned int lost_events;
	int leftover;
	int ent_size;
	int cpu;
	u64 ts;
	loff_t pos;
	long int idx;
};

enum print_line_t {
	TRACE_TYPE_PARTIAL_LINE = 0,
	TRACE_TYPE_HANDLED = 1,
	TRACE_TYPE_UNHANDLED = 2,
	TRACE_TYPE_NO_CONSUME = 3,
};

typedef enum print_line_t (*trace_print_func)(struct trace_iterator *, int, struct trace_event *);

struct trace_event_functions {
	trace_print_func trace;
	trace_print_func raw;
	trace_print_func hex;
	trace_print_func binary;
};

enum trace_reg {
	TRACE_REG_REGISTER = 0,
	TRACE_REG_UNREGISTER = 1,
	TRACE_REG_PERF_REGISTER = 2,
	TRACE_REG_PERF_UNREGISTER = 3,
	TRACE_REG_PERF_OPEN = 4,
	TRACE_REG_PERF_CLOSE = 5,
	TRACE_REG_PERF_ADD = 6,
	TRACE_REG_PERF_DEL = 7,
};

struct trace_event_fields {
	const char *type;
	union {
		struct {
			const char *name;
			const int size;
			const int align;
			const int is_signed;
			const int filter_type;
			const int len;
		};
		int (*define_fields)(struct trace_event_call *);
	};
};

struct trace_event_class {
	const char *system;
	void *probe;
	void *perf_probe;
	int (*reg)(struct trace_event_call *, enum trace_reg, void *);
	struct trace_event_fields *fields_array;
	struct list_head * (*get_fields)(struct trace_event_call *);
	struct list_head fields;
	int (*raw_init)(struct trace_event_call *);
};

typedef u32 compat_size_t;

typedef s32 compat_clock_t;

typedef s32 compat_pid_t;

typedef s32 compat_timer_t;

typedef s32 compat_int_t;

typedef u32 compat_ulong_t;

typedef u32 __compat_uid32_t;

typedef u32 compat_sigset_word;

struct compat_sigaltstack {
	compat_uptr_t ss_sp;
	int ss_flags;
	compat_size_t ss_size;
};

typedef struct compat_sigaltstack compat_stack_t;

typedef struct {
	compat_sigset_word sig[2];
} compat_sigset_t;

union compat_sigval {
	compat_int_t sival_int;
	compat_uptr_t sival_ptr;
};

typedef union compat_sigval compat_sigval_t;

struct compat_siginfo {
	int si_signo;
	int si_errno;
	int si_code;
	union {
		int _pad[29];
		struct {
			compat_pid_t _pid;
			__compat_uid32_t _uid;
		} _kill;
		struct {
			compat_timer_t _tid;
			int _overrun;
			compat_sigval_t _sigval;
		} _timer;
		struct {
			compat_pid_t _pid;
			__compat_uid32_t _uid;
			compat_sigval_t _sigval;
		} _rt;
		struct {
			compat_pid_t _pid;
			__compat_uid32_t _uid;
			int _status;
			compat_clock_t _utime;
			compat_clock_t _stime;
		} _sigchld;
		struct {
			compat_uptr_t _addr;
			union {
				int _trapno;
				short int _addr_lsb;
				struct {
					char _dummy_bnd[4];
					compat_uptr_t _lower;
					compat_uptr_t _upper;
				} _addr_bnd;
				struct {
					char _dummy_pkey[4];
					u32 _pkey;
				} _addr_pkey;
				struct {
					compat_ulong_t _data;
					u32 _type;
					u32 _flags;
				} _perf;
			};
		} _sigfault;
		struct {
			compat_long_t _band;
			int _fd;
		} _sigpoll;
		struct {
			compat_uptr_t _call_addr;
			int _syscall;
			unsigned int _arch;
		} _sigsys;
	} _sifields;
};

typedef struct compat_siginfo compat_siginfo_t;

struct sigcontext32 {
	unsigned int _unused[4];
	int signal;
	compat_uptr_t handler;
	unsigned int oldmask;
	compat_uptr_t regs;
};

struct mcontext32 {
	elf_gregset_t32 mc_gregs;
	elf_fpregset_t mc_fregs;
	unsigned int mc_pad[2];
	elf_vrregset_t32 mc_vregs;
	elf_vsrreghalf_t32 mc_vsregs;
};

struct ucontext32 {
	unsigned int uc_flags;
	unsigned int uc_link;
	compat_stack_t uc_stack;
	int uc_pad[7];
	compat_uptr_t uc_regs;
	compat_sigset_t uc_sigmask;
	int uc_maskext[30];
	int uc_pad2[3];
	struct mcontext32 uc_mcontext;
};

struct sigframe {
	struct sigcontext32 sctx;
	struct mcontext32 mctx;
	int abigap[56];
};

struct rt_sigframe {
	compat_siginfo_t info;
	struct ucontext32 uc;
	int abigap[56];
};

typedef phys_addr_t resource_size_t;

struct pci_host_bridge;

struct rtc_time;

struct kimage;

struct machdep_calls {
	const char *name;
	const char *compatible;
	const char * const *compatibles;
	void (*iommu_restore)();
	long unsigned int (*memory_block_size)();
	void (*dma_set_mask)(struct device *, u64);
	int (*probe)();
	void (*setup_arch)();
	void (*show_cpuinfo)(struct seq_file *);
	long unsigned int (*get_proc_freq)(unsigned int);
	void (*init_IRQ)();
	unsigned int (*get_irq)();
	void (*pcibios_fixup)();
	void (*pci_irq_fixup)(struct pci_dev *);
	int (*pcibios_root_bridge_prepare)(struct pci_host_bridge *);
	void (*discover_phbs)();
	int (*pci_setup_phb)(struct pci_controller *);
	void (*restart)(char *);
	void (*halt)();
	void (*panic)(char *);
	long int (*time_init)();
	int (*set_rtc_time)(struct rtc_time *);
	void (*get_rtc_time)(struct rtc_time *);
	time64_t (*get_boot_time)();
	void (*calibrate_decr)();
	void (*progress)(char *, short unsigned int);
	void (*log_error)(char *, unsigned int, int);
	unsigned char (*nvram_read_val)(int);
	void (*nvram_write_val)(int, unsigned char);
	ssize_t (*nvram_write)(char *, size_t, loff_t *);
	ssize_t (*nvram_read)(char *, size_t, loff_t *);
	ssize_t (*nvram_size)();
	void (*nvram_sync)();
	int (*system_reset_exception)(struct pt_regs *);
	int (*machine_check_exception)(struct pt_regs *);
	int (*handle_hmi_exception)(struct pt_regs *);
	int (*hmi_exception_early)(struct pt_regs *);
	long int (*machine_check_early)(struct pt_regs *);
	bool (*mce_check_early_recovery)(struct pt_regs *);
	void (*machine_check_log_err)();
	long int (*feature_call)(unsigned int, ...);
	int (*pci_get_legacy_ide_irq)(struct pci_dev *, int);
	pgprot_t (*phys_mem_access_prot)(long unsigned int, long unsigned int, pgprot_t);
	void (*power_save)();
	void (*enable_pmcs)();
	int (*set_dabr)(long unsigned int, long unsigned int);
	int (*set_dawr)(int, long unsigned int, long unsigned int);
	int (*pci_exclude_device)(struct pci_controller *, unsigned char, unsigned char);
	void (*pcibios_fixup_resources)(struct pci_dev *);
	void (*pcibios_fixup_bus)(struct pci_bus *);
	void (*pcibios_fixup_phb)(struct pci_controller *);
	void (*pcibios_bus_add_device)(struct pci_dev *);
	resource_size_t (*pcibios_default_alignment)();
	void (*pcibios_fixup_sriov)(struct pci_dev *);
	resource_size_t (*pcibios_iov_resource_alignment)(struct pci_dev *, int);
	int (*pcibios_sriov_enable)(struct pci_dev *, u16);
	int (*pcibios_sriov_disable)(struct pci_dev *);
	void (*machine_shutdown)();
	void (*kexec_cpu_down)(int, int);
	void (*machine_kexec)(struct kimage *);
	void (*suspend_disable_irqs)();
	void (*suspend_enable_irqs)();
	ssize_t (*cpu_probe)(const char *, size_t);
	ssize_t (*cpu_release)(const char *, size_t);
	int (*get_random_seed)(long unsigned int *);
};

typedef u64 uint64_t;

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

struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *, struct kobj_attribute *, char *);
	ssize_t (*store)(struct kobject *, struct kobj_attribute *, const char *, size_t);
};

enum opal_msg_type {
	OPAL_MSG_ASYNC_COMP = 0,
	OPAL_MSG_MEM_ERR = 1,
	OPAL_MSG_EPOW = 2,
	OPAL_MSG_SHUTDOWN = 3,
	OPAL_MSG_HMI_EVT = 4,
	OPAL_MSG_DPO = 5,
	OPAL_MSG_PRD = 6,
	OPAL_MSG_OCC = 7,
	OPAL_MSG_PRD2 = 8,
	OPAL_MSG_TYPE_MAX = 9,
};

struct opal_msg {
	__be32 msg_type;
	__be32 reserved;
	__be64 params[8];
};

enum {
	OPAL_P7IOC_NUM_PEST_REGS = 128,
	OPAL_PHB3_NUM_PEST_REGS = 256,
	OPAL_PHB4_NUM_PEST_REGS = 512,
};

struct psr_attr {
	u32 handle;
	struct kobj_attribute attr;
};

enum {
	FW_FEATURE_PSERIES_POSSIBLE = 35183556296703ULL,
	FW_FEATURE_PSERIES_ALWAYS = 0ULL,
	FW_FEATURE_POWERNV_POSSIBLE = 275146342400ULL,
	FW_FEATURE_POWERNV_ALWAYS = 0ULL,
	FW_FEATURE_PS3_POSSIBLE = 12582912ULL,
	FW_FEATURE_PS3_ALWAYS = 12582912ULL,
	FW_FEATURE_NATIVE_POSSIBLE = 0ULL,
	FW_FEATURE_NATIVE_ALWAYS = 0ULL,
	FW_FEATURE_POSSIBLE = 35183833120767ULL,
	FW_FEATURE_ALWAYS = 0ULL,
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

struct energy_scale_attribute {
	__be64 id;
	__be64 val;
	u8 desc[64];
	u8 value_desc[64];
};

struct h_energy_scale_info_hdr {
	__be64 num_attrs;
	__be64 array_offset;
	u8 data_header_version;
} __attribute__((packed));

struct papr_attr {
	u64 id;
	struct kobj_attribute kobj_attr;
};

struct papr_group {
	struct attribute_group pg;
	struct papr_attr pgattrs[3];
};

struct papr_ops_info {
	const char *attr_name;
	ssize_t (*show)(struct kobject *, struct kobj_attribute *, char *);
};

typedef long unsigned int irq_hw_number_t;

struct resource {
	resource_size_t start;
	resource_size_t end;
	const char *name;
	long unsigned int flags;
	long unsigned int desc;
	struct resource *parent;
	struct resource *sibling;
	struct resource *child;
};

typedef int pci_power_t;

typedef unsigned int pci_channel_state_t;

typedef short unsigned int pci_dev_flags_t;

struct pci_vpd {
	struct mutex lock;
	unsigned int len;
	u8 cap;
};

struct proc_dir_entry;

struct pci_slot;

struct aer_stats;

struct rcec_ea;

struct pci_driver;

struct pcie_link_state;

struct pci_sriov;

struct pci_dev {
	struct list_head bus_list;
	struct pci_bus *bus;
	struct pci_bus *subordinate;
	void *sysdata;
	struct proc_dir_entry *procent;
	struct pci_slot *slot;
	unsigned int devfn;
	short unsigned int vendor;
	short unsigned int device;
	short unsigned int subsystem_vendor;
	short unsigned int subsystem_device;
	unsigned int class;
	u8 revision;
	u8 hdr_type;
	u16 aer_cap;
	struct aer_stats *aer_stats;
	struct rcec_ea *rcec_ea;
	struct pci_dev *rcec;
	u32 devcap;
	u8 pcie_cap;
	u8 msi_cap;
	u8 msix_cap;
	u8 pcie_mpss: 3;
	u8 rom_base_reg;
	u8 pin;
	u16 pcie_flags_reg;
	long unsigned int *dma_alias_mask;
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
	struct pcie_link_state *link_state;
	unsigned int ltr_path: 1;
	unsigned int pasid_no_tlp: 1;
	unsigned int eetlp_prefix_path: 1;
	pci_channel_state_t error_state;
	struct device dev;
	int cfg_size;
	unsigned int irq;
	struct resource resource[17];
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
	struct bin_attribute *res_attr[17];
	struct bin_attribute *res_attr_wc[17];
	unsigned int broken_cmd_compl: 1;
	u16 ptm_cap;
	unsigned int ptm_root: 1;
	unsigned int ptm_enabled: 1;
	u8 ptm_granularity;
	void *msix_base;
	raw_spinlock_t msi_lock;
	struct pci_vpd vpd;
	u16 dpc_cap;
	unsigned int dpc_rp_extensions: 1;
	u8 dpc_rp_log_size;
	union {
		struct pci_sriov *sriov;
		struct pci_dev *physfn;
	};
	u16 ats_cap;
	u8 ats_stu;
	u16 acs_cap;
	phys_addr_t rom;
	size_t romlen;
	const char *driver_override;
	long unsigned int priv_flags;
	u8 reset_methods[7];
};

struct iommu_pool {
	long unsigned int start;
	long unsigned int end;
	long unsigned int hint;
	spinlock_t lock;
	long: 64;
	long: 64;
	long: 64;
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

struct iommu_table_ops;

struct iommu_table {
	long unsigned int it_busno;
	long unsigned int it_size;
	long unsigned int it_indirect_levels;
	long unsigned int it_level_size;
	long unsigned int it_allocated_size;
	long unsigned int it_offset;
	long unsigned int it_base;
	long unsigned int it_index;
	long unsigned int it_type;
	long unsigned int it_blocksize;
	long unsigned int poolsize;
	long unsigned int nr_pools;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct iommu_pool large_pool;
	struct iommu_pool pools[4];
	long unsigned int *it_map;
	long unsigned int it_page_shift;
	struct list_head it_group_list;
	__be64 *it_userspace;
	struct iommu_table_ops *it_ops;
	struct kref it_kref;
	int it_nid;
	long unsigned int it_reserved_start;
	long unsigned int it_reserved_end;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct iommu_table_group;

struct pci_dn {
	int flags;
	int busno;
	int devfn;
	int vendor_id;
	int device_id;
	int class_code;
	struct pci_dn *parent;
	struct pci_controller *phb;
	struct iommu_table_group *table_group;
	int pci_ext_config_space;
	struct eeh_dev *edev;
	unsigned int pe_number;
	u16 vfs_expanded;
	u16 num_vfs;
	unsigned int *pe_num_map;
	bool m64_single_mode;
	int (*m64_map)[6];
	int last_allow_rc;
	int mps;
	struct list_head child_list;
	struct list_head list;
	struct resource holes[6];
};

struct pdev_archdata {
	u64 dma_mask;
	void *priv;
};

struct iommu_fault_param;

struct iommu_fwspec;

struct iommu_device;

struct dev_iommu {
	struct mutex lock;
	struct iommu_fault_param *fault_param;
	struct iommu_fwspec *fwspec;
	struct iommu_device *iommu_dev;
	void *priv;
	u32 max_pasids;
	u32 attach_deferred: 1;
	u32 pci_32bit_workaround: 1;
	u32 require_direct: 1;
	u32 shadow_on_flush: 1;
};

struct pci_controller_ops {
	void (*dma_dev_setup)(struct pci_dev *);
	void (*dma_bus_setup)(struct pci_bus *);
	bool (*iommu_bypass_supported)(struct pci_dev *, u64);
	int (*probe_mode)(struct pci_bus *);
	bool (*enable_device_hook)(struct pci_dev *);
	void (*disable_device)(struct pci_dev *);
	void (*release_device)(struct pci_dev *);
	resource_size_t (*window_alignment)(struct pci_bus *, long unsigned int);
	void (*setup_bridge)(struct pci_bus *, long unsigned int);
	void (*reset_secondary_bus)(struct pci_dev *);
	int (*setup_msi_irqs)(struct pci_dev *, int, int);
	void (*teardown_msi_irqs)(struct pci_dev *);
	void (*shutdown)(struct pci_controller *);
	struct iommu_group * (*device_group)(struct pci_controller *, struct pci_dev *);
};

struct iommu_ops;

struct iommu_device {
	struct list_head list;
	const struct iommu_ops *ops;
	struct fwnode_handle *fwnode;
	struct device *dev;
	struct iommu_group *singleton_group;
	u32 max_pasids;
};

struct pci_ops;

struct pci_controller {
	struct pci_bus *bus;
	char is_dynamic;
	int node;
	struct device_node *dn;
	struct list_head list_node;
	struct device *parent;
	int first_busno;
	int last_busno;
	int self_busno;
	struct resource busn;
	void *io_base_virt;
	void *io_base_alloc;
	resource_size_t io_base_phys;
	resource_size_t pci_io_size;
	resource_size_t isa_mem_phys;
	resource_size_t isa_mem_size;
	struct pci_controller_ops controller_ops;
	struct pci_ops *ops;
	unsigned int *cfg_addr;
	void *cfg_data;
	u32 indirect_type;
	struct resource io_resource;
	struct resource mem_resources[3];
	resource_size_t mem_offset[3];
	int global_number;
	resource_size_t dma_window_base_cur;
	resource_size_t dma_window_size;
	long unsigned int buid;
	struct pci_dn *pci_data;
	void *private_data;
	struct irq_domain *dev_domain;
	struct irq_domain *msi_domain;
	struct fwnode_handle *fwnode;
	struct iommu_device iommu;
};

typedef short unsigned int pci_bus_flags_t;

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
	short unsigned int bridge_ctl;
	pci_bus_flags_t bus_flags;
	struct device *bridge;
	struct device dev;
	struct bin_attribute *legacy_io;
	struct bin_attribute *legacy_mem;
	unsigned int is_added: 1;
	unsigned int unsafe_warn: 1;
};

struct ppc_pci_io {
	u8 (*readb)(const volatile void *);
	u16 (*readw)(const volatile void *);
	u32 (*readl)(const volatile void *);
	u16 (*readw_be)(const volatile void *);
	u32 (*readl_be)(const volatile void *);
	void (*writeb)(u8, volatile void *);
	void (*writew)(u16, volatile void *);
	void (*writel)(u32, volatile void *);
	void (*writew_be)(u16, volatile void *);
	void (*writel_be)(u32, volatile void *);
	u64 (*readq)(const volatile void *);
	u64 (*readq_be)(const volatile void *);
	void (*writeq)(u64, volatile void *);
	void (*writeq_be)(u64, volatile void *);
	u8 (*inb)(long unsigned int);
	u16 (*inw)(long unsigned int);
	u32 (*inl)(long unsigned int);
	void (*outb)(u8, long unsigned int);
	void (*outw)(u16, long unsigned int);
	void (*outl)(u32, long unsigned int);
	void (*readsb)(const volatile void *, void *, long unsigned int);
	void (*readsw)(const volatile void *, void *, long unsigned int);
	void (*readsl)(const volatile void *, void *, long unsigned int);
	void (*writesb)(volatile void *, const void *, long unsigned int);
	void (*writesw)(volatile void *, const void *, long unsigned int);
	void (*writesl)(volatile void *, const void *, long unsigned int);
	void (*insb)(long unsigned int, void *, long unsigned int);
	void (*insw)(long unsigned int, void *, long unsigned int);
	void (*insl)(long unsigned int, void *, long unsigned int);
	void (*outsb)(long unsigned int, const void *, long unsigned int);
	void (*outsw)(long unsigned int, const void *, long unsigned int);
	void (*outsl)(long unsigned int, const void *, long unsigned int);
	void (*memset_io)(volatile void *, int, long unsigned int);
	void (*memcpy_fromio)(void *, const volatile void *, long unsigned int);
	void (*memcpy_toio)(volatile void *, const void *, long unsigned int);
};

struct msi_desc;

struct irq_common_data {
	unsigned int state_use_accessors;
	unsigned int node;
	void *handler_data;
	struct msi_desc *msi_desc;
	cpumask_var_t affinity;
};

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

enum irqchip_irq_state {
	IRQCHIP_STATE_PENDING = 0,
	IRQCHIP_STATE_ACTIVE = 1,
	IRQCHIP_STATE_MASKED = 2,
	IRQCHIP_STATE_LINE_LEVEL = 3,
};

struct msi_msg;

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
	long unsigned int flags;
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

struct platform_device_id {
	char name[20];
	kernel_ulong_t driver_data;
};

struct mfd_cell;

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

struct hotplug_slot;

struct pci_slot {
	struct pci_bus *bus;
	struct list_head list;
	struct hotplug_slot *hotplug;
	unsigned char number;
	struct kobject kobj;
};

enum {
	PCI_STD_RESOURCES = 0,
	PCI_STD_RESOURCE_END = 5,
	PCI_ROM_RESOURCE = 6,
	PCI_IOV_RESOURCES = 7,
	PCI_IOV_RESOURCE_END = 12,
	PCI_BRIDGE_RESOURCES = 13,
	PCI_BRIDGE_RESOURCE_END = 16,
	PCI_NUM_RESOURCES = 17,
	DEVICE_COUNT_RESOURCE = 17,
};

typedef unsigned int pcie_reset_state_t;

struct pci_dynids {
	spinlock_t lock;
	struct list_head list;
};

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

struct pci_host_bridge {
	struct device dev;
	struct pci_bus *bus;
	struct pci_ops *ops;
	struct pci_ops *child_ops;
	void *sysdata;
	int busnr;
	int domain_nr;
	struct list_head windows;
	struct list_head dma_ranges;
	u8 (*swizzle_irq)(struct pci_dev *, u8 *);
	int (*map_irq)(const struct pci_dev *, u8, u8);
	void (*release_fn)(struct pci_host_bridge *);
	void *release_data;
	unsigned int ignore_reset_delay: 1;
	unsigned int no_ext_tags: 1;
	unsigned int no_inc_mrrs: 1;
	unsigned int native_aer: 1;
	unsigned int native_pcie_hotplug: 1;
	unsigned int native_shpc_hotplug: 1;
	unsigned int native_pme: 1;
	unsigned int native_ltr: 1;
	unsigned int native_dpc: 1;
	unsigned int native_cxl_error: 1;
	unsigned int preserve_config: 1;
	unsigned int size_windows: 1;
	unsigned int msi_domain: 1;
	resource_size_t (*align_resource)(struct pci_dev *, const struct resource *, resource_size_t, resource_size_t, resource_size_t);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long unsigned int private[0];
};

struct pci_ops {
	int (*add_bus)(struct pci_bus *);
	void (*remove_bus)(struct pci_bus *);
	void * (*map_bus)(struct pci_bus *, unsigned int, int);
	int (*read)(struct pci_bus *, unsigned int, int, int, u32 *);
	int (*write)(struct pci_bus *, unsigned int, int, int, u32);
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

struct scatterlist {
	long unsigned int page_link;
	unsigned int offset;
	unsigned int length;
	dma_addr_t dma_address;
	unsigned int dma_length;
};

struct sg_table {
	struct scatterlist *sgl;
	unsigned int nents;
	unsigned int orig_nents;
};

struct pci_fixup {
	u16 vendor;
	u16 device;
	u32 class;
	unsigned int class_shift;
	void (*hook)(struct pci_dev *);
};

struct of_phandle_args {
	struct device_node *np;
	int args_count;
	uint32_t args[16];
};

struct iova_bitmap;

struct iommu_fault_page_request {
	u32 flags;
	u32 pasid;
	u32 grpid;
	u32 perm;
	u64 addr;
	u64 private_data[2];
};

struct iommu_fault {
	u32 type;
	struct iommu_fault_page_request prm;
};

struct iommu_page_response {
	u32 pasid;
	u32 grpid;
	u32 code;
};

struct iopf_fault {
	struct iommu_fault fault;
	struct list_head list;
};

struct iommu_domain;

struct iopf_group {
	struct iopf_fault last_fault;
	struct list_head faults;
	struct list_head pending_node;
	struct work_struct work;
	struct iommu_domain *domain;
	struct iommu_fault_param *fault_param;
};

struct iommu_domain_geometry {
	dma_addr_t aperture_start;
	dma_addr_t aperture_end;
	bool force_aperture;
};

struct iommu_dma_cookie;

typedef int (*iommu_fault_handler_t)(struct iommu_domain *, struct device *, long unsigned int, int, void *);

struct iommu_domain_ops;

struct iommu_dirty_ops;

struct iommu_domain {
	unsigned int type;
	const struct iommu_domain_ops *ops;
	const struct iommu_dirty_ops *dirty_ops;
	const struct iommu_ops *owner;
	long unsigned int pgsize_bitmap;
	struct iommu_domain_geometry geometry;
	struct iommu_dma_cookie *iova_cookie;
	int (*iopf_handler)(struct iopf_group *);
	void *fault_data;
	union {
		struct {
			iommu_fault_handler_t handler;
			void *handler_token;
		};
		struct {
			struct mm_struct *mm;
			int users;
			struct list_head next;
		};
	};
};

struct iopf_queue;

struct iommu_fault_param {
	struct mutex lock;
	refcount_t users;
	struct callback_head rcu;
	struct device *dev;
	struct iopf_queue *queue;
	struct list_head queue_list;
	struct list_head partial;
	struct list_head faults;
};

struct iopf_queue {
	struct workqueue_struct *wq;
	struct list_head devices;
	struct mutex lock;
};

typedef unsigned int ioasid_t;

struct iommu_iotlb_gather;

struct iommu_user_data_array;

struct iommu_domain_ops {
	int (*attach_dev)(struct iommu_domain *, struct device *);
	int (*set_dev_pasid)(struct iommu_domain *, struct device *, ioasid_t);
	int (*map_pages)(struct iommu_domain *, long unsigned int, phys_addr_t, size_t, size_t, int, gfp_t, size_t *);
	size_t (*unmap_pages)(struct iommu_domain *, long unsigned int, size_t, size_t, struct iommu_iotlb_gather *);
	void (*flush_iotlb_all)(struct iommu_domain *);
	int (*iotlb_sync_map)(struct iommu_domain *, long unsigned int, size_t);
	void (*iotlb_sync)(struct iommu_domain *, struct iommu_iotlb_gather *);
	int (*cache_invalidate_user)(struct iommu_domain *, struct iommu_user_data_array *);
	phys_addr_t (*iova_to_phys)(struct iommu_domain *, dma_addr_t);
	bool (*enforce_cache_coherency)(struct iommu_domain *);
	int (*enable_nesting)(struct iommu_domain *);
	int (*set_pgtable_quirks)(struct iommu_domain *, long unsigned int);
	void (*free)(struct iommu_domain *);
};

struct iommu_dirty_bitmap;

struct iommu_dirty_ops {
	int (*set_dirty_tracking)(struct iommu_domain *, bool);
	int (*read_and_clear_dirty)(struct iommu_domain *, long unsigned int, size_t, long unsigned int, struct iommu_dirty_bitmap *);
};

enum iommu_cap {
	IOMMU_CAP_CACHE_COHERENCY = 0,
	IOMMU_CAP_NOEXEC = 1,
	IOMMU_CAP_PRE_BOOT_PROTECTION = 2,
	IOMMU_CAP_ENFORCE_CACHE_COHERENCY = 3,
	IOMMU_CAP_DEFERRED_FLUSH = 4,
	IOMMU_CAP_DIRTY_TRACKING = 5,
};

enum iommu_dev_features {
	IOMMU_DEV_FEAT_SVA = 0,
	IOMMU_DEV_FEAT_IOPF = 1,
};

struct iommu_user_data;

struct iommu_ops {
	bool (*capable)(struct device *, enum iommu_cap);
	void * (*hw_info)(struct device *, u32 *, u32 *);
	struct iommu_domain * (*domain_alloc)(unsigned int);
	struct iommu_domain * (*domain_alloc_user)(struct device *, u32, struct iommu_domain *, const struct iommu_user_data *);
	struct iommu_domain * (*domain_alloc_paging)(struct device *);
	struct iommu_device * (*probe_device)(struct device *);
	void (*release_device)(struct device *);
	void (*probe_finalize)(struct device *);
	struct iommu_group * (*device_group)(struct device *);
	void (*get_resv_regions)(struct device *, struct list_head *);
	int (*of_xlate)(struct device *, const struct of_phandle_args *);
	bool (*is_attach_deferred)(struct device *);
	int (*dev_enable_feat)(struct device *, enum iommu_dev_features);
	int (*dev_disable_feat)(struct device *, enum iommu_dev_features);
	void (*page_response)(struct device *, struct iopf_fault *, struct iommu_page_response *);
	int (*def_domain_type)(struct device *);
	void (*remove_dev_pasid)(struct device *, ioasid_t);
	const struct iommu_domain_ops *default_domain_ops;
	long unsigned int pgsize_bitmap;
	struct module *owner;
	struct iommu_domain *identity_domain;
	struct iommu_domain *blocked_domain;
	struct iommu_domain *release_domain;
	struct iommu_domain *default_domain;
};

struct iommu_iotlb_gather {
	long unsigned int start;
	long unsigned int end;
	size_t pgsize;
	struct list_head freelist;
	bool queued;
};

struct iommu_dirty_bitmap {
	struct iova_bitmap *bitmap;
	struct iommu_iotlb_gather *gather;
};

struct iommu_user_data {
	unsigned int type;
	void *uptr;
	size_t len;
};

struct iommu_user_data_array {
	unsigned int type;
	void *uptr;
	size_t entry_len;
	u32 entry_num;
};

struct iommu_fwspec {
	const struct iommu_ops *ops;
	struct fwnode_handle *iommu_fwnode;
	u32 flags;
	unsigned int num_ids;
	u32 ids[0];
};

struct iommu_table_group_ops;

struct iommu_table_group {
	__u32 tce32_start;
	__u32 tce32_size;
	__u64 pgsizes;
	__u32 max_dynamic_windows_supported;
	__u32 max_levels;
	struct iommu_group *group;
	struct iommu_table *tables[2];
	struct iommu_table_group_ops *ops;
};

struct iommu_table_ops {
	int (*set)(struct iommu_table *, long int, long int, long unsigned int, enum dma_data_direction, long unsigned int);
	int (*xchg_no_kill)(struct iommu_table *, long int, long unsigned int *, enum dma_data_direction *);
	void (*tce_kill)(struct iommu_table *, long unsigned int, long unsigned int);
	__be64 * (*useraddrptr)(struct iommu_table *, long int, bool);
	void (*clear)(struct iommu_table *, long int, long int);
	long unsigned int (*get)(struct iommu_table *, long int);
	void (*flush)(struct iommu_table *);
	void (*free)(struct iommu_table *);
};

struct iommu_table_group_ops {
	long unsigned int (*get_table_size)(__u32, __u64, __u32);
	long int (*create_table)(struct iommu_table_group *, int, __u32, __u64, __u32, struct iommu_table **);
	long int (*set_window)(struct iommu_table_group *, int, struct iommu_table *);
	long int (*unset_window)(struct iommu_table_group *, int);
	long int (*take_ownership)(struct iommu_table_group *);
	void (*release_ownership)(struct iommu_table_group *);
};

enum spu_utilization_state {
	SPU_UTIL_USER = 0,
	SPU_UTIL_SYSTEM = 1,
	SPU_UTIL_IOWAIT = 2,
	SPU_UTIL_IDLE_LOADED = 3,
	SPU_UTIL_MAX = 4,
};

struct spu_runqueue;

struct spu_problem;

struct spu_priv2;

struct spu_context;

struct spu_priv1;

struct spu {
	const char *name;
	long unsigned int local_store_phys;
	u8 *local_store;
	long unsigned int problem_phys;
	struct spu_problem *problem;
	struct spu_priv2 *priv2;
	struct list_head cbe_list;
	struct list_head full_list;
	enum {
		SPU_FREE = 0,
		SPU_USED = 1,
	} alloc_state;
	int number;
	unsigned int irqs[3];
	u32 node;
	long unsigned int flags;
	u64 class_0_pending;
	u64 class_0_dar;
	u64 class_1_dar;
	u64 class_1_dsisr;
	size_t ls_size;
	unsigned int slb_replace;
	struct mm_struct *mm;
	struct spu_context *ctx;
	struct spu_runqueue *rq;
	long long unsigned int timestamp;
	pid_t pid;
	pid_t tgid;
	spinlock_t register_lock;
	void (*wbox_callback)(struct spu *);
	void (*ibox_callback)(struct spu *);
	void (*stop_callback)(struct spu *, int);
	void (*mfc_callback)(struct spu *);
	char irq_c0[8];
	char irq_c1[8];
	char irq_c2[8];
	u64 spe_id;
	void *pdata;
	struct device_node *devnode;
	struct spu_priv1 *priv1;
	u64 shadow_int_mask_RW[3];
	struct device dev;
	int has_mem_affinity;
	struct list_head aff_list;
	struct {
		enum spu_utilization_state util_state;
		long long unsigned int tstamp;
		long long unsigned int times[4];
		long long unsigned int vol_ctx_switch;
		long long unsigned int invol_ctx_switch;
		long long unsigned int min_flt;
		long long unsigned int maj_flt;
		long long unsigned int hash_flt;
		long long unsigned int slb_flt;
		long long unsigned int class2_intr;
		long long unsigned int libassist;
	} stats;
};

union mfc_tag_size_class_cmd {
	struct {
		u16 mfc_size;
		u16 mfc_tag;
		u8 pad;
		u8 mfc_rclassid;
		u16 mfc_cmd;
	} u;
	struct {
		u32 mfc_size_tag32;
		u32 mfc_class_cmd32;
	} by32;
	u64 all64;
};

struct spu_problem {
	u64 spc_mssync_RW;
	u8 pad_0x0008_0x3000[12280];
	u8 pad_0x3000_0x3004[4];
	u32 mfc_lsa_W;
	u64 mfc_ea_W;
	union mfc_tag_size_class_cmd mfc_union_W;
	u8 pad_0x3018_0x3104[236];
	u32 dma_qstatus_R;
	u8 pad_0x3108_0x3204[252];
	u32 dma_querytype_RW;
	u8 pad_0x3208_0x321c[20];
	u32 dma_querymask_RW;
	u8 pad_0x3220_0x322c[12];
	u32 dma_tagstatus_R;
	u8 pad_0x3230_0x4000[3536];
	u8 pad_0x4000_0x4004[4];
	u32 pu_mb_R;
	u8 pad_0x4008_0x400c[4];
	u32 spu_mb_W;
	u8 pad_0x4010_0x4014[4];
	u32 mb_stat_R;
	u8 pad_0x4018_0x401c[4];
	u32 spu_runcntl_RW;
	u8 pad_0x4020_0x4024[4];
	u32 spu_status_R;
	u8 pad_0x4028_0x402c[4];
	u32 spu_spe_R;
	u8 pad_0x4030_0x4034[4];
	u32 spu_npc_RW;
	u8 pad_0x4038_0x14000[65480];
	u8 pad_0x14000_0x1400c[12];
	u32 signal_notify1;
	u8 pad_0x14010_0x1c00c[32764];
	u32 signal_notify2;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct mfc_cq_sr {
	u64 mfc_cq_data0_RW;
	u64 mfc_cq_data1_RW;
	u64 mfc_cq_data2_RW;
	u64 mfc_cq_data3_RW;
};

struct spu_priv2 {
	u8 pad_0x0000_0x1100[4352];
	u8 pad_0x1100_0x1108[8];
	u64 slb_index_W;
	u64 slb_esid_RW;
	u64 slb_vsid_RW;
	u64 slb_invalidate_entry_W;
	u64 slb_invalidate_all_W;
	u8 pad_0x1130_0x2000[3792];
	struct mfc_cq_sr spuq[16];
	struct mfc_cq_sr puq[8];
	u8 pad_0x2300_0x3000[3328];
	u64 mfc_control_RW;
	u8 pad_0x3008_0x4000[4088];
	u64 puint_mb_R;
	u8 pad_0x4008_0x4040[56];
	u64 spu_privcntl_RW;
	u8 pad_0x4048_0x4058[16];
	u64 spu_lslr_RW;
	u64 spu_chnlcntptr_RW;
	u64 spu_chnlcnt_RW;
	u64 spu_chnldata_RW;
	u64 spu_cfg_RW;
	u8 pad_0x4080_0x5000[3968];
	u64 spu_pm_trace_tag_status_RW;
	u64 spu_tag_status_query_RW;
	u64 spu_cmd_buf1_RW;
	u64 spu_cmd_buf2_RW;
	u64 spu_atomic_status_RW;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct spu_priv1 {
	u64 mfc_sr1_RW;
	u64 mfc_lpid_RW;
	u64 spu_idr_RW;
	u64 mfc_vr_RO;
	u64 spu_vr_RO;
	u8 pad_0x28_0x100[216];
	u64 int_mask_RW[3];
	u8 pad_0x118_0x140[40];
	u64 int_stat_RW[3];
	u8 pad_0x158_0x180[40];
	u64 int_route_RW;
	u8 pad_0x188_0x200[120];
	u64 mfc_atomic_flush_RW;
	u8 pad_0x208_0x280[120];
	u64 resource_allocation_groupID_RW;
	u64 resource_allocation_enable_RW;
	u8 pad_0x290_0x3c8[312];
	u64 smf_sbi_signal_sel;
	u64 smf_ato_signal_sel;
	u8 pad_0x3d8_0x400[40];
	u64 mfc_sdr_RW;
	u8 pad_0x408_0x500[248];
	u64 tlb_index_hint_RO;
	u64 tlb_index_W;
	u64 tlb_vpn_RW;
	u64 tlb_rpn_RW;
	u8 pad_0x520_0x540[32];
	u64 tlb_invalidate_entry_W;
	u64 tlb_invalidate_all_W;
	u8 pad_0x550_0x580[48];
	u64 smm_hid;
	u8 pad_0x588_0x600[120];
	u64 mfc_accr_RW;
	u8 pad_0x608_0x610[8];
	u64 mfc_dsisr_RW;
	u8 pad_0x618_0x620[8];
	u64 mfc_dar_RW;
	u8 pad_0x628_0x700[216];
	u64 rmt_index_RW;
	u8 pad_0x708_0x710[8];
	u64 rmt_data1_RW;
	u8 pad_0x718_0x800[232];
	u64 mfc_dsir_R;
	u64 mfc_lsacr_RW;
	u64 mfc_lscrr_R;
	u8 pad_0x818_0x820[8];
	u64 mfc_tclass_id_RW;
	u8 pad_0x828_0x900[216];
	u64 mfc_rm_boundary;
	u8 pad_0x908_0x938[48];
	u64 smf_dma_signal_sel;
	u8 pad_0x940_0xa38[248];
	u64 smm_signal_sel;
	u8 pad_0xa40_0xc00[448];
	u64 mfc_cer_R;
	u8 pad_0xc08_0x1000[1016];
	u64 spu_ecc_cntl_RW;
	u64 spu_ecc_stat_RW;
	u64 spu_ecc_addr_RW;
	u64 spu_err_mask_RW;
	u8 pad_0x1020_0x1028[8];
	u64 spu_trig0_sel;
	u64 spu_trig1_sel;
	u64 spu_trig2_sel;
	u64 spu_trig3_sel;
	u64 spu_trace_sel;
	u64 spu_event0_sel;
	u64 spu_event1_sel;
	u64 spu_event2_sel;
	u64 spu_event3_sel;
	u64 spu_trace_cntl;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct spu_priv1_ops {
	void (*int_mask_and)(struct spu *, int, u64);
	void (*int_mask_or)(struct spu *, int, u64);
	void (*int_mask_set)(struct spu *, int, u64);
	u64 (*int_mask_get)(struct spu *, int);
	void (*int_stat_clear)(struct spu *, int, u64);
	u64 (*int_stat_get)(struct spu *, int);
	void (*cpu_affinity_set)(struct spu *, int);
	u64 (*mfc_dar_get)(struct spu *);
	u64 (*mfc_dsisr_get)(struct spu *);
	void (*mfc_dsisr_set)(struct spu *, u64);
	void (*mfc_sdr_setup)(struct spu *);
	void (*mfc_sr1_set)(struct spu *, u64);
	u64 (*mfc_sr1_get)(struct spu *);
	void (*mfc_tclass_id_set)(struct spu *, u64);
	u64 (*mfc_tclass_id_get)(struct spu *);
	void (*tlb_invalidate)(struct spu *);
	void (*resource_allocation_groupID_set)(struct spu *, u64);
	u64 (*resource_allocation_groupID_get)(struct spu *);
	void (*resource_allocation_enable_set)(struct spu *, u64);
	u64 (*resource_allocation_enable_get)(struct spu *);
};

struct spu_management_ops {
	int (*enumerate_spus)(int (*)(void *));
	int (*create_spu)(struct spu *, void *);
	int (*destroy_spu)(struct spu *);
	void (*enable_spu)(struct spu_context *);
	void (*disable_spu)(struct spu_context *);
	int (*init_affinity)();
};

typedef struct {
	void *token;
	unsigned int stride;
	unsigned int base;
} dcr_host_mmio_t;

typedef dcr_host_mmio_t dcr_host_t;

struct msi_bitmap {
	struct device_node *of_node;
	long unsigned int *bitmap;
	spinlock_t lock;
	unsigned int irq_count;
	bool bitmap_from_slab;
};

struct mpic_irq_fixup {
	u8 *base;
	u8 *applebase;
	u32 data;
	unsigned int index;
};

enum mpic_reg_type {
	mpic_access_mmio_le = 0,
	mpic_access_mmio_be = 1,
	mpic_access_dcr = 2,
};

struct mpic_reg_bank {
	u32 *base;
	dcr_host_t dhost;
};

struct mpic_irq_save {
	u32 vecprio;
	u32 dest;
	u32 fixup_data;
};

struct mpic {
	struct device_node *node;
	struct irq_domain *irqhost;
	struct irq_chip hc_irq;
	struct irq_chip hc_ht_irq;
	struct irq_chip hc_ipi;
	struct irq_chip hc_tm;
	struct irq_chip hc_err;
	const char *name;
	unsigned int flags;
	unsigned int isu_size;
	unsigned int isu_shift;
	unsigned int isu_mask;
	unsigned int num_sources;
	unsigned int ipi_vecs[4];
	unsigned int timer_vecs[8];
	unsigned int err_int_vecs[32];
	unsigned int spurious_vec;
	struct mpic_irq_fixup *fixups;
	raw_spinlock_t fixup_lock;
	enum mpic_reg_type reg_type;
	phys_addr_t paddr;
	struct mpic_reg_bank thiscpuregs;
	struct mpic_reg_bank gregs;
	struct mpic_reg_bank tmregs;
	struct mpic_reg_bank cpuregs[32];
	struct mpic_reg_bank isus[32];
	u32 *err_regs;
	long unsigned int *protected;
	struct msi_bitmap msi_bitmap;
	u32 isu_reg0_shadow[2048];
	struct mpic *next;
	struct mpic_irq_save *save_data;
};

struct cbe_mic_tm_regs {
	u8 pad_0x0000_0x0040[64];
	u64 mic_ctl_cnfg2;
	u64 pad_0x0048;
	u64 mic_aux_trc_base;
	u64 mic_aux_trc_max_addr;
	u64 mic_aux_trc_cur_addr;
	u64 mic_aux_trc_grf_addr;
	u64 mic_aux_trc_grf_data;
	u64 pad_0x0078;
	u64 mic_ctl_cnfg_0;
	u64 pad_0x0088;
	u64 slow_fast_timer_0;
	u64 slow_next_timer_0;
	u8 pad_0x00a0_0x00f8[88];
	u64 mic_df_ecc_address_0;
	u8 pad_0x0100_0x01b8[184];
	u64 mic_df_ecc_address_1;
	u64 mic_ctl_cnfg_1;
	u64 pad_0x01c8;
	u64 slow_fast_timer_1;
	u64 slow_next_timer_1;
	u8 pad_0x01e0_0x0208[40];
	u64 mic_exc;
	u64 mic_mnt_cfg;
	u64 mic_df_config;
	u8 pad_0x0220_0x0230[16];
	u64 mic_fir;
	u64 mic_fir_debug;
	u8 pad_0x0240_0x1000[3520];
};

struct iowa_bus {
	struct pci_controller *phb;
	struct ppc_pci_io *ops;
	void *private;
};

enum refcount_saturation_type {
	REFCOUNT_ADD_NOT_ZERO_OVF = 0,
	REFCOUNT_ADD_OVF = 1,
	REFCOUNT_ADD_UAF = 2,
	REFCOUNT_SUB_UAF = 3,
	REFCOUNT_DEC_LEAK = 4,
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

struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops;
	struct list_head list;
	dev_t dev;
	unsigned int count;
};

struct coprocessor_completion_block {
	__be64 value;
	__be64 address;
};

struct coprocessor_status_block {
	u8 flags;
	u8 cs;
	u8 cc;
	u8 ce;
	__be32 count;
	__be64 address;
};

struct data_descriptor_entry {
	__be16 flags;
	u8 count;
	u8 index;
	__be32 length;
	__be64 address;
};

struct nx_fault_stamp {
	__be64 fault_storage_addr;
	__be16 reserved;
	__u8 flags;
	__u8 fault_status;
	__be32 pswid;
};

struct coprocessor_request_block {
	__be32 ccw;
	__be32 flags;
	__be64 csb_addr;
	struct data_descriptor_entry source;
	struct data_descriptor_entry target;
	struct coprocessor_completion_block ccb;
	union {
		struct nx_fault_stamp nx;
		u8 reserved[16];
	} stamp;
	u8 reserved[32];
	struct coprocessor_status_block csb;
};

struct vas_tx_win_open_attr {
	__u32 version;
	__s16 vas_id;
	__u16 reserved1;
	__u64 flags;
	__u64 reserved2[6];
};

enum vas_cop_type {
	VAS_COP_TYPE_FAULT = 0,
	VAS_COP_TYPE_842 = 1,
	VAS_COP_TYPE_842_HIPRI = 2,
	VAS_COP_TYPE_GZIP = 3,
	VAS_COP_TYPE_GZIP_HIPRI = 4,
	VAS_COP_TYPE_FTW = 5,
	VAS_COP_TYPE_MAX = 6,
};

struct vas_user_win_ref {
	struct pid *pid;
	struct pid *tgid;
	struct mm_struct *mm;
	struct mutex mmap_mutex;
	struct vm_area_struct *vma;
};

struct vas_window {
	u32 winid;
	u32 wcreds_max;
	u32 status;
	enum vas_cop_type cop;
	struct vas_user_win_ref task_ref;
	char *dbgname;
	struct dentry *dbgdir;
};

struct vas_user_win_ops {
	struct vas_window * (*open_win)(int, u64, enum vas_cop_type);
	u64 (*paste_addr)(struct vas_window *);
	int (*close_win)(struct vas_window *);
};

struct coproc_dev {
	struct cdev cdev;
	struct device *device;
	char *name;
	dev_t devt;
	struct class *class;
	enum vas_cop_type cop_type;
	const struct vas_user_win_ops *vops;
};

struct coproc_instance {
	struct coproc_dev *coproc;
	struct vas_window *txwin;
};

enum key_being_used_for {
	VERIFYING_MODULE_SIGNATURE = 0,
	VERIFYING_FIRMWARE_SIGNATURE = 1,
	VERIFYING_KEXEC_PE_SIGNATURE = 2,
	VERIFYING_KEY_SIGNATURE = 3,
	VERIFYING_KEY_SELF_SIGNATURE = 4,
	VERIFYING_UNSPECIFIED_SIGNATURE = 5,
	NR__KEY_BEING_USED_FOR = 6,
};

typedef void (*crash_shutdown_t)();

typedef long unsigned int kimage_entry_t;

struct kexec_segment {
	union {
		void *buf;
		void *kbuf;
	};
	size_t bufsz;
	long unsigned int mem;
	size_t memsz;
};

struct kimage {
	kimage_entry_t head;
	kimage_entry_t *entry;
	kimage_entry_t *last_entry;
	long unsigned int start;
	struct page *control_code_page;
	struct page *swap_page;
	void *vmcoreinfo_data_copy;
	long unsigned int nr_segments;
	struct kexec_segment segment[16];
	struct list_head control_pages;
	struct list_head dest_pages;
	struct list_head unusable_pages;
	long unsigned int control_page;
	unsigned int type: 1;
	unsigned int preserve_context: 1;
	unsigned int file_mode: 1;
	void *elf_headers;
	long unsigned int elf_headers_sz;
	long unsigned int elf_load_addr;
};

typedef void (*swap_func_t)(void *, void *, int);

typedef int (*cmp_func_t)(const void *, const void *);

enum ucount_type {
	UCOUNT_USER_NAMESPACES = 0,
	UCOUNT_PID_NAMESPACES = 1,
	UCOUNT_UTS_NAMESPACES = 2,
	UCOUNT_IPC_NAMESPACES = 3,
	UCOUNT_NET_NAMESPACES = 4,
	UCOUNT_MNT_NAMESPACES = 5,
	UCOUNT_CGROUP_NAMESPACES = 6,
	UCOUNT_TIME_NAMESPACES = 7,
	UCOUNT_INOTIFY_INSTANCES = 8,
	UCOUNT_INOTIFY_WATCHES = 9,
	UCOUNT_FANOTIFY_GROUPS = 10,
	UCOUNT_FANOTIFY_MARKS = 11,
	UCOUNT_COUNTS = 12,
};

enum rlimit_type {
	UCOUNT_RLIMIT_NPROC = 0,
	UCOUNT_RLIMIT_MSGQUEUE = 1,
	UCOUNT_RLIMIT_SIGPENDING = 2,
	UCOUNT_RLIMIT_MEMLOCK = 3,
	UCOUNT_RLIMIT_COUNTS = 4,
};

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE = 0,
	RWSEM_WAITING_FOR_READ = 1,
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
	long unsigned int timeout;
	bool handoff_set;
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

typedef void (*rcu_callback_t)(struct callback_head *);

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

enum irqreturn {
	IRQ_NONE = 0,
	IRQ_HANDLED = 1,
	IRQ_WAKE_THREAD = 2,
};

typedef enum irqreturn irqreturn_t;

struct irq_desc;

typedef void (*irq_flow_handler_t)(struct irq_desc *);

struct irqaction;

struct irq_affinity_notify;

struct irq_desc {
	struct irq_common_data irq_common_data;
	struct irq_data irq_data;
	unsigned int *kstat_irqs;
	irq_flow_handler_t handle_irq;
	struct irqaction *action;
	unsigned int status_use_accessors;
	unsigned int core_internal_state__do_not_mess_with_it;
	unsigned int depth;
	unsigned int wake_depth;
	unsigned int tot_count;
	unsigned int irq_count;
	long unsigned int last_unhandled;
	unsigned int irqs_unhandled;
	atomic_t threads_handled;
	int threads_handled_last;
	raw_spinlock_t lock;
	struct cpumask *percpu_enabled;
	const struct cpumask *percpu_affinity;
	const struct cpumask *affinity_hint;
	struct irq_affinity_notify *affinity_notify;
	long unsigned int threads_oneshot;
	atomic_t threads_active;
	wait_queue_head_t wait_for_threads;
	unsigned int nr_actions;
	unsigned int no_suspend_depth;
	unsigned int cond_suspend_depth;
	unsigned int force_resume_depth;
	struct proc_dir_entry *dir;
	struct callback_head rcu;
	struct kobject kobj;
	struct mutex request_mutex;
	int parent_irq;
	struct module *owner;
	const char *name;
	struct hlist_node resend_node;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

typedef struct {
	void *lock;
} class_rcu_t;

struct maple_alloc {
	long unsigned int total;
	unsigned char node_count;
	unsigned int request_count;
	struct maple_alloc *slot[30];
};

struct maple_enode;

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

struct ma_state {
	struct maple_tree *tree;
	long unsigned int index;
	long unsigned int last;
	struct maple_enode *node;
	long unsigned int min;
	long unsigned int max;
	struct maple_alloc *alloc;
	enum maple_status status;
	unsigned char depth;
	unsigned char offset;
	unsigned char mas_flags;
	unsigned char end;
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

struct irq_domain_ops;

struct irq_domain_chip_generic;

struct msi_parent_ops;

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
	const struct msi_parent_ops *msi_parent_ops;
	irq_hw_number_t hwirq_max;
	unsigned int revmap_size;
	struct xarray revmap_tree;
	struct irq_data *revmap[0];
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

typedef irqreturn_t (*irq_handler_t)(int, void *);

struct irqaction {
	irq_handler_t handler;
	void *dev_id;
	void *percpu_dev_id;
	struct irqaction *next;
	irq_handler_t thread_fn;
	struct task_struct *thread;
	struct irqaction *secondary;
	unsigned int irq;
	unsigned int flags;
	long unsigned int thread_flags;
	long unsigned int thread_mask;
	const char *name;
	struct proc_dir_entry *dir;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct irq_affinity_notify {
	unsigned int irq;
	struct kref kref;
	struct work_struct work;
	void (*notify)(struct irq_affinity_notify *, const cpumask_t *);
	void (*release)(struct kref *);
};

struct irq_chip_regs {
	long unsigned int enable;
	long unsigned int disable;
	long unsigned int mask;
	long unsigned int ack;
	long unsigned int eoi;
	long unsigned int type;
	long unsigned int polarity;
};

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
	long unsigned int installed;
	long unsigned int unused;
	struct irq_domain *domain;
	struct list_head list;
	struct irq_chip_type chip_types[0];
};

enum irq_gc_flags {
	IRQ_GC_INIT_MASK_CACHE = 1,
	IRQ_GC_INIT_NESTED_LOCK = 2,
	IRQ_GC_MASK_CACHE_PER_TYPE = 4,
	IRQ_GC_NO_MASK = 8,
	IRQ_GC_BE_IO = 16,
};

struct irq_domain_chip_generic {
	unsigned int irqs_per_chip;
	unsigned int num_chips;
	unsigned int irq_flags_to_clear;
	unsigned int irq_flags_to_set;
	enum irq_gc_flags gc_flags;
	struct irq_chip_generic *gc[0];
};

struct irq_affinity_desc {
	struct cpumask mask;
	unsigned int is_managed: 1;
};

struct kernel_stat {
	long unsigned int irqs_sum;
	unsigned int softirqs[10];
};

struct irq_fwspec {
	struct fwnode_handle *fwnode;
	int param_count;
	u32 param[16];
};

struct irq_domain_ops {
	int (*match)(struct irq_domain *, struct device_node *, enum irq_domain_bus_token);
	int (*select)(struct irq_domain *, struct irq_fwspec *, enum irq_domain_bus_token);
	int (*map)(struct irq_domain *, unsigned int, irq_hw_number_t);
	void (*unmap)(struct irq_domain *, unsigned int);
	int (*xlate)(struct irq_domain *, struct device_node *, const u32 *, unsigned int, long unsigned int *, unsigned int *);
	int (*alloc)(struct irq_domain *, unsigned int, unsigned int, void *);
	void (*free)(struct irq_domain *, unsigned int, unsigned int);
	int (*activate)(struct irq_domain *, struct irq_data *, bool);
	void (*deactivate)(struct irq_domain *, struct irq_data *);
	int (*translate)(struct irq_domain *, struct irq_fwspec *, long unsigned int *, unsigned int *);
};

struct msi_domain_info;

struct msi_parent_ops {
	u32 supported_flags;
	u32 required_flags;
	u32 bus_select_token;
	u32 bus_select_mask;
	const char *prefix;
	bool (*init_dev_msi_info)(struct device *, struct irq_domain *, struct irq_domain *, struct msi_domain_info *);
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
	_IRQ_DEFAULT_INIT_FLAGS = 2048,
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

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

struct __kernel_timex_timeval {
	__kernel_time64_t tv_sec;
	long long int tv_usec;
};

struct __kernel_timex {
	unsigned int modes;
	long long int offset;
	long long int freq;
	long long int maxerror;
	long long int esterror;
	int status;
	long long int constant;
	long long int precision;
	long long int tolerance;
	struct __kernel_timex_timeval time;
	long long int tick;
	long long int ppsfreq;
	long long int jitter;
	int shift;
	long long int stabil;
	long long int jitcnt;
	long long int calcnt;
	long long int errcnt;
	long long int stbcnt;
	int tai;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum clocksource_ids {
	CSID_GENERIC = 0,
	CSID_ARM_ARCH_COUNTER = 1,
	CSID_X86_TSC_EARLY = 2,
	CSID_X86_TSC = 3,
	CSID_X86_KVM_CLK = 4,
	CSID_MAX = 5,
};

enum tk_offsets {
	TK_OFFS_REAL = 0,
	TK_OFFS_BOOT = 1,
	TK_OFFS_TAI = 2,
	TK_OFFS_MAX = 3,
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

struct system_counterval_t {
	u64 cycles;
	enum clocksource_ids cs_id;
};

typedef struct {
	seqcount_t seqcount;
} seqcount_latch_t;

struct notifier_block;

typedef int (*notifier_fn_t)(struct notifier_block *, long unsigned int, void *);

struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block *next;
	int priority;
};

struct raw_notifier_head {
	struct notifier_block *head;
};

enum vdso_clock_mode {
	VDSO_CLOCKMODE_NONE = 0,
	VDSO_CLOCKMODE_ARCHTIMER = 1,
	VDSO_CLOCKMODE_MAX = 2,
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
	long unsigned int flags;
	int (*enable)(struct clocksource *);
	void (*disable)(struct clocksource *);
	void (*suspend)(struct clocksource *);
	void (*resume)(struct clocksource *);
	void (*mark_unstable)(struct clocksource *);
	void (*tick_stable)(struct clocksource *);
	struct module *owner;
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
	long unsigned int ktime_sec;
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

struct syscore_ops {
	struct list_head node;
	int (*suspend)();
	void (*resume)();
	void (*shutdown)();
};

typedef int (*cpu_stop_fn_t)(void *);

enum audit_ntp_type {
	AUDIT_NTP_OFFSET = 0,
	AUDIT_NTP_FREQ = 1,
	AUDIT_NTP_STATUS = 2,
	AUDIT_NTP_TAI = 3,
	AUDIT_NTP_TICK = 4,
	AUDIT_NTP_ADJUST = 5,
	AUDIT_NTP_NVALS = 6,
};

struct audit_ntp_val {
	long long int oldval;
	long long int newval;
};

struct audit_ntp_data {
	struct audit_ntp_val vals[6];
};

enum timekeeping_adv_mode {
	TK_ADV_TICK = 0,
	TK_ADV_FREQ = 1,
};

struct tk_fast {
	seqcount_latch_t seq;
	struct tk_read_base base[2];
};

typedef int __kernel_key_t;

typedef int __kernel_mqd_t;

typedef __kernel_key_t key_t;

typedef __kernel_mqd_t mqd_t;

struct linux_binprm;

struct coredump_params;

struct linux_binfmt {
	struct list_head lh;
	struct module *module;
	int (*load_binary)(struct linux_binprm *);
	int (*load_shlib)(struct file *);
	int (*core_dump)(struct coredump_params *);
	long unsigned int min_coredump;
};

struct sigevent {
	sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		int _pad[12];
		int _tid;
		struct {
			void (*_function)(sigval_t);
			void *_attribute;
		} _sigev_thread;
	} _sigev_un;
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

enum audit_state {
	AUDIT_STATE_DISABLED = 0,
	AUDIT_STATE_BUILD = 1,
	AUDIT_STATE_RECORD = 2,
};

struct audit_cap_data {
	kernel_cap_t permitted;
	kernel_cap_t inheritable;
	union {
		unsigned int fE;
		kernel_cap_t effective;
	};
	kernel_cap_t ambient;
	kuid_t rootid;
};

struct filename;

struct audit_names {
	struct list_head list;
	struct filename *name;
	int name_len;
	bool hidden;
	long unsigned int ino;
	dev_t dev;
	umode_t mode;
	kuid_t uid;
	kgid_t gid;
	dev_t rdev;
	u32 osid;
	struct audit_cap_data fcap;
	unsigned int fcap_ver;
	unsigned char type;
	bool should_free;
};

struct mq_attr {
	__kernel_long_t mq_flags;
	__kernel_long_t mq_maxmsg;
	__kernel_long_t mq_msgsize;
	__kernel_long_t mq_curmsgs;
	__kernel_long_t __reserved[4];
};

struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

struct audit_proctitle {
	int len;
	char *value;
};

struct audit_aux_data;

struct __kernel_sockaddr_storage;

struct audit_tree_refs;

struct audit_context {
	int dummy;
	enum {
		AUDIT_CTX_UNUSED = 0,
		AUDIT_CTX_SYSCALL = 1,
		AUDIT_CTX_URING = 2,
	} context;
	enum audit_state state;
	enum audit_state current_state;
	unsigned int serial;
	int major;
	int uring_op;
	struct timespec64 ctime;
	long unsigned int argv[4];
	long int return_code;
	u64 prio;
	int return_valid;
	struct audit_names preallocated_names[5];
	int name_count;
	struct list_head names_list;
	char *filterkey;
	struct path pwd;
	struct audit_aux_data *aux;
	struct audit_aux_data *aux_pids;
	struct __kernel_sockaddr_storage *sockaddr;
	size_t sockaddr_len;
	pid_t ppid;
	kuid_t uid;
	kuid_t euid;
	kuid_t suid;
	kuid_t fsuid;
	kgid_t gid;
	kgid_t egid;
	kgid_t sgid;
	kgid_t fsgid;
	long unsigned int personality;
	int arch;
	pid_t target_pid;
	kuid_t target_auid;
	kuid_t target_uid;
	unsigned int target_sessionid;
	u32 target_sid;
	char target_comm[16];
	struct audit_tree_refs *trees;
	struct audit_tree_refs *first_trees;
	struct list_head killed_trees;
	int tree_count;
	int type;
	union {
		struct {
			int nargs;
			long int args[6];
		} socketcall;
		struct {
			kuid_t uid;
			kgid_t gid;
			umode_t mode;
			u32 osid;
			int has_perm;
			uid_t perm_uid;
			gid_t perm_gid;
			umode_t perm_mode;
			long unsigned int qbytes;
		} ipc;
		struct {
			mqd_t mqdes;
			struct mq_attr mqstat;
		} mq_getsetattr;
		struct {
			mqd_t mqdes;
			int sigev_signo;
		} mq_notify;
		struct {
			mqd_t mqdes;
			size_t msg_len;
			unsigned int msg_prio;
			struct timespec64 abs_timeout;
		} mq_sendrecv;
		struct {
			int oflag;
			umode_t mode;
			struct mq_attr attr;
		} mq_open;
		struct {
			pid_t pid;
			struct audit_cap_data cap;
		} capset;
		struct {
			int fd;
			int flags;
		} mmap;
		struct open_how openat2;
		struct {
			int argc;
		} execve;
		struct {
			char *name;
		} module;
		struct {
			struct audit_ntp_data ntp_data;
			struct timespec64 tk_injoffset;
		} time;
	};
	int fds[2];
	struct audit_proctitle proctitle;
};

struct cpu_vfs_cap_data {
	__u32 magic_etc;
	kuid_t rootid;
	kernel_cap_t permitted;
	kernel_cap_t inheritable;
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
	cc_t c_cc[19];
	cc_t c_line;
	speed_t c_ispeed;
	speed_t c_ospeed;
};

struct winsize {
	short unsigned int ws_row;
	short unsigned int ws_col;
	short unsigned int ws_xpixel;
	short unsigned int ws_ypixel;
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
	long unsigned int flags;
	int count;
	unsigned int receive_room;
	struct winsize winsize;
	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
		long unsigned int unused[0];
	} flow;
	struct {
		struct pid *pgrp;
		struct pid *session;
		spinlock_t lock;
		unsigned char pktstatus;
		bool packet;
		long unsigned int unused[0];
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

typedef struct fsnotify_mark_connector *fsnotify_connp_t;

struct fsnotify_mark_connector {
	spinlock_t lock;
	short unsigned int type;
	short unsigned int flags;
	union {
		fsnotify_connp_t *obj;
		struct fsnotify_mark_connector *destroy_next;
	};
	struct hlist_head list;
};

struct filename {
	const char *name;
	const char *uptr;
	atomic_t refcnt;
	struct audit_names *aname;
	const char iname[0];
};

typedef short unsigned int __kernel_sa_family_t;

struct __kernel_sockaddr_storage {
	union {
		struct {
			__kernel_sa_family_t ss_family;
			char __data[126];
		};
		void *__align;
	};
};

enum auditsc_class_t {
	AUDITSC_NATIVE = 0,
	AUDITSC_COMPAT = 1,
	AUDITSC_OPEN = 2,
	AUDITSC_OPENAT = 3,
	AUDITSC_SOCKETCALL = 4,
	AUDITSC_EXECVE = 5,
	AUDITSC_OPENAT2 = 6,
	AUDITSC_NVALS = 7,
};

enum {
	Audit_equal = 0,
	Audit_not_equal = 1,
	Audit_bitmask = 2,
	Audit_bittest = 3,
	Audit_lt = 4,
	Audit_gt = 5,
	Audit_le = 6,
	Audit_ge = 7,
	Audit_bad = 8,
};

struct fanotify_response_info_header {
	__u8 type;
	__u8 pad;
	__u16 len;
};

struct fanotify_response_info_audit_rule {
	struct fanotify_response_info_header hdr;
	__u32 rule_number;
	__u32 subj_trust;
	__u32 obj_trust;
};

struct audit_field;

struct audit_watch;

struct audit_tree;

struct audit_fsnotify_mark;

struct audit_krule {
	u32 pflags;
	u32 flags;
	u32 listnr;
	u32 action;
	u32 mask[64];
	u32 buflen;
	u32 field_count;
	char *filterkey;
	struct audit_field *fields;
	struct audit_field *arch_f;
	struct audit_field *inode_f;
	struct audit_watch *watch;
	struct audit_tree *tree;
	struct audit_fsnotify_mark *exe;
	struct list_head rlist;
	struct list_head list;
	u64 prio;
};

struct audit_field {
	u32 type;
	union {
		u32 val;
		kuid_t uid;
		kgid_t gid;
		struct {
			char *lsm_str;
			void *lsm_rule;
		};
	};
	u32 op;
};

enum audit_nfcfgop {
	AUDIT_XT_OP_REGISTER = 0,
	AUDIT_XT_OP_REPLACE = 1,
	AUDIT_XT_OP_UNREGISTER = 2,
	AUDIT_NFT_OP_TABLE_REGISTER = 3,
	AUDIT_NFT_OP_TABLE_UNREGISTER = 4,
	AUDIT_NFT_OP_CHAIN_REGISTER = 5,
	AUDIT_NFT_OP_CHAIN_UNREGISTER = 6,
	AUDIT_NFT_OP_RULE_REGISTER = 7,
	AUDIT_NFT_OP_RULE_UNREGISTER = 8,
	AUDIT_NFT_OP_SET_REGISTER = 9,
	AUDIT_NFT_OP_SET_UNREGISTER = 10,
	AUDIT_NFT_OP_SETELEM_REGISTER = 11,
	AUDIT_NFT_OP_SETELEM_UNREGISTER = 12,
	AUDIT_NFT_OP_GEN_REGISTER = 13,
	AUDIT_NFT_OP_OBJ_REGISTER = 14,
	AUDIT_NFT_OP_OBJ_UNREGISTER = 15,
	AUDIT_NFT_OP_OBJ_RESET = 16,
	AUDIT_NFT_OP_FLOWTABLE_REGISTER = 17,
	AUDIT_NFT_OP_FLOWTABLE_UNREGISTER = 18,
	AUDIT_NFT_OP_SETELEM_RESET = 19,
	AUDIT_NFT_OP_RULE_RESET = 20,
	AUDIT_NFT_OP_INVALID = 21,
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

struct binfmt_misc {
	struct list_head entries;
	rwlock_t entries_lock;
	bool enabled;
};

struct kern_ipc_perm {
	spinlock_t lock;
	bool deleted;
	int id;
	key_t key;
	kuid_t uid;
	kgid_t gid;
	kuid_t cuid;
	kgid_t cgid;
	umode_t mode;
	long unsigned int seq;
	void *security;
	struct rhash_head khtnode;
	struct callback_head rcu;
	refcount_t refcount;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct linux_binprm {
	struct vm_area_struct *vma;
	long unsigned int vma_pages;
	struct mm_struct *mm;
	long unsigned int p;
	long unsigned int argmin;
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
	long unsigned int loader;
	long unsigned int exec;
	struct rlimit rlim_stack;
	char buf[256];
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

enum {
	TRACE_EVENT_FL_FILTERED_BIT = 0,
	TRACE_EVENT_FL_CAP_ANY_BIT = 1,
	TRACE_EVENT_FL_NO_SET_FILTER_BIT = 2,
	TRACE_EVENT_FL_IGNORE_ENABLE_BIT = 3,
	TRACE_EVENT_FL_TRACEPOINT_BIT = 4,
	TRACE_EVENT_FL_DYNAMIC_BIT = 5,
	TRACE_EVENT_FL_KPROBE_BIT = 6,
	TRACE_EVENT_FL_UPROBE_BIT = 7,
	TRACE_EVENT_FL_EPROBE_BIT = 8,
	TRACE_EVENT_FL_FPROBE_BIT = 9,
	TRACE_EVENT_FL_CUSTOM_BIT = 10,
};

enum {
	EVENT_FILE_FL_ENABLED_BIT = 0,
	EVENT_FILE_FL_RECORDED_CMD_BIT = 1,
	EVENT_FILE_FL_RECORDED_TGID_BIT = 2,
	EVENT_FILE_FL_FILTERED_BIT = 3,
	EVENT_FILE_FL_NO_SET_FILTER_BIT = 4,
	EVENT_FILE_FL_SOFT_MODE_BIT = 5,
	EVENT_FILE_FL_SOFT_DISABLED_BIT = 6,
	EVENT_FILE_FL_TRIGGER_MODE_BIT = 7,
	EVENT_FILE_FL_TRIGGER_COND_BIT = 8,
	EVENT_FILE_FL_PID_FILTER_BIT = 9,
	EVENT_FILE_FL_WAS_ENABLED_BIT = 10,
	EVENT_FILE_FL_FREED_BIT = 11,
};

enum fsnotify_iter_type {
	FSNOTIFY_ITER_TYPE_INODE = 0,
	FSNOTIFY_ITER_TYPE_VFSMOUNT = 1,
	FSNOTIFY_ITER_TYPE_SB = 2,
	FSNOTIFY_ITER_TYPE_PARENT = 3,
	FSNOTIFY_ITER_TYPE_INODE2 = 4,
	FSNOTIFY_ITER_TYPE_COUNT = 5,
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
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
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
	short int type;
	short int subtype;
	struct ktermios init_termios;
	long unsigned int flags;
	struct proc_dir_entry *proc_entry;
	struct tty_driver *other;
	struct tty_struct **ttys;
	struct tty_port **ports;
	struct ktermios **termios;
	void *driver_state;
	const struct tty_operations *ops;
	struct list_head tty_drivers;
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

struct __kfifo {
	unsigned int in;
	unsigned int out;
	unsigned int mask;
	unsigned int esize;
	void *data;
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
	long unsigned int flags;
	long unsigned int iflags;
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

struct tty_ldisc_ops {
	char *name;
	int num;
	int (*open)(struct tty_struct *);
	void (*close)(struct tty_struct *);
	void (*flush_buffer)(struct tty_struct *);
	ssize_t (*read)(struct tty_struct *, struct file *, u8 *, size_t, void **, long unsigned int);
	ssize_t (*write)(struct tty_struct *, struct file *, const u8 *, size_t);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
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

struct tty_ldisc {
	struct tty_ldisc_ops *ops;
	struct tty_struct *tty;
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

struct audit_entry {
	struct list_head list;
	struct callback_head rcu;
	struct audit_krule rule;
};

struct audit_aux_data {
	struct audit_aux_data *next;
	int type;
};

struct audit_chunk;

struct audit_tree_refs {
	struct audit_tree_refs *next;
	struct audit_chunk *c[31];
};

struct audit_aux_data_pids {
	struct audit_aux_data d;
	pid_t target_pid[16];
	kuid_t target_auid[16];
	kuid_t target_uid[16];
	unsigned int target_sessionid[16];
	u32 target_sid[16];
	char target_comm[256];
	int pid_count;
};

struct audit_aux_data_bprm_fcaps {
	struct audit_aux_data d;
	struct audit_cap_data fcap;
	unsigned int fcap_ver;
	struct audit_cap_data old_pcap;
	struct audit_cap_data new_pcap;
};

struct audit_nfcfgop_tab {
	enum audit_nfcfgop op;
	const char *s;
};

struct ftrace_hash {
	long unsigned int size_bits;
	struct hlist_head *buckets;
	long unsigned int count;
	long unsigned int flags;
	struct callback_head rcu;
};

struct prog_entry;

struct event_filter {
	struct prog_entry *prog;
	char *filter_string;
};

struct trace_buffer;

struct trace_array_cpu;

struct array_buffer {
	struct trace_array *tr;
	struct trace_buffer *buffer;
	struct trace_array_cpu *data;
	u64 time_start;
	int cpu;
};

struct trace_pid_list;

struct trace_event_file;

struct eventfs_inode;

struct trace_options;

struct cond_snapshot;

struct trace_func_repeats;

struct trace_array {
	struct list_head list;
	char *name;
	struct array_buffer array_buffer;
	struct array_buffer max_buffer;
	bool allocated_snapshot;
	spinlock_t snapshot_trigger_lock;
	unsigned int snapshot;
	long unsigned int max_latency;
	struct dentry *d_max_latency;
	struct work_struct fsnotify_work;
	struct irq_work fsnotify_irqwork;
	struct trace_pid_list *filtered_pids;
	struct trace_pid_list *filtered_no_pids;
	arch_spinlock_t max_lock;
	int buffer_disabled;
	int sys_refcount_enter;
	int sys_refcount_exit;
	struct trace_event_file *enter_syscall_files[462];
	struct trace_event_file *exit_syscall_files[462];
	int stop_count;
	int clock_id;
	int nr_topts;
	bool clear_trace;
	int buffer_percent;
	unsigned int n_err_log_entries;
	struct tracer *current_trace;
	unsigned int trace_flags;
	unsigned char trace_flags_index[32];
	unsigned int flags;
	raw_spinlock_t start_lock;
	const char *system_names;
	struct list_head err_log;
	struct dentry *dir;
	struct dentry *options;
	struct dentry *percpu_dir;
	struct eventfs_inode *event_dir;
	struct trace_options *topts;
	struct list_head systems;
	struct list_head events;
	struct trace_event_file *trace_marker_file;
	cpumask_var_t tracing_cpumask;
	cpumask_var_t pipe_cpumask;
	int ref;
	int trace_ref;
	struct ftrace_ops *ops;
	struct trace_pid_list *function_pids;
	struct trace_pid_list *function_no_pids;
	struct list_head func_probes;
	struct list_head mod_trace;
	struct list_head mod_notrace;
	int function_enabled;
	int no_filter_buffering_ref;
	struct list_head hist_vars;
	struct cond_snapshot *cond_snapshot;
	struct trace_func_repeats *last_func_repeats;
	bool ring_buffer_expanded;
};

struct tracer_flags;

struct tracer {
	const char *name;
	int (*init)(struct trace_array *);
	void (*reset)(struct trace_array *);
	void (*start)(struct trace_array *);
	void (*stop)(struct trace_array *);
	int (*update_thresh)(struct trace_array *);
	void (*open)(struct trace_iterator *);
	void (*pipe_open)(struct trace_iterator *);
	void (*close)(struct trace_iterator *);
	void (*pipe_close)(struct trace_iterator *);
	ssize_t (*read)(struct trace_iterator *, struct file *, char *, size_t, loff_t *);
	ssize_t (*splice_read)(struct trace_iterator *, struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*print_header)(struct seq_file *);
	enum print_line_t (*print_line)(struct trace_iterator *);
	int (*set_flag)(struct trace_array *, u32, u32, int);
	int (*flag_changed)(struct trace_array *, u32, int);
	struct tracer *next;
	struct tracer_flags *flags;
	int enabled;
	bool print_max;
	bool allow_instances;
	bool use_max_tr;
	bool noboot;
};

struct trace_subsystem_dir;

struct trace_event_file {
	struct list_head list;
	struct trace_event_call *event_call;
	struct event_filter *filter;
	struct eventfs_inode *ei;
	struct trace_array *tr;
	struct trace_subsystem_dir *system;
	struct list_head triggers;
	long unsigned int flags;
	atomic_t ref;
	atomic_t sm_ref;
	atomic_t tm_ref;
};

struct event_subsystem;

struct trace_subsystem_dir {
	struct list_head list;
	struct event_subsystem *subsystem;
	struct trace_array *tr;
	struct eventfs_inode *ei;
	int ref_count;
	int nr_events;
};

union lower_chunk {
	union lower_chunk *next;
	long unsigned int data[256];
};

union upper_chunk {
	union upper_chunk *next;
	union lower_chunk *data[256];
};

struct trace_pid_list {
	raw_spinlock_t lock;
	struct irq_work refill_irqwork;
	union upper_chunk *upper[256];
	union upper_chunk *upper_list;
	union lower_chunk *lower_list;
	int free_upper_chunks;
	int free_lower_chunks;
};

struct trace_array_cpu {
	atomic_t disabled;
	void *buffer_page;
	long unsigned int entries;
	long unsigned int saved_latency;
	long unsigned int critical_start;
	long unsigned int critical_end;
	long unsigned int critical_sequence;
	long unsigned int nice;
	long unsigned int policy;
	long unsigned int rt_priority;
	long unsigned int skipped_entries;
	u64 preempt_timestamp;
	pid_t pid;
	kuid_t uid;
	char comm[16];
	int ftrace_ignore_pid;
	bool ignore_pid;
};

struct trace_option_dentry;

struct trace_options {
	struct tracer *tracer;
	struct trace_option_dentry *topts;
};

struct tracer_opt;

struct trace_option_dentry {
	struct tracer_opt *opt;
	struct tracer_flags *flags;
	struct trace_array *tr;
	struct dentry *entry;
};

typedef bool (*cond_update_fn_t)(struct trace_array *, void *);

struct cond_snapshot {
	void *cond_data;
	cond_update_fn_t update;
};

struct trace_func_repeats {
	long unsigned int ip;
	long unsigned int parent_ip;
	long unsigned int count;
	u64 ts_last_call;
};

struct tracer_opt {
	const char *name;
	u32 bit;
};

struct tracer_flags {
	u32 val;
	struct tracer_opt *opts;
	struct tracer *trace;
};

enum trace_iterator_bits {
	TRACE_ITER_PRINT_PARENT_BIT = 0,
	TRACE_ITER_SYM_OFFSET_BIT = 1,
	TRACE_ITER_SYM_ADDR_BIT = 2,
	TRACE_ITER_VERBOSE_BIT = 3,
	TRACE_ITER_RAW_BIT = 4,
	TRACE_ITER_HEX_BIT = 5,
	TRACE_ITER_BIN_BIT = 6,
	TRACE_ITER_BLOCK_BIT = 7,
	TRACE_ITER_FIELDS_BIT = 8,
	TRACE_ITER_PRINTK_BIT = 9,
	TRACE_ITER_ANNOTATE_BIT = 10,
	TRACE_ITER_USERSTACKTRACE_BIT = 11,
	TRACE_ITER_SYM_USEROBJ_BIT = 12,
	TRACE_ITER_PRINTK_MSGONLY_BIT = 13,
	TRACE_ITER_CONTEXT_INFO_BIT = 14,
	TRACE_ITER_LATENCY_FMT_BIT = 15,
	TRACE_ITER_RECORD_CMD_BIT = 16,
	TRACE_ITER_RECORD_TGID_BIT = 17,
	TRACE_ITER_OVERWRITE_BIT = 18,
	TRACE_ITER_STOP_ON_FREE_BIT = 19,
	TRACE_ITER_IRQ_INFO_BIT = 20,
	TRACE_ITER_MARKERS_BIT = 21,
	TRACE_ITER_EVENT_FORK_BIT = 22,
	TRACE_ITER_PAUSE_ON_TRACE_BIT = 23,
	TRACE_ITER_HASH_PTR_BIT = 24,
	TRACE_ITER_FUNCTION_BIT = 25,
	TRACE_ITER_FUNC_FORK_BIT = 26,
	TRACE_ITER_DISPLAY_GRAPH_BIT = 27,
	TRACE_ITER_STACKTRACE_BIT = 28,
	TRACE_ITER_LAST_BIT = 29,
};

struct event_subsystem {
	struct list_head list;
	const char *name;
	struct event_filter *filter;
	int ref_count;
};

enum {
	TRACE_NOP_OPT_ACCEPT = 1,
	TRACE_NOP_OPT_REFUSE = 2,
};

typedef __u32 __wsum;

typedef unsigned int slab_flags_t;

typedef struct {
	atomic_t refcnt;
} rcuref_t;

struct bpf_cgroup_storage_key {
	__u64 cgroup_inode_id;
	__u32 attach_type;
};

enum bpf_task_fd_type {
	BPF_FD_TYPE_RAW_TRACEPOINT = 0,
	BPF_FD_TYPE_TRACEPOINT = 1,
	BPF_FD_TYPE_KPROBE = 2,
	BPF_FD_TYPE_KRETPROBE = 3,
	BPF_FD_TYPE_UPROBE = 4,
	BPF_FD_TYPE_URETPROBE = 5,
};

typedef char *va_list;

struct blocking_notifier_head {
	struct rw_semaphore rwsem;
	struct notifier_block *head;
};

typedef __u64 __addrpair;

typedef __u32 __portpair;

typedef struct {
	struct net *net;
} possible_net_t;

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct proto;

struct inet_timewait_death_row;

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
	short unsigned int skc_family;
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
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
	atomic64_t skc_cookie;
	union {
		long unsigned int skc_flags;
		struct sock *skc_listener;
		struct inet_timewait_death_row *skc_tw_dr;
	};
	int skc_dontcopy_begin[0];
	union {
		struct hlist_node skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	short unsigned int skc_tx_queue_mapping;
	short unsigned int skc_rx_queue_mapping;
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

struct sk_buff;

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

typedef struct {
	spinlock_t slock;
	int owned;
	wait_queue_head_t wq;
} socket_lock_t;

typedef u64 netdev_features_t;

struct sock_cgroup_data {
	struct cgroup *cgroup;
	u32 classid;
	u16 prioidx;
};

typedef struct {} netns_tracker;

struct dst_entry;

struct sk_filter;

struct socket_wq;

struct socket;

struct xfrm_policy;

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
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	u16 sk_busy_poll_budget;
	u8 sk_prefer_busy_poll;
	u8 sk_userlocks;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	void (*sk_data_ready)(struct sock *);
	long int sk_rcvtimeo;
	int sk_rcvlowat;
	__u8 __cacheline_group_end__sock_read_rx[0];
	__u8 __cacheline_group_begin__sock_read_rxtx[0];
	int sk_err;
	struct socket *sk_socket;
	struct mem_cgroup *sk_memcg;
	struct xfrm_policy *sk_policy[2];
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
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head sk_write_queue;
	u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	struct page_frag sk_frag;
	struct timer_list sk_timer;
	long unsigned int sk_pacing_rate;
	atomic_t sk_zckey;
	atomic_t sk_tskey;
	__u8 __cacheline_group_end__sock_write_tx[0];
	__u8 __cacheline_group_begin__sock_read_tx[0];
	long unsigned int sk_max_pacing_rate;
	long int sk_sndtimeo;
	u32 sk_priority;
	u32 sk_mark;
	struct dst_entry *sk_dst_cache;
	netdev_features_t sk_route_caps;
	struct sk_buff * (*sk_validate_xmit_skb)(struct sock *, struct net_device *, struct sk_buff *);
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
	long unsigned int sk_lingertime;
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
	void *sk_security;
	struct sock_cgroup_data sk_cgrp_data;
	void (*sk_state_change)(struct sock *);
	void (*sk_write_space)(struct sock *);
	void (*sk_error_report)(struct sock *);
	int (*sk_backlog_rcv)(struct sock *, struct sk_buff *);
	void (*sk_destruct)(struct sock *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
};

typedef struct {
	union {
		void *kernel;
		void *user;
	};
	bool is_kernel: 1;
} sockptr_t;

struct btf_param {
	__u32 name_off;
	__u32 type;
};

struct ref_tracker_dir {};

struct prot_inuse;

struct netns_core {
	struct ctl_table_header *sysctl_hdr;
	int sysctl_somaxconn;
	int sysctl_optmem_max;
	u8 sysctl_txrehash;
	struct prot_inuse *prot_inuse;
	struct cpumask *rps_default_mask;
};

struct ipstats_mib;

struct tcp_mib;

struct linux_mib;

struct udp_mib;

struct linux_xfrm_mib;

struct linux_tls_mib;

struct mptcp_mib;

struct icmp_mib;

struct icmpmsg_mib;

struct icmpv6_mib;

struct icmpv6msg_mib;

struct netns_mib {
	struct ipstats_mib *ip_statistics;
	struct ipstats_mib *ipv6_statistics;
	struct tcp_mib *tcp_statistics;
	struct linux_mib *net_statistics;
	struct udp_mib *udp_statistics;
	struct udp_mib *udp_stats_in6;
	struct linux_xfrm_mib *xfrm_statistics;
	struct linux_tls_mib *tls_statistics;
	struct mptcp_mib *mptcp_statistics;
	struct udp_mib *udplite_statistics;
	struct udp_mib *udplite_stats_in6;
	struct icmp_mib *icmp_statistics;
	struct icmpmsg_mib *icmpmsg_statistics;
	struct icmpv6_mib *icmpv6_statistics;
	struct icmpv6msg_mib *icmpv6msg_statistics;
	struct proc_dir_entry *proc_net_devsnmp6;
};

struct netns_packet {
	struct mutex sklist_lock;
	struct hlist_head sklist;
};

struct unix_table {
	spinlock_t *locks;
	struct hlist_head *buckets;
};

struct netns_unix {
	struct unix_table table;
	int sysctl_max_dgram_qlen;
	struct ctl_table_header *ctl;
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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct inet_hashinfo *hashinfo;
	int sysctl_max_tw_buckets;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct udp_table;

struct ipv4_devconf;

struct ip_ra_chain;

struct fib_rules_ops;

struct fib_table;

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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct inet_timewait_death_row tcp_death_row;
	struct udp_table *udp_table;
	struct ctl_table_header *forw_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *ipv4_hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *xfrm4_hdr;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain *ra_chain;
	struct mutex ra_mutex;
	struct fib_rules_ops *rules_ops;
	struct fib_table *fib_main;
	struct fib_table *fib_default;
	unsigned int fib_rules_require_fldissect;
	bool fib_has_custom_rules;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	u8 sysctl_tcp_shrink_window;
	atomic_t fib_num_tclassid_users;
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
	u8 sysctl_raw_l3mdev_accept;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_l3mdev_accept;
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
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
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
	u8 sysctl_udp_l3mdev_accept;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	unsigned int sysctl_udp_child_hash_entries;
	long unsigned int *sysctl_local_reserved_ports;
	int sysctl_ip_prot_sock;
	struct list_head mr_tables;
	struct fib_rules_ops *mr_rules_ops;
	u32 sysctl_fib_multipath_hash_fields;
	u8 sysctl_fib_multipath_use_neigh;
	u8 sysctl_fib_multipath_hash_policy;
	struct fib_notifier_ops *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
	long: 64;
	long: 64;
	long: 64;
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

struct neighbour;

struct dst_ops {
	short unsigned int family;
	unsigned int gc_thresh;
	void (*gc)(struct dst_ops *);
	struct dst_entry * (*check)(struct dst_entry *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry *);
	unsigned int (*mtu)(const struct dst_entry *);
	u32 * (*cow_metrics)(struct dst_entry *, long unsigned int);
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
	long: 64;
	long: 64;
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

struct netns_sysctl_ipv6 {
	struct ctl_table_header *hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *icmp_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *xfrm6_hdr;
	int flush_delay;
	int ip6_rt_max_size;
	int ip6_rt_gc_min_interval;
	int ip6_rt_gc_timeout;
	int ip6_rt_gc_interval;
	int ip6_rt_gc_elasticity;
	int ip6_rt_mtu_expires;
	int ip6_rt_min_advmss;
	u32 multipath_hash_fields;
	u8 multipath_hash_policy;
	u8 bindv6only;
	u8 flowlabel_consistency;
	u8 auto_flowlabels;
	int icmpv6_time;
	u8 icmpv6_echo_ignore_all;
	u8 icmpv6_echo_ignore_multicast;
	u8 icmpv6_echo_ignore_anycast;
	long unsigned int icmpv6_ratemask[4];
	long unsigned int *icmpv6_ratemask_ptr;
	u8 anycast_src_echo_reply;
	u8 ip_nonlocal_bind;
	u8 fwmark_reflect;
	u8 flowlabel_state_ranges;
	int idgen_retries;
	int idgen_delay;
	int flowlabel_reflect;
	int max_dst_opts_cnt;
	int max_hbh_opts_cnt;
	int max_dst_opts_len;
	int max_hbh_opts_len;
	int seg6_flowlabel;
	u32 ioam6_id;
	u64 ioam6_id_wide;
	u8 skip_notify_on_dev_down;
	u8 fib_notify_on_flag_change;
	u8 icmpv6_error_anycast_as_unicast;
};

struct ipv6_devconf;

struct fib6_info;

struct rt6_info;

struct rt6_statistics;

struct fib6_table;

struct seg6_pernet_data;

struct ioam6_pernet_data;

struct netns_ipv6 {
	struct dst_ops ip6_dst_ops;
	struct netns_sysctl_ipv6 sysctl;
	struct ipv6_devconf *devconf_all;
	struct ipv6_devconf *devconf_dflt;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	struct fib6_info *fib6_null_entry;
	struct rt6_info *ip6_null_entry;
	struct rt6_statistics *rt6_stats;
	struct timer_list ip6_fib_timer;
	struct hlist_head *fib_table_hash;
	struct fib6_table *fib6_main_tbl;
	struct list_head fib6_walkers;
	rwlock_t fib6_walker_lock;
	spinlock_t fib6_gc_lock;
	atomic_t ip6_rt_gc_expire;
	long unsigned int ip6_rt_last_gc;
	unsigned char flowlabel_has_excl;
	bool fib6_has_custom_rules;
	unsigned int fib6_rules_require_fldissect;
	unsigned int fib6_routes_require_src;
	struct rt6_info *ip6_prohibit_entry;
	struct rt6_info *ip6_blk_hole_entry;
	struct fib6_table *fib6_local_tbl;
	struct fib_rules_ops *fib6_rules_ops;
	struct sock *ndisc_sk;
	struct sock *tcp_sk;
	struct sock *igmp_sk;
	struct sock *mc_autojoin_sk;
	struct hlist_head *inet6_addr_lst;
	spinlock_t addrconf_hash_lock;
	struct delayed_work addr_chk_work;
	struct list_head mr6_tables;
	struct fib_rules_ops *mr6_rules_ops;
	atomic_t dev_addr_genid;
	atomic_t fib6_sernum;
	struct seg6_pernet_data *seg6_data;
	struct fib_notifier_ops *notifier_ops;
	struct fib_notifier_ops *ip6mr_notifier_ops;
	unsigned int ipmr_seq;
	struct {
		struct hlist_head head;
		spinlock_t lock;
		u32 seq;
	} ip6addrlbl_table;
	struct ioam6_pernet_data *ioam6_data;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct netns_sysctl_lowpan {
	struct ctl_table_header *frags_hdr;
};

struct netns_ieee802154_lowpan {
	struct netns_sysctl_lowpan sysctl;
	struct fqdir *fqdir;
};

struct sctp_mib;

struct netns_sctp {
	struct sctp_mib *sctp_statistics;
	struct proc_dir_entry *proc_net_sctp;
	struct ctl_table_header *sysctl_header;
	struct sock *ctl_sock;
	struct sock *udp4_sock;
	struct sock *udp6_sock;
	int udp_port;
	int encap_port;
	struct list_head local_addr_list;
	struct list_head addr_waitq;
	struct timer_list addr_wq_timer;
	struct list_head auto_asconf_splist;
	spinlock_t addr_wq_lock;
	spinlock_t local_addr_lock;
	unsigned int rto_initial;
	unsigned int rto_min;
	unsigned int rto_max;
	int rto_alpha;
	int rto_beta;
	int max_burst;
	int cookie_preserve_enable;
	char *sctp_hmac_alg;
	unsigned int valid_cookie_life;
	unsigned int sack_timeout;
	unsigned int hb_interval;
	unsigned int probe_interval;
	int max_retrans_association;
	int max_retrans_path;
	int max_retrans_init;
	int pf_retrans;
	int ps_retrans;
	int pf_enable;
	int pf_expose;
	int sndbuf_policy;
	int rcvbuf_policy;
	int default_auto_asconf;
	int addip_enable;
	int addip_noauth;
	int prsctp_enable;
	int reconf_enable;
	int auth_enable;
	int intl_enable;
	int ecn_enable;
	int scope_policy;
	int rwnd_upd_shift;
	long unsigned int max_autoclose;
	int l3mdev_accept;
};

struct nf_logger;

struct nf_hook_entries;

struct netns_nf {
	struct proc_dir_entry *proc_netfilter;
	const struct nf_logger *nf_loggers[11];
	struct ctl_table_header *nf_log_dir_header;
	struct ctl_table_header *nf_lwtnl_dir_header;
	struct nf_hook_entries *hooks_ipv4[5];
	struct nf_hook_entries *hooks_ipv6[5];
	struct nf_hook_entries *hooks_arp[3];
	struct nf_hook_entries *hooks_bridge[5];
	unsigned int defrag_ipv4_users;
	unsigned int defrag_ipv6_users;
};

struct nf_generic_net {
	unsigned int timeout;
};

struct nf_tcp_net {
	unsigned int timeouts[14];
	u8 tcp_loose;
	u8 tcp_be_liberal;
	u8 tcp_max_retrans;
	u8 tcp_ignore_invalid_rst;
	unsigned int offload_timeout;
};

struct nf_udp_net {
	unsigned int timeouts[2];
	unsigned int offload_timeout;
};

struct nf_icmp_net {
	unsigned int timeout;
};

struct nf_dccp_net {
	u8 dccp_loose;
	unsigned int dccp_timeout[10];
};

struct nf_sctp_net {
	unsigned int timeouts[10];
};

struct nf_gre_net {
	struct list_head keymap_list;
	unsigned int timeouts[2];
};

struct nf_ip_net {
	struct nf_generic_net generic;
	struct nf_tcp_net tcp;
	struct nf_udp_net udp;
	struct nf_icmp_net icmp;
	struct nf_icmp_net icmpv6;
	struct nf_dccp_net dccp;
	struct nf_sctp_net sctp;
	struct nf_gre_net gre;
};

struct ip_conntrack_stat;

struct nf_ct_event_notifier;

struct netns_ct {
	bool ecache_dwork_pending;
	u8 sysctl_log_invalid;
	u8 sysctl_events;
	u8 sysctl_acct;
	u8 sysctl_tstamp;
	u8 sysctl_checksum;
	struct ip_conntrack_stat *stat;
	struct nf_ct_event_notifier *nf_conntrack_event_cb;
	struct nf_ip_net nf_ct_proto;
	atomic_t labels_used;
};

struct netns_nftables {
	u8 gencursor;
};

struct nf_flow_table_stat;

struct netns_ft {
	struct nf_flow_table_stat *stat;
};

struct netns_bpf {
	struct bpf_prog_array *run_array[2];
	struct bpf_prog *progs[2];
	struct list_head links[2];
};

struct xfrm_policy_hash {
	struct hlist_head *table;
	unsigned int hmask;
	u8 dbits4;
	u8 sbits4;
	u8 dbits6;
	u8 sbits6;
};

struct xfrm_policy_hthresh {
	struct work_struct work;
	seqlock_t lock;
	u8 lbits4;
	u8 rbits4;
	u8 lbits6;
	u8 rbits6;
};

struct netns_xfrm {
	struct list_head state_all;
	struct hlist_head *state_bydst;
	struct hlist_head *state_bysrc;
	struct hlist_head *state_byspi;
	struct hlist_head *state_byseq;
	unsigned int state_hmask;
	unsigned int state_num;
	struct work_struct state_hash_work;
	struct list_head policy_all;
	struct hlist_head *policy_byidx;
	unsigned int policy_idx_hmask;
	unsigned int idx_generator;
	struct hlist_head policy_inexact[3];
	struct xfrm_policy_hash policy_bydst[3];
	unsigned int policy_count[6];
	struct work_struct policy_hash_work;
	struct xfrm_policy_hthresh policy_hthresh;
	struct list_head inexact_bins;
	struct sock *nlsk;
	struct sock *nlsk_stash;
	u32 sysctl_aevent_etime;
	u32 sysctl_aevent_rseqth;
	int sysctl_larval_drop;
	u32 sysctl_acq_expires;
	u8 policy_default[3];
	struct ctl_table_header *sysctl_hdr;
	long: 64;
	long: 64;
	long: 64;
	struct dst_ops xfrm4_dst_ops;
	struct dst_ops xfrm6_dst_ops;
	spinlock_t xfrm_state_lock;
	seqcount_spinlock_t xfrm_state_hash_generation;
	seqcount_spinlock_t xfrm_policy_hash_generation;
	spinlock_t xfrm_policy_lock;
	struct mutex xfrm_cfg_mutex;
	long: 64;
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

struct netns_ipvs;

struct mpls_route;

struct netns_mpls {
	int ip_ttl_propagate;
	int default_ttl;
	size_t platform_labels;
	struct mpls_route **platform_label;
	struct ctl_table_header *ctl;
};

struct can_dev_rcv_lists;

struct can_pkg_stats;

struct can_rcv_lists_stats;

struct netns_can {
	struct proc_dir_entry *proc_dir;
	struct proc_dir_entry *pde_stats;
	struct proc_dir_entry *pde_reset_stats;
	struct proc_dir_entry *pde_rcvlist_all;
	struct proc_dir_entry *pde_rcvlist_fil;
	struct proc_dir_entry *pde_rcvlist_inv;
	struct proc_dir_entry *pde_rcvlist_sff;
	struct proc_dir_entry *pde_rcvlist_eff;
	struct proc_dir_entry *pde_rcvlist_err;
	struct proc_dir_entry *bcmproc_dir;
	struct can_dev_rcv_lists *rx_alldev_list;
	spinlock_t rcvlists_lock;
	struct timer_list stattimer;
	struct can_pkg_stats *pkg_stats;
	struct can_rcv_lists_stats *rcv_lists_stats;
	struct hlist_head cgw_list;
};

struct netns_xdp {
	struct mutex lock;
	struct hlist_head list;
};

struct smc_stats;

struct smc_stats_rsn;

struct netns_smc {
	struct smc_stats *smc_stats;
	struct mutex mutex_fback_rsn;
	struct smc_stats_rsn *fback_rsn;
	bool limit_smc_hs;
	struct ctl_table_header *smc_hdr;
	unsigned int sysctl_autocorking_size;
	unsigned int sysctl_smcr_buf_type;
	int sysctl_smcr_testlink_time;
	int sysctl_wmem;
	int sysctl_rmem;
	int sysctl_max_links_per_lgr;
	int sysctl_max_conns_per_lgr;
};

struct uevent_sock;

struct net_generic;

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
	struct key_tag *key_domain;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct ref_tracker_dir notrefcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
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
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_ipv4 ipv4;
	struct netns_ipv6 ipv6;
	struct netns_ieee802154_lowpan ieee802154_lowpan;
	struct netns_sctp sctp;
	struct netns_nf nf;
	struct netns_ct ct;
	struct netns_nftables nft;
	struct netns_ft ft;
	struct sk_buff_head wext_nlevents;
	struct net_generic *gen;
	struct netns_bpf bpf;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netns_xfrm xfrm;
	u64 net_cookie;
	struct netns_ipvs *ipvs;
	struct netns_mpls mpls;
	struct netns_can can;
	struct netns_xdp xdp;
	struct sock *crypto_nlsk;
	struct sock *diag_nlsk;
	struct netns_smc smc;
	long: 64;
	long: 64;
	long: 64;
};

typedef struct {
	local64_t v;
} u64_stats_t;

enum cgroup_bpf_attach_type {
	CGROUP_BPF_ATTACH_TYPE_INVALID = -1,
	CGROUP_INET_INGRESS = 0,
	CGROUP_INET_EGRESS = 1,
	CGROUP_INET_SOCK_CREATE = 2,
	CGROUP_SOCK_OPS = 3,
	CGROUP_DEVICE = 4,
	CGROUP_INET4_BIND = 5,
	CGROUP_INET6_BIND = 6,
	CGROUP_INET4_CONNECT = 7,
	CGROUP_INET6_CONNECT = 8,
	CGROUP_UNIX_CONNECT = 9,
	CGROUP_INET4_POST_BIND = 10,
	CGROUP_INET6_POST_BIND = 11,
	CGROUP_UDP4_SENDMSG = 12,
	CGROUP_UDP6_SENDMSG = 13,
	CGROUP_UNIX_SENDMSG = 14,
	CGROUP_SYSCTL = 15,
	CGROUP_UDP4_RECVMSG = 16,
	CGROUP_UDP6_RECVMSG = 17,
	CGROUP_UNIX_RECVMSG = 18,
	CGROUP_GETSOCKOPT = 19,
	CGROUP_SETSOCKOPT = 20,
	CGROUP_INET4_GETPEERNAME = 21,
	CGROUP_INET6_GETPEERNAME = 22,
	CGROUP_UNIX_GETPEERNAME = 23,
	CGROUP_INET4_GETSOCKNAME = 24,
	CGROUP_INET6_GETSOCKNAME = 25,
	CGROUP_UNIX_GETSOCKNAME = 26,
	CGROUP_INET_SOCK_RELEASE = 27,
	CGROUP_LSM_START = 28,
	CGROUP_LSM_END = 37,
	MAX_CGROUP_BPF_ATTACH_TYPE = 38,
};

struct bpf_offloaded_map;

struct bpf_map_dev_ops {
	int (*map_get_next_key)(struct bpf_offloaded_map *, void *, void *);
	int (*map_lookup_elem)(struct bpf_offloaded_map *, void *, void *);
	int (*map_update_elem)(struct bpf_offloaded_map *, void *, void *, u64);
	int (*map_delete_elem)(struct bpf_offloaded_map *, void *);
};

struct bpf_offloaded_map {
	struct bpf_map map;
	struct net_device *netdev;
	const struct bpf_map_dev_ops *dev_ops;
	void *dev_priv;
	struct list_head offloads;
};

struct netdev_tc_txq {
	u16 count;
	u16 offset;
};

enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER = 1,
	RX_HANDLER_EXACT = 2,
	RX_HANDLER_PASS = 3,
};

typedef enum rx_handler_result rx_handler_result_t;

typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **);

typedef u32 xdp_features_t;

struct net_device_stats {
	union {
		long unsigned int rx_packets;
		atomic_long_t __rx_packets;
	};
	union {
		long unsigned int tx_packets;
		atomic_long_t __tx_packets;
	};
	union {
		long unsigned int rx_bytes;
		atomic_long_t __rx_bytes;
	};
	union {
		long unsigned int tx_bytes;
		atomic_long_t __tx_bytes;
	};
	union {
		long unsigned int rx_errors;
		atomic_long_t __rx_errors;
	};
	union {
		long unsigned int tx_errors;
		atomic_long_t __tx_errors;
	};
	union {
		long unsigned int rx_dropped;
		atomic_long_t __rx_dropped;
	};
	union {
		long unsigned int tx_dropped;
		atomic_long_t __tx_dropped;
	};
	union {
		long unsigned int multicast;
		atomic_long_t __multicast;
	};
	union {
		long unsigned int collisions;
		atomic_long_t __collisions;
	};
	union {
		long unsigned int rx_length_errors;
		atomic_long_t __rx_length_errors;
	};
	union {
		long unsigned int rx_over_errors;
		atomic_long_t __rx_over_errors;
	};
	union {
		long unsigned int rx_crc_errors;
		atomic_long_t __rx_crc_errors;
	};
	union {
		long unsigned int rx_frame_errors;
		atomic_long_t __rx_frame_errors;
	};
	union {
		long unsigned int rx_fifo_errors;
		atomic_long_t __rx_fifo_errors;
	};
	union {
		long unsigned int rx_missed_errors;
		atomic_long_t __rx_missed_errors;
	};
	union {
		long unsigned int tx_aborted_errors;
		atomic_long_t __tx_aborted_errors;
	};
	union {
		long unsigned int tx_carrier_errors;
		atomic_long_t __tx_carrier_errors;
	};
	union {
		long unsigned int tx_fifo_errors;
		atomic_long_t __tx_fifo_errors;
	};
	union {
		long unsigned int tx_heartbeat_errors;
		atomic_long_t __tx_heartbeat_errors;
	};
	union {
		long unsigned int tx_window_errors;
		atomic_long_t __tx_window_errors;
	};
	union {
		long unsigned int rx_compressed;
		atomic_long_t __rx_compressed;
	};
	union {
		long unsigned int tx_compressed;
		atomic_long_t __tx_compressed;
	};
};

struct netdev_hw_addr_list {
	struct list_head list;
	int count;
	struct rb_root tree;
};

struct tipc_bearer;

struct mpls_dev;

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

struct garp_port;

struct mrp_port;

struct dm_hw_stat_delta;

struct udp_tunnel_nic;

struct bpf_xdp_link;

struct bpf_xdp_entity {
	struct bpf_prog *prog;
	struct bpf_xdp_link *link;
};

typedef struct {} netdevice_tracker;

struct net_device_ops;

struct header_ops;

struct netdev_queue;

struct xps_dev_maps;

struct bpf_mprog_entry;

struct pcpu_lstats;

struct pcpu_sw_netstats;

struct pcpu_dstats;

struct inet6_dev;

struct netdev_rx_queue;

struct netpoll_info;

struct netdev_name_node;

struct dev_ifalias;

struct xdp_metadata_ops;

struct xsk_tx_metadata_ops;

struct net_device_core_stats;

struct iw_handler_def;

struct iw_public_data;

struct ethtool_ops;

struct l3mdev_ops;

struct ndisc_ops;

struct xfrmdev_ops;

struct tlsdev_ops;

struct in_device;

struct vlan_info;

struct wireless_dev;

struct wpan_dev;

struct cpu_rmap;

struct Qdisc;

struct xdp_dev_bulk_queue;

struct rtnl_link_ops;

struct netdev_stat_ops;

struct dcbnl_rtnl_ops;

struct netprio_map;

struct phy_device;

struct sfp_bus;

struct macsec_ops;

struct udp_tunnel_nic_info;

struct rtnl_hw_stats64;

struct devlink_port;

struct dpll_pin;

struct net_device {
	__u8 __cacheline_group_begin__net_device_read_tx[0];
	long long unsigned int priv_flags;
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
	short unsigned int needed_headroom;
	struct netdev_tc_txq tc_to_txq[16];
	struct xps_dev_maps *xps_maps[2];
	struct nf_hook_entries *nf_hooks_egress;
	struct bpf_mprog_entry *tcx_egress;
	__u8 __cacheline_group_end__net_device_read_tx[0];
	__u8 __cacheline_group_begin__net_device_read_txrx[0];
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	long unsigned int state;
	unsigned int flags;
	short unsigned int hard_header_len;
	netdev_features_t features;
	struct inet6_dev *ip6_ptr;
	__u8 __cacheline_group_end__net_device_read_txrx[0];
	__u8 __cacheline_group_begin__net_device_read_rx[0];
	struct bpf_prog *xdp_prog;
	struct list_head ptype_specific;
	int ifindex;
	unsigned int real_num_rx_queues;
	struct netdev_rx_queue *_rx;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	unsigned int gro_ipv4_max_size;
	rx_handler_func_t *rx_handler;
	void *rx_handler_data;
	possible_net_t nd_net;
	struct netpoll_info *npinfo;
	struct bpf_mprog_entry *tcx_ingress;
	__u8 __cacheline_group_end__net_device_read_rx[0];
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
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
	short unsigned int gflags;
	short unsigned int needed_tailroom;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct iw_handler_def *wireless_handlers;
	struct iw_public_data *wireless_data;
	const struct ethtool_ops *ethtool_ops;
	const struct l3mdev_ops *l3mdev_ops;
	const struct ndisc_ops *ndisc_ops;
	const struct xfrmdev_ops *xfrmdev_ops;
	const struct tlsdev_ops *tlsdev_ops;
	unsigned int operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct vlan_info *vlan_info;
	struct tipc_bearer *tipc_ptr;
	void *atalk_ptr;
	void *ax25_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	struct mpls_dev *mpls_ptr;
	const unsigned char *dev_addr;
	unsigned int num_rx_queues;
	unsigned int xdp_zc_max_segs;
	struct netdev_queue *ingress_queue;
	struct nf_hook_entries *nf_hooks_ingress;
	unsigned char broadcast[32];
	struct cpu_rmap *rx_cpu_rmap;
	struct hlist_node index_hlist;
	unsigned int num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct hlist_head qdisc_hash[16];
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	int *pcpu_refcnt;
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
	struct garp_port *garp_port;
	struct mrp_port *mrp_port;
	struct dm_hw_stat_delta *dm_private;
	struct device dev;
	const struct attribute_group *sysfs_groups[4];
	const struct attribute_group *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	const struct netdev_stat_ops *stat_ops;
	unsigned int tso_max_size;
	u16 tso_max_segs;
	const struct dcbnl_rtnl_ops *dcbnl_ops;
	u8 prio_tc_map[16];
	unsigned int fcoe_ddp_xid;
	struct netprio_map *priomap;
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct macsec_ops *macsec_ops;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	struct devlink_port *devlink_port;
	struct dpll_pin *dpll_pin;
	struct hlist_head page_pools;
};

enum bpf_cgroup_storage_type {
	BPF_CGROUP_STORAGE_SHARED = 0,
	BPF_CGROUP_STORAGE_PERCPU = 1,
	__BPF_CGROUP_STORAGE_MAX = 2,
};

struct bpf_storage_buffer;

struct bpf_cgroup_storage_map;

struct bpf_cgroup_storage {
	union {
		struct bpf_storage_buffer *buf;
		void *percpu_buf;
	};
	struct bpf_cgroup_storage_map *map;
	struct bpf_cgroup_storage_key key;
	struct list_head list_map;
	struct list_head list_cg;
	struct rb_node node;
	struct callback_head rcu;
};

typedef unsigned int sk_buff_data_t;

struct skb_ext;

struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				struct net_device *dev;
				long unsigned int dev_scratch;
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
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	long unsigned int _nfct;
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
	__u8 active_extensions;
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
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 nf_trace: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u16 tc_index;
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
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32 secmark;
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
			__u8 tc_at_ingress: 1;
			__u8 tc_skip_classify: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 ndisc_nodetype: 2;
			__u8 ipvs_property: 1;
			__u8 nf_trace: 1;
			__u8 offload_fwd_mark: 1;
			__u8 offload_l3_fwd_mark: 1;
			__u8 redirected: 1;
			__u8 from_ingress: 1;
			__u8 nf_skip_egress: 1;
			__u8 decrypted: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			__u16 tc_index;
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
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			__u32 secmark;
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
	struct skb_ext *extensions;
};

struct dql {
	unsigned int num_queued;
	unsigned int adj_limit;
	unsigned int last_obj_cnt;
	long unsigned int history_head;
	long unsigned int history[4];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	unsigned int limit;
	unsigned int num_completed;
	unsigned int prev_ovlimit;
	unsigned int prev_num_queued;
	unsigned int prev_last_obj_cnt;
	unsigned int lowest_slack;
	long unsigned int slack_start_time;
	unsigned int max_limit;
	unsigned int min_limit;
	unsigned int slack_hold_time;
	short unsigned int stall_thrs;
	short unsigned int stall_max;
	long unsigned int last_reap;
	long unsigned int stall_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct flowi_tunnel {
	__be64 tun_id;
};

struct flowi_common {
	int flowic_oif;
	int flowic_iif;
	int flowic_l3mdev;
	__u32 flowic_mark;
	__u8 flowic_tos;
	__u8 flowic_scope;
	__u8 flowic_proto;
	__u8 flowic_flags;
	__u32 flowic_secid;
	kuid_t flowic_uid;
	__u32 flowic_multipath_hash;
	struct flowi_tunnel flowic_tun_key;
};

union flowi_uli {
	struct {
		__be16 dport;
		__be16 sport;
	} ports;
	struct {
		__u8 type;
		__u8 code;
	} icmpt;
	__be32 gre_key;
	struct {
		__u8 type;
	} mht;
};

struct flowi4 {
	struct flowi_common __fl_common;
	__be32 saddr;
	__be32 daddr;
	union flowi_uli uli;
};

struct flowi6 {
	struct flowi_common __fl_common;
	struct in6_addr daddr;
	struct in6_addr saddr;
	__be32 flowlabel;
	union flowi_uli uli;
	__u32 mp_hash;
};

struct flowi {
	union {
		struct flowi_common __fl_common;
		struct flowi4 ip4;
		struct flowi6 ip6;
	} u;
};

struct prot_inuse {
	int all;
	int val[64];
};

struct ipstats_mib {
	u64 mibs[38];
	struct u64_stats_sync syncp;
};

struct icmp_mib {
	long unsigned int mibs[30];
};

struct icmpmsg_mib {
	atomic_long_t mibs[512];
};

struct icmpv6_mib {
	long unsigned int mibs[7];
};

struct icmpv6msg_mib {
	atomic_long_t mibs[512];
};

struct tcp_mib {
	long unsigned int mibs[16];
};

struct udp_mib {
	long unsigned int mibs[10];
};

struct linux_mib {
	long unsigned int mibs[132];
};

struct linux_xfrm_mib {
	long unsigned int mibs[29];
};

struct linux_tls_mib {
	long unsigned int mibs[13];
};

struct rhashtable;

struct rhashtable_compare_arg {
	struct rhashtable *ht;
	const void *key;
};

typedef u32 (*rht_hashfn_t)(const void *, u32, u32);

typedef u32 (*rht_obj_hashfn_t)(const void *, u32, u32);

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
	struct bucket_table *tbl;
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
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags *f;
	struct net *net;
	bool dead;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct rhashtable rhashtable;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 64;
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

struct fib_rule;

struct fib_lookup_arg;

struct fib_rule_hdr;

struct nlattr;

struct netlink_ext_ack;

struct fib_rules_ops {
	int family;
	struct list_head list;
	int rule_size;
	int addr_size;
	int unresolved_rules;
	int nr_goto_rules;
	unsigned int fib_rules_seq;
	int (*action)(struct fib_rule *, struct flowi *, int, struct fib_lookup_arg *);
	bool (*suppress)(struct fib_rule *, int, struct fib_lookup_arg *);
	int (*match)(struct fib_rule *, struct flowi *, int);
	int (*configure)(struct fib_rule *, struct sk_buff *, struct fib_rule_hdr *, struct nlattr **, struct netlink_ext_ack *);
	int (*delete)(struct fib_rule *);
	int (*compare)(struct fib_rule *, struct fib_rule_hdr *, struct nlattr **);
	int (*fill)(struct fib_rule *, struct sk_buff *, struct fib_rule_hdr *);
	size_t (*nlmsg_payload)(struct fib_rule *);
	void (*flush_cache)(struct fib_rules_ops *);
	int nlgroup;
	struct list_head rules_list;
	struct module *owner;
	struct net *fro_net;
	struct callback_head rcu;
};

enum tcp_ca_event {
	CA_EVENT_TX_START = 0,
	CA_EVENT_CWND_RESTART = 1,
	CA_EVENT_COMPLETE_CWR = 2,
	CA_EVENT_LOSS = 3,
	CA_EVENT_ECN_NO_CE = 4,
	CA_EVENT_ECN_IS_CE = 5,
};

struct ack_sample;

struct rate_sample;

union tcp_cc_info;

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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct fib_notifier_ops {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net *);
	int (*fib_dump)(struct net *, struct notifier_block *, struct netlink_ext_ack *);
	struct module *owner;
	struct callback_head rcu;
};

struct xfrm_state;

struct uncached_list;

struct lwtunnel_state;

struct dst_entry {
	struct net_device *dev;
	struct dst_ops *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	struct xfrm_state *xfrm;
	int (*input)(struct sk_buff *);
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	rcuref_t __rcuref;
	int __use;
	long unsigned int lastuse;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	netdevice_tracker dev_tracker;
	struct list_head rt_uncached;
	struct uncached_list *rt_uncached_list;
	struct lwtunnel_state *lwtstate;
};

struct hh_cache {
	unsigned int hh_len;
	seqlock_t hh_lock;
	long unsigned int hh_data[16];
};

struct neigh_table;

struct neigh_parms;

struct neigh_ops;

struct neighbour {
	struct neighbour *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	long: 0;
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

struct ubuf_info;

struct msghdr {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb *msg_iocb;
	struct ubuf_info *msg_ubuf;
	int (*sg_from_iter)(struct sock *, struct sk_buff *, struct iov_iter *, size_t);
};

struct ubuf_info {
	void (*callback)(struct sk_buff *, struct ubuf_info *, bool);
	refcount_t refcnt;
	u8 flags;
};

enum nf_log_type {
	NF_LOG_TYPE_LOG = 0,
	NF_LOG_TYPE_ULOG = 1,
	NF_LOG_TYPE_MAX = 2,
};

typedef u8 u_int8_t;

struct nf_loginfo;

typedef void nf_logfn(struct net *, u_int8_t, unsigned int, const struct sk_buff *, const struct net_device *, const struct net_device *, const struct nf_loginfo *, const char *);

struct nf_logger {
	char *name;
	enum nf_log_type type;
	nf_logfn *logfn;
	struct module *me;
};

struct ip_conntrack_stat {
	unsigned int found;
	unsigned int invalid;
	unsigned int insert;
	unsigned int insert_failed;
	unsigned int clash_resolve;
	unsigned int drop;
	unsigned int early_drop;
	unsigned int error;
	unsigned int expect_new;
	unsigned int expect_create;
	unsigned int expect_delete;
	unsigned int search_restart;
	unsigned int chaintoolong;
};

struct nf_flow_table_stat {
	unsigned int count_wq_add;
	unsigned int count_wq_del;
	unsigned int count_wq_stats;
};

struct skb_shared_hwtstamps {
	union {
		ktime_t hwtstamp;
		void *netdev_data;
	};
};

struct skb_ext {
	refcount_t refcnt;
	u8 offset[3];
	u8 chunks;
	char data[0];
};

struct ieee_ets {
	__u8 willing;
	__u8 ets_cap;
	__u8 cbs;
	__u8 tc_tx_bw[8];
	__u8 tc_rx_bw[8];
	__u8 tc_tsa[8];
	__u8 prio_tc[8];
	__u8 tc_reco_bw[8];
	__u8 tc_reco_tsa[8];
	__u8 reco_prio_tc[8];
};

struct ieee_maxrate {
	__u64 tc_maxrate[8];
};

struct ieee_qcn {
	__u8 rpg_enable[8];
	__u32 rppp_max_rps[8];
	__u32 rpg_time_reset[8];
	__u32 rpg_byte_reset[8];
	__u32 rpg_threshold[8];
	__u32 rpg_max_rate[8];
	__u32 rpg_ai_rate[8];
	__u32 rpg_hai_rate[8];
	__u32 rpg_gd[8];
	__u32 rpg_min_dec_fac[8];
	__u32 rpg_min_rate[8];
	__u32 cndd_state_machine[8];
};

struct ieee_qcn_stats {
	__u64 rppp_rp_centiseconds[8];
	__u32 rppp_created_rps[8];
};

struct ieee_pfc {
	__u8 pfc_cap;
	__u8 pfc_en;
	__u8 mbc;
	__u16 delay;
	__u64 requests[8];
	__u64 indications[8];
};

struct dcbnl_buffer {
	__u8 prio2buffer[8];
	__u32 buffer_size[8];
	__u32 total_size;
};

struct cee_pg {
	__u8 willing;
	__u8 error;
	__u8 pg_en;
	__u8 tcs_supported;
	__u8 pg_bw[8];
	__u8 prio_pg[8];
};

struct cee_pfc {
	__u8 willing;
	__u8 error;
	__u8 pfc_en;
	__u8 tcs_supported;
};

struct dcb_app {
	__u8 selector;
	__u8 priority;
	__u16 protocol;
};

struct dcb_peer_app_info {
	__u8 willing;
	__u8 error;
};

struct dcbnl_rtnl_ops {
	int (*ieee_getets)(struct net_device *, struct ieee_ets *);
	int (*ieee_setets)(struct net_device *, struct ieee_ets *);
	int (*ieee_getmaxrate)(struct net_device *, struct ieee_maxrate *);
	int (*ieee_setmaxrate)(struct net_device *, struct ieee_maxrate *);
	int (*ieee_getqcn)(struct net_device *, struct ieee_qcn *);
	int (*ieee_setqcn)(struct net_device *, struct ieee_qcn *);
	int (*ieee_getqcnstats)(struct net_device *, struct ieee_qcn_stats *);
	int (*ieee_getpfc)(struct net_device *, struct ieee_pfc *);
	int (*ieee_setpfc)(struct net_device *, struct ieee_pfc *);
	int (*ieee_getapp)(struct net_device *, struct dcb_app *);
	int (*ieee_setapp)(struct net_device *, struct dcb_app *);
	int (*ieee_delapp)(struct net_device *, struct dcb_app *);
	int (*ieee_peer_getets)(struct net_device *, struct ieee_ets *);
	int (*ieee_peer_getpfc)(struct net_device *, struct ieee_pfc *);
	u8 (*getstate)(struct net_device *);
	u8 (*setstate)(struct net_device *, u8);
	void (*getpermhwaddr)(struct net_device *, u8 *);
	void (*setpgtccfgtx)(struct net_device *, int, u8, u8, u8, u8);
	void (*setpgbwgcfgtx)(struct net_device *, int, u8);
	void (*setpgtccfgrx)(struct net_device *, int, u8, u8, u8, u8);
	void (*setpgbwgcfgrx)(struct net_device *, int, u8);
	void (*getpgtccfgtx)(struct net_device *, int, u8 *, u8 *, u8 *, u8 *);
	void (*getpgbwgcfgtx)(struct net_device *, int, u8 *);
	void (*getpgtccfgrx)(struct net_device *, int, u8 *, u8 *, u8 *, u8 *);
	void (*getpgbwgcfgrx)(struct net_device *, int, u8 *);
	void (*setpfccfg)(struct net_device *, int, u8);
	void (*getpfccfg)(struct net_device *, int, u8 *);
	u8 (*setall)(struct net_device *);
	u8 (*getcap)(struct net_device *, int, u8 *);
	int (*getnumtcs)(struct net_device *, int, u8 *);
	int (*setnumtcs)(struct net_device *, int, u8);
	u8 (*getpfcstate)(struct net_device *);
	void (*setpfcstate)(struct net_device *, u8);
	void (*getbcncfg)(struct net_device *, int, u32 *);
	void (*setbcncfg)(struct net_device *, int, u32);
	void (*getbcnrp)(struct net_device *, int, u8 *);
	void (*setbcnrp)(struct net_device *, int, u8);
	int (*setapp)(struct net_device *, u8, u16, u8);
	int (*getapp)(struct net_device *, u8, u16);
	u8 (*getfeatcfg)(struct net_device *, int, u8 *);
	u8 (*setfeatcfg)(struct net_device *, int, u8);
	u8 (*getdcbx)(struct net_device *);
	u8 (*setdcbx)(struct net_device *, u8);
	int (*peer_getappinfo)(struct net_device *, struct dcb_peer_app_info *, u16 *);
	int (*peer_getapptable)(struct net_device *, struct dcb_app *);
	int (*cee_peer_getpg)(struct net_device *, struct cee_pg *);
	int (*cee_peer_getpfc)(struct net_device *, struct cee_pfc *);
	int (*dcbnl_getbuffer)(struct net_device *, struct dcbnl_buffer *);
	int (*dcbnl_setbuffer)(struct net_device *, struct dcbnl_buffer *);
	int (*dcbnl_setapptrust)(struct net_device *, u8 *, int);
	int (*dcbnl_getapptrust)(struct net_device *, u8 *, int *);
	int (*dcbnl_setrewr)(struct net_device *, struct dcb_app *);
	int (*dcbnl_delrewr)(struct net_device *, struct dcb_app *);
};

struct netprio_map {
	struct callback_head rcu;
	u32 priomap_len;
	u32 priomap[0];
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
	long unsigned int flags;
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
};

struct proto_ops;

struct socket {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file *file;
	struct sock *sk;
	const struct proto_ops *ops;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq wq;
};

typedef struct {
	size_t written;
	size_t count;
	union {
		char *buf;
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
	int (*ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket *, void *, bool, bool);
	int (*listen)(struct socket *, int);
	int (*shutdown)(struct socket *, int);
	int (*setsockopt)(struct socket *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket *, int, int, char *, int *);
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

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
} sync_serial_settings;

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
	unsigned int slot_map;
} te1_settings;

typedef struct {
	short unsigned int encoding;
	short unsigned int parity;
} raw_hdlc_proto;

typedef struct {
	unsigned int t391;
	unsigned int t392;
	unsigned int n391;
	unsigned int n392;
	unsigned int n393;
	short unsigned int lmi;
	short unsigned int dce;
} fr_proto;

typedef struct {
	unsigned int dlci;
} fr_proto_pvc;

typedef struct {
	unsigned int dlci;
	char master[16];
} fr_proto_pvc_info;

typedef struct {
	unsigned int interval;
	unsigned int timeout;
} cisco_proto;

typedef struct {
	short unsigned int dce;
	unsigned int modulo;
	unsigned int window;
	unsigned int t1;
	unsigned int t2;
	unsigned int n2;
} x25_hdlc_proto;

struct ifmap {
	long unsigned int mem_start;
	long unsigned int mem_end;
	short unsigned int base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

struct if_settings {
	unsigned int type;
	unsigned int size;
	union {
		raw_hdlc_proto *raw_hdlc;
		cisco_proto *cisco;
		fr_proto *fr;
		fr_proto_pvc *fr_pvc;
		fr_proto_pvc_info *fr_pvc_info;
		x25_hdlc_proto *x25;
		sync_serial_settings *sync;
		te1_settings *te1;
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
		short int ifru_flags;
		int ifru_ivalue;
		int ifru_mtu;
		struct ifmap ifru_map;
		char ifru_slave[16];
		char ifru_newname[16];
		void *ifru_data;
		struct if_settings ifru_settings;
	} ifr_ifru;
};

struct nlmsghdr {
	__u32 nlmsg_len;
	__u16 nlmsg_type;
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

struct nlattr {
	__u16 nla_len;
	__u16 nla_type;
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
		long int args[6];
	};
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

struct ifla_vf_guid {
	__u32 vf;
	__u64 guid;
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

enum netdev_tx {
	__NETDEV_TX_MIN = -2147483648,
	NETDEV_TX_OK = 0,
	NETDEV_TX_BUSY = 16,
};

typedef enum netdev_tx netdev_tx_t;

struct net_device_core_stats {
	long unsigned int rx_dropped;
	long unsigned int tx_dropped;
	long unsigned int rx_nohandler;
	long unsigned int rx_otherhost_dropped;
};

struct header_ops {
	int (*create)(struct sk_buff *, struct net_device *, short unsigned int, const void *, const void *, unsigned int);
	int (*parse)(const struct sk_buff *, unsigned char *);
	int (*cache)(const struct neighbour *, struct hh_cache *, __be16);
	void (*cache_update)(struct hh_cache *, const struct net_device *, const unsigned char *);
	bool (*validate)(const char *, unsigned int);
	__be16 (*parse_protocol)(const struct sk_buff *);
};

struct gro_list {
	struct list_head list;
	int count;
};

struct napi_struct {
	struct list_head poll_list;
	long unsigned int state;
	int weight;
	int defer_hard_irqs_count;
	long unsigned int gro_bitmask;
	int (*poll)(struct napi_struct *, int);
	int poll_owner;
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

enum {
	NAPI_STATE_SCHED = 0,
	NAPI_STATE_MISSED = 1,
	NAPI_STATE_DISABLE = 2,
	NAPI_STATE_NPSVC = 3,
	NAPI_STATE_LISTED = 4,
	NAPI_STATE_NO_BUSY_POLL = 5,
	NAPI_STATE_IN_BUSY_POLL = 6,
	NAPI_STATE_PREFER_BUSY_POLL = 7,
	NAPI_STATE_THREADED = 8,
	NAPI_STATE_SCHED_THREADED = 9,
};

struct xsk_buff_pool;

struct netdev_queue {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct Qdisc *qdisc;
	struct Qdisc *qdisc_sleeping;
	struct kobject kobj;
	int numa_node;
	long unsigned int tx_maxrate;
	atomic_long_t trans_timeout;
	struct net_device *sb_dev;
	struct xsk_buff_pool *pool;
	struct napi_struct *napi;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t _xmit_lock;
	int xmit_lock_owner;
	long unsigned int trans_start;
	long unsigned int state;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct dql dql;
};

enum xps_map_type {
	XPS_CPUS = 0,
	XPS_RXQS = 1,
	XPS_MAPS_MAX = 2,
};

struct xps_map {
	unsigned int len;
	unsigned int alloc_len;
	struct callback_head rcu;
	u16 queues[0];
};

struct xps_dev_maps {
	struct callback_head rcu;
	unsigned int nr_ids;
	s16 num_tc;
	struct xps_map *attr_map[0];
};

struct netdev_fcoe_hbainfo {
	char manufacturer[64];
	char serial_number[64];
	char hardware_version[64];
	char driver_version[64];
	char optionrom_version[64];
	char firmware_version[64];
	char model[256];
	char model_description[256];
};

struct netdev_phys_item_id {
	unsigned char id[32];
	unsigned char id_len;
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

struct net_device_path_ctx {
	const struct net_device *dev;
	u8 daddr[6];
	int num_vlans;
	struct {
		u16 id;
		__be16 proto;
	} vlan[2];
};

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

enum bpf_netdev_command {
	XDP_SETUP_PROG = 0,
	XDP_SETUP_PROG_HW = 1,
	BPF_OFFLOAD_MAP_ALLOC = 2,
	BPF_OFFLOAD_MAP_FREE = 3,
	XDP_SETUP_XSK_POOL = 4,
};

enum bpf_xdp_mode {
	XDP_MODE_SKB = 0,
	XDP_MODE_DRV = 1,
	XDP_MODE_HW = 2,
	__MAX_XDP_MODE = 3,
};

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

struct xfrmdev_ops {
	int (*xdo_dev_state_add)(struct xfrm_state *, struct netlink_ext_ack *);
	void (*xdo_dev_state_delete)(struct xfrm_state *);
	void (*xdo_dev_state_free)(struct xfrm_state *);
	bool (*xdo_dev_offload_ok)(struct sk_buff *, struct xfrm_state *);
	void (*xdo_dev_state_advance_esn)(struct xfrm_state *);
	void (*xdo_dev_state_update_stats)(struct xfrm_state *);
	int (*xdo_dev_policy_add)(struct xfrm_policy *, struct netlink_ext_ack *);
	void (*xdo_dev_policy_delete)(struct xfrm_policy *);
	void (*xdo_dev_policy_free)(struct xfrm_policy *);
};

struct dev_ifalias {
	struct callback_head rcuhead;
	char ifalias[0];
};

struct xdp_frame;

struct xdp_buff;

struct ip_tunnel_parm;

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
	int (*ndo_siocdevprivate)(struct net_device *, struct ifreq *, void *, int);
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
	void (*ndo_poll_controller)(struct net_device *);
	int (*ndo_netpoll_setup)(struct net_device *, struct netpoll_info *);
	void (*ndo_netpoll_cleanup)(struct net_device *);
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
	int (*ndo_fcoe_enable)(struct net_device *);
	int (*ndo_fcoe_disable)(struct net_device *);
	int (*ndo_fcoe_ddp_setup)(struct net_device *, u16, struct scatterlist *, unsigned int);
	int (*ndo_fcoe_ddp_done)(struct net_device *, u16);
	int (*ndo_fcoe_ddp_target)(struct net_device *, u16, struct scatterlist *, unsigned int);
	int (*ndo_fcoe_get_hbainfo)(struct net_device *, struct netdev_fcoe_hbainfo *);
	int (*ndo_fcoe_get_wwn)(struct net_device *, u64 *, int);
	int (*ndo_rx_flow_steer)(struct net_device *, const struct sk_buff *, u16, u32);
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
	long unsigned int data_state[1];
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

struct xsk_tx_metadata_ops {
	void (*tmo_request_timestamp)(void *);
	u64 (*tmo_fill_timestamp)(void *);
	void (*tmo_request_checksum)(u16, u16, void *);
};

struct iw_request_info;

union iwreq_data;

typedef int (*iw_handler)(struct net_device *, struct iw_request_info *, union iwreq_data *, char *);

struct iw_priv_args;

struct iw_statistics;

struct iw_handler_def {
	const iw_handler *standard;
	__u16 num_standard;
	__u16 num_private;
	__u16 num_private_args;
	const iw_handler *private;
	const struct iw_priv_args *private_args;
	struct iw_statistics * (*get_wireless_stats)(struct net_device *);
};

enum ethtool_phys_id_state {
	ETHTOOL_ID_INACTIVE = 0,
	ETHTOOL_ID_ACTIVE = 1,
	ETHTOOL_ID_ON = 2,
	ETHTOOL_ID_OFF = 3,
};

struct ethtool_drvinfo;

struct ethtool_regs;

struct ethtool_wolinfo;

struct ethtool_link_ext_state_info;

struct ethtool_link_ext_stats;

struct ethtool_eeprom;

struct ethtool_coalesce;

struct kernel_ethtool_coalesce;

struct ethtool_ringparam;

struct kernel_ethtool_ringparam;

struct ethtool_pause_stats;

struct ethtool_pauseparam;

struct ethtool_test;

struct ethtool_stats;

struct ethtool_rxnfc;

struct ethtool_flash;

struct ethtool_rxfh_param;

struct ethtool_channels;

struct ethtool_dump;

struct ethtool_ts_info;

struct ethtool_modinfo;

struct ethtool_keee;

struct ethtool_tunable;

struct ethtool_link_ksettings;

struct ethtool_fec_stats;

struct ethtool_fecparam;

struct ethtool_module_eeprom;

struct ethtool_eth_phy_stats;

struct ethtool_eth_mac_stats;

struct ethtool_eth_ctrl_stats;

struct ethtool_rmon_stats;

struct ethtool_rmon_hist_range;

struct ethtool_module_power_mode_params;

struct ethtool_mm_state;

struct ethtool_mm_cfg;

struct ethtool_mm_stats;

struct ethtool_ops {
	u32 cap_link_lanes_supported: 1;
	u32 cap_rss_ctx_supported: 1;
	u32 cap_rss_sym_xor_supported: 1;
	u32 supported_coalesce_params;
	u32 supported_ring_params;
	void (*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
	int (*get_regs_len)(struct net_device *);
	void (*get_regs)(struct net_device *, struct ethtool_regs *, void *);
	void (*get_wol)(struct net_device *, struct ethtool_wolinfo *);
	int (*set_wol)(struct net_device *, struct ethtool_wolinfo *);
	u32 (*get_msglevel)(struct net_device *);
	void (*set_msglevel)(struct net_device *, u32);
	int (*nway_reset)(struct net_device *);
	u32 (*get_link)(struct net_device *);
	int (*get_link_ext_state)(struct net_device *, struct ethtool_link_ext_state_info *);
	void (*get_link_ext_stats)(struct net_device *, struct ethtool_link_ext_stats *);
	int (*get_eeprom_len)(struct net_device *);
	int (*get_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*set_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*get_coalesce)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *);
	int (*set_coalesce)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *);
	void (*get_ringparam)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	int (*set_ringparam)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	void (*get_pause_stats)(struct net_device *, struct ethtool_pause_stats *);
	void (*get_pauseparam)(struct net_device *, struct ethtool_pauseparam *);
	int (*set_pauseparam)(struct net_device *, struct ethtool_pauseparam *);
	void (*self_test)(struct net_device *, struct ethtool_test *, u64 *);
	void (*get_strings)(struct net_device *, u32, u8 *);
	int (*set_phys_id)(struct net_device *, enum ethtool_phys_id_state);
	void (*get_ethtool_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int (*begin)(struct net_device *);
	void (*complete)(struct net_device *);
	u32 (*get_priv_flags)(struct net_device *);
	int (*set_priv_flags)(struct net_device *, u32);
	int (*get_sset_count)(struct net_device *, int);
	int (*get_rxnfc)(struct net_device *, struct ethtool_rxnfc *, u32 *);
	int (*set_rxnfc)(struct net_device *, struct ethtool_rxnfc *);
	int (*flash_device)(struct net_device *, struct ethtool_flash *);
	int (*reset)(struct net_device *, u32 *);
	u32 (*get_rxfh_key_size)(struct net_device *);
	u32 (*get_rxfh_indir_size)(struct net_device *);
	int (*get_rxfh)(struct net_device *, struct ethtool_rxfh_param *);
	int (*set_rxfh)(struct net_device *, struct ethtool_rxfh_param *, struct netlink_ext_ack *);
	void (*get_channels)(struct net_device *, struct ethtool_channels *);
	int (*set_channels)(struct net_device *, struct ethtool_channels *);
	int (*get_dump_flag)(struct net_device *, struct ethtool_dump *);
	int (*get_dump_data)(struct net_device *, struct ethtool_dump *, void *);
	int (*set_dump)(struct net_device *, struct ethtool_dump *);
	int (*get_ts_info)(struct net_device *, struct ethtool_ts_info *);
	int (*get_module_info)(struct net_device *, struct ethtool_modinfo *);
	int (*get_module_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*get_eee)(struct net_device *, struct ethtool_keee *);
	int (*set_eee)(struct net_device *, struct ethtool_keee *);
	int (*get_tunable)(struct net_device *, const struct ethtool_tunable *, void *);
	int (*set_tunable)(struct net_device *, const struct ethtool_tunable *, const void *);
	int (*get_per_queue_coalesce)(struct net_device *, u32, struct ethtool_coalesce *);
	int (*set_per_queue_coalesce)(struct net_device *, u32, struct ethtool_coalesce *);
	int (*get_link_ksettings)(struct net_device *, struct ethtool_link_ksettings *);
	int (*set_link_ksettings)(struct net_device *, const struct ethtool_link_ksettings *);
	void (*get_fec_stats)(struct net_device *, struct ethtool_fec_stats *);
	int (*get_fecparam)(struct net_device *, struct ethtool_fecparam *);
	int (*set_fecparam)(struct net_device *, struct ethtool_fecparam *);
	void (*get_ethtool_phy_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int (*get_phy_tunable)(struct net_device *, const struct ethtool_tunable *, void *);
	int (*set_phy_tunable)(struct net_device *, const struct ethtool_tunable *, const void *);
	int (*get_module_eeprom_by_page)(struct net_device *, const struct ethtool_module_eeprom *, struct netlink_ext_ack *);
	void (*get_eth_phy_stats)(struct net_device *, struct ethtool_eth_phy_stats *);
	void (*get_eth_mac_stats)(struct net_device *, struct ethtool_eth_mac_stats *);
	void (*get_eth_ctrl_stats)(struct net_device *, struct ethtool_eth_ctrl_stats *);
	void (*get_rmon_stats)(struct net_device *, struct ethtool_rmon_stats *, const struct ethtool_rmon_hist_range **);
	int (*get_module_power_mode)(struct net_device *, struct ethtool_module_power_mode_params *, struct netlink_ext_ack *);
	int (*set_module_power_mode)(struct net_device *, const struct ethtool_module_power_mode_params *, struct netlink_ext_ack *);
	int (*get_mm)(struct net_device *, struct ethtool_mm_state *);
	int (*set_mm)(struct net_device *, struct ethtool_mm_cfg *, struct netlink_ext_ack *);
	void (*get_mm_stats)(struct net_device *, struct ethtool_mm_stats *);
};

struct l3mdev_ops {
	u32 (*l3mdev_fib_table)(const struct net_device *);
	struct sk_buff * (*l3mdev_l3_rcv)(struct net_device *, struct sk_buff *, u16);
	struct sk_buff * (*l3mdev_l3_out)(struct net_device *, struct sock *, struct sk_buff *, u16);
	struct dst_entry * (*l3mdev_link_scope_lookup)(const struct net_device *, struct flowi6 *);
};

struct nd_opt_hdr;

struct ndisc_options;

struct prefix_info;

struct ndisc_ops {
	int (*is_useropt)(u8);
	int (*parse_options)(const struct net_device *, struct nd_opt_hdr *, struct ndisc_options *);
	void (*update)(const struct net_device *, struct neighbour *, u32, u8, const struct ndisc_options *);
	int (*opt_addr_space)(const struct net_device *, u8, struct neighbour *, u8 *, u8 **);
	void (*fill_addr_option)(const struct net_device *, struct sk_buff *, u8, const u8 *);
	void (*prefix_rcv_add_addr)(struct net *, struct net_device *, const struct prefix_info *, struct inet6_dev *, struct in6_addr *, int, u32, bool, bool, __u32, u32, bool);
};

enum tls_offload_ctx_dir {
	TLS_OFFLOAD_CTX_DIR_RX = 0,
	TLS_OFFLOAD_CTX_DIR_TX = 1,
};

struct tls_crypto_info;

struct tls_context;

struct tlsdev_ops {
	int (*tls_dev_add)(struct net_device *, struct sock *, enum tls_offload_ctx_dir, struct tls_crypto_info *, u32);
	void (*tls_dev_del)(struct net_device *, struct tls_context *, enum tls_offload_ctx_dir);
	int (*tls_dev_resync)(struct net_device *, struct sock *, u32, u8 *, enum tls_offload_ctx_dir);
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

struct netdev_queue_stats_rx;

struct netdev_queue_stats_tx;

struct netdev_stat_ops {
	void (*get_queue_stats_rx)(struct net_device *, int, struct netdev_queue_stats_rx *);
	void (*get_queue_stats_tx)(struct net_device *, int, struct netdev_queue_stats_tx *);
	void (*get_base_stats)(struct net_device *, struct netdev_queue_stats_rx *, struct netdev_queue_stats_tx *);
};

struct macsec_context;

struct macsec_ops {
	int (*mdo_dev_open)(struct macsec_context *);
	int (*mdo_dev_stop)(struct macsec_context *);
	int (*mdo_add_secy)(struct macsec_context *);
	int (*mdo_upd_secy)(struct macsec_context *);
	int (*mdo_del_secy)(struct macsec_context *);
	int (*mdo_add_rxsc)(struct macsec_context *);
	int (*mdo_upd_rxsc)(struct macsec_context *);
	int (*mdo_del_rxsc)(struct macsec_context *);
	int (*mdo_add_rxsa)(struct macsec_context *);
	int (*mdo_upd_rxsa)(struct macsec_context *);
	int (*mdo_del_rxsa)(struct macsec_context *);
	int (*mdo_add_txsa)(struct macsec_context *);
	int (*mdo_upd_txsa)(struct macsec_context *);
	int (*mdo_del_txsa)(struct macsec_context *);
	int (*mdo_get_dev_stats)(struct macsec_context *);
	int (*mdo_get_tx_sc_stats)(struct macsec_context *);
	int (*mdo_get_tx_sa_stats)(struct macsec_context *);
	int (*mdo_get_rx_sc_stats)(struct macsec_context *);
	int (*mdo_get_rx_sa_stats)(struct macsec_context *);
	int (*mdo_insert_tx_tag)(struct phy_device *, struct sk_buff *);
	unsigned int needed_headroom;
	unsigned int needed_tailroom;
	bool rx_uses_md_dst;
};

struct udp_tunnel_nic_table_info {
	unsigned int n_entries;
	unsigned int tunnel_types;
};

struct udp_tunnel_info;

struct udp_tunnel_nic_shared;

struct udp_tunnel_nic_info {
	int (*set_port)(struct net_device *, unsigned int, unsigned int, struct udp_tunnel_info *);
	int (*unset_port)(struct net_device *, unsigned int, unsigned int, struct udp_tunnel_info *);
	int (*sync_table)(struct net_device *, unsigned int);
	struct udp_tunnel_nic_shared *shared;
	unsigned int flags;
	struct udp_tunnel_nic_table_info tables[4];
};

enum {
	NETIF_MSG_DRV_BIT = 0,
	NETIF_MSG_PROBE_BIT = 1,
	NETIF_MSG_LINK_BIT = 2,
	NETIF_MSG_TIMER_BIT = 3,
	NETIF_MSG_IFDOWN_BIT = 4,
	NETIF_MSG_IFUP_BIT = 5,
	NETIF_MSG_RX_ERR_BIT = 6,
	NETIF_MSG_TX_ERR_BIT = 7,
	NETIF_MSG_TX_QUEUED_BIT = 8,
	NETIF_MSG_INTR_BIT = 9,
	NETIF_MSG_TX_DONE_BIT = 10,
	NETIF_MSG_RX_STATUS_BIT = 11,
	NETIF_MSG_PKTDATA_BIT = 12,
	NETIF_MSG_HW_BIT = 13,
	NETIF_MSG_WOL_BIT = 14,
	NETIF_MSG_CLASS_COUNT = 15,
};

enum {
	RTAX_UNSPEC = 0,
	RTAX_LOCK = 1,
	RTAX_MTU = 2,
	RTAX_WINDOW = 3,
	RTAX_RTT = 4,
	RTAX_RTTVAR = 5,
	RTAX_SSTHRESH = 6,
	RTAX_CWND = 7,
	RTAX_ADVMSS = 8,
	RTAX_REORDERING = 9,
	RTAX_HOPLIMIT = 10,
	RTAX_INITCWND = 11,
	RTAX_FEATURES = 12,
	RTAX_RTO_MIN = 13,
	RTAX_INITRWND = 14,
	RTAX_QUICKACK = 15,
	RTAX_CC_ALGO = 16,
	RTAX_FASTOPEN_NO_COOKIE = 17,
	__RTAX_MAX = 18,
};

struct netlink_range_validation {
	u64 min;
	u64 max;
};

struct netlink_range_validation_signed {
	s64 min;
	s64 max;
};

enum {
	NEIGH_VAR_MCAST_PROBES = 0,
	NEIGH_VAR_UCAST_PROBES = 1,
	NEIGH_VAR_APP_PROBES = 2,
	NEIGH_VAR_MCAST_REPROBES = 3,
	NEIGH_VAR_RETRANS_TIME = 4,
	NEIGH_VAR_BASE_REACHABLE_TIME = 5,
	NEIGH_VAR_DELAY_PROBE_TIME = 6,
	NEIGH_VAR_INTERVAL_PROBE_TIME_MS = 7,
	NEIGH_VAR_GC_STALETIME = 8,
	NEIGH_VAR_QUEUE_LEN_BYTES = 9,
	NEIGH_VAR_PROXY_QLEN = 10,
	NEIGH_VAR_ANYCAST_DELAY = 11,
	NEIGH_VAR_PROXY_DELAY = 12,
	NEIGH_VAR_LOCKTIME = 13,
	NEIGH_VAR_QUEUE_LEN = 14,
	NEIGH_VAR_RETRANS_TIME_MS = 15,
	NEIGH_VAR_BASE_REACHABLE_TIME_MS = 16,
	NEIGH_VAR_GC_INTERVAL = 17,
	NEIGH_VAR_GC_THRESH1 = 18,
	NEIGH_VAR_GC_THRESH2 = 19,
	NEIGH_VAR_GC_THRESH3 = 20,
	NEIGH_VAR_MAX = 21,
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
	long unsigned int last_flush;
	struct delayed_work gc_work;
	struct delayed_work managed_work;
	struct timer_list proxy_timer;
	struct sk_buff_head proxy_queue;
	atomic_t entries;
	atomic_t gc_entries;
	struct list_head gc_list;
	struct list_head managed_list;
	rwlock_t lock;
	long unsigned int last_rand;
	struct neigh_statistics *stats;
	struct neigh_hash_table *nht;
	struct pneigh_entry **phash_buckets;
};

struct neigh_statistics {
	long unsigned int allocs;
	long unsigned int destroys;
	long unsigned int hash_grows;
	long unsigned int res_failed;
	long unsigned int lookups;
	long unsigned int hits;
	long unsigned int rcv_probes_mcast;
	long unsigned int rcv_probes_ucast;
	long unsigned int periodic_gc_runs;
	long unsigned int forced_gc_runs;
	long unsigned int unres_discards;
	long unsigned int table_fulls;
};

struct neigh_ops {
	int family;
	void (*solicit)(struct neighbour *, struct sk_buff *);
	void (*error_report)(struct neighbour *, struct sk_buff *);
	int (*output)(struct neighbour *, struct sk_buff *);
	int (*connected_output)(struct neighbour *, struct sk_buff *);
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

struct neigh_hash_table {
	struct neighbour **hash_buckets;
	unsigned int hash_shift;
	__u32 hash_rnd[4];
	struct callback_head rcu;
};

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_BOUND_INACTIVE = 13,
	TCP_MAX_STATES = 14,
};

struct fib_rule_hdr {
	__u8 family;
	__u8 dst_len;
	__u8 src_len;
	__u8 tos;
	__u8 table;
	__u8 res1;
	__u8 res2;
	__u8 action;
	__u32 flags;
};

struct fib_rule_port_range {
	__u16 start;
	__u16 end;
};

struct fib_kuid_range {
	kuid_t start;
	kuid_t end;
};

struct fib_rule {
	struct list_head list;
	int iifindex;
	int oifindex;
	u32 mark;
	u32 mark_mask;
	u32 flags;
	u32 table;
	u8 action;
	u8 l3mdev;
	u8 proto;
	u8 ip_proto;
	u32 target;
	__be64 tun_id;
	struct fib_rule *ctarget;
	struct net *fr_net;
	refcount_t refcnt;
	u32 pref;
	int suppress_ifgroup;
	int suppress_prefixlen;
	char iifname[16];
	char oifname[16];
	struct fib_kuid_range uid_range;
	struct fib_rule_port_range sport_range;
	struct fib_rule_port_range dport_range;
	struct callback_head rcu;
};

struct fib_lookup_arg {
	void *lookup_ptr;
	const void *lookup_data;
	void *result;
	struct fib_rule *rule;
	u32 table;
	int flags;
};

struct smc_hashinfo;

struct sk_psock;

struct request_sock_ops;

struct timewait_sock_ops;

struct raw_hashinfo;

struct proto {
	void (*close)(struct sock *, long int);
	int (*pre_connect)(struct sock *, struct sockaddr *, int);
	int (*connect)(struct sock *, struct sockaddr *, int);
	int (*disconnect)(struct sock *, int);
	struct sock * (*accept)(struct sock *, int, int *, bool);
	int (*ioctl)(struct sock *, int, int *);
	int (*init)(struct sock *);
	void (*destroy)(struct sock *);
	void (*shutdown)(struct sock *, int);
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*keepalive)(struct sock *, int);
	int (*compat_ioctl)(struct sock *, unsigned int, long unsigned int);
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
	int (*get_port)(struct sock *, short unsigned int);
	void (*put_port)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	unsigned int inuse_idx;
	int (*forward_alloc_get)(const struct sock *);
	bool (*stream_memory_free)(const struct sock *, int);
	bool (*sock_is_readable)(struct sock *);
	void (*enter_memory_pressure)(struct sock *);
	void (*leave_memory_pressure)(struct sock *);
	atomic_long_t *memory_allocated;
	int *per_cpu_fw_alloc;
	struct percpu_counter *sockets_allocated;
	long unsigned int *memory_pressure;
	long int *sysctl_mem;
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
	unsigned int *orphan_count;
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

struct bpf_storage_buffer {
	struct callback_head rcu;
	char data[0];
};

struct ring_buffer_event {
	u32 type_len: 5;
	u32 time_delta: 27;
	u32 array[0];
};

struct trace_event_buffer {
	struct trace_buffer *buffer;
	struct ring_buffer_event *event;
	struct trace_event_file *trace_file;
	void *entry;
	unsigned int trace_ctx;
	struct pt_regs *regs;
};

enum {
	TRACE_EVENT_FL_FILTERED = 1,
	TRACE_EVENT_FL_CAP_ANY = 2,
	TRACE_EVENT_FL_NO_SET_FILTER = 4,
	TRACE_EVENT_FL_IGNORE_ENABLE = 8,
	TRACE_EVENT_FL_TRACEPOINT = 16,
	TRACE_EVENT_FL_DYNAMIC = 32,
	TRACE_EVENT_FL_KPROBE = 64,
	TRACE_EVENT_FL_UPROBE = 128,
	TRACE_EVENT_FL_EPROBE = 256,
	TRACE_EVENT_FL_FPROBE = 512,
	TRACE_EVENT_FL_CUSTOM = 1024,
};

enum dynevent_type {
	DYNEVENT_TYPE_SYNTH = 1,
	DYNEVENT_TYPE_KPROBE = 2,
	DYNEVENT_TYPE_NONE = 3,
};

struct dynevent_cmd;

typedef int (*dynevent_create_fn_t)(struct dynevent_cmd *);

struct dynevent_cmd {
	struct seq_buf seq;
	const char *event_name;
	unsigned int n_fields;
	enum dynevent_type type;
	dynevent_create_fn_t run_command;
	void *private_data;
};

enum {
	EVENT_FILE_FL_ENABLED = 1,
	EVENT_FILE_FL_RECORDED_CMD = 2,
	EVENT_FILE_FL_RECORDED_TGID = 4,
	EVENT_FILE_FL_FILTERED = 8,
	EVENT_FILE_FL_NO_SET_FILTER = 16,
	EVENT_FILE_FL_SOFT_MODE = 32,
	EVENT_FILE_FL_SOFT_DISABLED = 64,
	EVENT_FILE_FL_TRIGGER_MODE = 128,
	EVENT_FILE_FL_TRIGGER_COND = 256,
	EVENT_FILE_FL_PID_FILTER = 512,
	EVENT_FILE_FL_WAS_ENABLED = 1024,
	EVENT_FILE_FL_FREED = 2048,
};

enum {
	FILTER_OTHER = 0,
	FILTER_STATIC_STRING = 1,
	FILTER_DYN_STRING = 2,
	FILTER_RDYN_STRING = 3,
	FILTER_PTR_STRING = 4,
	FILTER_TRACE_FN = 5,
	FILTER_CPUMASK = 6,
	FILTER_COMM = 7,
	FILTER_CPU = 8,
	FILTER_STACKTRACE = 9,
};

struct kprobe_trace_entry_head {
	struct trace_entry ent;
	long unsigned int ip;
};

struct kretprobe_trace_entry_head {
	struct trace_entry ent;
	long unsigned int func;
	long unsigned int ret_ip;
};

enum {
	TRACE_ARRAY_FL_GLOBAL = 1,
};

enum trace_iterator_flags {
	TRACE_ITER_PRINT_PARENT = 1,
	TRACE_ITER_SYM_OFFSET = 2,
	TRACE_ITER_SYM_ADDR = 4,
	TRACE_ITER_VERBOSE = 8,
	TRACE_ITER_RAW = 16,
	TRACE_ITER_HEX = 32,
	TRACE_ITER_BIN = 64,
	TRACE_ITER_BLOCK = 128,
	TRACE_ITER_FIELDS = 256,
	TRACE_ITER_PRINTK = 512,
	TRACE_ITER_ANNOTATE = 1024,
	TRACE_ITER_USERSTACKTRACE = 2048,
	TRACE_ITER_SYM_USEROBJ = 4096,
	TRACE_ITER_PRINTK_MSGONLY = 8192,
	TRACE_ITER_CONTEXT_INFO = 16384,
	TRACE_ITER_LATENCY_FMT = 32768,
	TRACE_ITER_RECORD_CMD = 65536,
	TRACE_ITER_RECORD_TGID = 131072,
	TRACE_ITER_OVERWRITE = 262144,
	TRACE_ITER_STOP_ON_FREE = 524288,
	TRACE_ITER_IRQ_INFO = 1048576,
	TRACE_ITER_MARKERS = 2097152,
	TRACE_ITER_EVENT_FORK = 4194304,
	TRACE_ITER_PAUSE_ON_TRACE = 8388608,
	TRACE_ITER_HASH_PTR = 16777216,
	TRACE_ITER_FUNCTION = 33554432,
	TRACE_ITER_FUNC_FORK = 67108864,
	TRACE_ITER_DISPLAY_GRAPH = 134217728,
	TRACE_ITER_STACKTRACE = 268435456,
};

struct dyn_event;

struct dyn_event_operations {
	struct list_head list;
	int (*create)(const char *);
	int (*show)(struct seq_file *, struct dyn_event *);
	bool (*is_busy)(struct dyn_event *);
	int (*free)(struct dyn_event *);
	bool (*match)(const char *, const char *, int, const char **, struct dyn_event *);
};

struct dyn_event {
	struct list_head list;
	struct dyn_event_operations *ops;
};

typedef int (*dynevent_check_arg_fn_t)(void *);

struct dynevent_arg {
	const char *str;
	char separator;
};

struct objpool_slot {
	uint32_t head;
	uint32_t tail;
	uint32_t last;
	uint32_t mask;
	void *entries[0];
};

struct objpool_head;

typedef int (*objpool_fini_cb)(struct objpool_head *, void *);

struct objpool_head {
	int obj_size;
	int nr_objs;
	int nr_cpus;
	int capacity;
	gfp_t gfp;
	refcount_t ref;
	long unsigned int flags;
	struct objpool_slot **cpu_slots;
	objpool_fini_cb release;
	void *context;
};

typedef u32 kprobe_opcode_t;

struct arch_specific_insn {
	kprobe_opcode_t *insn;
	int boostable;
};

struct kprobe;

typedef int (*kprobe_pre_handler_t)(struct kprobe *, struct pt_regs *);

typedef void (*kprobe_post_handler_t)(struct kprobe *, struct pt_regs *, long unsigned int);

struct kprobe {
	struct hlist_node hlist;
	struct list_head list;
	long unsigned int nmissed;
	kprobe_opcode_t *addr;
	const char *symbol_name;
	unsigned int offset;
	kprobe_pre_handler_t pre_handler;
	kprobe_post_handler_t post_handler;
	kprobe_opcode_t opcode;
	struct arch_specific_insn ainsn;
	u32 flags;
};

struct kretprobe_instance;

typedef int (*kretprobe_handler_t)(struct kretprobe_instance *, struct pt_regs *);

struct kretprobe_holder;

struct kretprobe_instance {
	struct callback_head rcu;
	struct llist_node llist;
	struct kretprobe_holder *rph;
	kprobe_opcode_t *ret_addr;
	void *fp;
	char data[0];
};

struct kretprobe;

struct kretprobe_holder {
	struct kretprobe *rp;
	struct objpool_head pool;
};

struct kretprobe {
	struct kprobe kp;
	kretprobe_handler_t handler;
	kretprobe_handler_t entry_handler;
	int maxactive;
	int nmissed;
	size_t data_size;
	struct kretprobe_holder *rph;
};

typedef int (*print_type_func_t)(struct trace_seq *, void *, void *);

enum fetch_op {
	FETCH_OP_NOP = 0,
	FETCH_OP_REG = 1,
	FETCH_OP_STACK = 2,
	FETCH_OP_STACKP = 3,
	FETCH_OP_RETVAL = 4,
	FETCH_OP_IMM = 5,
	FETCH_OP_COMM = 6,
	FETCH_OP_ARG = 7,
	FETCH_OP_FOFFS = 8,
	FETCH_OP_DATA = 9,
	FETCH_OP_EDATA = 10,
	FETCH_OP_DEREF = 11,
	FETCH_OP_UDEREF = 12,
	FETCH_OP_ST_RAW = 13,
	FETCH_OP_ST_MEM = 14,
	FETCH_OP_ST_UMEM = 15,
	FETCH_OP_ST_STRING = 16,
	FETCH_OP_ST_USTRING = 17,
	FETCH_OP_ST_SYMSTR = 18,
	FETCH_OP_ST_EDATA = 19,
	FETCH_OP_MOD_BF = 20,
	FETCH_OP_LP_ARRAY = 21,
	FETCH_OP_TP_ARG = 22,
	FETCH_OP_END = 23,
	FETCH_NOP_SYMBOL = 24,
};

struct fetch_insn {
	enum fetch_op op;
	union {
		unsigned int param;
		struct {
			unsigned int size;
			int offset;
		};
		struct {
			unsigned char basesize;
			unsigned char lshift;
			unsigned char rshift;
		};
		long unsigned int immediate;
		void *data;
	};
};

struct fetch_type {
	const char *name;
	size_t size;
	bool is_signed;
	bool is_string;
	print_type_func_t print;
	const char *fmt;
	const char *fmttype;
};

struct probe_arg {
	struct fetch_insn *code;
	bool dynamic;
	unsigned int offset;
	unsigned int count;
	const char *name;
	const char *comm;
	char *fmt;
	const struct fetch_type *type;
};

struct probe_entry_arg {
	struct fetch_insn *code;
	unsigned int size;
};

struct trace_uprobe_filter {
	rwlock_t rwlock;
	int nr_systemwide;
	struct list_head perf_events;
};

struct trace_probe_event {
	unsigned int flags;
	struct trace_event_class class;
	struct trace_event_call call;
	struct list_head files;
	struct list_head probes;
	struct trace_uprobe_filter filter[0];
};

struct trace_probe {
	struct list_head list;
	struct trace_probe_event *event;
	ssize_t size;
	unsigned int nr_args;
	struct probe_entry_arg *entry_arg;
	struct probe_arg args[0];
};

struct event_file_link {
	struct trace_event_file *file;
	struct list_head list;
};

struct traceprobe_parse_context {
	struct trace_event_call *event;
	const char *funcname;
	const struct btf_type *proto;
	const struct btf_param *params;
	s32 nr_params;
	struct btf *btf;
	const struct btf_type *last_type;
	u32 last_bitoffs;
	u32 last_bitsize;
	struct trace_probe *tp;
	unsigned int flags;
	int offset;
};

enum probe_print_type {
	PROBE_PRINT_NORMAL = 0,
	PROBE_PRINT_RETURN = 1,
	PROBE_PRINT_EVENT = 2,
};

enum {
	TP_ERR_FILE_NOT_FOUND = 0,
	TP_ERR_NO_REGULAR_FILE = 1,
	TP_ERR_BAD_REFCNT = 2,
	TP_ERR_REFCNT_OPEN_BRACE = 3,
	TP_ERR_BAD_REFCNT_SUFFIX = 4,
	TP_ERR_BAD_UPROBE_OFFS = 5,
	TP_ERR_BAD_MAXACT_TYPE = 6,
	TP_ERR_BAD_MAXACT = 7,
	TP_ERR_MAXACT_TOO_BIG = 8,
	TP_ERR_BAD_PROBE_ADDR = 9,
	TP_ERR_NON_UNIQ_SYMBOL = 10,
	TP_ERR_BAD_RETPROBE = 11,
	TP_ERR_NO_TRACEPOINT = 12,
	TP_ERR_BAD_ADDR_SUFFIX = 13,
	TP_ERR_NO_GROUP_NAME = 14,
	TP_ERR_GROUP_TOO_LONG = 15,
	TP_ERR_BAD_GROUP_NAME = 16,
	TP_ERR_NO_EVENT_NAME = 17,
	TP_ERR_EVENT_TOO_LONG = 18,
	TP_ERR_BAD_EVENT_NAME = 19,
	TP_ERR_EVENT_EXIST = 20,
	TP_ERR_RETVAL_ON_PROBE = 21,
	TP_ERR_NO_RETVAL = 22,
	TP_ERR_BAD_STACK_NUM = 23,
	TP_ERR_BAD_ARG_NUM = 24,
	TP_ERR_BAD_VAR = 25,
	TP_ERR_BAD_REG_NAME = 26,
	TP_ERR_BAD_MEM_ADDR = 27,
	TP_ERR_BAD_IMM = 28,
	TP_ERR_IMMSTR_NO_CLOSE = 29,
	TP_ERR_FILE_ON_KPROBE = 30,
	TP_ERR_BAD_FILE_OFFS = 31,
	TP_ERR_SYM_ON_UPROBE = 32,
	TP_ERR_TOO_MANY_OPS = 33,
	TP_ERR_DEREF_NEED_BRACE = 34,
	TP_ERR_BAD_DEREF_OFFS = 35,
	TP_ERR_DEREF_OPEN_BRACE = 36,
	TP_ERR_COMM_CANT_DEREF = 37,
	TP_ERR_BAD_FETCH_ARG = 38,
	TP_ERR_ARRAY_NO_CLOSE = 39,
	TP_ERR_BAD_ARRAY_SUFFIX = 40,
	TP_ERR_BAD_ARRAY_NUM = 41,
	TP_ERR_ARRAY_TOO_BIG = 42,
	TP_ERR_BAD_TYPE = 43,
	TP_ERR_BAD_STRING = 44,
	TP_ERR_BAD_SYMSTRING = 45,
	TP_ERR_BAD_BITFIELD = 46,
	TP_ERR_ARG_NAME_TOO_LONG = 47,
	TP_ERR_NO_ARG_NAME = 48,
	TP_ERR_BAD_ARG_NAME = 49,
	TP_ERR_USED_ARG_NAME = 50,
	TP_ERR_ARG_TOO_LONG = 51,
	TP_ERR_NO_ARG_BODY = 52,
	TP_ERR_BAD_INSN_BNDRY = 53,
	TP_ERR_FAIL_REG_PROBE = 54,
	TP_ERR_DIFF_PROBE_TYPE = 55,
	TP_ERR_DIFF_ARG_TYPE = 56,
	TP_ERR_SAME_PROBE = 57,
	TP_ERR_NO_EVENT_INFO = 58,
	TP_ERR_BAD_ATTACH_EVENT = 59,
	TP_ERR_BAD_ATTACH_ARG = 60,
	TP_ERR_NO_EP_FILTER = 61,
	TP_ERR_NOSUP_BTFARG = 62,
	TP_ERR_NO_BTFARG = 63,
	TP_ERR_NO_BTF_ENTRY = 64,
	TP_ERR_BAD_VAR_ARGS = 65,
	TP_ERR_NOFENTRY_ARGS = 66,
	TP_ERR_DOUBLE_ARGS = 67,
	TP_ERR_ARGS_2LONG = 68,
	TP_ERR_ARGIDX_2BIG = 69,
	TP_ERR_NO_PTR_STRCT = 70,
	TP_ERR_NOSUP_DAT_ARG = 71,
	TP_ERR_BAD_HYPHEN = 72,
	TP_ERR_NO_BTF_FIELD = 73,
	TP_ERR_BAD_BTF_TID = 74,
	TP_ERR_BAD_TYPE4STR = 75,
	TP_ERR_NEED_STRING_TYPE = 76,
};

struct trace_kprobe {
	struct dyn_event devent;
	struct kretprobe rp;
	long unsigned int *nhit;
	const char *symbol;
	struct trace_probe tp;
};

struct sym_count_ctx {
	unsigned int count;
	const char *name;
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
	BPF_F_LOCK = 4,
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
	TASKSTATS_CMD_UNSPEC = 0,
	TASKSTATS_CMD_GET = 1,
	TASKSTATS_CMD_NEW = 2,
	__TASKSTATS_CMD_MAX = 3,
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

enum psi_task_count {
	NR_IOWAIT = 0,
	NR_MEMSTALL = 1,
	NR_RUNNING = 2,
	NR_MEMSTALL_RUNNING = 3,
	NR_PSI_TASK_COUNTS = 4,
};

enum psi_res {
	PSI_IO = 0,
	PSI_MEM = 1,
	PSI_CPU = 2,
	NR_PSI_RESOURCES = 3,
};

enum psi_states {
	PSI_IO_SOME = 0,
	PSI_IO_FULL = 1,
	PSI_MEM_SOME = 2,
	PSI_MEM_FULL = 3,
	PSI_CPU_SOME = 4,
	PSI_CPU_FULL = 5,
	PSI_NONIDLE = 6,
	NR_PSI_STATES = 7,
};

enum psi_aggregators {
	PSI_AVGS = 0,
	PSI_POLL = 1,
	NR_PSI_AGGREGATORS = 2,
};

enum cgroup_subsys_id {
	cpuset_cgrp_id = 0,
	cpu_cgrp_id = 1,
	cpuacct_cgrp_id = 2,
	io_cgrp_id = 3,
	memory_cgrp_id = 4,
	devices_cgrp_id = 5,
	freezer_cgrp_id = 6,
	net_cls_cgrp_id = 7,
	perf_event_cgrp_id = 8,
	net_prio_cgrp_id = 9,
	hugetlb_cgrp_id = 10,
	pids_cgrp_id = 11,
	rdma_cgrp_id = 12,
	misc_cgrp_id = 13,
	CGROUP_SUBSYS_COUNT = 14,
};

enum wb_stat_item {
	WB_RECLAIMABLE = 0,
	WB_WRITEBACK = 1,
	WB_DIRTIED = 2,
	WB_WRITTEN = 3,
	NR_WB_STAT_ITEMS = 4,
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

enum {
	BPF_MAX_TRAMP_LINKS = 38,
};

enum bpf_tramp_prog_type {
	BPF_TRAMP_FENTRY = 0,
	BPF_TRAMP_FEXIT = 1,
	BPF_TRAMP_MODIFY_RETURN = 2,
	BPF_TRAMP_MAX = 3,
	BPF_TRAMP_REPLACE = 4,
};

struct bpf_queue_stack {
	struct bpf_map map;
	raw_spinlock_t lock;
	u32 head;
	u32 tail;
	u32 size;
	char elements[0];
};

typedef long unsigned int pte_basic_t;

enum uprobe_filter_ctx {
	UPROBE_FILTER_REGISTER = 0,
	UPROBE_FILTER_UNREGISTER = 1,
	UPROBE_FILTER_MMAP = 2,
};

struct uprobe_consumer {
	int (*handler)(struct uprobe_consumer *, struct pt_regs *);
	int (*ret_handler)(struct uprobe_consumer *, long unsigned int, struct pt_regs *);
	bool (*filter)(struct uprobe_consumer *, enum uprobe_filter_ctx, struct mm_struct *);
	struct uprobe_consumer *next;
};

typedef u32 uprobe_opcode_t;

struct arch_uprobe {
	union {
		u32 insn[2];
		u32 ixol[2];
	};
};

struct uprobe {
	struct rb_node rb_node;
	refcount_t ref;
	struct rw_semaphore register_rwsem;
	struct rw_semaphore consumer_rwsem;
	struct list_head pending_list;
	struct uprobe_consumer *consumers;
	struct inode *inode;
	loff_t offset;
	loff_t ref_ctr_offset;
	long unsigned int flags;
	struct arch_uprobe arch;
};

enum rp_check {
	RP_CHECK_CALL = 0,
	RP_CHECK_CHAIN_CALL = 1,
	RP_CHECK_RET = 2,
};

struct vm_special_mapping {
	const char *name;
	struct page **pages;
	vm_fault_t (*fault)(const struct vm_special_mapping *, struct vm_area_struct *, struct vm_fault *);
	int (*mremap)(const struct vm_special_mapping *, struct vm_area_struct *);
};

struct xol_area {
	wait_queue_head_t wq;
	atomic_t slot_count;
	long unsigned int *bitmap;
	struct vm_special_mapping xol_mapping;
	struct page *pages[2];
	long unsigned int vaddr;
};

struct userfaultfd_ctx {
	wait_queue_head_t fault_pending_wqh;
	wait_queue_head_t fault_wqh;
	wait_queue_head_t fd_wqh;
	wait_queue_head_t event_wqh;
	seqcount_spinlock_t refile_seq;
	refcount_t refcount;
	unsigned int flags;
	unsigned int features;
	bool released;
	struct rw_semaphore map_changing_lock;
	atomic_t mmap_changing;
	struct mm_struct *mm;
};

struct anon_vma {
	struct anon_vma *root;
	struct rw_semaphore rwsem;
	atomic_t refcount;
	long unsigned int num_children;
	long unsigned int num_active_vmas;
	struct anon_vma *parent;
	struct rb_root_cached rb_root;
};

struct mempolicy {
	atomic_t refcnt;
	short unsigned int mode;
	short unsigned int flags;
	nodemask_t nodes;
	int home_node;
	union {
		nodemask_t cpuset_mems_allowed;
		nodemask_t user_nodemask;
	} w;
};

struct vma_iterator {
	struct ma_state mas;
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
	PG_hwpoison = 22,
	__NR_PAGEFLAGS = 23,
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
	PG_vmemmap_self_hosted = 12,
	PG_has_hwpoisoned = 10,
	PG_large_rmappable = 9,
};

struct reclaim_state {
	long unsigned int reclaimed;
	struct lru_gen_mm_walk *mm_walk;
};

enum mmu_notifier_event {
	MMU_NOTIFY_UNMAP = 0,
	MMU_NOTIFY_CLEAR = 1,
	MMU_NOTIFY_PROTECTION_VMA = 2,
	MMU_NOTIFY_PROTECTION_PAGE = 3,
	MMU_NOTIFY_SOFT_DIRTY = 4,
	MMU_NOTIFY_RELEASE = 5,
	MMU_NOTIFY_MIGRATE = 6,
	MMU_NOTIFY_EXCLUSIVE = 7,
};

struct mmu_notifier_range {
	struct mm_struct *mm;
	long unsigned int start;
	long unsigned int end;
	unsigned int flags;
	enum mmu_notifier_event event;
	void *owner;
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
	long unsigned int flags;
	short int prio;
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
	unsigned int *cluster_next_cpu;
	struct percpu_cluster *percpu_cluster;
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

struct fc_log;

struct p_log {
	const char *prefix;
	struct fc_log *log;
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

typedef int filler_t(struct file *, struct folio *);

typedef unsigned int fgf_t;

struct page_vma_mapped_walk {
	long unsigned int pfn;
	long unsigned int nr_pages;
	long unsigned int pgoff;
	struct vm_area_struct *vma;
	long unsigned int address;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned int flags;
};

struct percpu_cluster {
	struct swap_cluster_info index;
	unsigned int next;
};

typedef void (*task_work_func_t)(struct callback_head *);

enum task_work_notify_mode {
	TWA_NONE = 0,
	TWA_RESUME = 1,
	TWA_SIGNAL = 2,
	TWA_SIGNAL_NO_IPI = 3,
};

enum fs_value_type {
	fs_value_is_undefined = 0,
	fs_value_is_flag = 1,
	fs_value_is_string = 2,
	fs_value_is_blob = 3,
	fs_value_is_filename = 4,
	fs_value_is_file = 5,
};

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

struct fc_log {
	refcount_t usage;
	u8 head;
	u8 tail;
	u8 need_free;
	struct module *owner;
	char *buffer[8];
};

struct fs_context_operations {
	void (*free)(struct fs_context *);
	int (*dup)(struct fs_context *, struct fs_context *);
	int (*parse_param)(struct fs_context *, struct fs_parameter *);
	int (*parse_monolithic)(struct fs_context *, void *);
	int (*get_tree)(struct fs_context *);
	int (*reconfigure)(struct fs_context *);
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

struct delayed_uprobe {
	struct list_head list;
	struct uprobe *uprobe;
	struct mm_struct *mm;
};

struct __uprobe_key {
	struct inode *inode;
	loff_t offset;
};

struct map_info {
	struct map_info *next;
	struct mm_struct *mm;
	long unsigned int vaddr;
};

enum work_flags {
	WORK_STRUCT_PENDING = 1,
	WORK_STRUCT_INACTIVE = 2,
	WORK_STRUCT_PWQ = 4,
	WORK_STRUCT_LINKED = 8,
	WORK_STRUCT_STATIC = 0,
};

enum wq_misc_consts {
	WORK_NR_COLORS = 16,
	WORK_CPU_UNBOUND = 2048,
	WORK_BUSY_PENDING = 1,
	WORK_BUSY_RUNNING = 2,
	WORKER_DESC_LEN = 32,
};

struct ptdesc {
	long unsigned int __page_flags;
	union {
		struct callback_head pt_rcu_head;
		struct list_head pt_list;
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t pmd_huge_pte;
		};
	};
	long unsigned int __page_mapping;
	union {
		long unsigned int pt_index;
		struct mm_struct *pt_mm;
		atomic_t pt_frag_refcount;
	};
	union {
		long unsigned int _pt_pad_2;
		spinlock_t ptl;
	};
	unsigned int __page_type;
	atomic_t __page_refcount;
	long unsigned int pt_memcg_data;
};

typedef unsigned int zap_flags_t;

typedef struct pglist_data pg_data_t;

enum {
	__PERCPU_REF_ATOMIC = 1,
	__PERCPU_REF_DEAD = 2,
	__PERCPU_REF_ATOMIC_DEAD = 3,
	__PERCPU_REF_FLAG_BITS = 2,
};

struct compact_control;

struct capture_control {
	struct compact_control *cc;
	struct page *page;
};

struct task_delay_info {
	raw_spinlock_t lock;
	u64 blkio_start;
	u64 blkio_delay;
	u64 swapin_start;
	u64 swapin_delay;
	u32 blkio_count;
	u32 swapin_count;
	u64 freepages_start;
	u64 freepages_delay;
	u64 thrashing_start;
	u64 thrashing_delay;
	u64 compact_start;
	u64 compact_delay;
	u64 wpcopy_start;
	u64 wpcopy_delay;
	u64 irq_delay;
	u32 freepages_count;
	u32 thrashing_count;
	u32 compact_count;
	u32 wpcopy_count;
	u32 irq_count;
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

struct encoded_page;

struct vm_event_state {
	long unsigned int event[102];
};

struct zap_details {
	struct folio *single_folio;
	bool even_cows;
	zap_flags_t zap_flags;
};

enum string_size_units {
	STRING_UNITS_10 = 0,
	STRING_UNITS_2 = 1,
	STRING_UNITS_MASK = 1,
	STRING_UNITS_NO_SPACE = 1073741824,
	STRING_UNITS_NO_BYTES = 2147483648,
};

enum {
	MPOL_DEFAULT = 0,
	MPOL_PREFERRED = 1,
	MPOL_BIND = 2,
	MPOL_INTERLEAVE = 3,
	MPOL_LOCAL = 4,
	MPOL_PREFERRED_MANY = 5,
	MPOL_WEIGHTED_INTERLEAVE = 6,
	MPOL_MAX = 7,
};

enum {
	CSS_NO_REF = 1,
	CSS_ONLINE = 2,
	CSS_RELEASED = 4,
	CSS_VISIBLE = 8,
	CSS_DYING = 16,
};

struct node {
	struct device dev;
	struct list_head access_list;
};

typedef long unsigned int pte_marker;

typedef unsigned int uffd_flags_t;

enum mfill_atomic_mode {
	MFILL_ATOMIC_COPY = 0,
	MFILL_ATOMIC_ZEROPAGE = 1,
	MFILL_ATOMIC_CONTINUE = 2,
	MFILL_ATOMIC_POISON = 3,
	NR_MFILL_ATOMIC_MODES = 4,
};

struct hstate;

struct hugepage_subpool {
	spinlock_t lock;
	long int count;
	long int max_hpages;
	long int used_hpages;
	struct hstate *hstate;
	long int min_hpages;
	long int rsv_hpages;
};

struct hstate {
	struct mutex resize_lock;
	int next_nid_to_alloc;
	int next_nid_to_free;
	unsigned int order;
	unsigned int demote_order;
	long unsigned int mask;
	long unsigned int max_huge_pages;
	long unsigned int nr_huge_pages;
	long unsigned int free_huge_pages;
	long unsigned int resv_huge_pages;
	long unsigned int surplus_huge_pages;
	long unsigned int nr_overcommit_huge_pages;
	struct list_head hugepage_activelist;
	struct list_head hugepage_freelists[256];
	unsigned int max_huge_pages_node[256];
	unsigned int nr_huge_pages_node[256];
	unsigned int free_huge_pages_node[256];
	unsigned int surplus_huge_pages_node[256];
	struct cftype cgroup_files_dfl[8];
	struct cftype cgroup_files_legacy[10];
	char name[32];
};

struct resv_map {
	struct kref refs;
	spinlock_t lock;
	struct list_head regions;
	long int adds_in_progress;
	struct list_head region_cache;
	long int region_cache_count;
	struct rw_semaphore rw_sema;
	struct page_counter *reservation_counter;
	long unsigned int pages_per_hpage;
	struct cgroup_subsys_state *css;
};

struct file_region {
	struct list_head link;
	long int from;
	long int to;
	struct page_counter *reservation_counter;
	struct cgroup_subsys_state *css;
};

struct hugetlb_vma_lock {
	struct kref refs;
	struct rw_semaphore rw_sema;
	struct vm_area_struct *vma;
};

struct hugetlbfs_sb_info {
	long int max_inodes;
	long int free_inodes;
	spinlock_t stat_lock;
	struct hstate *hstate;
	struct hugepage_subpool *spool;
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
};

enum hugetlb_page_flags {
	HPG_restore_reserve = 0,
	HPG_migratable = 1,
	HPG_temporary = 2,
	HPG_freed = 3,
	HPG_vmemmap_optimized = 4,
	HPG_raw_hwp_unreliable = 5,
	__NR_HPAGEFLAGS = 6,
};

struct huge_bootmem_page {
	struct list_head list;
	struct hstate *hstate;
};

struct padata_mt_job {
	void (*thread_fn)(long unsigned int, long unsigned int, void *);
	void *fn_arg;
	long unsigned int start;
	long unsigned int size;
	long unsigned int align;
	long unsigned int min_chunk;
	int max_threads;
	bool numa_aware;
};

struct mmu_table_batch {
	struct callback_head rcu;
	unsigned int nr;
	void *tables[0];
};

struct mmu_gather_batch {
	struct mmu_gather_batch *next;
	unsigned int nr;
	unsigned int max;
	struct encoded_page *encoded_pages[0];
};

struct mmu_gather {
	struct mm_struct *mm;
	struct mmu_table_batch *batch;
	long unsigned int start;
	long unsigned int end;
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
	unsigned int page_size;
};

enum hugetlb_memory_event {
	HUGETLB_MAX = 0,
	HUGETLB_NR_MEMORY_EVENTS = 1,
};

struct hugetlb_cgroup_per_node {
	long unsigned int usage[15];
};

struct hugetlb_cgroup {
	struct cgroup_subsys_state css;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct page_counter hugepage[15];
	struct page_counter rsvd_hugepage[15];
	atomic_long_t events[15];
	atomic_long_t events_local[15];
	struct cgroup_file events_file[15];
	struct cgroup_file events_local_file[15];
	struct hugetlb_cgroup_per_node *nodeinfo[0];
};

struct compact_control {
	struct list_head freepages[9];
	struct list_head migratepages;
	unsigned int nr_freepages;
	unsigned int nr_migratepages;
	long unsigned int free_pfn;
	long unsigned int migrate_pfn;
	long unsigned int fast_start_pfn;
	struct zone *zone;
	long unsigned int total_migrate_scanned;
	long unsigned int total_free_scanned;
	short unsigned int fast_search_fail;
	short int search_order;
	const gfp_t gfp_mask;
	int order;
	int migratetype;
	const unsigned int alloc_flags;
	const int highest_zoneidx;
	enum migrate_mode mode;
	bool ignore_skip_hint;
	bool no_set_skip_hint;
	bool ignore_block_suitable;
	bool direct_compaction;
	bool proactive_compaction;
	bool whole_zone;
	bool contended;
	bool finish_pageblock;
	bool alloc_contig;
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

enum vma_resv_mode {
	VMA_NEEDS_RESV = 0,
	VMA_COMMIT_RESV = 1,
	VMA_END_RESV = 2,
	VMA_ADD_RESV = 3,
	VMA_DEL_RESV = 4,
};

struct node_hstate {
	struct kobject *hugepages_kobj;
	struct kobject *hstate_kobjs[15];
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

struct fs_pin {
	wait_queue_head_t wait;
	int done;
	struct hlist_node s_list;
	struct hlist_node m_list;
	void (*kill)(struct fs_pin *);
};

struct syscall_metadata {
	const char *name;
	int syscall_nr;
	int nb_args;
	const char **types;
	const char **args;
	struct list_head enter_fields;
	struct trace_event_call *enter_event;
	struct trace_event_call *exit_event;
};

struct mnt_pcp;

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
	struct mnt_pcp *mnt_pcp;
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
	struct fsnotify_mark_connector *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
	int mnt_id;
	u64 mnt_id_unique;
	int mnt_group_id;
	int mnt_expiry_mark;
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

struct prepend_buffer {
	char *buf;
	int len;
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

struct name_snapshot {
	struct qstr name;
	unsigned char inline_name[40];
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
	_SLAB_ACCOUNT = 13,
	_SLAB_NO_USER_FLAGS = 14,
	_SLAB_SKIP_KFENCE = 15,
	_SLAB_RECLAIM_ACCOUNT = 16,
	_SLAB_OBJECT_POISON = 17,
	_SLAB_CMPXCHG_DOUBLE = 18,
	_SLAB_FLAGS_LAST_BIT = 19,
};

struct fd {
	struct file *file;
	unsigned int flags;
};

struct epoll_event {
	__poll_t events;
	__u64 data;
};

struct epoll_params {
	__u32 busy_poll_usecs;
	__u16 busy_poll_budget;
	__u8 prefer_busy_poll;
	__u8 __pad;
};

typedef struct poll_table_struct poll_table;

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct bpf_prog_stats {
	u64_stats_t cnt;
	u64_stats_t nsecs;
	u64_stats_t misses;
	struct u64_stats_sync syncp;
	long: 64;
};

struct sock_fprog_kern {
	u16 len;
	struct sock_filter *filter;
};

struct icmpv6_mib_device {
	atomic_long_t mibs[7];
};

struct icmpv6msg_mib_device {
	atomic_long_t mibs[512];
};

struct ip_ra_chain {
	struct ip_ra_chain *next;
	struct sock *sk;
	union {
		void (*destructor)(struct sock *);
		struct sock *saved_sk;
	};
	struct callback_head rcu;
};

struct fib_table {
	struct hlist_node tb_hlist;
	u32 tb_id;
	int tb_num_default;
	struct callback_head rcu;
	long unsigned int *tb_data;
	long unsigned int __data[0];
};

struct inet_peer_base {
	struct rb_root rb_root;
	seqlock_t lock;
	int total;
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
	__s32 accept_ra_rtr_pref;
	__s32 rtr_probe_interval;
	__s32 accept_ra_rt_info_min_plen;
	__s32 accept_ra_rt_info_max_plen;
	__s32 accept_source_route;
	__s32 accept_ra_from_local;
	__s32 optimistic_dad;
	__s32 use_optimistic;
	atomic_t mc_forwarding;
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
	__s32 seg6_require_hmac;
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

struct tc_sizespec {
	unsigned char cell_log;
	unsigned char size_log;
	short int cell_align;
	int overhead;
	unsigned int linklayer;
	unsigned int mpu;
	unsigned int mtu;
	unsigned int tsize;
};

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

struct net_rate_estimator;

struct Qdisc {
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	unsigned int flags;
	u32 limit;
	const struct Qdisc_ops *ops;
	struct qdisc_size_table *stab;
	struct hlist_node hash;
	u32 handle;
	u32 parent;
	struct netdev_queue *dev_queue;
	struct net_rate_estimator *rate_est;
	struct gnet_stats_basic_sync *cpu_bstats;
	struct gnet_stats_queue *cpu_qstats;
	int pad;
	refcount_t refcnt;
	long: 64;
	long: 64;
	long: 64;
	struct sk_buff_head gso_skb;
	struct qdisc_skb_head q;
	struct gnet_stats_basic_sync bstats;
	struct gnet_stats_queue qstats;
	int owner;
	long unsigned int state;
	long unsigned int state2;
	struct Qdisc *next_sched;
	struct sk_buff_head skb_bad_txq;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long int privdata[0];
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

struct ipv6_devstat {
	struct proc_dir_entry *proc_dir_entry;
	struct ipstats_mib *ipv6;
	struct icmpv6_mib_device *icmpv6dev;
	struct icmpv6msg_mib_device *icmpv6msgdev;
};

struct ifmcaddr6;

struct ifacaddr6;

struct inet6_dev {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head addr_list;
	struct ifmcaddr6 *mc_list;
	struct ifmcaddr6 *mc_tomb;
	unsigned char mc_qrv;
	unsigned char mc_gq_running;
	unsigned char mc_ifc_count;
	unsigned char mc_dad_count;
	long unsigned int mc_v1_seen;
	long unsigned int mc_qi;
	long unsigned int mc_qri;
	long unsigned int mc_maxdelay;
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
	struct ifacaddr6 *ac_list;
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
	long unsigned int tstamp;
	struct callback_head rcu;
	unsigned int ra_mtu;
};

struct tcmsg {
	unsigned char tcm_family;
	unsigned char tcm__pad1;
	short unsigned int tcm__pad2;
	int tcm_ifindex;
	__u32 tcm_handle;
	__u32 tcm_parent;
	__u32 tcm_info;
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

struct timewait_sock_ops {
	struct kmem_cache *twsk_slab;
	char *twsk_slab_name;
	unsigned int twsk_obj_size;
	int (*twsk_unique)(struct sock *, struct sock *, void *);
	void (*twsk_destructor)(struct sock *);
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

struct ip6_sf_list {
	struct ip6_sf_list *sf_next;
	struct in6_addr sf_addr;
	long unsigned int sf_count[2];
	unsigned char sf_gsresp;
	unsigned char sf_oldin;
	unsigned char sf_crcount;
	struct callback_head rcu;
};

struct ifmcaddr6 {
	struct in6_addr mca_addr;
	struct inet6_dev *idev;
	struct ifmcaddr6 *next;
	struct ip6_sf_list *mca_sources;
	struct ip6_sf_list *mca_tomb;
	unsigned int mca_sfmode;
	unsigned char mca_crcount;
	long unsigned int mca_sfcount[2];
	struct delayed_work mca_work;
	unsigned int mca_flags;
	int mca_users;
	refcount_t mca_refcnt;
	long unsigned int mca_cstamp;
	long unsigned int mca_tstamp;
	struct callback_head rcu;
};

struct ifacaddr6 {
	struct in6_addr aca_addr;
	struct fib6_info *aca_rt;
	struct ifacaddr6 *aca_next;
	struct hlist_node aca_addr_lst;
	int aca_users;
	refcount_t aca_refcnt;
	long unsigned int aca_cstamp;
	long unsigned int aca_tstamp;
	struct callback_head rcu;
};

struct nd_opt_hdr {
	__u8 nd_opt_type;
	__u8 nd_opt_len;
};

struct ndisc_options {
	struct nd_opt_hdr *nd_opt_array[15];
	struct nd_opt_hdr *nd_opts_ri;
	struct nd_opt_hdr *nd_opts_ri_end;
	struct nd_opt_hdr *nd_useropts;
	struct nd_opt_hdr *nd_useropts_end;
	struct nd_opt_hdr *nd_802154_opt_array[3];
};

struct prefix_info {
	__u8 type;
	__u8 length;
	__u8 prefix_len;
	union {
		__u8 flags;
		struct {
			__u8 onlink: 1;
			__u8 autoconf: 1;
			__u8 reserved: 6;
		};
	};
	__be32 valid;
	__be32 prefered;
	__be32 reserved2;
	struct in6_addr prefix;
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

enum flow_action_hw_stats_bit {
	FLOW_ACTION_HW_STATS_IMMEDIATE_BIT = 0,
	FLOW_ACTION_HW_STATS_DELAYED_BIT = 1,
	FLOW_ACTION_HW_STATS_DISABLED_BIT = 2,
	FLOW_ACTION_HW_STATS_NUM_BITS = 3,
};

struct flow_block {
	struct list_head cb_list;
};

typedef int flow_setup_cb_t(enum tc_setup_type, void *, void *);

struct qdisc_size_table {
	struct callback_head rcu;
	struct list_head list;
	struct tc_sizespec szopts;
	int refcnt;
	u16 data[0];
};

struct Qdisc_class_ops;

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

struct tcf_block;

struct Qdisc_class_ops {
	unsigned int flags;
	struct netdev_queue * (*select_queue)(struct Qdisc *, struct tcmsg *);
	int (*graft)(struct Qdisc *, long unsigned int, struct Qdisc *, struct Qdisc **, struct netlink_ext_ack *);
	struct Qdisc * (*leaf)(struct Qdisc *, long unsigned int);
	void (*qlen_notify)(struct Qdisc *, long unsigned int);
	long unsigned int (*find)(struct Qdisc *, u32);
	int (*change)(struct Qdisc *, u32, u32, struct nlattr **, long unsigned int *, struct netlink_ext_ack *);
	int (*delete)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	void (*walk)(struct Qdisc *, struct qdisc_walker *);
	struct tcf_block * (*tcf_block)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	long unsigned int (*bind_tcf)(struct Qdisc *, long unsigned int, u32);
	void (*unbind_tcf)(struct Qdisc *, long unsigned int);
	int (*dump)(struct Qdisc *, long unsigned int, struct sk_buff *, struct tcmsg *);
	int (*dump_stats)(struct Qdisc *, long unsigned int, struct gnet_dump *);
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

struct tcf_result;

struct tcf_proto_ops;

struct tcf_proto {
	struct tcf_proto *next;
	void *root;
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
			long unsigned int class;
			u32 classid;
		};
		const struct tcf_proto *goto_tp;
	};
};

struct tcf_walker;

struct tcf_exts;

struct tcf_proto_ops {
	struct list_head head;
	char kind[16];
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	int (*init)(struct tcf_proto *);
	void (*destroy)(struct tcf_proto *, bool, struct netlink_ext_ack *);
	void * (*get)(struct tcf_proto *, u32);
	void (*put)(struct tcf_proto *, void *);
	int (*change)(struct net *, struct sk_buff *, struct tcf_proto *, long unsigned int, u32, struct nlattr **, void **, u32, struct netlink_ext_ack *);
	int (*delete)(struct tcf_proto *, void *, bool *, bool, struct netlink_ext_ack *);
	bool (*delete_empty)(struct tcf_proto *);
	void (*walk)(struct tcf_proto *, struct tcf_walker *, bool);
	int (*reoffload)(struct tcf_proto *, bool, flow_setup_cb_t *, void *, struct netlink_ext_ack *);
	void (*hw_add)(struct tcf_proto *, void *);
	void (*hw_del)(struct tcf_proto *, void *);
	void (*bind_class)(void *, u32, long unsigned int, void *, long unsigned int);
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

struct tcf_chain {
	struct mutex filter_chain_lock;
	struct tcf_proto *filter_chain;
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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct xdp_txq_info {
	struct net_device *dev;
};

struct epoll_filefd {
	struct file *file;
	int fd;
} __attribute__((packed));

struct epitem;

struct eppoll_entry {
	struct eppoll_entry *next;
	struct epitem *base;
	wait_queue_entry_t wait;
	wait_queue_head_t *whead;
};

struct eventpoll;

struct epitem {
	union {
		struct rb_node rbn;
		struct callback_head rcu;
	};
	struct list_head rdllink;
	struct epitem *next;
	struct epoll_filefd ffd;
	bool dying;
	struct eppoll_entry *pwqlist;
	struct eventpoll *ep;
	struct hlist_node fllink;
	struct wakeup_source *ws;
	struct epoll_event event;
};

struct eventpoll {
	struct mutex mtx;
	wait_queue_head_t wq;
	wait_queue_head_t poll_wait;
	struct list_head rdllist;
	rwlock_t lock;
	struct rb_root_cached rbr;
	struct epitem *ovflist;
	struct wakeup_source *ws;
	struct user_struct *user;
	struct file *file;
	u64 gen;
	struct hlist_head refs;
	refcount_t refcount;
	unsigned int napi_id;
	u32 busy_poll_usecs;
	u16 busy_poll_budget;
	bool prefer_busy_poll;
};

struct ep_pqueue {
	poll_table pt;
	struct epitem *epi;
};

struct epitems_head {
	struct hlist_head epitems;
	struct epitems_head *next;
};

typedef u32 nlink_t;

struct proc_ops {
	unsigned int proc_flags;
	int (*proc_open)(struct inode *, struct file *);
	ssize_t (*proc_read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*proc_read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*proc_write)(struct file *, const char *, size_t, loff_t *);
	loff_t (*proc_lseek)(struct file *, loff_t, int);
	int (*proc_release)(struct inode *, struct file *);
	__poll_t (*proc_poll)(struct file *, struct poll_table_struct *);
	long int (*proc_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*proc_compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*proc_mmap)(struct file *, struct vm_area_struct *);
	long unsigned int (*proc_get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
};

enum proc_hidepid {
	HIDEPID_OFF = 0,
	HIDEPID_NO_ACCESS = 1,
	HIDEPID_INVISIBLE = 2,
	HIDEPID_NOT_PTRACEABLE = 4,
};

enum proc_pidonly {
	PROC_PIDONLY_OFF = 0,
	PROC_PIDONLY_ON = 1,
};

struct proc_fs_info {
	struct pid_namespace *pid_ns;
	struct dentry *proc_self;
	struct dentry *proc_thread_self;
	kgid_t pid_gid;
	enum proc_hidepid hide_pid;
	enum proc_pidonly pidonly;
	struct callback_head rcu;
};

typedef int (*proc_write_t)(struct file *, char *, size_t);

struct nsset {
	unsigned int flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
};

struct proc_dir_entry {
	atomic_t in_use;
	refcount_t refcnt;
	struct list_head pde_openers;
	spinlock_t pde_unload_lock;
	struct completion *pde_unload_completion;
	const struct inode_operations *proc_iops;
	union {
		const struct proc_ops *proc_ops;
		const struct file_operations *proc_dir_ops;
	};
	const struct dentry_operations *proc_dops;
	union {
		const struct seq_operations *seq_ops;
		int (*single_show)(struct seq_file *, void *);
	};
	proc_write_t write;
	void *data;
	unsigned int state_size;
	unsigned int low_ino;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	char *name;
	umode_t mode;
	u8 flags;
	u8 namelen;
	char inline_name[0];
};

enum {
	PROC_ROOT_INO = 1,
	PROC_IPC_INIT_INO = 4026531839,
	PROC_UTS_INIT_INO = 4026531838,
	PROC_USER_INIT_INO = 4026531837,
	PROC_PID_INIT_INO = 4026531836,
	PROC_CGROUP_INIT_INO = 4026531835,
	PROC_TIME_INIT_INO = 4026531834,
};

struct proc_fs_context {
	struct pid_namespace *pid_ns;
	unsigned int mask;
	enum proc_hidepid hidepid;
	int gid;
	enum proc_pidonly pidonly;
};

enum proc_param {
	Opt_gid = 0,
	Opt_hidepid = 1,
	Opt_subset = 2,
};

enum kernfs_node_type {
	KERNFS_DIR = 1,
	KERNFS_FILE = 2,
	KERNFS_LINK = 4,
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

enum key_need_perm {
	KEY_NEED_UNSPECIFIED = 0,
	KEY_NEED_VIEW = 1,
	KEY_NEED_READ = 2,
	KEY_NEED_WRITE = 3,
	KEY_NEED_SEARCH = 4,
	KEY_NEED_LINK = 5,
	KEY_NEED_SETATTR = 6,
	KEY_NEED_UNLINK = 7,
	KEY_SYSADMIN_OVERRIDE = 8,
	KEY_AUTHTOKEN_OVERRIDE = 9,
	KEY_DEFER_PERM_CHECK = 10,
};

struct __key_reference_with_attributes;

typedef struct __key_reference_with_attributes *key_ref_t;

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

struct lsm_ctx {
	__u64 id;
	__u64 flags;
	__u64 len;
	__u64 ctx_len;
	__u8 ctx[0];
};

enum lsm_event {
	LSM_POLICY_CHANGE = 0,
};

struct lsm_id {
	const char *name;
	u64 id;
};

struct xattr;

typedef int (*initxattrs)(struct inode *, const struct xattr *, void *);

struct xattr {
	const char *name;
	void *value;
	size_t value_len;
};

enum kernel_load_data_id {
	LOADING_UNKNOWN = 0,
	LOADING_FIRMWARE = 1,
	LOADING_MODULE = 2,
	LOADING_KEXEC_IMAGE = 3,
	LOADING_KEXEC_INITRAMFS = 4,
	LOADING_POLICY = 5,
	LOADING_X509_CERTIFICATE = 6,
	LOADING_MAX_ID = 7,
};

struct msg_msg;

struct sembuf;

struct sctp_association;

struct xfrm_sec_ctx;

struct xfrm_user_sec_ctx;

union security_list_options {
	int (*binder_set_context_mgr)(const struct cred *);
	int (*binder_transaction)(const struct cred *, const struct cred *);
	int (*binder_transfer_binder)(const struct cred *, const struct cred *);
	int (*binder_transfer_file)(const struct cred *, const struct cred *, const struct file *);
	int (*ptrace_access_check)(struct task_struct *, unsigned int);
	int (*ptrace_traceme)(struct task_struct *);
	int (*capget)(const struct task_struct *, kernel_cap_t *, kernel_cap_t *, kernel_cap_t *);
	int (*capset)(struct cred *, const struct cred *, const kernel_cap_t *, const kernel_cap_t *, const kernel_cap_t *);
	int (*capable)(const struct cred *, struct user_namespace *, int, unsigned int);
	int (*quotactl)(int, int, int, const struct super_block *);
	int (*quota_on)(struct dentry *);
	int (*syslog)(int);
	int (*settime)(const struct timespec64 *, const struct timezone *);
	int (*vm_enough_memory)(struct mm_struct *, long int);
	int (*bprm_creds_for_exec)(struct linux_binprm *);
	int (*bprm_creds_from_file)(struct linux_binprm *, const struct file *);
	int (*bprm_check_security)(struct linux_binprm *);
	void (*bprm_committing_creds)(const struct linux_binprm *);
	void (*bprm_committed_creds)(const struct linux_binprm *);
	int (*fs_context_submount)(struct fs_context *, struct super_block *);
	int (*fs_context_dup)(struct fs_context *, struct fs_context *);
	int (*fs_context_parse_param)(struct fs_context *, struct fs_parameter *);
	int (*sb_alloc_security)(struct super_block *);
	void (*sb_delete)(struct super_block *);
	void (*sb_free_security)(struct super_block *);
	void (*sb_free_mnt_opts)(void *);
	int (*sb_eat_lsm_opts)(char *, void **);
	int (*sb_mnt_opts_compat)(struct super_block *, void *);
	int (*sb_remount)(struct super_block *, void *);
	int (*sb_kern_mount)(const struct super_block *);
	int (*sb_show_options)(struct seq_file *, struct super_block *);
	int (*sb_statfs)(struct dentry *);
	int (*sb_mount)(const char *, const struct path *, const char *, long unsigned int, void *);
	int (*sb_umount)(struct vfsmount *, int);
	int (*sb_pivotroot)(const struct path *, const struct path *);
	int (*sb_set_mnt_opts)(struct super_block *, void *, long unsigned int, long unsigned int *);
	int (*sb_clone_mnt_opts)(const struct super_block *, struct super_block *, long unsigned int, long unsigned int *);
	int (*move_mount)(const struct path *, const struct path *);
	int (*dentry_init_security)(struct dentry *, int, const struct qstr *, const char **, void **, u32 *);
	int (*dentry_create_files_as)(struct dentry *, int, struct qstr *, const struct cred *, struct cred *);
	int (*path_unlink)(const struct path *, struct dentry *);
	int (*path_mkdir)(const struct path *, struct dentry *, umode_t);
	int (*path_rmdir)(const struct path *, struct dentry *);
	int (*path_mknod)(const struct path *, struct dentry *, umode_t, unsigned int);
	void (*path_post_mknod)(struct mnt_idmap *, struct dentry *);
	int (*path_truncate)(const struct path *);
	int (*path_symlink)(const struct path *, struct dentry *, const char *);
	int (*path_link)(struct dentry *, const struct path *, struct dentry *);
	int (*path_rename)(const struct path *, struct dentry *, const struct path *, struct dentry *, unsigned int);
	int (*path_chmod)(const struct path *, umode_t);
	int (*path_chown)(const struct path *, kuid_t, kgid_t);
	int (*path_chroot)(const struct path *);
	int (*path_notify)(const struct path *, u64, unsigned int);
	int (*inode_alloc_security)(struct inode *);
	void (*inode_free_security)(struct inode *);
	int (*inode_init_security)(struct inode *, struct inode *, const struct qstr *, struct xattr *, int *);
	int (*inode_init_security_anon)(struct inode *, const struct qstr *, const struct inode *);
	int (*inode_create)(struct inode *, struct dentry *, umode_t);
	void (*inode_post_create_tmpfile)(struct mnt_idmap *, struct inode *);
	int (*inode_link)(struct dentry *, struct inode *, struct dentry *);
	int (*inode_unlink)(struct inode *, struct dentry *);
	int (*inode_symlink)(struct inode *, struct dentry *, const char *);
	int (*inode_mkdir)(struct inode *, struct dentry *, umode_t);
	int (*inode_rmdir)(struct inode *, struct dentry *);
	int (*inode_mknod)(struct inode *, struct dentry *, umode_t, dev_t);
	int (*inode_rename)(struct inode *, struct dentry *, struct inode *, struct dentry *);
	int (*inode_readlink)(struct dentry *);
	int (*inode_follow_link)(struct dentry *, struct inode *, bool);
	int (*inode_permission)(struct inode *, int);
	int (*inode_setattr)(struct mnt_idmap *, struct dentry *, struct iattr *);
	void (*inode_post_setattr)(struct mnt_idmap *, struct dentry *, int);
	int (*inode_getattr)(const struct path *);
	int (*inode_setxattr)(struct mnt_idmap *, struct dentry *, const char *, const void *, size_t, int);
	void (*inode_post_setxattr)(struct dentry *, const char *, const void *, size_t, int);
	int (*inode_getxattr)(struct dentry *, const char *);
	int (*inode_listxattr)(struct dentry *);
	int (*inode_removexattr)(struct mnt_idmap *, struct dentry *, const char *);
	void (*inode_post_removexattr)(struct dentry *, const char *);
	int (*inode_set_acl)(struct mnt_idmap *, struct dentry *, const char *, struct posix_acl *);
	void (*inode_post_set_acl)(struct dentry *, const char *, struct posix_acl *);
	int (*inode_get_acl)(struct mnt_idmap *, struct dentry *, const char *);
	int (*inode_remove_acl)(struct mnt_idmap *, struct dentry *, const char *);
	void (*inode_post_remove_acl)(struct mnt_idmap *, struct dentry *, const char *);
	int (*inode_need_killpriv)(struct dentry *);
	int (*inode_killpriv)(struct mnt_idmap *, struct dentry *);
	int (*inode_getsecurity)(struct mnt_idmap *, struct inode *, const char *, void **, bool);
	int (*inode_setsecurity)(struct inode *, const char *, const void *, size_t, int);
	int (*inode_listsecurity)(struct inode *, char *, size_t);
	void (*inode_getsecid)(struct inode *, u32 *);
	int (*inode_copy_up)(struct dentry *, struct cred **);
	int (*inode_copy_up_xattr)(const char *);
	int (*kernfs_init_security)(struct kernfs_node *, struct kernfs_node *);
	int (*file_permission)(struct file *, int);
	int (*file_alloc_security)(struct file *);
	void (*file_release)(struct file *);
	void (*file_free_security)(struct file *);
	int (*file_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*file_ioctl_compat)(struct file *, unsigned int, long unsigned int);
	int (*mmap_addr)(long unsigned int);
	int (*mmap_file)(struct file *, long unsigned int, long unsigned int, long unsigned int);
	int (*file_mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int);
	int (*file_lock)(struct file *, unsigned int);
	int (*file_fcntl)(struct file *, unsigned int, long unsigned int);
	void (*file_set_fowner)(struct file *);
	int (*file_send_sigiotask)(struct task_struct *, struct fown_struct *, int);
	int (*file_receive)(struct file *);
	int (*file_open)(struct file *);
	int (*file_post_open)(struct file *, int);
	int (*file_truncate)(struct file *);
	int (*task_alloc)(struct task_struct *, long unsigned int);
	void (*task_free)(struct task_struct *);
	int (*cred_alloc_blank)(struct cred *, gfp_t);
	void (*cred_free)(struct cred *);
	int (*cred_prepare)(struct cred *, const struct cred *, gfp_t);
	void (*cred_transfer)(struct cred *, const struct cred *);
	void (*cred_getsecid)(const struct cred *, u32 *);
	int (*kernel_act_as)(struct cred *, u32);
	int (*kernel_create_files_as)(struct cred *, struct inode *);
	int (*kernel_module_request)(char *);
	int (*kernel_load_data)(enum kernel_load_data_id, bool);
	int (*kernel_post_load_data)(char *, loff_t, enum kernel_load_data_id, char *);
	int (*kernel_read_file)(struct file *, enum kernel_read_file_id, bool);
	int (*kernel_post_read_file)(struct file *, char *, loff_t, enum kernel_read_file_id);
	int (*task_fix_setuid)(struct cred *, const struct cred *, int);
	int (*task_fix_setgid)(struct cred *, const struct cred *, int);
	int (*task_fix_setgroups)(struct cred *, const struct cred *);
	int (*task_setpgid)(struct task_struct *, pid_t);
	int (*task_getpgid)(struct task_struct *);
	int (*task_getsid)(struct task_struct *);
	void (*current_getsecid_subj)(u32 *);
	void (*task_getsecid_obj)(struct task_struct *, u32 *);
	int (*task_setnice)(struct task_struct *, int);
	int (*task_setioprio)(struct task_struct *, int);
	int (*task_getioprio)(struct task_struct *);
	int (*task_prlimit)(const struct cred *, const struct cred *, unsigned int);
	int (*task_setrlimit)(struct task_struct *, unsigned int, struct rlimit *);
	int (*task_setscheduler)(struct task_struct *);
	int (*task_getscheduler)(struct task_struct *);
	int (*task_movememory)(struct task_struct *);
	int (*task_kill)(struct task_struct *, struct kernel_siginfo *, int, const struct cred *);
	int (*task_prctl)(int, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	void (*task_to_inode)(struct task_struct *, struct inode *);
	int (*userns_create)(const struct cred *);
	int (*ipc_permission)(struct kern_ipc_perm *, short int);
	void (*ipc_getsecid)(struct kern_ipc_perm *, u32 *);
	int (*msg_msg_alloc_security)(struct msg_msg *);
	void (*msg_msg_free_security)(struct msg_msg *);
	int (*msg_queue_alloc_security)(struct kern_ipc_perm *);
	void (*msg_queue_free_security)(struct kern_ipc_perm *);
	int (*msg_queue_associate)(struct kern_ipc_perm *, int);
	int (*msg_queue_msgctl)(struct kern_ipc_perm *, int);
	int (*msg_queue_msgsnd)(struct kern_ipc_perm *, struct msg_msg *, int);
	int (*msg_queue_msgrcv)(struct kern_ipc_perm *, struct msg_msg *, struct task_struct *, long int, int);
	int (*shm_alloc_security)(struct kern_ipc_perm *);
	void (*shm_free_security)(struct kern_ipc_perm *);
	int (*shm_associate)(struct kern_ipc_perm *, int);
	int (*shm_shmctl)(struct kern_ipc_perm *, int);
	int (*shm_shmat)(struct kern_ipc_perm *, char *, int);
	int (*sem_alloc_security)(struct kern_ipc_perm *);
	void (*sem_free_security)(struct kern_ipc_perm *);
	int (*sem_associate)(struct kern_ipc_perm *, int);
	int (*sem_semctl)(struct kern_ipc_perm *, int);
	int (*sem_semop)(struct kern_ipc_perm *, struct sembuf *, unsigned int, int);
	int (*netlink_send)(struct sock *, struct sk_buff *);
	void (*d_instantiate)(struct dentry *, struct inode *);
	int (*getselfattr)(unsigned int, struct lsm_ctx *, u32 *, u32);
	int (*setselfattr)(unsigned int, struct lsm_ctx *, u32, u32);
	int (*getprocattr)(struct task_struct *, const char *, char **);
	int (*setprocattr)(const char *, void *, size_t);
	int (*ismaclabel)(const char *);
	int (*secid_to_secctx)(u32, char **, u32 *);
	int (*secctx_to_secid)(const char *, u32, u32 *);
	void (*release_secctx)(char *, u32);
	void (*inode_invalidate_secctx)(struct inode *);
	int (*inode_notifysecctx)(struct inode *, void *, u32);
	int (*inode_setsecctx)(struct dentry *, void *, u32);
	int (*inode_getsecctx)(struct inode *, void **, u32 *);
	int (*unix_stream_connect)(struct sock *, struct sock *, struct sock *);
	int (*unix_may_send)(struct socket *, struct socket *);
	int (*socket_create)(int, int, int, int);
	int (*socket_post_create)(struct socket *, int, int, int, int);
	int (*socket_socketpair)(struct socket *, struct socket *);
	int (*socket_bind)(struct socket *, struct sockaddr *, int);
	int (*socket_connect)(struct socket *, struct sockaddr *, int);
	int (*socket_listen)(struct socket *, int);
	int (*socket_accept)(struct socket *, struct socket *);
	int (*socket_sendmsg)(struct socket *, struct msghdr *, int);
	int (*socket_recvmsg)(struct socket *, struct msghdr *, int, int);
	int (*socket_getsockname)(struct socket *);
	int (*socket_getpeername)(struct socket *);
	int (*socket_getsockopt)(struct socket *, int, int);
	int (*socket_setsockopt)(struct socket *, int, int);
	int (*socket_shutdown)(struct socket *, int);
	int (*socket_sock_rcv_skb)(struct sock *, struct sk_buff *);
	int (*socket_getpeersec_stream)(struct socket *, sockptr_t, sockptr_t, unsigned int);
	int (*socket_getpeersec_dgram)(struct socket *, struct sk_buff *, u32 *);
	int (*sk_alloc_security)(struct sock *, int, gfp_t);
	void (*sk_free_security)(struct sock *);
	void (*sk_clone_security)(const struct sock *, struct sock *);
	void (*sk_getsecid)(const struct sock *, u32 *);
	void (*sock_graft)(struct sock *, struct socket *);
	int (*inet_conn_request)(const struct sock *, struct sk_buff *, struct request_sock *);
	void (*inet_csk_clone)(struct sock *, const struct request_sock *);
	void (*inet_conn_established)(struct sock *, struct sk_buff *);
	int (*secmark_relabel_packet)(u32);
	void (*secmark_refcount_inc)();
	void (*secmark_refcount_dec)();
	void (*req_classify_flow)(const struct request_sock *, struct flowi_common *);
	int (*tun_dev_alloc_security)(void **);
	void (*tun_dev_free_security)(void *);
	int (*tun_dev_create)();
	int (*tun_dev_attach_queue)(void *);
	int (*tun_dev_attach)(struct sock *, void *);
	int (*tun_dev_open)(void *);
	int (*sctp_assoc_request)(struct sctp_association *, struct sk_buff *);
	int (*sctp_bind_connect)(struct sock *, int, struct sockaddr *, int);
	void (*sctp_sk_clone)(struct sctp_association *, struct sock *, struct sock *);
	int (*sctp_assoc_established)(struct sctp_association *, struct sk_buff *);
	int (*mptcp_add_subflow)(struct sock *, struct sock *);
	int (*xfrm_policy_alloc_security)(struct xfrm_sec_ctx **, struct xfrm_user_sec_ctx *, gfp_t);
	int (*xfrm_policy_clone_security)(struct xfrm_sec_ctx *, struct xfrm_sec_ctx **);
	void (*xfrm_policy_free_security)(struct xfrm_sec_ctx *);
	int (*xfrm_policy_delete_security)(struct xfrm_sec_ctx *);
	int (*xfrm_state_alloc)(struct xfrm_state *, struct xfrm_user_sec_ctx *);
	int (*xfrm_state_alloc_acquire)(struct xfrm_state *, struct xfrm_sec_ctx *, u32);
	void (*xfrm_state_free_security)(struct xfrm_state *);
	int (*xfrm_state_delete_security)(struct xfrm_state *);
	int (*xfrm_policy_lookup)(struct xfrm_sec_ctx *, u32);
	int (*xfrm_state_pol_flow_match)(struct xfrm_state *, struct xfrm_policy *, const struct flowi_common *);
	int (*xfrm_decode_session)(struct sk_buff *, u32 *, int);
	int (*key_alloc)(struct key *, const struct cred *, long unsigned int);
	void (*key_free)(struct key *);
	int (*key_permission)(key_ref_t, const struct cred *, enum key_need_perm);
	int (*key_getsecurity)(struct key *, char **);
	void (*key_post_create_or_update)(struct key *, struct key *, const void *, size_t, long unsigned int, bool);
	int (*audit_rule_init)(u32, u32, char *, void **, gfp_t);
	int (*audit_rule_known)(struct audit_krule *);
	int (*audit_rule_match)(u32, u32, u32, void *);
	void (*audit_rule_free)(void *);
	int (*bpf)(int, union bpf_attr *, unsigned int);
	int (*bpf_map)(struct bpf_map *, fmode_t);
	int (*bpf_prog)(struct bpf_prog *);
	int (*bpf_map_create)(struct bpf_map *, union bpf_attr *, struct bpf_token *);
	void (*bpf_map_free)(struct bpf_map *);
	int (*bpf_prog_load)(struct bpf_prog *, union bpf_attr *, struct bpf_token *);
	void (*bpf_prog_free)(struct bpf_prog *);
	int (*bpf_token_create)(struct bpf_token *, union bpf_attr *, struct path *);
	void (*bpf_token_free)(struct bpf_token *);
	int (*bpf_token_cmd)(const struct bpf_token *, enum bpf_cmd);
	int (*bpf_token_capable)(const struct bpf_token *, int);
	int (*locked_down)(enum lockdown_reason);
	int (*perf_event_open)(struct perf_event_attr *, int);
	int (*perf_event_alloc)(struct perf_event *);
	void (*perf_event_free)(struct perf_event *);
	int (*perf_event_read)(struct perf_event *);
	int (*perf_event_write)(struct perf_event *);
	int (*uring_override_creds)(const struct cred *);
	int (*uring_sqpoll)();
	int (*uring_cmd)(struct io_uring_cmd *);
};

struct msg_msgseg;

struct msg_msg {
	struct list_head m_list;
	long int m_type;
	size_t m_ts;
	struct msg_msgseg *next;
	void *security;
};

struct security_hook_heads {
	struct hlist_head binder_set_context_mgr;
	struct hlist_head binder_transaction;
	struct hlist_head binder_transfer_binder;
	struct hlist_head binder_transfer_file;
	struct hlist_head ptrace_access_check;
	struct hlist_head ptrace_traceme;
	struct hlist_head capget;
	struct hlist_head capset;
	struct hlist_head capable;
	struct hlist_head quotactl;
	struct hlist_head quota_on;
	struct hlist_head syslog;
	struct hlist_head settime;
	struct hlist_head vm_enough_memory;
	struct hlist_head bprm_creds_for_exec;
	struct hlist_head bprm_creds_from_file;
	struct hlist_head bprm_check_security;
	struct hlist_head bprm_committing_creds;
	struct hlist_head bprm_committed_creds;
	struct hlist_head fs_context_submount;
	struct hlist_head fs_context_dup;
	struct hlist_head fs_context_parse_param;
	struct hlist_head sb_alloc_security;
	struct hlist_head sb_delete;
	struct hlist_head sb_free_security;
	struct hlist_head sb_free_mnt_opts;
	struct hlist_head sb_eat_lsm_opts;
	struct hlist_head sb_mnt_opts_compat;
	struct hlist_head sb_remount;
	struct hlist_head sb_kern_mount;
	struct hlist_head sb_show_options;
	struct hlist_head sb_statfs;
	struct hlist_head sb_mount;
	struct hlist_head sb_umount;
	struct hlist_head sb_pivotroot;
	struct hlist_head sb_set_mnt_opts;
	struct hlist_head sb_clone_mnt_opts;
	struct hlist_head move_mount;
	struct hlist_head dentry_init_security;
	struct hlist_head dentry_create_files_as;
	struct hlist_head path_unlink;
	struct hlist_head path_mkdir;
	struct hlist_head path_rmdir;
	struct hlist_head path_mknod;
	struct hlist_head path_post_mknod;
	struct hlist_head path_truncate;
	struct hlist_head path_symlink;
	struct hlist_head path_link;
	struct hlist_head path_rename;
	struct hlist_head path_chmod;
	struct hlist_head path_chown;
	struct hlist_head path_chroot;
	struct hlist_head path_notify;
	struct hlist_head inode_alloc_security;
	struct hlist_head inode_free_security;
	struct hlist_head inode_init_security;
	struct hlist_head inode_init_security_anon;
	struct hlist_head inode_create;
	struct hlist_head inode_post_create_tmpfile;
	struct hlist_head inode_link;
	struct hlist_head inode_unlink;
	struct hlist_head inode_symlink;
	struct hlist_head inode_mkdir;
	struct hlist_head inode_rmdir;
	struct hlist_head inode_mknod;
	struct hlist_head inode_rename;
	struct hlist_head inode_readlink;
	struct hlist_head inode_follow_link;
	struct hlist_head inode_permission;
	struct hlist_head inode_setattr;
	struct hlist_head inode_post_setattr;
	struct hlist_head inode_getattr;
	struct hlist_head inode_setxattr;
	struct hlist_head inode_post_setxattr;
	struct hlist_head inode_getxattr;
	struct hlist_head inode_listxattr;
	struct hlist_head inode_removexattr;
	struct hlist_head inode_post_removexattr;
	struct hlist_head inode_set_acl;
	struct hlist_head inode_post_set_acl;
	struct hlist_head inode_get_acl;
	struct hlist_head inode_remove_acl;
	struct hlist_head inode_post_remove_acl;
	struct hlist_head inode_need_killpriv;
	struct hlist_head inode_killpriv;
	struct hlist_head inode_getsecurity;
	struct hlist_head inode_setsecurity;
	struct hlist_head inode_listsecurity;
	struct hlist_head inode_getsecid;
	struct hlist_head inode_copy_up;
	struct hlist_head inode_copy_up_xattr;
	struct hlist_head kernfs_init_security;
	struct hlist_head file_permission;
	struct hlist_head file_alloc_security;
	struct hlist_head file_release;
	struct hlist_head file_free_security;
	struct hlist_head file_ioctl;
	struct hlist_head file_ioctl_compat;
	struct hlist_head mmap_addr;
	struct hlist_head mmap_file;
	struct hlist_head file_mprotect;
	struct hlist_head file_lock;
	struct hlist_head file_fcntl;
	struct hlist_head file_set_fowner;
	struct hlist_head file_send_sigiotask;
	struct hlist_head file_receive;
	struct hlist_head file_open;
	struct hlist_head file_post_open;
	struct hlist_head file_truncate;
	struct hlist_head task_alloc;
	struct hlist_head task_free;
	struct hlist_head cred_alloc_blank;
	struct hlist_head cred_free;
	struct hlist_head cred_prepare;
	struct hlist_head cred_transfer;
	struct hlist_head cred_getsecid;
	struct hlist_head kernel_act_as;
	struct hlist_head kernel_create_files_as;
	struct hlist_head kernel_module_request;
	struct hlist_head kernel_load_data;
	struct hlist_head kernel_post_load_data;
	struct hlist_head kernel_read_file;
	struct hlist_head kernel_post_read_file;
	struct hlist_head task_fix_setuid;
	struct hlist_head task_fix_setgid;
	struct hlist_head task_fix_setgroups;
	struct hlist_head task_setpgid;
	struct hlist_head task_getpgid;
	struct hlist_head task_getsid;
	struct hlist_head current_getsecid_subj;
	struct hlist_head task_getsecid_obj;
	struct hlist_head task_setnice;
	struct hlist_head task_setioprio;
	struct hlist_head task_getioprio;
	struct hlist_head task_prlimit;
	struct hlist_head task_setrlimit;
	struct hlist_head task_setscheduler;
	struct hlist_head task_getscheduler;
	struct hlist_head task_movememory;
	struct hlist_head task_kill;
	struct hlist_head task_prctl;
	struct hlist_head task_to_inode;
	struct hlist_head userns_create;
	struct hlist_head ipc_permission;
	struct hlist_head ipc_getsecid;
	struct hlist_head msg_msg_alloc_security;
	struct hlist_head msg_msg_free_security;
	struct hlist_head msg_queue_alloc_security;
	struct hlist_head msg_queue_free_security;
	struct hlist_head msg_queue_associate;
	struct hlist_head msg_queue_msgctl;
	struct hlist_head msg_queue_msgsnd;
	struct hlist_head msg_queue_msgrcv;
	struct hlist_head shm_alloc_security;
	struct hlist_head shm_free_security;
	struct hlist_head shm_associate;
	struct hlist_head shm_shmctl;
	struct hlist_head shm_shmat;
	struct hlist_head sem_alloc_security;
	struct hlist_head sem_free_security;
	struct hlist_head sem_associate;
	struct hlist_head sem_semctl;
	struct hlist_head sem_semop;
	struct hlist_head netlink_send;
	struct hlist_head d_instantiate;
	struct hlist_head getselfattr;
	struct hlist_head setselfattr;
	struct hlist_head getprocattr;
	struct hlist_head setprocattr;
	struct hlist_head ismaclabel;
	struct hlist_head secid_to_secctx;
	struct hlist_head secctx_to_secid;
	struct hlist_head release_secctx;
	struct hlist_head inode_invalidate_secctx;
	struct hlist_head inode_notifysecctx;
	struct hlist_head inode_setsecctx;
	struct hlist_head inode_getsecctx;
	struct hlist_head unix_stream_connect;
	struct hlist_head unix_may_send;
	struct hlist_head socket_create;
	struct hlist_head socket_post_create;
	struct hlist_head socket_socketpair;
	struct hlist_head socket_bind;
	struct hlist_head socket_connect;
	struct hlist_head socket_listen;
	struct hlist_head socket_accept;
	struct hlist_head socket_sendmsg;
	struct hlist_head socket_recvmsg;
	struct hlist_head socket_getsockname;
	struct hlist_head socket_getpeername;
	struct hlist_head socket_getsockopt;
	struct hlist_head socket_setsockopt;
	struct hlist_head socket_shutdown;
	struct hlist_head socket_sock_rcv_skb;
	struct hlist_head socket_getpeersec_stream;
	struct hlist_head socket_getpeersec_dgram;
	struct hlist_head sk_alloc_security;
	struct hlist_head sk_free_security;
	struct hlist_head sk_clone_security;
	struct hlist_head sk_getsecid;
	struct hlist_head sock_graft;
	struct hlist_head inet_conn_request;
	struct hlist_head inet_csk_clone;
	struct hlist_head inet_conn_established;
	struct hlist_head secmark_relabel_packet;
	struct hlist_head secmark_refcount_inc;
	struct hlist_head secmark_refcount_dec;
	struct hlist_head req_classify_flow;
	struct hlist_head tun_dev_alloc_security;
	struct hlist_head tun_dev_free_security;
	struct hlist_head tun_dev_create;
	struct hlist_head tun_dev_attach_queue;
	struct hlist_head tun_dev_attach;
	struct hlist_head tun_dev_open;
	struct hlist_head sctp_assoc_request;
	struct hlist_head sctp_bind_connect;
	struct hlist_head sctp_sk_clone;
	struct hlist_head sctp_assoc_established;
	struct hlist_head mptcp_add_subflow;
	struct hlist_head xfrm_policy_alloc_security;
	struct hlist_head xfrm_policy_clone_security;
	struct hlist_head xfrm_policy_free_security;
	struct hlist_head xfrm_policy_delete_security;
	struct hlist_head xfrm_state_alloc;
	struct hlist_head xfrm_state_alloc_acquire;
	struct hlist_head xfrm_state_free_security;
	struct hlist_head xfrm_state_delete_security;
	struct hlist_head xfrm_policy_lookup;
	struct hlist_head xfrm_state_pol_flow_match;
	struct hlist_head xfrm_decode_session;
	struct hlist_head key_alloc;
	struct hlist_head key_free;
	struct hlist_head key_permission;
	struct hlist_head key_getsecurity;
	struct hlist_head key_post_create_or_update;
	struct hlist_head audit_rule_init;
	struct hlist_head audit_rule_known;
	struct hlist_head audit_rule_match;
	struct hlist_head audit_rule_free;
	struct hlist_head bpf;
	struct hlist_head bpf_map;
	struct hlist_head bpf_prog;
	struct hlist_head bpf_map_create;
	struct hlist_head bpf_map_free;
	struct hlist_head bpf_prog_load;
	struct hlist_head bpf_prog_free;
	struct hlist_head bpf_token_create;
	struct hlist_head bpf_token_free;
	struct hlist_head bpf_token_cmd;
	struct hlist_head bpf_token_capable;
	struct hlist_head locked_down;
	struct hlist_head perf_event_open;
	struct hlist_head perf_event_alloc;
	struct hlist_head perf_event_free;
	struct hlist_head perf_event_read;
	struct hlist_head perf_event_write;
	struct hlist_head uring_override_creds;
	struct hlist_head uring_sqpoll;
	struct hlist_head uring_cmd;
};

struct security_hook_list {
	struct hlist_node list;
	struct hlist_head *head;
	union security_list_options hook;
	const struct lsm_id *lsmid;
};

struct lsm_blob_sizes {
	int lbs_cred;
	int lbs_file;
	int lbs_inode;
	int lbs_superblock;
	int lbs_ipc;
	int lbs_msg_msg;
	int lbs_task;
	int lbs_xattr_count;
};

enum lsm_order {
	LSM_ORDER_FIRST = -1,
	LSM_ORDER_MUTABLE = 0,
	LSM_ORDER_LAST = 1,
};

struct lsm_info {
	const char *name;
	enum lsm_order order;
	long unsigned int flags;
	int *enabled;
	int (*init)();
	struct lsm_blob_sizes *blobs;
};

enum fsnotify_data_type {
	FSNOTIFY_EVENT_NONE = 0,
	FSNOTIFY_EVENT_PATH = 1,
	FSNOTIFY_EVENT_INODE = 2,
	FSNOTIFY_EVENT_DENTRY = 3,
	FSNOTIFY_EVENT_ERROR = 4,
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

struct table_header {
	u16 td_id;
	u16 td_flags;
	u32 td_hilen;
	u32 td_lolen;
	char td_data[0];
};

struct aa_dfa {
	struct kref count;
	u16 flags;
	u32 max_oob;
	struct table_header *tables[8];
};

struct aa_str_table {
	int size;
	char **table;
};

struct rhash_lock_head;

struct bucket_table {
	unsigned int size;
	unsigned int nest;
	u32 hash_rnd;
	struct list_head walkers;
	struct callback_head rcu;
	struct bucket_table *future_tbl;
	struct lockdep_map dep_map;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct rhash_lock_head *buckets[0];
};

struct rhash_lock_head {};

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_proto;
};

struct ethtool_drvinfo {
	__u32 cmd;
	char driver[32];
	char version[32];
	char fw_version[32];
	char bus_info[32];
	char erom_version[32];
	char reserved2[12];
	__u32 n_priv_flags;
	__u32 n_stats;
	__u32 testinfo_len;
	__u32 eedump_len;
	__u32 regdump_len;
};

struct ethtool_wolinfo {
	__u32 cmd;
	__u32 supported;
	__u32 wolopts;
	__u8 sopass[6];
};

struct ethtool_tunable {
	__u32 cmd;
	__u32 id;
	__u32 type_id;
	__u32 len;
	void *data[0];
};

struct ethtool_regs {
	__u32 cmd;
	__u32 version;
	__u32 len;
	__u8 data[0];
};

struct ethtool_eeprom {
	__u32 cmd;
	__u32 magic;
	__u32 offset;
	__u32 len;
	__u8 data[0];
};

struct ethtool_modinfo {
	__u32 cmd;
	__u32 type;
	__u32 eeprom_len;
	__u32 reserved[8];
};

struct ethtool_coalesce {
	__u32 cmd;
	__u32 rx_coalesce_usecs;
	__u32 rx_max_coalesced_frames;
	__u32 rx_coalesce_usecs_irq;
	__u32 rx_max_coalesced_frames_irq;
	__u32 tx_coalesce_usecs;
	__u32 tx_max_coalesced_frames;
	__u32 tx_coalesce_usecs_irq;
	__u32 tx_max_coalesced_frames_irq;
	__u32 stats_block_coalesce_usecs;
	__u32 use_adaptive_rx_coalesce;
	__u32 use_adaptive_tx_coalesce;
	__u32 pkt_rate_low;
	__u32 rx_coalesce_usecs_low;
	__u32 rx_max_coalesced_frames_low;
	__u32 tx_coalesce_usecs_low;
	__u32 tx_max_coalesced_frames_low;
	__u32 pkt_rate_high;
	__u32 rx_coalesce_usecs_high;
	__u32 rx_max_coalesced_frames_high;
	__u32 tx_coalesce_usecs_high;
	__u32 tx_max_coalesced_frames_high;
	__u32 rate_sample_interval;
};

struct ethtool_ringparam {
	__u32 cmd;
	__u32 rx_max_pending;
	__u32 rx_mini_max_pending;
	__u32 rx_jumbo_max_pending;
	__u32 tx_max_pending;
	__u32 rx_pending;
	__u32 rx_mini_pending;
	__u32 rx_jumbo_pending;
	__u32 tx_pending;
};

struct ethtool_channels {
	__u32 cmd;
	__u32 max_rx;
	__u32 max_tx;
	__u32 max_other;
	__u32 max_combined;
	__u32 rx_count;
	__u32 tx_count;
	__u32 other_count;
	__u32 combined_count;
};

struct ethtool_pauseparam {
	__u32 cmd;
	__u32 autoneg;
	__u32 rx_pause;
	__u32 tx_pause;
};

enum ethtool_link_ext_state {
	ETHTOOL_LINK_EXT_STATE_AUTONEG = 0,
	ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE = 1,
	ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH = 2,
	ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY = 3,
	ETHTOOL_LINK_EXT_STATE_NO_CABLE = 4,
	ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE = 5,
	ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE = 6,
	ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE = 7,
	ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED = 8,
	ETHTOOL_LINK_EXT_STATE_OVERHEAT = 9,
	ETHTOOL_LINK_EXT_STATE_MODULE = 10,
};

enum ethtool_link_ext_substate_autoneg {
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE = 4,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE = 5,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD = 6,
};

enum ethtool_link_ext_substate_link_training {
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT = 4,
};

enum ethtool_link_ext_substate_link_logical_mismatch {
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED = 4,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED = 5,
};

enum ethtool_link_ext_substate_bad_signal_integrity {
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS = 4,
};

enum ethtool_link_ext_substate_cable_issue {
	ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE = 2,
};

enum ethtool_link_ext_substate_module {
	ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY = 1,
};

enum ethtool_mac_stats_src {
	ETHTOOL_MAC_STATS_SRC_AGGREGATE = 0,
	ETHTOOL_MAC_STATS_SRC_EMAC = 1,
	ETHTOOL_MAC_STATS_SRC_PMAC = 2,
};

enum ethtool_module_power_mode_policy {
	ETHTOOL_MODULE_POWER_MODE_POLICY_HIGH = 1,
	ETHTOOL_MODULE_POWER_MODE_POLICY_AUTO = 2,
};

enum ethtool_module_power_mode {
	ETHTOOL_MODULE_POWER_MODE_LOW = 1,
	ETHTOOL_MODULE_POWER_MODE_HIGH = 2,
};

enum ethtool_mm_verify_status {
	ETHTOOL_MM_VERIFY_STATUS_UNKNOWN = 0,
	ETHTOOL_MM_VERIFY_STATUS_INITIAL = 1,
	ETHTOOL_MM_VERIFY_STATUS_VERIFYING = 2,
	ETHTOOL_MM_VERIFY_STATUS_SUCCEEDED = 3,
	ETHTOOL_MM_VERIFY_STATUS_FAILED = 4,
	ETHTOOL_MM_VERIFY_STATUS_DISABLED = 5,
};

struct ethtool_test {
	__u32 cmd;
	__u32 flags;
	__u32 reserved;
	__u32 len;
	__u64 data[0];
};

struct ethtool_stats {
	__u32 cmd;
	__u32 n_stats;
	__u64 data[0];
};

struct ethtool_tcpip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be16 psrc;
	__be16 pdst;
	__u8 tos;
};

struct ethtool_ah_espip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be32 spi;
	__u8 tos;
};

struct ethtool_usrip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be32 l4_4_bytes;
	__u8 tos;
	__u8 ip_ver;
	__u8 proto;
};

struct ethtool_tcpip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be16 psrc;
	__be16 pdst;
	__u8 tclass;
};

struct ethtool_ah_espip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be32 spi;
	__u8 tclass;
};

struct ethtool_usrip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be32 l4_4_bytes;
	__u8 tclass;
	__u8 l4_proto;
};

union ethtool_flow_union {
	struct ethtool_tcpip4_spec tcp_ip4_spec;
	struct ethtool_tcpip4_spec udp_ip4_spec;
	struct ethtool_tcpip4_spec sctp_ip4_spec;
	struct ethtool_ah_espip4_spec ah_ip4_spec;
	struct ethtool_ah_espip4_spec esp_ip4_spec;
	struct ethtool_usrip4_spec usr_ip4_spec;
	struct ethtool_tcpip6_spec tcp_ip6_spec;
	struct ethtool_tcpip6_spec udp_ip6_spec;
	struct ethtool_tcpip6_spec sctp_ip6_spec;
	struct ethtool_ah_espip6_spec ah_ip6_spec;
	struct ethtool_ah_espip6_spec esp_ip6_spec;
	struct ethtool_usrip6_spec usr_ip6_spec;
	struct ethhdr ether_spec;
	__u8 hdata[52];
};

struct ethtool_flow_ext {
	__u8 padding[2];
	unsigned char h_dest[6];
	__be16 vlan_etype;
	__be16 vlan_tci;
	__be32 data[2];
};

struct ethtool_rx_flow_spec {
	__u32 flow_type;
	union ethtool_flow_union h_u;
	struct ethtool_flow_ext h_ext;
	union ethtool_flow_union m_u;
	struct ethtool_flow_ext m_ext;
	__u64 ring_cookie;
	__u32 location;
};

struct ethtool_rxnfc {
	__u32 cmd;
	__u32 flow_type;
	__u64 data;
	struct ethtool_rx_flow_spec fs;
	union {
		__u32 rule_cnt;
		__u32 rss_context;
	};
	__u32 rule_locs[0];
};

struct ethtool_flash {
	__u32 cmd;
	__u32 region;
	char data[128];
};

struct ethtool_dump {
	__u32 cmd;
	__u32 version;
	__u32 flag;
	__u32 len;
	__u8 data[0];
};

struct ethtool_ts_info {
	__u32 cmd;
	__u32 so_timestamping;
	__s32 phc_index;
	__u32 tx_types;
	__u32 tx_reserved[3];
	__u32 rx_filters;
	__u32 rx_reserved[3];
};

struct ethtool_fecparam {
	__u32 cmd;
	__u32 active_fec;
	__u32 fec;
	__u32 reserved;
};

struct ethtool_link_settings {
	__u32 cmd;
	__u32 speed;
	__u8 duplex;
	__u8 port;
	__u8 phy_address;
	__u8 autoneg;
	__u8 mdio_support;
	__u8 eth_tp_mdix;
	__u8 eth_tp_mdix_ctrl;
	__s8 link_mode_masks_nwords;
	__u8 transceiver;
	__u8 master_slave_cfg;
	__u8 master_slave_state;
	__u8 rate_matching;
	__u32 reserved[7];
	__u32 link_mode_masks[0];
};

struct kernel_ethtool_ringparam {
	u32 rx_buf_len;
	u8 tcp_data_split;
	u8 tx_push;
	u8 rx_push;
	u32 cqe_size;
	u32 tx_push_buf_len;
	u32 tx_push_buf_max_len;
};

struct ethtool_link_ext_state_info {
	enum ethtool_link_ext_state link_ext_state;
	union {
		enum ethtool_link_ext_substate_autoneg autoneg;
		enum ethtool_link_ext_substate_link_training link_training;
		enum ethtool_link_ext_substate_link_logical_mismatch link_logical_mismatch;
		enum ethtool_link_ext_substate_bad_signal_integrity bad_signal_integrity;
		enum ethtool_link_ext_substate_cable_issue cable_issue;
		enum ethtool_link_ext_substate_module module;
		u32 __link_ext_substate;
	};
};

struct ethtool_link_ext_stats {
	u64 link_down_events;
};

struct ethtool_link_ksettings {
	struct ethtool_link_settings base;
	struct {
		long unsigned int supported[2];
		long unsigned int advertising[2];
		long unsigned int lp_advertising[2];
	} link_modes;
	u32 lanes;
};

struct ethtool_keee {
	long unsigned int supported[2];
	long unsigned int advertised[2];
	long unsigned int lp_advertised[2];
	u32 tx_lpi_timer;
	bool tx_lpi_enabled;
	bool eee_active;
	bool eee_enabled;
};

struct kernel_ethtool_coalesce {
	u8 use_cqe_mode_tx;
	u8 use_cqe_mode_rx;
	u32 tx_aggr_max_bytes;
	u32 tx_aggr_max_frames;
	u32 tx_aggr_time_usecs;
};

struct ethtool_eth_mac_stats {
	enum ethtool_mac_stats_src src;
	union {
		struct {
			u64 FramesTransmittedOK;
			u64 SingleCollisionFrames;
			u64 MultipleCollisionFrames;
			u64 FramesReceivedOK;
			u64 FrameCheckSequenceErrors;
			u64 AlignmentErrors;
			u64 OctetsTransmittedOK;
			u64 FramesWithDeferredXmissions;
			u64 LateCollisions;
			u64 FramesAbortedDueToXSColls;
			u64 FramesLostDueToIntMACXmitError;
			u64 CarrierSenseErrors;
			u64 OctetsReceivedOK;
			u64 FramesLostDueToIntMACRcvError;
			u64 MulticastFramesXmittedOK;
			u64 BroadcastFramesXmittedOK;
			u64 FramesWithExcessiveDeferral;
			u64 MulticastFramesReceivedOK;
			u64 BroadcastFramesReceivedOK;
			u64 InRangeLengthErrors;
			u64 OutOfRangeLengthField;
			u64 FrameTooLongErrors;
		};
		struct {
			u64 FramesTransmittedOK;
			u64 SingleCollisionFrames;
			u64 MultipleCollisionFrames;
			u64 FramesReceivedOK;
			u64 FrameCheckSequenceErrors;
			u64 AlignmentErrors;
			u64 OctetsTransmittedOK;
			u64 FramesWithDeferredXmissions;
			u64 LateCollisions;
			u64 FramesAbortedDueToXSColls;
			u64 FramesLostDueToIntMACXmitError;
			u64 CarrierSenseErrors;
			u64 OctetsReceivedOK;
			u64 FramesLostDueToIntMACRcvError;
			u64 MulticastFramesXmittedOK;
			u64 BroadcastFramesXmittedOK;
			u64 FramesWithExcessiveDeferral;
			u64 MulticastFramesReceivedOK;
			u64 BroadcastFramesReceivedOK;
			u64 InRangeLengthErrors;
			u64 OutOfRangeLengthField;
			u64 FrameTooLongErrors;
		} stats;
	};
};

struct ethtool_eth_phy_stats {
	enum ethtool_mac_stats_src src;
	union {
		struct {
			u64 SymbolErrorDuringCarrier;
		};
		struct {
			u64 SymbolErrorDuringCarrier;
		} stats;
	};
};

struct ethtool_eth_ctrl_stats {
	enum ethtool_mac_stats_src src;
	union {
		struct {
			u64 MACControlFramesTransmitted;
			u64 MACControlFramesReceived;
			u64 UnsupportedOpcodesReceived;
		};
		struct {
			u64 MACControlFramesTransmitted;
			u64 MACControlFramesReceived;
			u64 UnsupportedOpcodesReceived;
		} stats;
	};
};

struct ethtool_pause_stats {
	enum ethtool_mac_stats_src src;
	union {
		struct {
			u64 tx_pause_frames;
			u64 rx_pause_frames;
		};
		struct {
			u64 tx_pause_frames;
			u64 rx_pause_frames;
		} stats;
	};
};

struct ethtool_fec_stat {
	u64 total;
	u64 lanes[8];
};

struct ethtool_fec_stats {
	struct ethtool_fec_stat corrected_blocks;
	struct ethtool_fec_stat uncorrectable_blocks;
	struct ethtool_fec_stat corrected_bits;
};

struct ethtool_rmon_hist_range {
	u16 low;
	u16 high;
};

struct ethtool_rmon_stats {
	enum ethtool_mac_stats_src src;
	union {
		struct {
			u64 undersize_pkts;
			u64 oversize_pkts;
			u64 fragments;
			u64 jabbers;
			u64 hist[10];
			u64 hist_tx[10];
		};
		struct {
			u64 undersize_pkts;
			u64 oversize_pkts;
			u64 fragments;
			u64 jabbers;
			u64 hist[10];
			u64 hist_tx[10];
		} stats;
	};
};

struct ethtool_module_eeprom {
	u32 offset;
	u32 length;
	u8 page;
	u8 bank;
	u8 i2c_address;
	u8 *data;
};

struct ethtool_module_power_mode_params {
	enum ethtool_module_power_mode_policy policy;
	enum ethtool_module_power_mode mode;
};

struct ethtool_mm_state {
	u32 verify_time;
	u32 max_verify_time;
	enum ethtool_mm_verify_status verify_status;
	bool tx_enabled;
	bool tx_active;
	bool pmac_enabled;
	bool verify_enabled;
	u32 tx_min_frag_size;
	u32 rx_min_frag_size;
};

struct ethtool_mm_cfg {
	u32 verify_time;
	bool verify_enabled;
	bool tx_enabled;
	bool pmac_enabled;
	u32 tx_min_frag_size;
};

struct ethtool_mm_stats {
	u64 MACMergeFrameAssErrorCount;
	u64 MACMergeFrameSmdErrorCount;
	u64 MACMergeFrameAssOkCount;
	u64 MACMergeFragCountRx;
	u64 MACMergeFragCountTx;
	u64 MACMergeHoldCount;
};

struct ethtool_rxfh_param {
	u8 hfunc;
	u32 indir_size;
	u32 *indir;
	u32 key_size;
	u8 *key;
	u32 rss_context;
	u8 rss_delete;
	u8 input_xfrm;
};

struct aa_perms {
	u32 allow;
	u32 deny;
	u32 subtree;
	u32 cond;
	u32 kill;
	u32 complain;
	u32 prompt;
	u32 audit;
	u32 quiet;
	u32 hide;
	u32 xindex;
	u32 tag;
	u32 label;
};

struct aa_policydb {
	struct kref count;
	struct aa_dfa *dfa;
	struct {
		struct aa_perms *perms;
		u32 size;
	};
	struct aa_str_table trans;
	unsigned int start[33];
};

struct crypto_alg;

struct crypto_tfm {
	refcount_t refcnt;
	u32 crt_flags;
	int node;
	void (*exit)(struct crypto_tfm *);
	struct crypto_alg *__crt_alg;
	void *__crt_ctx[0];
};

struct cipher_alg {
	unsigned int cia_min_keysize;
	unsigned int cia_max_keysize;
	int (*cia_setkey)(struct crypto_tfm *, const u8 *, unsigned int);
	void (*cia_encrypt)(struct crypto_tfm *, u8 *, const u8 *);
	void (*cia_decrypt)(struct crypto_tfm *, u8 *, const u8 *);
};

struct compress_alg {
	int (*coa_compress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
	int (*coa_decompress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
};

struct crypto_type;

struct crypto_alg {
	struct list_head cra_list;
	struct list_head cra_users;
	u32 cra_flags;
	unsigned int cra_blocksize;
	unsigned int cra_ctxsize;
	unsigned int cra_alignmask;
	int cra_priority;
	refcount_t cra_refcnt;
	char cra_name[128];
	char cra_driver_name[128];
	const struct crypto_type *cra_type;
	union {
		struct cipher_alg cipher;
		struct compress_alg compress;
	} cra_u;
	int (*cra_init)(struct crypto_tfm *);
	void (*cra_exit)(struct crypto_tfm *);
	void (*cra_destroy)(struct crypto_alg *);
	struct module *cra_module;
};

struct crypto_instance;

struct crypto_type {
	unsigned int (*ctxsize)(struct crypto_alg *, u32, u32);
	unsigned int (*extsize)(struct crypto_alg *);
	int (*init_tfm)(struct crypto_tfm *);
	void (*show)(struct seq_file *, struct crypto_alg *);
	int (*report)(struct sk_buff *, struct crypto_alg *);
	void (*free)(struct crypto_instance *);
	unsigned int type;
	unsigned int maskclear;
	unsigned int maskset;
	unsigned int tfmsize;
};

struct crypto_template;

struct crypto_spawn;

struct crypto_instance {
	struct crypto_alg alg;
	struct crypto_template *tmpl;
	union {
		struct hlist_node list;
		struct crypto_spawn *spawns;
	};
	struct work_struct free_work;
	void *__ctx[0];
};

struct crypto_spawn {
	struct list_head list;
	struct crypto_alg *alg;
	union {
		struct crypto_instance *inst;
		struct crypto_spawn *next;
	};
	const struct crypto_type *frontend;
	u32 mask;
	bool dead;
	bool registered;
};

struct rtattr;

struct crypto_template {
	struct list_head list;
	struct hlist_head instances;
	struct module *module;
	int (*create)(struct crypto_template *, struct rtattr **);
	char name[128];
};

struct crypto_cipher {
	struct crypto_tfm base;
};

enum asn1_class {
	ASN1_UNIV = 0,
	ASN1_APPL = 1,
	ASN1_CONT = 2,
	ASN1_PRIV = 3,
};

enum asn1_method {
	ASN1_PRIM = 0,
	ASN1_CONS = 1,
};

enum asn1_tag {
	ASN1_EOC = 0,
	ASN1_BOOL = 1,
	ASN1_INT = 2,
	ASN1_BTS = 3,
	ASN1_OTS = 4,
	ASN1_NULL = 5,
	ASN1_OID = 6,
	ASN1_ODE = 7,
	ASN1_EXT = 8,
	ASN1_REAL = 9,
	ASN1_ENUM = 10,
	ASN1_EPDV = 11,
	ASN1_UTF8STR = 12,
	ASN1_RELOID = 13,
	ASN1_SEQ = 16,
	ASN1_SET = 17,
	ASN1_NUMSTR = 18,
	ASN1_PRNSTR = 19,
	ASN1_TEXSTR = 20,
	ASN1_VIDSTR = 21,
	ASN1_IA5STR = 22,
	ASN1_UNITIM = 23,
	ASN1_GENTIM = 24,
	ASN1_GRASTR = 25,
	ASN1_VISSTR = 26,
	ASN1_GENSTR = 27,
	ASN1_UNISTR = 28,
	ASN1_CHRSTR = 29,
	ASN1_BMPSTR = 30,
	ASN1_LONG_TAG = 31,
};

typedef int (*asn1_action_t)(void *, size_t, unsigned char, const void *, size_t);

struct asn1_decoder {
	const unsigned char *machine;
	size_t machlen;
	const asn1_action_t *actions;
};

enum asn1_opcode {
	ASN1_OP_MATCH = 0,
	ASN1_OP_MATCH_OR_SKIP = 1,
	ASN1_OP_MATCH_ACT = 2,
	ASN1_OP_MATCH_ACT_OR_SKIP = 3,
	ASN1_OP_MATCH_JUMP = 4,
	ASN1_OP_MATCH_JUMP_OR_SKIP = 5,
	ASN1_OP_MATCH_ANY = 8,
	ASN1_OP_MATCH_ANY_OR_SKIP = 9,
	ASN1_OP_MATCH_ANY_ACT = 10,
	ASN1_OP_MATCH_ANY_ACT_OR_SKIP = 11,
	ASN1_OP_COND_MATCH_OR_SKIP = 17,
	ASN1_OP_COND_MATCH_ACT_OR_SKIP = 19,
	ASN1_OP_COND_MATCH_JUMP_OR_SKIP = 21,
	ASN1_OP_COND_MATCH_ANY = 24,
	ASN1_OP_COND_MATCH_ANY_OR_SKIP = 25,
	ASN1_OP_COND_MATCH_ANY_ACT = 26,
	ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP = 27,
	ASN1_OP_COND_FAIL = 28,
	ASN1_OP_COMPLETE = 29,
	ASN1_OP_ACT = 30,
	ASN1_OP_MAYBE_ACT = 31,
	ASN1_OP_END_SEQ = 32,
	ASN1_OP_END_SET = 33,
	ASN1_OP_END_SEQ_OF = 34,
	ASN1_OP_END_SET_OF = 35,
	ASN1_OP_END_SEQ_ACT = 36,
	ASN1_OP_END_SET_ACT = 37,
	ASN1_OP_END_SEQ_OF_ACT = 38,
	ASN1_OP_END_SET_OF_ACT = 39,
	ASN1_OP_RETURN = 40,
	ASN1_OP__NR = 41,
};

enum rsapubkey_actions {
	ACT_rsa_get_e = 0,
	ACT_rsa_get_n = 1,
	NR__rsapubkey_actions = 2,
};

typedef void (*exitcall_t)();

struct hash_alg_common {
	unsigned int digestsize;
	unsigned int statesize;
	struct crypto_alg base;
};

struct crypto_shash;

struct shash_desc {
	struct crypto_shash *tfm;
	void *__ctx[0];
};

struct crypto_shash {
	unsigned int descsize;
	struct crypto_tfm base;
};

struct shash_alg {
	int (*init)(struct shash_desc *);
	int (*update)(struct shash_desc *, const u8 *, unsigned int);
	int (*final)(struct shash_desc *, u8 *);
	int (*finup)(struct shash_desc *, const u8 *, unsigned int, u8 *);
	int (*digest)(struct shash_desc *, const u8 *, unsigned int, u8 *);
	int (*export)(struct shash_desc *, void *);
	int (*import)(struct shash_desc *, const void *);
	int (*setkey)(struct crypto_shash *, const u8 *, unsigned int);
	int (*init_tfm)(struct crypto_shash *);
	void (*exit_tfm)(struct crypto_shash *);
	int (*clone_tfm)(struct crypto_shash *, struct crypto_shash *);
	unsigned int descsize;
	union {
		struct {
			unsigned int digestsize;
			unsigned int statesize;
			struct crypto_alg base;
		};
		struct hash_alg_common halg;
	};
};

struct sha1_state {
	u32 state[5];
	u64 count;
	u8 buffer[64];
};

typedef void sha1_block_fn(struct sha1_state *, const u8 *, int);

struct request;

struct blk_plug {
	struct request *mq_list;
	struct request *cached_rq;
	u64 cur_ktime;
	short unsigned int nr_ios;
	short unsigned int rq_count;
	bool multiple_queues;
	bool has_elevator;
	struct list_head cb_list;
};

typedef unsigned int blk_mode_t;

struct block_device_operations;

struct timer_rand_state;

struct disk_events;

struct cdrom_device_info;

struct badblocks;

struct blk_independent_access_ranges;

struct gendisk {
	int major;
	int first_minor;
	int minors;
	char disk_name[32];
	short unsigned int events;
	short unsigned int event_flags;
	struct xarray part_tbl;
	struct block_device *part0;
	const struct block_device_operations *fops;
	struct request_queue *queue;
	void *private_data;
	struct bio_set bio_split;
	int flags;
	long unsigned int state;
	struct mutex open_mutex;
	unsigned int open_partitions;
	struct backing_dev_info *bdi;
	struct kobject queue_kobj;
	struct kobject *slave_dir;
	struct list_head slave_bdevs;
	struct timer_rand_state *random;
	atomic_t sync_io;
	struct disk_events *ev;
	unsigned int nr_zones;
	long unsigned int *conv_zones_bitmap;
	long unsigned int *seq_zones_wlock;
	struct cdrom_device_info *cdi;
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
	u64 diskseq;
	blk_mode_t open_mode;
	struct blk_independent_access_ranges *ia_ranges;
};

enum blk_bounce {
	BLK_BOUNCE_NONE = 0,
	BLK_BOUNCE_HIGH = 1,
};

struct queue_limits {
	enum blk_bounce bounce;
	long unsigned int seg_boundary_mask;
	long unsigned int virt_boundary_mask;
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
	short unsigned int max_segments;
	short unsigned int max_integrity_segments;
	short unsigned int max_discard_segments;
	unsigned char misaligned;
	unsigned char discard_misaligned;
	unsigned char raid_partial_stripes_expensive;
	bool zoned;
	unsigned int max_open_zones;
	unsigned int max_active_zones;
	unsigned int dma_alignment;
};

struct blk_integrity_profile;

struct blk_integrity {
	const struct blk_integrity_profile *profile;
	unsigned char flags;
	unsigned char tuple_size;
	unsigned char pi_offset;
	unsigned char interval_exp;
	unsigned char tag_size;
};

struct elevator_queue;

struct blk_mq_ops;

struct blk_mq_ctx;

struct blk_queue_stats;

struct rq_qos;

struct blk_mq_tags;

struct blk_trace;

struct blk_flush_queue;

struct throtl_data;

struct blk_mq_tag_set;

struct request_queue {
	void *queuedata;
	struct elevator_queue *elevator;
	const struct blk_mq_ops *mq_ops;
	struct blk_mq_ctx *queue_ctx;
	long unsigned int queue_flags;
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
	struct blk_integrity integrity;
	struct device *dev;
	enum rpm_status rpm_status;
	atomic_t pm_only;
	struct blk_queue_stats *stats;
	struct rq_qos *rq_qos;
	struct mutex rq_qos_mutex;
	int id;
	unsigned int dma_pad_mask;
	long unsigned int nr_requests;
	struct timer_list timeout;
	struct work_struct timeout_work;
	atomic_t nr_active_requests_shared_tags;
	unsigned int required_elevator_features;
	struct blk_mq_tags *sched_shared_tags;
	struct list_head icq_list;
	long unsigned int blkcg_pols[1];
	struct blkcg_gq *root_blkg;
	struct list_head blkg_list;
	struct mutex blkcg_mutex;
	int node;
	spinlock_t requeue_lock;
	struct list_head requeue_list;
	struct delayed_work requeue_work;
	struct blk_trace *blk_trace;
	struct blk_flush_queue *fq;
	struct list_head flush_list;
	struct mutex sysfs_lock;
	struct mutex sysfs_dir_lock;
	struct mutex limits_lock;
	struct list_head unused_hctx_list;
	spinlock_t unused_hctx_lock;
	int mq_freeze_depth;
	struct throtl_data *td;
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

struct io_comp_batch {
	struct request *req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};

typedef u32 compat_caddr_t;

struct partition_meta_info {
	char uuid[37];
	u8 volname[64];
};

typedef __u32 blk_mq_req_flags_t;

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

struct sbitmap_word {
	long unsigned int word;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long unsigned int cleared;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct sbitmap {
	unsigned int depth;
	unsigned int shift;
	unsigned int map_nr;
	bool round_robin;
	struct sbitmap_word *map;
	unsigned int *alloc_hint;
};

struct sbq_wait_state {
	wait_queue_head_t wait;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct sbitmap_queue {
	struct sbitmap sb;
	unsigned int wake_batch;
	atomic_t wake_index;
	struct sbq_wait_state *ws;
	atomic_t ws_active;
	unsigned int min_shallow_depth;
	atomic_t completion_cnt;
	atomic_t wakeup_cnt;
};

struct blk_integrity_iter;

typedef blk_status_t integrity_processing_fn(struct blk_integrity_iter *);

typedef void integrity_prepare_fn(struct request *);

typedef void integrity_complete_fn(struct request *, unsigned int);

struct blk_integrity_profile {
	integrity_processing_fn *generate_fn;
	integrity_processing_fn *verify_fn;
	integrity_prepare_fn *prepare_fn;
	integrity_complete_fn *complete_fn;
	const char *name;
};

typedef int (*report_zones_cb)(struct blk_zone *, unsigned int, void *);

enum blk_unique_id {
	BLK_UID_T10 = 1,
	BLK_UID_EUI64 = 2,
	BLK_UID_NAA = 3,
};

struct hd_geometry;

struct pr_ops;

struct block_device_operations {
	void (*submit_bio)(struct bio *);
	int (*poll_bio)(struct bio *, struct io_comp_batch *, unsigned int);
	int (*open)(struct gendisk *, blk_mode_t);
	void (*release)(struct gendisk *);
	int (*ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	unsigned int (*check_events)(struct gendisk *, unsigned int);
	void (*unlock_native_capacity)(struct gendisk *);
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	int (*set_read_only)(struct block_device *, bool);
	void (*free_disk)(struct gendisk *);
	void (*swap_slot_free_notify)(struct block_device *, long unsigned int);
	int (*report_zones)(struct gendisk *, sector_t, unsigned int, report_zones_cb, void *);
	char * (*devnode)(struct gendisk *, umode_t *);
	int (*get_unique_id)(struct gendisk *, u8 *, enum blk_unique_id);
	struct module *owner;
	const struct pr_ops *pr_ops;
	int (*alternative_gpt_sector)(struct gendisk *, sector_t *);
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

enum blk_eh_timer_return {
	BLK_EH_DONE = 0,
	BLK_EH_RESET_TIMER = 1,
};

struct blk_mq_hw_ctx;

struct blk_mq_queue_data;

struct blk_mq_ops {
	blk_status_t (*queue_rq)(struct blk_mq_hw_ctx *, const struct blk_mq_queue_data *);
	void (*commit_rqs)(struct blk_mq_hw_ctx *);
	void (*queue_rqs)(struct request **);
	int (*get_budget)(struct request_queue *);
	void (*put_budget)(struct request_queue *, int);
	void (*set_rq_budget_token)(struct request *, int);
	int (*get_rq_budget_token)(struct request *);
	enum blk_eh_timer_return (*timeout)(struct request *);
	int (*poll)(struct blk_mq_hw_ctx *, struct io_comp_batch *);
	void (*complete)(struct request *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, void *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	int (*init_request)(struct blk_mq_tag_set *, struct request *, unsigned int, unsigned int);
	void (*exit_request)(struct blk_mq_tag_set *, struct request *, unsigned int);
	void (*cleanup_rq)(struct request *);
	bool (*busy)(struct request_queue *);
	void (*map_queues)(struct blk_mq_tag_set *);
	void (*show_rq)(struct seq_file *, struct request *);
};

typedef __u32 req_flags_t;

enum mq_rq_state {
	MQ_RQ_IDLE = 0,
	MQ_RQ_IN_FLIGHT = 1,
	MQ_RQ_COMPLETE = 2,
};

enum rq_end_io_ret {
	RQ_END_IO_NONE = 0,
	RQ_END_IO_FREE = 1,
};

typedef enum rq_end_io_ret rq_end_io_fn(struct request *, blk_status_t);

struct request {
	struct request_queue *q;
	struct blk_mq_ctx *mq_ctx;
	struct blk_mq_hw_ctx *mq_hctx;
	blk_opf_t cmd_flags;
	req_flags_t rq_flags;
	int tag;
	int internal_tag;
	unsigned int timeout;
	unsigned int __data_len;
	sector_t __sector;
	struct bio *bio;
	struct bio *biotail;
	union {
		struct list_head queuelist;
		struct request *rq_next;
	};
	struct block_device *part;
	u64 alloc_time_ns;
	u64 start_time_ns;
	u64 io_start_time_ns;
	short unsigned int wbt_flags;
	short unsigned int stats_sectors;
	short unsigned int nr_phys_segments;
	short unsigned int nr_integrity_segments;
	enum rw_hint write_hint;
	short unsigned int ioprio;
	enum mq_rq_state state;
	atomic_t ref;
	long unsigned int deadline;
	union {
		struct hlist_node hash;
		struct llist_node ipi_list;
	};
	union {
		struct rb_node rb_node;
		struct bio_vec special_vec;
	};
	struct {
		struct io_cq *icq;
		void *priv[2];
	} elv;
	struct {
		unsigned int seq;
		rq_end_io_fn *saved_end_io;
	} flush;
	u64 fifo_time;
	rq_end_io_fn *end_io;
	void *end_io_data;
};

struct blk_mq_tags {
	unsigned int nr_tags;
	unsigned int nr_reserved_tags;
	unsigned int active_queues;
	struct sbitmap_queue bitmap_tags;
	struct sbitmap_queue breserved_tags;
	struct request **rqs;
	struct request **static_rqs;
	struct list_head page_list;
	spinlock_t lock;
};

struct rchan;

struct blk_trace {
	int trace_state;
	struct rchan *rchan;
	long unsigned int *sequence;
	unsigned char *msg_data;
	u16 act_mask;
	u64 start_lba;
	u64 end_lba;
	u32 pid;
	u32 dev;
	struct dentry *dir;
	struct list_head running_list;
	atomic_t dropped;
};

struct blk_flush_queue {
	spinlock_t mq_flush_lock;
	unsigned int flush_pending_idx: 1;
	unsigned int flush_running_idx: 1;
	blk_status_t rq_status;
	long unsigned int flush_pending_since;
	struct list_head flush_queue[2];
	long unsigned int flush_data_in_flight;
	struct request *flush_rq;
};

struct blk_mq_queue_map {
	unsigned int *mq_map;
	unsigned int nr_queues;
	unsigned int queue_offset;
};

struct blk_mq_tag_set {
	const struct blk_mq_ops *ops;
	struct blk_mq_queue_map map[3];
	unsigned int nr_maps;
	unsigned int nr_hw_queues;
	unsigned int queue_depth;
	unsigned int reserved_tags;
	unsigned int cmd_size;
	int numa_node;
	unsigned int timeout;
	unsigned int flags;
	void *driver_data;
	struct blk_mq_tags **tags;
	struct blk_mq_tags *shared_tags;
	struct mutex tag_list_lock;
	struct list_head tag_list;
	struct srcu_struct *srcu;
};

struct hd_geometry {
	unsigned char heads;
	unsigned char sectors;
	short unsigned int cylinders;
	long unsigned int start;
};

enum pr_type {
	PR_WRITE_EXCLUSIVE = 1,
	PR_EXCLUSIVE_ACCESS = 2,
	PR_WRITE_EXCLUSIVE_REG_ONLY = 3,
	PR_EXCLUSIVE_ACCESS_REG_ONLY = 4,
	PR_WRITE_EXCLUSIVE_ALL_REGS = 5,
	PR_EXCLUSIVE_ACCESS_ALL_REGS = 6,
};

struct pr_keys;

struct pr_held_reservation;

struct pr_ops {
	int (*pr_register)(struct block_device *, u64, u64, u32);
	int (*pr_reserve)(struct block_device *, u64, enum pr_type, u32);
	int (*pr_release)(struct block_device *, u64, enum pr_type);
	int (*pr_preempt)(struct block_device *, u64, u64, enum pr_type, bool);
	int (*pr_clear)(struct block_device *, u64);
	int (*pr_read_keys)(struct block_device *, struct pr_keys *);
	int (*pr_read_reservation)(struct block_device *, struct pr_held_reservation *);
};

struct blkpg_ioctl_arg {
	int op;
	int flags;
	int datalen;
	void *data;
};

struct blkpg_partition {
	long long int start;
	long long int length;
	int pno;
	char devname[64];
	char volname[64];
};

struct blk_mq_hw_ctx {
	struct {
		spinlock_t lock;
		struct list_head dispatch;
		long unsigned int state;
		long: 64;
		long: 64;
		long: 64;
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
	struct delayed_work run_work;
	cpumask_var_t cpumask;
	int next_cpu;
	int next_cpu_batch;
	long unsigned int flags;
	void *sched_data;
	struct request_queue *queue;
	struct blk_flush_queue *fq;
	void *driver_data;
	struct sbitmap ctx_map;
	struct blk_mq_ctx *dispatch_from;
	unsigned int dispatch_busy;
	short unsigned int type;
	short unsigned int nr_ctx;
	struct blk_mq_ctx **ctxs;
	spinlock_t dispatch_wait_lock;
	wait_queue_entry_t dispatch_wait;
	atomic_t wait_index;
	struct blk_mq_tags *tags;
	struct blk_mq_tags *sched_tags;
	unsigned int numa_node;
	unsigned int queue_num;
	atomic_t nr_active;
	struct hlist_node cpuhp_online;
	struct hlist_node cpuhp_dead;
	struct kobject kobj;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct list_head hctx_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

enum hctx_type {
	HCTX_TYPE_DEFAULT = 0,
	HCTX_TYPE_READ = 1,
	HCTX_TYPE_POLL = 2,
	HCTX_MAX_TYPES = 3,
};

struct blk_mq_queue_data {
	struct request *rq;
	bool last;
};

struct rchan_buf {
	void *start;
	void *data;
	size_t offset;
	size_t subbufs_produced;
	size_t subbufs_consumed;
	struct rchan *chan;
	wait_queue_head_t read_wait;
	struct irq_work wakeup_work;
	struct dentry *dentry;
	struct kref kref;
	struct page **page_array;
	unsigned int page_count;
	unsigned int finalized;
	size_t *padding;
	size_t prev_padding;
	size_t bytes_consumed;
	size_t early_bytes;
	unsigned int cpu;
	long: 64;
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

struct rchan_callbacks;

struct rchan {
	u32 version;
	size_t subbuf_size;
	size_t n_subbufs;
	size_t alloc_size;
	const struct rchan_callbacks *cb;
	struct kref kref;
	void *private_data;
	size_t last_toobig;
	struct rchan_buf **buf;
	int is_global;
	struct list_head list;
	struct dentry *parent;
	int has_base_filename;
	char base_filename[255];
};

struct rchan_callbacks {
	int (*subbuf_start)(struct rchan_buf *, void *, void *, size_t);
	struct dentry * (*create_buf_file)(const char *, struct dentry *, umode_t, struct rchan_buf *, int *);
	int (*remove_buf_file)(struct dentry *);
};

enum blktrace_act {
	__BLK_TA_QUEUE = 1,
	__BLK_TA_BACKMERGE = 2,
	__BLK_TA_FRONTMERGE = 3,
	__BLK_TA_GETRQ = 4,
	__BLK_TA_SLEEPRQ = 5,
	__BLK_TA_REQUEUE = 6,
	__BLK_TA_ISSUE = 7,
	__BLK_TA_COMPLETE = 8,
	__BLK_TA_PLUG = 9,
	__BLK_TA_UNPLUG_IO = 10,
	__BLK_TA_UNPLUG_TIMER = 11,
	__BLK_TA_INSERT = 12,
	__BLK_TA_SPLIT = 13,
	__BLK_TA_BOUNCE = 14,
	__BLK_TA_REMAP = 15,
	__BLK_TA_ABORT = 16,
	__BLK_TA_DRV_DATA = 17,
	__BLK_TA_CGROUP = 256,
};

struct pr_reservation {
	__u64 key;
	__u32 type;
	__u32 flags;
};

struct pr_registration {
	__u64 old_key;
	__u64 new_key;
	__u32 flags;
	__u32 __pad;
};

struct pr_preempt {
	__u64 old_key;
	__u64 new_key;
	__u32 type;
	__u32 flags;
};

struct pr_clear {
	__u64 key;
	__u32 flags;
	__u32 __pad;
};

struct pr_keys {
	u32 generation;
	u32 num_keys;
	u64 keys[0];
};

struct pr_held_reservation {
	u64 key;
	u32 generation;
	enum pr_type type;
};

struct compat_blkpg_ioctl_arg {
	compat_int_t op;
	compat_int_t flags;
	compat_int_t datalen;
	compat_caddr_t data;
};

struct compat_hd_geometry {
	unsigned char heads;
	unsigned char sectors;
	short unsigned int cylinders;
	u32 start;
};

struct rnd_state {
	__u32 s1;
	__u32 s2;
	__u32 s3;
	__u32 s4;
};

struct interval_tree_node {
	struct rb_node rb;
	long unsigned int start;
	long unsigned int last;
	long unsigned int __subtree_last;
};

struct rb_augment_callbacks {
	void (*propagate)(struct rb_node *, struct rb_node *);
	void (*copy)(struct rb_node *, struct rb_node *);
	void (*rotate)(struct rb_node *, struct rb_node *);
};

typedef __kernel_long_t __kernel_ptrdiff_t;

typedef __u32 __le32;

typedef __u64 __le64;

typedef __kernel_ptrdiff_t ptrdiff_t;

typedef u8 uint8_t;

typedef u16 uint16_t;

typedef uint8_t BYTE;

typedef uint16_t U16;

typedef uint32_t U32;

typedef uint64_t U64;

typedef struct {
	size_t bitContainer;
	unsigned int bitPos;
	char *startPtr;
	char *ptr;
	char *endPtr;
} BIT_CStream_t;

typedef unsigned int FSE_CTable;

typedef struct {
	ptrdiff_t value;
	const void *stateTable;
	const void *symbolTT;
	unsigned int stateLog;
} FSE_CState_t;

typedef struct {
	int deltaFindState;
	U32 deltaNbBits;
} FSE_symbolCompressionTransform;

struct word_at_a_time {
	const long unsigned int high_bits;
	const long unsigned int low_bits;
};

typedef struct mutex *class_mutex_t;

typedef struct {
	struct srcu_struct *lock;
	int idx;
} class_srcu_t;

struct gpio_desc;

struct gpio_chip;

struct gpio_array {
	struct gpio_desc **desc;
	unsigned int size;
	struct gpio_chip *chip;
	long unsigned int *get_mask;
	long unsigned int *set_mask;
	long unsigned int invert_mask[0];
};

struct gpio_device;

struct gpio_desc_label;

struct gpio_desc {
	struct gpio_device *gdev;
	long unsigned int flags;
	struct gpio_desc_label *label;
	const char *name;
	struct device_node *hog;
};

union gpio_irq_fwspec;

struct gpio_irq_chip {
	struct irq_chip *chip;
	struct irq_domain *domain;
	struct fwnode_handle *fwnode;
	struct irq_domain *parent_domain;
	int (*child_to_parent_hwirq)(struct gpio_chip *, unsigned int, unsigned int, unsigned int *, unsigned int *);
	int (*populate_parent_alloc_arg)(struct gpio_chip *, union gpio_irq_fwspec *, unsigned int, unsigned int);
	unsigned int (*child_offset_to_irq)(struct gpio_chip *, unsigned int);
	struct irq_domain_ops child_irq_domain_ops;
	irq_flow_handler_t handler;
	unsigned int default_type;
	struct lock_class_key *lock_key;
	struct lock_class_key *request_key;
	irq_flow_handler_t parent_handler;
	union {
		void *parent_handler_data;
		void **parent_handler_data_array;
	};
	unsigned int num_parents;
	unsigned int *parents;
	unsigned int *map;
	bool threaded;
	bool per_parent_data;
	bool initialized;
	bool domain_is_allocated_externally;
	int (*init_hw)(struct gpio_chip *);
	void (*init_valid_mask)(struct gpio_chip *, long unsigned int *, unsigned int);
	long unsigned int *valid_mask;
	unsigned int first;
	void (*irq_enable)(struct irq_data *);
	void (*irq_disable)(struct irq_data *);
	void (*irq_unmask)(struct irq_data *);
	void (*irq_mask)(struct irq_data *);
};

struct gpio_chip {
	const char *label;
	struct gpio_device *gpiodev;
	struct device *parent;
	struct fwnode_handle *fwnode;
	struct module *owner;
	int (*request)(struct gpio_chip *, unsigned int);
	void (*free)(struct gpio_chip *, unsigned int);
	int (*get_direction)(struct gpio_chip *, unsigned int);
	int (*direction_input)(struct gpio_chip *, unsigned int);
	int (*direction_output)(struct gpio_chip *, unsigned int, int);
	int (*get)(struct gpio_chip *, unsigned int);
	int (*get_multiple)(struct gpio_chip *, long unsigned int *, long unsigned int *);
	void (*set)(struct gpio_chip *, unsigned int, int);
	void (*set_multiple)(struct gpio_chip *, long unsigned int *, long unsigned int *);
	int (*set_config)(struct gpio_chip *, unsigned int, long unsigned int);
	int (*to_irq)(struct gpio_chip *, unsigned int);
	void (*dbg_show)(struct seq_file *, struct gpio_chip *);
	int (*init_valid_mask)(struct gpio_chip *, long unsigned int *, unsigned int);
	int (*add_pin_ranges)(struct gpio_chip *);
	int (*en_hw_timestamp)(struct gpio_chip *, u32, long unsigned int);
	int (*dis_hw_timestamp)(struct gpio_chip *, u32, long unsigned int);
	int base;
	u16 ngpio;
	u16 offset;
	const char * const *names;
	bool can_sleep;
	struct gpio_irq_chip irq;
	long unsigned int *valid_mask;
	unsigned int of_gpio_n_cells;
	int (*of_xlate)(struct gpio_chip *, const struct of_phandle_args *, u32 *);
};

struct msi_alloc_info {
	struct msi_desc *desc;
	irq_hw_number_t hwirq;
	long unsigned int flags;
	union {
		long unsigned int ul;
		void *ptr;
	} scratchpad[2];
};

typedef struct msi_alloc_info msi_alloc_info_t;

union gpio_irq_fwspec {
	struct irq_fwspec fwspec;
	msi_alloc_info_t msiinfo;
};

struct gpio_device {
	struct device dev;
	struct cdev chrdev;
	int id;
	struct device *mockdev;
	struct module *owner;
	struct gpio_chip *chip;
	struct gpio_desc *descs;
	struct srcu_struct desc_srcu;
	int base;
	u16 ngpio;
	bool can_sleep;
	const char *label;
	void *data;
	struct list_head list;
	struct blocking_notifier_head line_state_notifier;
	struct blocking_notifier_head device_notifier;
	struct srcu_struct srcu;
};

struct gpiochip_info {
	char name[32];
	char label[32];
	__u32 lines;
};

enum gpio_v2_line_flag {
	GPIO_V2_LINE_FLAG_USED = 1,
	GPIO_V2_LINE_FLAG_ACTIVE_LOW = 2,
	GPIO_V2_LINE_FLAG_INPUT = 4,
	GPIO_V2_LINE_FLAG_OUTPUT = 8,
	GPIO_V2_LINE_FLAG_EDGE_RISING = 16,
	GPIO_V2_LINE_FLAG_EDGE_FALLING = 32,
	GPIO_V2_LINE_FLAG_OPEN_DRAIN = 64,
	GPIO_V2_LINE_FLAG_OPEN_SOURCE = 128,
	GPIO_V2_LINE_FLAG_BIAS_PULL_UP = 256,
	GPIO_V2_LINE_FLAG_BIAS_PULL_DOWN = 512,
	GPIO_V2_LINE_FLAG_BIAS_DISABLED = 1024,
	GPIO_V2_LINE_FLAG_EVENT_CLOCK_REALTIME = 2048,
	GPIO_V2_LINE_FLAG_EVENT_CLOCK_HTE = 4096,
};

struct gpio_v2_line_values {
	__u64 bits;
	__u64 mask;
};

enum gpio_v2_line_attr_id {
	GPIO_V2_LINE_ATTR_ID_FLAGS = 1,
	GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES = 2,
	GPIO_V2_LINE_ATTR_ID_DEBOUNCE = 3,
};

struct gpio_v2_line_attribute {
	__u32 id;
	__u32 padding;
	union {
		__u64 flags;
		__u64 values;
		__u32 debounce_period_us;
	};
};

struct gpio_v2_line_config_attribute {
	struct gpio_v2_line_attribute attr;
	__u64 mask;
};

struct gpio_v2_line_config {
	__u64 flags;
	__u32 num_attrs;
	__u32 padding[5];
	struct gpio_v2_line_config_attribute attrs[10];
};

struct gpio_v2_line_request {
	__u32 offsets[64];
	char consumer[32];
	struct gpio_v2_line_config config;
	__u32 num_lines;
	__u32 event_buffer_size;
	__u32 padding[5];
	__s32 fd;
};

struct gpio_v2_line_info {
	char name[32];
	char consumer[32];
	__u32 offset;
	__u32 num_attrs;
	__u64 flags;
	struct gpio_v2_line_attribute attrs[10];
	__u32 padding[4];
};

enum gpio_v2_line_changed_type {
	GPIO_V2_LINE_CHANGED_REQUESTED = 1,
	GPIO_V2_LINE_CHANGED_RELEASED = 2,
	GPIO_V2_LINE_CHANGED_CONFIG = 3,
};

struct gpio_v2_line_info_changed {
	struct gpio_v2_line_info info;
	__u64 timestamp_ns;
	__u32 event_type;
	__u32 padding[5];
};

enum gpio_v2_line_event_id {
	GPIO_V2_LINE_EVENT_RISING_EDGE = 1,
	GPIO_V2_LINE_EVENT_FALLING_EDGE = 2,
};

struct gpio_v2_line_event {
	__u64 timestamp_ns;
	__u32 id;
	__u32 offset;
	__u32 seqno;
	__u32 line_seqno;
	__u32 padding[6];
};

struct gpioline_info {
	__u32 line_offset;
	__u32 flags;
	char name[32];
	char consumer[32];
};

struct gpioline_info_changed {
	struct gpioline_info info;
	__u64 timestamp;
	__u32 event_type;
	__u32 padding[5];
};

struct gpiohandle_request {
	__u32 lineoffsets[64];
	__u32 flags;
	__u8 default_values[64];
	char consumer_label[32];
	__u32 lines;
	int fd;
};

struct gpiohandle_config {
	__u32 flags;
	__u8 default_values[64];
	__u32 padding[4];
};

struct gpiohandle_data {
	__u8 values[64];
};

struct gpioevent_request {
	__u32 lineoffset;
	__u32 handleflags;
	__u32 eventflags;
	char consumer_label[32];
	int fd;
};

struct gpioevent_data {
	__u64 timestamp;
	__u32 id;
};

struct gpio_desc_label {
	struct callback_head rh;
	char str[0];
};

struct gpio_chip_guard {
	struct gpio_device *gdev;
	struct gpio_chip *gc;
	int idx;
};

typedef struct gpio_chip_guard class_gpio_chip_guard_t;

struct linehandle_state {
	struct gpio_device *gdev;
	const char *label;
	struct gpio_desc *descs[64];
	u32 num_descs;
};

struct linereq;

struct line {
	struct rb_node node;
	struct gpio_desc *desc;
	struct linereq *req;
	unsigned int irq;
	u64 edflags;
	u64 timestamp_ns;
	u32 req_seqno;
	u32 line_seqno;
	struct delayed_work work;
	unsigned int debounce_period_us;
	unsigned int sw_debounced;
	unsigned int level;
};

struct linereq {
	struct gpio_device *gdev;
	const char *label;
	u32 num_lines;
	wait_queue_head_t wait;
	struct notifier_block device_unregistered_nb;
	u32 event_buffer_size;
	struct {
		union {
			struct __kfifo kfifo;
			struct gpio_v2_line_event *type;
			const struct gpio_v2_line_event *const_type;
			char (*rectype)[0];
			struct gpio_v2_line_event *ptr;
			const struct gpio_v2_line_event *ptr_const;
		};
		struct gpio_v2_line_event buf[0];
	} events;
	atomic_t seqno;
	struct mutex config_mutex;
	struct line lines[0];
};

struct lineevent_state {
	struct gpio_device *gdev;
	const char *label;
	struct gpio_desc *desc;
	u32 eflags;
	int irq;
	wait_queue_head_t wait;
	struct notifier_block device_unregistered_nb;
	struct {
		union {
			struct __kfifo kfifo;
			struct gpioevent_data *type;
			const struct gpioevent_data *const_type;
			char (*rectype)[0];
			struct gpioevent_data *ptr;
			const struct gpioevent_data *ptr_const;
		};
		struct gpioevent_data buf[16];
	} events;
	u64 timestamp;
};

struct gpio_chardev_data {
	struct gpio_device *gdev;
	wait_queue_head_t wait;
	struct {
		union {
			struct __kfifo kfifo;
			struct gpio_v2_line_info_changed *type;
			const struct gpio_v2_line_info_changed *const_type;
			char (*rectype)[0];
			struct gpio_v2_line_info_changed *ptr;
			const struct gpio_v2_line_info_changed *ptr_const;
		};
		struct gpio_v2_line_info_changed buf[32];
	} events;
	struct notifier_block lineinfo_changed_nb;
	struct notifier_block device_unregistered_nb;
	long unsigned int *watched_lines;
	atomic_t watch_abi_version;
};

enum vesa_blank_mode {
	VESA_NO_BLANKING = 0,
	VESA_VSYNC_SUSPEND = 1,
	VESA_HSYNC_SUSPEND = 2,
	VESA_POWERDOWN = 3,
	VESA_BLANK_MAX = 3,
};

struct fb_fix_screeninfo {
	char id[16];
	long unsigned int smem_start;
	__u32 smem_len;
	__u32 type;
	__u32 type_aux;
	__u32 visual;
	__u16 xpanstep;
	__u16 ypanstep;
	__u16 ywrapstep;
	__u32 line_length;
	long unsigned int mmio_start;
	__u32 mmio_len;
	__u32 accel;
	__u16 capabilities;
	__u16 reserved[2];
};

struct fb_bitfield {
	__u32 offset;
	__u32 length;
	__u32 msb_right;
};

struct fb_var_screeninfo {
	__u32 xres;
	__u32 yres;
	__u32 xres_virtual;
	__u32 yres_virtual;
	__u32 xoffset;
	__u32 yoffset;
	__u32 bits_per_pixel;
	__u32 grayscale;
	struct fb_bitfield red;
	struct fb_bitfield green;
	struct fb_bitfield blue;
	struct fb_bitfield transp;
	__u32 nonstd;
	__u32 activate;
	__u32 height;
	__u32 width;
	__u32 accel_flags;
	__u32 pixclock;
	__u32 left_margin;
	__u32 right_margin;
	__u32 upper_margin;
	__u32 lower_margin;
	__u32 hsync_len;
	__u32 vsync_len;
	__u32 sync;
	__u32 vmode;
	__u32 rotate;
	__u32 colorspace;
	__u32 reserved[4];
};

struct fb_cmap {
	__u32 start;
	__u32 len;
	__u16 *red;
	__u16 *green;
	__u16 *blue;
	__u16 *transp;
};

enum {
	FB_BLANK_UNBLANK = 0,
	FB_BLANK_NORMAL = 1,
	FB_BLANK_VSYNC_SUSPEND = 2,
	FB_BLANK_HSYNC_SUSPEND = 3,
	FB_BLANK_POWERDOWN = 4,
};

struct fb_vblank {
	__u32 flags;
	__u32 count;
	__u32 vcount;
	__u32 hcount;
	__u32 reserved[4];
};

struct fb_copyarea {
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 sx;
	__u32 sy;
};

struct fb_fillrect {
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 color;
	__u32 rop;
};

struct fb_image {
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 fg_color;
	__u32 bg_color;
	__u8 depth;
	const char *data;
	struct fb_cmap cmap;
};

struct fbcurpos {
	__u16 x;
	__u16 y;
};

struct fb_cursor {
	__u16 set;
	__u16 enable;
	__u16 rop;
	const char *mask;
	struct fbcurpos hot;
	struct fb_image image;
};

struct fb_chroma {
	__u32 redx;
	__u32 greenx;
	__u32 bluex;
	__u32 whitex;
	__u32 redy;
	__u32 greeny;
	__u32 bluey;
	__u32 whitey;
};

struct fb_videomode;

struct fb_monspecs {
	struct fb_chroma chroma;
	struct fb_videomode *modedb;
	__u8 manufacturer[4];
	__u8 monitor[14];
	__u8 serial_no[14];
	__u8 ascii[14];
	__u32 modedb_len;
	__u32 model;
	__u32 serial;
	__u32 year;
	__u32 week;
	__u32 hfmin;
	__u32 hfmax;
	__u32 dclkmin;
	__u32 dclkmax;
	__u16 input;
	__u16 dpms;
	__u16 signal;
	__u16 vfmin;
	__u16 vfmax;
	__u16 gamma;
	__u16 gtf: 1;
	__u16 misc;
	__u8 version;
	__u8 revision;
	__u8 max_x;
	__u8 max_y;
};

struct fb_videomode {
	const char *name;
	u32 refresh;
	u32 xres;
	u32 yres;
	u32 pixclock;
	u32 left_margin;
	u32 right_margin;
	u32 upper_margin;
	u32 lower_margin;
	u32 hsync_len;
	u32 vsync_len;
	u32 sync;
	u32 vmode;
	u32 flag;
};

struct fb_info;

struct fb_pixmap {
	u8 *addr;
	u32 size;
	u32 offset;
	u32 buf_align;
	u32 scan_align;
	u32 access_align;
	u32 flags;
	long unsigned int blit_x[1];
	long unsigned int blit_y[2];
	void (*writeio)(struct fb_info *, void *, void *, unsigned int);
	void (*readio)(struct fb_info *, void *, void *, unsigned int);
};

struct backlight_device;

struct fb_deferred_io_pageref;

struct fb_deferred_io;

struct fb_ops;

struct fb_tile_ops;

struct fb_info {
	refcount_t count;
	int node;
	int flags;
	int fbcon_rotate_hint;
	struct mutex lock;
	struct mutex mm_lock;
	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	struct fb_monspecs monspecs;
	struct fb_pixmap pixmap;
	struct fb_pixmap sprite;
	struct fb_cmap cmap;
	struct list_head modelist;
	struct fb_videomode *mode;
	struct backlight_device *bl_dev;
	struct mutex bl_curve_mutex;
	u8 bl_curve[128];
	struct delayed_work deferred_work;
	long unsigned int npagerefs;
	struct fb_deferred_io_pageref *pagerefs;
	struct fb_deferred_io *fbdefio;
	const struct fb_ops *fbops;
	struct device *device;
	struct device *dev;
	int class_flag;
	struct fb_tile_ops *tileops;
	union {
		char *screen_base;
		char *screen_buffer;
	};
	long unsigned int screen_size;
	void *pseudo_palette;
	u32 state;
	void *fbcon_par;
	void *par;
	bool skip_vt_switch;
};

struct fb_blit_caps {
	long unsigned int x[1];
	long unsigned int y[2];
	u32 len;
	u32 flags;
};

struct fb_deferred_io_pageref {
	struct page *page;
	long unsigned int offset;
	struct list_head list;
};

struct fb_deferred_io {
	long unsigned int delay;
	bool sort_pagereflist;
	int open_count;
	struct mutex lock;
	struct list_head pagereflist;
	void (*deferred_io)(struct fb_info *, struct list_head *);
};

struct fb_ops {
	struct module *owner;
	int (*fb_open)(struct fb_info *, int);
	int (*fb_release)(struct fb_info *, int);
	ssize_t (*fb_read)(struct fb_info *, char *, size_t, loff_t *);
	ssize_t (*fb_write)(struct fb_info *, const char *, size_t, loff_t *);
	int (*fb_check_var)(struct fb_var_screeninfo *, struct fb_info *);
	int (*fb_set_par)(struct fb_info *);
	int (*fb_setcolreg)(unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, struct fb_info *);
	int (*fb_setcmap)(struct fb_cmap *, struct fb_info *);
	int (*fb_blank)(int, struct fb_info *);
	int (*fb_pan_display)(struct fb_var_screeninfo *, struct fb_info *);
	void (*fb_fillrect)(struct fb_info *, const struct fb_fillrect *);
	void (*fb_copyarea)(struct fb_info *, const struct fb_copyarea *);
	void (*fb_imageblit)(struct fb_info *, const struct fb_image *);
	int (*fb_cursor)(struct fb_info *, struct fb_cursor *);
	int (*fb_sync)(struct fb_info *);
	int (*fb_ioctl)(struct fb_info *, unsigned int, long unsigned int);
	int (*fb_compat_ioctl)(struct fb_info *, unsigned int, long unsigned int);
	int (*fb_mmap)(struct fb_info *, struct vm_area_struct *);
	void (*fb_get_caps)(struct fb_info *, struct fb_blit_caps *, struct fb_var_screeninfo *);
	void (*fb_destroy)(struct fb_info *);
	int (*fb_debug_enter)(struct fb_info *);
	int (*fb_debug_leave)(struct fb_info *);
};

struct fb_tilemap {
	__u32 width;
	__u32 height;
	__u32 depth;
	__u32 length;
	const __u8 *data;
};

struct fb_tilerect {
	__u32 sx;
	__u32 sy;
	__u32 width;
	__u32 height;
	__u32 index;
	__u32 fg;
	__u32 bg;
	__u32 rop;
};

struct fb_tilearea {
	__u32 sx;
	__u32 sy;
	__u32 dx;
	__u32 dy;
	__u32 width;
	__u32 height;
};

struct fb_tileblit {
	__u32 sx;
	__u32 sy;
	__u32 width;
	__u32 height;
	__u32 fg;
	__u32 bg;
	__u32 length;
	__u32 *indices;
};

struct fb_tilecursor {
	__u32 sx;
	__u32 sy;
	__u32 mode;
	__u32 shape;
	__u32 fg;
	__u32 bg;
};

struct fb_tile_ops {
	void (*fb_settile)(struct fb_info *, struct fb_tilemap *);
	void (*fb_tilecopy)(struct fb_info *, struct fb_tilearea *);
	void (*fb_tilefill)(struct fb_info *, struct fb_tilerect *);
	void (*fb_tileblit)(struct fb_info *, struct fb_tileblit *);
	void (*fb_tilecursor)(struct fb_info *, struct fb_tilecursor *);
	int (*fb_get_tilemax)(struct fb_info *);
};

enum ps3av_mode_num {
	PS3AV_MODE_AUTO = 0,
	PS3AV_MODE_480I = 1,
	PS3AV_MODE_480P = 2,
	PS3AV_MODE_720P60 = 3,
	PS3AV_MODE_1080I60 = 4,
	PS3AV_MODE_1080P60 = 5,
	PS3AV_MODE_576I = 6,
	PS3AV_MODE_576P = 7,
	PS3AV_MODE_720P50 = 8,
	PS3AV_MODE_1080I50 = 9,
	PS3AV_MODE_1080P50 = 10,
	PS3AV_MODE_WXGA = 11,
	PS3AV_MODE_SXGA = 12,
	PS3AV_MODE_WUXGA = 13,
};

struct ps3fb_ioctl_res {
	__u32 xres;
	__u32 yres;
	__u32 xoff;
	__u32 yoff;
	__u32 num_frames;
};

enum ps3_dma_page_size {
	PS3_DMA_4K = 12,
	PS3_DMA_64K = 16,
	PS3_DMA_1M = 20,
	PS3_DMA_16M = 24,
};

enum ps3_dma_region_type {
	PS3_DMA_OTHER = 0,
	PS3_DMA_INTERNAL = 2,
};

struct ps3_system_bus_device;

struct ps3_dma_region_ops;

struct ps3_dma_region {
	struct ps3_system_bus_device *dev;
	const struct ps3_dma_region_ops *region_ops;
	unsigned char ioid;
	enum ps3_dma_page_size page_size;
	enum ps3_dma_region_type region_type;
	long unsigned int len;
	long unsigned int offset;
	u64 dma_mask;
	long unsigned int bus_addr;
	struct {
		spinlock_t lock;
		struct list_head head;
	} chunk_list;
};

enum ps3_match_id {
	PS3_MATCH_ID_EHCI = 1,
	PS3_MATCH_ID_OHCI = 2,
	PS3_MATCH_ID_GELIC = 3,
	PS3_MATCH_ID_AV_SETTINGS = 4,
	PS3_MATCH_ID_SYSTEM_MANAGER = 5,
	PS3_MATCH_ID_STOR_DISK = 6,
	PS3_MATCH_ID_STOR_ROM = 7,
	PS3_MATCH_ID_STOR_FLASH = 8,
	PS3_MATCH_ID_SOUND = 9,
	PS3_MATCH_ID_GPU = 10,
	PS3_MATCH_ID_LPM = 11,
};

enum ps3_match_sub_id {
	PS3_MATCH_SUB_ID_GPU_FB = 1,
	PS3_MATCH_SUB_ID_GPU_RAMDISK = 2,
};

enum ps3_system_bus_device_type {
	PS3_DEVICE_TYPE_IOC0 = 1,
	PS3_DEVICE_TYPE_SB = 2,
	PS3_DEVICE_TYPE_VUART = 3,
	PS3_DEVICE_TYPE_LPM = 4,
};

struct ps3_mmio_region;

struct ps3_system_bus_device {
	enum ps3_match_id match_id;
	enum ps3_match_sub_id match_sub_id;
	enum ps3_system_bus_device_type dev_type;
	u64 bus_id;
	u64 dev_id;
	unsigned int interrupt_id;
	struct ps3_dma_region *d_region;
	struct ps3_mmio_region *m_region;
	unsigned int port_number;
	struct {
		u64 node_id;
		u64 pu_id;
		u64 rights;
	} lpm;
	struct device core;
	void *driver_priv;
};

struct ps3_dma_region_ops {
	int (*create)(struct ps3_dma_region *);
	int (*free)(struct ps3_dma_region *);
	int (*map)(struct ps3_dma_region *, long unsigned int, long unsigned int, dma_addr_t *, u64);
	int (*unmap)(struct ps3_dma_region *, dma_addr_t, long unsigned int);
};

enum ps3_mmio_page_size {
	PS3_MMIO_4K = 12,
	PS3_MMIO_64K = 16,
};

struct ps3_mmio_region_ops;

struct ps3_mmio_region {
	struct ps3_system_bus_device *dev;
	const struct ps3_mmio_region_ops *mmio_ops;
	long unsigned int bus_addr;
	long unsigned int len;
	enum ps3_mmio_page_size page_size;
	long unsigned int lpar_addr;
};

struct ps3_mmio_region_ops {
	int (*create)(struct ps3_mmio_region *);
	int (*free)(struct ps3_mmio_region *);
};

enum ps3_cpu_binding {
	PS3_BINDING_CPU_ANY = -1,
	PS3_BINDING_CPU_0 = 0,
	PS3_BINDING_CPU_1 = 1,
};

struct ps3_system_bus_driver {
	enum ps3_match_id match_id;
	enum ps3_match_sub_id match_sub_id;
	struct device_driver core;
	int (*probe)(struct ps3_system_bus_device *);
	void (*remove)(struct ps3_system_bus_device *);
	void (*shutdown)(struct ps3_system_bus_device *);
};

struct ps3_prealloc {
	const char *name;
	void *address;
	long unsigned int size;
	long unsigned int align;
};

struct display_head {
	u64 be_time_stamp;
	u32 status;
	u32 offset;
	u32 res1;
	u32 res2;
	u32 field;
	u32 reserved1;
	u64 res3;
	u32 raster;
	u64 vblank_count;
	u32 field_vsync;
	u32 reserved2;
};

struct gpu_irq {
	u32 irq_outlet;
	u32 status;
	u32 mask;
	u32 video_cause;
	u32 graph_cause;
	u32 user_cause;
	u32 res1;
	u64 res2;
	u32 reserved[4];
};

struct gpu_driver_info {
	u32 version_driver;
	u32 version_gpu;
	u32 memory_size;
	u32 hardware_channel;
	u32 nvcore_frequency;
	u32 memory_frequency;
	u32 reserved[1063];
	struct display_head display_head[8];
	struct gpu_irq irq;
};

struct ps3fb_priv {
	unsigned int irq_no;
	u64 context_handle;
	u64 memory_handle;
	struct gpu_driver_info *dinfo;
	u64 vblank_count;
	wait_queue_head_t wait_vsync;
	atomic_t ext_flip;
	atomic_t f_count;
	int is_blanked;
	int is_kicked;
	struct task_struct *task;
};

struct ps3fb_par {
	u32 pseudo_palette[16];
	int mode_id;
	int new_mode_id;
	unsigned int num_frames;
	unsigned int width;
	unsigned int height;
	unsigned int ddr_line_length;
	unsigned int ddr_frame_size;
	unsigned int xdr_frame_size;
	unsigned int full_offset;
	unsigned int fb_offset;
	unsigned int pan_offset;
};

typedef unsigned int uint;

struct ida {
	struct xarray xa;
};

enum nbcon_prio {
	NBCON_PRIO_NONE = 0,
	NBCON_PRIO_NORMAL = 1,
	NBCON_PRIO_EMERGENCY = 2,
	NBCON_PRIO_PANIC = 3,
	NBCON_PRIO_MAX = 4,
};

struct console;

struct printk_buffers;

struct nbcon_context {
	struct console *console;
	unsigned int spinwait_max_us;
	enum nbcon_prio prio;
	unsigned int allow_unsafe_takeover: 1;
	unsigned int backlog: 1;
	struct printk_buffers *pbufs;
	u64 seq;
};

struct nbcon_write_context;

struct console {
	char name[16];
	void (*write)(struct console *, const char *, unsigned int);
	int (*read)(struct console *, char *, unsigned int);
	struct tty_driver * (*device)(struct console *, int *);
	void (*unblank)();
	int (*setup)(struct console *, char *);
	int (*exit)(struct console *);
	int (*match)(struct console *, char *, int, char *);
	short int flags;
	short int index;
	int cflag;
	uint ispeed;
	uint ospeed;
	u64 seq;
	long unsigned int dropped;
	void *data;
	struct hlist_node node;
	bool (*write_atomic)(struct console *, struct nbcon_write_context *);
	atomic_t nbcon_state;
	atomic_long_t nbcon_seq;
	struct printk_buffers *pbufs;
};

struct nbcon_write_context {
	struct nbcon_context ctxt;
	char *outbuf;
	unsigned int len;
	bool unsafe_takeover;
};

struct circ_buf {
	char *buf;
	int head;
	int tail;
};

struct serial_icounter_struct {
	int cts;
	int dsr;
	int rng;
	int dcd;
	int rx;
	int tx;
	int frame;
	int overrun;
	int parity;
	int brk;
	int buf_overrun;
	int reserved[9];
};

struct serial_struct {
	int type;
	int line;
	unsigned int port;
	int irq;
	int flags;
	int xmit_fifo_size;
	int custom_divisor;
	int baud_base;
	short unsigned int close_delay;
	char io_type;
	char reserved_char[1];
	int hub6;
	short unsigned int closing_wait;
	short unsigned int closing_wait2;
	unsigned char *iomem_base;
	short unsigned int iomem_reg_shift;
	unsigned int port_high;
	long unsigned int iomap_base;
};

struct serial_rs485 {
	__u32 flags;
	__u32 delay_rts_before_send;
	__u32 delay_rts_after_send;
	union {
		__u32 padding[5];
		struct {
			__u8 addr_recv;
			__u8 addr_dest;
			__u8 padding0[2];
			__u32 padding1[4];
		};
	};
};

struct serial_iso7816 {
	__u32 flags;
	__u32 tg;
	__u32 sc_fi;
	__u32 sc_di;
	__u32 clk;
	__u32 reserved[5];
};

struct uart_port;

struct uart_ops {
	unsigned int (*tx_empty)(struct uart_port *);
	void (*set_mctrl)(struct uart_port *, unsigned int);
	unsigned int (*get_mctrl)(struct uart_port *);
	void (*stop_tx)(struct uart_port *);
	void (*start_tx)(struct uart_port *);
	void (*throttle)(struct uart_port *);
	void (*unthrottle)(struct uart_port *);
	void (*send_xchar)(struct uart_port *, char);
	void (*stop_rx)(struct uart_port *);
	void (*start_rx)(struct uart_port *);
	void (*enable_ms)(struct uart_port *);
	void (*break_ctl)(struct uart_port *, int);
	int (*startup)(struct uart_port *);
	void (*shutdown)(struct uart_port *);
	void (*flush_buffer)(struct uart_port *);
	void (*set_termios)(struct uart_port *, struct ktermios *, const struct ktermios *);
	void (*set_ldisc)(struct uart_port *, struct ktermios *);
	void (*pm)(struct uart_port *, unsigned int, unsigned int);
	const char * (*type)(struct uart_port *);
	void (*release_port)(struct uart_port *);
	int (*request_port)(struct uart_port *);
	void (*config_port)(struct uart_port *, int);
	int (*verify_port)(struct uart_port *, struct serial_struct *);
	int (*ioctl)(struct uart_port *, unsigned int, long unsigned int);
};

struct uart_icount {
	__u32 cts;
	__u32 dsr;
	__u32 rng;
	__u32 dcd;
	__u32 rx;
	__u32 tx;
	__u32 frame;
	__u32 overrun;
	__u32 parity;
	__u32 brk;
	__u32 buf_overrun;
};

typedef u64 upf_t;

typedef unsigned int upstat_t;

struct uart_state;

struct serial_port_device;

struct uart_port {
	spinlock_t lock;
	long unsigned int iobase;
	unsigned char *membase;
	unsigned int (*serial_in)(struct uart_port *, int);
	void (*serial_out)(struct uart_port *, int, int);
	void (*set_termios)(struct uart_port *, struct ktermios *, const struct ktermios *);
	void (*set_ldisc)(struct uart_port *, struct ktermios *);
	unsigned int (*get_mctrl)(struct uart_port *);
	void (*set_mctrl)(struct uart_port *, unsigned int);
	unsigned int (*get_divisor)(struct uart_port *, unsigned int, unsigned int *);
	void (*set_divisor)(struct uart_port *, unsigned int, unsigned int, unsigned int);
	int (*startup)(struct uart_port *);
	void (*shutdown)(struct uart_port *);
	void (*throttle)(struct uart_port *);
	void (*unthrottle)(struct uart_port *);
	int (*handle_irq)(struct uart_port *);
	void (*pm)(struct uart_port *, unsigned int, unsigned int);
	void (*handle_break)(struct uart_port *);
	int (*rs485_config)(struct uart_port *, struct ktermios *, struct serial_rs485 *);
	int (*iso7816_config)(struct uart_port *, struct serial_iso7816 *);
	unsigned int ctrl_id;
	unsigned int port_id;
	unsigned int irq;
	long unsigned int irqflags;
	unsigned int uartclk;
	unsigned int fifosize;
	unsigned char x_char;
	unsigned char regshift;
	unsigned char iotype;
	unsigned char quirks;
	unsigned int read_status_mask;
	unsigned int ignore_status_mask;
	struct uart_state *state;
	struct uart_icount icount;
	struct console *cons;
	upf_t flags;
	upstat_t status;
	bool hw_stopped;
	unsigned int mctrl;
	unsigned int frame_time;
	unsigned int type;
	const struct uart_ops *ops;
	unsigned int custom_divisor;
	unsigned int line;
	unsigned int minor;
	resource_size_t mapbase;
	resource_size_t mapsize;
	struct device *dev;
	struct serial_port_device *port_dev;
	long unsigned int sysrq;
	u8 sysrq_ch;
	unsigned char has_sysrq;
	unsigned char sysrq_seq;
	unsigned char hub6;
	unsigned char suspended;
	unsigned char console_reinit;
	const char *name;
	struct attribute_group *attr_group;
	const struct attribute_group **tty_groups;
	struct serial_rs485 rs485;
	struct serial_rs485 rs485_supported;
	struct gpio_desc *rs485_term_gpio;
	struct gpio_desc *rs485_rx_during_tx_gpio;
	struct serial_iso7816 iso7816;
	void *private_data;
};

enum uart_pm_state {
	UART_PM_STATE_ON = 0,
	UART_PM_STATE_OFF = 3,
	UART_PM_STATE_UNDEFINED = 4,
};

struct uart_state {
	struct tty_port port;
	enum uart_pm_state pm_state;
	struct circ_buf xmit;
	atomic_t refcount;
	wait_queue_head_t remove_wait;
	struct uart_port *uart_port;
};

struct mctrl_gpios;

struct uart_8250_dma;

struct uart_8250_ops;

struct uart_8250_em485;

struct uart_8250_port {
	struct uart_port port;
	struct timer_list timer;
	struct list_head list;
	u32 capabilities;
	u16 bugs;
	unsigned int tx_loadsz;
	unsigned char acr;
	unsigned char fcr;
	unsigned char ier;
	unsigned char lcr;
	unsigned char mcr;
	unsigned char cur_iotype;
	unsigned int rpm_tx_active;
	unsigned char canary;
	unsigned char probe;
	struct mctrl_gpios *gpios;
	u16 lsr_saved_flags;
	u16 lsr_save_mask;
	unsigned char msr_saved_flags;
	struct uart_8250_dma *dma;
	const struct uart_8250_ops *ops;
	u32 (*dl_read)(struct uart_8250_port *);
	void (*dl_write)(struct uart_8250_port *, u32);
	struct uart_8250_em485 *em485;
	void (*rs485_start_tx)(struct uart_8250_port *);
	void (*rs485_stop_tx)(struct uart_8250_port *);
	struct delayed_work overrun_backoff;
	u32 overrun_backoff_time_ms;
};

struct uart_8250_ops {
	int (*setup_irq)(struct uart_8250_port *);
	void (*release_irq)(struct uart_8250_port *);
	void (*setup_timer)(struct uart_8250_port *);
};

struct uart_8250_em485 {
	struct hrtimer start_tx_timer;
	struct hrtimer stop_tx_timer;
	struct hrtimer *active_timer;
	struct uart_8250_port *port;
	unsigned int tx_stopped: 1;
};

struct dma_chan;

typedef bool (*dma_filter_fn)(struct dma_chan *, void *);

enum dma_transfer_direction {
	DMA_MEM_TO_MEM = 0,
	DMA_MEM_TO_DEV = 1,
	DMA_DEV_TO_MEM = 2,
	DMA_DEV_TO_DEV = 3,
	DMA_TRANS_NONE = 4,
};

enum dma_slave_buswidth {
	DMA_SLAVE_BUSWIDTH_UNDEFINED = 0,
	DMA_SLAVE_BUSWIDTH_1_BYTE = 1,
	DMA_SLAVE_BUSWIDTH_2_BYTES = 2,
	DMA_SLAVE_BUSWIDTH_3_BYTES = 3,
	DMA_SLAVE_BUSWIDTH_4_BYTES = 4,
	DMA_SLAVE_BUSWIDTH_8_BYTES = 8,
	DMA_SLAVE_BUSWIDTH_16_BYTES = 16,
	DMA_SLAVE_BUSWIDTH_32_BYTES = 32,
	DMA_SLAVE_BUSWIDTH_64_BYTES = 64,
	DMA_SLAVE_BUSWIDTH_128_BYTES = 128,
};

struct dma_slave_config {
	enum dma_transfer_direction direction;
	phys_addr_t src_addr;
	phys_addr_t dst_addr;
	enum dma_slave_buswidth src_addr_width;
	enum dma_slave_buswidth dst_addr_width;
	u32 src_maxburst;
	u32 dst_maxburst;
	u32 src_port_window_size;
	u32 dst_port_window_size;
	bool device_fc;
	void *peripheral_config;
	size_t peripheral_size;
};

typedef s32 dma_cookie_t;

struct uart_8250_dma {
	int (*tx_dma)(struct uart_8250_port *);
	int (*rx_dma)(struct uart_8250_port *);
	void (*prepare_tx_dma)(struct uart_8250_port *);
	void (*prepare_rx_dma)(struct uart_8250_port *);
	dma_filter_fn fn;
	void *rx_param;
	void *tx_param;
	struct dma_slave_config rxconf;
	struct dma_slave_config txconf;
	struct dma_chan *rxchan;
	struct dma_chan *txchan;
	phys_addr_t rx_dma_addr;
	phys_addr_t tx_dma_addr;
	dma_addr_t rx_addr;
	dma_addr_t tx_addr;
	dma_cookie_t rx_cookie;
	dma_cookie_t tx_cookie;
	void *rx_buf;
	size_t rx_size;
	size_t tx_size;
	unsigned char tx_running;
	unsigned char tx_err;
	unsigned char rx_running;
};

enum dma_status {
	DMA_COMPLETE = 0,
	DMA_IN_PROGRESS = 1,
	DMA_PAUSED = 2,
	DMA_ERROR = 3,
	DMA_OUT_OF_ORDER = 4,
};

enum dma_transaction_type {
	DMA_MEMCPY = 0,
	DMA_XOR = 1,
	DMA_PQ = 2,
	DMA_XOR_VAL = 3,
	DMA_PQ_VAL = 4,
	DMA_MEMSET = 5,
	DMA_MEMSET_SG = 6,
	DMA_INTERRUPT = 7,
	DMA_PRIVATE = 8,
	DMA_ASYNC_TX = 9,
	DMA_SLAVE = 10,
	DMA_CYCLIC = 11,
	DMA_INTERLEAVE = 12,
	DMA_COMPLETION_NO_ORDER = 13,
	DMA_REPEAT = 14,
	DMA_LOAD_EOT = 15,
	DMA_TX_TYPE_END = 16,
};

struct data_chunk {
	size_t size;
	size_t icg;
	size_t dst_icg;
	size_t src_icg;
};

struct dma_interleaved_template {
	dma_addr_t src_start;
	dma_addr_t dst_start;
	enum dma_transfer_direction dir;
	bool src_inc;
	bool dst_inc;
	bool src_sgl;
	bool dst_sgl;
	size_t numf;
	size_t frame_size;
	struct data_chunk sgl[0];
};

enum dma_ctrl_flags {
	DMA_PREP_INTERRUPT = 1,
	DMA_CTRL_ACK = 2,
	DMA_PREP_PQ_DISABLE_P = 4,
	DMA_PREP_PQ_DISABLE_Q = 8,
	DMA_PREP_CONTINUE = 16,
	DMA_PREP_FENCE = 32,
	DMA_CTRL_REUSE = 64,
	DMA_PREP_CMD = 128,
	DMA_PREP_REPEAT = 256,
	DMA_PREP_LOAD_EOT = 512,
};

enum sum_check_bits {
	SUM_CHECK_P = 0,
	SUM_CHECK_Q = 1,
};

enum sum_check_flags {
	SUM_CHECK_P_RESULT = 1,
	SUM_CHECK_Q_RESULT = 2,
};

typedef struct {
	long unsigned int bits[1];
} dma_cap_mask_t;

enum dma_desc_metadata_mode {
	DESC_METADATA_NONE = 0,
	DESC_METADATA_CLIENT = 1,
	DESC_METADATA_ENGINE = 2,
};

struct dma_chan_percpu {
	long unsigned int memcpy_count;
	long unsigned int bytes_transferred;
};

struct dma_router {
	struct device *dev;
	void (*route_free)(struct device *, void *);
};

struct dma_device;

struct dma_chan_dev;

struct dma_chan {
	struct dma_device *device;
	struct device *slave;
	dma_cookie_t cookie;
	dma_cookie_t completed_cookie;
	int chan_id;
	struct dma_chan_dev *dev;
	const char *name;
	char *dbg_client_name;
	struct list_head device_node;
	struct dma_chan_percpu *local;
	int client_count;
	int table_count;
	struct dma_router *router;
	void *route_data;
	void *private;
};

struct dma_slave_map;

struct dma_filter {
	dma_filter_fn fn;
	int mapcnt;
	const struct dma_slave_map *map;
};

enum dmaengine_alignment {
	DMAENGINE_ALIGN_1_BYTE = 0,
	DMAENGINE_ALIGN_2_BYTES = 1,
	DMAENGINE_ALIGN_4_BYTES = 2,
	DMAENGINE_ALIGN_8_BYTES = 3,
	DMAENGINE_ALIGN_16_BYTES = 4,
	DMAENGINE_ALIGN_32_BYTES = 5,
	DMAENGINE_ALIGN_64_BYTES = 6,
	DMAENGINE_ALIGN_128_BYTES = 7,
	DMAENGINE_ALIGN_256_BYTES = 8,
};

enum dma_residue_granularity {
	DMA_RESIDUE_GRANULARITY_DESCRIPTOR = 0,
	DMA_RESIDUE_GRANULARITY_SEGMENT = 1,
	DMA_RESIDUE_GRANULARITY_BURST = 2,
};

struct dma_async_tx_descriptor;

struct dma_slave_caps;

struct dma_tx_state;

struct dma_device {
	struct kref ref;
	unsigned int chancnt;
	unsigned int privatecnt;
	struct list_head channels;
	struct list_head global_node;
	struct dma_filter filter;
	dma_cap_mask_t cap_mask;
	enum dma_desc_metadata_mode desc_metadata_modes;
	short unsigned int max_xor;
	short unsigned int max_pq;
	enum dmaengine_alignment copy_align;
	enum dmaengine_alignment xor_align;
	enum dmaengine_alignment pq_align;
	enum dmaengine_alignment fill_align;
	int dev_id;
	struct device *dev;
	struct module *owner;
	struct ida chan_ida;
	u32 src_addr_widths;
	u32 dst_addr_widths;
	u32 directions;
	u32 min_burst;
	u32 max_burst;
	u32 max_sg_burst;
	bool descriptor_reuse;
	enum dma_residue_granularity residue_granularity;
	int (*device_alloc_chan_resources)(struct dma_chan *);
	int (*device_router_config)(struct dma_chan *);
	void (*device_free_chan_resources)(struct dma_chan *);
	struct dma_async_tx_descriptor * (*device_prep_dma_memcpy)(struct dma_chan *, dma_addr_t, dma_addr_t, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_xor)(struct dma_chan *, dma_addr_t, dma_addr_t *, unsigned int, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_xor_val)(struct dma_chan *, dma_addr_t *, unsigned int, size_t, enum sum_check_flags *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_pq)(struct dma_chan *, dma_addr_t *, dma_addr_t *, unsigned int, const unsigned char *, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_pq_val)(struct dma_chan *, dma_addr_t *, dma_addr_t *, unsigned int, const unsigned char *, size_t, enum sum_check_flags *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_memset)(struct dma_chan *, dma_addr_t, int, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_memset_sg)(struct dma_chan *, struct scatterlist *, unsigned int, int, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_interrupt)(struct dma_chan *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_slave_sg)(struct dma_chan *, struct scatterlist *, unsigned int, enum dma_transfer_direction, long unsigned int, void *);
	struct dma_async_tx_descriptor * (*device_prep_dma_cyclic)(struct dma_chan *, dma_addr_t, size_t, size_t, enum dma_transfer_direction, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_interleaved_dma)(struct dma_chan *, struct dma_interleaved_template *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_imm_data)(struct dma_chan *, dma_addr_t, u64, long unsigned int);
	void (*device_caps)(struct dma_chan *, struct dma_slave_caps *);
	int (*device_config)(struct dma_chan *, struct dma_slave_config *);
	int (*device_pause)(struct dma_chan *);
	int (*device_resume)(struct dma_chan *);
	int (*device_terminate_all)(struct dma_chan *);
	void (*device_synchronize)(struct dma_chan *);
	enum dma_status (*device_tx_status)(struct dma_chan *, dma_cookie_t, struct dma_tx_state *);
	void (*device_issue_pending)(struct dma_chan *);
	void (*device_release)(struct dma_device *);
	void (*dbg_summary_show)(struct seq_file *, struct dma_device *);
	struct dentry *dbg_dev_root;
};

struct dma_chan_dev {
	struct dma_chan *chan;
	struct device device;
	int dev_id;
	bool chan_dma_dev;
};

struct dma_slave_caps {
	u32 src_addr_widths;
	u32 dst_addr_widths;
	u32 directions;
	u32 min_burst;
	u32 max_burst;
	u32 max_sg_burst;
	bool cmd_pause;
	bool cmd_resume;
	bool cmd_terminate;
	enum dma_residue_granularity residue_granularity;
	bool descriptor_reuse;
};

typedef void (*dma_async_tx_callback)(void *);

enum dmaengine_tx_result {
	DMA_TRANS_NOERROR = 0,
	DMA_TRANS_READ_FAILED = 1,
	DMA_TRANS_WRITE_FAILED = 2,
	DMA_TRANS_ABORTED = 3,
};

struct dmaengine_result {
	enum dmaengine_tx_result result;
	u32 residue;
};

typedef void (*dma_async_tx_callback_result)(void *, const struct dmaengine_result *);

struct dmaengine_unmap_data {
	u8 map_cnt;
	u8 to_cnt;
	u8 from_cnt;
	u8 bidi_cnt;
	struct device *dev;
	struct kref kref;
	size_t len;
	dma_addr_t addr[0];
};

struct dma_descriptor_metadata_ops {
	int (*attach)(struct dma_async_tx_descriptor *, void *, size_t);
	void * (*get_ptr)(struct dma_async_tx_descriptor *, size_t *, size_t *);
	int (*set_len)(struct dma_async_tx_descriptor *, size_t);
};

struct dma_async_tx_descriptor {
	dma_cookie_t cookie;
	enum dma_ctrl_flags flags;
	dma_addr_t phys;
	struct dma_chan *chan;
	dma_cookie_t (*tx_submit)(struct dma_async_tx_descriptor *);
	int (*desc_free)(struct dma_async_tx_descriptor *);
	dma_async_tx_callback callback;
	dma_async_tx_callback_result callback_result;
	void *callback_param;
	struct dmaengine_unmap_data *unmap;
	enum dma_desc_metadata_mode desc_metadata_mode;
	struct dma_descriptor_metadata_ops *metadata_ops;
};

struct dma_tx_state {
	dma_cookie_t last;
	dma_cookie_t used;
	u32 residue;
	u32 in_flight_bytes;
};

struct dma_slave_map {
	const char *devname;
	const char *slave;
	void *param;
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

struct driver_private {
	struct kobject kobj;
	struct klist klist_devices;
	struct klist_node knode_bus;
	struct module_kobject *mkobj;
	struct device_driver *driver;
};

typedef void (*dr_release_t)(struct device *, void *);

typedef int (*dr_match_t)(struct device *, void *, void *);

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

struct firmware {
	size_t size;
	const u8 *data;
	void *priv;
};

typedef u64 async_cookie_t;

typedef void (*async_func_t)(void *, async_cookie_t);

struct async_domain {
	struct list_head pending;
	unsigned int registered: 1;
};

typedef void * (*ZSTD_allocFunction)(void *, size_t);

typedef void (*ZSTD_freeFunction)(void *, void *);

typedef struct {
	ZSTD_allocFunction customAlloc;
	ZSTD_freeFunction customFree;
	void *opaque;
} ZSTD_customMem;

enum xz_mode {
	XZ_SINGLE = 0,
	XZ_PREALLOC = 1,
	XZ_DYNALLOC = 2,
};

enum xz_ret {
	XZ_OK = 0,
	XZ_STREAM_END = 1,
	XZ_UNSUPPORTED_CHECK = 2,
	XZ_MEM_ERROR = 3,
	XZ_MEMLIMIT_ERROR = 4,
	XZ_FORMAT_ERROR = 5,
	XZ_OPTIONS_ERROR = 6,
	XZ_DATA_ERROR = 7,
	XZ_BUF_ERROR = 8,
};

struct xz_buf {
	const uint8_t *in;
	size_t in_pos;
	size_t in_size;
	uint8_t *out;
	size_t out_pos;
	size_t out_size;
};

enum fw_opt {
	FW_OPT_UEVENT = 1,
	FW_OPT_NOWAIT = 2,
	FW_OPT_USERHELPER = 4,
	FW_OPT_NO_WARN = 8,
	FW_OPT_NOCACHE = 16,
	FW_OPT_NOFALLBACK_SYSFS = 32,
	FW_OPT_FALLBACK_PLATFORM = 64,
	FW_OPT_PARTIAL = 128,
};

enum fw_status {
	FW_STATUS_UNKNOWN = 0,
	FW_STATUS_LOADING = 1,
	FW_STATUS_DONE = 2,
	FW_STATUS_ABORTED = 3,
};

struct fw_state {
	struct completion completion;
	enum fw_status status;
};

struct firmware_cache;

struct fw_priv {
	struct kref ref;
	struct list_head list;
	struct firmware_cache *fwc;
	struct fw_state fw_st;
	void *data;
	size_t size;
	size_t allocated_size;
	size_t offset;
	u32 opt_flags;
	bool is_paged_buf;
	struct page **pages;
	int nr_pages;
	int page_array_size;
	const char *fw_name;
};

struct firmware_cache {
	spinlock_t lock;
	struct list_head head;
	int state;
	spinlock_t name_lock;
	struct list_head fw_names;
	struct delayed_work work;
	struct notifier_block pm_notify;
};

struct fw_cache_entry {
	struct list_head list;
	const char *name;
};

struct fw_name_devm {
	long unsigned int magic;
	const char *name;
};

struct firmware_work {
	struct work_struct work;
	struct module *module;
	const char *name;
	struct device *device;
	void *context;
	void (*cont)(const struct firmware *, void *);
	u32 opt_flags;
};

enum scsi_host_status {
	DID_OK = 0,
	DID_NO_CONNECT = 1,
	DID_BUS_BUSY = 2,
	DID_TIME_OUT = 3,
	DID_BAD_TARGET = 4,
	DID_ABORT = 5,
	DID_PARITY = 6,
	DID_ERROR = 7,
	DID_RESET = 8,
	DID_BAD_INTR = 9,
	DID_PASSTHROUGH = 10,
	DID_SOFT_ERROR = 11,
	DID_IMM_RETRY = 12,
	DID_REQUEUE = 13,
	DID_TRANSPORT_DISRUPTED = 14,
	DID_TRANSPORT_FAILFAST = 15,
	DID_TRANSPORT_MARGINAL = 20,
};

enum scsi_disposition {
	NEEDS_RETRY = 8193,
	SUCCESS = 8194,
	FAILED = 8195,
	QUEUED = 8196,
	SOFT_ERROR = 8197,
	ADD_TO_MLQUEUE = 8198,
	TIMEOUT_ERROR = 8199,
	SCSI_RETURN_NOT_HANDLED = 8200,
	FAST_IO_FAIL = 8201,
};

enum scsi_device_event {
	SDEV_EVT_MEDIA_CHANGE = 1,
	SDEV_EVT_INQUIRY_CHANGE_REPORTED = 2,
	SDEV_EVT_CAPACITY_CHANGE_REPORTED = 3,
	SDEV_EVT_SOFT_THRESHOLD_REACHED_REPORTED = 4,
	SDEV_EVT_MODE_PARAMETER_CHANGE_REPORTED = 5,
	SDEV_EVT_LUN_CHANGE_REPORTED = 6,
	SDEV_EVT_ALUA_STATE_CHANGE_REPORTED = 7,
	SDEV_EVT_POWER_ON_RESET_OCCURRED = 8,
	SDEV_EVT_FIRST = 1,
	SDEV_EVT_LAST = 8,
	SDEV_EVT_MAXBITS = 9,
};

struct value_name_pair;

struct sa_name_list {
	int opcode;
	const struct value_name_pair *arr;
	int arr_sz;
};

struct value_name_pair {
	int value;
	const char *name;
};

struct error_info {
	short unsigned int code12;
	short unsigned int size;
};

struct error_info2 {
	unsigned char code1;
	unsigned char code2_min;
	unsigned char code2_max;
	const char *str;
	const char *fmt;
};

typedef __u64 timeu64_t;

typedef unsigned int xa_mark_t;

enum xa_lock_type {
	XA_LOCK_IRQ = 1,
	XA_LOCK_BH = 2,
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

struct rtc_wkalrm {
	unsigned char enabled;
	unsigned char pending;
	struct rtc_time time;
};

struct rtc_param {
	__u64 param;
	union {
		__u64 uvalue;
		__s64 svalue;
		__u64 ptr;
	};
	__u32 index;
	__u32 __pad;
};

struct rtc_class_ops {
	int (*ioctl)(struct device *, unsigned int, long unsigned int);
	int (*read_time)(struct device *, struct rtc_time *);
	int (*set_time)(struct device *, struct rtc_time *);
	int (*read_alarm)(struct device *, struct rtc_wkalrm *);
	int (*set_alarm)(struct device *, struct rtc_wkalrm *);
	int (*proc)(struct device *, struct seq_file *);
	int (*alarm_irq_enable)(struct device *, unsigned int);
	int (*read_offset)(struct device *, long int *);
	int (*set_offset)(struct device *, long int);
	int (*param_get)(struct device *, struct rtc_param *);
	int (*param_set)(struct device *, struct rtc_param *);
};

struct rtc_device;

struct rtc_timer {
	struct timerqueue_node node;
	ktime_t period;
	void (*func)(struct rtc_device *);
	struct rtc_device *rtc;
	int enabled;
};

struct rtc_device {
	struct device dev;
	struct module *owner;
	int id;
	const struct rtc_class_ops *ops;
	struct mutex ops_lock;
	struct cdev char_dev;
	long unsigned int flags;
	long unsigned int irq_data;
	spinlock_t irq_lock;
	wait_queue_head_t irq_queue;
	struct fasync_struct *async_queue;
	int irq_freq;
	int max_user_freq;
	struct timerqueue_head timerqueue;
	struct rtc_timer aie_timer;
	struct rtc_timer uie_rtctimer;
	struct hrtimer pie_timer;
	int pie_enabled;
	struct work_struct irqwork;
	long unsigned int set_offset_nsec;
	long unsigned int features[1];
	time64_t range_min;
	timeu64_t range_max;
	timeu64_t alarm_offset_max;
	time64_t start_secs;
	time64_t offset_secs;
	bool set_start_time;
};

struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *, struct device_attribute *, char *);
	ssize_t (*store)(struct device *, struct device_attribute *, const char *, size_t);
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

struct posix_clock;

struct posix_clock_context;

struct posix_clock_operations {
	struct module *owner;
	int (*clock_adjtime)(struct posix_clock *, struct __kernel_timex *);
	int (*clock_gettime)(struct posix_clock *, struct timespec64 *);
	int (*clock_getres)(struct posix_clock *, struct timespec64 *);
	int (*clock_settime)(struct posix_clock *, const struct timespec64 *);
	long int (*ioctl)(struct posix_clock_context *, unsigned int, long unsigned int);
	int (*open)(struct posix_clock_context *, fmode_t);
	__poll_t (*poll)(struct posix_clock_context *, struct file *, poll_table *);
	int (*release)(struct posix_clock_context *);
	ssize_t (*read)(struct posix_clock_context *, uint, char *, size_t);
};

struct posix_clock {
	struct posix_clock_operations ops;
	struct cdev cdev;
	struct device *dev;
	struct rw_semaphore rwsem;
	bool zombie;
};

struct posix_clock_context {
	struct posix_clock *clk;
	void *private_clkdata;
};

struct ptp_clock_time {
	__s64 sec;
	__u32 nsec;
	__u32 reserved;
};

struct ptp_extts_request {
	unsigned int index;
	unsigned int flags;
	unsigned int rsv[2];
};

struct ptp_perout_request {
	union {
		struct ptp_clock_time start;
		struct ptp_clock_time phase;
	};
	struct ptp_clock_time period;
	unsigned int index;
	unsigned int flags;
	union {
		struct ptp_clock_time on;
		unsigned int rsv[4];
	};
};

enum ptp_pin_function {
	PTP_PF_NONE = 0,
	PTP_PF_EXTTS = 1,
	PTP_PF_PEROUT = 2,
	PTP_PF_PHYSYNC = 3,
};

struct ptp_pin_desc {
	char name[64];
	unsigned int index;
	unsigned int func;
	unsigned int chan;
	unsigned int rsv[5];
};

struct ptp_extts_event {
	struct ptp_clock_time t;
	unsigned int index;
	unsigned int flags;
	unsigned int rsv[2];
};

struct pps_ktime {
	__s64 sec;
	__s32 nsec;
	__u32 flags;
};

struct pps_kparams {
	int api_version;
	int mode;
	struct pps_ktime assert_off_tu;
	struct pps_ktime clear_off_tu;
};

struct pps_device;

struct pps_source_info {
	char name[32];
	char path[32];
	int mode;
	void (*echo)(struct pps_device *, int, void *);
	struct module *owner;
	struct device *dev;
};

struct pps_device {
	struct pps_source_info info;
	struct pps_kparams params;
	__u32 assert_sequence;
	__u32 clear_sequence;
	struct pps_ktime assert_tu;
	struct pps_ktime clear_tu;
	int current_mode;
	unsigned int last_ev;
	wait_queue_head_t queue;
	unsigned int id;
	const void *lookup_cookie;
	struct cdev cdev;
	struct device *dev;
	struct fasync_struct *async_queue;
	spinlock_t lock;
};

struct cyclecounter {
	u64 (*read)(const struct cyclecounter *);
	u64 mask;
	u32 mult;
	u32 shift;
};

struct timecounter {
	const struct cyclecounter *cc;
	u64 cycle_last;
	u64 nsec;
	u64 mask;
	u64 frac;
};

enum flow_dissector_key_id {
	FLOW_DISSECTOR_KEY_CONTROL = 0,
	FLOW_DISSECTOR_KEY_BASIC = 1,
	FLOW_DISSECTOR_KEY_IPV4_ADDRS = 2,
	FLOW_DISSECTOR_KEY_IPV6_ADDRS = 3,
	FLOW_DISSECTOR_KEY_PORTS = 4,
	FLOW_DISSECTOR_KEY_PORTS_RANGE = 5,
	FLOW_DISSECTOR_KEY_ICMP = 6,
	FLOW_DISSECTOR_KEY_ETH_ADDRS = 7,
	FLOW_DISSECTOR_KEY_TIPC = 8,
	FLOW_DISSECTOR_KEY_ARP = 9,
	FLOW_DISSECTOR_KEY_VLAN = 10,
	FLOW_DISSECTOR_KEY_FLOW_LABEL = 11,
	FLOW_DISSECTOR_KEY_GRE_KEYID = 12,
	FLOW_DISSECTOR_KEY_MPLS_ENTROPY = 13,
	FLOW_DISSECTOR_KEY_ENC_KEYID = 14,
	FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS = 15,
	FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS = 16,
	FLOW_DISSECTOR_KEY_ENC_CONTROL = 17,
	FLOW_DISSECTOR_KEY_ENC_PORTS = 18,
	FLOW_DISSECTOR_KEY_MPLS = 19,
	FLOW_DISSECTOR_KEY_TCP = 20,
	FLOW_DISSECTOR_KEY_IP = 21,
	FLOW_DISSECTOR_KEY_CVLAN = 22,
	FLOW_DISSECTOR_KEY_ENC_IP = 23,
	FLOW_DISSECTOR_KEY_ENC_OPTS = 24,
	FLOW_DISSECTOR_KEY_META = 25,
	FLOW_DISSECTOR_KEY_CT = 26,
	FLOW_DISSECTOR_KEY_HASH = 27,
	FLOW_DISSECTOR_KEY_NUM_OF_VLANS = 28,
	FLOW_DISSECTOR_KEY_PPPOE = 29,
	FLOW_DISSECTOR_KEY_L2TPV3 = 30,
	FLOW_DISSECTOR_KEY_CFM = 31,
	FLOW_DISSECTOR_KEY_IPSEC = 32,
	FLOW_DISSECTOR_KEY_MAX = 33,
};

enum skb_ext_id {
	SKB_EXT_BRIDGE_NF = 0,
	SKB_EXT_SEC_PATH = 1,
	SKB_EXT_MPTCP = 2,
	SKB_EXT_NUM = 3,
};

struct ptp_clock_request {
	enum {
		PTP_CLK_REQ_EXTTS = 0,
		PTP_CLK_REQ_PEROUT = 1,
		PTP_CLK_REQ_PPS = 2,
	} type;
	union {
		struct ptp_extts_request extts;
		struct ptp_perout_request perout;
	};
};

struct ptp_system_timestamp {
	struct timespec64 pre_ts;
	struct timespec64 post_ts;
};

struct ptp_clock_info {
	struct module *owner;
	char name[32];
	s32 max_adj;
	int n_alarm;
	int n_ext_ts;
	int n_per_out;
	int n_pins;
	int pps;
	struct ptp_pin_desc *pin_config;
	int (*adjfine)(struct ptp_clock_info *, long int);
	int (*adjphase)(struct ptp_clock_info *, s32);
	s32 (*getmaxphase)(struct ptp_clock_info *);
	int (*adjtime)(struct ptp_clock_info *, s64);
	int (*gettime64)(struct ptp_clock_info *, struct timespec64 *);
	int (*gettimex64)(struct ptp_clock_info *, struct timespec64 *, struct ptp_system_timestamp *);
	int (*getcrosststamp)(struct ptp_clock_info *, struct system_device_crosststamp *);
	int (*settime64)(struct ptp_clock_info *, const struct timespec64 *);
	int (*getcycles64)(struct ptp_clock_info *, struct timespec64 *);
	int (*getcyclesx64)(struct ptp_clock_info *, struct timespec64 *, struct ptp_system_timestamp *);
	int (*getcrosscycles)(struct ptp_clock_info *, struct system_device_crosststamp *);
	int (*enable)(struct ptp_clock_info *, struct ptp_clock_request *, int);
	int (*verify)(struct ptp_clock_info *, unsigned int, enum ptp_pin_function, unsigned int);
	long int (*do_aux_work)(struct ptp_clock_info *);
};

struct debugfs_u32_array {
	u32 *array;
	u32 n_elements;
};

struct timestamp_event_queue {
	struct ptp_extts_event buf[128];
	int head;
	int tail;
	spinlock_t lock;
	struct list_head qlist;
	long unsigned int *mask;
	struct dentry *debugfs_instance;
	struct debugfs_u32_array dfs_bitmap;
};

struct ptp_clock {
	struct posix_clock clock;
	struct device dev;
	struct ptp_clock_info *info;
	dev_t devid;
	int index;
	struct pps_device *pps_source;
	long int dialed_frequency;
	struct list_head tsevqs;
	spinlock_t tsevqs_lock;
	struct mutex pincfg_mux;
	wait_queue_head_t tsev_wq;
	int defunct;
	struct device_attribute *pin_dev_attr;
	struct attribute **pin_attr;
	struct attribute_group pin_attr_group;
	const struct attribute_group *pin_attr_groups[2];
	struct kthread_worker *kworker;
	struct kthread_delayed_work aux_work;
	unsigned int max_vclocks;
	unsigned int n_vclocks;
	int *vclock_index;
	struct mutex n_vclocks_mux;
	bool is_virtual_clock;
	bool has_cycles;
	struct dentry *debugfs_root;
};

struct ptp_vclock {
	struct ptp_clock *pclock;
	struct ptp_clock_info info;
	struct ptp_clock *clock;
	struct hlist_node vclock_hash_node;
	struct cyclecounter cc;
	struct timecounter tc;
	struct mutex lock;
};

struct cpuidle_state_usage {
	long long unsigned int disable;
	long long unsigned int usage;
	u64 time_ns;
	long long unsigned int above;
	long long unsigned int below;
	long long unsigned int rejected;
	long long unsigned int s2idle_usage;
	long long unsigned int s2idle_time;
};

struct cpuidle_device;

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

struct cpuidle_driver_kobj;

struct cpuidle_state_kobj;

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

struct cpuidle_state_kobj {
	struct cpuidle_state *state;
	struct cpuidle_state_usage *state_usage;
	struct completion kobj_unregister;
	struct kobject kobj;
	struct cpuidle_device *device;
};

struct cpuidle_device_kobj {
	struct cpuidle_device *dev;
	struct completion kobj_unregister;
	struct kobject kobj;
};

struct cpuidle_governor {
	char name[16];
	struct list_head governor_list;
	unsigned int rating;
	int (*enable)(struct cpuidle_driver *, struct cpuidle_device *);
	void (*disable)(struct cpuidle_driver *, struct cpuidle_device *);
	int (*select)(struct cpuidle_driver *, struct cpuidle_device *, bool *);
	void (*reflect)(struct cpuidle_device *, int);
};

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

struct cpuidle_attr {
	struct attribute attr;
	ssize_t (*show)(struct cpuidle_device *, char *);
	ssize_t (*store)(struct cpuidle_device *, const char *, size_t);
};

struct cpuidle_state_attr {
	struct attribute attr;
	ssize_t (*show)(struct cpuidle_state *, struct cpuidle_state_usage *, char *);
	ssize_t (*store)(struct cpuidle_state *, struct cpuidle_state_usage *, const char *, size_t);
};

struct ps3av_send_hdr {
	u16 version;
	u16 size;
	u32 cid;
};

struct ps3av_reply_hdr {
	u16 version;
	u16 size;
	u32 cid;
	u32 status;
};

struct ps3av_pkt_av_get_hw_conf {
	struct ps3av_send_hdr send_hdr;
	u32 status;
	u16 num_of_hdmi;
	u16 num_of_avmulti;
	u16 num_of_spdif;
	u16 reserved;
};

struct ps3av_info_resolution {
	u32 res_bits;
	u32 native;
};

struct ps3av_info_cs {
	u8 rgb;
	u8 yuv444;
	u8 yuv422;
	u8 reserved;
};

struct ps3av_info_color {
	u16 red_x;
	u16 red_y;
	u16 green_x;
	u16 green_y;
	u16 blue_x;
	u16 blue_y;
	u16 white_x;
	u16 white_y;
	u32 gamma;
};

struct ps3av_info_audio {
	u8 type;
	u8 max_num_of_ch;
	u8 fs;
	u8 sbit;
};

struct ps3av_info_monitor {
	u8 avport;
	u8 monitor_id[10];
	u8 monitor_type;
	u8 monitor_name[16];
	struct ps3av_info_resolution res_60;
	struct ps3av_info_resolution res_50;
	struct ps3av_info_resolution res_other;
	struct ps3av_info_resolution res_vesa;
	struct ps3av_info_cs cs;
	struct ps3av_info_color color;
	u8 supported_ai;
	u8 speaker_info;
	u8 num_of_audio_block;
	struct ps3av_info_audio audio[0];
	u8 reserved[169];
};

struct ps3av_pkt_av_get_monitor_info {
	struct ps3av_send_hdr send_hdr;
	u16 avport;
	u16 reserved;
	struct ps3av_info_monitor info;
};

struct ps3av_pkt_audio_mode {
	struct ps3av_send_hdr send_hdr;
	u8 avport;
	u8 reserved0[3];
	u32 mask;
	u32 audio_num_of_ch;
	u32 audio_fs;
	u32 audio_word_bits;
	u32 audio_format;
	u32 audio_source;
	u8 audio_enable[4];
	u8 audio_swap[4];
	u8 audio_map[4];
	u32 audio_layout;
	u32 audio_downmix;
	u32 audio_downmix_level;
	u8 audio_cs_info[8];
};

struct ps3av_pkt_avb_param {
	struct ps3av_send_hdr send_hdr;
	u16 num_of_video_pkt;
	u16 num_of_audio_pkt;
	u16 num_of_av_video_pkt;
	u16 num_of_av_audio_pkt;
	u8 buf[220];
};

enum ps3_param_av_multi_out {
	PS3_PARAM_AV_MULTI_OUT_NTSC = 0,
	PS3_PARAM_AV_MULTI_OUT_PAL_RGB = 1,
	PS3_PARAM_AV_MULTI_OUT_PAL_YCBCR = 2,
	PS3_PARAM_AV_MULTI_OUT_SECAM = 3,
};

struct ps3_vuart_port_driver {
	struct ps3_system_bus_driver core;
	int (*probe)(struct ps3_system_bus_device *);
	int (*remove)(struct ps3_system_bus_device *);
	void (*shutdown)(struct ps3_system_bus_device *);
	void (*work)(struct ps3_system_bus_device *);
};

struct ps3av {
	struct mutex mutex;
	struct work_struct work;
	struct completion done;
	int open_count;
	struct ps3_system_bus_device *dev;
	int region;
	struct ps3av_pkt_av_get_hw_conf av_hw_conf;
	u32 av_port[4];
	u32 opt_port[1];
	u32 head[2];
	u32 audio_port;
	int ps3av_mode;
	int ps3av_mode_old;
	union {
		struct ps3av_reply_hdr reply_hdr;
		u8 raw[512];
	} recv_buf;
};

struct avset_video_mode {
	u32 cs;
	u32 fmt;
	u32 vid;
	u32 aspect;
	u32 x;
	u32 y;
};

struct ps3av_monitor_quirk {
	const char *monitor_name;
	u32 clear_60;
};

typedef __u16 __sum16;

typedef unsigned char u_char;

struct va_format {
	const char *fmt;
	va_list *va;
};

typedef void (*smp_call_func_t)(void *);

struct __call_single_data {
	struct __call_single_node node;
	smp_call_func_t func;
	void *info;
};

typedef struct __call_single_data call_single_data_t;

struct page_pool_params_fast {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device *dev;
	struct napi_struct *napi;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
};

struct pp_alloc_cache {
	u32 count;
	struct page *cache[128];
};

struct ptr_ring {
	int producer;
	spinlock_t producer_lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	int consumer_head;
	int consumer_tail;
	spinlock_t consumer_lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	int size;
	int batch;
	void **queue;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct page_pool_params_slow {
	struct net_device *netdev;
	void (*init_callback)(struct page *, void *);
	void *init_arg;
};

struct page_pool {
	struct page_pool_params_fast p;
	int cpuid;
	bool has_init_callback;
	long int frag_users;
	struct page *frag_page;
	unsigned int frag_offset;
	u32 pages_state_hold_cnt;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 xdp_mem_id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	struct page_pool_params_slow slow;
	struct {
		struct hlist_node list;
		u64 detach_time;
		u32 napi_id;
		u32 id;
	} user;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct xa_limit {
	u32 max;
	u32 min;
};

enum device_link_state {
	DL_STATE_NONE = -1,
	DL_STATE_DORMANT = 0,
	DL_STATE_AVAILABLE = 1,
	DL_STATE_CONSUMER_PROBE = 2,
	DL_STATE_ACTIVE = 3,
	DL_STATE_SUPPLIER_UNBIND = 4,
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

struct semaphore {
	raw_spinlock_t lock;
	unsigned int count;
	struct list_head wait_list;
};

struct softirq_action {
	void (*action)(struct softirq_action *);
};

enum {
	NETIF_F_SG_BIT = 0,
	NETIF_F_IP_CSUM_BIT = 1,
	__UNUSED_NETIF_F_1 = 2,
	NETIF_F_HW_CSUM_BIT = 3,
	NETIF_F_IPV6_CSUM_BIT = 4,
	NETIF_F_HIGHDMA_BIT = 5,
	NETIF_F_FRAGLIST_BIT = 6,
	NETIF_F_HW_VLAN_CTAG_TX_BIT = 7,
	NETIF_F_HW_VLAN_CTAG_RX_BIT = 8,
	NETIF_F_HW_VLAN_CTAG_FILTER_BIT = 9,
	NETIF_F_VLAN_CHALLENGED_BIT = 10,
	NETIF_F_GSO_BIT = 11,
	NETIF_F_LLTX_BIT = 12,
	NETIF_F_NETNS_LOCAL_BIT = 13,
	NETIF_F_GRO_BIT = 14,
	NETIF_F_LRO_BIT = 15,
	NETIF_F_GSO_SHIFT = 16,
	NETIF_F_TSO_BIT = 16,
	NETIF_F_GSO_ROBUST_BIT = 17,
	NETIF_F_TSO_ECN_BIT = 18,
	NETIF_F_TSO_MANGLEID_BIT = 19,
	NETIF_F_TSO6_BIT = 20,
	NETIF_F_FSO_BIT = 21,
	NETIF_F_GSO_GRE_BIT = 22,
	NETIF_F_GSO_GRE_CSUM_BIT = 23,
	NETIF_F_GSO_IPXIP4_BIT = 24,
	NETIF_F_GSO_IPXIP6_BIT = 25,
	NETIF_F_GSO_UDP_TUNNEL_BIT = 26,
	NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT = 27,
	NETIF_F_GSO_PARTIAL_BIT = 28,
	NETIF_F_GSO_TUNNEL_REMCSUM_BIT = 29,
	NETIF_F_GSO_SCTP_BIT = 30,
	NETIF_F_GSO_ESP_BIT = 31,
	NETIF_F_GSO_UDP_BIT = 32,
	NETIF_F_GSO_UDP_L4_BIT = 33,
	NETIF_F_GSO_FRAGLIST_BIT = 34,
	NETIF_F_GSO_LAST = 34,
	NETIF_F_FCOE_CRC_BIT = 35,
	NETIF_F_SCTP_CRC_BIT = 36,
	NETIF_F_FCOE_MTU_BIT = 37,
	NETIF_F_NTUPLE_BIT = 38,
	NETIF_F_RXHASH_BIT = 39,
	NETIF_F_RXCSUM_BIT = 40,
	NETIF_F_NOCACHE_COPY_BIT = 41,
	NETIF_F_LOOPBACK_BIT = 42,
	NETIF_F_RXFCS_BIT = 43,
	NETIF_F_RXALL_BIT = 44,
	NETIF_F_HW_VLAN_STAG_TX_BIT = 45,
	NETIF_F_HW_VLAN_STAG_RX_BIT = 46,
	NETIF_F_HW_VLAN_STAG_FILTER_BIT = 47,
	NETIF_F_HW_L2FW_DOFFLOAD_BIT = 48,
	NETIF_F_HW_TC_BIT = 49,
	NETIF_F_HW_ESP_BIT = 50,
	NETIF_F_HW_ESP_TX_CSUM_BIT = 51,
	NETIF_F_RX_UDP_TUNNEL_PORT_BIT = 52,
	NETIF_F_HW_TLS_TX_BIT = 53,
	NETIF_F_HW_TLS_RX_BIT = 54,
	NETIF_F_GRO_HW_BIT = 55,
	NETIF_F_HW_TLS_RECORD_BIT = 56,
	NETIF_F_GRO_FRAGLIST_BIT = 57,
	NETIF_F_HW_MACSEC_BIT = 58,
	NETIF_F_GRO_UDP_FWD_BIT = 59,
	NETIF_F_HW_HSR_TAG_INS_BIT = 60,
	NETIF_F_HW_HSR_TAG_RM_BIT = 61,
	NETIF_F_HW_HSR_FWD_BIT = 62,
	NETIF_F_HW_HSR_DUP_BIT = 63,
	NETDEV_FEATURE_COUNT = 64,
};

enum skb_drop_reason {
	SKB_NOT_DROPPED_YET = 0,
	SKB_CONSUMED = 1,
	SKB_DROP_REASON_NOT_SPECIFIED = 2,
	SKB_DROP_REASON_NO_SOCKET = 3,
	SKB_DROP_REASON_PKT_TOO_SMALL = 4,
	SKB_DROP_REASON_TCP_CSUM = 5,
	SKB_DROP_REASON_SOCKET_FILTER = 6,
	SKB_DROP_REASON_UDP_CSUM = 7,
	SKB_DROP_REASON_NETFILTER_DROP = 8,
	SKB_DROP_REASON_OTHERHOST = 9,
	SKB_DROP_REASON_IP_CSUM = 10,
	SKB_DROP_REASON_IP_INHDR = 11,
	SKB_DROP_REASON_IP_RPFILTER = 12,
	SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST = 13,
	SKB_DROP_REASON_XFRM_POLICY = 14,
	SKB_DROP_REASON_IP_NOPROTO = 15,
	SKB_DROP_REASON_SOCKET_RCVBUFF = 16,
	SKB_DROP_REASON_PROTO_MEM = 17,
	SKB_DROP_REASON_TCP_AUTH_HDR = 18,
	SKB_DROP_REASON_TCP_MD5NOTFOUND = 19,
	SKB_DROP_REASON_TCP_MD5UNEXPECTED = 20,
	SKB_DROP_REASON_TCP_MD5FAILURE = 21,
	SKB_DROP_REASON_TCP_AONOTFOUND = 22,
	SKB_DROP_REASON_TCP_AOUNEXPECTED = 23,
	SKB_DROP_REASON_TCP_AOKEYNOTFOUND = 24,
	SKB_DROP_REASON_TCP_AOFAILURE = 25,
	SKB_DROP_REASON_SOCKET_BACKLOG = 26,
	SKB_DROP_REASON_TCP_FLAGS = 27,
	SKB_DROP_REASON_TCP_ABORT_ON_DATA = 28,
	SKB_DROP_REASON_TCP_ZEROWINDOW = 29,
	SKB_DROP_REASON_TCP_OLD_DATA = 30,
	SKB_DROP_REASON_TCP_OVERWINDOW = 31,
	SKB_DROP_REASON_TCP_OFOMERGE = 32,
	SKB_DROP_REASON_TCP_RFC7323_PAWS = 33,
	SKB_DROP_REASON_TCP_OLD_SEQUENCE = 34,
	SKB_DROP_REASON_TCP_INVALID_SEQUENCE = 35,
	SKB_DROP_REASON_TCP_INVALID_ACK_SEQUENCE = 36,
	SKB_DROP_REASON_TCP_RESET = 37,
	SKB_DROP_REASON_TCP_INVALID_SYN = 38,
	SKB_DROP_REASON_TCP_CLOSE = 39,
	SKB_DROP_REASON_TCP_FASTOPEN = 40,
	SKB_DROP_REASON_TCP_OLD_ACK = 41,
	SKB_DROP_REASON_TCP_TOO_OLD_ACK = 42,
	SKB_DROP_REASON_TCP_ACK_UNSENT_DATA = 43,
	SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE = 44,
	SKB_DROP_REASON_TCP_OFO_DROP = 45,
	SKB_DROP_REASON_IP_OUTNOROUTES = 46,
	SKB_DROP_REASON_BPF_CGROUP_EGRESS = 47,
	SKB_DROP_REASON_IPV6DISABLED = 48,
	SKB_DROP_REASON_NEIGH_CREATEFAIL = 49,
	SKB_DROP_REASON_NEIGH_FAILED = 50,
	SKB_DROP_REASON_NEIGH_QUEUEFULL = 51,
	SKB_DROP_REASON_NEIGH_DEAD = 52,
	SKB_DROP_REASON_TC_EGRESS = 53,
	SKB_DROP_REASON_SECURITY_HOOK = 54,
	SKB_DROP_REASON_QDISC_DROP = 55,
	SKB_DROP_REASON_CPU_BACKLOG = 56,
	SKB_DROP_REASON_XDP = 57,
	SKB_DROP_REASON_TC_INGRESS = 58,
	SKB_DROP_REASON_UNHANDLED_PROTO = 59,
	SKB_DROP_REASON_SKB_CSUM = 60,
	SKB_DROP_REASON_SKB_GSO_SEG = 61,
	SKB_DROP_REASON_SKB_UCOPY_FAULT = 62,
	SKB_DROP_REASON_DEV_HDR = 63,
	SKB_DROP_REASON_DEV_READY = 64,
	SKB_DROP_REASON_FULL_RING = 65,
	SKB_DROP_REASON_NOMEM = 66,
	SKB_DROP_REASON_HDR_TRUNC = 67,
	SKB_DROP_REASON_TAP_FILTER = 68,
	SKB_DROP_REASON_TAP_TXFILTER = 69,
	SKB_DROP_REASON_ICMP_CSUM = 70,
	SKB_DROP_REASON_INVALID_PROTO = 71,
	SKB_DROP_REASON_IP_INADDRERRORS = 72,
	SKB_DROP_REASON_IP_INNOROUTES = 73,
	SKB_DROP_REASON_PKT_TOO_BIG = 74,
	SKB_DROP_REASON_DUP_FRAG = 75,
	SKB_DROP_REASON_FRAG_REASM_TIMEOUT = 76,
	SKB_DROP_REASON_FRAG_TOO_FAR = 77,
	SKB_DROP_REASON_TCP_MINTTL = 78,
	SKB_DROP_REASON_IPV6_BAD_EXTHDR = 79,
	SKB_DROP_REASON_IPV6_NDISC_FRAG = 80,
	SKB_DROP_REASON_IPV6_NDISC_HOP_LIMIT = 81,
	SKB_DROP_REASON_IPV6_NDISC_BAD_CODE = 82,
	SKB_DROP_REASON_IPV6_NDISC_BAD_OPTIONS = 83,
	SKB_DROP_REASON_IPV6_NDISC_NS_OTHERHOST = 84,
	SKB_DROP_REASON_QUEUE_PURGE = 85,
	SKB_DROP_REASON_TC_COOKIE_ERROR = 86,
	SKB_DROP_REASON_PACKET_SOCK_ERROR = 87,
	SKB_DROP_REASON_TC_CHAIN_NOTFOUND = 88,
	SKB_DROP_REASON_TC_RECLASSIFY_LOOP = 89,
	SKB_DROP_REASON_MAX = 90,
	SKB_DROP_REASON_SUBSYS_MASK = 4294901760,
};

typedef long unsigned int netmem_ref;

struct skb_frag {
	netmem_ref netmem;
	unsigned int len;
	unsigned int offset;
};

typedef struct skb_frag skb_frag_t;

enum {
	SKBTX_HW_TSTAMP = 1,
	SKBTX_SW_TSTAMP = 2,
	SKBTX_IN_PROGRESS = 4,
	SKBTX_HW_TSTAMP_USE_CYCLES = 8,
	SKBTX_WIFI_STATUS = 16,
	SKBTX_HW_TSTAMP_NETDEV = 32,
	SKBTX_SCHED_TSTAMP = 64,
};

enum {
	SKBFL_ZEROCOPY_ENABLE = 1,
	SKBFL_SHARED_FRAG = 2,
	SKBFL_PURE_ZEROCOPY = 4,
	SKBFL_DONT_ORPHAN = 8,
	SKBFL_MANAGED_FRAG_REFS = 16,
};

struct xsk_tx_metadata_compl {
	__u64 *tx_timestamp;
};

struct skb_shared_info {
	__u8 flags;
	__u8 meta_len;
	__u8 nr_frags;
	__u8 tx_flags;
	short unsigned int gso_size;
	short unsigned int gso_segs;
	struct sk_buff *frag_list;
	union {
		struct skb_shared_hwtstamps hwtstamps;
		struct xsk_tx_metadata_compl xsk_meta;
	};
	unsigned int gso_type;
	u32 tskey;
	atomic_t dataref;
	unsigned int xdp_frags_size;
	void *destructor_arg;
	skb_frag_t frags[17];
};

enum {
	SKB_FCLONE_UNAVAILABLE = 0,
	SKB_FCLONE_ORIG = 1,
	SKB_FCLONE_CLONE = 2,
};

enum {
	SKB_GSO_TCPV4 = 1,
	SKB_GSO_DODGY = 2,
	SKB_GSO_TCP_ECN = 4,
	SKB_GSO_TCP_FIXEDID = 8,
	SKB_GSO_TCPV6 = 16,
	SKB_GSO_FCOE = 32,
	SKB_GSO_GRE = 64,
	SKB_GSO_GRE_CSUM = 128,
	SKB_GSO_IPXIP4 = 256,
	SKB_GSO_IPXIP6 = 512,
	SKB_GSO_UDP_TUNNEL = 1024,
	SKB_GSO_UDP_TUNNEL_CSUM = 2048,
	SKB_GSO_PARTIAL = 4096,
	SKB_GSO_TUNNEL_REMCSUM = 8192,
	SKB_GSO_SCTP = 16384,
	SKB_GSO_ESP = 32768,
	SKB_GSO_UDP = 65536,
	SKB_GSO_UDP_L4 = 131072,
	SKB_GSO_FRAGLIST = 262144,
};

struct skb_checksum_ops {
	__wsum (*update)(const void *, int, __wsum);
	__wsum (*combine)(__wsum, __wsum, int, int);
};

enum {
	LINUX_MIB_NUM = 0,
	LINUX_MIB_SYNCOOKIESSENT = 1,
	LINUX_MIB_SYNCOOKIESRECV = 2,
	LINUX_MIB_SYNCOOKIESFAILED = 3,
	LINUX_MIB_EMBRYONICRSTS = 4,
	LINUX_MIB_PRUNECALLED = 5,
	LINUX_MIB_RCVPRUNED = 6,
	LINUX_MIB_OFOPRUNED = 7,
	LINUX_MIB_OUTOFWINDOWICMPS = 8,
	LINUX_MIB_LOCKDROPPEDICMPS = 9,
	LINUX_MIB_ARPFILTER = 10,
	LINUX_MIB_TIMEWAITED = 11,
	LINUX_MIB_TIMEWAITRECYCLED = 12,
	LINUX_MIB_TIMEWAITKILLED = 13,
	LINUX_MIB_PAWSACTIVEREJECTED = 14,
	LINUX_MIB_PAWSESTABREJECTED = 15,
	LINUX_MIB_DELAYEDACKS = 16,
	LINUX_MIB_DELAYEDACKLOCKED = 17,
	LINUX_MIB_DELAYEDACKLOST = 18,
	LINUX_MIB_LISTENOVERFLOWS = 19,
	LINUX_MIB_LISTENDROPS = 20,
	LINUX_MIB_TCPHPHITS = 21,
	LINUX_MIB_TCPPUREACKS = 22,
	LINUX_MIB_TCPHPACKS = 23,
	LINUX_MIB_TCPRENORECOVERY = 24,
	LINUX_MIB_TCPSACKRECOVERY = 25,
	LINUX_MIB_TCPSACKRENEGING = 26,
	LINUX_MIB_TCPSACKREORDER = 27,
	LINUX_MIB_TCPRENOREORDER = 28,
	LINUX_MIB_TCPTSREORDER = 29,
	LINUX_MIB_TCPFULLUNDO = 30,
	LINUX_MIB_TCPPARTIALUNDO = 31,
	LINUX_MIB_TCPDSACKUNDO = 32,
	LINUX_MIB_TCPLOSSUNDO = 33,
	LINUX_MIB_TCPLOSTRETRANSMIT = 34,
	LINUX_MIB_TCPRENOFAILURES = 35,
	LINUX_MIB_TCPSACKFAILURES = 36,
	LINUX_MIB_TCPLOSSFAILURES = 37,
	LINUX_MIB_TCPFASTRETRANS = 38,
	LINUX_MIB_TCPSLOWSTARTRETRANS = 39,
	LINUX_MIB_TCPTIMEOUTS = 40,
	LINUX_MIB_TCPLOSSPROBES = 41,
	LINUX_MIB_TCPLOSSPROBERECOVERY = 42,
	LINUX_MIB_TCPRENORECOVERYFAIL = 43,
	LINUX_MIB_TCPSACKRECOVERYFAIL = 44,
	LINUX_MIB_TCPRCVCOLLAPSED = 45,
	LINUX_MIB_TCPDSACKOLDSENT = 46,
	LINUX_MIB_TCPDSACKOFOSENT = 47,
	LINUX_MIB_TCPDSACKRECV = 48,
	LINUX_MIB_TCPDSACKOFORECV = 49,
	LINUX_MIB_TCPABORTONDATA = 50,
	LINUX_MIB_TCPABORTONCLOSE = 51,
	LINUX_MIB_TCPABORTONMEMORY = 52,
	LINUX_MIB_TCPABORTONTIMEOUT = 53,
	LINUX_MIB_TCPABORTONLINGER = 54,
	LINUX_MIB_TCPABORTFAILED = 55,
	LINUX_MIB_TCPMEMORYPRESSURES = 56,
	LINUX_MIB_TCPMEMORYPRESSURESCHRONO = 57,
	LINUX_MIB_TCPSACKDISCARD = 58,
	LINUX_MIB_TCPDSACKIGNOREDOLD = 59,
	LINUX_MIB_TCPDSACKIGNOREDNOUNDO = 60,
	LINUX_MIB_TCPSPURIOUSRTOS = 61,
	LINUX_MIB_TCPMD5NOTFOUND = 62,
	LINUX_MIB_TCPMD5UNEXPECTED = 63,
	LINUX_MIB_TCPMD5FAILURE = 64,
	LINUX_MIB_SACKSHIFTED = 65,
	LINUX_MIB_SACKMERGED = 66,
	LINUX_MIB_SACKSHIFTFALLBACK = 67,
	LINUX_MIB_TCPBACKLOGDROP = 68,
	LINUX_MIB_PFMEMALLOCDROP = 69,
	LINUX_MIB_TCPMINTTLDROP = 70,
	LINUX_MIB_TCPDEFERACCEPTDROP = 71,
	LINUX_MIB_IPRPFILTER = 72,
	LINUX_MIB_TCPTIMEWAITOVERFLOW = 73,
	LINUX_MIB_TCPREQQFULLDOCOOKIES = 74,
	LINUX_MIB_TCPREQQFULLDROP = 75,
	LINUX_MIB_TCPRETRANSFAIL = 76,
	LINUX_MIB_TCPRCVCOALESCE = 77,
	LINUX_MIB_TCPBACKLOGCOALESCE = 78,
	LINUX_MIB_TCPOFOQUEUE = 79,
	LINUX_MIB_TCPOFODROP = 80,
	LINUX_MIB_TCPOFOMERGE = 81,
	LINUX_MIB_TCPCHALLENGEACK = 82,
	LINUX_MIB_TCPSYNCHALLENGE = 83,
	LINUX_MIB_TCPFASTOPENACTIVE = 84,
	LINUX_MIB_TCPFASTOPENACTIVEFAIL = 85,
	LINUX_MIB_TCPFASTOPENPASSIVE = 86,
	LINUX_MIB_TCPFASTOPENPASSIVEFAIL = 87,
	LINUX_MIB_TCPFASTOPENLISTENOVERFLOW = 88,
	LINUX_MIB_TCPFASTOPENCOOKIEREQD = 89,
	LINUX_MIB_TCPFASTOPENBLACKHOLE = 90,
	LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES = 91,
	LINUX_MIB_BUSYPOLLRXPACKETS = 92,
	LINUX_MIB_TCPAUTOCORKING = 93,
	LINUX_MIB_TCPFROMZEROWINDOWADV = 94,
	LINUX_MIB_TCPTOZEROWINDOWADV = 95,
	LINUX_MIB_TCPWANTZEROWINDOWADV = 96,
	LINUX_MIB_TCPSYNRETRANS = 97,
	LINUX_MIB_TCPORIGDATASENT = 98,
	LINUX_MIB_TCPHYSTARTTRAINDETECT = 99,
	LINUX_MIB_TCPHYSTARTTRAINCWND = 100,
	LINUX_MIB_TCPHYSTARTDELAYDETECT = 101,
	LINUX_MIB_TCPHYSTARTDELAYCWND = 102,
	LINUX_MIB_TCPACKSKIPPEDSYNRECV = 103,
	LINUX_MIB_TCPACKSKIPPEDPAWS = 104,
	LINUX_MIB_TCPACKSKIPPEDSEQ = 105,
	LINUX_MIB_TCPACKSKIPPEDFINWAIT2 = 106,
	LINUX_MIB_TCPACKSKIPPEDTIMEWAIT = 107,
	LINUX_MIB_TCPACKSKIPPEDCHALLENGE = 108,
	LINUX_MIB_TCPWINPROBE = 109,
	LINUX_MIB_TCPKEEPALIVE = 110,
	LINUX_MIB_TCPMTUPFAIL = 111,
	LINUX_MIB_TCPMTUPSUCCESS = 112,
	LINUX_MIB_TCPDELIVERED = 113,
	LINUX_MIB_TCPDELIVEREDCE = 114,
	LINUX_MIB_TCPACKCOMPRESSED = 115,
	LINUX_MIB_TCPZEROWINDOWDROP = 116,
	LINUX_MIB_TCPRCVQDROP = 117,
	LINUX_MIB_TCPWQUEUETOOBIG = 118,
	LINUX_MIB_TCPFASTOPENPASSIVEALTKEY = 119,
	LINUX_MIB_TCPTIMEOUTREHASH = 120,
	LINUX_MIB_TCPDUPLICATEDATAREHASH = 121,
	LINUX_MIB_TCPDSACKRECVSEGS = 122,
	LINUX_MIB_TCPDSACKIGNOREDDUBIOUS = 123,
	LINUX_MIB_TCPMIGRATEREQSUCCESS = 124,
	LINUX_MIB_TCPMIGRATEREQFAILURE = 125,
	LINUX_MIB_TCPPLBREHASH = 126,
	LINUX_MIB_TCPAOREQUIRED = 127,
	LINUX_MIB_TCPAOBAD = 128,
	LINUX_MIB_TCPAOKEYNOTFOUND = 129,
	LINUX_MIB_TCPAOGOOD = 130,
	LINUX_MIB_TCPAODROPPEDICMPS = 131,
	__LINUX_MIB_MAX = 132,
};

struct udp_hslot;

struct udp_table {
	struct udp_hslot *hash;
	struct udp_hslot *hash2;
	unsigned int mask;
	unsigned int log;
};

struct ipv4_devconf {
	void *sysctl;
	int data[33];
	long unsigned int state[1];
};

struct rt6key {
	struct in6_addr addr;
	int plen;
};

struct rtable;

struct fnhe_hash_bucket;

struct fib_nh_common {
	struct net_device *nhc_dev;
	netdevice_tracker nhc_dev_tracker;
	int nhc_oif;
	unsigned char nhc_scope;
	u8 nhc_family;
	u8 nhc_gw_family;
	unsigned char nhc_flags;
	struct lwtunnel_state *nhc_lwtstate;
	union {
		__be32 ipv4;
		struct in6_addr ipv6;
	} nhc_gw;
	int nhc_weight;
	atomic_t nhc_upper_bound;
	struct rtable **nhc_pcpu_rth_output;
	struct rtable *nhc_rth_input;
	struct fnhe_hash_bucket *nhc_exceptions;
};

struct rt6_exception_bucket;

struct fib6_nh {
	struct fib_nh_common nh_common;
	long unsigned int last_probe;
	struct rt6_info **rt6i_pcpu;
	struct rt6_exception_bucket *rt6i_exception_bucket;
};

struct fib6_node;

struct dst_metrics;

struct nexthop;

struct fib6_info {
	struct fib6_table *fib6_table;
	struct fib6_info *fib6_next;
	struct fib6_node *fib6_node;
	union {
		struct list_head fib6_siblings;
		struct list_head nh_list;
	};
	unsigned int fib6_nsiblings;
	refcount_t fib6_ref;
	long unsigned int expires;
	struct hlist_node gc_link;
	struct dst_metrics *fib6_metrics;
	struct rt6key fib6_dst;
	u32 fib6_flags;
	struct rt6key fib6_src;
	struct rt6key fib6_prefsrc;
	u32 fib6_metric;
	u8 fib6_protocol;
	u8 fib6_type;
	u8 offload;
	u8 trap;
	u8 offload_failed;
	u8 should_flush: 1;
	u8 dst_nocount: 1;
	u8 dst_nopolicy: 1;
	u8 fib6_destroying: 1;
	u8 unused: 4;
	struct callback_head rcu;
	struct nexthop *nh;
	struct fib6_nh fib6_nh[0];
};

struct rt6_info {
	struct dst_entry dst;
	struct fib6_info *from;
	int sernum;
	struct rt6key rt6i_dst;
	struct rt6key rt6i_src;
	struct in6_addr rt6i_gateway;
	struct inet6_dev *rt6i_idev;
	u32 rt6i_flags;
	short unsigned int rt6i_nfheader_len;
};

struct rt6_statistics {
	__u32 fib_nodes;
	__u32 fib_route_nodes;
	__u32 fib_rt_entries;
	__u32 fib_rt_cache;
	__u32 fib_discarded_routes;
	atomic_t fib_rt_alloc;
};

struct fib6_node {
	struct fib6_node *parent;
	struct fib6_node *left;
	struct fib6_node *right;
	struct fib6_node *subtree;
	struct fib6_info *leaf;
	__u16 fn_bit;
	__u16 fn_flags;
	int fn_sernum;
	struct fib6_info *rr_ptr;
	struct callback_head rcu;
};

struct fib6_table {
	struct hlist_node tb6_hlist;
	u32 tb6_id;
	spinlock_t tb6_lock;
	struct fib6_node tb6_root;
	struct inet_peer_base tb6_peers;
	unsigned int flags;
	unsigned int fib_seq;
	struct hlist_head tb6_gc_hlist;
};

struct in_addr {
	__be32 s_addr;
};

enum nf_inet_hooks {
	NF_INET_PRE_ROUTING = 0,
	NF_INET_LOCAL_IN = 1,
	NF_INET_FORWARD = 2,
	NF_INET_LOCAL_OUT = 3,
	NF_INET_POST_ROUTING = 4,
	NF_INET_NUMHOOKS = 5,
	NF_INET_INGRESS = 5,
};

enum nf_dev_hooks {
	NF_NETDEV_INGRESS = 0,
	NF_NETDEV_EGRESS = 1,
	NF_NETDEV_NUMHOOKS = 2,
};

enum {
	NFPROTO_UNSPEC = 0,
	NFPROTO_INET = 1,
	NFPROTO_IPV4 = 2,
	NFPROTO_ARP = 3,
	NFPROTO_NETDEV = 5,
	NFPROTO_BRIDGE = 7,
	NFPROTO_IPV6 = 10,
	NFPROTO_NUMPROTO = 11,
};

struct nf_hook_state;

typedef unsigned int nf_hookfn(void *, struct sk_buff *, const struct nf_hook_state *);

struct nf_hook_entry {
	nf_hookfn *hook;
	void *priv;
};

struct nf_hook_entries {
	u16 num_hook_entries;
	struct nf_hook_entry hooks[0];
};

typedef union {
	__be32 a4;
	__be32 a6[4];
	struct in6_addr in6;
} xfrm_address_t;

struct xfrm_id {
	xfrm_address_t daddr;
	__be32 spi;
	__u8 proto;
};

struct xfrm_sec_ctx {
	__u8 ctx_doi;
	__u8 ctx_alg;
	__u16 ctx_len;
	__u32 ctx_sid;
	char ctx_str[0];
};

struct xfrm_selector {
	xfrm_address_t daddr;
	xfrm_address_t saddr;
	__be16 dport;
	__be16 dport_mask;
	__be16 sport;
	__be16 sport_mask;
	__u16 family;
	__u8 prefixlen_d;
	__u8 prefixlen_s;
	__u8 proto;
	int ifindex;
	__kernel_uid32_t user;
};

struct xfrm_lifetime_cfg {
	__u64 soft_byte_limit;
	__u64 hard_byte_limit;
	__u64 soft_packet_limit;
	__u64 hard_packet_limit;
	__u64 soft_add_expires_seconds;
	__u64 hard_add_expires_seconds;
	__u64 soft_use_expires_seconds;
	__u64 hard_use_expires_seconds;
};

struct xfrm_lifetime_cur {
	__u64 bytes;
	__u64 packets;
	__u64 add_time;
	__u64 use_time;
};

struct xfrm_replay_state {
	__u32 oseq;
	__u32 seq;
	__u32 bitmap;
};

struct xfrm_replay_state_esn {
	unsigned int bmp_len;
	__u32 oseq;
	__u32 seq;
	__u32 oseq_hi;
	__u32 seq_hi;
	__u32 replay_window;
	__u32 bmp[0];
};

struct xfrm_algo {
	char alg_name[64];
	unsigned int alg_key_len;
	char alg_key[0];
};

struct xfrm_algo_auth {
	char alg_name[64];
	unsigned int alg_key_len;
	unsigned int alg_trunc_len;
	char alg_key[0];
};

struct xfrm_algo_aead {
	char alg_name[64];
	unsigned int alg_key_len;
	unsigned int alg_icv_len;
	char alg_key[0];
};

struct xfrm_stats {
	__u32 replay_window;
	__u32 replay;
	__u32 integrity_failed;
};

enum {
	XFRM_POLICY_TYPE_MAIN = 0,
	XFRM_POLICY_TYPE_SUB = 1,
	XFRM_POLICY_TYPE_MAX = 2,
	XFRM_POLICY_TYPE_ANY = 255,
};

enum {
	XFRM_MSG_BASE = 16,
	XFRM_MSG_NEWSA = 16,
	XFRM_MSG_DELSA = 17,
	XFRM_MSG_GETSA = 18,
	XFRM_MSG_NEWPOLICY = 19,
	XFRM_MSG_DELPOLICY = 20,
	XFRM_MSG_GETPOLICY = 21,
	XFRM_MSG_ALLOCSPI = 22,
	XFRM_MSG_ACQUIRE = 23,
	XFRM_MSG_EXPIRE = 24,
	XFRM_MSG_UPDPOLICY = 25,
	XFRM_MSG_UPDSA = 26,
	XFRM_MSG_POLEXPIRE = 27,
	XFRM_MSG_FLUSHSA = 28,
	XFRM_MSG_FLUSHPOLICY = 29,
	XFRM_MSG_NEWAE = 30,
	XFRM_MSG_GETAE = 31,
	XFRM_MSG_REPORT = 32,
	XFRM_MSG_MIGRATE = 33,
	XFRM_MSG_NEWSADINFO = 34,
	XFRM_MSG_GETSADINFO = 35,
	XFRM_MSG_NEWSPDINFO = 36,
	XFRM_MSG_GETSPDINFO = 37,
	XFRM_MSG_MAPPING = 38,
	XFRM_MSG_SETDEFAULT = 39,
	XFRM_MSG_GETDEFAULT = 40,
	__XFRM_MSG_MAX = 41,
};

struct xfrm_encap_tmpl {
	__u16 encap_type;
	__be16 encap_sport;
	__be16 encap_dport;
	xfrm_address_t encap_oa;
};

enum xfrm_attr_type_t {
	XFRMA_UNSPEC = 0,
	XFRMA_ALG_AUTH = 1,
	XFRMA_ALG_CRYPT = 2,
	XFRMA_ALG_COMP = 3,
	XFRMA_ENCAP = 4,
	XFRMA_TMPL = 5,
	XFRMA_SA = 6,
	XFRMA_POLICY = 7,
	XFRMA_SEC_CTX = 8,
	XFRMA_LTIME_VAL = 9,
	XFRMA_REPLAY_VAL = 10,
	XFRMA_REPLAY_THRESH = 11,
	XFRMA_ETIMER_THRESH = 12,
	XFRMA_SRCADDR = 13,
	XFRMA_COADDR = 14,
	XFRMA_LASTUSED = 15,
	XFRMA_POLICY_TYPE = 16,
	XFRMA_MIGRATE = 17,
	XFRMA_ALG_AEAD = 18,
	XFRMA_KMADDRESS = 19,
	XFRMA_ALG_AUTH_TRUNC = 20,
	XFRMA_MARK = 21,
	XFRMA_TFCPAD = 22,
	XFRMA_REPLAY_ESN_VAL = 23,
	XFRMA_SA_EXTRA_FLAGS = 24,
	XFRMA_PROTO = 25,
	XFRMA_ADDRESS_FILTER = 26,
	XFRMA_PAD = 27,
	XFRMA_OFFLOAD_DEV = 28,
	XFRMA_SET_MARK = 29,
	XFRMA_SET_MARK_MASK = 30,
	XFRMA_IF_ID = 31,
	XFRMA_MTIMER_THRESH = 32,
	__XFRMA_MAX = 33,
};

struct xfrm_mark {
	__u32 v;
	__u32 m;
};

struct xfrm_address_filter {
	xfrm_address_t saddr;
	xfrm_address_t daddr;
	__u16 family;
	__u8 splen;
	__u8 dplen;
};

struct net_generic {
	union {
		struct {
			unsigned int len;
			struct callback_head rcu;
		} s;
		struct {
			struct {} __empty_ptr;
			void *ptr[0];
		};
	};
};

struct pernet_operations {
	struct list_head list;
	int (*init)(struct net *);
	void (*pre_exit)(struct net *);
	void (*exit)(struct net *);
	void (*exit_batch)(struct list_head *);
	void (*exit_batch_rtnl)(struct list_head *, struct list_head *);
	unsigned int *id;
	size_t size;
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

enum tcx_action_base {
	TCX_NEXT = -1,
	TCX_PASS = 0,
	TCX_DROP = 2,
	TCX_REDIRECT = 7,
};

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP = 1,
	XDP_PASS = 2,
	XDP_TX = 3,
	XDP_REDIRECT = 4,
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

typedef unsigned int (*bpf_func_t)(const void *, const struct bpf_insn *);

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

struct bpf_link_primer {
	struct bpf_link *link;
	struct file *file;
	int fd;
	u32 id;
};

enum net_device_flags {
	IFF_UP = 1,
	IFF_BROADCAST = 2,
	IFF_DEBUG = 4,
	IFF_LOOPBACK = 8,
	IFF_POINTOPOINT = 16,
	IFF_NOTRAILERS = 32,
	IFF_RUNNING = 64,
	IFF_NOARP = 128,
	IFF_PROMISC = 256,
	IFF_ALLMULTI = 512,
	IFF_MASTER = 1024,
	IFF_SLAVE = 2048,
	IFF_MULTICAST = 4096,
	IFF_PORTSEL = 8192,
	IFF_AUTOMEDIA = 16384,
	IFF_DYNAMIC = 32768,
	IFF_LOWER_UP = 65536,
	IFF_DORMANT = 131072,
	IFF_ECHO = 262144,
};

enum {
	IF_OPER_UNKNOWN = 0,
	IF_OPER_NOTPRESENT = 1,
	IF_OPER_DOWN = 2,
	IF_OPER_LOWERLAYERDOWN = 3,
	IF_OPER_TESTING = 4,
	IF_OPER_DORMANT = 5,
	IF_OPER_UP = 6,
};

enum macsec_validation_type {
	MACSEC_VALIDATE_DISABLED = 0,
	MACSEC_VALIDATE_CHECK = 1,
	MACSEC_VALIDATE_STRICT = 2,
	__MACSEC_VALIDATE_END = 3,
	MACSEC_VALIDATE_MAX = 2,
};

enum macsec_offload {
	MACSEC_OFFLOAD_OFF = 0,
	MACSEC_OFFLOAD_PHY = 1,
	MACSEC_OFFLOAD_MAC = 2,
	__MACSEC_OFFLOAD_END = 3,
	MACSEC_OFFLOAD_MAX = 2,
};

struct ifbond {
	__s32 bond_mode;
	__s32 num_slaves;
	__s32 miimon;
};

typedef struct ifbond ifbond;

struct ifslave {
	__s32 slave_id;
	char slave_name[16];
	__s8 link;
	__s8 state;
	__u32 link_failure_count;
};

typedef struct ifslave ifslave;

enum tca_id {
	TCA_ID_UNSPEC = 0,
	TCA_ID_POLICE = 1,
	TCA_ID_GACT = 5,
	TCA_ID_IPT = 6,
	TCA_ID_PEDIT = 7,
	TCA_ID_MIRRED = 8,
	TCA_ID_NAT = 9,
	TCA_ID_XT = 10,
	TCA_ID_SKBEDIT = 11,
	TCA_ID_VLAN = 12,
	TCA_ID_BPF = 13,
	TCA_ID_CONNMARK = 14,
	TCA_ID_SKBMOD = 15,
	TCA_ID_CSUM = 16,
	TCA_ID_TUNNEL_KEY = 17,
	TCA_ID_SIMP = 22,
	TCA_ID_IFE = 25,
	TCA_ID_SAMPLE = 26,
	TCA_ID_CTINFO = 27,
	TCA_ID_MPLS = 28,
	TCA_ID_CT = 29,
	TCA_ID_GATE = 30,
	__TCA_ID_MAX = 255,
};

struct tcf_t {
	__u64 install;
	__u64 lastuse;
	__u64 expires;
	__u64 firstuse;
};

enum netdev_queue_type {
	NETDEV_QUEUE_TYPE_RX = 0,
	NETDEV_QUEUE_TYPE_TX = 1,
};

enum netdev_state_t {
	__LINK_STATE_START = 0,
	__LINK_STATE_PRESENT = 1,
	__LINK_STATE_NOCARRIER = 2,
	__LINK_STATE_LINKWATCH_PENDING = 3,
	__LINK_STATE_DORMANT = 4,
	__LINK_STATE_TESTING = 5,
};

enum {
	NAPIF_STATE_SCHED = 1,
	NAPIF_STATE_MISSED = 2,
	NAPIF_STATE_DISABLE = 4,
	NAPIF_STATE_NPSVC = 8,
	NAPIF_STATE_LISTED = 16,
	NAPIF_STATE_NO_BUSY_POLL = 32,
	NAPIF_STATE_IN_BUSY_POLL = 64,
	NAPIF_STATE_PREFER_BUSY_POLL = 128,
	NAPIF_STATE_THREADED = 256,
	NAPIF_STATE_SCHED_THREADED = 512,
};

enum netdev_queue_state_t {
	__QUEUE_STATE_DRV_XOFF = 0,
	__QUEUE_STATE_STACK_XOFF = 1,
	__QUEUE_STATE_FROZEN = 2,
};

struct net_device_path_stack {
	int num_paths;
	struct net_device_path path[5];
};

struct bpf_xdp_link {
	struct bpf_link link;
	struct net_device *dev;
	int flags;
};

struct xfrm_state_walk {
	struct list_head all;
	u8 state;
	u8 dying;
	u8 proto;
	u32 seq;
	struct xfrm_address_filter *filter;
};

enum xfrm_replay_mode {
	XFRM_REPLAY_MODE_LEGACY = 0,
	XFRM_REPLAY_MODE_BMP = 1,
	XFRM_REPLAY_MODE_ESN = 2,
};

struct xfrm_dev_offload {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct net_device *real_dev;
	long unsigned int offload_handle;
	u8 dir: 2;
	u8 type: 2;
	u8 flags: 2;
};

struct xfrm_mode {
	u8 encap;
	u8 family;
	u8 flags;
};

struct xfrm_type;

struct xfrm_type_offload;

struct xfrm_state {
	possible_net_t xs_net;
	union {
		struct hlist_node gclist;
		struct hlist_node bydst;
	};
	struct hlist_node bysrc;
	struct hlist_node byspi;
	struct hlist_node byseq;
	refcount_t refcnt;
	spinlock_t lock;
	struct xfrm_id id;
	struct xfrm_selector sel;
	struct xfrm_mark mark;
	u32 if_id;
	u32 tfcpad;
	u32 genid;
	struct xfrm_state_walk km;
	struct {
		u32 reqid;
		u8 mode;
		u8 replay_window;
		u8 aalgo;
		u8 ealgo;
		u8 calgo;
		u8 flags;
		u16 family;
		xfrm_address_t saddr;
		int header_len;
		int trailer_len;
		u32 extra_flags;
		struct xfrm_mark smark;
	} props;
	struct xfrm_lifetime_cfg lft;
	struct xfrm_algo_auth *aalg;
	struct xfrm_algo *ealg;
	struct xfrm_algo *calg;
	struct xfrm_algo_aead *aead;
	const char *geniv;
	__be16 new_mapping_sport;
	u32 new_mapping;
	u32 mapping_maxage;
	struct xfrm_encap_tmpl *encap;
	struct sock *encap_sk;
	xfrm_address_t *coaddr;
	struct xfrm_state *tunnel;
	atomic_t tunnel_users;
	struct xfrm_replay_state replay;
	struct xfrm_replay_state_esn *replay_esn;
	struct xfrm_replay_state preplay;
	struct xfrm_replay_state_esn *preplay_esn;
	enum xfrm_replay_mode repl_mode;
	u32 xflags;
	u32 replay_maxage;
	u32 replay_maxdiff;
	struct timer_list rtimer;
	struct xfrm_stats stats;
	struct xfrm_lifetime_cur curlft;
	struct hrtimer mtimer;
	struct xfrm_dev_offload xso;
	long int saved_tmo;
	time64_t lastused;
	struct page_frag xfrag;
	const struct xfrm_type *type;
	struct xfrm_mode inner_mode;
	struct xfrm_mode inner_mode_iaf;
	struct xfrm_mode outer_mode;
	const struct xfrm_type_offload *type_offload;
	struct xfrm_sec_ctx *security;
	void *data;
};

struct xfrm_policy_walk_entry {
	struct list_head all;
	u8 dead;
};

struct xfrm_policy_queue {
	struct sk_buff_head hold_queue;
	struct timer_list hold_timer;
	long unsigned int timeout;
};

struct xfrm_tmpl {
	struct xfrm_id id;
	xfrm_address_t saddr;
	short unsigned int encap_family;
	u32 reqid;
	u8 mode;
	u8 share;
	u8 optional;
	u8 allalgs;
	u32 aalgos;
	u32 ealgos;
	u32 calgos;
};

struct xfrm_policy {
	possible_net_t xp_net;
	struct hlist_node bydst;
	struct hlist_node byidx;
	rwlock_t lock;
	refcount_t refcnt;
	u32 pos;
	struct timer_list timer;
	atomic_t genid;
	u32 priority;
	u32 index;
	u32 if_id;
	struct xfrm_mark mark;
	struct xfrm_selector selector;
	struct xfrm_lifetime_cfg lft;
	struct xfrm_lifetime_cur curlft;
	struct xfrm_policy_walk_entry walk;
	struct xfrm_policy_queue polq;
	bool bydst_reinsert;
	u8 type;
	u8 action;
	u8 flags;
	u8 xfrm_nr;
	u16 family;
	struct xfrm_sec_ctx *security;
	struct xfrm_tmpl xfrm_vec[6];
	struct hlist_node bydst_inexact_list;
	struct callback_head rcu;
	struct xfrm_dev_offload xdo;
};

struct netdev_net_notifier {
	struct list_head list;
	struct notifier_block *nb;
};

struct netpoll;

struct netpoll_info {
	refcount_t refcnt;
	struct semaphore dev_lock;
	struct sk_buff_head txq;
	struct delayed_work tx_work;
	struct netpoll *netpoll;
	struct callback_head rcu;
};

struct iphdr {
	__u8 version: 4;
	__u8 ihl: 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
		};
		struct {
			__be32 saddr;
			__be32 daddr;
		} addrs;
	};
};

struct ip_tunnel_parm {
	char name[16];
	int link;
	__be16 i_flags;
	__be16 o_flags;
	__be32 i_key;
	__be32 o_key;
	struct iphdr iph;
};

enum netdev_priv_flags {
	IFF_802_1Q_VLAN = 1ULL,
	IFF_EBRIDGE = 2ULL,
	IFF_BONDING = 4ULL,
	IFF_ISATAP = 8ULL,
	IFF_WAN_HDLC = 16ULL,
	IFF_XMIT_DST_RELEASE = 32ULL,
	IFF_DONT_BRIDGE = 64ULL,
	IFF_DISABLE_NETPOLL = 128ULL,
	IFF_MACVLAN_PORT = 256ULL,
	IFF_BRIDGE_PORT = 512ULL,
	IFF_OVS_DATAPATH = 1024ULL,
	IFF_TX_SKB_SHARING = 2048ULL,
	IFF_UNICAST_FLT = 4096ULL,
	IFF_TEAM_PORT = 8192ULL,
	IFF_SUPP_NOFCS = 16384ULL,
	IFF_LIVE_ADDR_CHANGE = 32768ULL,
	IFF_MACVLAN = 65536ULL,
	IFF_XMIT_DST_RELEASE_PERM = 131072ULL,
	IFF_L3MDEV_MASTER = 262144ULL,
	IFF_NO_QUEUE = 524288ULL,
	IFF_OPENVSWITCH = 1048576ULL,
	IFF_L3MDEV_SLAVE = 2097152ULL,
	IFF_TEAM = 4194304ULL,
	IFF_RXFH_CONFIGURED = 8388608ULL,
	IFF_PHONY_HEADROOM = 16777216ULL,
	IFF_MACSEC = 33554432ULL,
	IFF_NO_RX_HANDLER = 67108864ULL,
	IFF_FAILOVER = 134217728ULL,
	IFF_FAILOVER_SLAVE = 268435456ULL,
	IFF_L3MDEV_RX_HANDLER = 536870912ULL,
	IFF_NO_ADDRCONF = 1073741824ULL,
	IFF_TX_SKB_NO_LINEAR = 2147483648ULL,
	IFF_CHANGE_PROTO_DOWN = 4294967296ULL,
	IFF_SEE_ALL_HWTSTAMP_REQUESTS = 8589934592ULL,
};

enum netdev_reg_state {
	NETREG_UNINITIALIZED = 0,
	NETREG_REGISTERED = 1,
	NETREG_UNREGISTERING = 2,
	NETREG_UNREGISTERED = 3,
	NETREG_RELEASED = 4,
	NETREG_DUMMY = 5,
};

struct bpf_mprog_fp {
	struct bpf_prog *prog;
};

struct bpf_mprog_bundle;

struct bpf_mprog_entry {
	struct bpf_mprog_fp fp_items[64];
	struct bpf_mprog_bundle *parent;
};

struct rps_map;

struct rps_dev_flow_table;

struct netdev_rx_queue {
	struct xdp_rxq_info xdp_rxq;
	struct rps_map *rps_map;
	struct rps_dev_flow_table *rps_flow_table;
	struct kobject kobj;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct xsk_buff_pool *pool;
	struct napi_struct *napi;
	long: 64;
	long: 64;
	long: 64;
};

struct netdev_name_node {
	struct hlist_node hlist;
	struct list_head list;
	struct net_device *dev;
	const char *name;
	struct callback_head rcu;
};

struct libipw_device;

struct iw_spy_data;

struct iw_public_data {
	struct iw_spy_data *spy_data;
	struct libipw_device *libipw;
};

struct in_ifaddr;

struct ip_mc_list;

struct in_device {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	refcount_t refcnt;
	int dead;
	struct in_ifaddr *ifa_list;
	struct ip_mc_list *mc_list;
	struct ip_mc_list **mc_hash;
	int mc_count;
	spinlock_t mc_tomb_lock;
	struct ip_mc_list *mc_tomb;
	long unsigned int mr_v1_seen;
	long unsigned int mr_v2_seen;
	long unsigned int mr_maxdelay;
	long unsigned int mr_qi;
	long unsigned int mr_qri;
	unsigned char mr_qrv;
	unsigned char mr_gq_running;
	u32 mr_ifc_count;
	struct timer_list mr_gq_timer;
	struct timer_list mr_ifc_timer;
	struct neigh_parms *arp_parms;
	struct ipv4_devconf cnf;
	struct callback_head callback_head;
};

struct cpu_rmap {
	struct kref refcount;
	u16 size;
	void **obj;
	struct {
		u16 index;
		u16 dist;
	} near[0];
};

struct reset_control;

struct mii_bus;

struct mdio_device {
	struct device dev;
	struct mii_bus *bus;
	char modalias[32];
	int (*bus_match)(struct device *, struct device_driver *);
	void (*device_free)(struct mdio_device *);
	void (*device_remove)(struct mdio_device *);
	int addr;
	int flags;
	int reset_state;
	struct gpio_desc *reset_gpio;
	struct reset_control *reset_ctrl;
	unsigned int reset_assert_delay;
	unsigned int reset_deassert_delay;
};

struct phy_c45_device_ids {
	u32 devices_in_package;
	u32 mmds_present;
	u32 device_ids[32];
};

enum phy_state {
	PHY_DOWN = 0,
	PHY_READY = 1,
	PHY_HALTED = 2,
	PHY_ERROR = 3,
	PHY_UP = 4,
	PHY_RUNNING = 5,
	PHY_NOLINK = 6,
	PHY_CABLETEST = 7,
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

struct eee_config {
	u32 tx_lpi_timer;
	bool tx_lpi_enabled;
	bool eee_enabled;
};

struct phy_led_trigger;

struct phylink;

struct pse_control;

struct phy_driver;

struct phy_package_shared;

struct mii_timestamper;

struct phy_device {
	struct mdio_device mdio;
	const struct phy_driver *drv;
	struct device_link *devlink;
	u32 phy_id;
	struct phy_c45_device_ids c45_ids;
	unsigned int is_c45: 1;
	unsigned int is_internal: 1;
	unsigned int is_pseudo_fixed_link: 1;
	unsigned int is_gigabit_capable: 1;
	unsigned int has_fixups: 1;
	unsigned int suspended: 1;
	unsigned int suspended_by_mdio_bus: 1;
	unsigned int sysfs_links: 1;
	unsigned int loopback_enabled: 1;
	unsigned int downshifted_rate: 1;
	unsigned int is_on_sfp_module: 1;
	unsigned int mac_managed_pm: 1;
	unsigned int wol_enabled: 1;
	unsigned int autoneg: 1;
	unsigned int link: 1;
	unsigned int autoneg_complete: 1;
	unsigned int interrupts: 1;
	unsigned int irq_suspended: 1;
	unsigned int irq_rerun: 1;
	int rate_matching;
	enum phy_state state;
	u32 dev_flags;
	phy_interface_t interface;
	long unsigned int possible_interfaces[1];
	int speed;
	int duplex;
	int port;
	int pause;
	int asym_pause;
	u8 master_slave_get;
	u8 master_slave_set;
	u8 master_slave_state;
	long unsigned int supported[2];
	long unsigned int advertising[2];
	long unsigned int lp_advertising[2];
	long unsigned int adv_old[2];
	long unsigned int supported_eee[2];
	long unsigned int advertising_eee[2];
	bool eee_enabled;
	long unsigned int host_interfaces[1];
	u32 eee_broken_modes;
	bool enable_tx_lpi;
	struct eee_config eee_cfg;
	struct phy_led_trigger *phy_led_triggers;
	unsigned int phy_num_led_triggers;
	struct phy_led_trigger *last_triggered;
	struct phy_led_trigger *led_link_trigger;
	struct list_head leds;
	int irq;
	void *priv;
	struct phy_package_shared *shared;
	struct sk_buff *skb;
	void *ehdr;
	struct nlattr *nest;
	struct delayed_work state_queue;
	struct mutex lock;
	bool sfp_bus_attached;
	struct sfp_bus *sfp_bus;
	struct phylink *phylink;
	struct net_device *attached_dev;
	struct mii_timestamper *mii_ts;
	struct pse_control *psec;
	u8 mdix;
	u8 mdix_ctrl;
	int pma_extable;
	unsigned int link_down_events;
	void (*phy_link_change)(struct phy_device *, bool);
	void (*adjust_link)(struct net_device *);
	const struct macsec_ops *macsec_ops;
};

enum devlink_port_type {
	DEVLINK_PORT_TYPE_NOTSET = 0,
	DEVLINK_PORT_TYPE_AUTO = 1,
	DEVLINK_PORT_TYPE_ETH = 2,
	DEVLINK_PORT_TYPE_IB = 3,
};

enum devlink_port_flavour {
	DEVLINK_PORT_FLAVOUR_PHYSICAL = 0,
	DEVLINK_PORT_FLAVOUR_CPU = 1,
	DEVLINK_PORT_FLAVOUR_DSA = 2,
	DEVLINK_PORT_FLAVOUR_PCI_PF = 3,
	DEVLINK_PORT_FLAVOUR_PCI_VF = 4,
	DEVLINK_PORT_FLAVOUR_VIRTUAL = 5,
	DEVLINK_PORT_FLAVOUR_UNUSED = 6,
	DEVLINK_PORT_FLAVOUR_PCI_SF = 7,
};

struct devlink_port_phys_attrs {
	u32 port_number;
	u32 split_subport_number;
};

struct devlink_port_pci_pf_attrs {
	u32 controller;
	u16 pf;
	u8 external: 1;
};

struct devlink_port_pci_vf_attrs {
	u32 controller;
	u16 pf;
	u16 vf;
	u8 external: 1;
};

struct devlink_port_pci_sf_attrs {
	u32 controller;
	u32 sf;
	u16 pf;
	u8 external: 1;
};

struct devlink_port_attrs {
	u8 split: 1;
	u8 splittable: 1;
	u32 lanes;
	enum devlink_port_flavour flavour;
	struct netdev_phys_item_id switch_id;
	union {
		struct devlink_port_phys_attrs phys;
		struct devlink_port_pci_pf_attrs pci_pf;
		struct devlink_port_pci_vf_attrs pci_vf;
		struct devlink_port_pci_sf_attrs pci_sf;
	};
};

struct devlink;

struct devlink_port_ops;

struct ib_device;

struct devlink_rate;

struct devlink_linecard;

struct devlink_port {
	struct list_head list;
	struct list_head region_list;
	struct devlink *devlink;
	const struct devlink_port_ops *ops;
	unsigned int index;
	spinlock_t type_lock;
	enum devlink_port_type type;
	enum devlink_port_type desired_type;
	union {
		struct {
			struct net_device *netdev;
			int ifindex;
			char ifname[16];
		} type_eth;
		struct {
			struct ib_device *ibdev;
		} type_ib;
	};
	struct devlink_port_attrs attrs;
	u8 attrs_set: 1;
	u8 switch_port: 1;
	u8 registered: 1;
	u8 initialized: 1;
	struct delayed_work type_warn_dw;
	struct list_head reporter_list;
	struct devlink_rate *devlink_rate;
	struct devlink_linecard *linecard;
	u32 rel_index;
};

struct packet_type {
	__be16 type;
	bool ignore_outgoing;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	int (*func)(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
	void (*list_func)(struct list_head *, struct packet_type *, struct net_device *);
	bool (*id_match)(struct packet_type *, struct sock *);
	struct net *af_packet_net;
	void *af_packet_priv;
	struct list_head list;
};

struct offload_callbacks {
	struct sk_buff * (*gso_segment)(struct sk_buff *, netdev_features_t);
	struct sk_buff * (*gro_receive)(struct list_head *, struct sk_buff *);
	int (*gro_complete)(struct sk_buff *, int);
};

struct packet_offload {
	__be16 type;
	u16 priority;
	struct offload_callbacks callbacks;
	struct list_head list;
};

enum netdev_cmd {
	NETDEV_UP = 1,
	NETDEV_DOWN = 2,
	NETDEV_REBOOT = 3,
	NETDEV_CHANGE = 4,
	NETDEV_REGISTER = 5,
	NETDEV_UNREGISTER = 6,
	NETDEV_CHANGEMTU = 7,
	NETDEV_CHANGEADDR = 8,
	NETDEV_PRE_CHANGEADDR = 9,
	NETDEV_GOING_DOWN = 10,
	NETDEV_CHANGENAME = 11,
	NETDEV_FEAT_CHANGE = 12,
	NETDEV_BONDING_FAILOVER = 13,
	NETDEV_PRE_UP = 14,
	NETDEV_PRE_TYPE_CHANGE = 15,
	NETDEV_POST_TYPE_CHANGE = 16,
	NETDEV_POST_INIT = 17,
	NETDEV_PRE_UNINIT = 18,
	NETDEV_RELEASE = 19,
	NETDEV_NOTIFY_PEERS = 20,
	NETDEV_JOIN = 21,
	NETDEV_CHANGEUPPER = 22,
	NETDEV_RESEND_IGMP = 23,
	NETDEV_PRECHANGEMTU = 24,
	NETDEV_CHANGEINFODATA = 25,
	NETDEV_BONDING_INFO = 26,
	NETDEV_PRECHANGEUPPER = 27,
	NETDEV_CHANGELOWERSTATE = 28,
	NETDEV_UDP_TUNNEL_PUSH_INFO = 29,
	NETDEV_UDP_TUNNEL_DROP_INFO = 30,
	NETDEV_CHANGE_TX_QUEUE_LEN = 31,
	NETDEV_CVLAN_FILTER_PUSH_INFO = 32,
	NETDEV_CVLAN_FILTER_DROP_INFO = 33,
	NETDEV_SVLAN_FILTER_PUSH_INFO = 34,
	NETDEV_SVLAN_FILTER_DROP_INFO = 35,
	NETDEV_OFFLOAD_XSTATS_ENABLE = 36,
	NETDEV_OFFLOAD_XSTATS_DISABLE = 37,
	NETDEV_OFFLOAD_XSTATS_REPORT_USED = 38,
	NETDEV_OFFLOAD_XSTATS_REPORT_DELTA = 39,
	NETDEV_XDP_FEAT_CHANGE = 40,
};

struct netdev_notifier_info {
	struct net_device *dev;
	struct netlink_ext_ack *extack;
};

struct netdev_notifier_info_ext {
	struct netdev_notifier_info info;
	union {
		u32 mtu;
	} ext;
};

struct netdev_notifier_change_info {
	struct netdev_notifier_info info;
	unsigned int flags_changed;
};

struct netdev_notifier_changeupper_info {
	struct netdev_notifier_info info;
	struct net_device *upper_dev;
	bool master;
	bool linking;
	void *upper_info;
};

struct netdev_notifier_changelowerstate_info {
	struct netdev_notifier_info info;
	void *lower_state_info;
};

struct netdev_notifier_pre_changeaddr_info {
	struct netdev_notifier_info info;
	const unsigned char *dev_addr;
};

enum netdev_offload_xstats_type {
	NETDEV_OFFLOAD_XSTATS_TYPE_L3 = 1,
};

struct netdev_notifier_offload_xstats_rd {
	struct rtnl_hw_stats64 stats;
	bool used;
};

struct netdev_notifier_offload_xstats_ru {
	bool used;
};

struct netdev_notifier_offload_xstats_info {
	struct netdev_notifier_info info;
	enum netdev_offload_xstats_type type;
	union {
		struct netdev_notifier_offload_xstats_rd *report_delta;
		struct netdev_notifier_offload_xstats_ru *report_used;
	};
};

struct sd_flow_limit;

struct softnet_data {
	struct list_head poll_list;
	struct sk_buff_head process_queue;
	unsigned int processed;
	unsigned int time_squeeze;
	struct softnet_data *rps_ipi_list;
	bool in_net_rx_action;
	bool in_napi_threaded_poll;
	struct sd_flow_limit *flow_limit;
	struct Qdisc *output_queue;
	struct Qdisc **output_queue_tailp;
	struct sk_buff *completion_queue;
	struct sk_buff_head xfrm_backlog;
	struct {
		u16 recursion;
		u8 more;
		u8 skip_txqueue;
	} xmit;
	long: 0;
	unsigned int input_queue_head;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	call_single_data_t csd;
	struct softnet_data *rps_ipi_next;
	unsigned int cpu;
	unsigned int input_queue_tail;
	unsigned int received_rps;
	unsigned int dropped;
	struct sk_buff_head input_pkt_queue;
	struct napi_struct backlog;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t defer_lock;
	int defer_count;
	int defer_ipi_scheduled;
	struct sk_buff *defer_list;
	long: 64;
	call_single_data_t defer_csd;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct sd_flow_limit {
	u64 count;
	unsigned int num_buckets;
	unsigned int history_head;
	u16 history[128];
	u8 buckets[0];
};

enum {
	NESTED_SYNC_IMM_BIT = 0,
	NESTED_SYNC_TODO_BIT = 1,
};

struct netdev_nested_priv {
	unsigned char flags;
	void *data;
};

struct netdev_bonding_info {
	ifslave slave;
	ifbond master;
};

struct netdev_notifier_bonding_info {
	struct netdev_notifier_info info;
	struct netdev_bonding_info bonding_info;
};

enum ethtool_link_mode_bit_indices {
	ETHTOOL_LINK_MODE_10baseT_Half_BIT = 0,
	ETHTOOL_LINK_MODE_10baseT_Full_BIT = 1,
	ETHTOOL_LINK_MODE_100baseT_Half_BIT = 2,
	ETHTOOL_LINK_MODE_100baseT_Full_BIT = 3,
	ETHTOOL_LINK_MODE_1000baseT_Half_BIT = 4,
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT = 5,
	ETHTOOL_LINK_MODE_Autoneg_BIT = 6,
	ETHTOOL_LINK_MODE_TP_BIT = 7,
	ETHTOOL_LINK_MODE_AUI_BIT = 8,
	ETHTOOL_LINK_MODE_MII_BIT = 9,
	ETHTOOL_LINK_MODE_FIBRE_BIT = 10,
	ETHTOOL_LINK_MODE_BNC_BIT = 11,
	ETHTOOL_LINK_MODE_10000baseT_Full_BIT = 12,
	ETHTOOL_LINK_MODE_Pause_BIT = 13,
	ETHTOOL_LINK_MODE_Asym_Pause_BIT = 14,
	ETHTOOL_LINK_MODE_2500baseX_Full_BIT = 15,
	ETHTOOL_LINK_MODE_Backplane_BIT = 16,
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT = 17,
	ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT = 18,
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT = 19,
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT = 20,
	ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT = 21,
	ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT = 22,
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT = 23,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT = 24,
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT = 25,
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT = 26,
	ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT = 27,
	ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT = 28,
	ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT = 29,
	ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT = 30,
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT = 31,
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT = 32,
	ETHTOOL_LINK_MODE_25000baseSR_Full_BIT = 33,
	ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT = 34,
	ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT = 35,
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT = 36,
	ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT = 37,
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT = 38,
	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT = 39,
	ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT = 40,
	ETHTOOL_LINK_MODE_1000baseX_Full_BIT = 41,
	ETHTOOL_LINK_MODE_10000baseCR_Full_BIT = 42,
	ETHTOOL_LINK_MODE_10000baseSR_Full_BIT = 43,
	ETHTOOL_LINK_MODE_10000baseLR_Full_BIT = 44,
	ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT = 45,
	ETHTOOL_LINK_MODE_10000baseER_Full_BIT = 46,
	ETHTOOL_LINK_MODE_2500baseT_Full_BIT = 47,
	ETHTOOL_LINK_MODE_5000baseT_Full_BIT = 48,
	ETHTOOL_LINK_MODE_FEC_NONE_BIT = 49,
	ETHTOOL_LINK_MODE_FEC_RS_BIT = 50,
	ETHTOOL_LINK_MODE_FEC_BASER_BIT = 51,
	ETHTOOL_LINK_MODE_50000baseKR_Full_BIT = 52,
	ETHTOOL_LINK_MODE_50000baseSR_Full_BIT = 53,
	ETHTOOL_LINK_MODE_50000baseCR_Full_BIT = 54,
	ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT = 55,
	ETHTOOL_LINK_MODE_50000baseDR_Full_BIT = 56,
	ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT = 57,
	ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT = 58,
	ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT = 59,
	ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT = 60,
	ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT = 61,
	ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT = 62,
	ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT = 63,
	ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT = 64,
	ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT = 65,
	ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT = 66,
	ETHTOOL_LINK_MODE_100baseT1_Full_BIT = 67,
	ETHTOOL_LINK_MODE_1000baseT1_Full_BIT = 68,
	ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT = 69,
	ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT = 70,
	ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT = 71,
	ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT = 72,
	ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT = 73,
	ETHTOOL_LINK_MODE_FEC_LLRS_BIT = 74,
	ETHTOOL_LINK_MODE_100000baseKR_Full_BIT = 75,
	ETHTOOL_LINK_MODE_100000baseSR_Full_BIT = 76,
	ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT = 77,
	ETHTOOL_LINK_MODE_100000baseCR_Full_BIT = 78,
	ETHTOOL_LINK_MODE_100000baseDR_Full_BIT = 79,
	ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT = 80,
	ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT = 81,
	ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT = 82,
	ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT = 83,
	ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT = 84,
	ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT = 85,
	ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT = 86,
	ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT = 87,
	ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT = 88,
	ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT = 89,
	ETHTOOL_LINK_MODE_100baseFX_Half_BIT = 90,
	ETHTOOL_LINK_MODE_100baseFX_Full_BIT = 91,
	ETHTOOL_LINK_MODE_10baseT1L_Full_BIT = 92,
	ETHTOOL_LINK_MODE_800000baseCR8_Full_BIT = 93,
	ETHTOOL_LINK_MODE_800000baseKR8_Full_BIT = 94,
	ETHTOOL_LINK_MODE_800000baseDR8_Full_BIT = 95,
	ETHTOOL_LINK_MODE_800000baseDR8_2_Full_BIT = 96,
	ETHTOOL_LINK_MODE_800000baseSR8_Full_BIT = 97,
	ETHTOOL_LINK_MODE_800000baseVR8_Full_BIT = 98,
	ETHTOOL_LINK_MODE_10baseT1S_Full_BIT = 99,
	ETHTOOL_LINK_MODE_10baseT1S_Half_BIT = 100,
	ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT = 101,
	__ETHTOOL_LINK_MODE_MASK_NBITS = 102,
};

struct phy_plca_cfg {
	int version;
	int enabled;
	int node_id;
	int node_cnt;
	int to_tmr;
	int burst_cnt;
	int burst_tmr;
};

struct phy_plca_status {
	bool pst;
};

struct phy_tdr_config {
	u32 first;
	u32 last;
	u32 step;
	s8 pair;
};

enum {
	RTM_BASE = 16,
	RTM_NEWLINK = 16,
	RTM_DELLINK = 17,
	RTM_GETLINK = 18,
	RTM_SETLINK = 19,
	RTM_NEWADDR = 20,
	RTM_DELADDR = 21,
	RTM_GETADDR = 22,
	RTM_NEWROUTE = 24,
	RTM_DELROUTE = 25,
	RTM_GETROUTE = 26,
	RTM_NEWNEIGH = 28,
	RTM_DELNEIGH = 29,
	RTM_GETNEIGH = 30,
	RTM_NEWRULE = 32,
	RTM_DELRULE = 33,
	RTM_GETRULE = 34,
	RTM_NEWQDISC = 36,
	RTM_DELQDISC = 37,
	RTM_GETQDISC = 38,
	RTM_NEWTCLASS = 40,
	RTM_DELTCLASS = 41,
	RTM_GETTCLASS = 42,
	RTM_NEWTFILTER = 44,
	RTM_DELTFILTER = 45,
	RTM_GETTFILTER = 46,
	RTM_NEWACTION = 48,
	RTM_DELACTION = 49,
	RTM_GETACTION = 50,
	RTM_NEWPREFIX = 52,
	RTM_GETMULTICAST = 58,
	RTM_GETANYCAST = 62,
	RTM_NEWNEIGHTBL = 64,
	RTM_GETNEIGHTBL = 66,
	RTM_SETNEIGHTBL = 67,
	RTM_NEWNDUSEROPT = 68,
	RTM_NEWADDRLABEL = 72,
	RTM_DELADDRLABEL = 73,
	RTM_GETADDRLABEL = 74,
	RTM_GETDCB = 78,
	RTM_SETDCB = 79,
	RTM_NEWNETCONF = 80,
	RTM_DELNETCONF = 81,
	RTM_GETNETCONF = 82,
	RTM_NEWMDB = 84,
	RTM_DELMDB = 85,
	RTM_GETMDB = 86,
	RTM_NEWNSID = 88,
	RTM_DELNSID = 89,
	RTM_GETNSID = 90,
	RTM_NEWSTATS = 92,
	RTM_GETSTATS = 94,
	RTM_SETSTATS = 95,
	RTM_NEWCACHEREPORT = 96,
	RTM_NEWCHAIN = 100,
	RTM_DELCHAIN = 101,
	RTM_GETCHAIN = 102,
	RTM_NEWNEXTHOP = 104,
	RTM_DELNEXTHOP = 105,
	RTM_GETNEXTHOP = 106,
	RTM_NEWLINKPROP = 108,
	RTM_DELLINKPROP = 109,
	RTM_GETLINKPROP = 110,
	RTM_NEWVLAN = 112,
	RTM_DELVLAN = 113,
	RTM_GETVLAN = 114,
	RTM_NEWNEXTHOPBUCKET = 116,
	RTM_DELNEXTHOPBUCKET = 117,
	RTM_GETNEXTHOPBUCKET = 118,
	RTM_NEWTUNNEL = 120,
	RTM_DELTUNNEL = 121,
	RTM_GETTUNNEL = 122,
	__RTM_MAX = 123,
};

enum {
	TCA_UNSPEC = 0,
	TCA_KIND = 1,
	TCA_OPTIONS = 2,
	TCA_STATS = 3,
	TCA_XSTATS = 4,
	TCA_RATE = 5,
	TCA_FCNT = 6,
	TCA_STATS2 = 7,
	TCA_STAB = 8,
	TCA_PAD = 9,
	TCA_DUMP_INVISIBLE = 10,
	TCA_CHAIN = 11,
	TCA_HW_OFFLOAD = 12,
	TCA_INGRESS_BLOCK = 13,
	TCA_EGRESS_BLOCK = 14,
	TCA_DUMP_FLAGS = 15,
	TCA_EXT_WARN_MSG = 16,
	__TCA_MAX = 17,
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct vlan_ethhdr {
	union {
		struct {
			unsigned char h_dest[6];
			unsigned char h_source[6];
		};
		struct {
			unsigned char h_dest[6];
			unsigned char h_source[6];
		} addrs;
	};
	__be16 h_vlan_proto;
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

union inet_addr {
	__u32 all[4];
	__be32 ip;
	__be32 ip6[4];
	struct in_addr in;
	struct in6_addr in6;
};

struct netpoll {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	char dev_name[16];
	const char *name;
	union inet_addr local_ip;
	union inet_addr remote_ip;
	bool ipv6;
	u16 local_port;
	u16 remote_port;
	u8 remote_mac[6];
};

struct ip_tunnel_key {
	__be64 tun_id;
	union {
		struct {
			__be32 src;
			__be32 dst;
		} ipv4;
		struct {
			struct in6_addr src;
			struct in6_addr dst;
		} ipv6;
	} u;
	__be16 tun_flags;
	u8 tos;
	u8 ttl;
	__be32 label;
	u32 nhid;
	__be16 tp_src;
	__be16 tp_dst;
	__u8 flow_flags;
};

struct ip_tunnel_encap {
	u16 type;
	u16 flags;
	__be16 sport;
	__be16 dport;
};

struct dst_cache_pcpu;

struct dst_cache {
	struct dst_cache_pcpu *cache;
	long unsigned int reset_ts;
};

struct ip_tunnel_info {
	struct ip_tunnel_key key;
	struct ip_tunnel_encap encap;
	struct dst_cache dst_cache;
	u8 options_len;
	u8 mode;
};

enum qdisc_state_t {
	__QDISC_STATE_SCHED = 0,
	__QDISC_STATE_DEACTIVATED = 1,
	__QDISC_STATE_MISSED = 2,
	__QDISC_STATE_DRAINING = 3,
};

enum qdisc_state2_t {
	__QDISC_STATE2_RUNNING = 0,
};

struct qdisc_walker {
	int stop;
	int skip;
	int count;
	int (*fn)(struct Qdisc *, long unsigned int, struct qdisc_walker *);
};

struct tcf_walker {
	int stop;
	int skip;
	int count;
	bool nonempty;
	long unsigned int cookie;
	int (*fn)(struct tcf_proto *, void *, struct tcf_walker *);
};

struct tc_action;

struct tcf_exts_miss_cookie_node;

struct tcf_exts {
	__u32 type;
	int nr_actions;
	struct tc_action **actions;
	struct net *net;
	netns_tracker ns_tracker;
	struct tcf_exts_miss_cookie_node *miss_cookie_node;
	int action;
	int police;
};

struct qdisc_skb_cb {
	struct {
		unsigned int pkt_len;
		u16 slave_dev_queue_mapping;
		u16 tc_classid;
	};
	unsigned char data[20];
};

struct tc_skb_cb {
	struct qdisc_skb_cb qdisc_cb;
	u32 drop_reason;
	u16 zone;
	u16 mru;
	u8 post_ct: 1;
	u8 post_ct_snat: 1;
	u8 post_ct_dnat: 1;
};

struct mini_Qdisc {
	struct tcf_proto *filter_list;
	struct tcf_block *block;
	struct gnet_stats_basic_sync *cpu_bstats;
	struct gnet_stats_queue *cpu_qstats;
	long unsigned int rcu_state;
};

typedef unsigned int (*bpf_dispatcher_fn)(const void *, const struct bpf_insn *, unsigned int (*)(const void *, const struct bpf_insn *));

struct bpf_skb_data_end {
	struct qdisc_skb_cb qdisc_cb;
	void *data_meta;
	void *data_end;
};

enum xdp_buff_flags {
	XDP_FLAGS_HAS_FRAGS = 1,
	XDP_FLAGS_FRAGS_PF_MEMALLOC = 2,
};

struct dst_metrics {
	u32 metrics[17];
	refcount_t refcnt;
};

enum {
	TCPF_ESTABLISHED = 2,
	TCPF_SYN_SENT = 4,
	TCPF_SYN_RECV = 8,
	TCPF_FIN_WAIT1 = 16,
	TCPF_FIN_WAIT2 = 32,
	TCPF_TIME_WAIT = 64,
	TCPF_CLOSE = 128,
	TCPF_CLOSE_WAIT = 256,
	TCPF_LAST_ACK = 512,
	TCPF_LISTEN = 1024,
	TCPF_CLOSING = 2048,
	TCPF_NEW_SYN_RECV = 4096,
	TCPF_BOUND_INACTIVE = 8192,
};

enum {
	IPV4_DEVCONF_FORWARDING = 1,
	IPV4_DEVCONF_MC_FORWARDING = 2,
	IPV4_DEVCONF_PROXY_ARP = 3,
	IPV4_DEVCONF_ACCEPT_REDIRECTS = 4,
	IPV4_DEVCONF_SECURE_REDIRECTS = 5,
	IPV4_DEVCONF_SEND_REDIRECTS = 6,
	IPV4_DEVCONF_SHARED_MEDIA = 7,
	IPV4_DEVCONF_RP_FILTER = 8,
	IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE = 9,
	IPV4_DEVCONF_BOOTP_RELAY = 10,
	IPV4_DEVCONF_LOG_MARTIANS = 11,
	IPV4_DEVCONF_TAG = 12,
	IPV4_DEVCONF_ARPFILTER = 13,
	IPV4_DEVCONF_MEDIUM_ID = 14,
	IPV4_DEVCONF_NOXFRM = 15,
	IPV4_DEVCONF_NOPOLICY = 16,
	IPV4_DEVCONF_FORCE_IGMP_VERSION = 17,
	IPV4_DEVCONF_ARP_ANNOUNCE = 18,
	IPV4_DEVCONF_ARP_IGNORE = 19,
	IPV4_DEVCONF_PROMOTE_SECONDARIES = 20,
	IPV4_DEVCONF_ARP_ACCEPT = 21,
	IPV4_DEVCONF_ARP_NOTIFY = 22,
	IPV4_DEVCONF_ACCEPT_LOCAL = 23,
	IPV4_DEVCONF_SRC_VMARK = 24,
	IPV4_DEVCONF_PROXY_ARP_PVLAN = 25,
	IPV4_DEVCONF_ROUTE_LOCALNET = 26,
	IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL = 27,
	IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL = 28,
	IPV4_DEVCONF_IGNORE_ROUTES_WITH_LINKDOWN = 29,
	IPV4_DEVCONF_DROP_UNICAST_IN_L2_MULTICAST = 30,
	IPV4_DEVCONF_DROP_GRATUITOUS_ARP = 31,
	IPV4_DEVCONF_BC_FORWARDING = 32,
	IPV4_DEVCONF_ARP_EVICT_NOCARRIER = 33,
	__IPV4_DEVCONF_MAX = 34,
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 doff: 4;
	__u16 res1: 4;
	__u16 cwr: 1;
	__u16 ece: 1;
	__u16 urg: 1;
	__u16 ack: 1;
	__u16 psh: 1;
	__u16 rst: 1;
	__u16 syn: 1;
	__u16 fin: 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

enum tsq_enum {
	TSQ_THROTTLED = 0,
	TSQ_QUEUED = 1,
	TCP_TSQ_DEFERRED = 2,
	TCP_WRITE_TIMER_DEFERRED = 3,
	TCP_DELACK_TIMER_DEFERRED = 4,
	TCP_MTU_REDUCED_DEFERRED = 5,
	TCP_ACK_DEFERRED = 6,
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

struct inet6_skb_parm {
	int iif;
	__be16 ra;
	__u16 dst0;
	__u16 srcrt;
	__u16 dst1;
	__u16 lastopt;
	__u16 nhoff;
	__u16 flags;
	__u16 dsthao;
	__u16 frag_max_size;
	__u16 srhoff;
};

struct fib_nh_exception {
	struct fib_nh_exception *fnhe_next;
	int fnhe_genid;
	__be32 fnhe_daddr;
	u32 fnhe_pmtu;
	bool fnhe_mtu_locked;
	__be32 fnhe_gw;
	long unsigned int fnhe_expires;
	struct rtable *fnhe_rth_input;
	struct rtable *fnhe_rth_output;
	long unsigned int fnhe_stamp;
	struct callback_head rcu;
};

struct rtable {
	struct dst_entry dst;
	int rt_genid;
	unsigned int rt_flags;
	__u16 rt_type;
	__u8 rt_is_input;
	__u8 rt_uses_gateway;
	int rt_iif;
	u8 rt_gw_family;
	union {
		__be32 rt_gw4;
		struct in6_addr rt_gw6;
	};
	u32 rt_mtu_locked: 1;
	u32 rt_pmtu: 31;
};

struct fnhe_hash_bucket {
	struct fib_nh_exception *chain;
};

struct fib_info;

struct fib_nh {
	struct fib_nh_common nh_common;
	struct hlist_node nh_hash;
	struct fib_info *nh_parent;
	__u32 nh_tclassid;
	__be32 nh_saddr;
	int nh_saddr_genid;
};

struct fib_info {
	struct hlist_node fib_hash;
	struct hlist_node fib_lhash;
	struct list_head nh_list;
	struct net *fib_net;
	refcount_t fib_treeref;
	refcount_t fib_clntref;
	unsigned int fib_flags;
	unsigned char fib_dead;
	unsigned char fib_protocol;
	unsigned char fib_scope;
	unsigned char fib_type;
	__be32 fib_prefsrc;
	u32 fib_tb_id;
	u32 fib_priority;
	struct dst_metrics *fib_metrics;
	int fib_nhs;
	bool fib_nh_is_v6;
	bool nh_updated;
	bool pfsrc_removed;
	struct nexthop *nh;
	struct callback_head rcu;
	struct fib_nh fib_nh[0];
};

struct nh_info;

struct nh_group;

struct nexthop {
	struct rb_node rb_node;
	struct list_head fi_list;
	struct list_head f6i_list;
	struct list_head fdb_list;
	struct list_head grp_list;
	struct net *net;
	u32 id;
	u8 protocol;
	u8 nh_flags;
	bool is_group;
	refcount_t refcnt;
	struct callback_head rcu;
	union {
		struct nh_info *nh_info;
		struct nh_group *nh_grp;
	};
};

enum {
	__ND_OPT_PREFIX_INFO_END = 0,
	ND_OPT_SOURCE_LL_ADDR = 1,
	ND_OPT_TARGET_LL_ADDR = 2,
	ND_OPT_PREFIX_INFO = 3,
	ND_OPT_REDIRECT_HDR = 4,
	ND_OPT_MTU = 5,
	ND_OPT_NONCE = 14,
	__ND_OPT_ARRAY_MAX = 15,
	ND_OPT_ROUTE_INFO = 24,
	ND_OPT_RDNSS = 25,
	ND_OPT_DNSSL = 31,
	ND_OPT_6CO = 34,
	ND_OPT_CAPTIVE_PORTAL = 37,
	ND_OPT_PREF64 = 38,
	__ND_OPT_MAX = 39,
};

enum led_brightness {
	LED_OFF = 0,
	LED_ON = 1,
	LED_HALF = 127,
	LED_FULL = 255,
};

struct mdio_bus_stats {
	u64_stats_t transfers;
	u64_stats_t errors;
	u64_stats_t writes;
	u64_stats_t reads;
	struct u64_stats_sync syncp;
};

struct mii_bus {
	struct module *owner;
	const char *name;
	char id[61];
	void *priv;
	int (*read)(struct mii_bus *, int, int);
	int (*write)(struct mii_bus *, int, int, u16);
	int (*read_c45)(struct mii_bus *, int, int, int);
	int (*write_c45)(struct mii_bus *, int, int, int, u16);
	int (*reset)(struct mii_bus *);
	struct mdio_bus_stats stats[32];
	struct mutex mdio_lock;
	struct device *parent;
	enum {
		MDIOBUS_ALLOCATED = 1,
		MDIOBUS_REGISTERED = 2,
		MDIOBUS_UNREGISTERED = 3,
		MDIOBUS_RELEASED = 4,
	} state;
	struct device dev;
	struct mdio_device *mdio_map[32];
	u32 phy_mask;
	u32 phy_ignore_ta_mask;
	int irq[32];
	int reset_delay_us;
	int reset_post_delay_us;
	struct gpio_desc *reset_gpiod;
	struct mutex shared_lock;
	struct phy_package_shared *shared[32];
};

struct mdio_driver_common {
	struct device_driver driver;
	int flags;
};

struct mii_timestamper {
	bool (*rxtstamp)(struct mii_timestamper *, struct sk_buff *, int);
	void (*txtstamp)(struct mii_timestamper *, struct sk_buff *, int);
	int (*hwtstamp)(struct mii_timestamper *, struct kernel_hwtstamp_config *, struct netlink_ext_ack *);
	void (*link_state)(struct mii_timestamper *, struct phy_device *);
	int (*ts_info)(struct mii_timestamper *, struct ethtool_ts_info *);
	struct device *device;
};

struct phy_package_shared {
	u8 base_addr;
	struct device_node *np;
	refcount_t refcnt;
	long unsigned int flags;
	size_t priv_size;
	void *priv;
};

struct phy_driver {
	struct mdio_driver_common mdiodrv;
	u32 phy_id;
	char *name;
	u32 phy_id_mask;
	const long unsigned int * const features;
	u32 flags;
	const void *driver_data;
	int (*soft_reset)(struct phy_device *);
	int (*config_init)(struct phy_device *);
	int (*probe)(struct phy_device *);
	int (*get_features)(struct phy_device *);
	int (*get_rate_matching)(struct phy_device *, phy_interface_t);
	int (*suspend)(struct phy_device *);
	int (*resume)(struct phy_device *);
	int (*config_aneg)(struct phy_device *);
	int (*aneg_done)(struct phy_device *);
	int (*read_status)(struct phy_device *);
	int (*config_intr)(struct phy_device *);
	irqreturn_t (*handle_interrupt)(struct phy_device *);
	void (*remove)(struct phy_device *);
	int (*match_phy_device)(struct phy_device *);
	int (*set_wol)(struct phy_device *, struct ethtool_wolinfo *);
	void (*get_wol)(struct phy_device *, struct ethtool_wolinfo *);
	void (*link_change_notify)(struct phy_device *);
	int (*read_mmd)(struct phy_device *, int, u16);
	int (*write_mmd)(struct phy_device *, int, u16, u16);
	int (*read_page)(struct phy_device *);
	int (*write_page)(struct phy_device *, int);
	int (*module_info)(struct phy_device *, struct ethtool_modinfo *);
	int (*module_eeprom)(struct phy_device *, struct ethtool_eeprom *, u8 *);
	int (*cable_test_start)(struct phy_device *);
	int (*cable_test_tdr_start)(struct phy_device *, const struct phy_tdr_config *);
	int (*cable_test_get_status)(struct phy_device *, bool *);
	int (*get_sset_count)(struct phy_device *);
	void (*get_strings)(struct phy_device *, u8 *);
	void (*get_stats)(struct phy_device *, struct ethtool_stats *, u64 *);
	int (*get_tunable)(struct phy_device *, struct ethtool_tunable *, void *);
	int (*set_tunable)(struct phy_device *, struct ethtool_tunable *, const void *);
	int (*set_loopback)(struct phy_device *, bool);
	int (*get_sqi)(struct phy_device *);
	int (*get_sqi_max)(struct phy_device *);
	int (*get_plca_cfg)(struct phy_device *, struct phy_plca_cfg *);
	int (*set_plca_cfg)(struct phy_device *, const struct phy_plca_cfg *);
	int (*get_plca_status)(struct phy_device *, struct phy_plca_status *);
	int (*led_brightness_set)(struct phy_device *, u8, enum led_brightness);
	int (*led_blink_set)(struct phy_device *, u8, long unsigned int *, long unsigned int *);
	int (*led_hw_is_supported)(struct phy_device *, u8, long unsigned int);
	int (*led_hw_control_set)(struct phy_device *, u8, long unsigned int);
	int (*led_hw_control_get)(struct phy_device *, u8, long unsigned int *);
	int (*led_polarity_set)(struct phy_device *, int, long unsigned int);
};

enum devlink_rate_type {
	DEVLINK_RATE_TYPE_LEAF = 0,
	DEVLINK_RATE_TYPE_NODE = 1,
};

enum devlink_port_fn_state {
	DEVLINK_PORT_FN_STATE_INACTIVE = 0,
	DEVLINK_PORT_FN_STATE_ACTIVE = 1,
};

enum devlink_port_fn_opstate {
	DEVLINK_PORT_FN_OPSTATE_DETACHED = 0,
	DEVLINK_PORT_FN_OPSTATE_ATTACHED = 1,
};

struct devlink_rate {
	struct list_head list;
	enum devlink_rate_type type;
	struct devlink *devlink;
	void *priv;
	u64 tx_share;
	u64 tx_max;
	struct devlink_rate *parent;
	union {
		struct devlink_port *devlink_port;
		struct {
			char *name;
			refcount_t refcnt;
		};
	};
	u32 tx_priority;
	u32 tx_weight;
};

struct devlink_port_ops {
	int (*port_split)(struct devlink *, struct devlink_port *, unsigned int, struct netlink_ext_ack *);
	int (*port_unsplit)(struct devlink *, struct devlink_port *, struct netlink_ext_ack *);
	int (*port_type_set)(struct devlink_port *, enum devlink_port_type);
	int (*port_del)(struct devlink *, struct devlink_port *, struct netlink_ext_ack *);
	int (*port_fn_hw_addr_get)(struct devlink_port *, u8 *, int *, struct netlink_ext_ack *);
	int (*port_fn_hw_addr_set)(struct devlink_port *, const u8 *, int, struct netlink_ext_ack *);
	int (*port_fn_roce_get)(struct devlink_port *, bool *, struct netlink_ext_ack *);
	int (*port_fn_roce_set)(struct devlink_port *, bool, struct netlink_ext_ack *);
	int (*port_fn_migratable_get)(struct devlink_port *, bool *, struct netlink_ext_ack *);
	int (*port_fn_migratable_set)(struct devlink_port *, bool, struct netlink_ext_ack *);
	int (*port_fn_state_get)(struct devlink_port *, enum devlink_port_fn_state *, enum devlink_port_fn_opstate *, struct netlink_ext_ack *);
	int (*port_fn_state_set)(struct devlink_port *, enum devlink_port_fn_state, struct netlink_ext_ack *);
	int (*port_fn_ipsec_crypto_get)(struct devlink_port *, bool *, struct netlink_ext_ack *);
	int (*port_fn_ipsec_crypto_set)(struct devlink_port *, bool, struct netlink_ext_ack *);
	int (*port_fn_ipsec_packet_get)(struct devlink_port *, bool *, struct netlink_ext_ack *);
	int (*port_fn_ipsec_packet_set)(struct devlink_port *, bool, struct netlink_ext_ack *);
};

struct rt6_exception_bucket {
	struct hlist_head chain;
	int depth;
};

struct nh_info {
	struct hlist_node dev_hash;
	struct nexthop *nh_parent;
	u8 family;
	bool reject_nh;
	bool fdb_nh;
	union {
		struct fib_nh_common fib_nhc;
		struct fib_nh fib_nh;
		struct fib6_nh fib6_nh;
	};
};

struct nh_grp_entry;

struct nh_res_bucket {
	struct nh_grp_entry *nh_entry;
	atomic_long_t used_time;
	long unsigned int migrated_time;
	bool occupied;
	u8 nh_flags;
};

struct nh_grp_entry_stats;

struct nh_grp_entry {
	struct nexthop *nh;
	struct nh_grp_entry_stats *stats;
	u8 weight;
	union {
		struct {
			atomic_t upper_bound;
		} hthr;
		struct {
			struct list_head uw_nh_entry;
			u16 count_buckets;
			u16 wants_buckets;
		} res;
	};
	struct list_head nh_list;
	struct nexthop *nh_parent;
	u64 packets_hw;
};

struct nh_res_table {
	struct net *net;
	u32 nhg_id;
	struct delayed_work upkeep_dw;
	struct list_head uw_nh_entries;
	long unsigned int unbalanced_since;
	u32 idle_timer;
	u32 unbalanced_timer;
	u16 num_nh_buckets;
	struct nh_res_bucket nh_buckets[0];
};

struct nh_grp_entry_stats {
	u64_stats_t packets;
	struct u64_stats_sync syncp;
};

struct nh_group {
	struct nh_group *spare;
	u16 num_nh;
	bool is_multipath;
	bool hash_threshold;
	bool resilient;
	bool fdb_nh;
	bool has_v4;
	bool hw_stats;
	struct nh_res_table *res_table;
	struct nh_grp_entry nh_entries[0];
};

typedef u64 sci_t;

typedef u32 ssci_t;

union salt {
	struct {
		u32 ssci;
		u64 pn;
	} __attribute__((packed));
	u8 bytes[12];
};

typedef union salt salt_t;

union pn {
	struct {
		u32 upper;
		u32 lower;
	};
	u64 full64;
};

typedef union pn pn_t;

struct crypto_aead;

struct macsec_key {
	u8 id[16];
	struct crypto_aead *tfm;
	salt_t salt;
};

struct macsec_rx_sc_stats {
	__u64 InOctetsValidated;
	__u64 InOctetsDecrypted;
	__u64 InPktsUnchecked;
	__u64 InPktsDelayed;
	__u64 InPktsOK;
	__u64 InPktsInvalid;
	__u64 InPktsLate;
	__u64 InPktsNotValid;
	__u64 InPktsNotUsingSA;
	__u64 InPktsUnusedSA;
};

struct macsec_rx_sa_stats {
	__u32 InPktsOK;
	__u32 InPktsInvalid;
	__u32 InPktsNotValid;
	__u32 InPktsNotUsingSA;
	__u32 InPktsUnusedSA;
};

struct macsec_tx_sa_stats {
	__u32 OutPktsProtected;
	__u32 OutPktsEncrypted;
};

struct macsec_tx_sc_stats {
	__u64 OutPktsProtected;
	__u64 OutPktsEncrypted;
	__u64 OutOctetsProtected;
	__u64 OutOctetsEncrypted;
};

struct macsec_dev_stats {
	__u64 OutPktsUntagged;
	__u64 InPktsUntagged;
	__u64 OutPktsTooLong;
	__u64 InPktsNoTag;
	__u64 InPktsBadTag;
	__u64 InPktsUnknownSCI;
	__u64 InPktsNoSCI;
	__u64 InPktsOverrun;
};

struct macsec_rx_sc;

struct macsec_rx_sa {
	struct macsec_key key;
	ssci_t ssci;
	spinlock_t lock;
	union {
		pn_t next_pn_halves;
		u64 next_pn;
	};
	refcount_t refcnt;
	bool active;
	struct macsec_rx_sa_stats *stats;
	struct macsec_rx_sc *sc;
	struct callback_head rcu;
};

struct pcpu_rx_sc_stats;

struct macsec_rx_sc {
	struct macsec_rx_sc *next;
	sci_t sci;
	bool active;
	struct macsec_rx_sa *sa[4];
	struct pcpu_rx_sc_stats *stats;
	refcount_t refcnt;
	struct callback_head callback_head;
};

struct pcpu_rx_sc_stats {
	struct macsec_rx_sc_stats stats;
	struct u64_stats_sync syncp;
};

struct pcpu_tx_sc_stats {
	struct macsec_tx_sc_stats stats;
	struct u64_stats_sync syncp;
};

struct macsec_tx_sa {
	struct macsec_key key;
	ssci_t ssci;
	spinlock_t lock;
	union {
		pn_t next_pn_halves;
		u64 next_pn;
	};
	refcount_t refcnt;
	bool active;
	struct macsec_tx_sa_stats *stats;
	struct callback_head rcu;
};

struct metadata_dst;

struct macsec_tx_sc {
	bool active;
	u8 encoding_sa;
	bool encrypt;
	bool send_sci;
	bool end_station;
	bool scb;
	struct macsec_tx_sa *sa[4];
	struct pcpu_tx_sc_stats *stats;
	struct metadata_dst *md_dst;
};

enum metadata_type {
	METADATA_IP_TUNNEL = 0,
	METADATA_HW_PORT_MUX = 1,
	METADATA_MACSEC = 2,
	METADATA_XFRM = 3,
};

struct hw_port_info {
	struct net_device *lower_dev;
	u32 port_id;
};

struct macsec_info {
	sci_t sci;
};

struct xfrm_md_info {
	u32 if_id;
	int link;
	struct dst_entry *dst_orig;
};

struct metadata_dst {
	struct dst_entry dst;
	enum metadata_type type;
	union {
		struct ip_tunnel_info tun_info;
		struct hw_port_info port_info;
		struct macsec_info macsec_info;
		struct xfrm_md_info xfrm_info;
	} u;
};

struct macsec_secy {
	struct net_device *netdev;
	unsigned int n_rx_sc;
	sci_t sci;
	u16 key_len;
	u16 icv_len;
	enum macsec_validation_type validate_frames;
	bool xpn;
	bool operational;
	bool protect_frames;
	bool replay_protect;
	u32 replay_window;
	struct macsec_tx_sc tx_sc;
	struct macsec_rx_sc *rx_sc;
};

struct macsec_context {
	union {
		struct net_device *netdev;
		struct phy_device *phydev;
	};
	enum macsec_offload offload;
	struct macsec_secy *secy;
	struct macsec_rx_sc *rx_sc;
	struct {
		bool update_pn;
		unsigned char assoc_num;
		u8 key[128];
		union {
			struct macsec_rx_sa *rx_sa;
			struct macsec_tx_sa *tx_sa;
		};
	} sa;
	union {
		struct macsec_tx_sc_stats *tx_sc_stats;
		struct macsec_tx_sa_stats *tx_sa_stats;
		struct macsec_rx_sc_stats *rx_sc_stats;
		struct macsec_rx_sa_stats *rx_sa_stats;
		struct macsec_dev_stats *dev_stats;
	} stats;
};

struct udp_hslot {
	struct hlist_head head;
	int count;
	spinlock_t lock;
};

struct net_protocol {
	int (*handler)(struct sk_buff *);
	int (*err_handler)(struct sk_buff *, u32);
	unsigned int no_policy: 1;
	unsigned int icmp_strict_tag_validation: 1;
	u32 secret;
};

struct inet6_protocol {
	int (*handler)(struct sk_buff *);
	int (*err_handler)(struct sk_buff *, struct inet6_skb_parm *, u8, u8, int, __be32);
	unsigned int flags;
	u32 secret;
};

struct net_offload {
	struct offload_callbacks callbacks;
	unsigned int flags;
	u32 secret;
};

struct rps_sock_flow_table;

struct net_hotdata {
	struct packet_offload ip_packet_offload;
	struct net_offload tcpv4_offload;
	struct net_protocol tcp_protocol;
	struct net_offload udpv4_offload;
	struct net_protocol udp_protocol;
	struct packet_offload ipv6_packet_offload;
	struct net_offload tcpv6_offload;
	struct inet6_protocol tcpv6_protocol;
	struct inet6_protocol udpv6_protocol;
	struct net_offload udpv6_offload;
	struct list_head offload_base;
	struct list_head ptype_all;
	struct kmem_cache *skbuff_cache;
	struct kmem_cache *skbuff_fclone_cache;
	struct kmem_cache *skb_small_head_cache;
	struct rps_sock_flow_table *rps_sock_flow_table;
	u32 rps_cpu_mask;
	int gro_normal_batch;
	int netdev_budget;
	int netdev_budget_usecs;
	int tstamp_prequeue;
	int max_backlog;
	int dev_tx_weight;
	int dev_rx_weight;
};

struct rps_sock_flow_table {
	u32 mask;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u32 ents[0];
};

struct tcf_idrinfo {
	struct mutex lock;
	struct idr action_idr;
	struct net *net;
};

struct tc_action_ops;

struct tc_cookie;

struct tc_action {
	const struct tc_action_ops *ops;
	__u32 type;
	struct tcf_idrinfo *idrinfo;
	u32 tcfa_index;
	refcount_t tcfa_refcnt;
	atomic_t tcfa_bindcnt;
	int tcfa_action;
	struct tcf_t tcfa_tm;
	long: 64;
	struct gnet_stats_basic_sync tcfa_bstats;
	struct gnet_stats_basic_sync tcfa_bstats_hw;
	struct gnet_stats_queue tcfa_qstats;
	struct net_rate_estimator *tcfa_rate_est;
	spinlock_t tcfa_lock;
	struct gnet_stats_basic_sync *cpu_bstats;
	struct gnet_stats_basic_sync *cpu_bstats_hw;
	struct gnet_stats_queue *cpu_qstats;
	struct tc_cookie *user_cookie;
	struct tcf_chain *goto_chain;
	u32 tcfa_flags;
	u8 hw_stats;
	u8 used_hw_stats;
	bool used_hw_stats_valid;
	u32 in_hw_count;
};

typedef void (*tc_action_priv_destructor)(void *);

struct psample_group;

struct tc_action_ops {
	struct list_head head;
	char kind[16];
	enum tca_id id;
	unsigned int net_id;
	size_t size;
	struct module *owner;
	int (*act)(struct sk_buff *, const struct tc_action *, struct tcf_result *);
	int (*dump)(struct sk_buff *, struct tc_action *, int, int);
	void (*cleanup)(struct tc_action *);
	int (*lookup)(struct net *, struct tc_action **, u32);
	int (*init)(struct net *, struct nlattr *, struct nlattr *, struct tc_action **, struct tcf_proto *, u32, struct netlink_ext_ack *);
	int (*walk)(struct net *, struct sk_buff *, struct netlink_callback *, int, const struct tc_action_ops *, struct netlink_ext_ack *);
	void (*stats_update)(struct tc_action *, u64, u64, u64, u64, bool);
	size_t (*get_fill_size)(const struct tc_action *);
	struct net_device * (*get_dev)(const struct tc_action *, tc_action_priv_destructor *);
	struct psample_group * (*get_psample_group)(const struct tc_action *, tc_action_priv_destructor *);
	int (*offload_act_setup)(struct tc_action *, void *, u32 *, bool, struct netlink_ext_ack *);
};

struct tc_cookie {
	u8 *data;
	u32 len;
	struct callback_head rcu;
};

struct xfrm_type {
	struct module *owner;
	u8 proto;
	u8 flags;
	int (*init_state)(struct xfrm_state *, struct netlink_ext_ack *);
	void (*destructor)(struct xfrm_state *);
	int (*input)(struct xfrm_state *, struct sk_buff *);
	int (*output)(struct xfrm_state *, struct sk_buff *);
	int (*reject)(struct xfrm_state *, struct sk_buff *, const struct flowi *);
};

struct xfrm_type_offload {
	struct module *owner;
	u8 proto;
	void (*encap)(struct xfrm_state *, struct sk_buff *);
	int (*input_tail)(struct xfrm_state *, struct sk_buff *);
	int (*xmit)(struct xfrm_state *, struct sk_buff *, netdev_features_t);
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

struct tcx_entry {
	struct mini_Qdisc *miniq;
	struct bpf_mprog_bundle bundle;
	u32 miniq_active;
	struct callback_head rcu;
};

struct iw_param {
	__s32 value;
	__u8 fixed;
	__u8 disabled;
	__u16 flags;
};

struct iw_point {
	void *pointer;
	__u16 length;
	__u16 flags;
};

struct iw_freq {
	__s32 m;
	__s16 e;
	__u8 i;
	__u8 flags;
};

struct iw_quality {
	__u8 qual;
	__u8 level;
	__u8 noise;
	__u8 updated;
};

struct iw_discarded {
	__u32 nwid;
	__u32 code;
	__u32 fragment;
	__u32 retries;
	__u32 misc;
};

struct iw_missed {
	__u32 beacon;
};

struct iw_statistics {
	__u16 status;
	struct iw_quality qual;
	struct iw_discarded discard;
	struct iw_missed miss;
};

union iwreq_data {
	char name[16];
	struct iw_point essid;
	struct iw_param nwid;
	struct iw_freq freq;
	struct iw_param sens;
	struct iw_param bitrate;
	struct iw_param txpower;
	struct iw_param rts;
	struct iw_param frag;
	__u32 mode;
	struct iw_param retry;
	struct iw_point encoding;
	struct iw_param power;
	struct iw_quality qual;
	struct sockaddr ap_addr;
	struct sockaddr addr;
	struct iw_param param;
	struct iw_point data;
};

struct iw_priv_args {
	__u32 cmd;
	__u16 set_args;
	__u16 get_args;
	char name[16];
};

struct iw_request_info {
	__u16 cmd;
	__u16 flags;
};

struct iw_spy_data {
	int spy_number;
	u_char spy_address[48];
	struct iw_quality spy_stat[8];
	struct iw_quality spy_thr_low;
	struct iw_quality spy_thr_high;
	u_char spy_thr_under[8];
};

struct in_ifaddr {
	struct hlist_node hash;
	struct in_ifaddr *ifa_next;
	struct in_device *ifa_dev;
	struct callback_head callback_head;
	__be32 ifa_local;
	__be32 ifa_address;
	__be32 ifa_mask;
	__u32 ifa_rt_priority;
	__be32 ifa_broadcast;
	unsigned char ifa_scope;
	unsigned char ifa_prefixlen;
	unsigned char ifa_proto;
	__u32 ifa_flags;
	char ifa_label[16];
	__u32 ifa_valid_lft;
	__u32 ifa_preferred_lft;
	long unsigned int ifa_cstamp;
	long unsigned int ifa_tstamp;
};

enum {
	SCM_TSTAMP_SND = 0,
	SCM_TSTAMP_SCHED = 1,
	SCM_TSTAMP_ACK = 2,
};

struct nf_hook_state {
	u8 hook;
	u8 pf;
	struct net_device *in;
	struct net_device *out;
	struct sock *sk;
	struct net *net;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};

enum sctp_msg_flags {
	MSG_NOTIFICATION = 32768,
};

struct udp_tunnel_info {
	short unsigned int type;
	sa_family_t sa_family;
	__be16 port;
	u8 hw_priv;
};

struct udp_tunnel_nic_shared {
	struct udp_tunnel_nic *udp_tunnel_nic_info;
	struct list_head devices;
};

struct rps_map {
	unsigned int len;
	struct callback_head rcu;
	u16 cpus[0];
};

struct rps_dev_flow {
	u16 cpu;
	u16 filter;
	unsigned int last_qtail;
};

struct rps_dev_flow_table {
	unsigned int mask;
	struct callback_head rcu;
	struct rps_dev_flow flows[0];
};

struct page_pool_params {
	union {
		struct {
			unsigned int flags;
			unsigned int order;
			unsigned int pool_size;
			int nid;
			struct device *dev;
			struct napi_struct *napi;
			enum dma_data_direction dma_dir;
			unsigned int max_len;
			unsigned int offset;
		};
		struct page_pool_params_fast fast;
	};
	union {
		struct {
			struct net_device *netdev;
			void (*init_callback)(struct page *, void *);
			void *init_arg;
		};
		struct page_pool_params_slow slow;
	};
};

typedef int (*bpf_op_t)(struct net_device *, struct netdev_bpf *);

struct dev_kfree_skb_cb {
	enum skb_drop_reason reason;
};

enum {
	NAPI_F_PREFER_BUSY_POLL = 1,
	NAPI_F_END_ON_RESCHED = 2,
};

struct netdev_adjacent {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	bool master;
	bool ignore;
	u16 ref_nr;
	void *private;
	struct list_head list;
	struct callback_head rcu;
};

enum netlink_attribute_type {
	NL_ATTR_TYPE_INVALID = 0,
	NL_ATTR_TYPE_FLAG = 1,
	NL_ATTR_TYPE_U8 = 2,
	NL_ATTR_TYPE_U16 = 3,
	NL_ATTR_TYPE_U32 = 4,
	NL_ATTR_TYPE_U64 = 5,
	NL_ATTR_TYPE_S8 = 6,
	NL_ATTR_TYPE_S16 = 7,
	NL_ATTR_TYPE_S32 = 8,
	NL_ATTR_TYPE_S64 = 9,
	NL_ATTR_TYPE_BINARY = 10,
	NL_ATTR_TYPE_STRING = 11,
	NL_ATTR_TYPE_NUL_STRING = 12,
	NL_ATTR_TYPE_NESTED = 13,
	NL_ATTR_TYPE_NESTED_ARRAY = 14,
	NL_ATTR_TYPE_BITFIELD32 = 15,
	NL_ATTR_TYPE_SINT = 16,
	NL_ATTR_TYPE_UINT = 17,
};

enum netlink_policy_type_attr {
	NL_POLICY_TYPE_ATTR_UNSPEC = 0,
	NL_POLICY_TYPE_ATTR_TYPE = 1,
	NL_POLICY_TYPE_ATTR_MIN_VALUE_S = 2,
	NL_POLICY_TYPE_ATTR_MAX_VALUE_S = 3,
	NL_POLICY_TYPE_ATTR_MIN_VALUE_U = 4,
	NL_POLICY_TYPE_ATTR_MAX_VALUE_U = 5,
	NL_POLICY_TYPE_ATTR_MIN_LENGTH = 6,
	NL_POLICY_TYPE_ATTR_MAX_LENGTH = 7,
	NL_POLICY_TYPE_ATTR_POLICY_IDX = 8,
	NL_POLICY_TYPE_ATTR_POLICY_MAXTYPE = 9,
	NL_POLICY_TYPE_ATTR_BITFIELD32_MASK = 10,
	NL_POLICY_TYPE_ATTR_PAD = 11,
	NL_POLICY_TYPE_ATTR_MASK = 12,
	__NL_POLICY_TYPE_ATTR_MAX = 13,
	NL_POLICY_TYPE_ATTR_MAX = 12,
};

enum {
	NLA_UNSPEC = 0,
	NLA_U8 = 1,
	NLA_U16 = 2,
	NLA_U32 = 3,
	NLA_U64 = 4,
	NLA_STRING = 5,
	NLA_FLAG = 6,
	NLA_MSECS = 7,
	NLA_NESTED = 8,
	NLA_NESTED_ARRAY = 9,
	NLA_NUL_STRING = 10,
	NLA_BINARY = 11,
	NLA_S8 = 12,
	NLA_S16 = 13,
	NLA_S32 = 14,
	NLA_S64 = 15,
	NLA_BITFIELD32 = 16,
	NLA_REJECT = 17,
	NLA_BE16 = 18,
	NLA_BE32 = 19,
	NLA_SINT = 20,
	NLA_UINT = 21,
	__NLA_TYPE_MAX = 22,
};

enum nla_policy_validation {
	NLA_VALIDATE_NONE = 0,
	NLA_VALIDATE_RANGE = 1,
	NLA_VALIDATE_RANGE_WARN_TOO_LONG = 2,
	NLA_VALIDATE_MIN = 3,
	NLA_VALIDATE_MAX = 4,
	NLA_VALIDATE_MASK = 5,
	NLA_VALIDATE_RANGE_PTR = 6,
	NLA_VALIDATE_FUNCTION = 7,
};

struct netlink_policy_dump_state {
	unsigned int policy_idx;
	unsigned int attr_idx;
	unsigned int n_alloc;
	struct {
		const struct nla_policy *policy;
		unsigned int maxtype;
	} policies[0];
};

enum {
	SOF_TIMESTAMPING_TX_HARDWARE = 1,
	SOF_TIMESTAMPING_TX_SOFTWARE = 2,
	SOF_TIMESTAMPING_RX_HARDWARE = 4,
	SOF_TIMESTAMPING_RX_SOFTWARE = 8,
	SOF_TIMESTAMPING_SOFTWARE = 16,
	SOF_TIMESTAMPING_SYS_HARDWARE = 32,
	SOF_TIMESTAMPING_RAW_HARDWARE = 64,
	SOF_TIMESTAMPING_OPT_ID = 128,
	SOF_TIMESTAMPING_TX_SCHED = 256,
	SOF_TIMESTAMPING_TX_ACK = 512,
	SOF_TIMESTAMPING_OPT_CMSG = 1024,
	SOF_TIMESTAMPING_OPT_TSONLY = 2048,
	SOF_TIMESTAMPING_OPT_STATS = 4096,
	SOF_TIMESTAMPING_OPT_PKTINFO = 8192,
	SOF_TIMESTAMPING_OPT_TX_SWHW = 16384,
	SOF_TIMESTAMPING_BIND_PHC = 32768,
	SOF_TIMESTAMPING_OPT_ID_TCP = 65536,
	SOF_TIMESTAMPING_LAST = 65536,
	SOF_TIMESTAMPING_MASK = 131071,
};

enum hwtstamp_tx_types {
	HWTSTAMP_TX_OFF = 0,
	HWTSTAMP_TX_ON = 1,
	HWTSTAMP_TX_ONESTEP_SYNC = 2,
	HWTSTAMP_TX_ONESTEP_P2P = 3,
	__HWTSTAMP_TX_CNT = 4,
};

enum hwtstamp_rx_filters {
	HWTSTAMP_FILTER_NONE = 0,
	HWTSTAMP_FILTER_ALL = 1,
	HWTSTAMP_FILTER_SOME = 2,
	HWTSTAMP_FILTER_PTP_V1_L4_EVENT = 3,
	HWTSTAMP_FILTER_PTP_V1_L4_SYNC = 4,
	HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ = 5,
	HWTSTAMP_FILTER_PTP_V2_L4_EVENT = 6,
	HWTSTAMP_FILTER_PTP_V2_L4_SYNC = 7,
	HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ = 8,
	HWTSTAMP_FILTER_PTP_V2_L2_EVENT = 9,
	HWTSTAMP_FILTER_PTP_V2_L2_SYNC = 10,
	HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ = 11,
	HWTSTAMP_FILTER_PTP_V2_EVENT = 12,
	HWTSTAMP_FILTER_PTP_V2_SYNC = 13,
	HWTSTAMP_FILTER_PTP_V2_DELAY_REQ = 14,
	HWTSTAMP_FILTER_NTP_ALL = 15,
	__HWTSTAMP_FILTER_CNT = 16,
};

enum tunable_id {
	ETHTOOL_ID_UNSPEC = 0,
	ETHTOOL_RX_COPYBREAK = 1,
	ETHTOOL_TX_COPYBREAK = 2,
	ETHTOOL_PFC_PREVENTION_TOUT = 3,
	ETHTOOL_TX_COPYBREAK_BUF_SIZE = 4,
	__ETHTOOL_TUNABLE_COUNT = 5,
};

enum phy_tunable_id {
	ETHTOOL_PHY_ID_UNSPEC = 0,
	ETHTOOL_PHY_DOWNSHIFT = 1,
	ETHTOOL_PHY_FAST_LINK_DOWN = 2,
	ETHTOOL_PHY_EDPD = 3,
	__ETHTOOL_PHY_TUNABLE_COUNT = 4,
};

enum {
	ETH_RSS_HASH_TOP_BIT = 0,
	ETH_RSS_HASH_XOR_BIT = 1,
	ETH_RSS_HASH_CRC32_BIT = 2,
	ETH_RSS_HASH_FUNCS_COUNT = 3,
};

enum {
	ETHTOOL_MSG_USER_NONE = 0,
	ETHTOOL_MSG_STRSET_GET = 1,
	ETHTOOL_MSG_LINKINFO_GET = 2,
	ETHTOOL_MSG_LINKINFO_SET = 3,
	ETHTOOL_MSG_LINKMODES_GET = 4,
	ETHTOOL_MSG_LINKMODES_SET = 5,
	ETHTOOL_MSG_LINKSTATE_GET = 6,
	ETHTOOL_MSG_DEBUG_GET = 7,
	ETHTOOL_MSG_DEBUG_SET = 8,
	ETHTOOL_MSG_WOL_GET = 9,
	ETHTOOL_MSG_WOL_SET = 10,
	ETHTOOL_MSG_FEATURES_GET = 11,
	ETHTOOL_MSG_FEATURES_SET = 12,
	ETHTOOL_MSG_PRIVFLAGS_GET = 13,
	ETHTOOL_MSG_PRIVFLAGS_SET = 14,
	ETHTOOL_MSG_RINGS_GET = 15,
	ETHTOOL_MSG_RINGS_SET = 16,
	ETHTOOL_MSG_CHANNELS_GET = 17,
	ETHTOOL_MSG_CHANNELS_SET = 18,
	ETHTOOL_MSG_COALESCE_GET = 19,
	ETHTOOL_MSG_COALESCE_SET = 20,
	ETHTOOL_MSG_PAUSE_GET = 21,
	ETHTOOL_MSG_PAUSE_SET = 22,
	ETHTOOL_MSG_EEE_GET = 23,
	ETHTOOL_MSG_EEE_SET = 24,
	ETHTOOL_MSG_TSINFO_GET = 25,
	ETHTOOL_MSG_CABLE_TEST_ACT = 26,
	ETHTOOL_MSG_CABLE_TEST_TDR_ACT = 27,
	ETHTOOL_MSG_TUNNEL_INFO_GET = 28,
	ETHTOOL_MSG_FEC_GET = 29,
	ETHTOOL_MSG_FEC_SET = 30,
	ETHTOOL_MSG_MODULE_EEPROM_GET = 31,
	ETHTOOL_MSG_STATS_GET = 32,
	ETHTOOL_MSG_PHC_VCLOCKS_GET = 33,
	ETHTOOL_MSG_MODULE_GET = 34,
	ETHTOOL_MSG_MODULE_SET = 35,
	ETHTOOL_MSG_PSE_GET = 36,
	ETHTOOL_MSG_PSE_SET = 37,
	ETHTOOL_MSG_RSS_GET = 38,
	ETHTOOL_MSG_PLCA_GET_CFG = 39,
	ETHTOOL_MSG_PLCA_SET_CFG = 40,
	ETHTOOL_MSG_PLCA_GET_STATUS = 41,
	ETHTOOL_MSG_MM_GET = 42,
	ETHTOOL_MSG_MM_SET = 43,
	__ETHTOOL_MSG_USER_CNT = 44,
	ETHTOOL_MSG_USER_MAX = 43,
};

enum {
	ETHTOOL_MSG_KERNEL_NONE = 0,
	ETHTOOL_MSG_STRSET_GET_REPLY = 1,
	ETHTOOL_MSG_LINKINFO_GET_REPLY = 2,
	ETHTOOL_MSG_LINKINFO_NTF = 3,
	ETHTOOL_MSG_LINKMODES_GET_REPLY = 4,
	ETHTOOL_MSG_LINKMODES_NTF = 5,
	ETHTOOL_MSG_LINKSTATE_GET_REPLY = 6,
	ETHTOOL_MSG_DEBUG_GET_REPLY = 7,
	ETHTOOL_MSG_DEBUG_NTF = 8,
	ETHTOOL_MSG_WOL_GET_REPLY = 9,
	ETHTOOL_MSG_WOL_NTF = 10,
	ETHTOOL_MSG_FEATURES_GET_REPLY = 11,
	ETHTOOL_MSG_FEATURES_SET_REPLY = 12,
	ETHTOOL_MSG_FEATURES_NTF = 13,
	ETHTOOL_MSG_PRIVFLAGS_GET_REPLY = 14,
	ETHTOOL_MSG_PRIVFLAGS_NTF = 15,
	ETHTOOL_MSG_RINGS_GET_REPLY = 16,
	ETHTOOL_MSG_RINGS_NTF = 17,
	ETHTOOL_MSG_CHANNELS_GET_REPLY = 18,
	ETHTOOL_MSG_CHANNELS_NTF = 19,
	ETHTOOL_MSG_COALESCE_GET_REPLY = 20,
	ETHTOOL_MSG_COALESCE_NTF = 21,
	ETHTOOL_MSG_PAUSE_GET_REPLY = 22,
	ETHTOOL_MSG_PAUSE_NTF = 23,
	ETHTOOL_MSG_EEE_GET_REPLY = 24,
	ETHTOOL_MSG_EEE_NTF = 25,
	ETHTOOL_MSG_TSINFO_GET_REPLY = 26,
	ETHTOOL_MSG_CABLE_TEST_NTF = 27,
	ETHTOOL_MSG_CABLE_TEST_TDR_NTF = 28,
	ETHTOOL_MSG_TUNNEL_INFO_GET_REPLY = 29,
	ETHTOOL_MSG_FEC_GET_REPLY = 30,
	ETHTOOL_MSG_FEC_NTF = 31,
	ETHTOOL_MSG_MODULE_EEPROM_GET_REPLY = 32,
	ETHTOOL_MSG_STATS_GET_REPLY = 33,
	ETHTOOL_MSG_PHC_VCLOCKS_GET_REPLY = 34,
	ETHTOOL_MSG_MODULE_GET_REPLY = 35,
	ETHTOOL_MSG_MODULE_NTF = 36,
	ETHTOOL_MSG_PSE_GET_REPLY = 37,
	ETHTOOL_MSG_RSS_GET_REPLY = 38,
	ETHTOOL_MSG_PLCA_GET_CFG_REPLY = 39,
	ETHTOOL_MSG_PLCA_GET_STATUS_REPLY = 40,
	ETHTOOL_MSG_PLCA_NTF = 41,
	ETHTOOL_MSG_MM_GET_REPLY = 42,
	ETHTOOL_MSG_MM_NTF = 43,
	__ETHTOOL_MSG_KERNEL_CNT = 44,
	ETHTOOL_MSG_KERNEL_MAX = 43,
};

enum {
	ETHTOOL_A_HEADER_UNSPEC = 0,
	ETHTOOL_A_HEADER_DEV_INDEX = 1,
	ETHTOOL_A_HEADER_DEV_NAME = 2,
	ETHTOOL_A_HEADER_FLAGS = 3,
	__ETHTOOL_A_HEADER_CNT = 4,
	ETHTOOL_A_HEADER_MAX = 3,
};

enum {
	ETHTOOL_A_STRSET_UNSPEC = 0,
	ETHTOOL_A_STRSET_HEADER = 1,
	ETHTOOL_A_STRSET_STRINGSETS = 2,
	ETHTOOL_A_STRSET_COUNTS_ONLY = 3,
	__ETHTOOL_A_STRSET_CNT = 4,
	ETHTOOL_A_STRSET_MAX = 3,
};

enum {
	ETHTOOL_A_LINKINFO_UNSPEC = 0,
	ETHTOOL_A_LINKINFO_HEADER = 1,
	ETHTOOL_A_LINKINFO_PORT = 2,
	ETHTOOL_A_LINKINFO_PHYADDR = 3,
	ETHTOOL_A_LINKINFO_TP_MDIX = 4,
	ETHTOOL_A_LINKINFO_TP_MDIX_CTRL = 5,
	ETHTOOL_A_LINKINFO_TRANSCEIVER = 6,
	__ETHTOOL_A_LINKINFO_CNT = 7,
	ETHTOOL_A_LINKINFO_MAX = 6,
};

enum {
	ETHTOOL_A_LINKMODES_UNSPEC = 0,
	ETHTOOL_A_LINKMODES_HEADER = 1,
	ETHTOOL_A_LINKMODES_AUTONEG = 2,
	ETHTOOL_A_LINKMODES_OURS = 3,
	ETHTOOL_A_LINKMODES_PEER = 4,
	ETHTOOL_A_LINKMODES_SPEED = 5,
	ETHTOOL_A_LINKMODES_DUPLEX = 6,
	ETHTOOL_A_LINKMODES_MASTER_SLAVE_CFG = 7,
	ETHTOOL_A_LINKMODES_MASTER_SLAVE_STATE = 8,
	ETHTOOL_A_LINKMODES_LANES = 9,
	ETHTOOL_A_LINKMODES_RATE_MATCHING = 10,
	__ETHTOOL_A_LINKMODES_CNT = 11,
	ETHTOOL_A_LINKMODES_MAX = 10,
};

enum {
	ETHTOOL_A_LINKSTATE_UNSPEC = 0,
	ETHTOOL_A_LINKSTATE_HEADER = 1,
	ETHTOOL_A_LINKSTATE_LINK = 2,
	ETHTOOL_A_LINKSTATE_SQI = 3,
	ETHTOOL_A_LINKSTATE_SQI_MAX = 4,
	ETHTOOL_A_LINKSTATE_EXT_STATE = 5,
	ETHTOOL_A_LINKSTATE_EXT_SUBSTATE = 6,
	ETHTOOL_A_LINKSTATE_EXT_DOWN_CNT = 7,
	__ETHTOOL_A_LINKSTATE_CNT = 8,
	ETHTOOL_A_LINKSTATE_MAX = 7,
};

enum {
	ETHTOOL_A_DEBUG_UNSPEC = 0,
	ETHTOOL_A_DEBUG_HEADER = 1,
	ETHTOOL_A_DEBUG_MSGMASK = 2,
	__ETHTOOL_A_DEBUG_CNT = 3,
	ETHTOOL_A_DEBUG_MAX = 2,
};

enum {
	ETHTOOL_A_WOL_UNSPEC = 0,
	ETHTOOL_A_WOL_HEADER = 1,
	ETHTOOL_A_WOL_MODES = 2,
	ETHTOOL_A_WOL_SOPASS = 3,
	__ETHTOOL_A_WOL_CNT = 4,
	ETHTOOL_A_WOL_MAX = 3,
};

enum {
	ETHTOOL_A_FEATURES_UNSPEC = 0,
	ETHTOOL_A_FEATURES_HEADER = 1,
	ETHTOOL_A_FEATURES_HW = 2,
	ETHTOOL_A_FEATURES_WANTED = 3,
	ETHTOOL_A_FEATURES_ACTIVE = 4,
	ETHTOOL_A_FEATURES_NOCHANGE = 5,
	__ETHTOOL_A_FEATURES_CNT = 6,
	ETHTOOL_A_FEATURES_MAX = 5,
};

enum {
	ETHTOOL_A_PRIVFLAGS_UNSPEC = 0,
	ETHTOOL_A_PRIVFLAGS_HEADER = 1,
	ETHTOOL_A_PRIVFLAGS_FLAGS = 2,
	__ETHTOOL_A_PRIVFLAGS_CNT = 3,
	ETHTOOL_A_PRIVFLAGS_MAX = 2,
};

enum {
	ETHTOOL_A_RINGS_UNSPEC = 0,
	ETHTOOL_A_RINGS_HEADER = 1,
	ETHTOOL_A_RINGS_RX_MAX = 2,
	ETHTOOL_A_RINGS_RX_MINI_MAX = 3,
	ETHTOOL_A_RINGS_RX_JUMBO_MAX = 4,
	ETHTOOL_A_RINGS_TX_MAX = 5,
	ETHTOOL_A_RINGS_RX = 6,
	ETHTOOL_A_RINGS_RX_MINI = 7,
	ETHTOOL_A_RINGS_RX_JUMBO = 8,
	ETHTOOL_A_RINGS_TX = 9,
	ETHTOOL_A_RINGS_RX_BUF_LEN = 10,
	ETHTOOL_A_RINGS_TCP_DATA_SPLIT = 11,
	ETHTOOL_A_RINGS_CQE_SIZE = 12,
	ETHTOOL_A_RINGS_TX_PUSH = 13,
	ETHTOOL_A_RINGS_RX_PUSH = 14,
	ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN = 15,
	ETHTOOL_A_RINGS_TX_PUSH_BUF_LEN_MAX = 16,
	__ETHTOOL_A_RINGS_CNT = 17,
	ETHTOOL_A_RINGS_MAX = 16,
};

enum {
	ETHTOOL_A_CHANNELS_UNSPEC = 0,
	ETHTOOL_A_CHANNELS_HEADER = 1,
	ETHTOOL_A_CHANNELS_RX_MAX = 2,
	ETHTOOL_A_CHANNELS_TX_MAX = 3,
	ETHTOOL_A_CHANNELS_OTHER_MAX = 4,
	ETHTOOL_A_CHANNELS_COMBINED_MAX = 5,
	ETHTOOL_A_CHANNELS_RX_COUNT = 6,
	ETHTOOL_A_CHANNELS_TX_COUNT = 7,
	ETHTOOL_A_CHANNELS_OTHER_COUNT = 8,
	ETHTOOL_A_CHANNELS_COMBINED_COUNT = 9,
	__ETHTOOL_A_CHANNELS_CNT = 10,
	ETHTOOL_A_CHANNELS_MAX = 9,
};

enum {
	ETHTOOL_A_COALESCE_UNSPEC = 0,
	ETHTOOL_A_COALESCE_HEADER = 1,
	ETHTOOL_A_COALESCE_RX_USECS = 2,
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES = 3,
	ETHTOOL_A_COALESCE_RX_USECS_IRQ = 4,
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_IRQ = 5,
	ETHTOOL_A_COALESCE_TX_USECS = 6,
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES = 7,
	ETHTOOL_A_COALESCE_TX_USECS_IRQ = 8,
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_IRQ = 9,
	ETHTOOL_A_COALESCE_STATS_BLOCK_USECS = 10,
	ETHTOOL_A_COALESCE_USE_ADAPTIVE_RX = 11,
	ETHTOOL_A_COALESCE_USE_ADAPTIVE_TX = 12,
	ETHTOOL_A_COALESCE_PKT_RATE_LOW = 13,
	ETHTOOL_A_COALESCE_RX_USECS_LOW = 14,
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_LOW = 15,
	ETHTOOL_A_COALESCE_TX_USECS_LOW = 16,
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_LOW = 17,
	ETHTOOL_A_COALESCE_PKT_RATE_HIGH = 18,
	ETHTOOL_A_COALESCE_RX_USECS_HIGH = 19,
	ETHTOOL_A_COALESCE_RX_MAX_FRAMES_HIGH = 20,
	ETHTOOL_A_COALESCE_TX_USECS_HIGH = 21,
	ETHTOOL_A_COALESCE_TX_MAX_FRAMES_HIGH = 22,
	ETHTOOL_A_COALESCE_RATE_SAMPLE_INTERVAL = 23,
	ETHTOOL_A_COALESCE_USE_CQE_MODE_TX = 24,
	ETHTOOL_A_COALESCE_USE_CQE_MODE_RX = 25,
	ETHTOOL_A_COALESCE_TX_AGGR_MAX_BYTES = 26,
	ETHTOOL_A_COALESCE_TX_AGGR_MAX_FRAMES = 27,
	ETHTOOL_A_COALESCE_TX_AGGR_TIME_USECS = 28,
	__ETHTOOL_A_COALESCE_CNT = 29,
	ETHTOOL_A_COALESCE_MAX = 28,
};

enum {
	ETHTOOL_A_PAUSE_UNSPEC = 0,
	ETHTOOL_A_PAUSE_HEADER = 1,
	ETHTOOL_A_PAUSE_AUTONEG = 2,
	ETHTOOL_A_PAUSE_RX = 3,
	ETHTOOL_A_PAUSE_TX = 4,
	ETHTOOL_A_PAUSE_STATS = 5,
	ETHTOOL_A_PAUSE_STATS_SRC = 6,
	__ETHTOOL_A_PAUSE_CNT = 7,
	ETHTOOL_A_PAUSE_MAX = 6,
};

enum {
	ETHTOOL_A_EEE_UNSPEC = 0,
	ETHTOOL_A_EEE_HEADER = 1,
	ETHTOOL_A_EEE_MODES_OURS = 2,
	ETHTOOL_A_EEE_MODES_PEER = 3,
	ETHTOOL_A_EEE_ACTIVE = 4,
	ETHTOOL_A_EEE_ENABLED = 5,
	ETHTOOL_A_EEE_TX_LPI_ENABLED = 6,
	ETHTOOL_A_EEE_TX_LPI_TIMER = 7,
	__ETHTOOL_A_EEE_CNT = 8,
	ETHTOOL_A_EEE_MAX = 7,
};

enum {
	ETHTOOL_A_TSINFO_UNSPEC = 0,
	ETHTOOL_A_TSINFO_HEADER = 1,
	ETHTOOL_A_TSINFO_TIMESTAMPING = 2,
	ETHTOOL_A_TSINFO_TX_TYPES = 3,
	ETHTOOL_A_TSINFO_RX_FILTERS = 4,
	ETHTOOL_A_TSINFO_PHC_INDEX = 5,
	__ETHTOOL_A_TSINFO_CNT = 6,
	ETHTOOL_A_TSINFO_MAX = 5,
};

enum {
	ETHTOOL_A_PHC_VCLOCKS_UNSPEC = 0,
	ETHTOOL_A_PHC_VCLOCKS_HEADER = 1,
	ETHTOOL_A_PHC_VCLOCKS_NUM = 2,
	ETHTOOL_A_PHC_VCLOCKS_INDEX = 3,
	__ETHTOOL_A_PHC_VCLOCKS_CNT = 4,
	ETHTOOL_A_PHC_VCLOCKS_MAX = 3,
};

enum {
	ETHTOOL_A_CABLE_TEST_UNSPEC = 0,
	ETHTOOL_A_CABLE_TEST_HEADER = 1,
	__ETHTOOL_A_CABLE_TEST_CNT = 2,
	ETHTOOL_A_CABLE_TEST_MAX = 1,
};

enum {
	ETHTOOL_A_CABLE_TEST_TDR_UNSPEC = 0,
	ETHTOOL_A_CABLE_TEST_TDR_HEADER = 1,
	ETHTOOL_A_CABLE_TEST_TDR_CFG = 2,
	__ETHTOOL_A_CABLE_TEST_TDR_CNT = 3,
	ETHTOOL_A_CABLE_TEST_TDR_MAX = 2,
};

enum {
	ETHTOOL_A_TUNNEL_INFO_UNSPEC = 0,
	ETHTOOL_A_TUNNEL_INFO_HEADER = 1,
	ETHTOOL_A_TUNNEL_INFO_UDP_PORTS = 2,
	__ETHTOOL_A_TUNNEL_INFO_CNT = 3,
	ETHTOOL_A_TUNNEL_INFO_MAX = 2,
};

enum {
	ETHTOOL_A_FEC_UNSPEC = 0,
	ETHTOOL_A_FEC_HEADER = 1,
	ETHTOOL_A_FEC_MODES = 2,
	ETHTOOL_A_FEC_AUTO = 3,
	ETHTOOL_A_FEC_ACTIVE = 4,
	ETHTOOL_A_FEC_STATS = 5,
	__ETHTOOL_A_FEC_CNT = 6,
	ETHTOOL_A_FEC_MAX = 5,
};

enum {
	ETHTOOL_A_MODULE_EEPROM_UNSPEC = 0,
	ETHTOOL_A_MODULE_EEPROM_HEADER = 1,
	ETHTOOL_A_MODULE_EEPROM_OFFSET = 2,
	ETHTOOL_A_MODULE_EEPROM_LENGTH = 3,
	ETHTOOL_A_MODULE_EEPROM_PAGE = 4,
	ETHTOOL_A_MODULE_EEPROM_BANK = 5,
	ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS = 6,
	ETHTOOL_A_MODULE_EEPROM_DATA = 7,
	__ETHTOOL_A_MODULE_EEPROM_CNT = 8,
	ETHTOOL_A_MODULE_EEPROM_MAX = 7,
};

enum {
	ETHTOOL_A_STATS_UNSPEC = 0,
	ETHTOOL_A_STATS_PAD = 1,
	ETHTOOL_A_STATS_HEADER = 2,
	ETHTOOL_A_STATS_GROUPS = 3,
	ETHTOOL_A_STATS_GRP = 4,
	ETHTOOL_A_STATS_SRC = 5,
	__ETHTOOL_A_STATS_CNT = 6,
	ETHTOOL_A_STATS_MAX = 5,
};

enum {
	ETHTOOL_STATS_ETH_PHY = 0,
	ETHTOOL_STATS_ETH_MAC = 1,
	ETHTOOL_STATS_ETH_CTRL = 2,
	ETHTOOL_STATS_RMON = 3,
	__ETHTOOL_STATS_CNT = 4,
};

enum {
	ETHTOOL_A_STATS_ETH_PHY_5_SYM_ERR = 0,
	__ETHTOOL_A_STATS_ETH_PHY_CNT = 1,
	ETHTOOL_A_STATS_ETH_PHY_MAX = 0,
};

enum {
	ETHTOOL_A_STATS_ETH_MAC_2_TX_PKT = 0,
	ETHTOOL_A_STATS_ETH_MAC_3_SINGLE_COL = 1,
	ETHTOOL_A_STATS_ETH_MAC_4_MULTI_COL = 2,
	ETHTOOL_A_STATS_ETH_MAC_5_RX_PKT = 3,
	ETHTOOL_A_STATS_ETH_MAC_6_FCS_ERR = 4,
	ETHTOOL_A_STATS_ETH_MAC_7_ALIGN_ERR = 5,
	ETHTOOL_A_STATS_ETH_MAC_8_TX_BYTES = 6,
	ETHTOOL_A_STATS_ETH_MAC_9_TX_DEFER = 7,
	ETHTOOL_A_STATS_ETH_MAC_10_LATE_COL = 8,
	ETHTOOL_A_STATS_ETH_MAC_11_XS_COL = 9,
	ETHTOOL_A_STATS_ETH_MAC_12_TX_INT_ERR = 10,
	ETHTOOL_A_STATS_ETH_MAC_13_CS_ERR = 11,
	ETHTOOL_A_STATS_ETH_MAC_14_RX_BYTES = 12,
	ETHTOOL_A_STATS_ETH_MAC_15_RX_INT_ERR = 13,
	ETHTOOL_A_STATS_ETH_MAC_18_TX_MCAST = 14,
	ETHTOOL_A_STATS_ETH_MAC_19_TX_BCAST = 15,
	ETHTOOL_A_STATS_ETH_MAC_20_XS_DEFER = 16,
	ETHTOOL_A_STATS_ETH_MAC_21_RX_MCAST = 17,
	ETHTOOL_A_STATS_ETH_MAC_22_RX_BCAST = 18,
	ETHTOOL_A_STATS_ETH_MAC_23_IR_LEN_ERR = 19,
	ETHTOOL_A_STATS_ETH_MAC_24_OOR_LEN = 20,
	ETHTOOL_A_STATS_ETH_MAC_25_TOO_LONG_ERR = 21,
	__ETHTOOL_A_STATS_ETH_MAC_CNT = 22,
	ETHTOOL_A_STATS_ETH_MAC_MAX = 21,
};

enum {
	ETHTOOL_A_STATS_ETH_CTRL_3_TX = 0,
	ETHTOOL_A_STATS_ETH_CTRL_4_RX = 1,
	ETHTOOL_A_STATS_ETH_CTRL_5_RX_UNSUP = 2,
	__ETHTOOL_A_STATS_ETH_CTRL_CNT = 3,
	ETHTOOL_A_STATS_ETH_CTRL_MAX = 2,
};

enum {
	ETHTOOL_A_STATS_RMON_UNDERSIZE = 0,
	ETHTOOL_A_STATS_RMON_OVERSIZE = 1,
	ETHTOOL_A_STATS_RMON_FRAG = 2,
	ETHTOOL_A_STATS_RMON_JABBER = 3,
	__ETHTOOL_A_STATS_RMON_CNT = 4,
	ETHTOOL_A_STATS_RMON_MAX = 3,
};

enum {
	ETHTOOL_A_MODULE_UNSPEC = 0,
	ETHTOOL_A_MODULE_HEADER = 1,
	ETHTOOL_A_MODULE_POWER_MODE_POLICY = 2,
	ETHTOOL_A_MODULE_POWER_MODE = 3,
	__ETHTOOL_A_MODULE_CNT = 4,
	ETHTOOL_A_MODULE_MAX = 3,
};

enum {
	ETHTOOL_A_PSE_UNSPEC = 0,
	ETHTOOL_A_PSE_HEADER = 1,
	ETHTOOL_A_PODL_PSE_ADMIN_STATE = 2,
	ETHTOOL_A_PODL_PSE_ADMIN_CONTROL = 3,
	ETHTOOL_A_PODL_PSE_PW_D_STATUS = 4,
	__ETHTOOL_A_PSE_CNT = 5,
	ETHTOOL_A_PSE_MAX = 4,
};

enum {
	ETHTOOL_A_RSS_UNSPEC = 0,
	ETHTOOL_A_RSS_HEADER = 1,
	ETHTOOL_A_RSS_CONTEXT = 2,
	ETHTOOL_A_RSS_HFUNC = 3,
	ETHTOOL_A_RSS_INDIR = 4,
	ETHTOOL_A_RSS_HKEY = 5,
	ETHTOOL_A_RSS_INPUT_XFRM = 6,
	__ETHTOOL_A_RSS_CNT = 7,
	ETHTOOL_A_RSS_MAX = 6,
};

enum {
	ETHTOOL_A_PLCA_UNSPEC = 0,
	ETHTOOL_A_PLCA_HEADER = 1,
	ETHTOOL_A_PLCA_VERSION = 2,
	ETHTOOL_A_PLCA_ENABLED = 3,
	ETHTOOL_A_PLCA_STATUS = 4,
	ETHTOOL_A_PLCA_NODE_CNT = 5,
	ETHTOOL_A_PLCA_NODE_ID = 6,
	ETHTOOL_A_PLCA_TO_TMR = 7,
	ETHTOOL_A_PLCA_BURST_CNT = 8,
	ETHTOOL_A_PLCA_BURST_TMR = 9,
	__ETHTOOL_A_PLCA_CNT = 10,
	ETHTOOL_A_PLCA_MAX = 9,
};

enum {
	ETHTOOL_A_MM_UNSPEC = 0,
	ETHTOOL_A_MM_HEADER = 1,
	ETHTOOL_A_MM_PMAC_ENABLED = 2,
	ETHTOOL_A_MM_TX_ENABLED = 3,
	ETHTOOL_A_MM_TX_ACTIVE = 4,
	ETHTOOL_A_MM_TX_MIN_FRAG_SIZE = 5,
	ETHTOOL_A_MM_RX_MIN_FRAG_SIZE = 6,
	ETHTOOL_A_MM_VERIFY_ENABLED = 7,
	ETHTOOL_A_MM_VERIFY_STATUS = 8,
	ETHTOOL_A_MM_VERIFY_TIME = 9,
	ETHTOOL_A_MM_MAX_VERIFY_TIME = 10,
	ETHTOOL_A_MM_STATS = 11,
	__ETHTOOL_A_MM_CNT = 12,
	ETHTOOL_A_MM_MAX = 11,
};

enum {
	IPSTATS_MIB_NUM = 0,
	IPSTATS_MIB_INPKTS = 1,
	IPSTATS_MIB_INOCTETS = 2,
	IPSTATS_MIB_INDELIVERS = 3,
	IPSTATS_MIB_OUTFORWDATAGRAMS = 4,
	IPSTATS_MIB_OUTREQUESTS = 5,
	IPSTATS_MIB_OUTOCTETS = 6,
	IPSTATS_MIB_INHDRERRORS = 7,
	IPSTATS_MIB_INTOOBIGERRORS = 8,
	IPSTATS_MIB_INNOROUTES = 9,
	IPSTATS_MIB_INADDRERRORS = 10,
	IPSTATS_MIB_INUNKNOWNPROTOS = 11,
	IPSTATS_MIB_INTRUNCATEDPKTS = 12,
	IPSTATS_MIB_INDISCARDS = 13,
	IPSTATS_MIB_OUTDISCARDS = 14,
	IPSTATS_MIB_OUTNOROUTES = 15,
	IPSTATS_MIB_REASMTIMEOUT = 16,
	IPSTATS_MIB_REASMREQDS = 17,
	IPSTATS_MIB_REASMOKS = 18,
	IPSTATS_MIB_REASMFAILS = 19,
	IPSTATS_MIB_FRAGOKS = 20,
	IPSTATS_MIB_FRAGFAILS = 21,
	IPSTATS_MIB_FRAGCREATES = 22,
	IPSTATS_MIB_INMCASTPKTS = 23,
	IPSTATS_MIB_OUTMCASTPKTS = 24,
	IPSTATS_MIB_INBCASTPKTS = 25,
	IPSTATS_MIB_OUTBCASTPKTS = 26,
	IPSTATS_MIB_INMCASTOCTETS = 27,
	IPSTATS_MIB_OUTMCASTOCTETS = 28,
	IPSTATS_MIB_INBCASTOCTETS = 29,
	IPSTATS_MIB_OUTBCASTOCTETS = 30,
	IPSTATS_MIB_CSUMERRORS = 31,
	IPSTATS_MIB_NOECTPKTS = 32,
	IPSTATS_MIB_ECT1PKTS = 33,
	IPSTATS_MIB_ECT0PKTS = 34,
	IPSTATS_MIB_CEPKTS = 35,
	IPSTATS_MIB_REASM_OVERLAPS = 36,
	IPSTATS_MIB_OUTPKTS = 37,
	__IPSTATS_MIB_MAX = 38,
};

enum {
	ICMP_MIB_NUM = 0,
	ICMP_MIB_INMSGS = 1,
	ICMP_MIB_INERRORS = 2,
	ICMP_MIB_INDESTUNREACHS = 3,
	ICMP_MIB_INTIMEEXCDS = 4,
	ICMP_MIB_INPARMPROBS = 5,
	ICMP_MIB_INSRCQUENCHS = 6,
	ICMP_MIB_INREDIRECTS = 7,
	ICMP_MIB_INECHOS = 8,
	ICMP_MIB_INECHOREPS = 9,
	ICMP_MIB_INTIMESTAMPS = 10,
	ICMP_MIB_INTIMESTAMPREPS = 11,
	ICMP_MIB_INADDRMASKS = 12,
	ICMP_MIB_INADDRMASKREPS = 13,
	ICMP_MIB_OUTMSGS = 14,
	ICMP_MIB_OUTERRORS = 15,
	ICMP_MIB_OUTDESTUNREACHS = 16,
	ICMP_MIB_OUTTIMEEXCDS = 17,
	ICMP_MIB_OUTPARMPROBS = 18,
	ICMP_MIB_OUTSRCQUENCHS = 19,
	ICMP_MIB_OUTREDIRECTS = 20,
	ICMP_MIB_OUTECHOS = 21,
	ICMP_MIB_OUTECHOREPS = 22,
	ICMP_MIB_OUTTIMESTAMPS = 23,
	ICMP_MIB_OUTTIMESTAMPREPS = 24,
	ICMP_MIB_OUTADDRMASKS = 25,
	ICMP_MIB_OUTADDRMASKREPS = 26,
	ICMP_MIB_CSUMERRORS = 27,
	ICMP_MIB_RATELIMITGLOBAL = 28,
	ICMP_MIB_RATELIMITHOST = 29,
	__ICMP_MIB_MAX = 30,
};

enum {
	ICMP6_MIB_NUM = 0,
	ICMP6_MIB_INMSGS = 1,
	ICMP6_MIB_INERRORS = 2,
	ICMP6_MIB_OUTMSGS = 3,
	ICMP6_MIB_OUTERRORS = 4,
	ICMP6_MIB_CSUMERRORS = 5,
	ICMP6_MIB_RATELIMITHOST = 6,
	__ICMP6_MIB_MAX = 7,
};

enum {
	TCP_MIB_NUM = 0,
	TCP_MIB_RTOALGORITHM = 1,
	TCP_MIB_RTOMIN = 2,
	TCP_MIB_RTOMAX = 3,
	TCP_MIB_MAXCONN = 4,
	TCP_MIB_ACTIVEOPENS = 5,
	TCP_MIB_PASSIVEOPENS = 6,
	TCP_MIB_ATTEMPTFAILS = 7,
	TCP_MIB_ESTABRESETS = 8,
	TCP_MIB_CURRESTAB = 9,
	TCP_MIB_INSEGS = 10,
	TCP_MIB_OUTSEGS = 11,
	TCP_MIB_RETRANSSEGS = 12,
	TCP_MIB_INERRS = 13,
	TCP_MIB_OUTRSTS = 14,
	TCP_MIB_CSUMERRORS = 15,
	__TCP_MIB_MAX = 16,
};

enum {
	UDP_MIB_NUM = 0,
	UDP_MIB_INDATAGRAMS = 1,
	UDP_MIB_NOPORTS = 2,
	UDP_MIB_INERRORS = 3,
	UDP_MIB_OUTDATAGRAMS = 4,
	UDP_MIB_RCVBUFERRORS = 5,
	UDP_MIB_SNDBUFERRORS = 6,
	UDP_MIB_CSUMERRORS = 7,
	UDP_MIB_IGNOREDMULTI = 8,
	UDP_MIB_MEMERRORS = 9,
	__UDP_MIB_MAX = 10,
};

enum {
	LINUX_MIB_XFRMNUM = 0,
	LINUX_MIB_XFRMINERROR = 1,
	LINUX_MIB_XFRMINBUFFERERROR = 2,
	LINUX_MIB_XFRMINHDRERROR = 3,
	LINUX_MIB_XFRMINNOSTATES = 4,
	LINUX_MIB_XFRMINSTATEPROTOERROR = 5,
	LINUX_MIB_XFRMINSTATEMODEERROR = 6,
	LINUX_MIB_XFRMINSTATESEQERROR = 7,
	LINUX_MIB_XFRMINSTATEEXPIRED = 8,
	LINUX_MIB_XFRMINSTATEMISMATCH = 9,
	LINUX_MIB_XFRMINSTATEINVALID = 10,
	LINUX_MIB_XFRMINTMPLMISMATCH = 11,
	LINUX_MIB_XFRMINNOPOLS = 12,
	LINUX_MIB_XFRMINPOLBLOCK = 13,
	LINUX_MIB_XFRMINPOLERROR = 14,
	LINUX_MIB_XFRMOUTERROR = 15,
	LINUX_MIB_XFRMOUTBUNDLEGENERROR = 16,
	LINUX_MIB_XFRMOUTBUNDLECHECKERROR = 17,
	LINUX_MIB_XFRMOUTNOSTATES = 18,
	LINUX_MIB_XFRMOUTSTATEPROTOERROR = 19,
	LINUX_MIB_XFRMOUTSTATEMODEERROR = 20,
	LINUX_MIB_XFRMOUTSTATESEQERROR = 21,
	LINUX_MIB_XFRMOUTSTATEEXPIRED = 22,
	LINUX_MIB_XFRMOUTPOLBLOCK = 23,
	LINUX_MIB_XFRMOUTPOLDEAD = 24,
	LINUX_MIB_XFRMOUTPOLERROR = 25,
	LINUX_MIB_XFRMFWDHDRERROR = 26,
	LINUX_MIB_XFRMOUTSTATEINVALID = 27,
	LINUX_MIB_XFRMACQUIREERROR = 28,
	__LINUX_MIB_XFRMMAX = 29,
};

enum {
	LINUX_MIB_TLSNUM = 0,
	LINUX_MIB_TLSCURRTXSW = 1,
	LINUX_MIB_TLSCURRRXSW = 2,
	LINUX_MIB_TLSCURRTXDEVICE = 3,
	LINUX_MIB_TLSCURRRXDEVICE = 4,
	LINUX_MIB_TLSTXSW = 5,
	LINUX_MIB_TLSRXSW = 6,
	LINUX_MIB_TLSTXDEVICE = 7,
	LINUX_MIB_TLSRXDEVICE = 8,
	LINUX_MIB_TLSDECRYPTERROR = 9,
	LINUX_MIB_TLSRXDEVICERESYNC = 10,
	LINUX_MIB_TLSDECRYPTRETRY = 11,
	LINUX_MIB_TLSRXNOPADVIOL = 12,
	__LINUX_MIB_TLSMAX = 13,
};

enum tcp_conntrack {
	TCP_CONNTRACK_NONE = 0,
	TCP_CONNTRACK_SYN_SENT = 1,
	TCP_CONNTRACK_SYN_RECV = 2,
	TCP_CONNTRACK_ESTABLISHED = 3,
	TCP_CONNTRACK_FIN_WAIT = 4,
	TCP_CONNTRACK_CLOSE_WAIT = 5,
	TCP_CONNTRACK_LAST_ACK = 6,
	TCP_CONNTRACK_TIME_WAIT = 7,
	TCP_CONNTRACK_CLOSE = 8,
	TCP_CONNTRACK_LISTEN = 9,
	TCP_CONNTRACK_MAX = 10,
	TCP_CONNTRACK_IGNORE = 11,
	TCP_CONNTRACK_RETRANS = 12,
	TCP_CONNTRACK_UNACK = 13,
	TCP_CONNTRACK_TIMEOUT_MAX = 14,
};

enum ct_dccp_states {
	CT_DCCP_NONE = 0,
	CT_DCCP_REQUEST = 1,
	CT_DCCP_RESPOND = 2,
	CT_DCCP_PARTOPEN = 3,
	CT_DCCP_OPEN = 4,
	CT_DCCP_CLOSEREQ = 5,
	CT_DCCP_CLOSING = 6,
	CT_DCCP_TIMEWAIT = 7,
	CT_DCCP_IGNORE = 8,
	CT_DCCP_INVALID = 9,
	__CT_DCCP_MAX = 10,
};

enum ip_conntrack_dir {
	IP_CT_DIR_ORIGINAL = 0,
	IP_CT_DIR_REPLY = 1,
	IP_CT_DIR_MAX = 2,
};

enum sctp_conntrack {
	SCTP_CONNTRACK_NONE = 0,
	SCTP_CONNTRACK_CLOSED = 1,
	SCTP_CONNTRACK_COOKIE_WAIT = 2,
	SCTP_CONNTRACK_COOKIE_ECHOED = 3,
	SCTP_CONNTRACK_ESTABLISHED = 4,
	SCTP_CONNTRACK_SHUTDOWN_SENT = 5,
	SCTP_CONNTRACK_SHUTDOWN_RECD = 6,
	SCTP_CONNTRACK_SHUTDOWN_ACK_SENT = 7,
	SCTP_CONNTRACK_HEARTBEAT_SENT = 8,
	SCTP_CONNTRACK_HEARTBEAT_ACKED = 9,
	SCTP_CONNTRACK_MAX = 10,
};

enum udp_conntrack {
	UDP_CT_UNREPLIED = 0,
	UDP_CT_REPLIED = 1,
	UDP_CT_MAX = 2,
};

enum gre_conntrack {
	GRE_CT_UNREPLIED = 0,
	GRE_CT_REPLIED = 1,
	GRE_CT_MAX = 2,
};

enum {
	XFRM_POLICY_IN = 0,
	XFRM_POLICY_OUT = 1,
	XFRM_POLICY_FWD = 2,
	XFRM_POLICY_MASK = 3,
	XFRM_POLICY_MAX = 3,
};

enum netns_bpf_attach_type {
	NETNS_BPF_INVALID = -1,
	NETNS_BPF_FLOW_DISSECTOR = 0,
	NETNS_BPF_SK_LOOKUP = 1,
	MAX_NETNS_BPF_ATTACH_TYPE = 2,
};

struct genlmsghdr {
	__u8 cmd;
	__u8 version;
	__u16 reserved;
};

struct genl_multicast_group {
	char name[16];
	u8 flags;
};

struct genl_split_ops;

struct genl_info;

struct genl_ops;

struct genl_small_ops;

struct genl_family {
	unsigned int hdrsize;
	char name[16];
	unsigned int version;
	unsigned int maxattr;
	u8 netnsok: 1;
	u8 parallel_ops: 1;
	u8 n_ops;
	u8 n_small_ops;
	u8 n_split_ops;
	u8 n_mcgrps;
	u8 resv_start_op;
	const struct nla_policy *policy;
	int (*pre_doit)(const struct genl_split_ops *, struct sk_buff *, struct genl_info *);
	void (*post_doit)(const struct genl_split_ops *, struct sk_buff *, struct genl_info *);
	int (*bind)(int);
	void (*unbind)(int);
	const struct genl_ops *ops;
	const struct genl_small_ops *small_ops;
	const struct genl_split_ops *split_ops;
	const struct genl_multicast_group *mcgrps;
	struct module *module;
	size_t sock_priv_size;
	void (*sock_priv_init)(void *);
	void (*sock_priv_destroy)(void *);
	int id;
	unsigned int mcgrp_offset;
	struct xarray *sock_privs;
};

struct genl_split_ops {
	union {
		struct {
			int (*pre_doit)(const struct genl_split_ops *, struct sk_buff *, struct genl_info *);
			int (*doit)(struct sk_buff *, struct genl_info *);
			void (*post_doit)(const struct genl_split_ops *, struct sk_buff *, struct genl_info *);
		};
		struct {
			int (*start)(struct netlink_callback *);
			int (*dumpit)(struct sk_buff *, struct netlink_callback *);
			int (*done)(struct netlink_callback *);
		};
	};
	const struct nla_policy *policy;
	unsigned int maxattr;
	u8 cmd;
	u8 internal_flags;
	u8 flags;
	u8 validate;
};

struct genl_info {
	u32 snd_seq;
	u32 snd_portid;
	const struct genl_family *family;
	const struct nlmsghdr *nlhdr;
	struct genlmsghdr *genlhdr;
	struct nlattr **attrs;
	possible_net_t _net;
	void *user_ptr[2];
	struct netlink_ext_ack *extack;
};

struct genl_ops {
	int (*doit)(struct sk_buff *, struct genl_info *);
	int (*start)(struct netlink_callback *);
	int (*dumpit)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	const struct nla_policy *policy;
	unsigned int maxattr;
	u8 cmd;
	u8 internal_flags;
	u8 flags;
	u8 validate;
};

struct genl_small_ops {
	int (*doit)(struct sk_buff *, struct genl_info *);
	int (*dumpit)(struct sk_buff *, struct netlink_callback *);
	u8 cmd;
	u8 internal_flags;
	u8 flags;
	u8 validate;
};

struct ethnl_req_info {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u32 flags;
};

struct ethnl_reply_data {
	struct net_device *dev;
};

struct ethnl_request_ops {
	u8 request_cmd;
	u8 reply_cmd;
	u16 hdr_attr;
	unsigned int req_info_size;
	unsigned int reply_data_size;
	bool allow_nodev_do;
	u8 set_ntf_cmd;
	int (*parse_request)(struct ethnl_req_info *, struct nlattr **, struct netlink_ext_ack *);
	int (*prepare_data)(const struct ethnl_req_info *, struct ethnl_reply_data *, const struct genl_info *);
	int (*reply_size)(const struct ethnl_req_info *, const struct ethnl_reply_data *);
	int (*fill_reply)(struct sk_buff *, const struct ethnl_req_info *, const struct ethnl_reply_data *);
	void (*cleanup_data)(struct ethnl_reply_data *);
	int (*set_validate)(struct ethnl_req_info *, struct genl_info *);
	int (*set)(struct ethnl_req_info *, struct genl_info *);
};

typedef const char (* const ethnl_string_array_t)[32];

struct tsinfo_reply_data {
	struct ethnl_reply_data base;
	struct ethtool_ts_info ts_info;
};

struct in6_pktinfo {
	struct in6_addr ipi6_addr;
	int ipi6_ifindex;
};

struct ipv6_rt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 type;
	__u8 segments_left;
};

struct ipv6_opt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
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
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct fastopen_queue {
	struct request_sock *rskq_rst_head;
	struct request_sock *rskq_rst_tail;
	spinlock_t lock;
	int qlen;
	int max_qlen;
	struct tcp_fastopen_context *ctx;
};

struct request_sock_queue {
	spinlock_t rskq_lock;
	u8 rskq_defer_accept;
	u32 synflood_warned;
	atomic_t qlen;
	atomic_t young;
	struct request_sock *rskq_accept_head;
	struct request_sock *rskq_accept_tail;
	struct fastopen_queue fastopenq;
};

struct ip_options {
	__be32 faddr;
	__be32 nexthop;
	unsigned char optlen;
	unsigned char srr;
	unsigned char rr;
	unsigned char ts;
	unsigned char is_strictroute: 1;
	unsigned char srr_is_hit: 1;
	unsigned char is_changed: 1;
	unsigned char rr_needaddr: 1;
	unsigned char ts_needtime: 1;
	unsigned char ts_needaddr: 1;
	unsigned char router_alert;
	unsigned char cipso;
	unsigned char __pad2;
	unsigned char __data[0];
};

struct ip_options_rcu {
	struct callback_head rcu;
	struct ip_options opt;
};

struct ipv6_txoptions {
	refcount_t refcnt;
	int tot_len;
	__u16 opt_flen;
	__u16 opt_nflen;
	struct ipv6_opt_hdr *hopopt;
	struct ipv6_opt_hdr *dst0opt;
	struct ipv6_rt_hdr *srcrt;
	struct ipv6_opt_hdr *dst1opt;
	struct callback_head rcu;
};

struct inet_cork {
	unsigned int flags;
	__be32 addr;
	struct ip_options *opt;
	unsigned int fragsize;
	int length;
	struct dst_entry *dst;
	u8 tx_flags;
	__u8 ttl;
	__s16 tos;
	char priority;
	__u16 gso_size;
	u64 transmit_time;
	u32 mark;
};

struct inet_cork_full {
	struct inet_cork base;
	struct flowi fl;
};

struct ipv6_pinfo;

struct ip_mc_socklist;

struct inet_sock {
	struct sock sk;
	struct ipv6_pinfo *pinet6;
	long unsigned int inet_flags;
	__be32 inet_saddr;
	__s16 uc_ttl;
	__be16 inet_sport;
	struct ip_options_rcu *inet_opt;
	atomic_t inet_id;
	__u8 tos;
	__u8 min_ttl;
	__u8 mc_ttl;
	__u8 pmtudisc;
	__u8 rcv_tos;
	__u8 convert_csum;
	int uc_index;
	int mc_index;
	__be32 mc_addr;
	u32 local_port_range;
	struct ip_mc_socklist *mc_list;
	struct inet_cork_full cork;
};

struct inet6_cork {
	struct ipv6_txoptions *opt;
	u8 hop_limit;
	u8 tclass;
};

struct ipv6_mc_socklist;

struct ipv6_ac_socklist;

struct ipv6_fl_socklist;

struct ipv6_pinfo {
	struct in6_addr saddr;
	struct in6_pktinfo sticky_pktinfo;
	const struct in6_addr *daddr_cache;
	const struct in6_addr *saddr_cache;
	__be32 flow_label;
	__u32 frag_size;
	s16 hop_limit;
	u8 mcast_hops;
	int ucast_oif;
	int mcast_oif;
	union {
		struct {
			__u16 srcrt: 1;
			__u16 osrcrt: 1;
			__u16 rxinfo: 1;
			__u16 rxoinfo: 1;
			__u16 rxhlim: 1;
			__u16 rxohlim: 1;
			__u16 hopopts: 1;
			__u16 ohopopts: 1;
			__u16 dstopts: 1;
			__u16 odstopts: 1;
			__u16 rxflow: 1;
			__u16 rxtclass: 1;
			__u16 rxpmtu: 1;
			__u16 rxorigdstaddr: 1;
			__u16 recvfragsize: 1;
		} bits;
		__u16 all;
	} rxopt;
	__u8 srcprefs;
	__u8 pmtudisc;
	__u8 min_hopcount;
	__u8 tclass;
	__be32 rcv_flowinfo;
	__u32 dst_cookie;
	struct ipv6_mc_socklist *ipv6_mc_list;
	struct ipv6_ac_socklist *ipv6_ac_list;
	struct ipv6_fl_socklist *ipv6_fl_list;
	struct ipv6_txoptions *opt;
	struct sk_buff *pktoptions;
	struct sk_buff *rxpmtu;
	struct inet6_cork cork;
};

enum {
	INET_FLAGS_PKTINFO = 0,
	INET_FLAGS_TTL = 1,
	INET_FLAGS_TOS = 2,
	INET_FLAGS_RECVOPTS = 3,
	INET_FLAGS_RETOPTS = 4,
	INET_FLAGS_PASSSEC = 5,
	INET_FLAGS_ORIGDSTADDR = 6,
	INET_FLAGS_CHECKSUM = 7,
	INET_FLAGS_RECVFRAGSIZE = 8,
	INET_FLAGS_RECVERR = 9,
	INET_FLAGS_RECVERR_RFC4884 = 10,
	INET_FLAGS_FREEBIND = 11,
	INET_FLAGS_HDRINCL = 12,
	INET_FLAGS_MC_LOOP = 13,
	INET_FLAGS_MC_ALL = 14,
	INET_FLAGS_TRANSPARENT = 15,
	INET_FLAGS_IS_ICSK = 16,
	INET_FLAGS_NODEFRAG = 17,
	INET_FLAGS_BIND_ADDRESS_NO_PORT = 18,
	INET_FLAGS_DEFER_CONNECT = 19,
	INET_FLAGS_MC6_LOOP = 20,
	INET_FLAGS_RECVERR6_RFC4884 = 21,
	INET_FLAGS_MC6_ALL = 22,
	INET_FLAGS_AUTOFLOWLABEL_SET = 23,
	INET_FLAGS_AUTOFLOWLABEL = 24,
	INET_FLAGS_DONTFRAG = 25,
	INET_FLAGS_RECVERR6 = 26,
	INET_FLAGS_REPFLOW = 27,
	INET_FLAGS_RTALERT_ISOLATE = 28,
	INET_FLAGS_SNDFLOW = 29,
	INET_FLAGS_RTALERT = 30,
};

struct inet_connection_sock_af_ops {
	int (*queue_xmit)(struct sock *, struct sk_buff *, struct flowi *);
	void (*send_check)(struct sock *, struct sk_buff *);
	int (*rebuild_header)(struct sock *);
	void (*sk_rx_dst_set)(struct sock *, const struct sk_buff *);
	int (*conn_request)(struct sock *, struct sk_buff *);
	struct sock * (*syn_recv_sock)(const struct sock *, struct sk_buff *, struct request_sock *, struct dst_entry *, struct request_sock *, bool *);
	u16 net_header_len;
	u16 sockaddr_len;
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*addr2sockaddr)(struct sock *, struct sockaddr *);
	void (*mtu_reduced)(struct sock *);
};

struct inet_bind_bucket;

struct inet_bind2_bucket;

struct tcp_ulp_ops;

struct inet_connection_sock {
	struct inet_sock icsk_inet;
	struct request_sock_queue icsk_accept_queue;
	struct inet_bind_bucket *icsk_bind_hash;
	struct inet_bind2_bucket *icsk_bind2_hash;
	long unsigned int icsk_timeout;
	struct timer_list icsk_retransmit_timer;
	struct timer_list icsk_delack_timer;
	__u32 icsk_rto;
	__u32 icsk_rto_min;
	__u32 icsk_delack_max;
	__u32 icsk_pmtu_cookie;
	const struct tcp_congestion_ops *icsk_ca_ops;
	const struct inet_connection_sock_af_ops *icsk_af_ops;
	const struct tcp_ulp_ops *icsk_ulp_ops;
	void *icsk_ulp_data;
	void (*icsk_clean_acked)(struct sock *, u32);
	unsigned int (*icsk_sync_mss)(struct sock *, u32);
	__u8 icsk_ca_state: 5;
	__u8 icsk_ca_initialized: 1;
	__u8 icsk_ca_setsockopt: 1;
	__u8 icsk_ca_dst_locked: 1;
	__u8 icsk_retransmits;
	__u8 icsk_pending;
	__u8 icsk_backoff;
	__u8 icsk_syn_retries;
	__u8 icsk_probes_out;
	__u16 icsk_ext_hdr_len;
	struct {
		__u8 pending;
		__u8 quick;
		__u8 pingpong;
		__u8 retry;
		__u32 ato: 8;
		__u32 lrcv_flowlabel: 20;
		__u32 unused: 4;
		long unsigned int timeout;
		__u32 lrcvtime;
		__u16 last_seg_size;
		__u16 rcv_mss;
	} icsk_ack;
	struct {
		int search_high;
		int search_low;
		u32 probe_size: 31;
		u32 enabled: 1;
		u32 probe_timestamp;
	} icsk_mtup;
	u32 icsk_probes_tstamp;
	u32 icsk_user_timeout;
	u64 icsk_ca_priv[13];
};

struct inet_bind_bucket {
	possible_net_t ib_net;
	int l3mdev;
	short unsigned int port;
	signed char fastreuse;
	signed char fastreuseport;
	kuid_t fastuid;
	struct in6_addr fast_v6_rcv_saddr;
	__be32 fast_rcv_saddr;
	short unsigned int fast_sk_family;
	bool fast_ipv6_only;
	struct hlist_node node;
	struct hlist_head bhash2;
};

struct inet_bind2_bucket {
	possible_net_t ib_net;
	int l3mdev;
	short unsigned int port;
	short unsigned int addr_type;
	struct in6_addr v6_rcv_saddr;
	struct hlist_node node;
	struct hlist_node bhash_node;
	struct hlist_head owners;
};

struct tcp_ulp_ops {
	struct list_head list;
	int (*init)(struct sock *);
	void (*update)(struct sock *, struct proto *, void (*)(struct sock *));
	void (*release)(struct sock *);
	int (*get_info)(struct sock *, struct sk_buff *);
	size_t (*get_info_size)(const struct sock *);
	void (*clone)(const struct request_sock *, struct sock *, const gfp_t);
	char name[16];
	struct module *owner;
};

struct inet_timewait_sock {
	struct sock_common __tw_common;
	__u32 tw_mark;
	volatile unsigned char tw_substate;
	unsigned char tw_rcv_wscale;
	__be16 tw_sport;
	unsigned int tw_transparent: 1;
	unsigned int tw_flowlabel: 20;
	unsigned int tw_usec_ts: 1;
	unsigned int tw_pad: 2;
	unsigned int tw_tos: 8;
	u32 tw_txhash;
	u32 tw_priority;
	struct timer_list tw_timer;
	struct inet_bind_bucket *tw_tb;
	struct inet_bind2_bucket *tw_tb2;
};

struct ip6_sf_socklist;

struct ipv6_mc_socklist {
	struct in6_addr addr;
	int ifindex;
	unsigned int sfmode;
	struct ipv6_mc_socklist *next;
	struct ip6_sf_socklist *sflist;
	struct callback_head rcu;
};

struct ipv6_ac_socklist {
	struct in6_addr acl_addr;
	int acl_ifindex;
	struct ipv6_ac_socklist *acl_next;
};

struct ip6_flowlabel;

struct ipv6_fl_socklist {
	struct ipv6_fl_socklist *next;
	struct ip6_flowlabel *fl;
	struct callback_head rcu;
};

struct ip6_sf_socklist {
	unsigned int sl_max;
	unsigned int sl_count;
	struct callback_head rcu;
	struct in6_addr sl_addr[0];
};

struct ip6_flowlabel {
	struct ip6_flowlabel *next;
	__be32 label;
	atomic_t users;
	struct in6_addr dst;
	struct ipv6_txoptions *opt;
	long unsigned int linger;
	struct callback_head rcu;
	u8 share;
	union {
		struct pid *pid;
		kuid_t uid;
	} owner;
	long unsigned int lastuse;
	long unsigned int expires;
	struct net *fl_net;
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

struct tcp_fastopen_context {
	siphash_key_t key[2];
	int num;
	struct callback_head rcu;
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
	struct bpf_prog *prog;
	struct sock *socks[0];
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
	long int interval_us;
	u32 snd_interval_us;
	u32 rcv_interval_us;
	long int rtt_us;
	int losses;
	u32 acked_sacked;
	u32 prior_in_flight;
	u32 last_end_seq;
	bool is_app_limited;
	bool is_retrans;
	bool is_ack_delayed;
};

struct xfrm_user_sec_ctx {
	__u16 len;
	__u16 exttype;
	__u8 ctx_alg;
	__u8 ctx_doi;
	__u16 ctx_len;
};

enum xfrm_ae_ftype_t {
	XFRM_AE_UNSPEC = 0,
	XFRM_AE_RTHR = 1,
	XFRM_AE_RVAL = 2,
	XFRM_AE_LVAL = 4,
	XFRM_AE_ETHR = 8,
	XFRM_AE_CR = 16,
	XFRM_AE_CE = 32,
	XFRM_AE_CU = 64,
	__XFRM_AE_MAX = 65,
};

enum xfrm_nlgroups {
	XFRMNLGRP_NONE = 0,
	XFRMNLGRP_ACQUIRE = 1,
	XFRMNLGRP_EXPIRE = 2,
	XFRMNLGRP_SA = 3,
	XFRMNLGRP_POLICY = 4,
	XFRMNLGRP_AEVENTS = 5,
	XFRMNLGRP_REPORT = 6,
	XFRMNLGRP_MIGRATE = 7,
	XFRMNLGRP_MAPPING = 8,
	__XFRMNLGRP_MAX = 9,
};

enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_L2TP = 115,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_RAW = 255,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};

struct ipv6hdr {
	__u8 version: 4;
	__u8 priority: 4;
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	union {
		struct {
			struct in6_addr saddr;
			struct in6_addr daddr;
		};
		struct {
			struct in6_addr saddr;
			struct in6_addr daddr;
		} addrs;
	};
};

enum {
	XFRM_DEV_OFFLOAD_UNSPECIFIED = 0,
	XFRM_DEV_OFFLOAD_CRYPTO = 1,
	XFRM_DEV_OFFLOAD_PACKET = 2,
};

enum {
	XFRM_DEV_OFFLOAD_FLAG_ACQ = 1,
};

enum {
	XFRM_MODE_FLAG_TUNNEL = 1,
};

enum {
	XFRM_STATE_VOID = 0,
	XFRM_STATE_ACQ = 1,
	XFRM_STATE_VALID = 2,
	XFRM_STATE_ERROR = 3,
	XFRM_STATE_EXPIRED = 4,
	XFRM_STATE_DEAD = 5,
};

struct km_event {
	union {
		u32 hard;
		u32 proto;
		u32 byid;
		u32 aevent;
		u32 type;
	} data;
	u32 seq;
	u32 portid;
	u32 event;
	struct net *net;
};

struct xfrm_state_afinfo {
	u8 family;
	u8 proto;
	const struct xfrm_type_offload *type_offload_esp;
	const struct xfrm_type *type_esp;
	const struct xfrm_type *type_ipip;
	const struct xfrm_type *type_ipip6;
	const struct xfrm_type *type_comp;
	const struct xfrm_type *type_ah;
	const struct xfrm_type *type_routing;
	const struct xfrm_type *type_dstopts;
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	int (*transport_finish)(struct sk_buff *, int);
	void (*local_error)(struct sk_buff *, u32);
};

struct xfrm_kmaddress {
	xfrm_address_t local;
	xfrm_address_t remote;
	u32 reserved;
	u16 family;
};

struct xfrm_migrate {
	xfrm_address_t old_daddr;
	xfrm_address_t old_saddr;
	xfrm_address_t new_daddr;
	xfrm_address_t new_saddr;
	u8 proto;
	u8 mode;
	u16 reserved;
	u32 reqid;
	u16 old_family;
	u16 new_family;
};

struct xfrm_mgr {
	struct list_head list;
	int (*notify)(struct xfrm_state *, const struct km_event *);
	int (*acquire)(struct xfrm_state *, struct xfrm_tmpl *, struct xfrm_policy *);
	struct xfrm_policy * (*compile_policy)(struct sock *, int, u8 *, int, int *);
	int (*new_mapping)(struct xfrm_state *, xfrm_address_t *, __be16);
	int (*notify_policy)(struct xfrm_policy *, int, const struct km_event *);
	int (*report)(struct net *, u8, struct xfrm_selector *, xfrm_address_t *);
	int (*migrate)(const struct xfrm_selector *, u8, u8, const struct xfrm_migrate *, int, const struct xfrm_kmaddress *, const struct xfrm_encap_tmpl *);
	bool (*is_alive)(const struct km_event *);
};

struct xfrmk_sadinfo {
	u32 sadhcnt;
	u32 sadhmcnt;
	u32 sadcnt;
};

struct xfrm_translator {
	int (*alloc_compat)(struct sk_buff *, const struct nlmsghdr *);
	struct nlmsghdr * (*rcv_msg_compat)(const struct nlmsghdr *, int, const struct nla_policy *, struct netlink_ext_ack *);
	int (*xlate_user_policy_sockptr)(u8 **, int);
	struct module *owner;
};

struct crypto_aead {
	unsigned int authsize;
	unsigned int reqsize;
	struct crypto_tfm base;
};

typedef u32 u_int32_t;

struct flow_dissector_key_control {
	u16 thoff;
	u16 addr_type;
	u32 flags;
};

struct flow_dissector_key_basic {
	__be16 n_proto;
	u8 ip_proto;
	u8 padding;
};

struct flow_dissector_key_tags {
	u32 flow_label;
};

struct flow_dissector_key_vlan {
	union {
		struct {
			u16 vlan_id: 12;
			u16 vlan_dei: 1;
			u16 vlan_priority: 3;
		};
		__be16 vlan_tci;
	};
	__be16 vlan_tpid;
	__be16 vlan_eth_type;
	u16 padding;
};

struct flow_dissector_key_keyid {
	__be32 keyid;
};

struct flow_dissector_key_ipv4_addrs {
	__be32 src;
	__be32 dst;
};

struct flow_dissector_key_ipv6_addrs {
	struct in6_addr src;
	struct in6_addr dst;
};

struct flow_dissector_key_tipc {
	__be32 key;
};

struct flow_dissector_key_addrs {
	union {
		struct flow_dissector_key_ipv4_addrs v4addrs;
		struct flow_dissector_key_ipv6_addrs v6addrs;
		struct flow_dissector_key_tipc tipckey;
	};
};

struct flow_dissector_key_ports {
	union {
		__be32 ports;
		struct {
			__be16 src;
			__be16 dst;
		};
	};
};

struct flow_dissector_key_icmp {
	struct {
		u8 type;
		u8 code;
	};
	u16 id;
};

struct flow_dissector {
	long long unsigned int used_keys;
	short unsigned int offset[33];
};

struct flow_keys {
	struct flow_dissector_key_control control;
	struct flow_dissector_key_basic basic;
	struct flow_dissector_key_tags tags;
	struct flow_dissector_key_vlan vlan;
	struct flow_dissector_key_vlan cvlan;
	struct flow_dissector_key_keyid keyid;
	struct flow_dissector_key_ports ports;
	struct flow_dissector_key_icmp icmp;
	struct flow_dissector_key_addrs addrs;
	long: 0;
};

struct ip6_fraglist_iter {
	struct ipv6hdr *tmp_hdr;
	struct sk_buff *frag;
	int offset;
	unsigned int hlen;
	__be32 frag_id;
	u8 nexthdr;
};

struct ip6_frag_state {
	u8 *prevhdr;
	unsigned int hlen;
	unsigned int mtu;
	unsigned int left;
	int offset;
	int ptr;
	int hroom;
	int troom;
	__be32 frag_id;
	u8 nexthdr;
};

struct ip6_rt_info {
	struct in6_addr daddr;
	struct in6_addr saddr;
	u_int32_t mark;
};

struct nf_queue_entry;

struct nf_ipv6_ops {
	void (*route_input)(struct sk_buff *);
	int (*fragment)(struct net *, struct sock *, struct sk_buff *, int (*)(struct net *, struct sock *, struct sk_buff *));
	int (*reroute)(struct sk_buff *, const struct nf_queue_entry *);
};

struct nf_queue_entry {
	struct list_head list;
	struct sk_buff *skb;
	unsigned int id;
	unsigned int hook_index;
	struct net_device *physin;
	struct net_device *physout;
	struct nf_hook_state state;
	u16 size;
};

enum {
	BR_MCAST_DIR_RX = 0,
	BR_MCAST_DIR_TX = 1,
	BR_MCAST_DIR_SIZE = 2,
};

struct br_input_skb_cb {
	struct net_device *brdev;
	u16 frag_max_size;
	u8 igmp;
	u8 mrouters_only: 1;
	u8 proxyarp_replied: 1;
	u8 src_port_isolated: 1;
	u8 promisc: 1;
	u8 vlan_filtered: 1;
	u8 br_netfilter_broute: 1;
	u8 tx_fwd_offload: 1;
	int src_hwdom;
	long unsigned int fwd_hwdoms;
	u32 backup_nhid;
};

struct nf_bridge_frag_data;

enum devlink_command {
	DEVLINK_CMD_UNSPEC = 0,
	DEVLINK_CMD_GET = 1,
	DEVLINK_CMD_SET = 2,
	DEVLINK_CMD_NEW = 3,
	DEVLINK_CMD_DEL = 4,
	DEVLINK_CMD_PORT_GET = 5,
	DEVLINK_CMD_PORT_SET = 6,
	DEVLINK_CMD_PORT_NEW = 7,
	DEVLINK_CMD_PORT_DEL = 8,
	DEVLINK_CMD_PORT_SPLIT = 9,
	DEVLINK_CMD_PORT_UNSPLIT = 10,
	DEVLINK_CMD_SB_GET = 11,
	DEVLINK_CMD_SB_SET = 12,
	DEVLINK_CMD_SB_NEW = 13,
	DEVLINK_CMD_SB_DEL = 14,
	DEVLINK_CMD_SB_POOL_GET = 15,
	DEVLINK_CMD_SB_POOL_SET = 16,
	DEVLINK_CMD_SB_POOL_NEW = 17,
	DEVLINK_CMD_SB_POOL_DEL = 18,
	DEVLINK_CMD_SB_PORT_POOL_GET = 19,
	DEVLINK_CMD_SB_PORT_POOL_SET = 20,
	DEVLINK_CMD_SB_PORT_POOL_NEW = 21,
	DEVLINK_CMD_SB_PORT_POOL_DEL = 22,
	DEVLINK_CMD_SB_TC_POOL_BIND_GET = 23,
	DEVLINK_CMD_SB_TC_POOL_BIND_SET = 24,
	DEVLINK_CMD_SB_TC_POOL_BIND_NEW = 25,
	DEVLINK_CMD_SB_TC_POOL_BIND_DEL = 26,
	DEVLINK_CMD_SB_OCC_SNAPSHOT = 27,
	DEVLINK_CMD_SB_OCC_MAX_CLEAR = 28,
	DEVLINK_CMD_ESWITCH_GET = 29,
	DEVLINK_CMD_ESWITCH_SET = 30,
	DEVLINK_CMD_DPIPE_TABLE_GET = 31,
	DEVLINK_CMD_DPIPE_ENTRIES_GET = 32,
	DEVLINK_CMD_DPIPE_HEADERS_GET = 33,
	DEVLINK_CMD_DPIPE_TABLE_COUNTERS_SET = 34,
	DEVLINK_CMD_RESOURCE_SET = 35,
	DEVLINK_CMD_RESOURCE_DUMP = 36,
	DEVLINK_CMD_RELOAD = 37,
	DEVLINK_CMD_PARAM_GET = 38,
	DEVLINK_CMD_PARAM_SET = 39,
	DEVLINK_CMD_PARAM_NEW = 40,
	DEVLINK_CMD_PARAM_DEL = 41,
	DEVLINK_CMD_REGION_GET = 42,
	DEVLINK_CMD_REGION_SET = 43,
	DEVLINK_CMD_REGION_NEW = 44,
	DEVLINK_CMD_REGION_DEL = 45,
	DEVLINK_CMD_REGION_READ = 46,
	DEVLINK_CMD_PORT_PARAM_GET = 47,
	DEVLINK_CMD_PORT_PARAM_SET = 48,
	DEVLINK_CMD_PORT_PARAM_NEW = 49,
	DEVLINK_CMD_PORT_PARAM_DEL = 50,
	DEVLINK_CMD_INFO_GET = 51,
	DEVLINK_CMD_HEALTH_REPORTER_GET = 52,
	DEVLINK_CMD_HEALTH_REPORTER_SET = 53,
	DEVLINK_CMD_HEALTH_REPORTER_RECOVER = 54,
	DEVLINK_CMD_HEALTH_REPORTER_DIAGNOSE = 55,
	DEVLINK_CMD_HEALTH_REPORTER_DUMP_GET = 56,
	DEVLINK_CMD_HEALTH_REPORTER_DUMP_CLEAR = 57,
	DEVLINK_CMD_FLASH_UPDATE = 58,
	DEVLINK_CMD_FLASH_UPDATE_END = 59,
	DEVLINK_CMD_FLASH_UPDATE_STATUS = 60,
	DEVLINK_CMD_TRAP_GET = 61,
	DEVLINK_CMD_TRAP_SET = 62,
	DEVLINK_CMD_TRAP_NEW = 63,
	DEVLINK_CMD_TRAP_DEL = 64,
	DEVLINK_CMD_TRAP_GROUP_GET = 65,
	DEVLINK_CMD_TRAP_GROUP_SET = 66,
	DEVLINK_CMD_TRAP_GROUP_NEW = 67,
	DEVLINK_CMD_TRAP_GROUP_DEL = 68,
	DEVLINK_CMD_TRAP_POLICER_GET = 69,
	DEVLINK_CMD_TRAP_POLICER_SET = 70,
	DEVLINK_CMD_TRAP_POLICER_NEW = 71,
	DEVLINK_CMD_TRAP_POLICER_DEL = 72,
	DEVLINK_CMD_HEALTH_REPORTER_TEST = 73,
	DEVLINK_CMD_RATE_GET = 74,
	DEVLINK_CMD_RATE_SET = 75,
	DEVLINK_CMD_RATE_NEW = 76,
	DEVLINK_CMD_RATE_DEL = 77,
	DEVLINK_CMD_LINECARD_GET = 78,
	DEVLINK_CMD_LINECARD_SET = 79,
	DEVLINK_CMD_LINECARD_NEW = 80,
	DEVLINK_CMD_LINECARD_DEL = 81,
	DEVLINK_CMD_SELFTESTS_GET = 82,
	DEVLINK_CMD_SELFTESTS_RUN = 83,
	DEVLINK_CMD_NOTIFY_FILTER_SET = 84,
	__DEVLINK_CMD_MAX = 85,
	DEVLINK_CMD_MAX = 84,
};

enum devlink_sb_pool_type {
	DEVLINK_SB_POOL_TYPE_INGRESS = 0,
	DEVLINK_SB_POOL_TYPE_EGRESS = 1,
};

enum devlink_sb_threshold_type {
	DEVLINK_SB_THRESHOLD_TYPE_STATIC = 0,
	DEVLINK_SB_THRESHOLD_TYPE_DYNAMIC = 1,
};

enum devlink_eswitch_encap_mode {
	DEVLINK_ESWITCH_ENCAP_MODE_NONE = 0,
	DEVLINK_ESWITCH_ENCAP_MODE_BASIC = 1,
};

enum devlink_attr_selftest_id {
	DEVLINK_ATTR_SELFTEST_ID_UNSPEC = 0,
	DEVLINK_ATTR_SELFTEST_ID_FLASH = 1,
	__DEVLINK_ATTR_SELFTEST_ID_MAX = 2,
	DEVLINK_ATTR_SELFTEST_ID_MAX = 1,
};

enum devlink_selftest_status {
	DEVLINK_SELFTEST_STATUS_SKIP = 0,
	DEVLINK_SELFTEST_STATUS_PASS = 1,
	DEVLINK_SELFTEST_STATUS_FAIL = 2,
};

enum devlink_trap_action {
	DEVLINK_TRAP_ACTION_DROP = 0,
	DEVLINK_TRAP_ACTION_TRAP = 1,
	DEVLINK_TRAP_ACTION_MIRROR = 2,
};

enum devlink_trap_type {
	DEVLINK_TRAP_TYPE_DROP = 0,
	DEVLINK_TRAP_TYPE_EXCEPTION = 1,
	DEVLINK_TRAP_TYPE_CONTROL = 2,
};

enum devlink_reload_action {
	DEVLINK_RELOAD_ACTION_UNSPEC = 0,
	DEVLINK_RELOAD_ACTION_DRIVER_REINIT = 1,
	DEVLINK_RELOAD_ACTION_FW_ACTIVATE = 2,
	__DEVLINK_RELOAD_ACTION_MAX = 3,
	DEVLINK_RELOAD_ACTION_MAX = 2,
};

enum devlink_reload_limit {
	DEVLINK_RELOAD_LIMIT_UNSPEC = 0,
	DEVLINK_RELOAD_LIMIT_NO_RESET = 1,
	__DEVLINK_RELOAD_LIMIT_MAX = 2,
	DEVLINK_RELOAD_LIMIT_MAX = 1,
};

enum devlink_attr {
	DEVLINK_ATTR_UNSPEC = 0,
	DEVLINK_ATTR_BUS_NAME = 1,
	DEVLINK_ATTR_DEV_NAME = 2,
	DEVLINK_ATTR_PORT_INDEX = 3,
	DEVLINK_ATTR_PORT_TYPE = 4,
	DEVLINK_ATTR_PORT_DESIRED_TYPE = 5,
	DEVLINK_ATTR_PORT_NETDEV_IFINDEX = 6,
	DEVLINK_ATTR_PORT_NETDEV_NAME = 7,
	DEVLINK_ATTR_PORT_IBDEV_NAME = 8,
	DEVLINK_ATTR_PORT_SPLIT_COUNT = 9,
	DEVLINK_ATTR_PORT_SPLIT_GROUP = 10,
	DEVLINK_ATTR_SB_INDEX = 11,
	DEVLINK_ATTR_SB_SIZE = 12,
	DEVLINK_ATTR_SB_INGRESS_POOL_COUNT = 13,
	DEVLINK_ATTR_SB_EGRESS_POOL_COUNT = 14,
	DEVLINK_ATTR_SB_INGRESS_TC_COUNT = 15,
	DEVLINK_ATTR_SB_EGRESS_TC_COUNT = 16,
	DEVLINK_ATTR_SB_POOL_INDEX = 17,
	DEVLINK_ATTR_SB_POOL_TYPE = 18,
	DEVLINK_ATTR_SB_POOL_SIZE = 19,
	DEVLINK_ATTR_SB_POOL_THRESHOLD_TYPE = 20,
	DEVLINK_ATTR_SB_THRESHOLD = 21,
	DEVLINK_ATTR_SB_TC_INDEX = 22,
	DEVLINK_ATTR_SB_OCC_CUR = 23,
	DEVLINK_ATTR_SB_OCC_MAX = 24,
	DEVLINK_ATTR_ESWITCH_MODE = 25,
	DEVLINK_ATTR_ESWITCH_INLINE_MODE = 26,
	DEVLINK_ATTR_DPIPE_TABLES = 27,
	DEVLINK_ATTR_DPIPE_TABLE = 28,
	DEVLINK_ATTR_DPIPE_TABLE_NAME = 29,
	DEVLINK_ATTR_DPIPE_TABLE_SIZE = 30,
	DEVLINK_ATTR_DPIPE_TABLE_MATCHES = 31,
	DEVLINK_ATTR_DPIPE_TABLE_ACTIONS = 32,
	DEVLINK_ATTR_DPIPE_TABLE_COUNTERS_ENABLED = 33,
	DEVLINK_ATTR_DPIPE_ENTRIES = 34,
	DEVLINK_ATTR_DPIPE_ENTRY = 35,
	DEVLINK_ATTR_DPIPE_ENTRY_INDEX = 36,
	DEVLINK_ATTR_DPIPE_ENTRY_MATCH_VALUES = 37,
	DEVLINK_ATTR_DPIPE_ENTRY_ACTION_VALUES = 38,
	DEVLINK_ATTR_DPIPE_ENTRY_COUNTER = 39,
	DEVLINK_ATTR_DPIPE_MATCH = 40,
	DEVLINK_ATTR_DPIPE_MATCH_VALUE = 41,
	DEVLINK_ATTR_DPIPE_MATCH_TYPE = 42,
	DEVLINK_ATTR_DPIPE_ACTION = 43,
	DEVLINK_ATTR_DPIPE_ACTION_VALUE = 44,
	DEVLINK_ATTR_DPIPE_ACTION_TYPE = 45,
	DEVLINK_ATTR_DPIPE_VALUE = 46,
	DEVLINK_ATTR_DPIPE_VALUE_MASK = 47,
	DEVLINK_ATTR_DPIPE_VALUE_MAPPING = 48,
	DEVLINK_ATTR_DPIPE_HEADERS = 49,
	DEVLINK_ATTR_DPIPE_HEADER = 50,
	DEVLINK_ATTR_DPIPE_HEADER_NAME = 51,
	DEVLINK_ATTR_DPIPE_HEADER_ID = 52,
	DEVLINK_ATTR_DPIPE_HEADER_FIELDS = 53,
	DEVLINK_ATTR_DPIPE_HEADER_GLOBAL = 54,
	DEVLINK_ATTR_DPIPE_HEADER_INDEX = 55,
	DEVLINK_ATTR_DPIPE_FIELD = 56,
	DEVLINK_ATTR_DPIPE_FIELD_NAME = 57,
	DEVLINK_ATTR_DPIPE_FIELD_ID = 58,
	DEVLINK_ATTR_DPIPE_FIELD_BITWIDTH = 59,
	DEVLINK_ATTR_DPIPE_FIELD_MAPPING_TYPE = 60,
	DEVLINK_ATTR_PAD = 61,
	DEVLINK_ATTR_ESWITCH_ENCAP_MODE = 62,
	DEVLINK_ATTR_RESOURCE_LIST = 63,
	DEVLINK_ATTR_RESOURCE = 64,
	DEVLINK_ATTR_RESOURCE_NAME = 65,
	DEVLINK_ATTR_RESOURCE_ID = 66,
	DEVLINK_ATTR_RESOURCE_SIZE = 67,
	DEVLINK_ATTR_RESOURCE_SIZE_NEW = 68,
	DEVLINK_ATTR_RESOURCE_SIZE_VALID = 69,
	DEVLINK_ATTR_RESOURCE_SIZE_MIN = 70,
	DEVLINK_ATTR_RESOURCE_SIZE_MAX = 71,
	DEVLINK_ATTR_RESOURCE_SIZE_GRAN = 72,
	DEVLINK_ATTR_RESOURCE_UNIT = 73,
	DEVLINK_ATTR_RESOURCE_OCC = 74,
	DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_ID = 75,
	DEVLINK_ATTR_DPIPE_TABLE_RESOURCE_UNITS = 76,
	DEVLINK_ATTR_PORT_FLAVOUR = 77,
	DEVLINK_ATTR_PORT_NUMBER = 78,
	DEVLINK_ATTR_PORT_SPLIT_SUBPORT_NUMBER = 79,
	DEVLINK_ATTR_PARAM = 80,
	DEVLINK_ATTR_PARAM_NAME = 81,
	DEVLINK_ATTR_PARAM_GENERIC = 82,
	DEVLINK_ATTR_PARAM_TYPE = 83,
	DEVLINK_ATTR_PARAM_VALUES_LIST = 84,
	DEVLINK_ATTR_PARAM_VALUE = 85,
	DEVLINK_ATTR_PARAM_VALUE_DATA = 86,
	DEVLINK_ATTR_PARAM_VALUE_CMODE = 87,
	DEVLINK_ATTR_REGION_NAME = 88,
	DEVLINK_ATTR_REGION_SIZE = 89,
	DEVLINK_ATTR_REGION_SNAPSHOTS = 90,
	DEVLINK_ATTR_REGION_SNAPSHOT = 91,
	DEVLINK_ATTR_REGION_SNAPSHOT_ID = 92,
	DEVLINK_ATTR_REGION_CHUNKS = 93,
	DEVLINK_ATTR_REGION_CHUNK = 94,
	DEVLINK_ATTR_REGION_CHUNK_DATA = 95,
	DEVLINK_ATTR_REGION_CHUNK_ADDR = 96,
	DEVLINK_ATTR_REGION_CHUNK_LEN = 97,
	DEVLINK_ATTR_INFO_DRIVER_NAME = 98,
	DEVLINK_ATTR_INFO_SERIAL_NUMBER = 99,
	DEVLINK_ATTR_INFO_VERSION_FIXED = 100,
	DEVLINK_ATTR_INFO_VERSION_RUNNING = 101,
	DEVLINK_ATTR_INFO_VERSION_STORED = 102,
	DEVLINK_ATTR_INFO_VERSION_NAME = 103,
	DEVLINK_ATTR_INFO_VERSION_VALUE = 104,
	DEVLINK_ATTR_SB_POOL_CELL_SIZE = 105,
	DEVLINK_ATTR_FMSG = 106,
	DEVLINK_ATTR_FMSG_OBJ_NEST_START = 107,
	DEVLINK_ATTR_FMSG_PAIR_NEST_START = 108,
	DEVLINK_ATTR_FMSG_ARR_NEST_START = 109,
	DEVLINK_ATTR_FMSG_NEST_END = 110,
	DEVLINK_ATTR_FMSG_OBJ_NAME = 111,
	DEVLINK_ATTR_FMSG_OBJ_VALUE_TYPE = 112,
	DEVLINK_ATTR_FMSG_OBJ_VALUE_DATA = 113,
	DEVLINK_ATTR_HEALTH_REPORTER = 114,
	DEVLINK_ATTR_HEALTH_REPORTER_NAME = 115,
	DEVLINK_ATTR_HEALTH_REPORTER_STATE = 116,
	DEVLINK_ATTR_HEALTH_REPORTER_ERR_COUNT = 117,
	DEVLINK_ATTR_HEALTH_REPORTER_RECOVER_COUNT = 118,
	DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS = 119,
	DEVLINK_ATTR_HEALTH_REPORTER_GRACEFUL_PERIOD = 120,
	DEVLINK_ATTR_HEALTH_REPORTER_AUTO_RECOVER = 121,
	DEVLINK_ATTR_FLASH_UPDATE_FILE_NAME = 122,
	DEVLINK_ATTR_FLASH_UPDATE_COMPONENT = 123,
	DEVLINK_ATTR_FLASH_UPDATE_STATUS_MSG = 124,
	DEVLINK_ATTR_FLASH_UPDATE_STATUS_DONE = 125,
	DEVLINK_ATTR_FLASH_UPDATE_STATUS_TOTAL = 126,
	DEVLINK_ATTR_PORT_PCI_PF_NUMBER = 127,
	DEVLINK_ATTR_PORT_PCI_VF_NUMBER = 128,
	DEVLINK_ATTR_STATS = 129,
	DEVLINK_ATTR_TRAP_NAME = 130,
	DEVLINK_ATTR_TRAP_ACTION = 131,
	DEVLINK_ATTR_TRAP_TYPE = 132,
	DEVLINK_ATTR_TRAP_GENERIC = 133,
	DEVLINK_ATTR_TRAP_METADATA = 134,
	DEVLINK_ATTR_TRAP_GROUP_NAME = 135,
	DEVLINK_ATTR_RELOAD_FAILED = 136,
	DEVLINK_ATTR_HEALTH_REPORTER_DUMP_TS_NS = 137,
	DEVLINK_ATTR_NETNS_FD = 138,
	DEVLINK_ATTR_NETNS_PID = 139,
	DEVLINK_ATTR_NETNS_ID = 140,
	DEVLINK_ATTR_HEALTH_REPORTER_AUTO_DUMP = 141,
	DEVLINK_ATTR_TRAP_POLICER_ID = 142,
	DEVLINK_ATTR_TRAP_POLICER_RATE = 143,
	DEVLINK_ATTR_TRAP_POLICER_BURST = 144,
	DEVLINK_ATTR_PORT_FUNCTION = 145,
	DEVLINK_ATTR_INFO_BOARD_SERIAL_NUMBER = 146,
	DEVLINK_ATTR_PORT_LANES = 147,
	DEVLINK_ATTR_PORT_SPLITTABLE = 148,
	DEVLINK_ATTR_PORT_EXTERNAL = 149,
	DEVLINK_ATTR_PORT_CONTROLLER_NUMBER = 150,
	DEVLINK_ATTR_FLASH_UPDATE_STATUS_TIMEOUT = 151,
	DEVLINK_ATTR_FLASH_UPDATE_OVERWRITE_MASK = 152,
	DEVLINK_ATTR_RELOAD_ACTION = 153,
	DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED = 154,
	DEVLINK_ATTR_RELOAD_LIMITS = 155,
	DEVLINK_ATTR_DEV_STATS = 156,
	DEVLINK_ATTR_RELOAD_STATS = 157,
	DEVLINK_ATTR_RELOAD_STATS_ENTRY = 158,
	DEVLINK_ATTR_RELOAD_STATS_LIMIT = 159,
	DEVLINK_ATTR_RELOAD_STATS_VALUE = 160,
	DEVLINK_ATTR_REMOTE_RELOAD_STATS = 161,
	DEVLINK_ATTR_RELOAD_ACTION_INFO = 162,
	DEVLINK_ATTR_RELOAD_ACTION_STATS = 163,
	DEVLINK_ATTR_PORT_PCI_SF_NUMBER = 164,
	DEVLINK_ATTR_RATE_TYPE = 165,
	DEVLINK_ATTR_RATE_TX_SHARE = 166,
	DEVLINK_ATTR_RATE_TX_MAX = 167,
	DEVLINK_ATTR_RATE_NODE_NAME = 168,
	DEVLINK_ATTR_RATE_PARENT_NODE_NAME = 169,
	DEVLINK_ATTR_REGION_MAX_SNAPSHOTS = 170,
	DEVLINK_ATTR_LINECARD_INDEX = 171,
	DEVLINK_ATTR_LINECARD_STATE = 172,
	DEVLINK_ATTR_LINECARD_TYPE = 173,
	DEVLINK_ATTR_LINECARD_SUPPORTED_TYPES = 174,
	DEVLINK_ATTR_NESTED_DEVLINK = 175,
	DEVLINK_ATTR_SELFTESTS = 176,
	DEVLINK_ATTR_RATE_TX_PRIORITY = 177,
	DEVLINK_ATTR_RATE_TX_WEIGHT = 178,
	DEVLINK_ATTR_REGION_DIRECT = 179,
	__DEVLINK_ATTR_MAX = 180,
	DEVLINK_ATTR_MAX = 179,
};

enum devlink_dpipe_field_mapping_type {
	DEVLINK_DPIPE_FIELD_MAPPING_TYPE_NONE = 0,
	DEVLINK_DPIPE_FIELD_MAPPING_TYPE_IFINDEX = 1,
};

enum devlink_dpipe_match_type {
	DEVLINK_DPIPE_MATCH_TYPE_FIELD_EXACT = 0,
};

enum devlink_dpipe_action_type {
	DEVLINK_DPIPE_ACTION_TYPE_FIELD_MODIFY = 0,
};

enum devlink_dpipe_field_ethernet_id {
	DEVLINK_DPIPE_FIELD_ETHERNET_DST_MAC = 0,
};

enum devlink_dpipe_field_ipv4_id {
	DEVLINK_DPIPE_FIELD_IPV4_DST_IP = 0,
};

enum devlink_dpipe_field_ipv6_id {
	DEVLINK_DPIPE_FIELD_IPV6_DST_IP = 0,
};

enum devlink_dpipe_header_id {
	DEVLINK_DPIPE_HEADER_ETHERNET = 0,
	DEVLINK_DPIPE_HEADER_IPV4 = 1,
	DEVLINK_DPIPE_HEADER_IPV6 = 2,
};

enum devlink_port_function_attr {
	DEVLINK_PORT_FUNCTION_ATTR_UNSPEC = 0,
	DEVLINK_PORT_FUNCTION_ATTR_HW_ADDR = 1,
	DEVLINK_PORT_FN_ATTR_STATE = 2,
	DEVLINK_PORT_FN_ATTR_OPSTATE = 3,
	DEVLINK_PORT_FN_ATTR_CAPS = 4,
	DEVLINK_PORT_FN_ATTR_DEVLINK = 5,
	__DEVLINK_PORT_FUNCTION_ATTR_MAX = 6,
	DEVLINK_PORT_FUNCTION_ATTR_MAX = 5,
};

struct devlink_dev_stats {
	u32 reload_stats[6];
	u32 remote_reload_stats[6];
};

struct devlink_dpipe_headers;

struct devlink_ops;

struct devlink_rel;

struct devlink {
	u32 index;
	struct xarray ports;
	struct list_head rate_list;
	struct list_head sb_list;
	struct list_head dpipe_table_list;
	struct list_head resource_list;
	struct xarray params;
	struct list_head region_list;
	struct list_head reporter_list;
	struct devlink_dpipe_headers *dpipe_headers;
	struct list_head trap_list;
	struct list_head trap_group_list;
	struct list_head trap_policer_list;
	struct list_head linecard_list;
	const struct devlink_ops *ops;
	struct xarray snapshot_ids;
	struct devlink_dev_stats stats;
	struct device *dev;
	possible_net_t _net;
	struct mutex lock;
	struct lock_class_key lock_key;
	u8 reload_failed: 1;
	refcount_t refcount;
	struct rcu_work rwork;
	struct devlink_rel *rel;
	struct xarray nested_rels;
	char priv[0];
};

enum rdma_driver_id {
	RDMA_DRIVER_UNKNOWN = 0,
	RDMA_DRIVER_MLX5 = 1,
	RDMA_DRIVER_MLX4 = 2,
	RDMA_DRIVER_CXGB3 = 3,
	RDMA_DRIVER_CXGB4 = 4,
	RDMA_DRIVER_MTHCA = 5,
	RDMA_DRIVER_BNXT_RE = 6,
	RDMA_DRIVER_OCRDMA = 7,
	RDMA_DRIVER_NES = 8,
	RDMA_DRIVER_I40IW = 9,
	RDMA_DRIVER_IRDMA = 9,
	RDMA_DRIVER_VMW_PVRDMA = 10,
	RDMA_DRIVER_QEDR = 11,
	RDMA_DRIVER_HNS = 12,
	RDMA_DRIVER_USNIC = 13,
	RDMA_DRIVER_RXE = 14,
	RDMA_DRIVER_HFI1 = 15,
	RDMA_DRIVER_QIB = 16,
	RDMA_DRIVER_EFA = 17,
	RDMA_DRIVER_SIW = 18,
	RDMA_DRIVER_ERDMA = 19,
	RDMA_DRIVER_MANA = 20,
};

enum ib_cq_notify_flags {
	IB_CQ_SOLICITED = 1,
	IB_CQ_NEXT_COMP = 2,
	IB_CQ_SOLICITED_MASK = 3,
	IB_CQ_REPORT_MISSED_EVENTS = 4,
};

struct ib_mad;

enum rdma_link_layer {
	IB_LINK_LAYER_UNSPECIFIED = 0,
	IB_LINK_LAYER_INFINIBAND = 1,
	IB_LINK_LAYER_ETHERNET = 2,
};

enum rdma_netdev_t {
	RDMA_NETDEV_OPA_VNIC = 0,
	RDMA_NETDEV_IPOIB = 1,
};

enum ib_srq_attr_mask {
	IB_SRQ_MAX_WR = 1,
	IB_SRQ_LIMIT = 2,
};

enum ib_mr_type {
	IB_MR_TYPE_MEM_REG = 0,
	IB_MR_TYPE_SG_GAPS = 1,
	IB_MR_TYPE_DM = 2,
	IB_MR_TYPE_USER = 3,
	IB_MR_TYPE_DMA = 4,
	IB_MR_TYPE_INTEGRITY = 5,
};

enum ib_uverbs_advise_mr_advice {
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH = 0,
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_WRITE = 1,
	IB_UVERBS_ADVISE_MR_ADVICE_PREFETCH_NO_FAULT = 2,
};

struct uverbs_attr_bundle;

struct rdma_cm_id;

struct iw_cm_id;

struct iw_cm_conn_param;

struct ib_qp;

struct ib_send_wr;

struct ib_recv_wr;

struct ib_cq;

struct ib_wc;

struct ib_srq;

struct ib_grh;

struct ib_device_attr;

struct ib_udata;

struct ib_device_modify;

struct ib_port_attr;

struct ib_port_modify;

struct ib_port_immutable;

struct rdma_netdev_alloc_params;

union ib_gid;

struct ib_gid_attr;

struct ib_ucontext;

struct rdma_user_mmap_entry;

struct ib_pd;

struct ib_ah;

struct rdma_ah_init_attr;

struct rdma_ah_attr;

struct ib_srq_init_attr;

struct ib_srq_attr;

struct ib_qp_init_attr;

struct ib_qp_attr;

struct ib_cq_init_attr;

struct ib_mr;

struct ib_sge;

struct ib_mr_status;

struct ib_mw;

struct ib_xrcd;

struct ib_flow;

struct ib_flow_attr;

struct ib_flow_action;

struct ib_wq;

struct ib_wq_init_attr;

struct ib_wq_attr;

struct ib_rwq_ind_table;

struct ib_rwq_ind_table_init_attr;

struct ib_dm;

struct ib_dm_alloc_attr;

struct ib_dm_mr_attr;

struct ib_counters;

struct ib_counters_read_attr;

struct rdma_hw_stats;

struct rdma_counter;

struct ib_device_ops {
	struct module *owner;
	enum rdma_driver_id driver_id;
	u32 uverbs_abi_ver;
	unsigned int uverbs_no_driver_id_binding: 1;
	const struct attribute_group *device_group;
	const struct attribute_group **port_groups;
	int (*post_send)(struct ib_qp *, const struct ib_send_wr *, const struct ib_send_wr **);
	int (*post_recv)(struct ib_qp *, const struct ib_recv_wr *, const struct ib_recv_wr **);
	void (*drain_rq)(struct ib_qp *);
	void (*drain_sq)(struct ib_qp *);
	int (*poll_cq)(struct ib_cq *, int, struct ib_wc *);
	int (*peek_cq)(struct ib_cq *, int);
	int (*req_notify_cq)(struct ib_cq *, enum ib_cq_notify_flags);
	int (*post_srq_recv)(struct ib_srq *, const struct ib_recv_wr *, const struct ib_recv_wr **);
	int (*process_mad)(struct ib_device *, int, u32, const struct ib_wc *, const struct ib_grh *, const struct ib_mad *, struct ib_mad *, size_t *, u16 *);
	int (*query_device)(struct ib_device *, struct ib_device_attr *, struct ib_udata *);
	int (*modify_device)(struct ib_device *, int, struct ib_device_modify *);
	void (*get_dev_fw_str)(struct ib_device *, char *);
	const struct cpumask * (*get_vector_affinity)(struct ib_device *, int);
	int (*query_port)(struct ib_device *, u32, struct ib_port_attr *);
	int (*modify_port)(struct ib_device *, u32, int, struct ib_port_modify *);
	int (*get_port_immutable)(struct ib_device *, u32, struct ib_port_immutable *);
	enum rdma_link_layer (*get_link_layer)(struct ib_device *, u32);
	struct net_device * (*get_netdev)(struct ib_device *, u32);
	struct net_device * (*alloc_rdma_netdev)(struct ib_device *, u32, enum rdma_netdev_t, const char *, unsigned char, void (*)(struct net_device *));
	int (*rdma_netdev_get_params)(struct ib_device *, u32, enum rdma_netdev_t, struct rdma_netdev_alloc_params *);
	int (*query_gid)(struct ib_device *, u32, int, union ib_gid *);
	int (*add_gid)(const struct ib_gid_attr *, void **);
	int (*del_gid)(const struct ib_gid_attr *, void **);
	int (*query_pkey)(struct ib_device *, u32, u16, u16 *);
	int (*alloc_ucontext)(struct ib_ucontext *, struct ib_udata *);
	void (*dealloc_ucontext)(struct ib_ucontext *);
	int (*mmap)(struct ib_ucontext *, struct vm_area_struct *);
	void (*mmap_free)(struct rdma_user_mmap_entry *);
	void (*disassociate_ucontext)(struct ib_ucontext *);
	int (*alloc_pd)(struct ib_pd *, struct ib_udata *);
	int (*dealloc_pd)(struct ib_pd *, struct ib_udata *);
	int (*create_ah)(struct ib_ah *, struct rdma_ah_init_attr *, struct ib_udata *);
	int (*create_user_ah)(struct ib_ah *, struct rdma_ah_init_attr *, struct ib_udata *);
	int (*modify_ah)(struct ib_ah *, struct rdma_ah_attr *);
	int (*query_ah)(struct ib_ah *, struct rdma_ah_attr *);
	int (*destroy_ah)(struct ib_ah *, u32);
	int (*create_srq)(struct ib_srq *, struct ib_srq_init_attr *, struct ib_udata *);
	int (*modify_srq)(struct ib_srq *, struct ib_srq_attr *, enum ib_srq_attr_mask, struct ib_udata *);
	int (*query_srq)(struct ib_srq *, struct ib_srq_attr *);
	int (*destroy_srq)(struct ib_srq *, struct ib_udata *);
	int (*create_qp)(struct ib_qp *, struct ib_qp_init_attr *, struct ib_udata *);
	int (*modify_qp)(struct ib_qp *, struct ib_qp_attr *, int, struct ib_udata *);
	int (*query_qp)(struct ib_qp *, struct ib_qp_attr *, int, struct ib_qp_init_attr *);
	int (*destroy_qp)(struct ib_qp *, struct ib_udata *);
	int (*create_cq)(struct ib_cq *, const struct ib_cq_init_attr *, struct ib_udata *);
	int (*modify_cq)(struct ib_cq *, u16, u16);
	int (*destroy_cq)(struct ib_cq *, struct ib_udata *);
	int (*resize_cq)(struct ib_cq *, int, struct ib_udata *);
	struct ib_mr * (*get_dma_mr)(struct ib_pd *, int);
	struct ib_mr * (*reg_user_mr)(struct ib_pd *, u64, u64, u64, int, struct ib_udata *);
	struct ib_mr * (*reg_user_mr_dmabuf)(struct ib_pd *, u64, u64, u64, int, int, struct ib_udata *);
	struct ib_mr * (*rereg_user_mr)(struct ib_mr *, int, u64, u64, u64, int, struct ib_pd *, struct ib_udata *);
	int (*dereg_mr)(struct ib_mr *, struct ib_udata *);
	struct ib_mr * (*alloc_mr)(struct ib_pd *, enum ib_mr_type, u32);
	struct ib_mr * (*alloc_mr_integrity)(struct ib_pd *, u32, u32);
	int (*advise_mr)(struct ib_pd *, enum ib_uverbs_advise_mr_advice, u32, struct ib_sge *, u32, struct uverbs_attr_bundle *);
	int (*map_mr_sg)(struct ib_mr *, struct scatterlist *, int, unsigned int *);
	int (*check_mr_status)(struct ib_mr *, u32, struct ib_mr_status *);
	int (*alloc_mw)(struct ib_mw *, struct ib_udata *);
	int (*dealloc_mw)(struct ib_mw *);
	int (*attach_mcast)(struct ib_qp *, union ib_gid *, u16);
	int (*detach_mcast)(struct ib_qp *, union ib_gid *, u16);
	int (*alloc_xrcd)(struct ib_xrcd *, struct ib_udata *);
	int (*dealloc_xrcd)(struct ib_xrcd *, struct ib_udata *);
	struct ib_flow * (*create_flow)(struct ib_qp *, struct ib_flow_attr *, struct ib_udata *);
	int (*destroy_flow)(struct ib_flow *);
	int (*destroy_flow_action)(struct ib_flow_action *);
	int (*set_vf_link_state)(struct ib_device *, int, u32, int);
	int (*get_vf_config)(struct ib_device *, int, u32, struct ifla_vf_info *);
	int (*get_vf_stats)(struct ib_device *, int, u32, struct ifla_vf_stats *);
	int (*get_vf_guid)(struct ib_device *, int, u32, struct ifla_vf_guid *, struct ifla_vf_guid *);
	int (*set_vf_guid)(struct ib_device *, int, u32, u64, int);
	struct ib_wq * (*create_wq)(struct ib_pd *, struct ib_wq_init_attr *, struct ib_udata *);
	int (*destroy_wq)(struct ib_wq *, struct ib_udata *);
	int (*modify_wq)(struct ib_wq *, struct ib_wq_attr *, u32, struct ib_udata *);
	int (*create_rwq_ind_table)(struct ib_rwq_ind_table *, struct ib_rwq_ind_table_init_attr *, struct ib_udata *);
	int (*destroy_rwq_ind_table)(struct ib_rwq_ind_table *);
	struct ib_dm * (*alloc_dm)(struct ib_device *, struct ib_ucontext *, struct ib_dm_alloc_attr *, struct uverbs_attr_bundle *);
	int (*dealloc_dm)(struct ib_dm *, struct uverbs_attr_bundle *);
	struct ib_mr * (*reg_dm_mr)(struct ib_pd *, struct ib_dm *, struct ib_dm_mr_attr *, struct uverbs_attr_bundle *);
	int (*create_counters)(struct ib_counters *, struct uverbs_attr_bundle *);
	int (*destroy_counters)(struct ib_counters *);
	int (*read_counters)(struct ib_counters *, struct ib_counters_read_attr *, struct uverbs_attr_bundle *);
	int (*map_mr_sg_pi)(struct ib_mr *, struct scatterlist *, int, unsigned int *, struct scatterlist *, int, unsigned int *);
	struct rdma_hw_stats * (*alloc_hw_device_stats)(struct ib_device *);
	struct rdma_hw_stats * (*alloc_hw_port_stats)(struct ib_device *, u32);
	int (*get_hw_stats)(struct ib_device *, struct rdma_hw_stats *, u32, int);
	int (*modify_hw_stat)(struct ib_device *, u32, unsigned int, bool);
	int (*fill_res_mr_entry)(struct sk_buff *, struct ib_mr *);
	int (*fill_res_mr_entry_raw)(struct sk_buff *, struct ib_mr *);
	int (*fill_res_cq_entry)(struct sk_buff *, struct ib_cq *);
	int (*fill_res_cq_entry_raw)(struct sk_buff *, struct ib_cq *);
	int (*fill_res_qp_entry)(struct sk_buff *, struct ib_qp *);
	int (*fill_res_qp_entry_raw)(struct sk_buff *, struct ib_qp *);
	int (*fill_res_cm_id_entry)(struct sk_buff *, struct rdma_cm_id *);
	int (*fill_res_srq_entry)(struct sk_buff *, struct ib_srq *);
	int (*fill_res_srq_entry_raw)(struct sk_buff *, struct ib_srq *);
	int (*enable_driver)(struct ib_device *);
	void (*dealloc_driver)(struct ib_device *);
	void (*iw_add_ref)(struct ib_qp *);
	void (*iw_rem_ref)(struct ib_qp *);
	struct ib_qp * (*iw_get_qp)(struct ib_device *, int);
	int (*iw_connect)(struct iw_cm_id *, struct iw_cm_conn_param *);
	int (*iw_accept)(struct iw_cm_id *, struct iw_cm_conn_param *);
	int (*iw_reject)(struct iw_cm_id *, const void *, u8);
	int (*iw_create_listen)(struct iw_cm_id *, int);
	int (*iw_destroy_listen)(struct iw_cm_id *);
	int (*counter_bind_qp)(struct rdma_counter *, struct ib_qp *);
	int (*counter_unbind_qp)(struct ib_qp *);
	int (*counter_dealloc)(struct rdma_counter *);
	struct rdma_hw_stats * (*counter_alloc_stats)(struct rdma_counter *);
	int (*counter_update_stats)(struct rdma_counter *);
	int (*fill_stat_mr_entry)(struct sk_buff *, struct ib_mr *);
	int (*query_ucontext)(struct ib_ucontext *, struct uverbs_attr_bundle *);
	int (*get_numa_node)(struct ib_device *);
	size_t size_ib_ah;
	size_t size_ib_counters;
	size_t size_ib_cq;
	size_t size_ib_mw;
	size_t size_ib_pd;
	size_t size_ib_qp;
	size_t size_ib_rwq_ind_table;
	size_t size_ib_srq;
	size_t size_ib_ucontext;
	size_t size_ib_xrcd;
};

struct ib_core_device {
	struct device dev;
	possible_net_t rdma_net;
	struct kobject *ports_kobj;
	struct list_head port_list;
	struct ib_device *owner;
};

enum ib_atomic_cap {
	IB_ATOMIC_NONE = 0,
	IB_ATOMIC_HCA = 1,
	IB_ATOMIC_GLOB = 2,
};

struct ib_odp_caps {
	uint64_t general_caps;
	struct {
		uint32_t rc_odp_caps;
		uint32_t uc_odp_caps;
		uint32_t ud_odp_caps;
		uint32_t xrc_odp_caps;
	} per_transport_caps;
};

struct ib_rss_caps {
	u32 supported_qpts;
	u32 max_rwq_indirection_tables;
	u32 max_rwq_indirection_table_size;
};

struct ib_tm_caps {
	u32 max_rndv_hdr_size;
	u32 max_num_tags;
	u32 flags;
	u32 max_ops;
	u32 max_sge;
};

struct ib_cq_caps {
	u16 max_cq_moderation_count;
	u16 max_cq_moderation_period;
};

struct ib_device_attr {
	u64 fw_ver;
	__be64 sys_image_guid;
	u64 max_mr_size;
	u64 page_size_cap;
	u32 vendor_id;
	u32 vendor_part_id;
	u32 hw_ver;
	int max_qp;
	int max_qp_wr;
	u64 device_cap_flags;
	u64 kernel_cap_flags;
	int max_send_sge;
	int max_recv_sge;
	int max_sge_rd;
	int max_cq;
	int max_cqe;
	int max_mr;
	int max_pd;
	int max_qp_rd_atom;
	int max_ee_rd_atom;
	int max_res_rd_atom;
	int max_qp_init_rd_atom;
	int max_ee_init_rd_atom;
	enum ib_atomic_cap atomic_cap;
	enum ib_atomic_cap masked_atomic_cap;
	int max_ee;
	int max_rdd;
	int max_mw;
	int max_raw_ipv6_qp;
	int max_raw_ethy_qp;
	int max_mcast_grp;
	int max_mcast_qp_attach;
	int max_total_mcast_qp_attach;
	int max_ah;
	int max_srq;
	int max_srq_wr;
	int max_srq_sge;
	unsigned int max_fast_reg_page_list_len;
	unsigned int max_pi_fast_reg_page_list_len;
	u16 max_pkeys;
	u8 local_ca_ack_delay;
	int sig_prot_cap;
	int sig_guard_cap;
	struct ib_odp_caps odp_caps;
	uint64_t timestamp_mask;
	uint64_t hca_core_clock;
	struct ib_rss_caps rss_caps;
	u32 max_wq_type_rq;
	u32 raw_packet_caps;
	struct ib_tm_caps tm_caps;
	struct ib_cq_caps cq_caps;
	u64 max_dm_size;
	u32 max_sgl_rd;
};

struct hw_stats_device_data;

struct rdmacg_device {
	struct list_head dev_node;
	struct list_head rpools;
	char *name;
};

struct rdma_restrack_root;

struct uapi_definition;

struct ib_port_data;

struct rdma_link_ops;

struct ib_device {
	struct device *dma_device;
	struct ib_device_ops ops;
	char name[64];
	struct callback_head callback_head;
	struct list_head event_handler_list;
	struct rw_semaphore event_handler_rwsem;
	spinlock_t qp_open_list_lock;
	struct rw_semaphore client_data_rwsem;
	struct xarray client_data;
	struct mutex unregistration_lock;
	rwlock_t cache_lock;
	struct ib_port_data *port_data;
	int num_comp_vectors;
	union {
		struct device dev;
		struct ib_core_device coredev;
	};
	const struct attribute_group *groups[4];
	u64 uverbs_cmd_mask;
	char node_desc[64];
	__be64 node_guid;
	u32 local_dma_lkey;
	u16 is_switch: 1;
	u16 kverbs_provider: 1;
	u16 use_cq_dim: 1;
	u8 node_type;
	u32 phys_port_cnt;
	struct ib_device_attr attrs;
	struct hw_stats_device_data *hw_stats_data;
	struct rdmacg_device cg_device;
	u32 index;
	spinlock_t cq_pools_lock;
	struct list_head cq_pools[3];
	struct rdma_restrack_root *res;
	const struct uapi_definition *driver_def;
	refcount_t refcount;
	struct completion unreg_completion;
	struct work_struct unregistration_work;
	const struct rdma_link_ops *link_ops;
	struct mutex compat_devs_mutex;
	struct xarray compat_devs;
	char iw_ifname[16];
	u32 iw_driver_flags;
	u32 lag_flags;
};

struct devlink_port_new_attrs {
	enum devlink_port_flavour flavour;
	unsigned int port_index;
	u32 controller;
	u32 sfnum;
	u16 pfnum;
	u8 port_index_valid: 1;
	u8 controller_valid: 1;
	u8 sfnum_valid: 1;
};

struct devlink_sb_pool_info {
	enum devlink_sb_pool_type pool_type;
	u32 size;
	enum devlink_sb_threshold_type threshold_type;
	u32 cell_size;
};

struct devlink_dpipe_field {
	const char *name;
	unsigned int id;
	unsigned int bitwidth;
	enum devlink_dpipe_field_mapping_type mapping_type;
};

struct devlink_dpipe_header {
	const char *name;
	unsigned int id;
	struct devlink_dpipe_field *fields;
	unsigned int fields_count;
	bool global;
};

struct devlink_dpipe_match {
	enum devlink_dpipe_match_type type;
	unsigned int header_index;
	struct devlink_dpipe_header *header;
	unsigned int field_id;
};

struct devlink_dpipe_action {
	enum devlink_dpipe_action_type type;
	unsigned int header_index;
	struct devlink_dpipe_header *header;
	unsigned int field_id;
};

struct devlink_dpipe_value {
	union {
		struct devlink_dpipe_action *action;
		struct devlink_dpipe_match *match;
	};
	unsigned int mapping_value;
	bool mapping_valid;
	unsigned int value_size;
	void *value;
	void *mask;
};

struct devlink_dpipe_entry {
	u64 index;
	struct devlink_dpipe_value *match_values;
	unsigned int match_values_count;
	struct devlink_dpipe_value *action_values;
	unsigned int action_values_count;
	u64 counter;
	bool counter_valid;
};

struct devlink_dpipe_dump_ctx {
	struct genl_info *info;
	enum devlink_command cmd;
	struct sk_buff *skb;
	struct nlattr *nest;
	void *hdr;
};

struct devlink_dpipe_table_ops;

struct devlink_dpipe_table {
	void *priv;
	struct list_head list;
	const char *name;
	bool counters_enabled;
	bool counter_control_extern;
	bool resource_valid;
	u64 resource_id;
	u64 resource_units;
	struct devlink_dpipe_table_ops *table_ops;
	struct callback_head rcu;
};

struct devlink_dpipe_table_ops {
	int (*actions_dump)(void *, struct sk_buff *);
	int (*matches_dump)(void *, struct sk_buff *);
	int (*entries_dump)(void *, bool, struct devlink_dpipe_dump_ctx *);
	int (*counters_set_update)(void *, bool);
	u64 (*size_get)(void *);
};

struct devlink_dpipe_headers {
	struct devlink_dpipe_header **headers;
	unsigned int headers_count;
};

struct devlink_flash_update_params {
	const struct firmware *fw;
	const char *component;
	u32 overwrite_mask;
};

struct devlink_trap_policer {
	u32 id;
	u64 init_rate;
	u64 init_burst;
	u64 max_rate;
	u64 min_rate;
	u64 max_burst;
	u64 min_burst;
};

struct devlink_trap_group {
	const char *name;
	u16 id;
	bool generic;
	u32 init_policer_id;
};

struct devlink_trap {
	enum devlink_trap_type type;
	enum devlink_trap_action init_action;
	bool generic;
	u16 id;
	const char *name;
	u16 init_group_id;
	u32 metadata_cap;
};

struct devlink_info_req;

struct devlink_ops {
	u32 supported_flash_update_params;
	long unsigned int reload_actions;
	long unsigned int reload_limits;
	int (*reload_down)(struct devlink *, bool, enum devlink_reload_action, enum devlink_reload_limit, struct netlink_ext_ack *);
	int (*reload_up)(struct devlink *, enum devlink_reload_action, enum devlink_reload_limit, u32 *, struct netlink_ext_ack *);
	int (*sb_pool_get)(struct devlink *, unsigned int, u16, struct devlink_sb_pool_info *);
	int (*sb_pool_set)(struct devlink *, unsigned int, u16, u32, enum devlink_sb_threshold_type, struct netlink_ext_ack *);
	int (*sb_port_pool_get)(struct devlink_port *, unsigned int, u16, u32 *);
	int (*sb_port_pool_set)(struct devlink_port *, unsigned int, u16, u32, struct netlink_ext_ack *);
	int (*sb_tc_pool_bind_get)(struct devlink_port *, unsigned int, u16, enum devlink_sb_pool_type, u16 *, u32 *);
	int (*sb_tc_pool_bind_set)(struct devlink_port *, unsigned int, u16, enum devlink_sb_pool_type, u16, u32, struct netlink_ext_ack *);
	int (*sb_occ_snapshot)(struct devlink *, unsigned int);
	int (*sb_occ_max_clear)(struct devlink *, unsigned int);
	int (*sb_occ_port_pool_get)(struct devlink_port *, unsigned int, u16, u32 *, u32 *);
	int (*sb_occ_tc_port_bind_get)(struct devlink_port *, unsigned int, u16, enum devlink_sb_pool_type, u32 *, u32 *);
	int (*eswitch_mode_get)(struct devlink *, u16 *);
	int (*eswitch_mode_set)(struct devlink *, u16, struct netlink_ext_ack *);
	int (*eswitch_inline_mode_get)(struct devlink *, u8 *);
	int (*eswitch_inline_mode_set)(struct devlink *, u8, struct netlink_ext_ack *);
	int (*eswitch_encap_mode_get)(struct devlink *, enum devlink_eswitch_encap_mode *);
	int (*eswitch_encap_mode_set)(struct devlink *, enum devlink_eswitch_encap_mode, struct netlink_ext_ack *);
	int (*info_get)(struct devlink *, struct devlink_info_req *, struct netlink_ext_ack *);
	int (*flash_update)(struct devlink *, struct devlink_flash_update_params *, struct netlink_ext_ack *);
	int (*trap_init)(struct devlink *, const struct devlink_trap *, void *);
	void (*trap_fini)(struct devlink *, const struct devlink_trap *, void *);
	int (*trap_action_set)(struct devlink *, const struct devlink_trap *, enum devlink_trap_action, struct netlink_ext_ack *);
	int (*trap_group_init)(struct devlink *, const struct devlink_trap_group *);
	int (*trap_group_set)(struct devlink *, const struct devlink_trap_group *, const struct devlink_trap_policer *, struct netlink_ext_ack *);
	int (*trap_group_action_set)(struct devlink *, const struct devlink_trap_group *, enum devlink_trap_action, struct netlink_ext_ack *);
	int (*trap_drop_counter_get)(struct devlink *, const struct devlink_trap *, u64 *);
	int (*trap_policer_init)(struct devlink *, const struct devlink_trap_policer *);
	void (*trap_policer_fini)(struct devlink *, const struct devlink_trap_policer *);
	int (*trap_policer_set)(struct devlink *, const struct devlink_trap_policer *, u64, u64, struct netlink_ext_ack *);
	int (*trap_policer_counter_get)(struct devlink *, const struct devlink_trap_policer *, u64 *);
	int (*port_new)(struct devlink *, const struct devlink_port_new_attrs *, struct netlink_ext_ack *, struct devlink_port **);
	int (*rate_leaf_tx_share_set)(struct devlink_rate *, void *, u64, struct netlink_ext_ack *);
	int (*rate_leaf_tx_max_set)(struct devlink_rate *, void *, u64, struct netlink_ext_ack *);
	int (*rate_leaf_tx_priority_set)(struct devlink_rate *, void *, u32, struct netlink_ext_ack *);
	int (*rate_leaf_tx_weight_set)(struct devlink_rate *, void *, u32, struct netlink_ext_ack *);
	int (*rate_node_tx_share_set)(struct devlink_rate *, void *, u64, struct netlink_ext_ack *);
	int (*rate_node_tx_max_set)(struct devlink_rate *, void *, u64, struct netlink_ext_ack *);
	int (*rate_node_tx_priority_set)(struct devlink_rate *, void *, u32, struct netlink_ext_ack *);
	int (*rate_node_tx_weight_set)(struct devlink_rate *, void *, u32, struct netlink_ext_ack *);
	int (*rate_node_new)(struct devlink_rate *, void **, struct netlink_ext_ack *);
	int (*rate_node_del)(struct devlink_rate *, void *, struct netlink_ext_ack *);
	int (*rate_leaf_parent_set)(struct devlink_rate *, struct devlink_rate *, void *, void *, struct netlink_ext_ack *);
	int (*rate_node_parent_set)(struct devlink_rate *, struct devlink_rate *, void *, void *, struct netlink_ext_ack *);
	bool (*selftest_check)(struct devlink *, unsigned int, struct netlink_ext_ack *);
	enum devlink_selftest_status (*selftest_run)(struct devlink *, unsigned int, struct netlink_ext_ack *);
};

struct irq_poll;

typedef int irq_poll_fn(struct irq_poll *, int);

struct irq_poll {
	struct list_head list;
	long unsigned int state;
	int weight;
	irq_poll_fn *poll;
};

struct rdma_cgroup {
	struct cgroup_subsys_state css;
	struct list_head rpools;
};

struct dim_sample {
	ktime_t time;
	u32 pkt_ctr;
	u32 byte_ctr;
	u16 event_ctr;
	u32 comp_ctr;
};

struct dim_stats {
	int ppms;
	int bpms;
	int epms;
	int cpms;
	int cpe_ratio;
};

struct dim {
	u8 state;
	struct dim_stats prev_stats;
	struct dim_sample start_sample;
	struct dim_sample measuring_sample;
	struct work_struct work;
	void *priv;
	u8 profile_ix;
	u8 mode;
	u8 tune_state;
	u8 steps_right;
	u8 steps_left;
	u8 tired;
};

enum ib_uverbs_write_cmds {
	IB_USER_VERBS_CMD_GET_CONTEXT = 0,
	IB_USER_VERBS_CMD_QUERY_DEVICE = 1,
	IB_USER_VERBS_CMD_QUERY_PORT = 2,
	IB_USER_VERBS_CMD_ALLOC_PD = 3,
	IB_USER_VERBS_CMD_DEALLOC_PD = 4,
	IB_USER_VERBS_CMD_CREATE_AH = 5,
	IB_USER_VERBS_CMD_MODIFY_AH = 6,
	IB_USER_VERBS_CMD_QUERY_AH = 7,
	IB_USER_VERBS_CMD_DESTROY_AH = 8,
	IB_USER_VERBS_CMD_REG_MR = 9,
	IB_USER_VERBS_CMD_REG_SMR = 10,
	IB_USER_VERBS_CMD_REREG_MR = 11,
	IB_USER_VERBS_CMD_QUERY_MR = 12,
	IB_USER_VERBS_CMD_DEREG_MR = 13,
	IB_USER_VERBS_CMD_ALLOC_MW = 14,
	IB_USER_VERBS_CMD_BIND_MW = 15,
	IB_USER_VERBS_CMD_DEALLOC_MW = 16,
	IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL = 17,
	IB_USER_VERBS_CMD_CREATE_CQ = 18,
	IB_USER_VERBS_CMD_RESIZE_CQ = 19,
	IB_USER_VERBS_CMD_DESTROY_CQ = 20,
	IB_USER_VERBS_CMD_POLL_CQ = 21,
	IB_USER_VERBS_CMD_PEEK_CQ = 22,
	IB_USER_VERBS_CMD_REQ_NOTIFY_CQ = 23,
	IB_USER_VERBS_CMD_CREATE_QP = 24,
	IB_USER_VERBS_CMD_QUERY_QP = 25,
	IB_USER_VERBS_CMD_MODIFY_QP = 26,
	IB_USER_VERBS_CMD_DESTROY_QP = 27,
	IB_USER_VERBS_CMD_POST_SEND = 28,
	IB_USER_VERBS_CMD_POST_RECV = 29,
	IB_USER_VERBS_CMD_ATTACH_MCAST = 30,
	IB_USER_VERBS_CMD_DETACH_MCAST = 31,
	IB_USER_VERBS_CMD_CREATE_SRQ = 32,
	IB_USER_VERBS_CMD_MODIFY_SRQ = 33,
	IB_USER_VERBS_CMD_QUERY_SRQ = 34,
	IB_USER_VERBS_CMD_DESTROY_SRQ = 35,
	IB_USER_VERBS_CMD_POST_SRQ_RECV = 36,
	IB_USER_VERBS_CMD_OPEN_XRCD = 37,
	IB_USER_VERBS_CMD_CLOSE_XRCD = 38,
	IB_USER_VERBS_CMD_CREATE_XSRQ = 39,
	IB_USER_VERBS_CMD_OPEN_QP = 40,
};

enum ib_uverbs_wc_opcode {
	IB_UVERBS_WC_SEND = 0,
	IB_UVERBS_WC_RDMA_WRITE = 1,
	IB_UVERBS_WC_RDMA_READ = 2,
	IB_UVERBS_WC_COMP_SWAP = 3,
	IB_UVERBS_WC_FETCH_ADD = 4,
	IB_UVERBS_WC_BIND_MW = 5,
	IB_UVERBS_WC_LOCAL_INV = 6,
	IB_UVERBS_WC_TSO = 7,
	IB_UVERBS_WC_FLUSH = 8,
	IB_UVERBS_WC_ATOMIC_WRITE = 9,
};

enum ib_uverbs_create_qp_mask {
	IB_UVERBS_CREATE_QP_MASK_IND_TABLE = 1,
};

enum ib_uverbs_wr_opcode {
	IB_UVERBS_WR_RDMA_WRITE = 0,
	IB_UVERBS_WR_RDMA_WRITE_WITH_IMM = 1,
	IB_UVERBS_WR_SEND = 2,
	IB_UVERBS_WR_SEND_WITH_IMM = 3,
	IB_UVERBS_WR_RDMA_READ = 4,
	IB_UVERBS_WR_ATOMIC_CMP_AND_SWP = 5,
	IB_UVERBS_WR_ATOMIC_FETCH_AND_ADD = 6,
	IB_UVERBS_WR_LOCAL_INV = 7,
	IB_UVERBS_WR_BIND_MW = 8,
	IB_UVERBS_WR_SEND_WITH_INV = 9,
	IB_UVERBS_WR_TSO = 10,
	IB_UVERBS_WR_RDMA_READ_WITH_INV = 11,
	IB_UVERBS_WR_MASKED_ATOMIC_CMP_AND_SWP = 12,
	IB_UVERBS_WR_MASKED_ATOMIC_FETCH_AND_ADD = 13,
	IB_UVERBS_WR_FLUSH = 14,
	IB_UVERBS_WR_ATOMIC_WRITE = 15,
};

enum ib_uverbs_device_cap_flags {
	IB_UVERBS_DEVICE_RESIZE_MAX_WR = 1ULL,
	IB_UVERBS_DEVICE_BAD_PKEY_CNTR = 2ULL,
	IB_UVERBS_DEVICE_BAD_QKEY_CNTR = 4ULL,
	IB_UVERBS_DEVICE_RAW_MULTI = 8ULL,
	IB_UVERBS_DEVICE_AUTO_PATH_MIG = 16ULL,
	IB_UVERBS_DEVICE_CHANGE_PHY_PORT = 32ULL,
	IB_UVERBS_DEVICE_UD_AV_PORT_ENFORCE = 64ULL,
	IB_UVERBS_DEVICE_CURR_QP_STATE_MOD = 128ULL,
	IB_UVERBS_DEVICE_SHUTDOWN_PORT = 256ULL,
	IB_UVERBS_DEVICE_PORT_ACTIVE_EVENT = 1024ULL,
	IB_UVERBS_DEVICE_SYS_IMAGE_GUID = 2048ULL,
	IB_UVERBS_DEVICE_RC_RNR_NAK_GEN = 4096ULL,
	IB_UVERBS_DEVICE_SRQ_RESIZE = 8192ULL,
	IB_UVERBS_DEVICE_N_NOTIFY_CQ = 16384ULL,
	IB_UVERBS_DEVICE_MEM_WINDOW = 131072ULL,
	IB_UVERBS_DEVICE_UD_IP_CSUM = 262144ULL,
	IB_UVERBS_DEVICE_XRC = 1048576ULL,
	IB_UVERBS_DEVICE_MEM_MGT_EXTENSIONS = 2097152ULL,
	IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2A = 8388608ULL,
	IB_UVERBS_DEVICE_MEM_WINDOW_TYPE_2B = 16777216ULL,
	IB_UVERBS_DEVICE_RC_IP_CSUM = 33554432ULL,
	IB_UVERBS_DEVICE_RAW_IP_CSUM = 67108864ULL,
	IB_UVERBS_DEVICE_MANAGED_FLOW_STEERING = 536870912ULL,
	IB_UVERBS_DEVICE_RAW_SCATTER_FCS = 17179869184ULL,
	IB_UVERBS_DEVICE_PCI_WRITE_END_PADDING = 68719476736ULL,
	IB_UVERBS_DEVICE_FLUSH_GLOBAL = 274877906944ULL,
	IB_UVERBS_DEVICE_FLUSH_PERSISTENT = 549755813888ULL,
	IB_UVERBS_DEVICE_ATOMIC_WRITE = 1099511627776ULL,
};

enum ib_uverbs_raw_packet_caps {
	IB_UVERBS_RAW_PACKET_CAP_CVLAN_STRIPPING = 1,
	IB_UVERBS_RAW_PACKET_CAP_SCATTER_FCS = 2,
	IB_UVERBS_RAW_PACKET_CAP_IP_CSUM = 4,
	IB_UVERBS_RAW_PACKET_CAP_DELAY_DROP = 8,
};

enum rdma_nl_counter_mode {
	RDMA_COUNTER_MODE_NONE = 0,
	RDMA_COUNTER_MODE_AUTO = 1,
	RDMA_COUNTER_MODE_MANUAL = 2,
	RDMA_COUNTER_MODE_MAX = 3,
};

enum rdma_nl_counter_mask {
	RDMA_COUNTER_MASK_QP_TYPE = 1,
	RDMA_COUNTER_MASK_PID = 2,
};

enum rdma_restrack_type {
	RDMA_RESTRACK_PD = 0,
	RDMA_RESTRACK_CQ = 1,
	RDMA_RESTRACK_QP = 2,
	RDMA_RESTRACK_CM_ID = 3,
	RDMA_RESTRACK_MR = 4,
	RDMA_RESTRACK_CTX = 5,
	RDMA_RESTRACK_COUNTER = 6,
	RDMA_RESTRACK_SRQ = 7,
	RDMA_RESTRACK_MAX = 8,
};

struct rdma_restrack_entry {
	bool valid;
	u8 no_track: 1;
	struct kref kref;
	struct completion comp;
	struct task_struct *task;
	const char *kern_name;
	enum rdma_restrack_type type;
	bool user;
	u32 id;
};

struct rdma_link_ops {
	struct list_head list;
	const char *type;
	int (*newlink)(const char *, struct net_device *);
};

struct auto_mode_param {
	int qp_type;
};

struct rdma_counter_mode {
	enum rdma_nl_counter_mode mode;
	enum rdma_nl_counter_mask mask;
	struct auto_mode_param param;
};

struct rdma_port_counter {
	struct rdma_counter_mode mode;
	struct rdma_hw_stats *hstats;
	unsigned int num_counters;
	struct mutex lock;
};

struct rdma_stat_desc;

struct rdma_hw_stats {
	struct mutex lock;
	long unsigned int timestamp;
	long unsigned int lifespan;
	const struct rdma_stat_desc *descs;
	long unsigned int *is_disabled;
	int num_counters;
	u64 value[0];
};

struct rdma_counter {
	struct rdma_restrack_entry res;
	struct ib_device *device;
	uint32_t id;
	struct kref kref;
	struct rdma_counter_mode mode;
	struct mutex lock;
	struct rdma_hw_stats *stats;
	u32 port;
};

enum ib_signature_type {
	IB_SIG_TYPE_NONE = 0,
	IB_SIG_TYPE_T10_DIF = 1,
};

enum ib_t10_dif_bg_type {
	IB_T10DIF_CRC = 0,
	IB_T10DIF_CSUM = 1,
};

struct ib_t10_dif_domain {
	enum ib_t10_dif_bg_type bg_type;
	u16 pi_interval;
	u16 bg;
	u16 app_tag;
	u32 ref_tag;
	bool ref_remap;
	bool app_escape;
	bool ref_escape;
	u16 apptag_check_mask;
};

struct ib_sig_domain {
	enum ib_signature_type sig_type;
	union {
		struct ib_t10_dif_domain dif;
	} sig;
};

struct ib_sig_attrs {
	u8 check_mask;
	struct ib_sig_domain mem;
	struct ib_sig_domain wire;
	int meta_length;
};

enum ib_sig_err_type {
	IB_SIG_BAD_GUARD = 0,
	IB_SIG_BAD_REFTAG = 1,
	IB_SIG_BAD_APPTAG = 2,
};

struct ib_sig_err {
	enum ib_sig_err_type err_type;
	u32 expected;
	u32 actual;
	u64 sig_err_offset;
	u32 key;
};

enum ib_uverbs_access_flags {
	IB_UVERBS_ACCESS_LOCAL_WRITE = 1,
	IB_UVERBS_ACCESS_REMOTE_WRITE = 2,
	IB_UVERBS_ACCESS_REMOTE_READ = 4,
	IB_UVERBS_ACCESS_REMOTE_ATOMIC = 8,
	IB_UVERBS_ACCESS_MW_BIND = 16,
	IB_UVERBS_ACCESS_ZERO_BASED = 32,
	IB_UVERBS_ACCESS_ON_DEMAND = 64,
	IB_UVERBS_ACCESS_HUGETLB = 128,
	IB_UVERBS_ACCESS_FLUSH_GLOBAL = 256,
	IB_UVERBS_ACCESS_FLUSH_PERSISTENT = 512,
	IB_UVERBS_ACCESS_RELAXED_ORDERING = 1048576,
	IB_UVERBS_ACCESS_OPTIONAL_RANGE = 1072693248,
};

enum ib_uverbs_srq_type {
	IB_UVERBS_SRQT_BASIC = 0,
	IB_UVERBS_SRQT_XRC = 1,
	IB_UVERBS_SRQT_TM = 2,
};

enum ib_uverbs_wq_type {
	IB_UVERBS_WQT_RQ = 0,
};

enum ib_uverbs_wq_flags {
	IB_UVERBS_WQ_FLAGS_CVLAN_STRIPPING = 1,
	IB_UVERBS_WQ_FLAGS_SCATTER_FCS = 2,
	IB_UVERBS_WQ_FLAGS_DELAY_DROP = 4,
	IB_UVERBS_WQ_FLAGS_PCI_WRITE_END_PADDING = 8,
};

enum ib_uverbs_qp_type {
	IB_UVERBS_QPT_RC = 2,
	IB_UVERBS_QPT_UC = 3,
	IB_UVERBS_QPT_UD = 4,
	IB_UVERBS_QPT_RAW_PACKET = 8,
	IB_UVERBS_QPT_XRC_INI = 9,
	IB_UVERBS_QPT_XRC_TGT = 10,
	IB_UVERBS_QPT_DRIVER = 255,
};

enum ib_uverbs_qp_create_flags {
	IB_UVERBS_QP_CREATE_BLOCK_MULTICAST_LOOPBACK = 2,
	IB_UVERBS_QP_CREATE_SCATTER_FCS = 256,
	IB_UVERBS_QP_CREATE_CVLAN_STRIPPING = 512,
	IB_UVERBS_QP_CREATE_PCI_WRITE_END_PADDING = 2048,
	IB_UVERBS_QP_CREATE_SQ_SIG_ALL = 4096,
};

enum ib_uverbs_gid_type {
	IB_UVERBS_GID_TYPE_IB = 0,
	IB_UVERBS_GID_TYPE_ROCE_V1 = 1,
	IB_UVERBS_GID_TYPE_ROCE_V2 = 2,
};

union ib_gid {
	u8 raw[16];
	struct {
		__be64 subnet_prefix;
		__be64 interface_id;
	} global;
};

enum ib_gid_type {
	IB_GID_TYPE_IB = 0,
	IB_GID_TYPE_ROCE = 1,
	IB_GID_TYPE_ROCE_UDP_ENCAP = 2,
	IB_GID_TYPE_SIZE = 3,
};

struct ib_gid_attr {
	struct net_device *ndev;
	struct ib_device *device;
	union ib_gid gid;
	enum ib_gid_type gid_type;
	u16 index;
	u32 port_num;
};

struct ib_cq_init_attr {
	unsigned int cqe;
	u32 comp_vector;
	u32 flags;
};

struct ib_dm_mr_attr {
	u64 length;
	u64 offset;
	u32 access_flags;
};

struct ib_dm_alloc_attr {
	u64 length;
	u32 alignment;
	u32 flags;
};

enum ib_mtu {
	IB_MTU_256 = 1,
	IB_MTU_512 = 2,
	IB_MTU_1024 = 3,
	IB_MTU_2048 = 4,
	IB_MTU_4096 = 5,
};

enum ib_port_state {
	IB_PORT_NOP = 0,
	IB_PORT_DOWN = 1,
	IB_PORT_INIT = 2,
	IB_PORT_ARMED = 3,
	IB_PORT_ACTIVE = 4,
	IB_PORT_ACTIVE_DEFER = 5,
};

struct rdma_stat_desc {
	const char *name;
	unsigned int flags;
	const void *priv;
};

struct ib_port_attr {
	u64 subnet_prefix;
	enum ib_port_state state;
	enum ib_mtu max_mtu;
	enum ib_mtu active_mtu;
	u32 phys_mtu;
	int gid_tbl_len;
	unsigned int ip_gids: 1;
	u32 port_cap_flags;
	u32 max_msg_sz;
	u32 bad_pkey_cntr;
	u32 qkey_viol_cntr;
	u16 pkey_tbl_len;
	u32 sm_lid;
	u32 lid;
	u8 lmc;
	u8 max_vl_num;
	u8 sm_sl;
	u8 subnet_timeout;
	u8 init_type_reply;
	u8 active_width;
	u16 active_speed;
	u8 phys_state;
	u16 port_cap_flags2;
};

struct ib_device_modify {
	u64 sys_image_guid;
	char node_desc[64];
};

struct ib_port_modify {
	u32 set_port_cap_mask;
	u32 clr_port_cap_mask;
	u8 init_type;
};

enum ib_event_type {
	IB_EVENT_CQ_ERR = 0,
	IB_EVENT_QP_FATAL = 1,
	IB_EVENT_QP_REQ_ERR = 2,
	IB_EVENT_QP_ACCESS_ERR = 3,
	IB_EVENT_COMM_EST = 4,
	IB_EVENT_SQ_DRAINED = 5,
	IB_EVENT_PATH_MIG = 6,
	IB_EVENT_PATH_MIG_ERR = 7,
	IB_EVENT_DEVICE_FATAL = 8,
	IB_EVENT_PORT_ACTIVE = 9,
	IB_EVENT_PORT_ERR = 10,
	IB_EVENT_LID_CHANGE = 11,
	IB_EVENT_PKEY_CHANGE = 12,
	IB_EVENT_SM_CHANGE = 13,
	IB_EVENT_SRQ_ERR = 14,
	IB_EVENT_SRQ_LIMIT_REACHED = 15,
	IB_EVENT_QP_LAST_WQE_REACHED = 16,
	IB_EVENT_CLIENT_REREGISTER = 17,
	IB_EVENT_GID_CHANGE = 18,
	IB_EVENT_WQ_FATAL = 19,
};

struct ib_ucq_object;

typedef void (*ib_comp_handler)(struct ib_cq *, void *);

enum ib_poll_context {
	IB_POLL_SOFTIRQ = 0,
	IB_POLL_WORKQUEUE = 1,
	IB_POLL_UNBOUND_WORKQUEUE = 2,
	IB_POLL_LAST_POOL_TYPE = 2,
	IB_POLL_DIRECT = 3,
};

struct ib_event;

struct ib_cq {
	struct ib_device *device;
	struct ib_ucq_object *uobject;
	ib_comp_handler comp_handler;
	void (*event_handler)(struct ib_event *, void *);
	void *cq_context;
	int cqe;
	unsigned int cqe_used;
	atomic_t usecnt;
	enum ib_poll_context poll_ctx;
	struct ib_wc *wc;
	struct list_head pool_entry;
	union {
		struct irq_poll iop;
		struct work_struct work;
	};
	struct workqueue_struct *comp_wq;
	struct dim *dim;
	ktime_t timestamp;
	u8 interrupt: 1;
	u8 shared: 1;
	unsigned int comp_vector;
	struct rdma_restrack_entry res;
};

struct ib_uqp_object;

enum ib_qp_type {
	IB_QPT_SMI = 0,
	IB_QPT_GSI = 1,
	IB_QPT_RC = 2,
	IB_QPT_UC = 3,
	IB_QPT_UD = 4,
	IB_QPT_RAW_IPV6 = 5,
	IB_QPT_RAW_ETHERTYPE = 6,
	IB_QPT_RAW_PACKET = 8,
	IB_QPT_XRC_INI = 9,
	IB_QPT_XRC_TGT = 10,
	IB_QPT_MAX = 11,
	IB_QPT_DRIVER = 255,
	IB_QPT_RESERVED1 = 4096,
	IB_QPT_RESERVED2 = 4097,
	IB_QPT_RESERVED3 = 4098,
	IB_QPT_RESERVED4 = 4099,
	IB_QPT_RESERVED5 = 4100,
	IB_QPT_RESERVED6 = 4101,
	IB_QPT_RESERVED7 = 4102,
	IB_QPT_RESERVED8 = 4103,
	IB_QPT_RESERVED9 = 4104,
	IB_QPT_RESERVED10 = 4105,
};

struct ib_qp_security;

struct ib_qp {
	struct ib_device *device;
	struct ib_pd *pd;
	struct ib_cq *send_cq;
	struct ib_cq *recv_cq;
	spinlock_t mr_lock;
	int mrs_used;
	struct list_head rdma_mrs;
	struct list_head sig_mrs;
	struct ib_srq *srq;
	struct ib_xrcd *xrcd;
	struct list_head xrcd_list;
	atomic_t usecnt;
	struct list_head open_list;
	struct ib_qp *real_qp;
	struct ib_uqp_object *uobject;
	void (*event_handler)(struct ib_event *, void *);
	void *qp_context;
	const struct ib_gid_attr *av_sgid_attr;
	const struct ib_gid_attr *alt_path_sgid_attr;
	u32 qp_num;
	u32 max_write_sge;
	u32 max_read_sge;
	enum ib_qp_type qp_type;
	struct ib_rwq_ind_table *rwq_ind_tbl;
	struct ib_qp_security *qp_sec;
	u32 port;
	bool integrity_en;
	struct rdma_restrack_entry res;
	struct rdma_counter *counter;
};

struct ib_usrq_object;

enum ib_srq_type {
	IB_SRQT_BASIC = 0,
	IB_SRQT_XRC = 1,
	IB_SRQT_TM = 2,
};

struct ib_srq {
	struct ib_device *device;
	struct ib_pd *pd;
	struct ib_usrq_object *uobject;
	void (*event_handler)(struct ib_event *, void *);
	void *srq_context;
	enum ib_srq_type srq_type;
	atomic_t usecnt;
	struct {
		struct ib_cq *cq;
		union {
			struct {
				struct ib_xrcd *xrcd;
				u32 srq_num;
			} xrc;
		};
	} ext;
	struct rdma_restrack_entry res;
};

struct ib_uwq_object;

enum ib_wq_state {
	IB_WQS_RESET = 0,
	IB_WQS_RDY = 1,
	IB_WQS_ERR = 2,
};

enum ib_wq_type {
	IB_WQT_RQ = 0,
};

struct ib_wq {
	struct ib_device *device;
	struct ib_uwq_object *uobject;
	void *wq_context;
	void (*event_handler)(struct ib_event *, void *);
	struct ib_pd *pd;
	struct ib_cq *cq;
	u32 wq_num;
	enum ib_wq_state state;
	enum ib_wq_type wq_type;
	atomic_t usecnt;
};

struct ib_event {
	struct ib_device *device;
	union {
		struct ib_cq *cq;
		struct ib_qp *qp;
		struct ib_srq *srq;
		struct ib_wq *wq;
		u32 port_num;
	} element;
	enum ib_event_type event;
};

struct ib_global_route {
	const struct ib_gid_attr *sgid_attr;
	union ib_gid dgid;
	u32 flow_label;
	u8 sgid_index;
	u8 hop_limit;
	u8 traffic_class;
};

struct ib_grh {
	__be32 version_tclass_flow;
	__be16 paylen;
	u8 next_hdr;
	u8 hop_limit;
	union ib_gid sgid;
	union ib_gid dgid;
};

struct ib_mr_status {
	u32 fail_status;
	struct ib_sig_err sig_err;
};

struct rdma_ah_init_attr {
	struct rdma_ah_attr *ah_attr;
	u32 flags;
	struct net_device *xmit_slave;
};

enum rdma_ah_attr_type {
	RDMA_AH_ATTR_TYPE_UNDEFINED = 0,
	RDMA_AH_ATTR_TYPE_IB = 1,
	RDMA_AH_ATTR_TYPE_ROCE = 2,
	RDMA_AH_ATTR_TYPE_OPA = 3,
};

struct ib_ah_attr {
	u16 dlid;
	u8 src_path_bits;
};

struct roce_ah_attr {
	u8 dmac[6];
};

struct opa_ah_attr {
	u32 dlid;
	u8 src_path_bits;
	bool make_grd;
};

struct rdma_ah_attr {
	struct ib_global_route grh;
	u8 sl;
	u8 static_rate;
	u32 port_num;
	u8 ah_flags;
	enum rdma_ah_attr_type type;
	union {
		struct ib_ah_attr ib;
		struct roce_ah_attr roce;
		struct opa_ah_attr opa;
	};
};

enum ib_wc_status {
	IB_WC_SUCCESS = 0,
	IB_WC_LOC_LEN_ERR = 1,
	IB_WC_LOC_QP_OP_ERR = 2,
	IB_WC_LOC_EEC_OP_ERR = 3,
	IB_WC_LOC_PROT_ERR = 4,
	IB_WC_WR_FLUSH_ERR = 5,
	IB_WC_MW_BIND_ERR = 6,
	IB_WC_BAD_RESP_ERR = 7,
	IB_WC_LOC_ACCESS_ERR = 8,
	IB_WC_REM_INV_REQ_ERR = 9,
	IB_WC_REM_ACCESS_ERR = 10,
	IB_WC_REM_OP_ERR = 11,
	IB_WC_RETRY_EXC_ERR = 12,
	IB_WC_RNR_RETRY_EXC_ERR = 13,
	IB_WC_LOC_RDD_VIOL_ERR = 14,
	IB_WC_REM_INV_RD_REQ_ERR = 15,
	IB_WC_REM_ABORT_ERR = 16,
	IB_WC_INV_EECN_ERR = 17,
	IB_WC_INV_EEC_STATE_ERR = 18,
	IB_WC_FATAL_ERR = 19,
	IB_WC_RESP_TIMEOUT_ERR = 20,
	IB_WC_GENERAL_ERR = 21,
};

enum ib_wc_opcode {
	IB_WC_SEND = 0,
	IB_WC_RDMA_WRITE = 1,
	IB_WC_RDMA_READ = 2,
	IB_WC_COMP_SWAP = 3,
	IB_WC_FETCH_ADD = 4,
	IB_WC_BIND_MW = 5,
	IB_WC_LOCAL_INV = 6,
	IB_WC_LSO = 7,
	IB_WC_ATOMIC_WRITE = 9,
	IB_WC_REG_MR = 10,
	IB_WC_MASKED_COMP_SWAP = 11,
	IB_WC_MASKED_FETCH_ADD = 12,
	IB_WC_FLUSH = 8,
	IB_WC_RECV = 128,
	IB_WC_RECV_RDMA_WITH_IMM = 129,
};

struct ib_cqe {
	void (*done)(struct ib_cq *, struct ib_wc *);
};

struct ib_wc {
	union {
		u64 wr_id;
		struct ib_cqe *wr_cqe;
	};
	enum ib_wc_status status;
	enum ib_wc_opcode opcode;
	u32 vendor_err;
	u32 byte_len;
	struct ib_qp *qp;
	union {
		__be32 imm_data;
		u32 invalidate_rkey;
	} ex;
	u32 src_qp;
	u32 slid;
	int wc_flags;
	u16 pkey_index;
	u8 sl;
	u8 dlid_path_bits;
	u32 port_num;
	u8 smac[6];
	u16 vlan_id;
	u8 network_hdr_type;
};

struct ib_srq_attr {
	u32 max_wr;
	u32 max_sge;
	u32 srq_limit;
};

struct ib_xrcd {
	struct ib_device *device;
	atomic_t usecnt;
	struct inode *inode;
	struct rw_semaphore tgt_qps_rwsem;
	struct xarray tgt_qps;
};

struct ib_srq_init_attr {
	void (*event_handler)(struct ib_event *, void *);
	void *srq_context;
	struct ib_srq_attr attr;
	enum ib_srq_type srq_type;
	struct {
		struct ib_cq *cq;
		union {
			struct {
				struct ib_xrcd *xrcd;
			} xrc;
			struct {
				u32 max_num_tags;
			} tag_matching;
		};
	} ext;
};

struct ib_qp_cap {
	u32 max_send_wr;
	u32 max_recv_wr;
	u32 max_send_sge;
	u32 max_recv_sge;
	u32 max_inline_data;
	u32 max_rdma_ctxs;
};

enum ib_sig_type {
	IB_SIGNAL_ALL_WR = 0,
	IB_SIGNAL_REQ_WR = 1,
};

struct ib_qp_init_attr {
	void (*event_handler)(struct ib_event *, void *);
	void *qp_context;
	struct ib_cq *send_cq;
	struct ib_cq *recv_cq;
	struct ib_srq *srq;
	struct ib_xrcd *xrcd;
	struct ib_qp_cap cap;
	enum ib_sig_type sq_sig_type;
	enum ib_qp_type qp_type;
	u32 create_flags;
	u32 port_num;
	struct ib_rwq_ind_table *rwq_ind_tbl;
	u32 source_qpn;
};

struct ib_uobject;

struct ib_rwq_ind_table {
	struct ib_device *device;
	struct ib_uobject *uobject;
	atomic_t usecnt;
	u32 ind_tbl_num;
	u32 log_ind_tbl_size;
	struct ib_wq **ind_tbl;
};

enum ib_qp_state {
	IB_QPS_RESET = 0,
	IB_QPS_INIT = 1,
	IB_QPS_RTR = 2,
	IB_QPS_RTS = 3,
	IB_QPS_SQD = 4,
	IB_QPS_SQE = 5,
	IB_QPS_ERR = 6,
};

enum ib_mig_state {
	IB_MIG_MIGRATED = 0,
	IB_MIG_REARM = 1,
	IB_MIG_ARMED = 2,
};

enum ib_mw_type {
	IB_MW_TYPE_1 = 1,
	IB_MW_TYPE_2 = 2,
};

struct ib_qp_attr {
	enum ib_qp_state qp_state;
	enum ib_qp_state cur_qp_state;
	enum ib_mtu path_mtu;
	enum ib_mig_state path_mig_state;
	u32 qkey;
	u32 rq_psn;
	u32 sq_psn;
	u32 dest_qp_num;
	int qp_access_flags;
	struct ib_qp_cap cap;
	struct rdma_ah_attr ah_attr;
	struct rdma_ah_attr alt_ah_attr;
	u16 pkey_index;
	u16 alt_pkey_index;
	u8 en_sqd_async_notify;
	u8 sq_draining;
	u8 max_rd_atomic;
	u8 max_dest_rd_atomic;
	u8 min_rnr_timer;
	u32 port_num;
	u8 timeout;
	u8 retry_cnt;
	u8 rnr_retry;
	u32 alt_port_num;
	u8 alt_timeout;
	u32 rate_limit;
	struct net_device *xmit_slave;
};

enum ib_wr_opcode {
	IB_WR_RDMA_WRITE = 0,
	IB_WR_RDMA_WRITE_WITH_IMM = 1,
	IB_WR_SEND = 2,
	IB_WR_SEND_WITH_IMM = 3,
	IB_WR_RDMA_READ = 4,
	IB_WR_ATOMIC_CMP_AND_SWP = 5,
	IB_WR_ATOMIC_FETCH_AND_ADD = 6,
	IB_WR_BIND_MW = 8,
	IB_WR_LSO = 10,
	IB_WR_SEND_WITH_INV = 9,
	IB_WR_RDMA_READ_WITH_INV = 11,
	IB_WR_LOCAL_INV = 7,
	IB_WR_MASKED_ATOMIC_CMP_AND_SWP = 12,
	IB_WR_MASKED_ATOMIC_FETCH_AND_ADD = 13,
	IB_WR_FLUSH = 14,
	IB_WR_ATOMIC_WRITE = 15,
	IB_WR_REG_MR = 32,
	IB_WR_REG_MR_INTEGRITY = 33,
	IB_WR_RESERVED1 = 240,
	IB_WR_RESERVED2 = 241,
	IB_WR_RESERVED3 = 242,
	IB_WR_RESERVED4 = 243,
	IB_WR_RESERVED5 = 244,
	IB_WR_RESERVED6 = 245,
	IB_WR_RESERVED7 = 246,
	IB_WR_RESERVED8 = 247,
	IB_WR_RESERVED9 = 248,
	IB_WR_RESERVED10 = 249,
};

struct ib_sge {
	u64 addr;
	u32 length;
	u32 lkey;
};

struct ib_send_wr {
	struct ib_send_wr *next;
	union {
		u64 wr_id;
		struct ib_cqe *wr_cqe;
	};
	struct ib_sge *sg_list;
	int num_sge;
	enum ib_wr_opcode opcode;
	int send_flags;
	union {
		__be32 imm_data;
		u32 invalidate_rkey;
	} ex;
};

struct ib_ah {
	struct ib_device *device;
	struct ib_pd *pd;
	struct ib_uobject *uobject;
	const struct ib_gid_attr *sgid_attr;
	enum rdma_ah_attr_type type;
};

struct ib_mr {
	struct ib_device *device;
	struct ib_pd *pd;
	u32 lkey;
	u32 rkey;
	u64 iova;
	u64 length;
	unsigned int page_size;
	enum ib_mr_type type;
	bool need_inval;
	union {
		struct ib_uobject *uobject;
		struct list_head qp_entry;
	};
	struct ib_dm *dm;
	struct ib_sig_attrs *sig_attrs;
	struct rdma_restrack_entry res;
};

struct ib_recv_wr {
	struct ib_recv_wr *next;
	union {
		u64 wr_id;
		struct ib_cqe *wr_cqe;
	};
	struct ib_sge *sg_list;
	int num_sge;
};

struct ib_rdmacg_object {
	struct rdma_cgroup *cg;
};

struct ib_uverbs_file;

struct ib_ucontext {
	struct ib_device *device;
	struct ib_uverbs_file *ufile;
	struct ib_rdmacg_object cg_obj;
	struct rdma_restrack_entry res;
	struct xarray mmap_xa;
};

struct uverbs_api_object;

struct ib_uobject {
	u64 user_handle;
	struct ib_uverbs_file *ufile;
	struct ib_ucontext *context;
	void *object;
	struct list_head list;
	struct ib_rdmacg_object cg_obj;
	int id;
	struct kref ref;
	atomic_t usecnt;
	struct callback_head rcu;
	const struct uverbs_api_object *uapi_object;
};

struct ib_udata {
	const void *inbuf;
	void *outbuf;
	size_t inlen;
	size_t outlen;
};

struct ib_pd {
	u32 local_dma_lkey;
	u32 flags;
	struct ib_device *device;
	struct ib_uobject *uobject;
	atomic_t usecnt;
	u32 unsafe_global_rkey;
	struct ib_mr *__internal_mr;
	struct rdma_restrack_entry res;
};

struct ib_wq_init_attr {
	void *wq_context;
	enum ib_wq_type wq_type;
	u32 max_wr;
	u32 max_sge;
	struct ib_cq *cq;
	void (*event_handler)(struct ib_event *, void *);
	u32 create_flags;
};

struct ib_wq_attr {
	enum ib_wq_state wq_state;
	enum ib_wq_state curr_wq_state;
	u32 flags;
	u32 flags_mask;
};

struct ib_rwq_ind_table_init_attr {
	u32 log_ind_tbl_size;
	struct ib_wq **ind_tbl;
};

enum port_pkey_state {
	IB_PORT_PKEY_NOT_VALID = 0,
	IB_PORT_PKEY_VALID = 1,
	IB_PORT_PKEY_LISTED = 2,
};

struct ib_port_pkey {
	enum port_pkey_state state;
	u16 pkey_index;
	u32 port_num;
	struct list_head qp_list;
	struct list_head to_error_list;
	struct ib_qp_security *sec;
};

struct ib_ports_pkeys;

struct ib_qp_security {
	struct ib_qp *qp;
	struct ib_device *dev;
	struct mutex mutex;
	struct ib_ports_pkeys *ports_pkeys;
	struct list_head shared_qp_list;
	void *security;
	bool destroying;
	atomic_t error_list_count;
	struct completion error_complete;
	int error_comps_pending;
};

struct ib_ports_pkeys {
	struct ib_port_pkey main;
	struct ib_port_pkey alt;
};

struct ib_dm {
	struct ib_device *device;
	u32 length;
	u32 flags;
	struct ib_uobject *uobject;
	atomic_t usecnt;
};

struct ib_mw {
	struct ib_device *device;
	struct ib_pd *pd;
	struct ib_uobject *uobject;
	u32 rkey;
	enum ib_mw_type type;
};

enum ib_flow_attr_type {
	IB_FLOW_ATTR_NORMAL = 0,
	IB_FLOW_ATTR_ALL_DEFAULT = 1,
	IB_FLOW_ATTR_MC_DEFAULT = 2,
	IB_FLOW_ATTR_SNIFFER = 3,
};

enum ib_flow_spec_type {
	IB_FLOW_SPEC_ETH = 32,
	IB_FLOW_SPEC_IB = 34,
	IB_FLOW_SPEC_IPV4 = 48,
	IB_FLOW_SPEC_IPV6 = 49,
	IB_FLOW_SPEC_ESP = 52,
	IB_FLOW_SPEC_TCP = 64,
	IB_FLOW_SPEC_UDP = 65,
	IB_FLOW_SPEC_VXLAN_TUNNEL = 80,
	IB_FLOW_SPEC_GRE = 81,
	IB_FLOW_SPEC_MPLS = 96,
	IB_FLOW_SPEC_INNER = 256,
	IB_FLOW_SPEC_ACTION_TAG = 4096,
	IB_FLOW_SPEC_ACTION_DROP = 4097,
	IB_FLOW_SPEC_ACTION_HANDLE = 4098,
	IB_FLOW_SPEC_ACTION_COUNT = 4099,
};

struct ib_flow_eth_filter {
	u8 dst_mac[6];
	u8 src_mac[6];
	__be16 ether_type;
	__be16 vlan_tag;
};

struct ib_flow_spec_eth {
	u32 type;
	u16 size;
	struct ib_flow_eth_filter val;
	struct ib_flow_eth_filter mask;
};

struct ib_flow_ib_filter {
	__be16 dlid;
	__u8 sl;
};

struct ib_flow_spec_ib {
	u32 type;
	u16 size;
	struct ib_flow_ib_filter val;
	struct ib_flow_ib_filter mask;
};

struct ib_flow_ipv4_filter {
	__be32 src_ip;
	__be32 dst_ip;
	u8 proto;
	u8 tos;
	u8 ttl;
	u8 flags;
};

struct ib_flow_spec_ipv4 {
	u32 type;
	u16 size;
	struct ib_flow_ipv4_filter val;
	struct ib_flow_ipv4_filter mask;
};

struct ib_flow_ipv6_filter {
	u8 src_ip[16];
	u8 dst_ip[16];
	__be32 flow_label;
	u8 next_hdr;
	u8 traffic_class;
	u8 hop_limit;
} __attribute__((packed));

struct ib_flow_spec_ipv6 {
	u32 type;
	u16 size;
	struct ib_flow_ipv6_filter val;
	struct ib_flow_ipv6_filter mask;
};

struct ib_flow_tcp_udp_filter {
	__be16 dst_port;
	__be16 src_port;
};

struct ib_flow_spec_tcp_udp {
	u32 type;
	u16 size;
	struct ib_flow_tcp_udp_filter val;
	struct ib_flow_tcp_udp_filter mask;
};

struct ib_flow_tunnel_filter {
	__be32 tunnel_id;
};

struct ib_flow_spec_tunnel {
	u32 type;
	u16 size;
	struct ib_flow_tunnel_filter val;
	struct ib_flow_tunnel_filter mask;
};

struct ib_flow_esp_filter {
	__be32 spi;
	__be32 seq;
};

struct ib_flow_spec_esp {
	u32 type;
	u16 size;
	struct ib_flow_esp_filter val;
	struct ib_flow_esp_filter mask;
};

struct ib_flow_gre_filter {
	__be16 c_ks_res0_ver;
	__be16 protocol;
	__be32 key;
};

struct ib_flow_spec_gre {
	u32 type;
	u16 size;
	struct ib_flow_gre_filter val;
	struct ib_flow_gre_filter mask;
};

struct ib_flow_mpls_filter {
	__be32 tag;
};

struct ib_flow_spec_mpls {
	u32 type;
	u16 size;
	struct ib_flow_mpls_filter val;
	struct ib_flow_mpls_filter mask;
};

struct ib_flow_spec_action_tag {
	enum ib_flow_spec_type type;
	u16 size;
	u32 tag_id;
};

struct ib_flow_spec_action_drop {
	enum ib_flow_spec_type type;
	u16 size;
};

struct ib_flow_spec_action_handle {
	enum ib_flow_spec_type type;
	u16 size;
	struct ib_flow_action *act;
};

enum ib_flow_action_type {
	IB_FLOW_ACTION_UNSPECIFIED = 0,
	IB_FLOW_ACTION_ESP = 1,
};

struct ib_flow_action {
	struct ib_device *device;
	struct ib_uobject *uobject;
	enum ib_flow_action_type type;
	atomic_t usecnt;
};

struct ib_flow_spec_action_count {
	enum ib_flow_spec_type type;
	u16 size;
	struct ib_counters *counters;
};

struct ib_counters {
	struct ib_device *device;
	struct ib_uobject *uobject;
	atomic_t usecnt;
};

union ib_flow_spec {
	struct {
		u32 type;
		u16 size;
	};
	struct ib_flow_spec_eth eth;
	struct ib_flow_spec_ib ib;
	struct ib_flow_spec_ipv4 ipv4;
	struct ib_flow_spec_tcp_udp tcp_udp;
	struct ib_flow_spec_ipv6 ipv6;
	struct ib_flow_spec_tunnel tunnel;
	struct ib_flow_spec_esp esp;
	struct ib_flow_spec_gre gre;
	struct ib_flow_spec_mpls mpls;
	struct ib_flow_spec_action_tag flow_tag;
	struct ib_flow_spec_action_drop drop;
	struct ib_flow_spec_action_handle action;
	struct ib_flow_spec_action_count flow_count;
};

struct ib_flow_attr {
	enum ib_flow_attr_type type;
	u16 size;
	u16 priority;
	u32 flags;
	u8 num_of_specs;
	u32 port;
	union ib_flow_spec flows[0];
};

struct ib_flow {
	struct ib_qp *qp;
	struct ib_device *device;
	struct ib_uobject *uobject;
};

struct ib_pkey_cache;

struct ib_gid_table;

struct ib_port_cache {
	u64 subnet_prefix;
	struct ib_pkey_cache *pkey;
	struct ib_gid_table *gid;
	u8 lmc;
	enum ib_port_state port_state;
};

struct ib_port_immutable {
	int pkey_tbl_len;
	int gid_tbl_len;
	u32 core_cap_flags;
	u32 max_mad_size;
};

struct ib_port;

struct ib_port_data {
	struct ib_device *ib_dev;
	struct ib_port_immutable immutable;
	spinlock_t pkey_list_lock;
	spinlock_t netdev_lock;
	struct list_head pkey_list;
	struct ib_port_cache cache;
	struct net_device *netdev;
	netdevice_tracker netdev_tracker;
	struct hlist_node ndev_hash_link;
	struct rdma_port_counter port_counter;
	struct ib_port *sysfs;
};

struct rdma_netdev_alloc_params {
	size_t sizeof_priv;
	unsigned int txqs;
	unsigned int rxqs;
	void *param;
	int (*initialize_rdma_netdev)(struct ib_device *, u32, struct net_device *, void *);
};

struct ib_counters_read_attr {
	u64 *counters_buff;
	u32 ncounters;
	u32 flags;
};

struct rdma_user_mmap_entry {
	struct kref ref;
	struct ib_ucontext *ucontext;
	long unsigned int start_pgoff;
	size_t npages;
	bool driver_removed;
};

struct xdp_umem;

struct xsk_queue;

struct xdp_buff_xsk;

struct xdp_desc;

struct xsk_buff_pool {
	struct device *dev;
	struct net_device *netdev;
	struct list_head xsk_tx_list;
	spinlock_t xsk_tx_list_lock;
	refcount_t users;
	struct xdp_umem *umem;
	struct work_struct work;
	struct list_head free_list;
	struct list_head xskb_list;
	u32 heads_cnt;
	u16 queue_id;
	long: 64;
	struct xsk_queue *fq;
	struct xsk_queue *cq;
	dma_addr_t *dma_pages;
	struct xdp_buff_xsk *heads;
	struct xdp_desc *tx_descs;
	u64 chunk_mask;
	u64 addrs_cnt;
	u32 free_list_cnt;
	u32 dma_pages_cnt;
	u32 free_heads_cnt;
	u32 headroom;
	u32 chunk_size;
	u32 chunk_shift;
	u32 frame_len;
	u8 tx_metadata_len;
	u8 cached_need_wakeup;
	bool uses_need_wakeup;
	bool dma_need_sync;
	bool unaligned;
	bool tx_sw_csum;
	void *addrs;
	spinlock_t cq_lock;
	struct xdp_buff_xsk *free_heads[0];
	long: 64;
	long: 64;
};

struct xdp_umem_reg {
	__u64 addr;
	__u64 len;
	__u32 chunk_size;
	__u32 headroom;
	__u32 flags;
	__u32 tx_metadata_len;
};

struct xdp_desc {
	__u64 addr;
	__u32 len;
	__u32 options;
};

struct xdp_umem {
	void *addrs;
	u64 size;
	u32 headroom;
	u32 chunk_size;
	u32 chunks;
	u32 npgs;
	struct user_struct *user;
	refcount_t users;
	u8 flags;
	u8 tx_metadata_len;
	bool zc;
	struct page **pgs;
	int id;
	struct list_head xsk_dma_list;
	struct work_struct work;
};

struct xdp_ring;

struct xsk_queue {
	u32 ring_mask;
	u32 nentries;
	u32 cached_prod;
	u32 cached_cons;
	struct xdp_ring *ring;
	u64 invalid_descs;
	u64 queue_empty_descs;
	size_t ring_vmalloc_size;
};

struct xdp_buff_xsk {
	struct xdp_buff xdp;
	u8 cb[24];
	dma_addr_t dma;
	dma_addr_t frame_dma;
	struct xsk_buff_pool *pool;
	u64 orig_addr;
	struct list_head free_list_node;
	struct list_head xskb_list_node;
};

struct xdp_ring {
	u32 producer;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u32 pad1;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u32 consumer;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u32 pad2;
	u32 flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u32 pad3;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct mptcp_mib {
	long unsigned int mibs[59];
};

enum sock_type {
	SOCK_STREAM = 1,
	SOCK_DGRAM = 2,
	SOCK_RAW = 3,
	SOCK_RDM = 4,
	SOCK_SEQPACKET = 5,
	SOCK_DCCP = 6,
	SOCK_PACKET = 10,
};

struct scm_creds {
	u32 pid;
	kuid_t uid;
	kgid_t gid;
};

struct netlink_skb_parms {
	struct scm_creds creds;
	__u32 portid;
	__u32 dst_group;
	__u32 flags;
	struct sock *sk;
	bool nsid_is_set;
	int nsid;
};

typedef int (*netlink_filter_fn)(struct sock *, struct sk_buff *, void *);

enum netlink_validation {
	NL_VALIDATE_LIBERAL = 0,
	NL_VALIDATE_TRAILING = 1,
	NL_VALIDATE_MAXTYPE = 2,
	NL_VALIDATE_UNSPEC = 4,
	NL_VALIDATE_STRICT_ATTRS = 8,
	NL_VALIDATE_NESTED = 16,
};

struct minmax_sample {
	u32 t;
	u32 v;
};

struct minmax {
	struct minmax_sample s[3];
};

struct tcp_fastopen_cookie {
	__le64 val[2];
	s8 len;
	bool exp;
};

struct tcp_sack_block {
	u32 start_seq;
	u32 end_seq;
};

struct tcp_options_received {
	int ts_recent_stamp;
	u32 ts_recent;
	u32 rcv_tsval;
	u32 rcv_tsecr;
	u16 saw_tstamp: 1;
	u16 tstamp_ok: 1;
	u16 dsack: 1;
	u16 wscale_ok: 1;
	u16 sack_ok: 3;
	u16 smc_ok: 1;
	u16 snd_wscale: 4;
	u16 rcv_wscale: 4;
	u8 saw_unknown: 1;
	u8 unused: 7;
	u8 num_sacks;
	u16 user_mss;
	u16 mss_clamp;
};

struct tcp_rack {
	u64 mstamp;
	u32 rtt_us;
	u32 end_seq;
	u32 last_delivered;
	u8 reo_wnd_steps;
	u8 reo_wnd_persist: 5;
	u8 dsack_seen: 1;
	u8 advanced: 1;
};

struct tcp_sock_af_ops;

struct tcp_md5sig_info;

struct tcp_fastopen_request;

struct tcp_sock {
	struct inet_connection_sock inet_conn;
	__u8 __cacheline_group_begin__tcp_sock_read_tx[0];
	u32 max_window;
	u32 rcv_ssthresh;
	u32 reordering;
	u32 notsent_lowat;
	u16 gso_segs;
	struct sk_buff *lost_skb_hint;
	struct sk_buff *retransmit_skb_hint;
	__u8 __cacheline_group_end__tcp_sock_read_tx[0];
	__u8 __cacheline_group_begin__tcp_sock_read_txrx[0];
	u32 tsoffset;
	u32 snd_wnd;
	u32 mss_cache;
	u32 snd_cwnd;
	u32 prr_out;
	u32 lost_out;
	u32 sacked_out;
	u16 tcp_header_len;
	u8 scaling_ratio;
	u8 chrono_type: 2;
	u8 repair: 1;
	u8 tcp_usec_ts: 1;
	u8 is_sack_reneg: 1;
	u8 is_cwnd_limited: 1;
	__u8 __cacheline_group_end__tcp_sock_read_txrx[0];
	__u8 __cacheline_group_begin__tcp_sock_read_rx[0];
	u32 copied_seq;
	u32 rcv_tstamp;
	u32 snd_wl1;
	u32 tlp_high_seq;
	u32 rttvar_us;
	u32 retrans_out;
	u16 advmss;
	u16 urg_data;
	u32 lost;
	struct minmax rtt_min;
	struct rb_root out_of_order_queue;
	u32 snd_ssthresh;
	__u8 __cacheline_group_end__tcp_sock_read_rx[0];
	long: 64;
	__u8 __cacheline_group_begin__tcp_sock_write_tx[0];
	u32 segs_out;
	u32 data_segs_out;
	u64 bytes_sent;
	u32 snd_sml;
	u32 chrono_start;
	u32 chrono_stat[3];
	u32 write_seq;
	u32 pushed_seq;
	u32 lsndtime;
	u32 mdev_us;
	u32 rtt_seq;
	u64 tcp_wstamp_ns;
	u64 tcp_clock_cache;
	u64 tcp_mstamp;
	struct list_head tsorted_sent_queue;
	struct sk_buff *highest_sack;
	u8 ecn_flags;
	__u8 __cacheline_group_end__tcp_sock_write_tx[0];
	__u8 __cacheline_group_begin__tcp_sock_write_txrx[0];
	__be32 pred_flags;
	u32 rcv_nxt;
	u32 snd_nxt;
	u32 snd_una;
	u32 window_clamp;
	u32 srtt_us;
	u32 packets_out;
	u32 snd_up;
	u32 delivered;
	u32 delivered_ce;
	u32 app_limited;
	u32 rcv_wnd;
	struct tcp_options_received rx_opt;
	u8 nonagle: 4;
	u8 rate_app_limited: 1;
	__u8 __cacheline_group_end__tcp_sock_write_txrx[0];
	long: 0;
	__u8 __cacheline_group_begin__tcp_sock_write_rx[0];
	u64 bytes_received;
	u32 segs_in;
	u32 data_segs_in;
	u32 rcv_wup;
	u32 max_packets_out;
	u32 cwnd_usage_seq;
	u32 rate_delivered;
	u32 rate_interval_us;
	u32 rcv_rtt_last_tsecr;
	u64 first_tx_mstamp;
	u64 delivered_mstamp;
	u64 bytes_acked;
	struct {
		u32 rtt_us;
		u32 seq;
		u64 time;
	} rcv_rtt_est;
	struct {
		u32 space;
		u32 seq;
		u64 time;
	} rcvq_space;
	__u8 __cacheline_group_end__tcp_sock_write_rx[0];
	u32 dsack_dups;
	u32 compressed_ack_rcv_nxt;
	struct list_head tsq_node;
	struct tcp_rack rack;
	u8 compressed_ack;
	u8 dup_ack_counter: 2;
	u8 tlp_retrans: 1;
	u8 unused: 5;
	u8 thin_lto: 1;
	u8 recvmsg_inq: 1;
	u8 fastopen_connect: 1;
	u8 fastopen_no_cookie: 1;
	u8 fastopen_client_fail: 2;
	u8 frto: 1;
	u8 repair_queue;
	u8 save_syn: 2;
	u8 syn_data: 1;
	u8 syn_fastopen: 1;
	u8 syn_fastopen_exp: 1;
	u8 syn_fastopen_ch: 1;
	u8 syn_data_acked: 1;
	u8 keepalive_probes;
	u32 tcp_tx_delay;
	u32 mdev_max_us;
	u32 reord_seen;
	u32 snd_cwnd_cnt;
	u32 snd_cwnd_clamp;
	u32 snd_cwnd_used;
	u32 snd_cwnd_stamp;
	u32 prior_cwnd;
	u32 prr_delivered;
	u32 last_oow_ack_time;
	struct hrtimer pacing_timer;
	struct hrtimer compressed_ack_timer;
	struct sk_buff *ooo_last_skb;
	struct tcp_sack_block duplicate_sack[1];
	struct tcp_sack_block selective_acks[4];
	struct tcp_sack_block recv_sack_cache[4];
	int lost_cnt_hint;
	u32 prior_ssthresh;
	u32 high_seq;
	u32 retrans_stamp;
	u32 undo_marker;
	int undo_retrans;
	u64 bytes_retrans;
	u32 total_retrans;
	u32 rto_stamp;
	u16 total_rto;
	u16 total_rto_recoveries;
	u32 total_rto_time;
	u32 urg_seq;
	unsigned int keepalive_time;
	unsigned int keepalive_intvl;
	int linger2;
	u8 bpf_sock_ops_cb_flags;
	u8 bpf_chg_cc_inprogress: 1;
	u16 timeout_rehash;
	u32 rcv_ooopack;
	struct {
		u32 probe_seq_start;
		u32 probe_seq_end;
	} mtu_probe;
	u32 plb_rehash;
	u32 mtu_info;
	bool is_mptcp;
	bool syn_smc;
	bool (*smc_hs_congested)(const struct sock *);
	const struct tcp_sock_af_ops *af_specific;
	struct tcp_md5sig_info *md5sig_info;
	struct tcp_fastopen_request *fastopen_req;
	struct request_sock *fastopen_rsk;
	struct saved_syn *saved_syn;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct tcp_md5sig_key;

struct tcp_sock_af_ops {
	struct tcp_md5sig_key * (*md5_lookup)(const struct sock *, const struct sock *);
	int (*calc_md5_hash)(char *, const struct tcp_md5sig_key *, const struct sock *, const struct sk_buff *);
	int (*md5_parse)(struct sock *, int, sockptr_t, int);
};

struct tcp_md5sig_info {
	struct hlist_head head;
	struct callback_head rcu;
};

struct tcp_fastopen_request {
	struct tcp_fastopen_cookie cookie;
	struct msghdr *data;
	size_t size;
	int copied;
	struct ubuf_info *uarg;
};

union tcp_ao_addr {
	struct in_addr a4;
	struct in6_addr a6;
};

struct tcp_md5sig_key {
	struct hlist_node node;
	u8 keylen;
	u8 family;
	u8 prefixlen;
	u8 flags;
	union tcp_ao_addr addr;
	int l3index;
	u8 key[80];
	struct callback_head rcu;
};

struct mptcp_rm_list {
	u8 ids[8];
	u8 nr;
};

struct mptcp_addr_info {
	u8 id;
	sa_family_t family;
	__be16 port;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
};

struct mptcp_subflow_context;

struct mptcp_sched_data {
	bool reinject;
	u8 subflows;
	struct mptcp_subflow_context *contexts[8];
};

struct mptcp_subflow_context {
	struct list_head node;
	union {
		struct {
			long unsigned int avg_pacing_rate;
			u64 local_key;
			u64 remote_key;
			u64 idsn;
			u64 map_seq;
			u32 snd_isn;
			u32 token;
			u32 rel_write_seq;
			u32 map_subflow_seq;
			u32 ssn_offset;
			u32 map_data_len;
			__wsum map_data_csum;
			u32 map_csum_len;
			u32 request_mptcp: 1;
			u32 request_join: 1;
			u32 request_bkup: 1;
			u32 mp_capable: 1;
			u32 mp_join: 1;
			u32 fully_established: 1;
			u32 pm_notified: 1;
			u32 conn_finished: 1;
			u32 map_valid: 1;
			u32 map_csum_reqd: 1;
			u32 map_data_fin: 1;
			u32 mpc_map: 1;
			u32 backup: 1;
			u32 send_mp_prio: 1;
			u32 send_mp_fail: 1;
			u32 send_fastclose: 1;
			u32 send_infinite_map: 1;
			u32 remote_key_valid: 1;
			u32 disposable: 1;
			u32 stale: 1;
			u32 valid_csum_seen: 1;
			u32 is_mptfo: 1;
			u32 __unused: 10;
			bool data_avail;
			bool scheduled;
			u32 remote_nonce;
			u64 thmac;
			u32 local_nonce;
			u32 remote_token;
			union {
				u8 hmac[20];
				u64 iasn;
			};
			s16 local_id;
			u8 remote_id;
			u8 reset_seen: 1;
			u8 reset_transient: 1;
			u8 reset_reason: 4;
			u8 stale_count;
			u32 subflow_id;
			long int delegated_status;
			long unsigned int fail_tout;
		};
		struct {
			long unsigned int avg_pacing_rate;
			u64 local_key;
			u64 remote_key;
			u64 idsn;
			u64 map_seq;
			u32 snd_isn;
			u32 token;
			u32 rel_write_seq;
			u32 map_subflow_seq;
			u32 ssn_offset;
			u32 map_data_len;
			__wsum map_data_csum;
			u32 map_csum_len;
			u32 request_mptcp: 1;
			u32 request_join: 1;
			u32 request_bkup: 1;
			u32 mp_capable: 1;
			u32 mp_join: 1;
			u32 fully_established: 1;
			u32 pm_notified: 1;
			u32 conn_finished: 1;
			u32 map_valid: 1;
			u32 map_csum_reqd: 1;
			u32 map_data_fin: 1;
			u32 mpc_map: 1;
			u32 backup: 1;
			u32 send_mp_prio: 1;
			u32 send_mp_fail: 1;
			u32 send_fastclose: 1;
			u32 send_infinite_map: 1;
			u32 remote_key_valid: 1;
			u32 disposable: 1;
			u32 stale: 1;
			u32 valid_csum_seen: 1;
			u32 is_mptfo: 1;
			u32 __unused: 10;
			bool data_avail;
			bool scheduled;
			u32 remote_nonce;
			u64 thmac;
			u32 local_nonce;
			u32 remote_token;
			union {
				u8 hmac[20];
				u64 iasn;
			};
			s16 local_id;
			u8 remote_id;
			u8 reset_seen: 1;
			u8 reset_transient: 1;
			u8 reset_reason: 4;
			u8 stale_count;
			u32 subflow_id;
			long int delegated_status;
			long unsigned int fail_tout;
		} reset;
	};
	struct list_head delegated_node;
	u32 setsockopt_seq;
	u32 stale_rcv_tstamp;
	int cached_sndbuf;
	struct sock *tcp_sock;
	struct sock *conn;
	const struct inet_connection_sock_af_ops *icsk_af_ops;
	void (*tcp_state_change)(struct sock *);
	void (*tcp_error_report)(struct sock *);
	struct callback_head rcu;
};

struct mptcp_sock;

struct mptcp_sched_ops {
	int (*get_subflow)(struct mptcp_sock *, struct mptcp_sched_data *);
	char name[16];
	struct module *owner;
	struct list_head list;
	void (*init)(struct mptcp_sock *);
	void (*release)(struct mptcp_sock *);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct mptcp_pm_data {
	struct mptcp_addr_info local;
	struct mptcp_addr_info remote;
	struct list_head anno_list;
	struct list_head userspace_pm_local_addr_list;
	spinlock_t lock;
	u8 addr_signal;
	bool server_side;
	bool work_pending;
	bool accept_addr;
	bool accept_subflow;
	bool remote_deny_join_id0;
	u8 add_addr_signaled;
	u8 add_addr_accepted;
	u8 local_addr_used;
	u8 pm_type;
	u8 subflows;
	u8 status;
	long unsigned int id_avail_bitmap[4];
	struct mptcp_rm_list rm_list_tx;
	struct mptcp_rm_list rm_list_rx;
};

struct mptcp_data_frag;

struct mptcp_sock {
	struct inet_connection_sock sk;
	u64 local_key;
	u64 remote_key;
	u64 write_seq;
	u64 bytes_sent;
	u64 snd_nxt;
	u64 bytes_received;
	u64 ack_seq;
	atomic64_t rcv_wnd_sent;
	u64 rcv_data_fin_seq;
	u64 bytes_retrans;
	u64 bytes_consumed;
	int rmem_fwd_alloc;
	int snd_burst;
	int old_wspace;
	u64 recovery_snd_nxt;
	u64 bytes_acked;
	u64 snd_una;
	u64 wnd_end;
	long unsigned int timer_ival;
	u32 token;
	int rmem_released;
	long unsigned int flags;
	long unsigned int cb_flags;
	bool recovery;
	bool can_ack;
	bool fully_established;
	bool rcv_data_fin;
	bool snd_data_fin_enable;
	bool rcv_fastclose;
	bool use_64bit_ack;
	bool csum_enabled;
	bool allow_infinite_fallback;
	u8 pending_state;
	u8 mpc_endpoint_id;
	u8 recvmsg_inq: 1;
	u8 cork: 1;
	u8 nodelay: 1;
	u8 fastopening: 1;
	u8 in_accept_queue: 1;
	u8 free_first: 1;
	u8 rcvspace_init: 1;
	u32 notsent_lowat;
	int keepalive_cnt;
	int keepalive_idle;
	int keepalive_intvl;
	struct work_struct work;
	struct sk_buff *ooo_last_skb;
	struct rb_root out_of_order_queue;
	struct sk_buff_head receive_queue;
	struct list_head conn_list;
	struct list_head rtx_queue;
	struct mptcp_data_frag *first_pending;
	struct list_head join_list;
	struct sock *first;
	struct mptcp_pm_data pm;
	struct mptcp_sched_ops *sched;
	struct {
		u32 space;
		u32 copied;
		u64 time;
		u64 rtt_us;
	} rcvq_space;
	u8 scaling_ratio;
	u32 subflow_id;
	u32 setsockopt_seq;
	char ca_name[16];
};

enum mptcp_event_type {
	MPTCP_EVENT_UNSPEC = 0,
	MPTCP_EVENT_CREATED = 1,
	MPTCP_EVENT_ESTABLISHED = 2,
	MPTCP_EVENT_CLOSED = 3,
	MPTCP_EVENT_ANNOUNCED = 6,
	MPTCP_EVENT_REMOVED = 7,
	MPTCP_EVENT_SUB_ESTABLISHED = 10,
	MPTCP_EVENT_SUB_CLOSED = 11,
	MPTCP_EVENT_SUB_PRIORITY = 13,
	MPTCP_EVENT_LISTENER_CREATED = 15,
	MPTCP_EVENT_LISTENER_CLOSED = 16,
};

enum {
	MPTCP_PM_ADDR_ATTR_UNSPEC = 0,
	MPTCP_PM_ADDR_ATTR_FAMILY = 1,
	MPTCP_PM_ADDR_ATTR_ID = 2,
	MPTCP_PM_ADDR_ATTR_ADDR4 = 3,
	MPTCP_PM_ADDR_ATTR_ADDR6 = 4,
	MPTCP_PM_ADDR_ATTR_PORT = 5,
	MPTCP_PM_ADDR_ATTR_FLAGS = 6,
	MPTCP_PM_ADDR_ATTR_IF_IDX = 7,
	__MPTCP_PM_ADDR_ATTR_MAX = 8,
};

enum {
	MPTCP_PM_ENDPOINT_ADDR = 1,
	__MPTCP_PM_ENDPOINT_MAX = 2,
};

enum {
	MPTCP_PM_ATTR_UNSPEC = 0,
	MPTCP_PM_ATTR_ADDR = 1,
	MPTCP_PM_ATTR_RCV_ADD_ADDRS = 2,
	MPTCP_PM_ATTR_SUBFLOWS = 3,
	MPTCP_PM_ATTR_TOKEN = 4,
	MPTCP_PM_ATTR_LOC_ID = 5,
	MPTCP_PM_ATTR_ADDR_REMOTE = 6,
	__MPTCP_ATTR_AFTER_LAST = 7,
};

enum mptcp_event_attr {
	MPTCP_ATTR_UNSPEC = 0,
	MPTCP_ATTR_TOKEN = 1,
	MPTCP_ATTR_FAMILY = 2,
	MPTCP_ATTR_LOC_ID = 3,
	MPTCP_ATTR_REM_ID = 4,
	MPTCP_ATTR_SADDR4 = 5,
	MPTCP_ATTR_SADDR6 = 6,
	MPTCP_ATTR_DADDR4 = 7,
	MPTCP_ATTR_DADDR6 = 8,
	MPTCP_ATTR_SPORT = 9,
	MPTCP_ATTR_DPORT = 10,
	MPTCP_ATTR_BACKUP = 11,
	MPTCP_ATTR_ERROR = 12,
	MPTCP_ATTR_FLAGS = 13,
	MPTCP_ATTR_TIMEOUT = 14,
	MPTCP_ATTR_IF_IDX = 15,
	MPTCP_ATTR_RESET_REASON = 16,
	MPTCP_ATTR_RESET_FLAGS = 17,
	MPTCP_ATTR_SERVER_SIDE = 18,
	__MPTCP_ATTR_MAX = 19,
};

enum {
	MPTCP_PM_CMD_UNSPEC = 0,
	MPTCP_PM_CMD_ADD_ADDR = 1,
	MPTCP_PM_CMD_DEL_ADDR = 2,
	MPTCP_PM_CMD_GET_ADDR = 3,
	MPTCP_PM_CMD_FLUSH_ADDRS = 4,
	MPTCP_PM_CMD_SET_LIMITS = 5,
	MPTCP_PM_CMD_GET_LIMITS = 6,
	MPTCP_PM_CMD_SET_FLAGS = 7,
	MPTCP_PM_CMD_ANNOUNCE = 8,
	MPTCP_PM_CMD_REMOVE = 9,
	MPTCP_PM_CMD_SUBFLOW_CREATE = 10,
	MPTCP_PM_CMD_SUBFLOW_DESTROY = 11,
	__MPTCP_PM_CMD_AFTER_LAST = 12,
};

enum mptcp_pm_status {
	MPTCP_PM_ADD_ADDR_RECEIVED = 0,
	MPTCP_PM_ADD_ADDR_SEND_ACK = 1,
	MPTCP_PM_RM_ADDR_RECEIVED = 2,
	MPTCP_PM_ESTABLISHED = 3,
	MPTCP_PM_SUBFLOW_ESTABLISHED = 4,
	MPTCP_PM_ALREADY_ESTABLISHED = 5,
	MPTCP_PM_MPC_ENDPOINT_ACCOUNTED = 6,
};

enum mptcp_pm_type {
	MPTCP_PM_TYPE_KERNEL = 0,
	MPTCP_PM_TYPE_USERSPACE = 1,
	__MPTCP_PM_TYPE_NR = 2,
	__MPTCP_PM_TYPE_MAX = 1,
};

enum mptcp_addr_signal_status {
	MPTCP_ADD_ADDR_SIGNAL = 0,
	MPTCP_ADD_ADDR_ECHO = 1,
	MPTCP_RM_ADDR_SIGNAL = 2,
};

struct mptcp_pm_addr_entry {
	struct list_head list;
	struct mptcp_addr_info addr;
	u8 flags;
	int ifindex;
	struct socket *lsk;
};

struct mptcp_data_frag {
	struct list_head list;
	u64 data_seq;
	u16 data_len;
	u16 offset;
	u16 overhead;
	u16 already_sent;
	struct page *page;
};

enum linux_mptcp_mib_field {
	MPTCP_MIB_NUM = 0,
	MPTCP_MIB_MPCAPABLEPASSIVE = 1,
	MPTCP_MIB_MPCAPABLEACTIVE = 2,
	MPTCP_MIB_MPCAPABLEACTIVEACK = 3,
	MPTCP_MIB_MPCAPABLEPASSIVEACK = 4,
	MPTCP_MIB_MPCAPABLEPASSIVEFALLBACK = 5,
	MPTCP_MIB_MPCAPABLEACTIVEFALLBACK = 6,
	MPTCP_MIB_TOKENFALLBACKINIT = 7,
	MPTCP_MIB_RETRANSSEGS = 8,
	MPTCP_MIB_JOINNOTOKEN = 9,
	MPTCP_MIB_JOINSYNRX = 10,
	MPTCP_MIB_JOINSYNACKRX = 11,
	MPTCP_MIB_JOINSYNACKMAC = 12,
	MPTCP_MIB_JOINACKRX = 13,
	MPTCP_MIB_JOINACKMAC = 14,
	MPTCP_MIB_DSSNOMATCH = 15,
	MPTCP_MIB_INFINITEMAPTX = 16,
	MPTCP_MIB_INFINITEMAPRX = 17,
	MPTCP_MIB_DSSTCPMISMATCH = 18,
	MPTCP_MIB_DATACSUMERR = 19,
	MPTCP_MIB_OFOQUEUETAIL = 20,
	MPTCP_MIB_OFOQUEUE = 21,
	MPTCP_MIB_OFOMERGE = 22,
	MPTCP_MIB_NODSSWINDOW = 23,
	MPTCP_MIB_DUPDATA = 24,
	MPTCP_MIB_ADDADDR = 25,
	MPTCP_MIB_ADDADDRTX = 26,
	MPTCP_MIB_ADDADDRTXDROP = 27,
	MPTCP_MIB_ECHOADD = 28,
	MPTCP_MIB_ECHOADDTX = 29,
	MPTCP_MIB_ECHOADDTXDROP = 30,
	MPTCP_MIB_PORTADD = 31,
	MPTCP_MIB_ADDADDRDROP = 32,
	MPTCP_MIB_JOINPORTSYNRX = 33,
	MPTCP_MIB_JOINPORTSYNACKRX = 34,
	MPTCP_MIB_JOINPORTACKRX = 35,
	MPTCP_MIB_MISMATCHPORTSYNRX = 36,
	MPTCP_MIB_MISMATCHPORTACKRX = 37,
	MPTCP_MIB_RMADDR = 38,
	MPTCP_MIB_RMADDRDROP = 39,
	MPTCP_MIB_RMADDRTX = 40,
	MPTCP_MIB_RMADDRTXDROP = 41,
	MPTCP_MIB_RMSUBFLOW = 42,
	MPTCP_MIB_MPPRIOTX = 43,
	MPTCP_MIB_MPPRIORX = 44,
	MPTCP_MIB_MPFAILTX = 45,
	MPTCP_MIB_MPFAILRX = 46,
	MPTCP_MIB_MPFASTCLOSETX = 47,
	MPTCP_MIB_MPFASTCLOSERX = 48,
	MPTCP_MIB_MPRSTTX = 49,
	MPTCP_MIB_MPRSTRX = 50,
	MPTCP_MIB_RCVPRUNED = 51,
	MPTCP_MIB_SUBFLOWSTALE = 52,
	MPTCP_MIB_SUBFLOWRECOVER = 53,
	MPTCP_MIB_SNDWNDSHARED = 54,
	MPTCP_MIB_RCVWNDSHARED = 55,
	MPTCP_MIB_RCVWNDCONFLICTUPDATE = 56,
	MPTCP_MIB_RCVWNDCONFLICT = 57,
	MPTCP_MIB_CURRESTAB = 58,
	__MPTCP_MIB_MAX = 59,
};

struct mptcp_pm_add_entry {
	struct list_head list;
	struct mptcp_addr_info addr;
	u8 retrans_times;
	struct timer_list add_timer;
	struct mptcp_sock *sock;
};

struct pm_nl_pernet {
	spinlock_t lock;
	struct list_head local_addr_list;
	unsigned int addrs;
	unsigned int stale_loss_cnt;
	unsigned int add_addr_signal_max;
	unsigned int add_addr_accept_max;
	unsigned int local_addr_max;
	unsigned int subflows_max;
	unsigned int next_id;
	long unsigned int id_bitmap[4];
};

struct rtas_t {
	long unsigned int entry;
	long unsigned int base;
	long unsigned int size;
	struct device_node *dev;
};

struct rtas_error_log {
	u8 byte0;
	u8 byte1;
	u8 byte2;
	u8 byte3;
	__be32 extended_log_length;
	unsigned char buffer[1];
};

enum rtas_function_index {
	RTAS_FNIDX__CHECK_EXCEPTION = 0,
	RTAS_FNIDX__DISPLAY_CHARACTER = 1,
	RTAS_FNIDX__EVENT_SCAN = 2,
	RTAS_FNIDX__FREEZE_TIME_BASE = 3,
	RTAS_FNIDX__GET_POWER_LEVEL = 4,
	RTAS_FNIDX__GET_SENSOR_STATE = 5,
	RTAS_FNIDX__GET_TERM_CHAR = 6,
	RTAS_FNIDX__GET_TIME_OF_DAY = 7,
	RTAS_FNIDX__IBM_ACTIVATE_FIRMWARE = 8,
	RTAS_FNIDX__IBM_CBE_START_PTCAL = 9,
	RTAS_FNIDX__IBM_CBE_STOP_PTCAL = 10,
	RTAS_FNIDX__IBM_CHANGE_MSI = 11,
	RTAS_FNIDX__IBM_CLOSE_ERRINJCT = 12,
	RTAS_FNIDX__IBM_CONFIGURE_BRIDGE = 13,
	RTAS_FNIDX__IBM_CONFIGURE_CONNECTOR = 14,
	RTAS_FNIDX__IBM_CONFIGURE_KERNEL_DUMP = 15,
	RTAS_FNIDX__IBM_CONFIGURE_PE = 16,
	RTAS_FNIDX__IBM_CREATE_PE_DMA_WINDOW = 17,
	RTAS_FNIDX__IBM_DISPLAY_MESSAGE = 18,
	RTAS_FNIDX__IBM_ERRINJCT = 19,
	RTAS_FNIDX__IBM_EXTI2C = 20,
	RTAS_FNIDX__IBM_GET_CONFIG_ADDR_INFO = 21,
	RTAS_FNIDX__IBM_GET_CONFIG_ADDR_INFO2 = 22,
	RTAS_FNIDX__IBM_GET_DYNAMIC_SENSOR_STATE = 23,
	RTAS_FNIDX__IBM_GET_INDICES = 24,
	RTAS_FNIDX__IBM_GET_RIO_TOPOLOGY = 25,
	RTAS_FNIDX__IBM_GET_SYSTEM_PARAMETER = 26,
	RTAS_FNIDX__IBM_GET_VPD = 27,
	RTAS_FNIDX__IBM_GET_XIVE = 28,
	RTAS_FNIDX__IBM_INT_OFF = 29,
	RTAS_FNIDX__IBM_INT_ON = 30,
	RTAS_FNIDX__IBM_IO_QUIESCE_ACK = 31,
	RTAS_FNIDX__IBM_LPAR_PERFTOOLS = 32,
	RTAS_FNIDX__IBM_MANAGE_FLASH_IMAGE = 33,
	RTAS_FNIDX__IBM_MANAGE_STORAGE_PRESERVATION = 34,
	RTAS_FNIDX__IBM_NMI_INTERLOCK = 35,
	RTAS_FNIDX__IBM_NMI_REGISTER = 36,
	RTAS_FNIDX__IBM_OPEN_ERRINJCT = 37,
	RTAS_FNIDX__IBM_OPEN_SRIOV_ALLOW_UNFREEZE = 38,
	RTAS_FNIDX__IBM_OPEN_SRIOV_MAP_PE_NUMBER = 39,
	RTAS_FNIDX__IBM_OS_TERM = 40,
	RTAS_FNIDX__IBM_PARTNER_CONTROL = 41,
	RTAS_FNIDX__IBM_PHYSICAL_ATTESTATION = 42,
	RTAS_FNIDX__IBM_PLATFORM_DUMP = 43,
	RTAS_FNIDX__IBM_POWER_OFF_UPS = 44,
	RTAS_FNIDX__IBM_QUERY_INTERRUPT_SOURCE_NUMBER = 45,
	RTAS_FNIDX__IBM_QUERY_PE_DMA_WINDOW = 46,
	RTAS_FNIDX__IBM_READ_PCI_CONFIG = 47,
	RTAS_FNIDX__IBM_READ_SLOT_RESET_STATE = 48,
	RTAS_FNIDX__IBM_READ_SLOT_RESET_STATE2 = 49,
	RTAS_FNIDX__IBM_REMOVE_PE_DMA_WINDOW = 50,
	RTAS_FNIDX__IBM_RESET_PE_DMA_WINDOW = 51,
	RTAS_FNIDX__IBM_SCAN_LOG_DUMP = 52,
	RTAS_FNIDX__IBM_SET_DYNAMIC_INDICATOR = 53,
	RTAS_FNIDX__IBM_SET_EEH_OPTION = 54,
	RTAS_FNIDX__IBM_SET_SLOT_RESET = 55,
	RTAS_FNIDX__IBM_SET_SYSTEM_PARAMETER = 56,
	RTAS_FNIDX__IBM_SET_XIVE = 57,
	RTAS_FNIDX__IBM_SLOT_ERROR_DETAIL = 58,
	RTAS_FNIDX__IBM_SUSPEND_ME = 59,
	RTAS_FNIDX__IBM_TUNE_DMA_PARMS = 60,
	RTAS_FNIDX__IBM_UPDATE_FLASH_64_AND_REBOOT = 61,
	RTAS_FNIDX__IBM_UPDATE_NODES = 62,
	RTAS_FNIDX__IBM_UPDATE_PROPERTIES = 63,
	RTAS_FNIDX__IBM_VALIDATE_FLASH_IMAGE = 64,
	RTAS_FNIDX__IBM_WRITE_PCI_CONFIG = 65,
	RTAS_FNIDX__NVRAM_FETCH = 66,
	RTAS_FNIDX__NVRAM_STORE = 67,
	RTAS_FNIDX__POWER_OFF = 68,
	RTAS_FNIDX__PUT_TERM_CHAR = 69,
	RTAS_FNIDX__QUERY_CPU_STOPPED_STATE = 70,
	RTAS_FNIDX__READ_PCI_CONFIG = 71,
	RTAS_FNIDX__RTAS_LAST_ERROR = 72,
	RTAS_FNIDX__SET_INDICATOR = 73,
	RTAS_FNIDX__SET_POWER_LEVEL = 74,
	RTAS_FNIDX__SET_TIME_FOR_POWER_ON = 75,
	RTAS_FNIDX__SET_TIME_OF_DAY = 76,
	RTAS_FNIDX__START_CPU = 77,
	RTAS_FNIDX__STOP_SELF = 78,
	RTAS_FNIDX__SYSTEM_REBOOT = 79,
	RTAS_FNIDX__THAW_TIME_BASE = 80,
	RTAS_FNIDX__WRITE_PCI_CONFIG = 81,
};

typedef struct {
	const enum rtas_function_index index;
} rtas_fn_handle_t;

struct prev_kprobe {
	struct kprobe *kp;
	long unsigned int status;
	long unsigned int saved_msr;
};

struct kprobe_ctlblk {
	long unsigned int kprobe_status;
	long unsigned int kprobe_saved_msr;
	struct prev_kprobe prev_kprobe;
};

struct kretprobe_blackpoint {
	const char *name;
	void *addr;
};

struct kprobe_insn_cache {
	struct mutex mutex;
	void * (*alloc)();
	void (*free)(void *);
	const char *sym;
	struct list_head pages;
	size_t insn_size;
	int nr_garbage;
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

struct msi_dev_domain {
	struct xarray store;
	struct irq_domain *domain;
};

struct platform_msi_priv_data;

struct msi_device_data {
	long unsigned int properties;
	struct platform_msi_priv_data *platform_data;
	struct mutex mutex;
	struct msi_dev_domain __domains[2];
	long unsigned int __iter_idx;
};

struct arch_msi_msg_addr_lo {
	u32 address_lo;
};

typedef struct arch_msi_msg_addr_lo arch_msi_msg_addr_lo_t;

struct arch_msi_msg_addr_hi {
	u32 address_hi;
};

typedef struct arch_msi_msg_addr_hi arch_msi_msg_addr_hi_t;

struct arch_msi_msg_data {
	u32 data;
};

typedef struct arch_msi_msg_data arch_msi_msg_data_t;

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

struct msi_desc {
	unsigned int irq;
	unsigned int nvec_used;
	struct device *dev;
	struct msi_msg msg;
	struct irq_affinity_desc *affinity;
	struct device_attribute *sysfs_attrs;
	void (*write_msi_msg)(struct msi_desc *, void *);
	void *write_msi_msg_data;
	u16 msi_index;
	union {
		struct pci_msi_desc pci;
		struct msi_desc_data data;
	};
};

enum msi_domain_ids {
	MSI_DEFAULT_DOMAIN = 0,
	MSI_SECONDARY_DOMAIN = 1,
	MSI_MAX_DEVICE_IRQDOMAINS = 2,
};

enum pci_mmap_state {
	pci_mmap_io = 0,
	pci_mmap_mem = 1,
};

struct pci_sriov {
	int pos;
	int nres;
	u32 cap;
	u16 ctrl;
	u16 total_VFs;
	u16 initial_VFs;
	u16 num_VFs;
	u16 offset;
	u16 stride;
	u16 vf_device;
	u32 pgsz;
	u8 link;
	u8 max_VF_buses;
	u16 driver_max_VFs;
	struct pci_dev *dev;
	struct pci_dev *self;
	u32 class;
	u8 hdr_type;
	u16 subsystem_vendor;
	u16 subsystem_device;
	resource_size_t barsz[6];
	bool drivers_autoprobe;
};

struct rcec_ea {
	u8 nextbusn;
	u8 lastbusn;
	u32 bitmap;
};

typedef u64 pci_bus_addr_t;

struct pci_bus_region {
	pci_bus_addr_t start;
	pci_bus_addr_t end;
};

enum {
	PCI_REASSIGN_ALL_RSRC = 1,
	PCI_REASSIGN_ALL_BUS = 2,
	PCI_PROBE_ONLY = 4,
	PCI_CAN_SKIP_ISA_ALIGN = 8,
	PCI_ENABLE_PROC_DOMAINS = 16,
	PCI_COMPAT_DOMAIN_0 = 32,
	PCI_SCAN_ALL_PCIE_DEVS = 64,
};

struct of_bus;

struct of_pci_range_parser {
	struct device_node *node;
	struct of_bus *bus;
	const __be32 *range;
	const __be32 *end;
	int na;
	int ns;
	int pna;
	bool dma;
};

struct of_pci_range {
	union {
		u64 pci_addr;
		u64 bus_addr;
	};
	u64 cpu_addr;
	u64 size;
	u32 flags;
};

struct msi_domain_ops {
	irq_hw_number_t (*get_hwirq)(struct msi_domain_info *, msi_alloc_info_t *);
	int (*msi_init)(struct irq_domain *, struct msi_domain_info *, unsigned int, irq_hw_number_t, msi_alloc_info_t *);
	void (*msi_free)(struct irq_domain *, struct msi_domain_info *, unsigned int);
	int (*msi_prepare)(struct irq_domain *, struct device *, int, msi_alloc_info_t *);
	void (*prepare_desc)(struct irq_domain *, msi_alloc_info_t *, struct msi_desc *);
	void (*set_desc)(msi_alloc_info_t *, struct msi_desc *);
	int (*domain_alloc_irqs)(struct irq_domain *, struct device *, int);
	void (*domain_free_irqs)(struct irq_domain *, struct device *);
	void (*msi_post_free)(struct irq_domain *, struct device *);
	int (*msi_translate)(struct irq_domain *, struct irq_fwspec *, irq_hw_number_t *, unsigned int *);
};

struct msi_domain_info {
	u32 flags;
	enum irq_domain_bus_token bus_token;
	unsigned int hwsize;
	struct msi_domain_ops *ops;
	struct irq_chip *chip;
	void *chip_data;
	irq_flow_handler_t handler;
	void *handler_data;
	const char *handler_name;
	void *data;
};

struct pci_intx_virq {
	int virq;
	struct kref kref;
	struct list_head list_node;
};

enum {
	IRQ_SET_MASK_OK = 0,
	IRQ_SET_MASK_OK_NOCOPY = 1,
	IRQ_SET_MASK_OK_DONE = 2,
};

struct icp_ops {
	unsigned int (*get_irq)();
	void (*eoi)(struct irq_data *);
	void (*set_priority)(unsigned char);
	void (*teardown_cpu)();
	void (*flush_ipi)();
	void (*cause_ipi)(int);
	irq_handler_t ipi_action;
};

struct ics {
	struct list_head link;
	int (*check)(struct ics *, unsigned int);
	void (*mask_unknown)(struct ics *, long unsigned int);
	long int (*get_server)(struct ics *, long unsigned int);
	int (*host_match)(struct ics *, struct device_node *);
	struct irq_chip *chip;
	char data[0];
};

struct cpu_spec;

typedef void (*cpu_setup_t)(long unsigned int, struct cpu_spec *);

enum powerpc_pmc_type {
	PPC_PMC_DEFAULT = 0,
	PPC_PMC_IBM = 1,
	PPC_PMC_PA6T = 2,
	PPC_PMC_G4 = 3,
};

typedef void (*cpu_restore_t)();

struct cpu_spec {
	unsigned int pvr_mask;
	unsigned int pvr_value;
	char *cpu_name;
	long unsigned int cpu_features;
	unsigned int cpu_user_features;
	unsigned int cpu_user_features2;
	unsigned int mmu_features;
	unsigned int icache_bsize;
	unsigned int dcache_bsize;
	void (*cpu_down_flush)();
	unsigned int num_pmcs;
	enum powerpc_pmc_type pmc_type;
	cpu_setup_t cpu_setup;
	cpu_restore_t cpu_restore;
	char *platform;
	int (*machine_check)(struct pt_regs *);
	long int (*machine_check_early)(struct pt_regs *);
};

enum perf_event_task_context {
	perf_invalid_context = -1,
	perf_hw_context = 0,
	perf_sw_context = 1,
	perf_nr_task_contexts = 2,
};

typedef bool (*smp_cond_func_t)(int, void *);

enum perf_type_id {
	PERF_TYPE_HARDWARE = 0,
	PERF_TYPE_SOFTWARE = 1,
	PERF_TYPE_TRACEPOINT = 2,
	PERF_TYPE_HW_CACHE = 3,
	PERF_TYPE_RAW = 4,
	PERF_TYPE_BREAKPOINT = 5,
	PERF_TYPE_MAX = 6,
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

struct mmcr_regs {
	long unsigned int mmcr0;
	long unsigned int mmcr1;
	long unsigned int mmcr2;
	long unsigned int mmcra;
	long unsigned int mmcr3;
};

struct power_pmu {
	const char *name;
	int n_counter;
	int max_alternatives;
	long unsigned int add_fields;
	long unsigned int test_adder;
	int (*compute_mmcr)(u64 *, int, unsigned int *, struct mmcr_regs *, struct perf_event **, u32);
	int (*get_constraint)(u64, long unsigned int *, long unsigned int *, u64);
	int (*get_alternatives)(u64, unsigned int, u64 *);
	void (*get_mem_data_src)(union perf_mem_data_src *, u32, struct pt_regs *);
	void (*get_mem_weight)(u64 *, u64);
	long unsigned int group_constraint_mask;
	long unsigned int group_constraint_val;
	u64 (*bhrb_filter_map)(u64);
	void (*config_bhrb)(u64);
	void (*disable_pmc)(unsigned int, struct mmcr_regs *);
	int (*limited_pmc_event)(u64);
	u32 flags;
	const struct attribute_group **attr_groups;
	int n_generic;
	int *generic_events;
	u64 (*cache_events)[42];
	int n_blacklist_ev;
	int *blacklist_ev;
	int bhrb_nr;
	int capabilities;
	int (*check_attr_config)(struct perf_event *);
};

struct perf_pmu_events_attr {
	struct device_attribute attr;
	u64 id;
	const char *event_str;
};

typedef void (*perf_irq_t)(struct pt_regs *);

struct cpu_hw_events {
	int n_events;
	int n_percpu;
	int disabled;
	int n_added;
	int n_limited;
	u8 pmcs_enabled;
	struct perf_event *event[8];
	u64 events[8];
	unsigned int flags[8];
	struct mmcr_regs mmcr;
	struct perf_event *limited_counter[2];
	u8 limited_hwidx[2];
	u64 alternatives[64];
	long unsigned int amasks[64];
	long unsigned int avalues[64];
	unsigned int txn_flags;
	int n_txn_start;
	u64 bhrb_filter;
	unsigned int bhrb_users;
	void *bhrb_context;
	struct perf_branch_stack bhrb_stack;
	struct perf_branch_entry bhrb_entries[32];
	u64 ic_init;
	long unsigned int pmcs[8];
};

enum lockdep_ok {
	LOCKDEP_STILL_OK = 0,
	LOCKDEP_NOW_UNRELIABLE = 1,
};

struct pin_cookie {};

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

struct preempt_notifier;

struct preempt_ops {
	void (*sched_in)(struct preempt_notifier *, int);
	void (*sched_out)(struct preempt_notifier *, struct task_struct *);
};

struct preempt_notifier {
	struct hlist_node link;
	struct preempt_ops *ops;
};

typedef struct {
	void *lock;
} class_preempt_t;

typedef struct {
	void *lock;
	long unsigned int flags;
} class_irqsave_t;

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

typedef int (*task_call_f)(struct task_struct *, void *);

struct wait_bit_key {
	void *flags;
	int bit_nr;
	long unsigned int timeout;
};

struct wait_bit_queue_entry {
	struct wait_bit_key key;
	struct wait_queue_entry wq_entry;
};

enum mm_cid_state {
	MM_CID_UNSET = 4294967295,
	MM_CID_LAZY_PUT = 2147483648,
};

struct plist_head {
	struct list_head node_list;
};

enum uclamp_id {
	UCLAMP_MIN = 0,
	UCLAMP_MAX = 1,
	UCLAMP_CNT = 2,
};

struct dl_bw {
	raw_spinlock_t lock;
	u64 bw;
	u64 total_bw;
};

struct cpudl_item;

struct cpudl {
	raw_spinlock_t lock;
	int size;
	cpumask_var_t free_cpus;
	struct cpudl_item *elements;
};

struct cpupri_vec {
	atomic_t count;
	cpumask_var_t mask;
};

struct cpupri {
	struct cpupri_vec pri_to_cpu[101];
	int *cpu_to_pri;
};

struct perf_domain;

struct root_domain {
	atomic_t refcount;
	atomic_t rto_count;
	struct callback_head rcu;
	cpumask_var_t span;
	cpumask_var_t online;
	int overload;
	int overutilized;
	cpumask_var_t dlo_mask;
	atomic_t dlo_count;
	struct dl_bw dl_bw;
	struct cpudl cpudl;
	u64 visit_gen;
	struct irq_work rto_push_work;
	raw_spinlock_t rto_lock;
	int rto_loop;
	int rto_cpu;
	atomic_t rto_loop_next;
	atomic_t rto_loop_start;
	cpumask_var_t rto_mask;
	struct cpupri cpupri;
	long unsigned int max_cpu_capacity;
	struct perf_domain *pd;
};

struct sched_param {
	int sched_priority;
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
	unsigned int nr_spread_over;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg;
	struct {
		raw_spinlock_t lock;
		int nr;
		long unsigned int load_avg;
		long unsigned int util_avg;
		long unsigned int runnable_avg;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	} removed;
	u64 last_update_tg_load_avg;
	long unsigned int tg_load_avg_contrib;
	long int propagate;
	long int prop_runnable_sum;
	long unsigned int h_load;
	u64 last_h_load_update;
	struct sched_entity *h_load_next;
	struct rq *rq;
	int on_list;
	struct list_head leaf_cfs_rq_list;
	struct task_group *tg;
	int idle;
	int runtime_enabled;
	s64 runtime_remaining;
	u64 throttled_pelt_idle;
	u64 throttled_clock;
	u64 throttled_clock_pelt;
	u64 throttled_clock_pelt_time;
	u64 throttled_clock_self;
	u64 throttled_clock_self_time;
	int throttled;
	int throttle_count;
	struct list_head throttled_list;
	struct list_head throttled_csd_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct rt_prio_array {
	long unsigned int bitmap[2];
	struct list_head queue[100];
};

struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
	struct {
		int curr;
		int next;
	} highest_prio;
	int overloaded;
	struct plist_head pushable_tasks;
	int rt_queued;
	int rt_throttled;
	u64 rt_time;
	u64 rt_runtime;
	raw_spinlock_t rt_runtime_lock;
};

struct dl_rq {
	struct rb_root_cached root;
	unsigned int dl_nr_running;
	struct {
		u64 curr;
		u64 next;
	} earliest_dl;
	int overloaded;
	struct rb_root_cached pushable_dl_tasks_root;
	u64 running_bw;
	u64 this_bw;
	u64 extra_bw;
	u64 max_bw;
	u64 bw_ratio;
};

struct cpu_stop_done;

struct cpu_stop_work {
	struct list_head list;
	cpu_stop_fn_t fn;
	long unsigned int caller;
	void *arg;
	struct cpu_stop_done *done;
};

struct sched_domain;

struct balance_callback;

struct rq {
	raw_spinlock_t __lock;
	unsigned int nr_running;
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
	long unsigned int last_blocked_load_update_tick;
	unsigned int has_blocked_load;
	long: 64;
	long: 64;
	long: 64;
	call_single_data_t nohz_csd;
	unsigned int nohz_tick_stopped;
	atomic_t nohz_flags;
	unsigned int ttwu_pending;
	u64 nr_switches;
	long: 64;
	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;
	struct list_head leaf_cfs_rq_list;
	struct list_head *tmp_alone_branch;
	unsigned int nr_uninterruptible;
	struct task_struct *curr;
	struct task_struct *idle;
	struct task_struct *stop;
	long unsigned int next_balance;
	struct mm_struct *prev_mm;
	unsigned int clock_update_flags;
	u64 clock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u64 clock_task;
	u64 clock_pelt;
	long unsigned int lost_idle_time;
	u64 clock_pelt_idle;
	u64 clock_idle;
	atomic_t nr_iowait;
	u64 last_seen_need_resched_ns;
	int ticks_without_resched;
	int membarrier_state;
	struct root_domain *rd;
	struct sched_domain *sd;
	long unsigned int cpu_capacity;
	struct balance_callback *balance_callback;
	unsigned char nohz_idle_balance;
	unsigned char idle_balance;
	long unsigned int misfit_task_load;
	int active_balance;
	int push_cpu;
	struct cpu_stop_work active_balance_work;
	int cpu;
	int online;
	struct list_head cfs_tasks;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg_rt;
	struct sched_avg avg_dl;
	struct sched_avg avg_irq;
	u64 idle_stamp;
	u64 avg_idle;
	u64 max_idle_balance_cost;
	struct rcuwait hotplug_wait;
	u64 prev_steal_time;
	u64 prev_steal_time_rq;
	long unsigned int calc_load_update;
	long int calc_load_active;
	call_single_data_t hrtick_csd;
	struct hrtimer hrtick_timer;
	ktime_t hrtick_time;
	struct sched_info rq_sched_info;
	long long unsigned int rq_cpu_time;
	unsigned int yld_count;
	unsigned int sched_count;
	unsigned int sched_goidle;
	unsigned int ttwu_count;
	unsigned int ttwu_local;
	struct cpuidle_state *idle_state;
	unsigned int nr_pinned;
	unsigned int push_busy;
	struct cpu_stop_work push_work;
	cpumask_var_t scratch_mask;
	long: 64;
	long: 64;
	long: 64;
	call_single_data_t cfsb_csd;
	struct list_head cfsb_csd_list;
	long: 64;
	long: 64;
};

struct cfs_bandwidth {
	raw_spinlock_t lock;
	ktime_t period;
	u64 quota;
	u64 runtime;
	u64 burst;
	u64 runtime_snap;
	s64 hierarchical_quota;
	u8 idle;
	u8 period_active;
	u8 slack_started;
	struct hrtimer period_timer;
	struct hrtimer slack_timer;
	struct list_head throttled_cfs_rq;
	int nr_periods;
	int nr_throttled;
	int nr_burst;
	u64 throttled_time;
	u64 burst_time;
};

struct task_group {
	struct cgroup_subsys_state css;
	struct sched_entity **se;
	struct cfs_rq **cfs_rq;
	long unsigned int shares;
	int idle;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t load_avg;
	struct callback_head rcu;
	struct list_head list;
	struct task_group *parent;
	struct list_head siblings;
	struct list_head children;
	struct autogroup *autogroup;
	struct cfs_bandwidth cfs_bandwidth;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct io_ring_ctx;

struct io_wq;

struct io_uring_task {
	int cached_refs;
	const struct io_ring_ctx *last;
	struct io_wq *io_wq;
	struct file *registered_rings[16];
	struct xarray xa;
	struct wait_queue_head wait;
	atomic_t in_cancel;
	atomic_t inflight_tracked;
	struct percpu_counter inflight;
	long: 64;
	long: 64;
	struct {
		struct llist_head task_list;
		struct callback_head task_work;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
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
};

enum {
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY = 1,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED = 2,
	MEMBARRIER_STATE_GLOBAL_EXPEDITED_READY = 4,
	MEMBARRIER_STATE_GLOBAL_EXPEDITED = 8,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY = 16,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE = 32,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ_READY = 64,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ = 128,
};

struct trace_print_flags {
	long unsigned int mask;
	const char *name;
};

struct kernel_clone_args {
	u64 flags;
	int *pidfd;
	int *child_tid;
	int *parent_tid;
	const char *name;
	int exit_signal;
	u32 kthread: 1;
	u32 io_thread: 1;
	u32 user_worker: 1;
	u32 no_files: 1;
	long unsigned int stack;
	long unsigned int stack_size;
	long unsigned int tls;
	pid_t *set_tid;
	size_t set_tid_size;
	int cgroup;
	int idle;
	int (*fn)(void *);
	void *fn_arg;
	struct cgroup *cgrp;
	struct css_set *cset;
};

struct autogroup {
	struct kref kref;
	struct task_group *tg;
	struct rw_semaphore lock;
	long unsigned int id;
	int nice;
};

typedef int __kernel_rwf_t;

struct sched_domain_attr {
	int relax_domain_level;
};

struct sched_domain_shared {
	atomic_t ref;
	atomic_t nr_busy_cpus;
	int has_idle_cores;
	int nr_idle_scan;
};

struct sched_group;

struct sched_domain {
	struct sched_domain *parent;
	struct sched_domain *child;
	struct sched_group *groups;
	long unsigned int min_interval;
	long unsigned int max_interval;
	unsigned int busy_factor;
	unsigned int imbalance_pct;
	unsigned int cache_nice_tries;
	unsigned int imb_numa_nr;
	int nohz_idle;
	int flags;
	int level;
	long unsigned int last_balance;
	unsigned int balance_interval;
	unsigned int nr_balance_failed;
	u64 max_newidle_lb_cost;
	long unsigned int last_decay_max_lb_cost;
	unsigned int lb_count[3];
	unsigned int lb_failed[3];
	unsigned int lb_balanced[3];
	unsigned int lb_imbalance[3];
	unsigned int lb_gained[3];
	unsigned int lb_hot_gained[3];
	unsigned int lb_nobusyg[3];
	unsigned int lb_nobusyq[3];
	unsigned int alb_count;
	unsigned int alb_failed;
	unsigned int alb_pushed;
	unsigned int sbe_count;
	unsigned int sbe_balanced;
	unsigned int sbe_pushed;
	unsigned int sbf_count;
	unsigned int sbf_balanced;
	unsigned int sbf_pushed;
	unsigned int ttwu_wake_remote;
	unsigned int ttwu_move_affine;
	unsigned int ttwu_move_balance;
	char *name;
	union {
		void *private;
		struct callback_head rcu;
	};
	struct sched_domain_shared *shared;
	unsigned int span_weight;
	long unsigned int span[0];
};

struct sched_group_capacity;

struct sched_group {
	struct sched_group *next;
	atomic_t ref;
	unsigned int group_weight;
	unsigned int cores;
	struct sched_group_capacity *sgc;
	int asym_prefer_cpu;
	int flags;
	long unsigned int cpumask[0];
};

struct sched_group_capacity {
	atomic_t ref;
	long unsigned int capacity;
	long unsigned int min_capacity;
	long unsigned int max_capacity;
	long unsigned int next_update;
	int imbalance;
	int id;
	long unsigned int cpumask[0];
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

typedef struct {
	void *lock;
} class_cpus_read_lock_t;

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

struct kernel_cpustat {
	u64 cpustat[10];
};

enum {
	CFTYPE_ONLY_ON_ROOT = 1,
	CFTYPE_NOT_ON_ROOT = 2,
	CFTYPE_NS_DELEGATABLE = 4,
	CFTYPE_NO_PREFIX = 8,
	CFTYPE_WORLD_WRITABLE = 16,
	CFTYPE_DEBUG = 32,
	__CFTYPE_ONLY_ON_DFL = 65536,
	__CFTYPE_NOT_ON_DFL = 131072,
	__CFTYPE_ADDED = 262144,
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

enum numa_vmaskip_reason {
	NUMAB_SKIP_UNSUITABLE = 0,
	NUMAB_SKIP_SHARED_RO = 1,
	NUMAB_SKIP_INACCESSIBLE = 2,
	NUMAB_SKIP_SCAN_DELAY = 3,
	NUMAB_SKIP_PID_INACTIVE = 4,
	NUMAB_SKIP_IGNORE_PID = 5,
	NUMAB_SKIP_SEQ_COMPLETED = 6,
};

struct trace_event_raw_sched_kthread_stop {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	char __data[0];
};

struct trace_event_raw_sched_kthread_stop_ret {
	struct trace_entry ent;
	int ret;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_queue_work {
	struct trace_entry ent;
	void *work;
	void *function;
	void *worker;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_execute_start {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_execute_end {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_sched_wakeup_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int target_cpu;
	char __data[0];
};

struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long int prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
	char __data[0];
};

struct trace_event_raw_sched_migrate_task {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int orig_cpu;
	int dest_cpu;
	char __data[0];
};

struct trace_event_raw_sched_process_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

struct trace_event_raw_sched_process_wait {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	char parent_comm[16];
	pid_t parent_pid;
	char child_comm[16];
	pid_t child_pid;
	char __data[0];
};

struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	u32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
	char __data[0];
};

struct trace_event_raw_sched_stat_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	u64 delay;
	char __data[0];
};

struct trace_event_raw_sched_stat_runtime {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	u64 runtime;
	char __data[0];
};

struct trace_event_raw_sched_pi_setprio {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int oldprio;
	int newprio;
	char __data[0];
};

struct trace_event_raw_sched_process_hang {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	char __data[0];
};

struct trace_event_raw_sched_move_numa {
	struct trace_entry ent;
	pid_t pid;
	pid_t tgid;
	pid_t ngid;
	int src_cpu;
	int src_nid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};

struct trace_event_raw_sched_numa_pair_template {
	struct trace_entry ent;
	pid_t src_pid;
	pid_t src_tgid;
	pid_t src_ngid;
	int src_cpu;
	int src_nid;
	pid_t dst_pid;
	pid_t dst_tgid;
	pid_t dst_ngid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};

struct trace_event_raw_sched_skip_vma_numa {
	struct trace_entry ent;
	long unsigned int numa_scan_offset;
	long unsigned int vm_start;
	long unsigned int vm_end;
	enum numa_vmaskip_reason reason;
	char __data[0];
};

struct trace_event_raw_sched_wake_idle_without_ipi {
	struct trace_entry ent;
	int cpu;
	char __data[0];
};

struct trace_event_data_offsets_sched_kthread_stop {};

struct trace_event_data_offsets_sched_kthread_stop_ret {};

struct trace_event_data_offsets_sched_kthread_work_queue_work {};

struct trace_event_data_offsets_sched_kthread_work_execute_start {};

struct trace_event_data_offsets_sched_kthread_work_execute_end {};

struct trace_event_data_offsets_sched_wakeup_template {};

struct trace_event_data_offsets_sched_switch {};

struct trace_event_data_offsets_sched_migrate_task {};

struct trace_event_data_offsets_sched_process_template {};

struct trace_event_data_offsets_sched_process_wait {};

struct trace_event_data_offsets_sched_process_fork {};

struct trace_event_data_offsets_sched_process_exec {
	u32 filename;
	const void *filename_ptr_;
};

struct trace_event_data_offsets_sched_stat_template {};

struct trace_event_data_offsets_sched_stat_runtime {};

struct trace_event_data_offsets_sched_pi_setprio {};

struct trace_event_data_offsets_sched_process_hang {};

struct trace_event_data_offsets_sched_move_numa {};

struct trace_event_data_offsets_sched_numa_pair_template {};

struct trace_event_data_offsets_sched_skip_vma_numa {};

struct trace_event_data_offsets_sched_wake_idle_without_ipi {};

typedef void (*btf_trace_sched_kthread_stop)(void *, struct task_struct *);

typedef void (*btf_trace_sched_kthread_stop_ret)(void *, int);

typedef void (*btf_trace_sched_kthread_work_queue_work)(void *, struct kthread_worker *, struct kthread_work *);

typedef void (*btf_trace_sched_kthread_work_execute_start)(void *, struct kthread_work *);

typedef void (*btf_trace_sched_kthread_work_execute_end)(void *, struct kthread_work *, kthread_work_func_t);

typedef void (*btf_trace_sched_waking)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wakeup)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wakeup_new)(void *, struct task_struct *);

typedef void (*btf_trace_sched_switch)(void *, bool, struct task_struct *, struct task_struct *, unsigned int);

typedef void (*btf_trace_sched_migrate_task)(void *, struct task_struct *, int);

typedef void (*btf_trace_sched_process_free)(void *, struct task_struct *);

typedef void (*btf_trace_sched_process_exit)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wait_task)(void *, struct task_struct *);

typedef void (*btf_trace_sched_process_wait)(void *, struct pid *);

typedef void (*btf_trace_sched_process_fork)(void *, struct task_struct *, struct task_struct *);

typedef void (*btf_trace_sched_process_exec)(void *, struct task_struct *, pid_t, struct linux_binprm *);

typedef void (*btf_trace_sched_stat_wait)(void *, struct task_struct *, u64);

typedef void (*btf_trace_sched_stat_sleep)(void *, struct task_struct *, u64);

typedef void (*btf_trace_sched_stat_iowait)(void *, struct task_struct *, u64);

typedef void (*btf_trace_sched_stat_blocked)(void *, struct task_struct *, u64);

typedef void (*btf_trace_sched_stat_runtime)(void *, struct task_struct *, u64);

typedef void (*btf_trace_sched_pi_setprio)(void *, struct task_struct *, struct task_struct *);

typedef void (*btf_trace_sched_process_hang)(void *, struct task_struct *);

typedef void (*btf_trace_sched_move_numa)(void *, struct task_struct *, int, int);

typedef void (*btf_trace_sched_stick_numa)(void *, struct task_struct *, int, struct task_struct *, int);

typedef void (*btf_trace_sched_swap_numa)(void *, struct task_struct *, int, struct task_struct *, int);

typedef void (*btf_trace_sched_skip_vma_numa)(void *, struct mm_struct *, struct vm_area_struct *, enum numa_vmaskip_reason);

typedef void (*btf_trace_sched_wake_idle_without_ipi)(void *, int);

typedef void (*btf_trace_pelt_cfs_tp)(void *, struct cfs_rq *);

typedef void (*btf_trace_pelt_rt_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_dl_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_thermal_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_irq_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_se_tp)(void *, struct sched_entity *);

typedef void (*btf_trace_sched_cpu_capacity_tp)(void *, struct rq *);

typedef void (*btf_trace_sched_overutilized_tp)(void *, struct root_domain *, bool);

typedef void (*btf_trace_sched_util_est_cfs_tp)(void *, struct cfs_rq *);

typedef void (*btf_trace_sched_util_est_se_tp)(void *, struct sched_entity *);

typedef void (*btf_trace_sched_update_nr_running_tp)(void *, struct rq *, int);

typedef void (*btf_trace_sched_compute_energy_tp)(void *, struct task_struct *, int, long unsigned int, long unsigned int, long unsigned int);

struct trace_event_raw_ipi_raise {
	struct trace_entry ent;
	u32 __data_loc_target_cpus;
	const char *reason;
	char __data[0];
};

struct trace_event_raw_ipi_send_cpu {
	struct trace_entry ent;
	unsigned int cpu;
	void *callsite;
	void *callback;
	char __data[0];
};

struct trace_event_raw_ipi_send_cpumask {
	struct trace_entry ent;
	u32 __data_loc_cpumask;
	void *callsite;
	void *callback;
	char __data[0];
};

struct trace_event_raw_ipi_handler {
	struct trace_entry ent;
	const char *reason;
	char __data[0];
};

struct trace_event_data_offsets_ipi_raise {
	u32 target_cpus;
	const void *target_cpus_ptr_;
};

struct trace_event_data_offsets_ipi_send_cpu {};

struct trace_event_data_offsets_ipi_send_cpumask {
	u32 cpumask;
	const void *cpumask_ptr_;
};

struct trace_event_data_offsets_ipi_handler {};

typedef void (*btf_trace_ipi_raise)(void *, const struct cpumask *, const char *);

typedef void (*btf_trace_ipi_send_cpu)(void *, const unsigned int, long unsigned int, void *);

typedef void (*btf_trace_ipi_send_cpumask)(void *, const struct cpumask *, long unsigned int, void *);

typedef void (*btf_trace_ipi_entry)(void *, const char *);

typedef void (*btf_trace_ipi_exit)(void *, const char *);

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

struct cpudl_item {
	u64 dl;
	int cpu;
	int idx;
};

struct rt_bandwidth {
	raw_spinlock_t rt_runtime_lock;
	ktime_t rt_period;
	u64 rt_runtime;
	struct hrtimer rt_period_timer;
	unsigned int rt_period_active;
};

typedef int (*tg_visitor)(struct task_group *, void *);

struct perf_domain {
	struct em_perf_domain *em_pd;
	struct perf_domain *next;
	struct callback_head rcu;
};

struct balance_callback {
	struct balance_callback *next;
	void (*func)(struct rq *);
};

struct rq_flags {
	long unsigned int flags;
	struct pin_cookie cookie;
	unsigned int clock_update_flags;
};

typedef struct {
	struct task_struct *lock;
	struct rq *rq;
	struct rq_flags rf;
} class_task_rq_lock_t;

typedef struct {
	struct rq *lock;
	struct rq_flags rf;
} class_rq_lock_irq_t;

typedef struct {
	struct rq *lock;
	struct rq_flags rf;
} class_rq_lock_irqsave_t;

struct sched_entity_stats {
	struct sched_entity se;
	struct sched_statistics stats;
};

enum {
	__SCHED_FEAT_PLACE_LAG = 0,
	__SCHED_FEAT_PLACE_DEADLINE_INITIAL = 1,
	__SCHED_FEAT_RUN_TO_PARITY = 2,
	__SCHED_FEAT_NEXT_BUDDY = 3,
	__SCHED_FEAT_CACHE_HOT_BUDDY = 4,
	__SCHED_FEAT_WAKEUP_PREEMPTION = 5,
	__SCHED_FEAT_HRTICK = 6,
	__SCHED_FEAT_HRTICK_DL = 7,
	__SCHED_FEAT_DOUBLE_TICK = 8,
	__SCHED_FEAT_NONTASK_CAPACITY = 9,
	__SCHED_FEAT_TTWU_QUEUE = 10,
	__SCHED_FEAT_SIS_UTIL = 11,
	__SCHED_FEAT_WARN_DOUBLE_CLOCK = 12,
	__SCHED_FEAT_RT_PUSH_IPI = 13,
	__SCHED_FEAT_RT_RUNTIME_SHARE = 14,
	__SCHED_FEAT_LB_MIN = 15,
	__SCHED_FEAT_ATTACH_AGE_LOAD = 16,
	__SCHED_FEAT_WA_IDLE = 17,
	__SCHED_FEAT_WA_WEIGHT = 18,
	__SCHED_FEAT_WA_BIAS = 19,
	__SCHED_FEAT_UTIL_EST = 20,
	__SCHED_FEAT_LATENCY_WARN = 21,
	__SCHED_FEAT_HZ_BW = 22,
	__SCHED_FEAT_NR = 23,
};

struct affinity_context {
	const struct cpumask *new_mask;
	struct cpumask *user_mask;
	unsigned int flags;
};

typedef struct {
	raw_spinlock_t *lock;
	raw_spinlock_t *lock2;
} class_double_raw_spinlock_t;

typedef struct {
	struct rq *lock;
	struct rq *lock2;
} class_double_rq_lock_t;

struct io_uring_sqe {
	__u8 opcode;
	__u8 flags;
	__u16 ioprio;
	__s32 fd;
	union {
		__u64 off;
		__u64 addr2;
		struct {
			__u32 cmd_op;
			__u32 __pad1;
		};
	};
	union {
		__u64 addr;
		__u64 splice_off_in;
		struct {
			__u32 level;
			__u32 optname;
		};
	};
	__u32 len;
	union {
		__kernel_rwf_t rw_flags;
		__u32 fsync_flags;
		__u16 poll_events;
		__u32 poll32_events;
		__u32 sync_range_flags;
		__u32 msg_flags;
		__u32 timeout_flags;
		__u32 accept_flags;
		__u32 cancel_flags;
		__u32 open_flags;
		__u32 statx_flags;
		__u32 fadvise_advice;
		__u32 splice_flags;
		__u32 rename_flags;
		__u32 unlink_flags;
		__u32 hardlink_flags;
		__u32 xattr_flags;
		__u32 msg_ring_flags;
		__u32 uring_cmd_flags;
		__u32 waitid_flags;
		__u32 futex_flags;
		__u32 install_fd_flags;
	};
	__u64 user_data;
	union {
		__u16 buf_index;
		__u16 buf_group;
	};
	__u16 personality;
	union {
		__s32 splice_fd_in;
		__u32 file_index;
		__u32 optlen;
		struct {
			__u16 addr_len;
			__u16 __pad3[1];
		};
	};
	union {
		struct {
			__u64 addr3;
			__u64 __pad2[1];
		};
		__u64 optval;
		__u8 cmd[0];
	};
};

enum {
	IOSQE_FIXED_FILE_BIT = 0,
	IOSQE_IO_DRAIN_BIT = 1,
	IOSQE_IO_LINK_BIT = 2,
	IOSQE_IO_HARDLINK_BIT = 3,
	IOSQE_ASYNC_BIT = 4,
	IOSQE_BUFFER_SELECT_BIT = 5,
	IOSQE_CQE_SKIP_SUCCESS_BIT = 6,
};

enum io_uring_op {
	IORING_OP_NOP = 0,
	IORING_OP_READV = 1,
	IORING_OP_WRITEV = 2,
	IORING_OP_FSYNC = 3,
	IORING_OP_READ_FIXED = 4,
	IORING_OP_WRITE_FIXED = 5,
	IORING_OP_POLL_ADD = 6,
	IORING_OP_POLL_REMOVE = 7,
	IORING_OP_SYNC_FILE_RANGE = 8,
	IORING_OP_SENDMSG = 9,
	IORING_OP_RECVMSG = 10,
	IORING_OP_TIMEOUT = 11,
	IORING_OP_TIMEOUT_REMOVE = 12,
	IORING_OP_ACCEPT = 13,
	IORING_OP_ASYNC_CANCEL = 14,
	IORING_OP_LINK_TIMEOUT = 15,
	IORING_OP_CONNECT = 16,
	IORING_OP_FALLOCATE = 17,
	IORING_OP_OPENAT = 18,
	IORING_OP_CLOSE = 19,
	IORING_OP_FILES_UPDATE = 20,
	IORING_OP_STATX = 21,
	IORING_OP_READ = 22,
	IORING_OP_WRITE = 23,
	IORING_OP_FADVISE = 24,
	IORING_OP_MADVISE = 25,
	IORING_OP_SEND = 26,
	IORING_OP_RECV = 27,
	IORING_OP_OPENAT2 = 28,
	IORING_OP_EPOLL_CTL = 29,
	IORING_OP_SPLICE = 30,
	IORING_OP_PROVIDE_BUFFERS = 31,
	IORING_OP_REMOVE_BUFFERS = 32,
	IORING_OP_TEE = 33,
	IORING_OP_SHUTDOWN = 34,
	IORING_OP_RENAMEAT = 35,
	IORING_OP_UNLINKAT = 36,
	IORING_OP_MKDIRAT = 37,
	IORING_OP_SYMLINKAT = 38,
	IORING_OP_LINKAT = 39,
	IORING_OP_MSG_RING = 40,
	IORING_OP_FSETXATTR = 41,
	IORING_OP_SETXATTR = 42,
	IORING_OP_FGETXATTR = 43,
	IORING_OP_GETXATTR = 44,
	IORING_OP_SOCKET = 45,
	IORING_OP_URING_CMD = 46,
	IORING_OP_SEND_ZC = 47,
	IORING_OP_SENDMSG_ZC = 48,
	IORING_OP_READ_MULTISHOT = 49,
	IORING_OP_WAITID = 50,
	IORING_OP_FUTEX_WAIT = 51,
	IORING_OP_FUTEX_WAKE = 52,
	IORING_OP_FUTEX_WAITV = 53,
	IORING_OP_FIXED_FD_INSTALL = 54,
	IORING_OP_FTRUNCATE = 55,
	IORING_OP_LAST = 56,
};

struct io_uring_cqe {
	__u64 user_data;
	__s32 res;
	__u32 flags;
	__u64 big_cqe[0];
};

enum {
	IORING_REGISTER_BUFFERS = 0,
	IORING_UNREGISTER_BUFFERS = 1,
	IORING_REGISTER_FILES = 2,
	IORING_UNREGISTER_FILES = 3,
	IORING_REGISTER_EVENTFD = 4,
	IORING_UNREGISTER_EVENTFD = 5,
	IORING_REGISTER_FILES_UPDATE = 6,
	IORING_REGISTER_EVENTFD_ASYNC = 7,
	IORING_REGISTER_PROBE = 8,
	IORING_REGISTER_PERSONALITY = 9,
	IORING_UNREGISTER_PERSONALITY = 10,
	IORING_REGISTER_RESTRICTIONS = 11,
	IORING_REGISTER_ENABLE_RINGS = 12,
	IORING_REGISTER_FILES2 = 13,
	IORING_REGISTER_FILES_UPDATE2 = 14,
	IORING_REGISTER_BUFFERS2 = 15,
	IORING_REGISTER_BUFFERS_UPDATE = 16,
	IORING_REGISTER_IOWQ_AFF = 17,
	IORING_UNREGISTER_IOWQ_AFF = 18,
	IORING_REGISTER_IOWQ_MAX_WORKERS = 19,
	IORING_REGISTER_RING_FDS = 20,
	IORING_UNREGISTER_RING_FDS = 21,
	IORING_REGISTER_PBUF_RING = 22,
	IORING_UNREGISTER_PBUF_RING = 23,
	IORING_REGISTER_SYNC_CANCEL = 24,
	IORING_REGISTER_FILE_ALLOC_RANGE = 25,
	IORING_REGISTER_PBUF_STATUS = 26,
	IORING_REGISTER_NAPI = 27,
	IORING_UNREGISTER_NAPI = 28,
	IORING_REGISTER_LAST = 29,
	IORING_REGISTER_USE_REGISTERED_RING = 2147483648,
};

struct io_wq_work_node {
	struct io_wq_work_node *next;
};

struct io_wq_work_list {
	struct io_wq_work_node *first;
	struct io_wq_work_node *last;
};

struct io_wq_work {
	struct io_wq_work_node list;
	unsigned int flags;
	int cancel_seq;
};

struct io_fixed_file {
	long unsigned int file_ptr;
};

struct io_file_table {
	struct io_fixed_file *files;
	long unsigned int *bitmap;
	unsigned int alloc_hint;
};

struct io_hash_bucket {
	spinlock_t lock;
	struct hlist_head list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct io_hash_table {
	struct io_hash_bucket *hbs;
	unsigned int hash_bits;
};

struct io_kiocb;

struct io_submit_link {
	struct io_kiocb *head;
	struct io_kiocb *last;
};

struct io_submit_state {
	struct io_wq_work_node free_list;
	struct io_wq_work_list compl_reqs;
	struct io_submit_link link;
	bool plug_started;
	bool need_plug;
	short unsigned int submit_nr;
	unsigned int cqes_count;
	struct blk_plug plug;
};

struct io_alloc_cache {
	struct io_wq_work_node list;
	unsigned int nr_cached;
	unsigned int max_cached;
	size_t elem_size;
};

struct io_restriction {
	long unsigned int register_op[1];
	long unsigned int sqe_op[1];
	u8 sqe_flags_allowed;
	u8 sqe_flags_required;
	bool registered;
};

struct io_rings;

struct io_rsrc_node;

struct io_mapped_ubuf;

struct io_ev_fd;

struct io_sq_data;

struct io_rsrc_data;

struct io_wq_hash;

struct io_ring_ctx {
	struct {
		unsigned int flags;
		unsigned int drain_next: 1;
		unsigned int restricted: 1;
		unsigned int off_timeout_used: 1;
		unsigned int drain_active: 1;
		unsigned int has_evfd: 1;
		unsigned int task_complete: 1;
		unsigned int lockless_cq: 1;
		unsigned int syscall_iopoll: 1;
		unsigned int poll_activated: 1;
		unsigned int drain_disabled: 1;
		unsigned int compat: 1;
		unsigned int iowq_limits_set: 1;
		struct task_struct *submitter_task;
		struct io_rings *rings;
		struct percpu_ref refs;
		enum task_work_notify_mode notify_method;
		unsigned int sq_thread_idle;
		long: 64;
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
	struct {
		struct mutex uring_lock;
		u32 *sq_array;
		struct io_uring_sqe *sq_sqes;
		unsigned int cached_sq_head;
		unsigned int sq_entries;
		struct io_rsrc_node *rsrc_node;
		atomic_t cancel_seq;
		bool poll_multi_queue;
		struct io_wq_work_list iopoll_list;
		struct io_file_table file_table;
		struct io_mapped_ubuf **user_bufs;
		unsigned int nr_user_files;
		unsigned int nr_user_bufs;
		struct io_submit_state submit_state;
		struct xarray io_bl_xa;
		struct io_hash_table cancel_table_locked;
		struct io_alloc_cache apoll_cache;
		struct io_alloc_cache netmsg_cache;
		struct hlist_head cancelable_uring_cmd;
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
	struct {
		struct io_uring_cqe *cqe_cached;
		struct io_uring_cqe *cqe_sentinel;
		unsigned int cached_cq_tail;
		unsigned int cq_entries;
		struct io_ev_fd *io_ev_fd;
		unsigned int cq_extra;
		long: 64;
		long: 64;
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
	struct {
		struct llist_head work_llist;
		long unsigned int check_cq;
		atomic_t cq_wait_nr;
		atomic_t cq_timeouts;
		struct wait_queue_head cq_wait;
		long: 64;
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
	struct {
		spinlock_t timeout_lock;
		struct list_head timeout_list;
		struct list_head ltimeout_list;
		unsigned int cq_last_tm_flush;
		long: 64;
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
	struct io_uring_cqe completion_cqes[16];
	spinlock_t completion_lock;
	unsigned int locked_free_nr;
	struct io_wq_work_list locked_free_list;
	struct list_head io_buffers_comp;
	struct list_head cq_overflow_list;
	struct io_hash_table cancel_table;
	struct hlist_head waitid_list;
	struct hlist_head futex_list;
	struct io_alloc_cache futex_cache;
	const struct cred *sq_creds;
	struct io_sq_data *sq_data;
	struct wait_queue_head sqo_sq_wait;
	struct list_head sqd_list;
	unsigned int file_alloc_start;
	unsigned int file_alloc_end;
	struct list_head io_buffers_cache;
	struct hlist_head io_buf_list;
	struct wait_queue_head poll_wq;
	struct io_restriction restrictions;
	struct io_mapped_ubuf *dummy_ubuf;
	struct io_rsrc_data *file_data;
	struct io_rsrc_data *buf_data;
	struct list_head rsrc_ref_list;
	struct io_alloc_cache rsrc_node_cache;
	struct wait_queue_head rsrc_quiesce_wq;
	unsigned int rsrc_quiesce;
	u32 pers_next;
	struct xarray personalities;
	struct io_wq_hash *hash_map;
	struct user_struct *user;
	struct mm_struct *mm_account;
	struct llist_head fallback_llist;
	struct delayed_work fallback_work;
	struct work_struct exit_work;
	struct list_head tctx_list;
	struct completion ref_comp;
	u32 iowq_limits[2];
	struct callback_head poll_wq_task_work;
	struct list_head defer_list;
	struct list_head napi_list;
	spinlock_t napi_lock;
	unsigned int napi_busy_poll_to;
	bool napi_prefer_busy_poll;
	bool napi_enabled;
	struct hlist_head napi_ht[16];
	unsigned int evfd_last_cq_tail;
	short unsigned int n_ring_pages;
	short unsigned int n_sqe_pages;
	struct page **ring_pages;
	struct page **sqe_pages;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
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

struct io_uring {
	u32 head;
	u32 tail;
};

struct io_rings {
	struct io_uring sq;
	struct io_uring cq;
	u32 sq_ring_mask;
	u32 cq_ring_mask;
	u32 sq_ring_entries;
	u32 cq_ring_entries;
	u32 sq_dropped;
	atomic_t sq_flags;
	u32 cq_flags;
	u32 cq_overflow;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct io_uring_cqe cqes[0];
};

struct io_cmd_data {
	struct file *file;
	__u8 data[56];
};

typedef u64 io_req_flags_t;

struct io_cqe {
	__u64 user_data;
	__s32 res;
	union {
		__u32 flags;
		int fd;
	};
};

struct io_tw_state;

typedef void (*io_req_tw_func_t)(struct io_kiocb *, struct io_tw_state *);

struct io_task_work {
	struct llist_node node;
	io_req_tw_func_t func;
};

struct io_buffer;

struct io_buffer_list;

struct async_poll;

struct io_kiocb {
	union {
		struct file *file;
		struct io_cmd_data cmd;
	};
	u8 opcode;
	u8 iopoll_completed;
	u16 buf_index;
	unsigned int nr_tw;
	io_req_flags_t flags;
	struct io_cqe cqe;
	struct io_ring_ctx *ctx;
	struct task_struct *task;
	union {
		struct io_mapped_ubuf *imu;
		struct io_buffer *kbuf;
		struct io_buffer_list *buf_list;
	};
	union {
		struct io_wq_work_node comp_list;
		__poll_t apoll_events;
	};
	struct io_rsrc_node *rsrc_node;
	atomic_t refs;
	bool cancel_seq_set;
	struct io_task_work io_task_work;
	struct hlist_node hash_node;
	struct async_poll *apoll;
	void *async_data;
	atomic_t poll_refs;
	struct io_kiocb *link;
	const struct cred *creds;
	struct io_wq_work work;
	struct {
		u64 extra1;
		u64 extra2;
	} big_cqe;
};

struct io_ev_fd {
	struct eventfd_ctx *cq_ev_fd;
	unsigned int eventfd_async: 1;
	struct callback_head rcu;
	atomic_t refs;
	atomic_t ops;
};

struct io_wq_hash {
	refcount_t refs;
	long unsigned int map;
	struct wait_queue_head wait;
};

struct io_tw_state {
	bool locked;
};

enum {
	REQ_F_FIXED_FILE_BIT = 0,
	REQ_F_IO_DRAIN_BIT = 1,
	REQ_F_LINK_BIT = 2,
	REQ_F_HARDLINK_BIT = 3,
	REQ_F_FORCE_ASYNC_BIT = 4,
	REQ_F_BUFFER_SELECT_BIT = 5,
	REQ_F_CQE_SKIP_BIT = 6,
	REQ_F_FAIL_BIT = 8,
	REQ_F_INFLIGHT_BIT = 9,
	REQ_F_CUR_POS_BIT = 10,
	REQ_F_NOWAIT_BIT = 11,
	REQ_F_LINK_TIMEOUT_BIT = 12,
	REQ_F_NEED_CLEANUP_BIT = 13,
	REQ_F_POLLED_BIT = 14,
	REQ_F_BUFFER_SELECTED_BIT = 15,
	REQ_F_BUFFER_RING_BIT = 16,
	REQ_F_REISSUE_BIT = 17,
	REQ_F_CREDS_BIT = 18,
	REQ_F_REFCOUNT_BIT = 19,
	REQ_F_ARM_LTIMEOUT_BIT = 20,
	REQ_F_ASYNC_DATA_BIT = 21,
	REQ_F_SKIP_LINK_CQES_BIT = 22,
	REQ_F_SINGLE_POLL_BIT = 23,
	REQ_F_DOUBLE_POLL_BIT = 24,
	REQ_F_APOLL_MULTISHOT_BIT = 25,
	REQ_F_CLEAR_POLLIN_BIT = 26,
	REQ_F_HASH_LOCKED_BIT = 27,
	REQ_F_SUPPORT_NOWAIT_BIT = 28,
	REQ_F_ISREG_BIT = 29,
	REQ_F_POLL_NO_LAZY_BIT = 30,
	REQ_F_CANCEL_SEQ_BIT = 31,
	REQ_F_CAN_POLL_BIT = 32,
	REQ_F_BL_EMPTY_BIT = 33,
	REQ_F_BL_NO_RECYCLE_BIT = 34,
	__REQ_F_LAST_BIT = 35,
};

struct set_affinity_pending;

struct migration_arg {
	struct task_struct *task;
	int dest_cpu;
	struct set_affinity_pending *pending;
};

struct set_affinity_pending {
	refcount_t refs;
	unsigned int stop_pending;
	struct completion done;
	struct cpu_stop_work stop_work;
	struct migration_arg arg;
};

struct migration_swap_arg {
	struct task_struct *src_task;
	struct task_struct *dst_task;
	int src_cpu;
	int dst_cpu;
};

struct tick_work {
	int cpu;
	atomic_t state;
	struct delayed_work work;
};

typedef struct task_struct *class_find_get_task_t;

struct cfs_schedulable_data {
	struct task_group *tg;
	u64 period;
	u64 quota;
};

enum {
	cpuset = 0,
	possible = 1,
	fail = 2,
};

union cpumask_rcuhead {
	cpumask_t cpumask;
	struct callback_head rcu;
};

struct tmigr_event {
	struct timerqueue_node nextevt;
	unsigned int cpu;
	bool ignore;
};

struct tmigr_group {
	raw_spinlock_t lock;
	struct tmigr_group *parent;
	struct tmigr_event groupevt;
	u64 next_expiry;
	struct timerqueue_head events;
	atomic_t migr_state;
	unsigned int level;
	int numa_node;
	unsigned int num_children;
	u8 childmask;
	struct list_head list;
};

struct tmigr_cpu {
	raw_spinlock_t lock;
	bool online;
	bool idle;
	bool remote;
	struct tmigr_group *tmgroup;
	u8 childmask;
	u64 wakeup;
	struct tmigr_event cpuevt;
};

union tmigr_state {
	u32 state;
	struct {
		u8 active;
		u8 migrator;
		u16 seq;
	};
};

struct timer_events {
	u64 local;
	u64 global;
};

struct trace_event_raw_tmigr_group_set {
	struct trace_entry ent;
	void *group;
	unsigned int lvl;
	unsigned int numa_node;
	char __data[0];
};

struct trace_event_raw_tmigr_connect_child_parent {
	struct trace_entry ent;
	void *child;
	void *parent;
	unsigned int lvl;
	unsigned int numa_node;
	unsigned int num_children;
	u32 childmask;
	char __data[0];
};

struct trace_event_raw_tmigr_connect_cpu_parent {
	struct trace_entry ent;
	void *parent;
	unsigned int cpu;
	unsigned int lvl;
	unsigned int numa_node;
	unsigned int num_children;
	u32 childmask;
	char __data[0];
};

struct trace_event_raw_tmigr_group_and_cpu {
	struct trace_entry ent;
	void *group;
	void *parent;
	unsigned int lvl;
	unsigned int numa_node;
	u32 childmask;
	u8 active;
	u8 migrator;
	char __data[0];
};

struct trace_event_raw_tmigr_cpugroup {
	struct trace_entry ent;
	u64 wakeup;
	void *parent;
	unsigned int cpu;
	char __data[0];
};

struct trace_event_raw_tmigr_idle {
	struct trace_entry ent;
	u64 nextevt;
	u64 wakeup;
	void *parent;
	unsigned int cpu;
	char __data[0];
};

struct trace_event_raw_tmigr_update_events {
	struct trace_entry ent;
	void *child;
	void *group;
	u64 nextevt;
	u64 group_next_expiry;
	u64 child_evt_expiry;
	unsigned int group_lvl;
	unsigned int child_evtcpu;
	u8 child_active;
	u8 group_active;
	char __data[0];
};

struct trace_event_raw_tmigr_handle_remote {
	struct trace_entry ent;
	void *group;
	unsigned int lvl;
	char __data[0];
};

struct trace_event_data_offsets_tmigr_group_set {};

struct trace_event_data_offsets_tmigr_connect_child_parent {};

struct trace_event_data_offsets_tmigr_connect_cpu_parent {};

struct trace_event_data_offsets_tmigr_group_and_cpu {};

struct trace_event_data_offsets_tmigr_cpugroup {};

struct trace_event_data_offsets_tmigr_idle {};

struct trace_event_data_offsets_tmigr_update_events {};

struct trace_event_data_offsets_tmigr_handle_remote {};

typedef void (*btf_trace_tmigr_group_set)(void *, struct tmigr_group *);

typedef void (*btf_trace_tmigr_connect_child_parent)(void *, struct tmigr_group *);

typedef void (*btf_trace_tmigr_connect_cpu_parent)(void *, struct tmigr_cpu *);

typedef void (*btf_trace_tmigr_group_set_cpu_inactive)(void *, struct tmigr_group *, union tmigr_state, u32);

typedef void (*btf_trace_tmigr_group_set_cpu_active)(void *, struct tmigr_group *, union tmigr_state, u32);

typedef void (*btf_trace_tmigr_cpu_new_timer)(void *, struct tmigr_cpu *);

typedef void (*btf_trace_tmigr_cpu_active)(void *, struct tmigr_cpu *);

typedef void (*btf_trace_tmigr_cpu_online)(void *, struct tmigr_cpu *);

typedef void (*btf_trace_tmigr_cpu_offline)(void *, struct tmigr_cpu *);

typedef void (*btf_trace_tmigr_handle_remote_cpu)(void *, struct tmigr_cpu *);

typedef void (*btf_trace_tmigr_cpu_idle)(void *, struct tmigr_cpu *, u64);

typedef void (*btf_trace_tmigr_cpu_new_timer_idle)(void *, struct tmigr_cpu *, u64);

typedef void (*btf_trace_tmigr_update_events)(void *, struct tmigr_group *, struct tmigr_group *, union tmigr_state, union tmigr_state, u64);

typedef void (*btf_trace_tmigr_handle_remote)(void *, struct tmigr_group *);

typedef bool (*up_f)(struct tmigr_group *, struct tmigr_group *, void *);

struct tmigr_walk {
	u64 nextexp;
	u64 firstexp;
	struct tmigr_event *evt;
	u8 childmask;
	bool remote;
};

struct tmigr_remote_data {
	long unsigned int basej;
	u64 now;
	u64 firstexp;
	u8 childmask;
	bool check;
	bool tmc_active;
};

enum ring_buffer_type {
	RINGBUF_TYPE_DATA_TYPE_LEN_MAX = 28,
	RINGBUF_TYPE_PADDING = 29,
	RINGBUF_TYPE_TIME_EXTEND = 30,
	RINGBUF_TYPE_TIME_STAMP = 31,
};

typedef bool (*ring_buffer_cond_fn)(void *);

enum ring_buffer_flags {
	RB_FL_OVERWRITE = 1,
};

struct ring_buffer_per_cpu;

struct buffer_page;

struct ring_buffer_iter {
	struct ring_buffer_per_cpu *cpu_buffer;
	long unsigned int head;
	long unsigned int next_event;
	struct buffer_page *head_page;
	struct buffer_page *cache_reader_page;
	long unsigned int cache_read;
	long unsigned int cache_pages_removed;
	u64 read_stamp;
	u64 page_stamp;
	struct ring_buffer_event *event;
	size_t event_size;
	int missed_events;
};

struct rb_irq_work {
	struct irq_work work;
	wait_queue_head_t waiters;
	wait_queue_head_t full_waiters;
	atomic_t seq;
	bool waiters_pending;
	bool full_waiters_pending;
	bool wakeup_full;
};

struct trace_buffer {
	unsigned int flags;
	int cpus;
	atomic_t record_disabled;
	atomic_t resizing;
	cpumask_var_t cpumask;
	struct lock_class_key *reader_lock_key;
	struct mutex mutex;
	struct ring_buffer_per_cpu **buffers;
	struct hlist_node node;
	u64 (*clock)();
	struct rb_irq_work irq_work;
	bool time_stamp_abs;
	unsigned int subbuf_size;
	unsigned int subbuf_order;
	unsigned int max_data_size;
};

enum {
	RB_LEN_TIME_EXTEND = 8,
	RB_LEN_TIME_STAMP = 8,
};

struct buffer_data_page {
	u64 time_stamp;
	local_t commit;
	unsigned char data[0];
};

struct buffer_data_read_page {
	unsigned int order;
	struct buffer_data_page *data;
};

struct buffer_page {
	struct list_head list;
	local_t write;
	unsigned int read;
	local_t entries;
	long unsigned int real_end;
	unsigned int order;
	struct buffer_data_page *page;
};

struct rb_event_info {
	u64 ts;
	u64 delta;
	u64 before;
	u64 after;
	long unsigned int length;
	struct buffer_page *tail_page;
	int add_timestamp;
};

enum {
	RB_ADD_STAMP_NONE = 0,
	RB_ADD_STAMP_EXTEND = 2,
	RB_ADD_STAMP_ABSOLUTE = 4,
	RB_ADD_STAMP_FORCE = 8,
};

enum {
	RB_CTX_TRANSITION = 0,
	RB_CTX_NMI = 1,
	RB_CTX_IRQ = 2,
	RB_CTX_SOFTIRQ = 3,
	RB_CTX_NORMAL = 4,
	RB_CTX_MAX = 5,
};

struct rb_time_struct {
	local64_t time;
};

typedef struct rb_time_struct rb_time_t;

struct ring_buffer_per_cpu {
	int cpu;
	atomic_t record_disabled;
	atomic_t resize_disabled;
	struct trace_buffer *buffer;
	raw_spinlock_t reader_lock;
	arch_spinlock_t lock;
	struct lock_class_key lock_key;
	struct buffer_data_page *free_page;
	long unsigned int nr_pages;
	unsigned int current_context;
	struct list_head *pages;
	struct buffer_page *head_page;
	struct buffer_page *tail_page;
	struct buffer_page *commit_page;
	struct buffer_page *reader_page;
	long unsigned int lost_events;
	long unsigned int last_overrun;
	long unsigned int nest;
	local_t entries_bytes;
	local_t entries;
	local_t overrun;
	local_t commit_overrun;
	local_t dropped_events;
	local_t committing;
	local_t commits;
	local_t pages_touched;
	local_t pages_lost;
	local_t pages_read;
	long int last_pages_touch;
	size_t shortest_full;
	long unsigned int read;
	long unsigned int read_bytes;
	rb_time_t write_stamp;
	rb_time_t before_stamp;
	u64 event_stamp[5];
	u64 read_stamp;
	long unsigned int pages_removed;
	long int nr_pages_to_update;
	struct list_head new_pages;
	struct work_struct update_pages_work;
	struct completion update_done;
	struct rb_irq_work irq_work;
};

struct rb_wait_data {
	struct rb_irq_work *irq_work;
	int seq;
};

enum {
	BPF_F_BROADCAST = 8,
	BPF_F_EXCLUDE_INGRESS = 16,
};

struct bpf_cpumap_val {
	__u32 qsize;
	union {
		int fd;
		__u32 id;
	} bpf_prog;
};

struct bpf_nh_params {
	u32 nh_family;
	union {
		u32 ipv4_nh;
		struct in6_addr ipv6_nh;
	};
};

struct bpf_redirect_info {
	u64 tgt_index;
	void *tgt_value;
	struct bpf_map *map;
	u32 flags;
	u32 kern_flags;
	u32 map_id;
	enum bpf_map_type map_type;
	struct bpf_nh_params nh;
};

struct xdp_cpumap_stats {
	unsigned int redirect;
	unsigned int pass;
	unsigned int drop;
};

struct bpf_cpu_map_entry;

struct xdp_bulk_queue {
	void *q[8];
	struct list_head flush_node;
	struct bpf_cpu_map_entry *obj;
	unsigned int count;
};

struct bpf_cpu_map_entry {
	u32 cpu;
	int map_id;
	struct xdp_bulk_queue *bulkq;
	struct ptr_ring *queue;
	struct task_struct *kthread;
	struct bpf_cpumap_val value;
	struct bpf_prog *prog;
	struct completion kthread_running;
	struct rcu_work free_work;
};

struct bpf_cpu_map {
	struct bpf_map map;
	struct bpf_cpu_map_entry **cpu_map;
};

typedef struct {
	pgd_t pgd;
} p4d_t;

struct xa_node {
	unsigned char shift;
	unsigned char offset;
	unsigned char count;
	unsigned char nr_values;
	struct xa_node *parent;
	struct xarray *array;
	union {
		struct list_head private_list;
		struct callback_head callback_head;
	};
	void *slots[64];
	union {
		long unsigned int tags[3];
		long unsigned int marks[3];
	};
};

typedef void (*xa_update_node_t)(struct xa_node *);

struct xa_state {
	struct xarray *xa;
	long unsigned int xa_index;
	unsigned char xa_shift;
	unsigned char xa_sibs;
	unsigned char xa_offset;
	unsigned char xa_pad;
	struct xa_node *xa_node;
	struct xa_node *xa_alloc;
	xa_update_node_t xa_update;
	struct list_lru *xa_lru;
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

struct vma_swap_readahead {
	short unsigned int win;
	short unsigned int offset;
	short unsigned int nr_pte;
};

typedef struct {} local_lock_t;

typedef unsigned int isolate_mode_t;

enum zs_mapmode {
	ZS_MM_RW = 0,
	ZS_MM_RO = 1,
	ZS_MM_WO = 2,
};

struct zs_pool_stats {
	atomic_long_t pages_compacted;
};

enum zpool_mapmode {
	ZPOOL_MM_RW = 0,
	ZPOOL_MM_RO = 1,
	ZPOOL_MM_WO = 2,
	ZPOOL_MM_DEFAULT = 0,
};

struct zpool_driver {
	char *type;
	struct module *owner;
	atomic_t refcount;
	struct list_head list;
	void * (*create)(const char *, gfp_t);
	void (*destroy)(void *);
	bool malloc_support_movable;
	int (*malloc)(void *, size_t, gfp_t, long unsigned int *);
	void (*free)(void *, long unsigned int);
	bool sleep_mapped;
	void * (*map)(void *, long unsigned int, enum zpool_mapmode);
	void (*unmap)(void *, long unsigned int);
	u64 (*total_size)(void *);
};

struct movable_operations {
	bool (*isolate_page)(struct page *, isolate_mode_t);
	int (*migrate_page)(struct page *, struct page *, enum migrate_mode);
	void (*putback_page)(struct page *);
};

enum fullness_group {
	ZS_INUSE_RATIO_0 = 0,
	ZS_INUSE_RATIO_10 = 1,
	ZS_INUSE_RATIO_99 = 10,
	ZS_INUSE_RATIO_100 = 11,
	NR_FULLNESS_GROUPS = 12,
};

enum class_stat_type {
	ZS_OBJS_ALLOCATED = 12,
	ZS_OBJS_INUSE = 13,
	NR_CLASS_STAT_TYPES = 14,
};

struct zs_size_stat {
	long unsigned int objs[14];
};

struct size_class {
	struct list_head fullness_list[12];
	int size;
	int objs_per_zspage;
	int pages_per_zspage;
	unsigned int index;
	struct zs_size_stat stats;
};

struct link_free {
	union {
		long unsigned int next;
		long unsigned int handle;
	};
};

struct zs_pool {
	const char *name;
	struct size_class *size_class[257];
	struct kmem_cache *handle_cachep;
	struct kmem_cache *zspage_cachep;
	atomic_long_t pages_allocated;
	struct zs_pool_stats stats;
	struct shrinker *shrinker;
	struct work_struct free_work;
	spinlock_t lock;
	atomic_t compaction_in_progress;
};

struct zspage {
	struct {
		unsigned int huge: 1;
		unsigned int fullness: 4;
		unsigned int class: 9;
		unsigned int magic: 8;
	};
	unsigned int inuse;
	unsigned int freeobj;
	struct page *first_page;
	struct list_head list;
	struct zs_pool *pool;
	rwlock_t lock;
};

struct mapping_area {
	local_lock_t lock;
	char *vm_buf;
	char *vm_addr;
	enum zs_mapmode vm_mm;
};

typedef __kernel_ulong_t ino_t;

typedef int wait_bit_action_f(struct wait_bit_key *, int);

enum wb_state {
	WB_registered = 0,
	WB_writeback_running = 1,
	WB_has_dirty_io = 2,
	WB_start_all = 3,
};

enum page_memcg_data_flags {
	MEMCG_DATA_OBJCGS = 1,
	MEMCG_DATA_KMEM = 2,
	__NR_MEMCG_DATA_FLAGS = 4,
};

struct wb_writeback_work {
	long int nr_pages;
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

struct trace_event_raw_writeback_folio_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int index;
	char __data[0];
};

struct trace_event_raw_writeback_dirty_inode_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int state;
	long unsigned int flags;
	char __data[0];
};

struct trace_event_raw_inode_foreign_history {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	ino_t cgroup_ino;
	unsigned int history;
	char __data[0];
};

struct trace_event_raw_inode_switch_wbs {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	ino_t old_cgroup_ino;
	ino_t new_cgroup_ino;
	char __data[0];
};

struct trace_event_raw_track_foreign_dirty {
	struct trace_entry ent;
	char name[32];
	u64 bdi_id;
	ino_t ino;
	unsigned int memcg_id;
	ino_t cgroup_ino;
	ino_t page_cgroup_ino;
	char __data[0];
};

struct trace_event_raw_flush_foreign {
	struct trace_entry ent;
	char name[32];
	ino_t cgroup_ino;
	unsigned int frn_bdi_id;
	unsigned int frn_memcg_id;
	char __data[0];
};

struct trace_event_raw_writeback_write_inode_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	int sync_mode;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_work_class {
	struct trace_entry ent;
	char name[32];
	long int nr_pages;
	dev_t sb_dev;
	int sync_mode;
	int for_kupdate;
	int range_cyclic;
	int for_background;
	int reason;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_pages_written {
	struct trace_entry ent;
	long int pages;
	char __data[0];
};

struct trace_event_raw_writeback_class {
	struct trace_entry ent;
	char name[32];
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_bdi_register {
	struct trace_entry ent;
	char name[32];
	char __data[0];
};

struct trace_event_raw_wbc_class {
	struct trace_entry ent;
	char name[32];
	long int nr_to_write;
	long int pages_skipped;
	int sync_mode;
	int for_kupdate;
	int for_background;
	int for_reclaim;
	int range_cyclic;
	long int range_start;
	long int range_end;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_queue_io {
	struct trace_entry ent;
	char name[32];
	long unsigned int older;
	long int age;
	int moved;
	int reason;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_global_dirty_state {
	struct trace_entry ent;
	long unsigned int nr_dirty;
	long unsigned int nr_writeback;
	long unsigned int background_thresh;
	long unsigned int dirty_thresh;
	long unsigned int dirty_limit;
	long unsigned int nr_dirtied;
	long unsigned int nr_written;
	char __data[0];
};

struct trace_event_raw_bdi_dirty_ratelimit {
	struct trace_entry ent;
	char bdi[32];
	long unsigned int write_bw;
	long unsigned int avg_write_bw;
	long unsigned int dirty_rate;
	long unsigned int dirty_ratelimit;
	long unsigned int task_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_balance_dirty_pages {
	struct trace_entry ent;
	char bdi[32];
	long unsigned int limit;
	long unsigned int setpoint;
	long unsigned int dirty;
	long unsigned int bdi_setpoint;
	long unsigned int bdi_dirty;
	long unsigned int dirty_ratelimit;
	long unsigned int task_ratelimit;
	unsigned int dirtied;
	unsigned int dirtied_pause;
	long unsigned int paused;
	long int pause;
	long unsigned int period;
	long int think;
	ino_t cgroup_ino;
	char __data[0];
};

	ino_t ino;
