// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
#ifndef __INTF_H
#define __INTF_H

#include <stdbool.h>
#ifndef __kptr
#ifdef __KERNEL__
#error "__kptr_ref not defined in the kernel"
#endif
#define __kptr
#endif

#ifndef __KERNEL__
typedef unsigned char u8;
typedef unsigned short u16;
typedef int s32;
typedef unsigned u32;
typedef long long s64;
typedef unsigned long long u64;
#endif

enum consts {
	CACHELINE_SIZE		= 64,
	MAX_CPUS_SHIFT		= 9,
	MAX_CPUS		= 1 << MAX_CPUS_SHIFT,
	MAX_CPUS_U8		= MAX_CPUS / 8,
	MAX_TASKS		= 131072,
	MAX_PATH		= 4096,
	MAX_NUMA_NODES		= 32,
	MAX_LLCS		= 64,
	MAX_COMM		= 16,
	MAX_LAYER_MATCH_ORS	= 32,
	/* 64 chars for user-provided name, 64 for possible template suffix. */
	MAX_LAYER_NAME		= 128,
	MAX_LAYERS		= 16,
	MAX_CGROUP_REGEXES	= 16,
	MAX_LAYER_WEIGHT	= 10000,
	MIN_LAYER_WEIGHT	= 1,
	DEFAULT_LAYER_WEIGHT	= 100,
	USAGE_HALF_LIFE		= 100000000,	/* 100ms */
	RUNTIME_DECAY_FACTOR	= 4,
	DUTY_CYCLE_SHIFT	= 20,		/* duty_cycle 1.0 = 1 << 20 */
	LAYER_LAT_DECAY_FACTOR	= 32,
	CLEAR_PREEMPTING_AFTER	= 10000000,	/* 10ms */
	NUM_PROXIMITY_MAPS = 32,

	DSQ_ID_SPECIAL_MASK	= 0xc0000000,
	HI_FB_DSQ_BASE		= 0x40000000,
	LO_FB_DSQ_BASE		= 0x80000000,

	DSQ_ID_LAYER_SHIFT	= 16,
	DSQ_ID_LLC_MASK		= (1LLU << DSQ_ID_LAYER_SHIFT) - 1,		/* 0x0000ffff */
	DSQ_ID_LAYER_MASK	= ~DSQ_ID_LLC_MASK & ~DSQ_ID_SPECIAL_MASK,	/* 0x3fff0000 */

	/* XXX remove */
	MAX_CGRP_PREFIXES	= 32,

	NSEC_PER_USEC		= 1000ULL,
	NSEC_PER_MSEC		= (1000ULL * NSEC_PER_USEC),
	MSEC_PER_SEC		= 1000ULL,
	NSEC_PER_SEC		= NSEC_PER_MSEC * MSEC_PER_SEC,

	SCXCMD_OP_NONE 		= 0,
	SCXCMD_OP_JOIN 		= 1,
	SCXCMD_OP_LEAVE 	= 2,

	SCXCMD_PREFIX		= 0x5C10,
	SCXCMD_COMLEN		= 13,
	MAX_GPU_PIDS 		= 100000,

};

enum layer_membership {
	MEMBER_NOEXPIRE		= (u64)-1,
	MEMBER_EXPIRED		= (u64)-2,
	MEMBER_CANTMATCH	= (u64)-3,
	MEMBER_INVALID		= (u64)-4,
};

static inline void ___consts_sanity_check___(void) {
	/* layer->llcs_to_drain uses u64 as LLC bitmap */
	_Static_assert(MAX_LLCS <= 64, "MAX_LLCS too high");
	_Static_assert(MAX_LLCS <= (1 << DSQ_ID_LAYER_SHIFT), "MAX_LLCS too high");
	_Static_assert(MAX_LAYERS <= (DSQ_ID_LAYER_MASK >> DSQ_ID_LAYER_SHIFT) + 1,
		       "MAX_LAYERS too high");
	/* cgroup regex matching uses u64 as match bitmap */
	_Static_assert(MAX_CGROUP_REGEXES <= 64, "MAX_CGROUP_REGEXES too high for u64 bitmap");
}

enum layer_kind {
	/*
	 * Open 不参与用户态 util_range 扩缩。它的 cpus[] 是
	 * Confined/Grouped 分配后剩余的 CPU；没有剩余 idle CPU 时仍可在
	 * 其他 unprotected CPU 上运行。常用作最后的 catch-all。
	 */
	LAYER_KIND_OPEN,
	/*
	 * Grouped 有动态 owned CPU 集合，但允许借用层外 unprotected idle
	 * CPU。idle_confined 只推迟这种借用，并不把它变成严格隔离。
	 */
	LAYER_KIND_GROUPED,
	/*
	 * Confined 有动态 owned CPU 集合；普通选核和 dispatch 不从层外
	 * CPU 运行任务。affinity 冲突、fallback 和 stranded-task rescue
	 * 仍是有意保留的例外路径。
	 */
	LAYER_KIND_CONFINED,
};

enum layer_usage {
	LAYER_USAGE_OWNED,
	LAYER_USAGE_OPEN,
	LAYER_USAGE_SUM_UPTO = LAYER_USAGE_OPEN,

	LAYER_USAGE_PROTECTED,
	LAYER_USAGE_PROTECTED_PREEMPT,

	NR_LAYER_USAGES,
};

/* Statistics */
enum global_stat_id {
	GSTAT_EXCL_IDLE,
	GSTAT_EXCL_WAKEUP,
	GSTAT_HI_FB_EVENTS,
	GSTAT_HI_FB_USAGE,
	GSTAT_LO_FB_EVENTS,
	GSTAT_LO_FB_USAGE,
	GSTAT_FB_CPU_USAGE,
	GSTAT_ANTISTALL,
	GSTAT_SKIP_PREEMPT,
	GSTAT_FIXUP_VTIME,
	GSTAT_PREEMPTING_MISMATCH,
	NR_GSTATS,
};

enum layer_stat_id {
	LSTAT_SEL_LOCAL,
	LSTAT_ENQ_LOCAL,
	LSTAT_ENQ_WAKEUP,
	LSTAT_ENQ_EXPIRE,
	LSTAT_ENQ_REENQ,
	LSTAT_ENQ_DSQ,
	LSTAT_KEEP,
	LSTAT_MIN_EXEC,
	LSTAT_MIN_EXEC_NS,
	LSTAT_OPEN_IDLE,
	LSTAT_AFFN_VIOL,
	LSTAT_KEEP_FAIL_MAX_EXEC,
	LSTAT_KEEP_FAIL_BUSY,
	LSTAT_PREEMPT,
	LSTAT_PREEMPT_FIRST,
	LSTAT_PREEMPT_XLLC,
	LSTAT_PREEMPT_XNUMA,
	LSTAT_PREEMPT_IDLE,
	LSTAT_PREEMPT_FAIL,
	LSTAT_EXCL_COLLISION,
	LSTAT_EXCL_PREEMPT,
	LSTAT_YIELD,
	LSTAT_YIELD_IGNORE,
	LSTAT_MIGRATION,
	LSTAT_XNUMA_MIGRATION,
	LSTAT_XLLC_MIGRATION,
	LSTAT_XLLC_MIGRATION_SKIP,
	LSTAT_XLAYER_WAKE,
	LSTAT_XLAYER_REWAKE,
	LSTAT_LLC_DRAIN_TRY,
	LSTAT_LLC_DRAIN,
	LSTAT_SKIP_REMOTE_NODE,
	NR_LSTATS,
};

enum llc_layer_stat_id {
	LLC_LSTAT_LAT,
	LLC_LSTAT_CNT,
	NR_LLC_LSTATS,
};

/*
 * CPU 拓扑邻近表。cpus[] 从近到远排列，四个 end 是半开区间终点：
 * [0, core_end) 同一物理 core（含自己），[core_end, llc_end) 同 LLC，
 * [llc_end, node_end) 同 NUMA node，[node_end, sys_end) 远端 node。
 * 抢占路径按该顺序扫描，优先保留 cache/NUMA 局部性。
 */
struct cpu_prox_map {
	u16			cpus[MAX_CPUS];
	u32			core_end;
	u32			llc_end;
	u32			node_end;
	u32			sys_end;
};

/*
 * 每 CPU 的 BPF 私有状态，存放在 percpu array `cpu_ctxs` 中。
 *
 * 它同时承担四类职责：
 * 1. 描述 CPU 的拓扑与非 Open owner；
 * 2. 记录当前/下一任务的抢占和 SMT-exclusive 状态；
 * 3. 累计用户态控制循环要读取的利用率、带宽和统计；
 * 4. 保存该 CPU 的 DSQ 拉取顺序和 fallback 进度。
 */
struct cpu_ctx {
	/* 当前 percpu value 对应的逻辑 CPU ID。 */
	s32			cpu;
	/* 当前任务是否属于 preempt 层；其他 preempt 任务不会再抢占它。 */
	bool			current_preempt;
	/* 当前运行任务是否请求独占整个 SMT core。 */
	bool			current_excl;
	/* 上一个任务的 exclusive 状态，用于退出 exclusive 时唤醒 sibling。 */
	bool			prev_excl;
	/* 已为即将直派的 exclusive 任务预留 sibling-idle 状态。 */
	bool			next_excl;
	/* 当前任务的 yield 是否耗尽了 slice；enqueue/keep_running 会读取并清除。 */
	bool			yielding;
	/* select_cpu 给 enqueue 的一次性信号：先抢占 previous CPU。 */
	bool			try_preempt_first;
	/* 用户态拓扑探测写入：异构系统中该 CPU 是否为 big/turbo core。 */
	bool			is_big;
	/* 原子声明该 CPU 的待抢占任务，避免多个 wakeup 同时选择同一 CPU。 */
	struct task_struct	*preempting_task;
	/* preempting_task 的设置时间；超时后可清理陈旧声明。 */
	u64			preempting_at;

	/* CPU 连续繁忙后，普通 Open/Grouped 工作是否应让 owner 先运行。 */
	bool			protect_owned;
	/* 更强的保护：是否拒绝其他 preempt 层抢占当前 owned 工作。 */
	bool			protect_owned_preempt;
	/* 当前任务是否在该 CPU owner layer 上运行，用于 OWNED/OPEN 计费。 */
	bool			running_owned;
	/* 当前任务是否来自 Open layer。 */
	bool			running_open;
	/* 当前任务是否由 per-node stranded-task fallback 路径拉取。 */
	bool			running_fallback;
	/* account_used() 上次结算该 CPU 运行时间的时间戳。 */
	u64			used_at;
	/* 当前 CPU owner layer 的 protected 属性缓存。 */
	bool			is_protected;

	/* 每层 owned/open/protected 等 CPU 时间累计值，用户态周期读取并清算。 */
	u64			layer_usages[MAX_LAYERS][NR_LAYER_USAGES];
	/* 每层 affinity 被固定到本 node 的任务所消耗的 CPU 时间。 */
	u64			node_pinned_usage[MAX_LAYERS];
	/* 与 layer_usages 同维度的内存带宽事件累计值。 */
	u64			layer_membw_agg[MAX_LAYERS][NR_LAYER_USAGES];
	/* 本 CPU 的全局统计计数器。 */
	u64			gstats[NR_GSTATS];
	/* 本 CPU、每层的调度事件统计计数器。 */
	u64			lstats[MAX_LAYERS][NR_LSTATS];
	/* 每层 runnable duty 累计；包含排队时间，用于跨 NUMA 失衡判断。 */
	u64			layer_duty_sum[MAX_LAYERS];
	/* keep_running() 已连续给当前任务续了多少时间。 */
	u64			ran_current_for;

	/* 此 CPU 自启动以来的累计忙时间。 */
	u64			usage;
	/* 最近一次进入 idle 时的 usage 快照，用于计算连续繁忙时长。 */
	u64			usage_at_idle;

	/* 本 LLC 的高优先级 fallback DSQ，主要服务关键 per-CPU kthread。 */
	u64			hi_fb_dsq_id;
	/* 本 LLC 的低优先级 fallback DSQ，服务 affinity/空层等异常放置。 */
	u64			lo_fb_dsq_id;
	/* 此 CPU 是否包含在至少一个 Open layer 的当前 CPU mask 中。 */
	bool			in_open_layers;
	/* 非 Open owner 的 layer ID；无 owner/Open CPU 时为 MAX_LAYERS。 */
	u32			layer_id;
	/* CPU 所属 LLC 与 NUMA node，初始化后不变。 */
	u32			llc_id;
	u32			node_id;
	/* 最近一次通过 scx_bpf_cpuperf_set() 设置的 target，避免重复调用。 */
	u32			perf;

	/* low fallback DSQ 从空变非空的代次。 */
	u64			lo_fb_seq;
	/* 当前代次开始观测的时间。 */
	u64			lo_fb_seq_at;
	/* 当前代次开始时的低优先级 fallback 用量基线。 */
	u64			lo_fb_usage_base;

	/* 以下数组是 dispatch 的随机化 layer 扫描顺序，按 kind/preempt 分类。 */
	u32			ogp_layer_order[MAX_LAYERS];	/* open/grouped preempt */
	u32			ogn_layer_order[MAX_LAYERS];	/* open/grouped non-preempt */

	u32			op_layer_order[MAX_LAYERS];	/* open preempt */
	u32			on_layer_order[MAX_LAYERS];	/* open non-preempt */
	u32			gp_layer_order[MAX_LAYERS];	/* grouped preempt */
	u32			gn_layer_order[MAX_LAYERS];	/* grouped non-preempt */

	/* 以本 CPU 为起点的抢占邻近顺序。 */
	struct cpu_prox_map	prox_map;
};

/* LLC 从近到远的扫描表；node_end 前与当前 LLC 同 NUMA node。 */
struct llc_prox_map {
	u16			llcs[MAX_LLCS];
	u32			node_end;
	u32			sys_end;
};

/* 每 LLC 的共享调度状态。layer DSQ 的公平时钟和排队量都按 LLC 隔离。 */
struct llc_ctx {
	/* 连续 LLC ID。 */
	u32			id;
	/* 该 LLC 包含的逻辑 CPU bitmap。 */
	struct bpf_cpumask __kptr *cpumask;
	/* bitmap 中的 CPU 数。 */
	u32			nr_cpus;
	/* 每层在此 LLC 上的 vtime 基准，跨 LLC 时用它平移任务 vtime。 */
	u64			vtime_now[MAX_LAYERS];
	/* 每层 DSQ 中任务 runtime_avg 总和，近似“还要跑多久”。 */
	u64			queued_runtime[MAX_LAYERS];
	/* low fallback DSQ 从空变非空时递增，通知各 CPU 开始新等待窗口。 */
	u64			lo_fb_seq;
	/* 每层在此 LLC 上的延迟/次数统计。 */
	u64			lstats[MAX_LAYERS][NR_LLC_LSTATS];
	/* 多份打乱后的 LLC 邻近表，dispatch 随机选一份以减少同距偏置。 */
	struct llc_prox_map	prox_maps[NUM_PROXIMITY_MAPS];
};

/* NUMA node 从近到远的顺序；nodes[0] 通常是源 node。 */
struct node_prox_map {
	u16			nodes[MAX_NUMA_NODES];
	u32			sys_end;
};

/* 每 NUMA node 的共享状态，服务 node-local 选核和 stranded-task rescue。 */
struct node_ctx {
	/* 连续 node ID。 */
	u32			id;
	/* node 内全部 CPU。 */
	struct bpf_cpumask __kptr *cpumask;
	/* node 内未被 protected layer 排除、可被 Grouped/Open 借用的 CPU。 */
	struct bpf_cpumask __kptr *unprotected_cpumask;
	/* node 内有效 LLC/CPU 数及 LLC ID 列表。 */
	u32			nr_llcs;
	u32			nr_cpus;
	u32			llcs[MAX_LLCS];
	/* 此 node 上当前没有 owned CPU 的层；fallback CPU 用它排空遗留 DSQ。 */
	u32			empty_layer_ids[MAX_LAYERS];
	u32			nr_empty_layer_ids;
	/* 跨 node 搜索顺序。 */
	struct node_prox_map	prox_map;
};

/* 用户态 test_run(refresh_node_ctx) 传给 BPF 的更新参数。 */
struct refresh_node_ctx_arg {
	/* 要更新的 node。 */
	u32			node_id;
	/* true 表示首次初始化，同时复制静态 LLC 拓扑。 */
	u32			init;
	/* 运行期更新的 empty-layer 集合。 */
	u32			empty_layer_ids[MAX_LAYERS];
	u32			nr_empty_layer_ids;
	/* 仅初始化时复制的 node 内 LLC 列表。 */
	u32			llcs[MAX_LLCS];
	u32			nr_llcs;
};

enum layer_match_kind {
	MATCH_CGROUP_PREFIX,
	MATCH_COMM_PREFIX,
	MATCH_PCOMM_PREFIX,
	MATCH_NICE_ABOVE,
	MATCH_NICE_BELOW,
	MATCH_NICE_EQUALS,
	MATCH_USER_ID_EQUALS,
	MATCH_GROUP_ID_EQUALS,
	MATCH_PID_EQUALS,
	MATCH_PPID_EQUALS,
	MATCH_TGID_EQUALS,
	MATCH_NSPID_EQUALS,
	MATCH_NS_EQUALS,
	MATCH_SCXCMD_JOIN,
	MATCH_IS_GROUP_LEADER,
	MATCH_IS_KTHREAD,
	MATCH_USED_GPU_TID,
	MATCH_USED_GPU_PID,
	MATCH_AVG_RUNTIME,
	MATCH_CGROUP_SUFFIX,
	MATCH_CGROUP_CONTAINS,
	MATCH_CGROUP_REGEX,
	MATCH_HINT_EQUALS,
	MATCH_SYSTEM_CPU_UTIL_BELOW,
	MATCH_DSQ_INSERT_BELOW,
	MATCH_NUMA_NODE,

	NR_LAYER_MATCH_KINDS,
};

/*
 * 一个 AND 条件的固定大小载体。它在逻辑上是 tagged union，但为简化
 * BPF verifier 使用普通 struct：只有 kind 对应的字段有意义。
 */
struct layer_match {
	/* enum layer_match_kind，决定 match_one() 读取下面哪个成员。 */
	int		kind;
	/* cgroup 字符串 matcher 的模式值，路径最长 MAX_PATH。 */
	char		cgroup_prefix[MAX_PATH];
	char		cgroup_suffix[MAX_PATH];
	char		cgroup_substr[MAX_PATH];
	/* CgroupRegex 由用户态计算 bitmap；这里保存 bitmap bit 编号。 */
	u32		cgroup_regex_id;
	/* 线程 comm 与线程组 leader comm 模式。 */
	char		comm_prefix[MAX_COMM];
	char		pcomm_prefix[MAX_COMM];
	/* nice/身份/PID namespace matcher 的比较值。 */
	int		nice;
	u32		user_id;
	u32		group_id;
	u32		pid;
	u32		ppid;
	u32		tgid;
	u64		nsid;
	/* 布尔 matcher 的期望极性。 */
	bool		is_group_leader;
	bool		is_kthread;
	bool		used_gpu_tid;
	bool		used_gpu_pid;
	/* true 时反转本 matcher 结果，用于 *Exclude 规则。 */
	bool		exclude;
	/* AvgRuntime 的半开区间 [min, max)，单位微秒。 */
	u64		min_avg_runtime_us;
	u64		max_avg_runtime_us;
	/* task hint 及两个乘 10000 保存的比例阈值。 */
	u64		hint;
	u64		system_cpu_util_below;	/* ratio * 10000 */
	u64		dsq_insert_below;	/* ratio * 10000 */
	/* NumaNode matcher 的目标 node。 */
	u32		numa_node_id;
};

/* JSON matches 的一个内层数组：matches[0..nr_match_ands) 必须全部命中。 */
struct layer_match_ands {
	struct layer_match	matches[NR_LAYER_MATCH_KINDS];
	int			nr_match_ands;
};

enum layer_growth_algo {
	GROWTH_ALGO_STICKY,
	GROWTH_ALGO_LINEAR,
	GROWTH_ALGO_REVERSE,
	GROWTH_ALGO_RANDOM,
	GROWTH_ALGO_TOPO,
	GROWTH_ALGO_ROUND_ROBIN,
	GROWTH_ALGO_BIG_LITTLE,
	GROWTH_ALGO_LITTLE_BIG,
	GROWTH_ALGO_NODE_SPREAD,
	GROWTH_ALGO_NODE_SPREAD_REVERSE,
	GROWTH_ALGO_NODE_SPREAD_RANDOM,
	GROWTH_ALGO_CPUSET_SPREAD,
	GROWTH_ALGO_CPUSET_SPREAD_REVERSE,
	GROWTH_ALGO_CPUSET_SPREAD_RANDOM,
	GROWTH_ALGO_RANDOM_TOPO,
	GROWTH_ALGO_STICKY_DYNAMIC,
};

enum layer_task_place {
	PLACEMENT_STD,
	PLACEMENT_STICK,
	PLACEMENT_FLOAT,
};

struct xnuma_bucket {
	/* 当前迁移预算，可暂时为负；单位与 task duty_cycle 相同。 */
	s64			tokens;
	/* 上次按 rate 补充预算的 BPF 时钟时间。 */
	u64			last_refill_ts;
	/* 每秒补充量；0=禁止，U64_MAX=不限流。 */
	u64			rate;		/* duty_cycle units per second, set by userspace */
};

/* 某 layer 在某 NUMA node 上的运行时状态。 */
struct layer_node_ctx {
	/* 用户态当前分给本层、本 node 的 owned CPU 数。 */
	u32			nr_cpus;
	/* affinity 只能落在此 node 的本层任务数。 */
	u64			nr_pinned_tasks;
	/* 位图：哪些已无 owned CPU 的 LLC DSQ 仍需要被其他 LLC 排空。 */
	u64			llcs_to_drain;
	/* drain 扫描轮转计数，避免每次都从同一 LLC 开始。 */
	u32			llc_drain_cnt;
	/* 此 node 是否过载且无法扩容，允许成为跨 NUMA 迁移源。 */
	bool			xnuma_is_mig_src;
	/* 以目标 node ID 索引的迁移 token bucket。 */
	struct xnuma_bucket xnuma[MAX_NUMA_NODES];
};

struct layer {
	/* 这个 layer 的匹配条件。
	第一维是 OR 分组，layer_match_ands 内部是 AND 条件。
来自 JSON 的 matches。 */
	struct layer_match_ands	matches[MAX_LAYER_MATCH_ORS];
/* 实际有效的 OR 分组数量。
match_layer() 根据它遍历匹配规则。 */
	unsigned int		nr_match_ors;
	/* 层编号，也就是 JSON 数组中的顺序索引。
任务通过 task_ctx.layer_id 引用它。
层 DSQ ID、统计数组也都使用这个编号。 */
	unsigned int		id;
/* 任务一次运行即使很短，也至少按这个时间计入虚拟运行时间。
防止频繁睡眠/唤醒的任务因为每次运行太短而获得不公平优势。 */
	u64			min_exec_ns;
/* struct layer 中存在，但当前代码没有实际读写它。
当前连续运行限制使用的是全局 const volatile u64 max_exec_ns，不是该成员。
因此它目前更像遗留或预留字段。 */
	u64			max_exec_ns;
/* 任务调用 yield() 时，从剩余时间片中扣除多少。
由 yield_ignore 和 slice_ns 计算。 */
	u64			yield_step_ns;
/* 本层任务的调度时间片，单位纳秒。
JSON slice_us 乘 1000 后写入。
插入 DSQ 时作为 slice 参数使用。 */
	u64			slice_ns;
/* false：默认按虚拟时间 dsq_vtime 排序。
true：按 FIFO 顺序入队。 */
	bool			fifo;
/* 层配置权重的 BPF 镜像。
当前 BPF 调度路径没有直接读取 layer->weight。
真正的层权重主要在用户态 CPU 分配阶段使用。
任务自身公平性使用的是 p->scx.weight。 */
	u32			weight;
/* CPU 连续繁忙超过该时间后，阻止普通 Open/Grouped 工作借用该 CPU。 */
	u64			disallow_open_after_ns;
/* CPU 连续繁忙超过该时间后，进一步阻止其他 preempt layer 抢占。 */
	u64			disallow_preempt_after_ns;
/* 跨 LLC 迁移阈值。
当前 LLC 中排队工作不够多时，不值得为了寻找空闲 CPU 跨 LLC 迁移。
用于在缓存局部性和排队延迟之间取舍。 */
	u64			xllc_mig_min_ns;
/*
BPF 侧的 LAYER_KIND_CONFINED、GROUPED 或 OPEN。
决定任务能否使用层外 CPU。 */
	int			kind;
/* 本层任务在没有空闲 CPU 时，是否可以主动抢占其他非抢占层任务。 */
	bool			preempt;
/* 是否优先尝试抢占任务之前运行的 CPU，然后再搜索空闲 CPU。 */
	bool			preempt_first;
/* 是否尝试独占整个物理核心。
SMT sibling 会尽量保持空闲。
不是安全隔离保证。 */
	bool			excl;
/* 表示 cpuset[] 中是否有显式的 layer cpuset。
通常由模板展开生成的 spec.cpuset 设置。 */
	bool			has_cpuset;
/* dispatch 时是否跳过远端 NUMA 节点上的队列。 */
	bool			skip_remote_node;
/* SMT 系统中，即使存在完整 idle core，也优先继续使用 previous CPU。 */
	bool			prev_over_idle_core;
/* 仅适用于 Grouped。
未饱和时像 Confined 一样只在本层 CPU 中找 idle CPU。
饱和或系统已全部分配后，再允许使用外部 unprotected CPU。 */
	bool			idle_confined;
/* 用户态告知 BPF：系统所有 CPU 是否已分配完。
若已分完，idle_confined 的 Grouped 层继续等待已经没有意义，可以向外借 CPU。 */
	bool			fully_allocated;
/* 层 CPU 集合增长/拓扑顺序算法。
与 placement 不同：
growth_algo 决定给 layer 分配哪些 CPU。
task_place 决定 layer 内具体任务如何选 CPU。
大多数增长逻辑在用户态；BPF 也会用它处理 big/little 选核偏好。 */
	int			growth_algo;
/* 当前归属于该层的任务数。
switch_to_layer() 在旧层减一、新层加一。 */
	u64			nr_tasks;
/* 层 CPU mask 的版本号。
用户态改变层 CPU 集合后，BPF 增加它。
任务缓存的 CPU mask 版本落后时重新计算。 */
	u64			cpus_seq;
/* 表示最近一次搜索发现该层没有可用 idle CPU。
用于快速跳过重复且昂贵的分层选核搜索。
找到 idle CPU 时清零，找不到时置位。 */
	bool			check_no_idle;
/* 层的 CPU performance target。
非零时在任务运行阶段调用 scx_bpf_cpuperf_set()。 */
	u32			perf;
/* refresh_cpus

用户态写为 1，通知 BPF cpus[] 已更新。
BPF 通过 compare-and-swap 消费后清零。
cpus

用户态序列化后的 layer CPU bitmap。
nr_cpus

当前分配给该层的 CPU 总数。
nr_llc_cpus

每个 LLC 中，该层拥有的 CPU 数。
如果某个 LLC 已没有该层 CPU，但 DSQ 仍有任务，需要启动 drain。 */
	u64			refresh_cpus;
	u8			cpus[MAX_CPUS_U8];

	u32			nr_cpus;
	u32			nr_llc_cpus[MAX_LLCS];
/* node[]
每个 NUMA 节点对应一个 layer_node_ctx。 */
	struct layer_node_ctx	node[MAX_NUMA_NODES];
/* task_place

JSON placement 转换后的 BPF 枚举。
Standard、Sticky、Floating。 */
	enum layer_task_place   task_place;

	char			name[MAX_LAYER_NAME];
	/* 本层 CPU 是否从普通可借用 CPU 集合中排除。
protected CPU 的 dispatch 也不会主动拉取其他层工作。 */
	bool			is_protected;
	/* 只要层中存在 MATCH_AVG_RUNTIME，初始化时就置为 true。
表示任务需要周期性重新检查 AvgRuntime 区间。 */
	bool			periodically_refresh;
	/* 层的静态允许 CPU bitmap，主要用于模板展开/显式 cpuset。 */
	u8			cpuset[MAX_CPUS_U8];
	/* GPU 使用等动态成员资格的过期时间。
到期后设置 refresh_layer，重新判断归属。 */
	u64			member_expire_ms;
};

struct scx_cmd {
	u16			prefix;
	u8 			opcode;
	u8			cmd[SCXCMD_COMLEN];
} __attribute__((packed));

struct hint_layer_info {
	u32			layer_id;
	u64			system_cpu_util_below;	/* ratio * 10000, u64::MAX = disabled */
	u64			dsq_insert_below;	/* ratio * 10000, u64::MAX = disabled */
};

#endif /* __INTF_H */
