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
	/* 没有自己的地盘，哪里空闲去哪里
Open 适合：

默认兜底 layer；
没有特殊隔离要求的普通任务；
系统线程或通用 workload；
希望尽可能利用全机空闲算力的任务。 */
	LAYER_KIND_OPEN,
	/* 有自己的地盘，但外面空闲时可以借
	目标不是严格隔离，而是：

平时把同组任务聚在一起；
尽量保持缓存和拓扑局部性；
系统有空闲算力时仍然保持 work-conserving；
避免因为硬限制而让 CPU 闲着、任务却排队。

适合：

希望任务主要集中在部分 LLC/CPU；
但不能接受任务排队时外部 CPU 闲置；
前台服务、普通业务层；
需要在局部性和吞吐量之间折中的任务。

官方定义就是“类似 Confined，但允许在分配 CPU 之外存在空闲 CPU 时溢出”。*/
	LAYER_KIND_GROUPED,
	/* 有自己的地盘，原则上不许出去
动态调整：
平均每 CPU 利用率高于 90%：增加 CPU；
低于 80%：减少 CPU；
CPU 数量限制在 1～8。

适合：

后台任务、离线任务；
希望压缩到少量 CPU 的任务；
避免任务在整机迁移、污染 LLC；
需要较强 CPU 隔离的 workload。 */
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

/* CPU proximity map from closest to farthest, starts with self */
struct cpu_prox_map {
	u16			cpus[MAX_CPUS];
	u32			core_end;
	u32			llc_end;
	u32			node_end;
	u32			sys_end;
};

struct cpu_ctx {
	s32			cpu;
	bool			current_preempt;
	bool			current_excl;
	bool			prev_excl;
	bool			next_excl;
	bool			yielding;
	bool			try_preempt_first;
	bool			is_big;
	struct task_struct	*preempting_task;
	u64			preempting_at;

	bool			protect_owned;
	bool			protect_owned_preempt;
	bool			running_owned;
	bool			running_open;
	bool			running_fallback;
	u64			used_at;
	bool			is_protected;

	u64			layer_usages[MAX_LAYERS][NR_LAYER_USAGES];
	/* 这个 layer 的 pin 的 usage */
	u64			node_pinned_usage[MAX_LAYERS];
	u64			layer_membw_agg[MAX_LAYERS][NR_LAYER_USAGES];
	u64			gstats[NR_GSTATS];
	u64			lstats[MAX_LAYERS][NR_LSTATS];
	u64			layer_duty_sum[MAX_LAYERS];
	u64			ran_current_for;

	u64			usage;
	u64			usage_at_idle;

	u64			hi_fb_dsq_id;
	u64			lo_fb_dsq_id;
	bool			in_open_layers;
	u32			layer_id;
	u32			llc_id;
	u32			node_id;
	u32			perf;

	u64			lo_fb_seq;
	u64			lo_fb_seq_at;
	u64			lo_fb_usage_base;

	u32			ogp_layer_order[MAX_LAYERS];	/* open/grouped preempt */
	u32			ogn_layer_order[MAX_LAYERS];	/* open/grouped non-preempt */

	u32			op_layer_order[MAX_LAYERS];	/* open preempt */
	u32			on_layer_order[MAX_LAYERS];	/* open non-preempt */
	u32			gp_layer_order[MAX_LAYERS];	/* grouped preempt */
	u32			gn_layer_order[MAX_LAYERS];	/* grouped non-preempt */

	struct cpu_prox_map	prox_map;
};

struct llc_prox_map {
	u16			llcs[MAX_LLCS];
	u32			node_end;
	u32			sys_end;
};

struct llc_ctx {
	u32			id;
	struct bpf_cpumask __kptr *cpumask;
	u32			nr_cpus;
	u64			vtime_now[MAX_LAYERS];
	u64			queued_runtime[MAX_LAYERS];
	u64			lo_fb_seq;
	u64			lstats[MAX_LAYERS][NR_LLC_LSTATS];
	struct llc_prox_map	prox_maps[NUM_PROXIMITY_MAPS];
};

struct node_prox_map {
	u16			nodes[MAX_NUMA_NODES];
	u32			sys_end;
};

struct node_ctx {
	u32			id;
	struct bpf_cpumask __kptr *cpumask;
	struct bpf_cpumask __kptr *unprotected_cpumask;
	u32			nr_llcs;
	u32			nr_cpus;
	u32			llcs[MAX_LLCS];
	u32			empty_layer_ids[MAX_LAYERS];
	u32			nr_empty_layer_ids;
	struct node_prox_map	prox_map;
};

struct refresh_node_ctx_arg {
	u32			node_id;
	u32			init;
	u32			empty_layer_ids[MAX_LAYERS];
	u32			nr_empty_layer_ids;
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

struct layer_match {
	int		kind;
	char		cgroup_prefix[MAX_PATH];
	char		cgroup_suffix[MAX_PATH];
	char		cgroup_substr[MAX_PATH];
	u32		cgroup_regex_id;
	char		comm_prefix[MAX_COMM];
	char		pcomm_prefix[MAX_COMM];
	int		nice;
	u32		user_id;
	u32		group_id;
	u32		pid;
	u32		ppid;
	u32		tgid;
	u64		nsid;
	bool		is_group_leader;
	bool		is_kthread;
	bool		used_gpu_tid;
	bool		used_gpu_pid;
	bool		exclude;
	u64		min_avg_runtime_us;
	u64		max_avg_runtime_us;
	u64		hint;
	u64		system_cpu_util_below;	/* ratio * 10000 */
	u64		dsq_insert_below;	/* ratio * 10000 */
	u32		numa_node_id;
};

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
	s64			tokens;
	u64			last_refill_ts;
	u64			rate;		/* duty_cycle units per second, set by userspace */
};
/* 
nr_cpus：该层在这个 node 的 CPU 数。
nr_pinned_tasks：CPU affinity 被限制在该 node 的任务数。
llcs_to_drain：需要从哪些无 owner CPU 的 LLC DSQ 搬走任务。
llc_drain_cnt：LLC drain 状态/计数。
xnuma_is_mig_src：该 node 当前是否允许作为跨 NUMA 迁移源。
xnuma[]：跨 NUMA 迁移的 token bucket。
*/
struct layer_node_ctx {
	u32			nr_cpus;
	u64			nr_pinned_tasks;
	u64			llcs_to_drain;
	u32			llc_drain_cnt;
	bool			xnuma_is_mig_src;
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
