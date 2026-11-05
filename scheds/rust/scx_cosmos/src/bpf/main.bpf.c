/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>
 */
#include <scx/common.bpf.h>
#include <scx/percpu.bpf.h>
#include <lib/pmu.h>
#include "intf.h"
/* 用户态 (main.rs)                         BPF (main.bpf.c)
─────────────────                        ────────────────
Topology / 主域 / SMT 兄弟               cosmos_select_cpu
NVML: PID → GPU NUMA                     cosmos_enqueue
/proc/stat → cpu_util_map                cosmos_dispatch
动态 PMU 阈值                            cosmos_tick / running / stopping
stats 监控                               本地 DSQ / 共享(或 per-node) DSQ */
char _license[] SEC("license") = "GPL";

/*
 * Maximum amount of CPUs supported by the scheduler when flat or preferred
 * idle CPU scan is enabled.
 */
#define MAX_CPUS	1024

/*
 * Maximum amount of NUMA nodes supported by the scheduler.
 */
#define MAX_NODES	1024

/*
 * Maximum amount of GPUs supported by the scheduler.
 */
#define MAX_GPUS	32

/*
 * Shared DSQ used to schedule tasks in deadline mode when the system is
 * saturated.
 *
 * When system is not saturated tasks will be dispatched to the local DSQ
 * in round-robin mode.
 */
#define SHARED_DSQ		0

/*
 * Thresholds for applying hysteresis to CPU performance scaling:
 *  - CPUFREQ_LOW_THRESH: below this level, reduce performance to minimum
 *  - CPUFREQ_HIGH_THRESH: above this level, raise performance to maximum
 *
 * Values between the two thresholds retain the current smoothed performance level.
 */
#define CPUFREQ_LOW_THRESH	(SCX_CPUPERF_ONE / 4)
#define CPUFREQ_HIGH_THRESH	(SCX_CPUPERF_ONE - SCX_CPUPERF_ONE / 4)

/*
 * Subset of CPUs to prioritize.
 */
private(COSMOS) struct bpf_cpumask __kptr *primary_cpumask;

/*
 * Set to true when @primary_cpumask is empty (primary domain includes all
 * the CPU).
 */
const volatile bool primary_all = true;

/*
 * Enable flat iteration to find idle CPUs (fast but inaccurate).
 */
const volatile bool flat_idle_scan = false;

/*
 * CPUs in the system have SMT is enabled.
 */
const volatile bool smt_enabled = true;

/*
 * Enable preferred cores prioritization.
 */
const volatile bool preferred_idle_scan = false;

/*
 * CPUs sorted by their capacity in descendent order.
 */
const volatile u64 preferred_cpus[MAX_CPUS];

/*
 * Cache CPU capacity values.
 */
const volatile u64 cpu_capacity[MAX_CPUS];

/*
 * True when all CPUs have the same capacity (no capacity asymmetry).
 */
const volatile bool all_cpus_same_capacity = false;

/*
 * Enable cpufreq integration.
 */
const volatile bool cpufreq_enabled = true;

/*
 * Enable NUMA optimizations.
 */
const volatile bool numa_enabled;

/*
 * Enable automatic GPU affinity.
 */
const volatile bool gpu_enabled = true;

/*
 * Enable address space affinity.
 */
const volatile bool mm_affinity;

/*
 * ID of perf-event being tracked. 0 for "no event".
 */
const volatile u64 perf_config;

/*
 * Performance counter threshold to classify a task as event heavy.
 */
volatile u64 perf_threshold;

/*
 * Sticky perf event (0x0 = disabled). When task's count for this event
 * exceeds perf_sticky_threshold, keep it on the same CPU.
 */
const volatile u64 perf_sticky;

/*
 * Threshold for sticky event; task is kept on same CPU when exceeded.
 */
volatile u64 perf_sticky_threshold;

/*
 * Disable high-resolution preemption enforcement.
 */
const volatile bool time_preemption;

/*
 * Ignore synchronous wakeup events.
 */
const volatile bool no_wake_sync;

/*
 * Disable early clearing of idle CPU state.
 */
const volatile bool no_early_clear;

/*
 * Default time slice.
 */
const volatile u64 slice_ns = 1000000ULL;

/*
 * Maximum runtime that can be charged to a task.
 */
const volatile u64 slice_lag = 20000000ULL;

/*
 * User CPU utilization threshold to determine when the system is busy.
 */
const volatile u64 busy_threshold;

/*
 * Per-CPU user utilization in the range [0 .. 1024], updated periodically
 * from userspace. Indexed by CPU id.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u64);
} cpu_util_map SEC(".maps");

/*
 * Scheduler statistics.
 */
volatile u64 nr_event_dispatches;
volatile u64 nr_ev_sticky_dispatches;
volatile u64 nr_gpu_dispatches;

/*
 * Scheduler's exit status.
 */
UEI_DEFINE(uei);

/*
 * Maximum amount of CPUs supported by the system.
 */
static u64 nr_cpu_ids;

/*
 * Maximum possible NUMA node number.
 */
const volatile u32 nr_node_ids;

/*
 * Current system vruntime.
 */
static u64 vtime_now;

/*
 * Per-task context.
 */
struct task_ctx {
	struct bpf_cpumask __kptr *cpumask;
	u64 last_run_at;
	u64 exec_runtime;
	u64 wakeup_freq;
	u64 last_woke_at;
	u64 perf_events;
	u64 perf_sticky_events;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * NUMA node context.
 */
struct node_ctx {
        struct bpf_cpumask __kptr *cpumask;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct node_ctx);
	__uint(max_entries, MAX_NODES);
} node_ctx_stor SEC(".maps");

struct node_ctx *try_lookup_node_ctx(int node)
{
	return bpf_map_lookup_elem(&node_ctx_stor, &node);
}

/*
 * CPU -> NUMA node mapping.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);	/* cpu_id */
	__type(value, u32);	/* node_id */
} cpu_node_map SEC(".maps");

static int cpu_node(s32 cpu)
{
	u32 *id;

	if (!numa_enabled)
		return 0;

	id = bpf_map_lookup_elem(&cpu_node_map, &cpu);
	if (!id)
		return -ENOENT;

	return *id;
}

/*
 * GPU -> node mapping.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_GPUS);
	__type(key, u32);	/* nvml_id */
	__type(value, u32);	/* node_id */
} gpu_node_map SEC(".maps");

/*
 * PID -> NUMA node mapping for GPU tasks (updated from userspace via NVML).
 * Key is the task's pid (thread id). Entries are removed when the task
 * is no longer using a GPU.
 */
#define MAX_GPU_PIDS	8192

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_GPU_PIDS);
	__type(key, u32);	/* pid (task/thread id) */
	__type(value, u32);	/* node_id */
} gpu_pid_map SEC(".maps");

/*
 * Look up preferred NUMA node for a PID from userspace-provided GPU process
 * list (NVML). Returns node id or negative error.
 */
static int gpu_node_by_pid(u32 pid)
{
	u32 *node;

	if (!gpu_enabled || !numa_enabled)
		return -ENOENT;

	node = bpf_map_lookup_elem(&gpu_pid_map, &pid);
	if (!node)
		return -ENOENT;

	return *node;
}

/*
 * Return a local task context from a generic task.
 */
struct task_ctx *try_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor,
					(struct task_struct *)p, 0, 0);
}

/*
 * Per-CPU context.
 */
struct cpu_ctx {
	u64 last_update;
	u64 perf_lvl;
	u64 perf_events;
	struct bpf_cpumask __kptr *smt;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, struct cpu_ctx);
	__uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return a CPU context.
 */
struct cpu_ctx *try_lookup_cpu_ctx(s32 cpu)
{
	const u32 idx = 0;
	return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

static void update_counters(struct task_struct *p, struct task_ctx *tctx, s32 cpu)
{
	struct cpu_ctx *cctx;
	u64 delta = 0;
	u64 sticky_delta = 0;

	cctx = try_lookup_cpu_ctx(cpu);
	if (cctx)
		cctx->perf_events += delta;

	if (perf_config) {
		scx_pmu_read(p, perf_config, &delta, true);
		tctx->perf_events = delta;
	}

	if (perf_sticky) {
		scx_pmu_read(p, perf_sticky, &sticky_delta, true);
		tctx->perf_sticky_events = sticky_delta;
	}
}

/*
 * Return true if the task is triggering too many PMU events (migration event).
 */
static inline bool is_event_heavy(const struct task_ctx *tctx)
{
	return perf_config && tctx->perf_events > perf_threshold;
}

/*
 * Return true if the task exceeds the sticky event threshold and should
 * stay on the same CPU.
 */
static inline bool is_sticky_event_heavy(const struct task_ctx *tctx)
{
	return perf_sticky && tctx->perf_sticky_events > perf_sticky_threshold;
}

/*
 * Exponential weighted moving average (EWMA).
 *
 * Copied from scx_lavd. Returns the new average as:
 *
 *	new_avg := (old_avg * .75) + (new_val * .25);
 */
static u64 calc_avg(u64 old_val, u64 new_val)
{
	return (old_val - (old_val >> 2)) + (new_val >> 2);
}

/*
 * Update the average frequency of an event.
 *
 * The frequency is computed from the given interval since the last event
 * and combined with the previous frequency using an exponential weighted
 * moving average.
 */
static u64 update_freq(u64 freq, u64 interval)
{
        u64 new_freq;

        new_freq = (100 * NSEC_PER_MSEC) / interval;
        return calc_avg(freq, new_freq);
}

/*
 * Update CPU load and scale target performance level accordingly.
 */
static void update_cpu_load(struct task_struct *p, u64 slice)
{
	u64 now = bpf_ktime_get_ns();
	s32 cpu = scx_bpf_task_cpu(p);
	u64 perf_lvl, delta_t;
	struct cpu_ctx *cctx;

	if (!cpufreq_enabled)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Evaluate dynamic cpuperf scaling factor using the average CPU
	 * utilization, normalized in the range [0 .. SCX_CPUPERF_ONE].
	 */
	delta_t = now - cctx->last_update;
	if (!delta_t)
		return;

	/*
	 * Refresh target performance level.
	 */
	perf_lvl = MIN(slice * SCX_CPUPERF_ONE / delta_t, SCX_CPUPERF_ONE);
	cctx->perf_lvl = calc_avg(cctx->perf_lvl, perf_lvl);
	cctx->last_update = now;
}

/*
 * Apply target cpufreq performance level to @cpu.
 */
static void update_cpufreq(s32 cpu)
{
	struct cpu_ctx *cctx;
	u64 perf_lvl;

	if (!cpufreq_enabled)
		return;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return;

	/*
	 * Apply target performance level to the cpufreq governor.
	 */
	if (cctx->perf_lvl >= CPUFREQ_HIGH_THRESH)
		perf_lvl = SCX_CPUPERF_ONE;
	else if (cctx->perf_lvl <= CPUFREQ_LOW_THRESH)
		perf_lvl = SCX_CPUPERF_ONE / 2;
	else
		perf_lvl = cctx->perf_lvl;

	scx_bpf_cpuperf_set(cpu, perf_lvl);
}

/*
 * Return the global system shared DSQ.
 */
static inline u64 shared_dsq(s32 cpu)
{
	return numa_enabled ? cpu_node(cpu) : SHARED_DSQ;
}

/*
 * Return true if task @p can run on NUMA node @node, false otherwise.
 */
static bool can_use_node(const struct task_struct *p, int node)
{
	struct node_ctx *nctx;

	if (!numa_enabled)
		return true;

	if (p->nr_cpus_allowed == nr_cpu_ids)
		return true;

	nctx = try_lookup_node_ctx(node);
	if (!nctx || !nctx->cpumask ||
	    !bpf_cpumask_intersects(cast_mask(nctx->cpumask), p->cpus_ptr))
		return false;

	return true;
}

/*
 * If the task is in gpu_pid_map and should run on a different node, pick a CPU
 * on the preferred GPU node. Returns the CPU id (>= 0) on success, or a
 * negative value if the task is not GPU-bound, is already on the right node,
 * or no suitable CPU was found.
 */
static s32 pick_cpu_on_gpu_node(const struct task_struct *p, int node,
				struct task_ctx *tctx)
{
	struct node_ctx *nctx;
	struct bpf_cpumask *mask;
	int target_node;

	target_node = gpu_node_by_pid(p->pid);
	if (target_node < 0 || target_node == node || !can_use_node(p, target_node))
		return -ENOENT;

	nctx = try_lookup_node_ctx(target_node);
	if (!nctx || !nctx->cpumask)
		return -ENOENT;

	mask = tctx->cpumask;
	if (!mask || !bpf_cpumask_and(mask, cast_mask(nctx->cpumask), p->cpus_ptr))
		return -ENOENT;

	return __COMPAT_scx_bpf_pick_idle_cpu_node(cast_mask(mask), target_node, 0);
}

/*
 * Return true if @p still wants to run, false otherwise.
 */
static bool is_task_queued(const struct task_struct *p)
{
	return p->scx.flags & SCX_TASK_QUEUED;
}

/*
 * Return true if @p can only run on a single CPU, false otherwise.
 */
static inline bool is_pcpu_task(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

/*
 * Return true if the given CPU is busy, false otherwise.
 *
 * @cpu should be the CPU of interest: prev_cpu in select_cpu/enqueue, or
 * scx_bpf_task_cpu(p) in tick.
 *
 * This determines when the scheduler needs to switch to deadline-mode
 * (using a shared DSQ) vs round-robin mode (using per-CPU local DSQs).
 忙闲由 用户态写入的每 CPU 利用率 决定，不是内核瞬时 runqueue：

用户态按 -p 轮询 /proc/stat 的 user+nice，归一化到 [0, 1024]，写入 cpu_util_map
BPF 里 is_cpu_busy(cpu)：util >= busy_threshold（-c 转成 thresh * 1024 / 100）

状态	队列	                   策略	           目的
不忙    SCX_DSQ_LOCAL / LOCAL_ON  尽量留在原 CPU   缓存局部性、少抢共享队列锁
忙      全局 SHARED_DSQ=0，或 每 NUMA node 一个 DSQ dsq_insert_vtime   跨 CPU 迁移、交互任务更容易插队
默认 -c 0、-p 0：map 全 0，0 >= 0 恒为真，默认按“忙”走 deadline 共享队列。
更低阈值 = 更早切 deadline = 更偏交互；更高阈值 = 更 sticky，偏服务器。*/
static inline bool is_cpu_busy(s32 cpu)
{
	u64 *util;
	u64 max_cpu = MIN(nr_cpu_ids, MAX_CPUS);

	if (cpu < 0 || cpu >= max_cpu)
		return false;

	util = bpf_map_lookup_elem(&cpu_util_map, &cpu);
	if (!util)
		return false;

	return *util >= busy_threshold;
}

/*
 * Return the SMT sibling CPU of a @cpu.
 */
static s32 smt_sibling(s32 cpu)
{
	const struct cpumask *smt;
	struct cpu_ctx *cctx;

	cctx = try_lookup_cpu_ctx(cpu);
	if (!cctx)
		return cpu;

	smt = cast_mask(cctx->smt);
	if (!smt)
		return cpu;

	return bpf_cpumask_first(smt);
}

/*
 * Return the cpumask of idle CPUs within the NUMA node that contains @cpu.
 *
 * If NUMA support is disabled, @cpu is ignored.
 */
static inline const struct cpumask *get_idle_cpumask(s32 cpu)
{
	if (!numa_enabled)
		return scx_bpf_get_idle_cpumask();

	return __COMPAT_scx_bpf_get_idle_cpumask_node(__COMPAT_scx_bpf_cpu_node(cpu));
}

/*
 * Return the cpumask of idle SMT cores within the NUMA node that contains
 * @cpu.
 *
 * If NUMA support is disabled, @cpu is ignored.
 */
static inline const struct cpumask *get_idle_smtmask(s32 cpu)
{
	if (!numa_enabled)
		return scx_bpf_get_idle_smtmask();

	return __COMPAT_scx_bpf_get_idle_smtmask_node(__COMPAT_scx_bpf_cpu_node(cpu));
}

/*
 * Return true if the CPU is part of a fully busy SMT core, false
 * otherwise.
 *
 * If SMT is disabled or SMT contention avoidance is disabled, always
 * return false (since there's no SMT contention or it's ignored).
 */
static bool is_smt_contended(s32 cpu)
{
	const struct cpumask *idle_mask;
	bool is_contended;

	if (!smt_enabled)
		return false;

	/*
	 * If the sibling SMT CPU is not idle and there are other full-idle
	 * SMT cores available, consider the current CPU as contended.
	 */
	idle_mask = get_idle_cpumask(cpu);
	is_contended = !bpf_cpumask_test_cpu(smt_sibling(cpu), idle_mask) &&
		       !bpf_cpumask_empty(idle_mask);
	scx_bpf_put_cpumask(idle_mask);

	return is_contended;
}

/*
 * Return true if @cpu is valid, otherwise trigger an error and return
 * false.
 */
static inline bool is_cpu_valid(s32 cpu)
{
	u64 max_cpu = MIN(nr_cpu_ids, MAX_CPUS);

	if (cpu < 0 || cpu >= max_cpu) {
		scx_bpf_error("invalid CPU id: %d", cpu);
		return false;
	}
	return true;
}

/*
 * Return true if @this_cpu and @that_cpu are in the same LLC, false
 * otherwise.
 */
static inline bool cpus_share_cache(s32 this_cpu, s32 that_cpu)
{
	if (this_cpu == that_cpu)
		return true;

	if (!is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu))
		return false;

	return cpu_llc_id(this_cpu) == cpu_llc_id(that_cpu);
}
/*
 * Return true if @this_cpu is faster than @that_cpu, false otherwise.
 */
static inline bool is_cpu_faster(s32 this_cpu, s32 that_cpu)
{
	if (all_cpus_same_capacity || this_cpu == that_cpu)
		return false;

	if (!is_cpu_valid(this_cpu) || !is_cpu_valid(that_cpu))
		return false;

	return cpu_capacity[this_cpu] > cpu_capacity[that_cpu];
}

/*
 * Return true if @cpu is in the primary domain, false otherwise.
 */
static inline bool is_primary_cpu(s32 cpu)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);

	if (primary_all)
		return true;

	return mask && bpf_cpumask_test_cpu(cpu, mask);
}

static inline bool is_cpu_idle(s32 cpu)
{
	struct task_struct *p;

	p = __COMPAT_scx_bpf_cpu_curr(cpu);

	return p ? p->flags & PF_IDLE : false;
}

/*
 * Test if a CPU is idle.
 *
 * If no_early_clear is true, leave the idle state intact so that concurrent
 * wakeups can stack tasks on the same cache. Otherwise, atomically test and
 * clear the idle state.
 */
static inline bool test_cpu_idle(s32 cpu)
{
	return no_early_clear ? is_cpu_idle(cpu) : scx_bpf_test_and_clear_cpu_idle(cpu);
}

/*
 * Try to pick the best idle CPU based on the @preferred_cpus ranking.
 * Return a full-idle SMT core if @do_idle_smt is true, or any idle CPU if
 * @do_idle_smt is false.
 */
static s32 pick_idle_cpu_pref_smt(struct task_struct *p, s32 prev_cpu, bool is_prev_allowed,
				  const struct cpumask *primary, const struct cpumask *smt)
{
	static u32 last_cpu;
	u64 max_cpus = MIN(nr_cpu_ids, MAX_CPUS);
	int i, start;

	if (is_prev_allowed &&
	    (!primary || bpf_cpumask_test_cpu(prev_cpu, primary)) &&
	    (!smt || bpf_cpumask_test_cpu(prev_cpu, smt)) &&
	    test_cpu_idle(prev_cpu))
		return prev_cpu;

	start = last_cpu;
	bpf_for(i, 0, max_cpus) {
		/*
		 * If @preferred_idle_scan is true, always scan the CPUs in
		 * the preferred order, otherwise rotate the CPUs to
		 * distribute the load more evenly.
		 */
		s32 cpu = preferred_idle_scan ?
				preferred_cpus[i] : (start + i) % max_cpus;

		if ((cpu == prev_cpu) || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;

		if ((!primary || bpf_cpumask_test_cpu(cpu, primary)) &&
		    (!smt || bpf_cpumask_test_cpu(cpu, smt)) &&
		    test_cpu_idle(cpu)) {
			if (!preferred_idle_scan)
				last_cpu = cpu + 1;
			return cpu;
		}
	}

	return -EBUSY;
}

/*
 * Return the optimal idle CPU for task @p or -EBUSY if no idle CPU is
 * found.
 */
static s32 pick_idle_cpu_flat(struct task_struct *p, s32 prev_cpu)
{
	const struct cpumask *smt, *primary;
	bool is_prev_allowed = bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr);
	s32 cpu;

	primary = !primary_all ? cast_mask(primary_cpumask) : NULL;
	smt = smt_enabled ? get_idle_smtmask(prev_cpu) : NULL;

	/*
	 * If the task can't migrate, there's no point looking for other
	 * CPUs.
	 */
	if (p->nr_cpus_allowed == 1 || is_migration_disabled(p)) {
		if (test_cpu_idle(prev_cpu)) {
			cpu = prev_cpu;
			goto out;
		}
	}

	if (!primary_all) {
		if (smt_enabled) {
			/*
			 * Try to pick a full-idle core in the primary
			 * domain.
			 */
			cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, smt);
			if (cpu >= 0)
				goto out;
		}

		/*
		 * Try to pick any idle CPU in the primary domain.
		 */
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, primary, NULL);
		if (cpu >= 0)
			goto out;
	}

	if (smt_enabled) {
		/*
		 * Try to pick any full-idle core in the system.
		 */
		cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, NULL, smt);
		if (cpu >= 0)
			goto out;
	}

	/*
	 * Try to pick any idle CPU in the system.
	 */
	cpu = pick_idle_cpu_pref_smt(p, prev_cpu, is_prev_allowed, NULL, NULL);

out:
	if (smt)
		scx_bpf_put_cpumask(smt);

	return cpu;
}

/*
 * Return true in case of a task wakeup, false otherwise.
 */
static inline bool is_wakeup(u64 wake_flags)
{
	return wake_flags & SCX_WAKE_TTWU;
}

/*
 * Pick an optimal idle CPU for task @p (as close as possible to
 * @prev_cpu).
 *
 * Return the CPU id or a negative value if an idle CPU can't be found.
  ================================
 ENQ 的时候需要选核：
 并非每次 enqueue 前都执行过 select_cpu。
常见情况包括：
任务从睡眠中唤醒：通常先 select_cpu。
任务时间片耗尽，但仍然 runnable。
任务被抢占后重新入队。
CPU 被更高调度类占用后重新入队。
迁移、亲和性变化及其他 re-enqueue 路径。
某些路径内核跳过了 select_cpu。
===================
所以 enqueue 中重新选核至少覆盖：

queued-wakeup 跳过 select_cpu；
migration-disabled/per-CPU 任务；
时间片耗尽或抢占后的重新入队；
任务重新入队、CPU ownership 变化等非唤醒路径；
select_cpu 执行过，但当时没有完成 direct dispatch；
从 select 到 enqueue 之间 CPU idle/SMT 状态发生变化。
 */
static s32 pick_idle_cpu(struct task_struct *p, s32 prev_cpu, s32 this_cpu,
			 u64 wake_flags, bool from_enqueue)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);
	s32 cpu;

	/*
	 * Use lightweight idle CPU scanning when flat or preferred idle
	 * scan is enabled, unless the system is busy, in which case the
	 * cpumask-based scanning is more efficient.
	 */
	if ((flat_idle_scan || preferred_idle_scan) && !is_cpu_busy(prev_cpu))
		return pick_idle_cpu_flat(p, prev_cpu);

	/*
	 * Clear the wake sync bit if synchronous wakeups are disabled.
	 */
	if (no_wake_sync)
		wake_flags &= ~SCX_WAKE_SYNC;

	/*
	 * On wakeup if the waker's CPU is faster than the wakee's CPU, try
	 * to move the wakee closer to the waker.
	 *
	 * In presence of hybrid cores this helps to naturally migrate
	 * tasks over to the faster cores.
	 */
	if (primary_all && is_wakeup(wake_flags) && this_cpu >= 0 &&
	    is_cpu_faster(this_cpu, prev_cpu)) {
		/*
		 * If both the waker's CPU and the wakee's CPU are in the
		 * same LLC and the wakee's CPU is a fully idle SMT core,
		 * don't migrate.
		 */
		if (cpus_share_cache(this_cpu, prev_cpu) &&
		    !is_smt_contended(prev_cpu) &&
		    test_cpu_idle(prev_cpu))
			return prev_cpu;

		prev_cpu = this_cpu;
	}

	/*
	 * Fallback to the old API if the kernel doesn't support
	 * scx_bpf_select_cpu_and().
	 *
	 * This is required to support kernels <= 6.16.
	 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		bool is_idle = false;

		if (from_enqueue)
			return -EBUSY;

		cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

		return is_idle ? cpu : -EBUSY;
	}

	/*
	 * If a primary domain is defined, try to pick an idle CPU from there
	 * first.
	 */
	if (!primary_all && mask) {
		cpu = scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, mask, 0);
		if (cpu >= 0)
			return cpu;
	}

	/*
	 * Pick any idle CPU usable by the task.
	 */
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags, p->cpus_ptr, 0);
}

/*
 * Return a time slice scaled by the task's weight.
 */
static u64 task_slice(const struct task_struct *p)
{
	return scale_by_task_weight(p, slice_ns);
}

/*
 * Calculate and return the virtual deadline for the given task.
 *
 *  The deadline is defined as:
 *
 *    deadline = vruntime + exec_vruntime
 *
 * Here, `vruntime` represents the task's total accumulated runtime,
 * inversely scaled by its weight, while `exec_vruntime` accounts the
 * runtime accumulated since the last sleep event, also inversely scaled by
 * the task's weight.
 *
 * Fairness is driven by `vruntime`, while `exec_vruntime` helps prioritize
 * tasks that sleep frequently and use the CPU in short bursts (resulting
 * in a small `exec_vruntime` value), which are typically latency critical.
 *
 * Additionally, to prevent over-prioritizing tasks that sleep for long
 * periods of time, the vruntime credit they can accumulate while sleeping
 * is limited by @slice_lag, which is also scaled based on the task's
 * weight.
 *
 * To prioritize tasks that sleep frequently over those with long sleep
 * intervals, @slice_lag is also adjusted in function of the task's wakeup
 * frequency: tasks that sleep often have a bigger slice lag, allowing them
 * to accumulate more time-slice credit than tasks with infrequent, long
 * sleeps.


 deadline = vruntime + weight_inverse(exec_runtime)
 vruntime：累计运行时间按 weight 反比缩放（公平）
exec_runtime：上次睡眠以来的运行量，上限 slice_lag（默认 20ms），压低长跑任务
睡眠攒的 vruntime 信用有上限：weight(slice_lag * wakeup_freq)，wakeup_freq
 用 EWMA，上限 1024
高频短睡任务 wakeup_freq 大、exec_runtime 小 → deadline 更靠前，这是交互优先的核心。
stopping 里实际 slice 还会按 CPU capacity 缩放：慢核上同样墙钟时间少记账，避免
 big.LITTLE 上慢核任务被当成“跑得少”。
默认 slice：-s 1000 → 1ms（README 写的 10µs 已过时）。

在经过睡眠信用上限裁剪的历史 vruntime 上，加上“本轮唤醒以来执行时间”的权重反比惩罚，得到 shared DSQ 排序键。
综合效果：

因素	对 deadline 的影响
高频唤醒
减小，提升优先级
睡醒后只跑很短时间
惩罚小
睡醒后持续占 CPU
增大，降低优先级
高权重任务
睡眠信用更大、运行惩罚更小
低权重任务
睡眠信用更小、运行惩罚更大

*/
static u64 task_dl(struct task_struct *p, struct task_ctx *tctx)
{
	u64 lag_scale = MAX(tctx->wakeup_freq, 1);
	u64 vsleep_max = scale_by_task_weight(p, slice_lag * lag_scale);
	u64 vtime_min = vtime_now - vsleep_max;

	if (time_before(p->scx.dsq_vtime, vtime_min))
		p->scx.dsq_vtime = vtime_min;

	return p->scx.dsq_vtime + scale_by_task_weight_inverse(p, tctx->exec_runtime);
}

/*
 * Initialize a new cpumask, return 0 in case of success or a negative
 * value otherwise.
 */
static int init_cpumask(struct bpf_cpumask **p_cpumask)
{
	struct bpf_cpumask *mask;

	mask = *p_cpumask;
	if (mask)
		return 0;

	mask = bpf_cpumask_create();
	if (!mask)
		return -ENOMEM;

	mask = bpf_kptr_xchg(p_cpumask, mask);
	if (mask)
		bpf_cpumask_release(mask);

	return *p_cpumask ? 0 : -ENOMEM;
}

SEC("syscall")
int enable_sibling_cpu(struct domain_arg *input)
{
	struct cpu_ctx *cctx;
	struct bpf_cpumask *mask, **pmask;
	int err = 0;

	cctx = try_lookup_cpu_ctx(input->cpu_id);
	if (!cctx)
		return -ENOENT;

	pmask = &cctx->smt;
	err = init_cpumask(pmask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = *pmask;
	if (mask)
		bpf_cpumask_set_cpu(input->sibling_cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

/*
 * Called from user-space to add CPUs to the the primary domain.
 */
SEC("syscall")
int enable_primary_cpu(struct cpu_arg *input)
{
	struct bpf_cpumask *mask;
	int err = 0;

	err = init_cpumask(&primary_cpumask);
	if (err)
		return err;

	bpf_rcu_read_lock();
	mask = primary_cpumask;
	if (mask)
		bpf_cpumask_set_cpu(input->cpu_id, mask);
	bpf_rcu_read_unlock();

	return err;
}

/*
 * Return true if the task should attempt a migration, false otherwise.
 */
static bool task_should_migrate(struct task_struct *p, u64 enq_flags)
{
	/*
	 * Attempt a migration on wakeup (task was not running) and only if
	 * ops.select_cpu() has not been called already.
	 */
	return !__COMPAT_is_enq_cpu_selected(enq_flags) && !scx_bpf_task_running(p);
}

/*
 * Return true if a task is waking up another task that share the same
 * address space, false otherwise.
 */
static inline bool is_wake_affine(const struct task_struct *waker, const struct task_struct *wakee)
{
	return mm_affinity &&
		!(waker->flags & PF_EXITING) && wakee->mm && (wakee->mm == waker->mm);
}

/* 
任务 p 被唤醒
  → cosmos_select_cpu(p)
      → 返回目标 CPU
      → 若调用 dsq_insert(... LOCAL)，直接派发，跳过 enqueue
      → 若未调用 dsq_insert，继续进入 enqueue
  → 内核把返回 CPU 记录为 p 当前关联的 CPU
  → cosmos_enqueue(p)
      → scx_bpf_task_cpu(p) 读到 select_cpu 返回的 CPU
      → 放入该 CPU 的 local DSQ，或放入 shared DSQ
  → CPU 优先消费自己的 local DSQ
  → local 没活时调用 cosmos_dispatch()
      → 从 shared DSQ 搬一个任务到 local DSQ
 */
s32 BPF_STRUCT_OPS(cosmos_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	const struct task_struct *current = (void *)bpf_get_current_task_btf();
	struct task_ctx *tctx;
	bool is_busy = is_cpu_busy(prev_cpu);
	s32 cpu, this_cpu = bpf_get_smp_processor_id();
	bool is_this_cpu_allowed = bpf_cpumask_test_cpu(this_cpu, p->cpus_ptr);

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return prev_cpu;

	/*
	 * Make sure @prev_cpu is usable, otherwise try to move close to
	 * the waker's CPU. If the waker's CPU is also not usable, then
	 * pick the first usable CPU.
	 prev_cpu 不在 cpus_ptr 里时，改成 waker CPU 或第一个可用 CPU
	 */
	if (!bpf_cpumask_test_cpu(prev_cpu, p->cpus_ptr))
		prev_cpu = is_this_cpu_allowed ? this_cpu : bpf_cpumask_first(p->cpus_ptr);

	/*
	 * When the waker and wakee share the same address space and were previously
	 * running on the same CPU, there's a high chance of finding hot cache data
	 * on that CPU. In such cases, prefer keeping the wakee on the same CPU.
	 *
	 * This optimization is applied only when the system is not saturated,
	 * to avoid introducing too much unfairness.
current：当前正在执行唤醒操作的任务，通常是 waker。
p：被唤醒的任务，即 wakee。
this_cpu：当前执行 select_cpu 回调的 CPU，通常是 waker 所在 CPU。
prev_cpu：p 上次运行或此前关联的 CPU；若已不在 p->cpus_ptr，会被代码修正。

	 */
	if (is_wake_affine(current, p) && !is_busy) {
		if (this_cpu == prev_cpu) {
			/* 是在“waker 当前 CPU 正好也是 wakee 上次 CPU”时，利用可能仍然
			热的缓存直接留在该 CPU。*/
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);
			return this_cpu;
		}
	}

	/*
	 * If GPU affinity is enabled and the task's pid is in gpu_pid_map
	 * but not on the GPU's node, try to pick a CPU on the GPU node.
	 */
	if (gpu_enabled && numa_enabled) {
		/* 尝试在 GPU 节点上选择一个 CPU。 */
		cpu = pick_cpu_on_gpu_node(p, cpu_node(prev_cpu), tctx);
		if (cpu >= 0) {
			__sync_fetch_and_add(&nr_gpu_dispatches, 1);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);
			return cpu;
		}
	}

	/*
	 * Try to find an idle CPU and dispatch the task directly to the
	 * target CPU.
	 *
	 * Since we only use local DSQs, there's no reason to bounce the
	 * task to ops.enqueue(). Dispatching directly from here, even if
	 * we can't find an idle CPU, allows to save some locking overhead.
	 */
	cpu = pick_idle_cpu(p, prev_cpu, is_this_cpu_allowed ? this_cpu : -1,
			    wake_flags, false);
	if (cpu >= 0 || !is_busy)
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), 0);/* 这里过会儿直接
	把这个进程插入到 select CPU 返回的 CPU 的 local dsq 里面。 */

	/* 
情况一：找到 idle CPU, 	效果：

记录 direct-dispatch；
返回目标 CPU；
内核将任务关联到该 CPU；
插入该 CPU 的 local DSQ；
跳过 cosmos_enqueue()。

情况二：没找到 idle CPU，但 prev_cpu 不忙

cpu < 0
!is_busy == true
仍执行 direct-dispatch：


scx_bpf_dsq_insert(... SCX_DSQ_LOCAL ...);
return prev_cpu;
效果是留在 prev_cpu，强调局部性，同样跳过 enqueue。

情况三：没找到 idle CPU，且 prev_cpu 忙

cpu < 0
is_busy == true
这时不调用 scx_bpf_dsq_insert()，只执行：


return prev_cpu;
prev_cpu 不是“不合适的无效 CPU”。
它仍然是一个合法、实际生效的初始 CPU/RQ 归属。
只是 Cosmos 没有在 select 阶段决定最终 DSQ。
因为没有 direct-dispatch 标记，内核随后调用 cosmos_enqueue()。
enqueue 可以再找 idle CPU，也可以把任务放进 shared DSQ。
换句话说：

return prev_cpu 负责给任务一个合法的初始 rq；“没有调用 dsq_insert”才表示把最终排队策略交给 enqueue。
而且 enqueue 并不知道前面的局部变量 cpu 是负数；它通过：

enq_flags；
当前 CPU 是否 idle；
CPU busy 状态；
SMT、PMU、主域、GPU 条件；
重新独立决策。

	
	*/
	return cpu >= 0 ? cpu : prev_cpu;
}

void BPF_STRUCT_OPS(cosmos_tick, struct task_struct *p)
{
	struct task_ctx *tctx;

	if (!time_preemption)
		return;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Force preemption if the task has exceeded its time slice and
	 * either:
	 * - SMT contention has changed since we started running
	 *   (sibling went busy or idle), triggering rescheduling so
	 *   select_cpu can make a better placement decision, or
	 * - the system is busy and there are tasks waiting in the
	 *   local or shared DSQ.
	 */
	if (time_delta(bpf_ktime_get_ns(), tctx->last_run_at) > task_slice(p)) {
		s32 cpu = scx_bpf_task_cpu(p);
		bool cpu_busy = scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu) ||
				scx_bpf_dsq_nr_queued(shared_dsq(cpu));

		if (is_smt_contended(cpu) || (is_cpu_busy(cpu) && cpu_busy))
			p->scx.slice = 0;
	}
}

/* enqueue 的准确含义：选 DSQ，不是“加入 RQ”
任务进入 enqueue 前通常已经有关联 CPU，即：scx_bpf_task_cpu(p)
但还需要决定等待在哪里：
当前 CPU 的 local DSQ；
明确指定 CPU 的 local DSQ；
全局/per-node shared DSQ。
因此更准确的描述是：
select_cpu：确定初始 CPU 归属
enqueue：确定任务放进哪个 sched_ext DSQ
dispatch：shared DSQ → 当前 CPU local DSQ
而不是“select 选 DSQ，enqueue 加入 RQ”。 */
void BPF_STRUCT_OPS(cosmos_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 prev_cpu = scx_bpf_task_cpu(p), cpu;
	int node = cpu_node(prev_cpu);
	struct task_ctx *tctx;

	/*
	 * Dispatch the task to the shared DSQ, using the deadline-based
	 * scheduling.
	 */
	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * If the task's pid is in gpu_pid_map (NVML GPU task), prefer the
	 * GPU NUMA node. If we're on a different node, migrate to the GPU
	 * node.
	 第一级：GPU 亲和
满足 GPU/NUMA、可迁移、目标 node 有 idle CPU：
→ LOCAL_ON | GPU_CPU
→ kick GPU_CPU
→ return
直接插入这个 GPU CPU 的 DSQ，方便保持它的亲和性。
	 */
	if (gpu_enabled && numa_enabled && !is_pcpu_task(p) &&
	    task_should_migrate(p, enq_flags)) {
			/* GPU 任务：迁到 GPU node 的 LOCAL_ON，必要时 kick_cpu(IDLE) */
		cpu = pick_cpu_on_gpu_node(p, node, tctx);
		if (cpu >= 0) {
			/* 当前/隐含 CPU：SCX_DSQ_LOCAL
显式指定 CPU：SCX_DSQ_LOCAL_ON | cpu
下面这段确实把 GPU 任务插入选中的 CPU*/
			__sync_fetch_and_add(&nr_gpu_dispatches, 1);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					   task_slice(p), enq_flags);
			if (cpu != prev_cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}

	/*
	 * Attempt to immediately dispatch sticky event-heavy tasks to the
	 * same CPU.
	 sticky PMU：事件超过阈值、且在主域/绑核、SMT 不争用 → 钉在原 CPU（若共享队列
	 队头是 per-CPU 任务则放弃，防饿死）
	 */
	if (is_sticky_event_heavy(tctx) &&
	    (is_primary_cpu(prev_cpu) || is_pcpu_task(p)) &&
	    !is_smt_contended(prev_cpu)) {
		const struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(shared_dsq(prev_cpu));

		/*
		 * If a per-CPU task is waiting to acquire the CPU, skip
		 * direct dispatch to prevent starvation.
		 */
		if (!q || q->nr_cpus_allowed > 1) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, task_slice(p), enq_flags);
			__sync_fetch_and_add(&nr_ev_sticky_dispatches, 1);

			if (!scx_bpf_task_running(p))
				scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
			return;
		}

	}

	/*
	 * Attempt to dispatch directly to an idle CPU if the task can
	 * migrate.
	 需要迁移 / 原 CPU 非空闲 / SMT 争用 / PMU 过重 / 不在主域 → 再找 idle，成功则 LOCAL_ON
	 */
	if (task_should_migrate(p, enq_flags) ||
	    !is_cpu_idle(prev_cpu) ||
	    is_smt_contended(prev_cpu) ||
	    (!is_pcpu_task(p) && (is_event_heavy(tctx) || !is_primary_cpu(prev_cpu)))) {
/* 也就是：

本次没有经过 select_cpu；
原 CPU 不 idle；
原 CPU 有 SMT contention；
PMU migration event 过重；
原 CPU 不在 primary domain。
找到 CPU 后直接 LOCAL_ON | cpu。 */
		if (is_pcpu_task(p))
			cpu = test_cpu_idle(prev_cpu) ? prev_cpu : -EBUSY;
		else
			cpu = pick_idle_cpu(p, prev_cpu, -1, 0, true);
		if (cpu >= 0) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, task_slice(p), enq_flags);
			if (is_event_heavy(tctx) && cpu != prev_cpu)
				__sync_fetch_and_add(&nr_event_dispatches, 1);

			if (cpu != prev_cpu || !scx_bpf_task_running(p))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			return;
		}
	}
	/*
	 * Keep using the same CPU if that CPU is not busy.
	 原 CPU 不忙且在主域（或绑核）→ 继续 LOCAL_ON
	 */
	if (!is_cpu_busy(prev_cpu) &&
	    (is_primary_cpu(prev_cpu) || is_pcpu_task(p))) {
/* 第四级：留在原 CPU
如果没有成功直接派发，而且：
原 CPU 不忙；
原 CPU 在 primary domain，或任务不可迁移；
则：→ LOCAL_ON | prev_cpu */
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, task_slice(p), enq_flags);
		if (task_should_migrate(p, enq_flags))
			scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
		return;
	}
/* 第五级：shared deadline DSQ
剩余任务：
→ shared/per-node DSQ
→ 按 virtual deadline 排序
因此说“走到这里就是前面两个 if 都没进去”不完全准确。还可能是：
sticky 分支进去了，但发现 q 是单核任务；
重选 idle 分支进去了，但没找到 idle CPU；
GPU 分支进去了，但目标 node 没有可用 idle CPU。
关键条件是：前面都没有成功 direct dispatch 并 return。 */
	/*
	 * Dispatch the task to the shared DSQ.
	 否则 dsq_insert_vtime(shared_dsq, deadline)
为什么只有 shared DSQ 使用 deadline？
不是因为 shared DSQ“优先级低”，而是两种模式的目标不同：

local DSQ：低负载模式，强调 CPU locality、低锁竞争和简单 FIFO/RR。
shared DSQ：高负载模式，多个 CPU/任务竞争，需要跨 CPU 公平性和交互优先，因此用 vtime 排序。
如果 local 也按 deadline 排序，就增加了 Cosmos 低负载快速路径的复杂度，并削弱其“local round-robin”的设计目标。
	 */
	scx_bpf_dsq_insert_vtime(p, shared_dsq(prev_cpu),
				 task_slice(p), task_dl(p, tctx), enq_flags);

	if (task_should_migrate(p, enq_flags))
		scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
}

/*
 * Return true if the task can keep running on its current CPU from
 * ops.dispatch(), false if the task should migrate.
 */
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	const struct cpumask *mask = cast_mask(primary_cpumask);

	/*
	 * Do not keep running if the task doesn't need to run.
	 */
	if (!is_task_queued(p))
		return false;

	/*
	* If the task can only run on this CPU, keep it running.
	*/
	if (is_pcpu_task(p))
		return true;

	/*
	 * If the task is not running in a full-idle SMT core and there are
	 * full-idle SMT cores available in the system, give it a chance to
	 * migrate elsewhere.
	 */
	if (is_smt_contended(cpu))
		return false;

	/*
	 * If the task is not in the primary domain, give it a chance to
	 * migrate.
	 */
	if (!is_primary_cpu(cpu) &&
	    mask && bpf_cpumask_intersects(p->cpus_ptr, mask))
		return false;

	return true;
}

/* 这里来消费共享 DSQ 里面的任务。 */
void BPF_STRUCT_OPS(cosmos_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Check if the there's any task waiting in the shared DSQ and
	 * dispatch.
	 */
	if (scx_bpf_dsq_move_to_local(shared_dsq(cpu), 0))
		return;

	/*
	 * If the previous task expired its time slice, but no other task
	 * wants to run on this CPU, give it another time slot if the CPU
	 * is on the primary domain.
	 */
	if (prev && keep_running(prev, cpu))
		prev->scx.slice = task_slice(prev);
}

void BPF_STRUCT_OPS(cosmos_runnable, struct task_struct *p, u64 enq_flags)
{
	u64 now = bpf_ktime_get_ns(), delta_t;
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Reset exec runtime (accumulated execution time since last
	 * sleep).
	 */
	tctx->exec_runtime = 0;

	/*
	 * Update the task's wakeup frequency based on the time since
	 * the last wakeup, then cap the result at 1024 to avoid large
	 * spikes.
	 */
	delta_t = now - tctx->last_woke_at;
	tctx->wakeup_freq = update_freq(tctx->wakeup_freq, delta_t);
	tctx->wakeup_freq = MIN(tctx->wakeup_freq, 1024);
	tctx->last_woke_at = now;
}

void BPF_STRUCT_OPS(cosmos_running, struct task_struct *p)
{
	struct task_ctx *tctx;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Save a timestamp when the task begins to run (used to evaluate
	 * the used time slice).
	 */
	tctx->last_run_at = bpf_ktime_get_ns();

	/*
	 * Update current system's vruntime.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	/*
	 * Refresh cpufreq performance level.
	 */
	update_cpufreq(scx_bpf_task_cpu(p));

	/*
	 * Capture performance counter baseline when task starts running.
	 */
	if (perf_config || perf_sticky)
		scx_pmu_event_start(p, false);
}

/*
 * Return the time slice normalized by @cpu's capacity.
 */
static u64 scale_by_cpu_capacity(u64 slice, s32 cpu)
{
	if (all_cpus_same_capacity || !is_cpu_valid(cpu))
		return slice;

	return slice * cpu_capacity[cpu] / SCX_CPUPERF_ONE;
}

void BPF_STRUCT_OPS(cosmos_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);
	struct task_ctx *tctx;
	u64 slice;

	tctx = try_lookup_task_ctx(p);
	if (!tctx)
		return;

	/* Update task's performance counters */
	if (perf_config || perf_sticky) {
		scx_pmu_event_stop(p);
		update_counters(p, tctx, cpu);
	}

	/*
	 * Evaluate the used time slice.
	 */
	slice = bpf_ktime_get_ns() - tctx->last_run_at;

	/*
	 * Scale used time slice by CPU capacity: time spent on slower CPU
	 * is charged less time than running on faster CPU.
	 */
	slice = scale_by_cpu_capacity(slice, cpu);

	/*
	 * Update the vruntime and the total accumulated runtime since last
	 * sleep.
	 *
	 * Cap the maximum accumulated time since last sleep to @slice_lag,
	 * to prevent starving CPU-intensive tasks.
	 */
	p->scx.dsq_vtime += scale_by_task_weight_inverse(p, slice);
	tctx->exec_runtime = MIN(tctx->exec_runtime + slice, slice_lag);

	/*
	 * Update per-CPU statistics.
	 */
	update_cpu_load(p, slice);
}

void BPF_STRUCT_OPS(cosmos_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS(cosmos_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	struct task_ctx *tctx;
	int ret;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!tctx)
		return -ENOMEM;

	if ((ret = scx_pmu_task_init(p)))
		return ret;

	ret = init_cpumask(&tctx->cpumask);
	if (ret)
		return ret;

	return 0;
}

void BPF_STRUCT_OPS(cosmos_exit_task, struct task_struct *p,
		   struct scx_exit_task_args *args)
{
	scx_pmu_task_fini(p);
}

/*
 * Initialize a NUMA node context.
 *
 * Return 0 if @node contains at least one CPU, -ENODEV if it is CPU-less, or
 * another negative errno on failure.
 */
static int init_node(int node)
{
	struct bpf_cpumask *cpumask;
	struct node_ctx *nctx;
	bool has_cpus = false;
	u32 cpu;
	int ret;

	nctx = try_lookup_node_ctx(node);
	if (!nctx)
		return -ENOENT;

	ret = init_cpumask(&nctx->cpumask);
	if (ret)
		return ret;

	bpf_rcu_read_lock();
	cpumask = nctx->cpumask;
	if (!cpumask) {
		ret = -EINVAL;
		goto out_unlock;
	}
	bpf_for(cpu, 0, nr_cpu_ids) {
		if (cpu_node(cpu) == node) {
			bpf_cpumask_set_cpu(cpu, cpumask);
			has_cpus = true;
		}
	}
out_unlock:
	bpf_rcu_read_unlock();

	if (ret)
		return ret;
	return has_cpus ? 0 : -ENODEV;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cosmos_init)
{
	int err;
	int cpu;
	struct cpu_ctx *cctx;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();

	/*
	 * Create separate per-node DSQs if NUMA optimization is enabled,
	 * otherwise use a single shared DSQ.
	 */
	if (numa_enabled) {
		int node;

		bpf_for(node, 0, nr_node_ids) {
			/*
			 * Skip per-node DSQ creation for nodes that failed to
			 * initialize, including CPU-less NUMA nodes (e.g.,
			 * GPU-memory or CXL-memory nodes): with no CPU to
			 * consume from it, the DSQ would never be used.
			 */
			err = init_node(node);
			if (err)
				continue;

			err = scx_bpf_create_dsq(node, node);
			if (err) {
				scx_bpf_error("failed to create node DSQ %d: %d", node, err);
				return err;
			}
		}
	} else {
		err = scx_bpf_create_dsq(SHARED_DSQ, -1);
		if (err) {
			scx_bpf_error("failed to create shared DSQ: %d", err);
			return err;
		}
	}

	bpf_for(cpu, 0, nr_cpu_ids) {
		cctx = try_lookup_cpu_ctx(cpu);
		if (!cctx)
			continue;
		cctx->perf_events = 0;
	}

	if (perf_config) {
		err = scx_pmu_install(perf_config);
		if (err)
			return err;
	}

	if (perf_sticky) {
		err = scx_pmu_install(perf_sticky);
		if (err)
			return err;
	}

	return 0;
}

void BPF_STRUCT_OPS(cosmos_exit, struct scx_exit_info *ei)
{
	if (perf_config)
		scx_pmu_uninstall(perf_config);

	if (perf_sticky)
		scx_pmu_uninstall(perf_sticky);

	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(cosmos_ops,
	       .select_cpu		= (void *)cosmos_select_cpu,
	       .enqueue			= (void *)cosmos_enqueue,
	       .dispatch		= (void *)cosmos_dispatch,
	       .tick                    = (void *)cosmos_tick,
	       .runnable		= (void *)cosmos_runnable,
	       .running			= (void *)cosmos_running,
	       .stopping		= (void *)cosmos_stopping,
	       .enable			= (void *)cosmos_enable,
	       .init_task		= (void *)cosmos_init_task,
	       .exit_task		= (void *)cosmos_exit_task,
	       .init			= (void *)cosmos_init,
	       .exit			= (void *)cosmos_exit,
	       .timeout_ms		= 5000,
	       .name			= "cosmos");
