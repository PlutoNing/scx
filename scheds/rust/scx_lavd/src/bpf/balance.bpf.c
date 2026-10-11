/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2025 Valve Corporation.
 * Author: Changwoo Min <changwoo@igalia.com>
 */

#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <lib/cgroup.h>


/* 这个文件解决的是跨域负载均衡
sys_stat timer (每~10ms)
   └─ plan_x_cpdom_migration()
        ├─ 计算每个域 load_invr
        ├─ classify_cpdom() ×N → 设置 is_stealer / is_stealee / budget
        └─ 无需均衡则重置所有标记

CPU dispatch
   └─ consume_task()
        ├─ 本域是 stealer? → try_to_steal_task()   (受预算约束)
        ├─ 本域 DSQ 消费 (vtime 最小优先)
        └─ 仍没任务 → force_to_steal_task()        (保持 work-conserving)
		 */
extern const volatile u8	mig_delta_pct;
extern const volatile u8	no_fast_lb;
extern const volatile u64	lb_low_util_wall;

/* 计算迁移容忍带 x_mig_delta,作用是给"公平份额"加上滞回区间,避免负载稍有偏差就
来回迁移(ping-pong)。 */
u64 __attribute__ ((noinline)) calc_mig_delta(u64 avg_load_invr, int nz_qlen,
					      u64 mig_delta_factor)
{
	/*
	 * Note that added "noinline" to make the verifier happy.
	 * When mig_delta_factor > 0, the user specified a fixed
	 * migration delta percentage; otherwise use the dynamic
	 * shift-based heuristic.
	 nz_qlen = 有排队负载的域个数。越多域在排队(系统越忙),容忍带越窄,
	 均衡越积极;没人排队时带宽很宽,几乎不迁移。noinline 是为了让 verifier 分开分析。
	 */
	if (mig_delta_factor > 0)
		return avg_load_invr * mig_delta_factor / LAVD_SCALE;
	if (nz_qlen >= sys_stat.nr_active_cpdoms)
		return avg_load_invr >> LAVD_CPDOM_MIG_SHIFT_OL;
	if (nz_qlen == 0)
		return avg_load_invr >> LAVD_CPDOM_MIG_SHIFT_UL;
	return avg_load_invr >> LAVD_CPDOM_MIG_SHIFT;
}

/*
给单个域定角色。返回 1 表示它成为 stealee。
 * Classify a single compute domain as stealer, stealee, or neutral.
 * Returns 1 if the domain became a stealee, 0 otherwise.
 * Marked noinline so the verifier analyses it separately from the
 * calling loop, keeping the jump complexity of the caller manageable.
 */
int __attribute__((noinline))
classify_cpdom(struct cpdom_ctx *cpdomc, u64 total_load_invr,
	       u64 total_cap_sum, int nz_qlen, u64 mig_delta_factor)
{
	u64 x_mig_delta = 0;
	u64 fair_share_invr = 0;
	u64 stealer_threshold = 0;
	u64 stealee_threshold = 0;

	if (!cpdomc)
		return 0;

		/* 第一步:算阈值 */
	if (no_fast_lb && sys_stat.nr_active_cpdoms) {
		/* no_fast_lb:简单平均 avg = total_load / nr_active_cpdoms,上下加减 delta。 */
		u64 avg = total_load_invr / sys_stat.nr_active_cpdoms;
		x_mig_delta = calc_mig_delta(avg, nz_qlen, mig_delta_factor);
		stealer_threshold = avg - x_mig_delta;
		stealee_threshold = avg + x_mig_delta;
	} else if (cpdomc->nr_active_cpus && total_cap_sum > 0) {
		/* fast LB(默认):按算力比例的公平份额 fair_share_invr = 
		total_load_invr × cap_sum_active_cpus / total_cap_sum 然后
		 stealer_threshold = fair_share − delta,stealee_threshold = fair_share + delta。 
		这对大小核异构很重要:大核域应该承担更多负载。 */
		fair_share_invr = total_load_invr *
			     cpdomc->cap_sum_active_cpus /
			     total_cap_sum;

		x_mig_delta = calc_mig_delta(
				fair_share_invr, nz_qlen,
				mig_delta_factor);

		stealer_threshold = fair_share_invr - x_mig_delta;
		stealee_threshold = fair_share_invr + x_mig_delta;
	}

	/* 第二步:判 stealer 条件:域活跃且 load_invr <= stealer_threshold。 */
	/*
	 * Under-loaded active domains become a stealer.
	 * Ingress budget = half the deficit below fair share.
	 */
	if (cpdomc->nr_active_cpus &&
	    cpdomc->load_invr <= stealer_threshold) {
			/* stealer_budget = (fair_share − load_invr) / 2:只填补一半缺口,防止过冲。
设置 is_stealer = true、is_stealee = false,返回 0。 */
		u64 stealer_budget = 0;

		if (fair_share_invr > cpdomc->load_invr)
			stealer_budget = (fair_share_invr -
					  cpdomc->load_invr) / 2;

		WRITE_ONCE(cpdomc->stealer_budget_invr, stealer_budget);
		WRITE_ONCE(cpdomc->stealee_budget_invr, 0);
		WRITE_ONCE(cpdomc->is_stealer, true);
		WRITE_ONCE(cpdomc->is_stealee, false);
		return 0;
	}

	/*
	第三步:判 stealee 条件:域非活跃,或 load_invr >= stealee_threshold。
	 * Over-loaded or non-active domains become a stealee.
	 * Egress budget = half the excess above fair share. Halving
	 * (rather than draining the full excess) avoids two failure
	 * modes:
	 * - Ping-pong: prevent overshooting. Moving everything in one
	 *   round may trigger the imbalance and ping-pong effect.
	 * - Thundering-herd: without a per-round limit, every stealer
	 *   that sees this domain can migrate out the tasks from it and
	 *   drain it past the fair share in a single round.
	 *
	 * Also skip domains with nothing to steal: a domain may appear
	 * overloaded due to running task utilization (avg_util_invr_sum)
	 * but have an empty DSQ — trying to steal from it would waste
	 * cycles and could cause oscillation.
	 */
	if (!cpdomc->nr_active_cpus ||
	    cpdomc->load_invr >= stealee_threshold) {
		u64 stealee_budget_invr = 0;

		/* 若 qload_invr == 0 → 没有排队任务可偷,重置角色
		(注释:可能因为"正在运行"的负载大而看起来过载,但 DSQ 是空的,硬偷只会浪费、引起震荡)。 */
		if (cpdomc->qload_invr == 0)
			goto reset_role;

			/* stealee_budget = (load_invr − fair_share) / 2,同样取一半,避免:
ping-pong:一次迁太多导致反向失衡
惊群:多个 stealer 同时看到该域,在一轮里把它抽干 */
		if (cpdomc->load_invr > fair_share_invr)
			stealee_budget_invr = (cpdomc->load_invr -
					       fair_share_invr) / 2;

		if (!stealee_budget_invr)
			goto reset_role;

		WRITE_ONCE(cpdomc->stealee_budget_invr, stealee_budget_invr);
		WRITE_ONCE(cpdomc->stealer_budget_invr, 0);
		WRITE_ONCE(cpdomc->is_stealer, false);
		WRITE_ONCE(cpdomc->is_stealee, true);
		return 1;
	}

reset_role:
	WRITE_ONCE(cpdomc->stealee_budget_invr, 0);
	WRITE_ONCE(cpdomc->stealer_budget_invr, 0);
	WRITE_ONCE(cpdomc->is_stealer, false);
	WRITE_ONCE(cpdomc->is_stealee, false);
	return 0;
}

/* 跨域负载均衡,
它是 pull 模型:空闲/低负载的域主动去偷,不是高负载域往外推。分两个阶段:
计划阶段：plan_x_cpdom_migration()全局统计各域负载,把域标记为 stealer(偷取方)/ stealee(被偷方),并计算预算
执行(Execute)阶段：每个 CPU 在 dispatch 时,需要拿任务
调用consume_task() → try_to_steal_task() / force_to_steal_task()
按规划结果实际从别的域拉任务
*/
/* . plan_x_cpdom_migration()(142–246 行)
规划阶段入口,标 __weak 以便链接。流程:

统计每个活跃域的负载(158–193 行)

跳过 nr_active_cpus == 0 的域,但若其 cur_util_wall_sum > 0,说明休眠域上仍有任务在跑 → overflow_running = true(需要触发均衡把它们迁走)。
计算 per-CPU 平均利用率 util = avg_util_wall_sum / nr_active_cpus,记录最大值 max_avg_util_wall。
域负载:
fast LB:load_invr = avg_util_invr_sum + qload_invr(运行负载 + 排队负载),qload_invr != 0 则 nz_qlen++。
no_fast_lb:util + qlen_invr,其中 qlen_invr 按任务数除以算力。
累加 total_load_invr、total_cap_sum。
低利用率短路(200–201 行) max_avg_util_wall < lb_low_util_wall → 系统整体很闲,不值得均衡,跳到 reset。

准备 mig_delta_factor(209–211 行):把百分比转定点数。

逐域分类(213–222 行):调用 classify_cpdom(),累计 nr_stealee。

无需均衡:nr_stealee == 0 && !overflow_running → reset。否则写入 sys_stat.nr_stealee 返回。

reset_and_skip_lb(231–245 行):仅在上一轮有 stealee 时(sys_stat.nr_stealee > 0)才遍历清理所有域的标志和预算,并把 nr_stealee 置 0——避免每轮无谓写 cacheline。

这个函数每个周期会"从头重算"所有预算,所以消费端对预算的过度扣减会在下一轮自我纠正。 */
__weak
int plan_x_cpdom_migration(void)
{
	struct cpdom_ctx *cpdomc;
	u64 cpdom_id;
	u32 nr_stealee = 0;
	u64 max_avg_util_wall = 0;
	u64 util;
	u64 total_load_invr = 0;
	u64 total_cap_sum = 0;
	bool overflow_running = false;
	int nz_qlen = 0;

	/*
	统计每个活跃域的负载
	 * Calculate load for each active compute domain.
	 */
	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
		if (!cpdomc->nr_active_cpus) {
			if (cpdomc->cur_util_wall_sum > 0)
				overflow_running = true;
			continue;
		}

		util = (cpdomc->avg_util_wall_sum << LAVD_SHIFT) / cpdomc->nr_active_cpus;
		if ((util >> LAVD_SHIFT) > max_avg_util_wall)
			max_avg_util_wall = util >> LAVD_SHIFT;

		/*
		 * Domain load combines running load (avg_util_invr_sum)
		 * and queued load (qload_invr, tracked atomically via
		 * account/unaccount at enqueue/running).
		 */
		if (no_fast_lb) {
			u64 qlen = cpdomc->nr_queued_task;
			u64 qlen_invr = (qlen << (LAVD_SHIFT * 3)) /
					cpdomc->cap_sum_active_cpus;
			cpdomc->load_invr = util + qlen_invr;
			if (qlen)
				nz_qlen++;
		} else {
			cpdomc->load_invr = cpdomc->avg_util_invr_sum +
					    cpdomc->qload_invr;
			if (cpdomc->qload_invr)
				nz_qlen++;
		}
		total_load_invr += cpdomc->load_invr;
		total_cap_sum += cpdomc->cap_sum_active_cpus;
	}

	/*
	 * When the highest per-CPU utilization among all compute
	 * domains is below the low utilization threshold, there is
	 * no meaningful workload worth rebalancing across domains.
	 */
	if (lb_low_util_wall > 0 && max_avg_util_wall < lb_low_util_wall)
		goto reset_and_skip_lb;

	/*
	 * Classify stealer and stealee domains using per-domain
	 * capacity-proportional targets. Each domain's target is its
	 * fair share of total system load scaled by its capacity
	 * proportion.
	 */
	u64 mig_delta_factor = 0;
	if (mig_delta_pct > 0)
		mig_delta_factor = (mig_delta_pct << LAVD_SHIFT) / 100;

	bpf_for(cpdom_id, 0, nr_cpdoms) {
		if (cpdom_id >= LAVD_CPDOM_MAX_NR)
			break;

		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);

		nr_stealee += classify_cpdom(cpdomc, total_load_invr,
					     total_cap_sum, nz_qlen,
					     mig_delta_factor);
	}

	if (nr_stealee == 0 && !overflow_running)
		goto reset_and_skip_lb;

	sys_stat.nr_stealee = nr_stealee;

	return 0;

reset_and_skip_lb:
	if (sys_stat.nr_stealee > 0) {
		bpf_for(cpdom_id, 0, nr_cpdoms) {
			if (cpdom_id >= LAVD_CPDOM_MAX_NR)
				break;

			cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
			WRITE_ONCE(cpdomc->stealee_budget_invr, 0);
			WRITE_ONCE(cpdomc->stealer_budget_invr, 0);
			WRITE_ONCE(cpdomc->is_stealer, false);
			WRITE_ONCE(cpdomc->is_stealee, false);
		}
		sys_stat.nr_stealee = 0;
	}
	return 0;
}

/*
对 scx_bpf_dsq_move_to_local(dsq_id, 0) 的封装:把指定 DSQ 的队首任务移入当前
 CPU 的本地 DSQ。is_monitored 打开时,
记录耗时写入 cpdomc->dsq_consume_lat。参数 dsq_id 可以是 per-cpdom DSQ 或 per-CPU DSQ。
 * dsq_id: candidate DSQ to consume from, can be per-cpdom or per-cpu.
 */
static bool consume_dsq(struct cpdom_ctx *cpdomc, u64 dsq_id)
{
	bool ret;
	u64 before = 0;

	if (is_monitored)
		before = bpf_ktime_get_ns();
	/*
	 * Try to consume a task on the associated DSQ.
	 */
	ret = scx_bpf_dsq_move_to_local(dsq_id, 0);

	if (is_monitored)
		cpdomc->dsq_consume_lat = time_delta(bpf_ktime_get_ns(), before);

	return ret;
}

/* 用 __COMPAT_scx_bpf_dsq_peek() 窥视 DSQ 队首任务(不取出),取其 task_ctx,返回
 task_load_metric。
用于预算扣减量。窥不到返回 0。 */
u64 __attribute__((noinline)) dsq_peek_task_load(u64 dsq_id)
{
	struct task_struct *peek_p = __COMPAT_scx_bpf_dsq_peek(dsq_id);

	if (peek_p) {
		task_ctx *peek_taskc = get_task_ctx(peek_p);
		if (peek_taskc)
			return task_load_metric(peek_taskc);
	}
	return 0;
}

/* 在 stealee 域内挑选负载最重的 DSQ:

域级 DSQ(use_cpdom_dsq()):候选 = cpdom_to_dsq(id),负载 = qload_invr(no_fast_lb 时为 DSQ 队列长度)。
per-CPU DSQ(is_per_cpu_dsq_migratable()):遍历域内所有 CPU(用 __cpumask 逐 64 位、cpumask_next_set_bit 找置位),负载为 cpuc->qload_invr(no_fast_lb 时为 per-CPU DSQ + SCX_DSQ_LOCAL_ON 队列长度),取最大者。
返回 DSQ id,没有任何排队负载则保持 -ENOENT。
注释提到:当 pinned_slice_ns 开启但 per_cpu_dsq 关闭时,per-CPU DSQ 里只有被绑定的任务,不可迁移,所以不检查。

(highest_load 初值是域 DSQ 的负载,所以 per-CPU DSQ 必须"严格更重"才会替换。) */
u64 __attribute__((noinline)) pick_most_loaded_dsq(struct cpdom_ctx *cpdomc)
{
	u64 pick_dsq_id = -ENOENT;
	u64 highest_load = 0;

	if (!cpdomc) {
		scx_bpf_error("Invalid cpdom context");
		return -ENOENT;
	}

	/*
	 * Pick the (per-CPU or per-domain) DSQ in this compute domain
	 * with the highest RAVG-weighted queued load.
	 */
	if (use_cpdom_dsq()) {
		pick_dsq_id = cpdom_to_dsq(cpdomc->id);
		if (no_fast_lb)
			highest_load = scx_bpf_dsq_nr_queued(pick_dsq_id);
		else
			highest_load = READ_ONCE(cpdomc->qload_invr);
	}

	/*
	 * When tasks on a per-CPU DSQ are not migratable
	 * (e.g., pinned_slice_ns is on but per_cpu_dsq is not),
	 * there is no need to check per-CPU DSQs.
	 */
	if (is_per_cpu_dsq_migratable()) {
		int pick_cpu = -ENOENT, cpu, i, j, k;

		bpf_for(i, 0, LAVD_CPU_ID_MAX/64) {
			u64 cpumask = cpdomc->__cpumask[i];
			bpf_for(k, 0, 64) {
				u64 load;

				j = cpumask_next_set_bit(&cpumask);
				if (j < 0)
					break;
				cpu = (i * 64) + j;
				if (cpu >= nr_cpu_ids)
					break;

				if (no_fast_lb) {
					load = scx_bpf_dsq_nr_queued(cpu_to_dsq(cpu)) +
					       scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | cpu);
				} else {
					struct cpu_ctx *cpuc = get_cpu_ctx_id(cpu);
					load = cpuc ? READ_ONCE(cpuc->qload_invr) : 0;
				}
				if (load > highest_load) {
					highest_load = load;
					pick_cpu = cpu;
				}
			}
		}

		if (pick_cpu != -ENOENT)
			pick_dsq_id = cpu_to_dsq(pick_cpu);
	}

	return pick_dsq_id;
}

/* try_to_steal_task()(344–452 行)
受控偷取(依赖规划阶段的标志与预算),调用者是 stealer 域的 CPU。

非活跃域不偷。
no_fast_lb 时按概率 1 / (nr_active_cpus × MIG_PROB_FT) 尝试,让整个域平均每个周期
只尝试少数几次,避免所有 CPU 同时去偷。
按距离由近到远遍历邻居(外层 i 是距离层级,内层 j 是同距离内的环形序):
跳过非 is_stealee、非 is_valid、或 stealee_budget_invr <= 0 的域。
pick_most_loaded_dsq() 选 DSQ;(s64)dsq_id < 0 则 continue(否则后面传 -ENOENT
 会让调度器报错退出)。
dsq_peek_task_load() 获取预估任务大小(no_fast_lb 时跳过)。注释说明有 TOCTOU:peek
 的任务不一定是最终被 consume 的那个,
但预算只是提示,下一轮会重算,可接受。
consume_dsq() 成功后:
no_fast_lb:直接清掉双方的 is_stealee / is_stealer,即"一次一个"。
fast LB:decrement_stealee_budget / decrement_stealer_budget,原子扣减,预算 ≤ 0 时
自动清标志。stealer 在整轮里可持续偷,直到预算耗尽。
同一距离层级偷不到,则以 1 / LAVD_CPDOM_MIG_PROB_FT 的概率才去更远一层,否则 break。跨
更远(如跨 NUMA)迁移代价更大,所以概率随距离指数衰减,更倾向近邻。 */
static bool try_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	s64 nr_nbr, cpdom_id;

	/*
	 * Only active domains steal the tasks from other domains.
	 */
	if (!cpdomc->nr_active_cpus)
		return false;

	if (no_fast_lb &&
	    !prob_x_out_of_y(1, cpdomc->nr_active_cpus * LAVD_CPDOM_MIG_PROB_FT))
		return false;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbors in the same distance in circular distance order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++) {
			u64 dsq_id;
			if (j >= nr_nbr)
				break;

			cpdom_id = get_neighbor_id(cpdomc, i, j);
			if (cpdom_id < 0)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", cpdom_id);
				return false;
			}

			if (!READ_ONCE(cpdomc_pick->is_stealee) || !cpdomc_pick->is_valid)
				continue;

			if (READ_ONCE(cpdomc_pick->stealee_budget_invr) <= 0)
				continue;

			dsq_id = pick_most_loaded_dsq(cpdomc_pick);

			/*
			 * No DSQ in cpdomc_pick has any queued load.
			 * Move on to the next neighbor rather than passing
			 * -ENOENT to dsq_peek_task_load() / consume_dsq(),
			 * which would abort the scheduler.
			 */
			if ((s64)dsq_id < 0)
				continue;

			/*
			 * Peek at the head task to get its size for budget
			 * accounting. Skip the peek when no_fast_lb is set
			 * since the budget path below is bypassed and the
			 * value would be unused.
			 *
			 * TOCTOU: the task peeked here may not be the one
			 * actually consumed by consume_dsq() below. To be more
			 * specific, another CPU may grab the head first, or the
			 * task may become ineligible during the window between
			 * the peek and the consume_dsq. The budget is just a
			 * hint, and over-debiting will be self-corrected
			 * because the next LB round recomputes budgets from
			 * scratch.
			 */
			u64 task_load = no_fast_lb ? 0 : dsq_peek_task_load(dsq_id);

			/*
			 * On success, decrement both egress and ingress
			 * budgets. The stealer stays active for the
			 * entire round. Budget exhaustion clears the
			 * is_stealee/is_stealer flags via the decrement
			 * helpers.
			 */
			if (consume_dsq(cpdomc_pick, dsq_id)) {
				if (no_fast_lb) {
					WRITE_ONCE(cpdomc_pick->is_stealee, false);
					WRITE_ONCE(cpdomc->is_stealer, false);
				} else {
					decrement_stealee_budget(cpdomc_pick, task_load);
					decrement_stealer_budget(cpdomc, task_load);
				}
				return true;
			}
		}

		/*
		 * Now, we need to steal a task from a farther neighbor
		 * for load balancing. Since task migration from a farther
		 * neighbor is more expensive (e.g., crossing a NUMA boundary),
		 * we will do this with a lot of hesitation. The chance of
		 * further migration will decrease exponentially as distance
		 * increases, so, on the other hand, it increases the chance
		 * of closer migration.
		 */
		if (!prob_x_out_of_y(1, LAVD_CPDOM_MIG_PROB_FT))
			break;
	}

	return false;
}

/* force_to_steal_task()(454–520 行)
强制偷取,保证 work-conserving:本域没任务时,哪怕不满足 stealer/stealee 条件,
也从任一有效邻居域偷。

与 try_to_steal_task 的区别:

不检查 is_stealee、预算、概率。
不做距离衰减概率,按距离顺序全部遍历。
仍然会 peek 并 decrement 预算以保持账目一致(!no_fast_lb),成功则直接返回 true。
 */
static bool force_to_steal_task(struct cpdom_ctx *cpdomc)
{
	struct cpdom_ctx *cpdomc_pick;
	s64 nr_nbr, cpdom_id;

	/*
	 * Traverse neighbor compute domains in distance order.
	 */
	for (int i = 0; i < LAVD_CPDOM_MAX_DIST; i++) {
		nr_nbr = min(cpdomc->nr_neighbors[i], LAVD_CPDOM_MAX_NR);
		if (nr_nbr == 0)
			break;

		/*
		 * Traverse neighbors in the same distance in circular distance order.
		 */
		for (int j = 0; j < LAVD_CPDOM_MAX_NR; j++) {
			u64 dsq_id;
			if (j >= nr_nbr)
				break;

			cpdom_id = get_neighbor_id(cpdomc, i, j);
			if (cpdom_id < 0)
				continue;

			cpdomc_pick = MEMBER_VPTR(cpdom_ctxs, [cpdom_id]);
			if (!cpdomc_pick) {
				scx_bpf_error("Failed to lookup cpdom_ctx for %llu", cpdom_id);
				return false;
			}

			if (!cpdomc_pick->is_valid)
				continue;

			dsq_id = pick_most_loaded_dsq(cpdomc_pick);
			/*
			 * Same defensive check as the try_to_steal_task
			 * path above.
			 */
			if ((s64)dsq_id < 0)
				continue;

			/*
			 * Peek at the head task to get its size. Skip the
			 * peek when no_fast_lb is set since the budget
			 * accounting below is bypassed and the value would
			 * be unused.
			 */
			u64 task_load = no_fast_lb ? 0 : dsq_peek_task_load(dsq_id);

			/*
			 * Force steal is unconditional for work
			 * conservation. Decrement budgets to keep
			 * the accounting consistent.
			 */
			if (consume_dsq(cpdomc_pick, dsq_id)) {
				if (!no_fast_lb) {
					decrement_stealee_budget(cpdomc_pick, task_load);
					decrement_stealer_budget(cpdomc, task_load);
				}
				return true;
			}
		}
	}

	return false;
}

/* 9. consume_task()(522–604 行)
dispatch 路径的入口,取任务的完整策略:



判断本 CPU 是否"湍流":cpuc->lat_headroom < LAVD_LC_LATENCY_SENSITIVE_THRESH
(受 IRQ/steal 影响大,不适合跑延迟敏感任务)。

优先跨域偷:nr_cpdoms > 1 && is_stealer && try_to_steal_task() 成功则
 goto x_domain_migration_out,直接返回 true。

本域内多队列合并:构造 3 个候选 DSQ(dsqs[0..2]):

[0] per-CPU DSQ(use_per_cpu_dsq() 时有效)
[1] cpdom DSQ。非湍流 CPU 总是可消费;湍流 CPU 仅当该 DSQ 排队数 > 湍流 DSQ 排队数
(防饿死),或域内没有 steady CPU(没人能清它)时才可消费
[2] cpdom 的 turbulent DSQ(存放非延迟关键任务,所有 CPU 都可消费)
对每个 eligible 的 DSQ 用 peek_dsq_vtime() 取队首 vtime,sort_dsqs() 按 vtime 升序
,然后依次尝试 consume_dsq,vtime 最小者优先,保证跨队列的公平性。

兜底:本域都没任务,且 nr_cpdoms > 1 && mig_delta_pct == 0 时,调用 force_to_steal_task()。
若用户设置了 mig_delta_pct,意图是"只依靠阈值迁移",所以禁用 force steal。

都没拿到任务返回 false(CPU 将 idle)。 */
__hidden
bool consume_task(u64 cpu_dsq_id, u64 cpdom_dsq_id)
{
	struct cpdom_ctx *cpdomc;
	struct cpu_ctx *cpuc;
	u64 cpdom_turb_dsq_id;
	bool turbulent;
	struct dsq_entry dsqs[3];

	cpdomc = MEMBER_VPTR(cpdom_ctxs, [dsq_to_cpdom(cpdom_dsq_id)]);
	if (!cpdomc) {
		scx_bpf_error("Failed to lookup cpdom_ctx for %llu", dsq_to_cpdom(cpdom_dsq_id));
		return false;
	}

	/* 取本 CPU 所在 cpdom 的 cpdomc,算出 turbulent DSQ id。 */
	cpdom_turb_dsq_id = cpdom_to_turb_dsq(dsq_to_cpdom(cpdom_dsq_id));

	/*
	 * Determine if this CPU is turbulent (high IRQ/steal time).
	 * Non-turbulent CPUs consume from all 3 DSQs.
	 * Turbulent CPUs only consume from the turbulent DSQ
	 * (which holds non-latency-critical tasks).
	 */
	cpuc = get_cpu_ctx();
	if (!cpuc)
		return false;
	turbulent = cpuc->lat_headroom < LAVD_LC_LATENCY_SENSITIVE_THRESH;

	/*
	 * If the current compute domain is a stealer, try to steal
	 * a task from any of stealee domains probabilistically.
	 */
	if (nr_cpdoms > 1 && READ_ONCE(cpdomc->is_stealer) &&
	    try_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	/*
	 * Collect eligible DSQs and consume in lowest-vtime-first order.
	 * Non-turbulent CPUs always see the cpdom DSQ. Turbulent CPUs
	 * also see it when it has more queued tasks than the turbulent
	 * DSQ (to prevent starvation) or when there are no steady CPUs
	 * to drain it.
	 */
	dsqs[0] = (struct dsq_entry){ cpu_dsq_id,       U64_MAX, use_per_cpu_dsq() };
	dsqs[1] = (struct dsq_entry){ cpdom_dsq_id,     U64_MAX, use_cpdom_dsq() &&
		(!turbulent ||
		 scx_bpf_dsq_nr_queued(cpdom_dsq_id) > scx_bpf_dsq_nr_queued(cpdom_turb_dsq_id) ||
		 cpdomc->nr_steady_cpus == 0) };
	dsqs[2] = (struct dsq_entry){ cpdom_turb_dsq_id, U64_MAX, use_cpdom_dsq() };

	if (dsqs[0].eligible)
		dsqs[0].vtime = peek_dsq_vtime(dsqs[0].dsq_id);
	if (dsqs[1].eligible)
		dsqs[1].vtime = peek_dsq_vtime(dsqs[1].dsq_id);
	if (dsqs[2].eligible)
		dsqs[2].vtime = peek_dsq_vtime(dsqs[2].dsq_id);

	sort_dsqs(&dsqs[0], &dsqs[1], &dsqs[2]);

	if (dsqs[0].eligible && consume_dsq(cpdomc, dsqs[0].dsq_id))
		return true;
	if (dsqs[1].eligible && consume_dsq(cpdomc, dsqs[1].dsq_id))
		return true;
	if (dsqs[2].eligible && consume_dsq(cpdomc, dsqs[2].dsq_id))
		return true;

	/*
	 * If there is no task in the associated DSQ, traverse neighbor
	 * compute domains in distance order -- task stealing.
	 * Skip force stealing when mig_delta_pct is set (> 0) to rely
	 * only on the is_stealer/is_stealee thresholds.
	 */
	if (nr_cpdoms > 1 && mig_delta_pct == 0 && force_to_steal_task(cpdomc))
		goto x_domain_migration_out;

	return false;

	/*
	 * Task migration across compute domains happens.
	 */
x_domain_migration_out:
	return true;
}
