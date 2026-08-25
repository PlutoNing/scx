/* Budget lifecycle tracking — included by main.bpf.c via #include */

/* 入队了 */
void BPF_STRUCT_OPS(flow_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now;

	/* 任务的上下文 */
	tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	/* 当前时间 */
	now = bpf_ktime_get_ns();
	if (tctx->sleep_started_at && now > tctx->sleep_started_at)
		FLOW_CPUSTAT_INC(lookup_cpu_state(), runnable_wakeups);
	// 更新任务的预算
	update_budget_on_wakeup(p, tctx, now);

	/*
	 * Track per-CPU runnable count for load awareness (heuristic,
	 * up to 50% slice reduction).  Atomic increment matches the
	 * atomic decrement in flow_stopping, keeping drift bounded
	 * to migration-related mismatch between the wakeup CPU and
	 * the actual execution CPU.
	 翻译：
	 跟踪每个CPU的运行任务数，用于负载感知（启发式，最多50%的切片减少）。
	 原子增加与flow_stopping中的原子减少匹配，保持漂移边界到迁移相关的不匹配，
	 即唤醒CPU和实际执行CPU之间的不匹配。
	 */
	{
		s32 cpu = scx_bpf_task_cpu(p);
		if (cpu >= 0 && (u32)cpu < 1024) {
			u32 c = (u32)cpu;
			tctx->runnable_cpu = cpu;
			// 这个 cpu 的运行任务数 +1
			__sync_fetch_and_add(&per_cpu_runnable[c], 1);
		}
	}
}

/* 运行了 */
void BPF_STRUCT_OPS(flow_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	s32 current_cpu;
	u64 now;

	// 任务的上下文
	tctx = lookup_task_ctx(p);
	if (tctx) {
		// 当前 CPU
		current_cpu = bpf_get_smp_processor_id();
		// 当前时间
		now = bpf_ktime_get_ns();
		if (tctx->last_cpu >= 0 && tctx->last_cpu != current_cpu)
			FLOW_CPUSTAT_INC(lookup_cpu_state(), cpu_migrations);
		// 上一个 CPU
		tctx->last_cpu = current_cpu;
		tctx->last_llc = (s32)per_cpu_llc_id[current_cpu];
		tctx->last_run_at = now;
		tctx->first_run = false;
	}

	// 正在运行的任务数 +1
	__sync_fetch_and_add(&on_cpu, 1);
}

/* 下 cpu 了 */
void BPF_STRUCT_OPS(flow_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	u64 now;
	u64 runtime_ns = 0;

	tctx = lookup_task_ctx(p);

	if (tctx) {
		now = bpf_ktime_get_ns();
		// 计算运行时间
		if (tctx->last_run_at && now > tctx->last_run_at)
			runtime_ns = now - tctx->last_run_at;

		// 这次跑超额了
		if (tctx->budget_ns > 0 &&
		    (s64)runtime_ns >= tctx->budget_ns)
			FLOW_CPUSTAT_INC(lookup_cpu_state(), budget_exhaustions);

		// 下次的预算
		tctx->budget_ns = clamp_budget(tctx->budget_ns - (s64)runtime_ns);
		tctx->last_run_at = 0;
		tctx->sleep_started_at = runnable ? 0 : now;
		if (!runnable)
			clear_wake_target(tctx);
	}

	__sync_fetch_and_add(&total_runtime, runtime_ns);

	/*
	 * on_cpu diagnostic counter — incremented in flow_running,
	 * decremented here.  Atomic with saturation guard: if the
	 * counter was already zero, the guard restores it.  Under
	 * concurrent access, minor drift is possible but bounded
	 * (diagnostic only, no scheduling decisions depend on it).
	 */
	if (__sync_fetch_and_sub(&on_cpu, 1) == 0)
		__sync_fetch_and_add(&on_cpu, 1);

	/*
	 * Decrement per_cpu_runnable only when the task is truly leaving
	 * the runnable state (runnable == false — going to sleep/block).
	 * When preempted (runnable == true), the task stays runnable and
	 * will be re-enqueued — the counter should remain unchanged.
	 * Clear runnable_cpu after decrement to prevent double-counting.
	 */
	if (tctx && !runnable && tctx->runnable_cpu >= 0 &&
	    (u32)tctx->runnable_cpu < 1024) {
		u32 c = (u32)tctx->runnable_cpu;
		if (__sync_fetch_and_sub(&per_cpu_runnable[c], 1) == 0)
			__sync_fetch_and_add(&per_cpu_runnable[c], 1);
		tctx->runnable_cpu = -1;
	}

}
