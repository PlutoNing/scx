/* Waiting Room — included by main.bpf.c via #include
 *
 * Per-CPU fair-share dispatch:
 *   Each task dispatched to a CPU receives a slice of
 *   FLOW_CARRIAGE_NS / tasks_on_target_cpu, clamped to [50us, 2ms].
 *   This divides the CPU's bandwidth equally among all tasks currently
 *   assigned to it — no budget lookups, no frequency ratios.
 *
 *   Target CPU is always last_cpu (cache warmth, O(1), no scan).
 *   When more tasks arrive on a CPU, each automatically gets a
 *   proportionally smaller slice.
 *
 *   Dispatch uses per-CPU vtime DSQs (FLOW_VTIME_DSQ_BASE + cpu) via
 *   scx_bpf_dsq_insert_vtime.  ops.dispatch() on the same CPU consumes
 *   from that CPU's DSQ, and may steal from peer CPUs when idle.
 翻译：
 等待区 - 由 main.bpf.c 通过 #include 包含
 每个 CPU 的公平调度：
   每个任务被调度到 CPU 时，会收到一个切片，切片大小为 FLOW_CARRIAGE_NS / tasks_on_target_cpu，
   切片大小被限制在 [50us, 2ms] 之间。
   这个切片将 CPU 的带宽平均分配给所有当前分配到该 CPU 的任务 - 没有预算查找，没有频率比率。
   目标 CPU 始终是 last_cpu（缓存温暖，O(1)，没有扫描）。
   当更多任务到达 CPU 时，每个任务会自动获得一个按比例缩小的切片。
   调度使用每个 CPU 的 vtime DSQ（FLOW_VTIME_DSQ_BASE + cpu）通过 scx_bpf_dsq_insert_vtime 插入。
   同一 CPU 上的 ops.dispatch() 消耗该 CPU 的 DSQ，并在空闲时从其他 CPU 窃取。
 */

void scx_bpf_dsq_insert___v1(struct task_struct *p, u64 dsq_id,
			      u64 slice, u64 enq_flags) __ksym __weak;

/*
计算任务的切片， 按照公平-份额切片的方式， 按照目标 CPU 上的任务数量平均分配。
 * Fair-share slice: window divided equally among tasks on the target CPU.
 * Clamped to [FLOW_SLICE_MIN_NS, FLOW_BUDGET_MAX_NS].
 公平-份额切片：窗口按目标 CPU 上的任务数量平均分配。
 限制在 [FLOW_SLICE_MIN_NS, FLOW_BUDGET_MAX_NS] 之间。
 */
static __always_inline u64 compute_task_slice(struct task_ctx *tctx,
					       s32 target_cpu)
{
	u64 tasks, slice;

	if (target_cpu < 0 || (u32)target_cpu >= 1024)
		return task_slice_ns(tctx);

	// 目标 CPU 上的任务数量
	tasks = per_cpu_runnable[target_cpu];
	if (tasks == 0) tasks = 1;

	slice = FLOW_CARRIAGE_NS / tasks;
	if (slice < FLOW_SLICE_MIN_NS) slice = FLOW_SLICE_MIN_NS;
	if (slice > FLOW_BUDGET_MAX_NS) slice = FLOW_BUDGET_MAX_NS;
	return slice;
}

/*
 * Dispatch a non-wakeup task to its last_cpu's per-CPU vtime DSQ.
 * No CPU scan, no budget bandwidth formula — just fair-share slice.
 把一个非唤醒任务调度到它的 last_cpu 的per CPU 的 vtime DSQ。
 没有 CPU 扫描，没有预算带宽公式 - 只是公平-份额切片。
 */
static __always_inline void carriage_enqueue_task(struct task_struct *p,
						   struct task_ctx *tctx)
{
	u64 slot, slice_ns, dsq_id;
	s32 target_cpu;

	slot = __sync_fetch_and_add(&carriage_producer, 1)
		& (FLOW_NR_CARRIAGES - 1);

	target_cpu = (tctx && tctx->last_cpu >= 0) ? tctx->last_cpu
		     : scx_bpf_task_cpu(p);
	if (target_cpu < 0 || (u32)target_cpu >= 1024)
		target_cpu = 0;

		/* 计算任务的切片 */
	slice_ns = compute_task_slice(tctx, target_cpu);
	// 查找目标 CPU 的 vtime DSQ
	dsq_id = FLOW_VTIME_DSQ_BASE + (u32)target_cpu;

	// 插入到目标 CPU 的 vtime DSQ
	if (!scx_bpf_dsq_insert_vtime(p, dsq_id, slice_ns, slice_ns, 0))
		scx_bpf_dsq_insert___v1(p, FLOW_BATCH_DSQ, slice_ns, 0);

	carriage_pool[slot].tasks[carriage_pool[slot].count %
				  FLOW_CARRIAGE_CAPACITY] = (u64)(s32)p->pid;
	carriage_pool[slot].count++;
}
