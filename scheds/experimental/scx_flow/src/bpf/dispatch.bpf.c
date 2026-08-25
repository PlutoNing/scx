/* Dispatch hierarchy — included by main.bpf.c via #include
 *
 * 1. Per-CPU pinned DSQ (non-migratable tasks)
 * 2. Per-CPU vtime DSQ (this CPU's own tasks)
 * 3. Peer CPU vtime DSQs (work stealing — idle CPU steals from busiest peer)
 * 4. Shared FLOW_BATCH_DSQ (fallback)
 * 5. Previous task extension
 *
 * flow_dsq_move_one wraps scx_bpf_dsq_move_to_local from compat.bpf.h.
 翻译：
 调度层次结构 - 由 main.bpf.c 通过 #include 包含
 1. 每个 CPU 的 pinned DSQ（不可迁移任务）
 2. 每个 CPU 的 vtime DSQ（本 CPU 的任务）
 3. 对等 CPU vtime DSQs（工作窃取 - 空闲 CPU 从最繁忙的对等 CPU 窃取）
 4. 共享 FLOW_BATCH_DSQ（回退）
 5. 上一个任务扩展

 flow_dsq_move_one 包装 scx_bpf_dsq_move_to_local 从 compat.bpf.h。
 */

static __always_inline bool flow_dsq_move_one(u64 dsq_id)
{
	return scx_bpf_dsq_move_to_local(dsq_id, 0);
}

/* dispatch 的实现 */
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu, struct task_struct *prev)
{
	s32 peer;
	u64 best_load = 0, load;
	s32 steal_from = -1;

	/* 1. Per-CPU pinned DSQ.
	先从 pinned dsq 拿任务 */
	if (scx_bpf_dsq_nr_queued(FLOW_PINNED_DSQ_BASE + (u32)cpu) > 0 &&
	    flow_dsq_move_one(FLOW_PINNED_DSQ_BASE + (u32)cpu)) {
		__sync_fetch_and_add(&pinned_dispatches, 1);
		return;
	}

	/* 2. Per-CPU vtime DSQ (this CPU's own tasks). 
	再从 vtime dsq 拿任务*/
	if (scx_bpf_dsq_nr_queued(FLOW_VTIME_DSQ_BASE + (u32)cpu) > 0 &&
	    flow_dsq_move_one(FLOW_VTIME_DSQ_BASE + (u32)cpu))
		return;

	/* 3. Work stealing: if this CPU is idle, steal from the busiest peer.
	 *    Scan peer DSQs (bounded by nr_cpu_ids ≤ 1024).
	 从其他 cpu 偷取任务 */
	bpf_for(peer, 0, 1024) {
		if ((u32)peer >= nr_cpu_ids)
			break;
		if (peer == cpu)
			continue;
		/* 这个 cpu 的 vtime dsq 有任务 */
		if (scx_bpf_dsq_nr_queued(FLOW_VTIME_DSQ_BASE + (u32)peer) > 0) {
			/* 直接把 dsq 的任务数量当做 load */
			load = scx_bpf_dsq_nr_queued(FLOW_VTIME_DSQ_BASE + (u32)peer);
			if (load > best_load) {
				best_load = load;
				steal_from = peer;
			}
		}
	}
	/* 找到了最忙的 dsq， 就从那个 dsq 偷取任务 */
	if (steal_from >= 0 &&
	    flow_dsq_move_one(FLOW_VTIME_DSQ_BASE + (u32)steal_from))
		return;

	/* 4. Shared FLOW_BATCH_DSQ fallback.
	从 fallback dsq 拿任务 */
	if (scx_bpf_dsq_nr_queued(FLOW_BATCH_DSQ) > 0 &&
	    flow_dsq_move_one(FLOW_BATCH_DSQ))
		return;

	/* 5. Previous task extension. */
	if (!prev || !(prev->scx.flags & SCX_TASK_QUEUED))
		return;

	prev->scx.slice = task_slice_ns(lookup_task_ctx(prev));
	return;
}
