# scx_flash

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

A scheduler that focuses on ensuring fairness among tasks and performance
predictability.

It operates using an earliest deadline first (EDF) policy, where each task is
assigned a "latency" weight. This weight is dynamically adjusted based on how
often a task release the CPU before its full time slice is used. Tasks that
release the CPU early are given a higher latency weight, prioritizing them over
tasks that fully consume their time slice.

## Typical Use Case

The combination of dynamic latency weights and EDF scheduling ensures
responsive and consistent performance, even in overcommitted systems.

This makes the scheduler particularly well-suited for latency-sensitive
workloads, such as multimedia or real-time audio processing.

## Production Ready?

Yes.
**scx_flash 的负载均衡是节点内共享队列（work sharing），不是经典的 per-CPU 工作窃取。** `flash_dispatch` 只从本 NUMA 节点的 vtime DSQ 拉任务；跨节点不会偷，主要靠 wakeup 时把任务推到空闲核。

可视化总览在 [scx_flash 工作共享](/data/home/paulning/.cursor/projects/data-home-paulning-scx/canvases/scx-flash-work-sharing.canvas.tsx)（Canvas 是可在聊天旁打开的独立视图）。下面按源码把逻辑拆开。

## 整体结构

用户态 `src/main.rs` 只做配置和生命周期：拓扑、primary domain、SMT sibling、cpufreq hint、统计。真正的调度在 `src/bpf/main.bpf.c`。

目标是 **公平 + 延迟可预测**（多媒体 / 实时音频）。手段是 EDF：每个任务一个 deadline，节点内所有 CPU 从同一个按 deadline 排序的 DSQ 取任务。

关键开关：

| 标志 | 作用 |
|---|---|
| `SCX_OPS_ENQ_LAST` | 最后一个 runnable 任务也走 enqueue，从而能进共享 DSQ |
| `SCX_OPS_BUILTIN_IDLE_PER_NODE` | NUMA 开启时按节点跟踪 idle CPU |
| `SCX_OPS_ENQ_EXITING` / `ENQ_MIGRATION_DISABLED` | 退出中 / 禁止迁移的任务仍由调度器入队 |

## 三条入队路径

1. **Direct LOCAL**（快路径）  
   `flash_select_cpu` 找到空闲核后，直接 `scx_bpf_dsq_insert(..., SCX_DSQ_LOCAL)`。enqueue 被跳过。适合短 wakeup。

2. **Direct LOCAL_ON**（二次推送）  
   `try_direct_dispatch` 在 SMT 争用、`SCX_ENQ_REENQ`、或没走过 `select_cpu` 时，再找一次空闲核并 `kick idle`。

3. **Shared per-node DSQ**（慢路径 / 工作池）  
   插不进空闲核时：

```664:674:scheds/rust/scx_flash/src/bpf/main.bpf.c
	tctx = try_lookup_task_ctx(p);
	if (tctx) {
		int node = __COMPAT_scx_bpf_cpu_node(prev_cpu);

		scx_bpf_dsq_insert_vtime(p, node, task_slice(p),
					 task_dl(p, tctx, enq_flags), enq_flags);
		__sync_fetch_and_add(&nr_shared_dispatches, 1);
```

`flash_init` 里 `dsq_id = node_id`。统计里的 `nr_shared_dispatches` 是进这个共享队列的次数，不是 steal 次数。

## 工作窃取：实际做了什么

经典 work stealing 是：每核一个 deque，空闲核去 victim 的队尾偷。scx_flash **没有** 这套结构，也没有扫描其他 CPU 队列的循环。

它做的是：

```
同节点所有 CPU  ──pull──►  一个 EDF DSQ
跨节点          ──不 pull──►  邻居 DSQ
wakeup          ──push──►   pick_idle_cpu（可以跨节点）
```

消费端只有这一句：

```738:747:scheds/rust/scx_flash/src/bpf/main.bpf.c
	if (scx_bpf_dsq_move_to_local(node, 0))
		return;

	if (need_running)
		prev->scx.slice = task_slice(prev);
```

本地 DSQ 空了：要么续跑 `prev`，要么让 CPU idle。**不会去 `node+1` 偷。**

`--disable-numa` 也不会改成全局共享队列。它只做两件事：关掉 per-node idle 跟踪、SMT 争用检测改用全局 idle mask。enqueue / dispatch 仍然按 `cpu_node()` 分 DSQ。

`numa_timer` map 定义了但从未启动，更像是规划过 NUMA rebalance，后来没落地。

## 真正承担「均衡」的四件事

**1. 节点内 pull（主路径）**  
`SCX_OPS_ENQ_LAST` 让最后那个任务也进共享 DSQ，同节点空闲核可以马上 `dsq_move_to_local` 拉走。这是 work sharing，不是 steal。

**2. wakeup 时 push-to-idle**  
`pick_idle_cpu`：先 primary domain，失败再 `p->cpus_ptr` 里任意核。注释写明 idle 选择故意允许 racy，换更低开销。这是**推送**，可以跨 NUMA。

**3. keep_running + peek（让出，不是偷）**  
slice 到期时，用投影 vruntime 和队头比：

```721:736:scheds/rust/scx_flash/src/bpf/main.bpf.c
	if (need_running) {
		struct task_ctx *tctx = try_lookup_task_ctx(prev);
		struct task_struct *q = __COMPAT_scx_bpf_dsq_peek(node);
		u64 q_vtime = q ? q->scx.dsq_vtime : ULLONG_MAX;

		if (tctx) {
			u64 slice = bpf_ktime_get_ns() - tctx->last_run_at;
			u64 prev_vtime = prev->scx.dsq_vtime +
					 scale_by_weight_inverse(prev, slice);

			if (prev_vtime < q_vtime) {
				prev->scx.slice = task_slice(prev);
				return;
			}
		}
	}
```

本轮已跑时间会加进比较，避免「刚跑完一轮的任务」继续压过队头。队头更紧急才让出 CPU。

**4. SMT 争用迁移**  
兄弟超线程忙、且还有全空闲核 → `keep_running = false`，并在 enqueue 时强制再找 idle CPU。这是离开半忙 SMT core，不是队列窃取。

`is_pcpu_task`（单核亲和或 migration disabled）会跳过迁移。

## 为什么用共享队列而不是随机偷

Deadline 就是被睡眠信用夹过的 vruntime：

- 运行：`dsq_vtime += slice / effective_weight`（含 cgroup `cpu.weight`）
- 睡眠信用：`vtime_min = vtime_now - weight * slice_lag * wakeup_freq`
- `--wakeup-throttle`：slice EWMA &lt; 10µs 再加一笔 `slice_lag`（per-CPU kthread 除外）

节点内一张有序列表，才能稳定选出 earliest deadline。per-CPU 随机偷会打乱这个顺序，和「可预测延迟」冲突。代价是节点内 DSQ 锁竞争，以及节点间不均衡时空闲核不会主动跨节点拉活。

## 和文档的一点偏差

`main.rs` 长说明写了 `deadline = vruntime + exec_vruntime` 和 `--slice-lag-scaling`。BPF 里 `slice_lag_scaling` 从未使用，实际 deadline 就是 clamped vruntime。README 里「提前释放 CPU 就提高 latency weight」也不完全对应现码：现在是 wakeup 频率放大 `slice_lag`，再用 EWMA 惩罚过短 slice。

如果你接下来想对比 `scx_cosmos` 或其它调度器的 steal 路径，可以说一下，我按同样粒度拆。