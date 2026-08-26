# scx_forge

This is a base scheduler for [`sched_ext`](https://github.com/sched-ext/scx/tree/main), intended to be customized and optimized in place by AI systems through [`scx_forge_agent`](../../../tools/scx_forge_agent). It is kept buildable and runnable so policy changes can be validated quickly, but it is not intended to be used as a production scheduler unchanged. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_forge` is an AI-oriented base scheduler. It provides a complete
sched_ext Rust crate, BPF program, CLI, stats plumbing, and topology setup whose
policy is meant to be evolved in place by the agent.

Default policy:

- `select_cpu()` is primarily a wakeup placement hint, and may directly dispatch
  to a terminal DSQ when there is a clear fast-path reason, such as an idle CPU.
  It should not own global queueing or selection policy.
- `enqueue()` admits runnable tasks that were not consumed by a `select_cpu()`
  direct-dispatch fast path, including migration-disabled and
  affinity-constrained tasks that skipped wakeup placement. By default, it
  enqueues those tasks only to per-CPU DSQs.
- `dispatch()` is the primary selection point and pulls from per-CPU DSQs,
  stealing from other CPU DSQs when their earliest runnable task can run on the
  dispatching CPU.
- Per-LLC, per-NUMA-node, and global DSQs are supported. The default policy
  uses CPU-local queueing with work stealing across per-CPU DSQs.
- Queue ordering uses a DSQ queue key derived from task-local weighted virtual
  runtime. Deadline and FIFO queueing is also supported optionally.
- Runtime budget is a fixed slice by default.

## Typical Use Case

`scx_forge` is meant to be customized and optimized through
[`scx_forge_agent`](../../../tools/scx_forge_agent), the LLM-driven optimizer.

The agent edits this crate's policy in place, then builds, runs, and scores each
change with its bundled validation harness. The agent's `SKILL.md` documents how
to translate Rust-like policy specs into BPF helpers while preserving sched_ext
callback constraints.

## Validate / Iterate

`scx_forge` is scored and improved by
[`scx_forge_agent`](../../../tools/scx_forge_agent), which owns the closed-loop
validation harness and spec. The agent edits the policy, builds, attaches the
scheduler, runs a workload, extracts one metric, and keeps or reverts the change
based on whether it improved beyond run-to-run noise. See that tool's
`README.md` and `SKILL.md` for the workflow and the spec format.

## Production Ready?

No. `scx_forge` is a starting-point scheduler for AI-driven policy development.
`scx_forge` 把**放置**和**选择**拆开：任务先尽量直派到空闲核；没派出去的才进用户 DSQ。**工作窃取只发生在 per-CPU DSQ 模式**，而且是空闲核按「最早队头」去拉别人队列，不是按队列长度做负载均衡。

可视化拆解在 [scx_forge 工作窃取](/data/home/paulning/.cursor/projects/data-home-paulning-scx/canvases/scx-forge-work-steal.canvas.tsx)（可在聊天旁打开的交互面板）。下面是结论。

## 整体结构

| 层 | 文件 | 职责 |
|---|---|---|
| 用户态 | `src/main.rs` | CLI、拓扑探测、写 BPF map、挂载、统计 |
| 接口 | `src/bpf/intf.h` | DSQ 层级、排序、idle 策略枚举 |
| 策略 | `src/bpf/main.bpf.c` | `select_cpu` / `enqueue` / `dispatch` |

三个回调的边界写得很清楚：

- `select_cpu()`：wakeup **放置提示**。找到 idle CPU 就直派到 `SCX_DSQ_LOCAL`，不负责全局排队。
- `enqueue()`：**准入**。直派失败的任务（含迁移禁用、亲和受限、queued wakeup）按 `task_dsq(p, prev_cpu)` 入队。
- `dispatch()`：**真正选谁跑**。先拉本核 DSQ，空了再偷。

默认入队是「任务回家」：进 **上一次跑过的那颗 CPU** 的 DSQ，而不是推到更空的核。迁移发生在别人来偷的时候。

## 工作窃取怎么做

只在 `topo_dsq == TOPO_DSQ_CPU` 时启用。LLC / Node / Global 已经是共享队列，dispatch 只 pull 本域，没有跨域 steal。

`forge_dispatch(cpu)` 的路径：

1. `scx_bpf_dsq_move_to_local(CPU_DSQ_ID(cpu))` —— 本地有活就结束  
2. 失败则 `pick_remote_cpu(cpu)`，再对选中的远程 DSQ 做一次 `move_to_local`  
3. 再失败：若 `prev` 仍 queued 且 `selection_keep_running()` 允许，续一个 slice；否则让 CPU 闲着

`pick_remote_cpu()` 的选择规则：

```1259:1286:scheds/rust/scx_forge/src/bpf/main.bpf.c
static s32 pick_remote_cpu(s32 dst_cpu)
{
	u64 min_vtime = ULLONG_MAX;
	s32 min_cpu = -ENOENT;
	u64 i, cpu;

	bpf_for(i, 0, nr_cpu_ids) {
		// 从 dst_cpu 起环形扫描全部 CPU
		p = __COMPAT_scx_bpf_dsq_peek(CPU_DSQ_ID(cpu));
		if (!p || !bpf_cpumask_test_cpu(dst_cpu, p->cpus_ptr))
			continue;
		if (p->scx.dsq_vtime < min_vtime) {
			min_vtime = p->scx.dsq_vtime;
			min_cpu = (s32)cpu;
		}
	}
	return min_cpu;
}
```

要点：

- **Victim = 各 DSQ 队头里 queue key 最早、且能在本核跑的那个**，不是最长队列。
- 比较的是 `p->scx.dsq_vtime`，也就是入队时的 key（vruntime / deadline / FIFO），所以 steal 继承同一套公平性。
- **只 peek 队头**：队头亲和不匹配就整队跳过，后面即使有能跑的任务也偷不到。
- **没有 SMT / LLC / NUMA 分层**：跨 NUMA 和同 LLC 一视同仁，只比 vtime。
- **每次 dispatch 只偷一次**：两个空闲核同时看上同一条远程队列时，失败者不会改选下一个，可能一边有活一边闲着。
- 扫描是 `O(nr_cpu_ids)`，上限 4096，发生在 CPU 变空的热路径上。

这是 **pull 型** 窃取：空闲核自己来拿。对应的 **push** 是 `select_cpu` / `try_direct_dispatch` 的 idle 直派；直派进的是终端 LOCAL DSQ，**不会进入可被偷的用户 DSQ**。

## 一个必须知道的默认不一致

README 和 BPF `topo_dsq` 默认都是 per-CPU + 窃取。但 CLI 是：

```148:149:scheds/rust/scx_forge/src/main.rs
    #[clap(long, value_enum, default_value_t = DsqTopology::Global)]
    dsq_topology: DsqTopology,
```

加载时用户态会覆盖 rodata。不带 `--dsq-topology cpu` 启动时，走的是全局共享 DSQ，`pick_remote_cpu()` 不会执行。要看窃取行为，必须显式开 CPU 拓扑。

## 设计意图

这是给 `scx_forge_agent` 改策略用的模板，不是成品调度器。把「放哪颗核」和「从哪条队列取」拆开，是为了让后续改 BPF helper 时回调语义稳定。

窃取用队头 vtime 而不是队列长度，是在做 **全局公平**，不是缓存局部负载均衡。局部性完全交给 idle 策略（默认 `IDLE_WAKEE`：尽量留在 prev CPU）和「任务先回家」的入队规则。若要做成层次化 steal（先 SMT sibling，再 LLC，再 NUMA），当前 `pick_remote_cpu()` 没有这个结构。



