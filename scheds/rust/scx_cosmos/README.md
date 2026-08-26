# scx_cosmos

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

Lightweight scheduler optimized for preserving task-to-CPU locality.

When the system is not saturated, the scheduler prioritizes keeping tasks
on the same CPU using local DSQs. This not only maintains locality but also
reduces locking contention compared to shared DSQs, enabling good
scalability across many CPUs.

Under saturation, the scheduler switches to a deadline-based policy and
uses a shared DSQ (or per-node DSQs if NUMA optimizations are enabled).
This increases task migration across CPUs and boosts the chances for
interactive tasks to run promptly over the CPU-intensive ones.

To further improve responsiveness, the scheduler batches and defers CPU
wakeups using a timer. This reduces the task enqueue overhead and allows
the use of very short time slices (10 us by default).

The scheduler tries to keep tasks running on the same CPU as much as
possible when the system is not saturated.

## Typical Use Case

General-purpose scheduler: the scheduler should adapt itself both for
server workloads or desktop workloads.

## Production Ready?

Yes.
我已把 BPF 路径和用户态配置对上：工作窃取主要发生在饱和时从共享 DSQ 拉取，而不是从其他 CPU 的本地队列偷任务。下面按设计把这条路径讲清楚。

---

## 总体设计

`scx_cosmos` 是一个 **以局部性为优先、饱和时再做负载均衡** 的轻量调度器。核心不是“随时 work-steal”，而是 **双模式队列**：

| 系统状态 | 判定 | 队列 | 策略 |
|---|---|---|---|
| 未饱和 | `is_cpu_busy(cpu) == false` | 每 CPU 的 **local DSQ** | 粘在原 CPU，round-robin |
| 饱和 | 该 CPU 用户态利用率 ≥ `busy_threshold` | **共享 DSQ**（全局或每 NUMA node） | deadline，允许跨 CPU 迁移 |

“忙”不是瞬时 runqueue 长度，而是用户态按 `-p` 周期读 `/proc/stat`，把每 CPU 的 user+nice 占比写成 `[0, 1024]`，再和 `-c` 阈值比较。默认 `-c 0` 且 `-p 0`，等于 **几乎总是走共享 DSQ**；把阈值调高、打开 polling，才会真正“粘核”。

---

## 工作窃取：它实际在做什么

这里的 stealing **不是** 经典 work-steal（空闲 CPU 去别的 CPU 的 local DSQ 里抢任务）。代码里 **没有任何** `scx_bpf_dsq_move` 从 `SCX_DSQ_LOCAL_ON | other_cpu` 拉任务。

真正的“偷活”只有一条 **pull 路径**，在 `ops.dispatch()`：

```1278:1294:scheds/rust/scx_cosmos/src/bpf/main.bpf.c
void BPF_STRUCT_OPS(cosmos_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_dsq_move_to_local(shared_dsq(cpu), 0))
		return;

	if (prev && keep_running(prev, cpu))
		prev->scx.slice = task_slice(prev);
}
```

含义：

1. CPU 空闲或时间片用完、需要下一个任务时进入 `dispatch`。
2. 从 **本 NUMA 节点的共享 DSQ**（或全局 `SHARED_DSQ=0`）把队头任务挪到本 CPU 的 local DSQ。
3. 共享队列为空，才考虑让 `prev` 再跑一个 slice（`keep_running`）。

所以：

- **可被偷的任务** = 已经进共享 DSQ 的任务（饱和路径、deadline 入队）。
- **不可被偷的任务** = 还在别的 CPU local DSQ 里的任务（轻载路径刻意保护 cache）。

共享 DSQ 的范围：

```466:469:scheds/rust/scx_cosmos/src/bpf/main.bpf.c
static inline u64 shared_dsq(s32 cpu)
{
	return numa_enabled ? cpu_node(cpu) : SHARED_DSQ;
}
```

NUMA 打开时，stealing **被限制在 node 内**：每个有 CPU 的 node 一个 DSQ。跨 node 不会互相偷，避免远程内存。GPU 任务则在 enqueue/select 阶段被主动推到 GPU 所在 node，而不是靠 steal 过去。

---

## 任务如何变成“可被偷”

入队决策在 `cosmos_enqueue`，大致是一条 **短路链**，只有最后才会进共享 DSQ：

```
GPU 亲和 → sticky PMU 粘核 → 找空闲 CPU 直派 → 原 CPU 不忙则粘 local → 共享 DSQ（可被 steal）
```

最后两段：

```1218:1236:scheds/rust/scx_cosmos/src/bpf/main.bpf.c
	if (!is_cpu_busy(prev_cpu) &&
	    (is_primary_cpu(prev_cpu) || is_pcpu_task(p))) {
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, ...);
		...
		return;
	}

	scx_bpf_dsq_insert_vtime(p, shared_dsq(prev_cpu),
				 task_slice(p), task_dl(p, tctx), enq_flags);
```

设计取舍很明确：

- **轻载**：任务进 local DSQ，别的 CPU **看不到**，换 cache locality 和更少的 DSQ 锁。
- **重载**：任务进共享 DSQ，任何同 node 空闲 CPU 都能 `move_to_local`，交互任务更容易插队（deadline 小的先跑）。

`select_cpu` 在未饱和时甚至 **不经过 enqueue**，直接 `SCX_DSQ_LOCAL` 直派，进一步减少共享结构竞争。

---

## 另一半：push，不是 steal

空闲核上的负载均衡，主要靠 **把任务推到空闲 CPU**，而不是空闲 CPU 去偷：

1. **`pick_idle_cpu`**：wakeup / enqueue 时找空闲核，直派 `SCX_DSQ_LOCAL_ON | cpu`。
2. **`scx_bpf_kick_cpu(..., SCX_KICK_IDLE)`**：目标核在 idle 时被踢醒，随后走 `dispatch`。若共享 DSQ 里已有任务，被踢醒的核就会把它们偷走。

因此完整闭环是：

```
饱和 enqueue → 共享 DSQ
        ↓
kick 空闲 CPU
        ↓
dispatch: move_to_local(shared_dsq)   ← 真正的 work steal
```

Kick 发生在：GPU 迁移、sticky 直派、找到空闲核、粘回不忙的 prev_cpu、以及最终进共享 DSQ 且这次 enqueue 需要迁移时。`task_should_migrate()` 限制为：**wakeup 且 `select_cpu` 没跑过、任务当前没在跑**，避免热路径上反复踢核。

---

## Deadline：共享队列里“偷谁”

共享 DSQ 用 `dsq_insert_vtime`，deadline 为：

```
deadline = vruntime + exec_vruntime
```

- `vruntime`：按权重反比累积，管公平。
- `exec_vruntime`：自上次睡眠以来的执行量；短睡短跑的交互任务这项小，deadline 更靠前。
- 睡眠攒的 credit 被 `slice_lag * wakeup_freq` 卡住，避免“睡很久的任务”霸占优先级。

空闲 CPU steal 时拿的是 **共享 DSQ 里 deadline 最早的任务**，不是随机或 FIFO。这就是饱和模式下“交互任务更容易跑起来”的来源。

---

## 刻意不 steal 的情况（`keep_running`）

共享 DSQ 空时，并不立刻让 CPU 闲着或去别的 local 队列翻：

```1243:1276:scheds/rust/scx_cosmos/src/bpf/main.bpf.c
static bool keep_running(const struct task_struct *p, s32 cpu)
{
	if (!is_task_queued(p)) return false;
	if (is_pcpu_task(p)) return true;
	if (is_smt_contended(cpu)) return false;   // 让它有机会迁到满空闲 SMT
	if (!is_primary_cpu(cpu) && 能迁到 primary) return false;
	return true;
}
```

也就是说：没有可偷的共享任务时，优先 **续跑 prev**（再给一个 slice），而不是跨 CPU 翻 local 队列。只有 SMT 争用、或不在 primary domain 时，才拒绝续跑，迫使任务走下一轮 enqueue / select，相当于 **延迟的、有条件的再放置**，不是 steal。

---

## 和 stealing 正交的几条旁路

这些会 **绕过或抑制** 进入共享 DSQ，从而减少被 steal 的机会：

| 机制 | 效果 |
|---|---|
| **Sticky PMU** (`-y/-Y`) | 事件超阈值则钉在原 CPU local DSQ（除非有 per-CPU 任务在等） |
| **Event-heavy** (`-e/-E`) | 反过来：强制 `pick_idle_cpu` 迁走（cache miss 等） |
| **GPU PID → node** | 用户态 NVML 填 `gpu_pid_map`，直派到 GPU 所在 node |
| **mm_affinity** (`-a`) | 同地址空间、同 CPU、未饱和：wakeup 粘在 waker CPU |
| **Primary domain** (`-m`) | 优先在指定核上跑；不在 primary 的任务更容易被“挤”去再选核 |
| **no_early_clear** (`-N`) | 不原子清 idle，允许多个 wakeup 叠到同一 cache，偏向堆积而非分散 |

用户态对 `-E/-Y` 为 0 时，还会用 EMA + 滞回动态调阈值，把“因 PMU 触发的迁移/粘核”速率压在约 2000–4000 次/秒，避免 steal/迁移抖动。

---

## 设计意图（针对 work stealing）

1. **默认不偷 local 队列**：轻载时接受瞬时不均衡，换 locality 和更少锁。
2. **饱和才开放一个中央（或 per-node）池**：steal 的对象是共享 DSQ，语义是 **pull from shared pool**，不是 **steal from victim CPU**。
3. **NUMA 把 steal 域切小**：跨 node 不互相拉任务。
4. **Push 找闲核 + Kick 唤醒** 补足另一侧：能直派就直派，派不出去才进共享池等人来偷。
5. **Deadline 决定被偷的优先级**：steal 同时完成负载均衡和延迟敏感任务插队。

README 里写的 “timer 批量延迟 wakeup、默认 10µs slice” 和当前实现不完全一致：`no_deferred_wakeup` 已废弃，默认 slice 是 **1000µs**。当前 wakeup 是即时 `kick`，不是定时器攒批。

如果你接下来要改 stealing（例如允许从邻居 local DSQ 偷、或跨 LLC 限制），比较自然的插入点就是 `cosmos_dispatch()`：在 `move_to_local(shared_dsq)` 失败之后、`keep_running` 之前。

===================================================
以局部性为优先、饱和时再做负载均衡
双模式队列：
系统状态	判定	队列	策略
未饱和
is_cpu_busy(cpu) == false
每 CPU 的 local DSQ
粘在原 CPU，round-robin
饱和
该 CPU 用户态利用率 ≥ busy_threshold
共享 DSQ（全局或每 NUMA node）
deadline，允许跨 CPU 迁移

窃取： 空闲时从本 NUMA 节点的共享 DSQ（或全局 SHARED_DSQ=0）把队头任务挪到本 CPU 的 local DSQ。

NUMA 打开时，stealing 被限制在 node 内：每个有 CPU 的 node 一个 DSQ。跨 node 不会互相偷，避免远程内存。GPU 任务则在 enqueue/select 阶段被主动推到 GPU 所在 node，而不是靠 steal 过去。

设计意图（针对 work stealing）
默认不偷 local 队列：轻载时接受瞬时不均衡，换 locality 和更少锁。
饱和才开放一个中央（或 per-node）池：steal 的对象是共享 DSQ，语义是 pull from shared pool，不是 steal from victim CPU。
NUMA 把 steal 域切小：跨 node 不互相拉任务。
Push 找闲核 + Kick 唤醒 补足另一侧：能直派就直派，派不出去才进共享池等人来偷。
Deadline 决定被偷的优先级：steal 同时完成负载均衡和延迟敏感任务插队。