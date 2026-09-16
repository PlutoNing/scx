# scx_beerland

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_beerland (BPF-Enhanced Execution Runtime Locality-Aware Non-blocking
Dispatcher) is a scheduler designed to prioritize locality and scalability.

The scheduler uses separate DSQ (deadline ordered) for each CPU. Tasks get
a chance to migrate only on wakeup, when the system is not saturated. If
the system becomes saturated, CPUs also start pulling tasks from the remote
DSQs, always selecting the task with the smallest deadline.

## Typical Use Case

Cache-intensive workloads, systems with a large amount of CPUs.

## Production Ready?

Yes.

`scx_beerland` 是一个以 **locality + scalability** 为核心的 `sched_ext` 调度器：
每个 CPU 一张按 deadline 排序的 DSQ，非饱和时任务尽量不迁；饱和时才从远程 DSQ 偷最早 deadline 的任务。实现分用户态（Rust）和内核态（BPF）两层。

---

## 1. 整体结构

| 文件 | 职责 |
|------|------|
| `src/bpf/main.bpf.c` | 真正的调度逻辑（`select_cpu` / `enqueue` / `dispatch` 等） |
| `src/bpf/intf.h` | 用户态 ↔ BPF 的参数结构 |
| `src/main.rs` | 拓扑探测、参数注入、SMT/primary domain 初始化、挂载 |
| `src/stats.rs` | 本地/远程 dispatch、keep-running 计数 |
| `build.rs` | 用 `scx_cargo` 编译 BPF 并生成 skeleton |

作者是 Andrea Righi（NVIDIA），版本 `1.1.1`。README 标为 production ready，适合 cache-intensive、CPU 很多的机器。

---

## 2. 核心模型：每 CPU 一张 deadline DSQ

`beerland_init` 为每个 CPU 建一张 DSQ，ID 就是 CPU 号，并绑到该 CPU 的 NUMA node：

```965:971:scheds/rust/scx_beerland/src/bpf/main.bpf.c
	bpf_for(cpu, 0, nr_cpu_ids) {
		int err;

		err = scx_bpf_create_dsq(cpu, __COMPAT_scx_bpf_cpu_node(cpu));
		if (err)
			return err;
	}
```

任务默认进 **自己 prev CPU 的 DSQ**，用 `dsq_vtime` 当 deadline。
这是 locality 的根基：不饱和时几乎不跨核，cache 热度能保住。

---

## 3. 虚拟时间与 deadline

全局 `vtime_now` 是系统虚拟时钟。任务权重通过 `scale_by_task_weight_inverse` 折算真实 runtime → vruntime。

**Sleep virtual lag（睡眠信用/债务）**

- 自愿睡眠（`SCX_DEQ_SLEEP`）时，把 `vtime_now - dsq_vtime` 夹在 `±slice_lag/weight` 里存下来。
- 正 lag = 睡落后、醒来有信用；负 lag = 睡超前、醒来有债务。
- 唤醒时把 vruntime 重新对齐到 `vtime_now - vlag`。

**连续 runnable 的下界**

非 sleeper 的 vruntime 不能落后 `vtime_now` 超过同样的 `slice_lag`。否则重载核上跑得很慢的任务会一直抢同一张 DSQ，饿死别人并触发 stall watchdog。

`slice_lag` 默认 BPF 侧 40ms，用户态默认 `--slice-us-lag 20000`（20ms）。越大交互任务越灵敏，吞吐越容易抖。

---

## 4. 调度路径

```
wakeup
  └─ select_cpu()  ──有空闲核──► 直接 LOCAL insert，结束
                     无空闲
enqueue()
  ├─ try_migrate? ──找到 idle ──► LOCAL_ON + kick
  ├─ sleeper 可抢占 curr? ──是──► LOCAL_ON + PREEMPT
  └─ 否则 ──► 本 CPU DSQ（vtime 排序）

CPU 空出来
  └─ dispatch()
        ├─ try_steal_task()  远程最早 deadline
        ├─ 本 CPU DSQ
        └─ prev 还能跑 ──► 续 slice（keep_running）
```

### `select_cpu`：唤醒时才主动迁

1. **Waker 更快**：`SCX_WAKE_TTWU` 且 waker CPU capacity 更高、且 wakee 能跑在 waker 上 → 把 `prev_cpu` 改成 waker，把任务拉近。
   - 例外：同 LLC、prev 是完整 idle SMT core → 不迁，直接 LOCAL。
2. 否则用 `pick_idle_cpu`：先 primary domain，再任意可跑核。
3. 找到 idle 就 `SCX_DSQ_LOCAL`；找不到就回 prev。

### `enqueue`：时间片用完，或唤醒时没 idle

`try_migrate` 在这些情况下再找 idle：

- `select_cpu` 被跳过，且任务当前没在跑
- prev CPU 的 DSQ 已有排队
- SMT sibling 在忙、系统里还有完整 idle core

找不到 idle 就进 prev 的 per-CPU DSQ。若是 **sleep wakeup** 且 deadline 比 curr 更早（或 curr 已 ineligible），则 `SCX_ENQ_PREEMPT` 抢占。RT/stop/idle 不抢：它们的 `dsq_vtime == 0`。

### `dispatch`：先偷再本地再续跑

`try_steal_task` 从 `dst_cpu` 起环形扫所有 CPU DSQ，只看 `is_cpu_busy` 为真的源，选 **最小 vtime** 且能跑在本核上的任务，`dsq_move_to_local`。

偷不到再拉本 CPU DSQ。都没有且 `keep_running(prev)` 为真，就续一个 `slice_ns`。

`keep_running` 为假的情况：任务不再 queued、SMT 争用、或不在 primary domain（且任务能去 primary）。per-CPU 任务永远留下。

---

## 5. 饱和与 work-stealing

`busy_threshold`（`--cpu-busy-thresh`，0–100%）控制“哪些核值得偷”：

- 0：不过滤，任何有队列的核都能被偷（默认）。
- \>0：`stopping` 时用 `utime+stime` 增量判断本 slice 是否“够忙”（`total_delta >= runtime * thresh / 1024`）。够忙则把该 CPU 标 busy，窗口为 `now + slice_ns`。
- steal 只从仍在窗口内的核拉任务，避免从几乎空闲的核上抢。

这和 README 一致：**未饱和只在 wakeup 迁；饱和才 pull 远程最小 deadline。**

---

## 6. Locality 相关机制

| 机制 | 作用 |
|------|------|
| 每 CPU DSQ | 默认不跨核 |
| LLC 感知 | 同 LLC + idle SMT 时不跟 waker 走 |
| CPU capacity | 唤醒时倾向迁到更快的核 |
| SMT | 避开 sibling 忙、系统还有完整 idle core 的核 |
| NUMA | 多 node 时用 per-node idle mask；单 node 自动关 |
| primary domain | `-m turbo/performance/powersave/all` 或 CPU 列表，优先 idle 选择与 keep_running |

用户态用 `Topology` 填 `cpu_capacity[]`、SMT sibling（syscall `enable_sibling_cpu`）、primary mask（`enable_primary_cpu`）。

---

## 7. 用户态挂载与 flags

`main.rs` 注入：

- `slice_ns`（默认 1ms）、`slice_lag`、`smt_enabled`、`numa_enabled`、`busy_threshold`、`primary_all`、`cpu_capacity[]`

struct_ops flags：

- `SCX_OPS_ENQ_EXITING` / `ENQ_LAST` / `ENQ_MIGRATION_DISABLED`
- `ALWAYS_ENQ_IMMED`、`ALLOW_QUEUED_WAKEUP`
- NUMA 时加 `BUILTIN_IDLE_PER_NODE`

`timeout_ms = 5000`。兼容内核 ≤ 6.16：没有 `scx_bpf_select_cpu_and` 时退回 `scx_bpf_select_cpu_dfl`。

统计三项：`nr_local_dispatch`、`nr_remote_dispatch`、`nr_keep_running`。`--monitor` 只看统计不挂调度器。

---

## 8. 设计取舍（对照 README）

**做得好的地方**

- 迁移窗口很窄：wakeup + 饱和 steal，cache 友好、大核数下锁争用少。
- vlag 对称夹紧，既照顾交互 sleeper，又防止连续 runnable 饿死。
- steal 环形偏移 + busy 过滤，避免所有核都抢 CPU 0，也避免从空闲核拉活。
- primary domain / SMT / NUMA / capacity 都是“尽量不迁，迁也往更好的地方”。

**代价**

- `try_steal_task` 最坏扫全部 CPU，核数很大时 `dispatch` 路径偏重（可用 `-c` 缩小候选）。
- `vtime_now` 是全局标量，无锁更新，有轻微竞态，但对 deadline 排序通常可接受。
- 默认不抢占非 sleeper；时间片内的交互任务要等 slice 结束或 steal。
- `veristat/9950x.json` 显示默认 `slice_lag=40ms`，和 clap 默认 20ms 不一致，是 BPF 编译时常量 vs 运行时覆盖的差别。

---

## 9. 一句话串起来

**轻载**：任务钉在自己的 per-CPU DSQ，只在 wakeup 找 idle / 更快核。  
**重载**：CPU 空出来时从“够忙”的远程 DSQ 偷最早 deadline，本核没活才续跑 prev。  
**公平**：加权 vruntime + 有界 sleep lag，交互有信用、长跑任务有下界。

这就是 “BPF-Enhanced Execution Runtime Locality-Aware Non-blocking Dispatcher” 的实现主线。
