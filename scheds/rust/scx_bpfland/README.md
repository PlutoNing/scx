# scx_bpfland

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_bpfland`: a vruntime-based `sched_ext` scheduler that prioritizes interactive
workloads.

This scheduler is derived from `scx_rustland`, but it is fully implemented in BPF.
It has a minimal user-space `Rust` part to process command line options, collect
metrics and log out scheduling statistics. The BPF part makes all the
scheduling decisions.

Tasks are categorized as either interactive or regular based on their average
rate of voluntary context switches per second. Tasks that exceed a specific
voluntary context switch threshold are classified as interactive. Interactive
tasks are prioritized in a higher-priority queue, while regular tasks are
placed in a lower-priority queue. Within each queue, tasks are sorted based on
their weighted runtime: tasks that have higher weight (priority) or use the CPU
for less time (smaller runtime) are scheduled sooner, due to their a higher
position in the queue.

Moreover, each task gets a time slice budget. When a task is dispatched, it
receives a time slice equivalent to the remaining unused portion of its
previously allocated time slice (with a minimum threshold applied). This gives
latency-sensitive workloads more chances to exceed their time slice when needed
to perform short bursts of CPU activity without being interrupted (i.e.,
real-time audio encoding / decoding workloads).

## Typical Use Case

Interactive workloads, such as gaming, live streaming, multimedia, real-time
audio encoding/decoding, especially when these workloads are running alongside
CPU-intensive background tasks.

In this scenario `scx_bpfland` ensures that interactive workloads maintain a high
level of responsiveness.

## Production Ready?

The scheduler is based on `scx_rustland`, implementing nearly the same scheduling
algorithm with minor changes and optimizations to be fully implemented in BPF.

Given that the `scx_rustland` scheduling algorithm has been extensively tested,
this scheduler can be considered ready for production use.

只看了 `scheds/rust/scx_bpfland`。结论先说：**README 描述的是旧算法**；当前实现是「单队列 deadline（`vruntime + awake_vtime`）+ 两级 DSQ」，不是双队列 interactive/regular。

---

## 1. 分层：谁做决策

| 层 | 文件 | 职责 |
|---|---|---|
| BPF | `src/bpf/main.bpf.c` | 全部调度：选核、入队、派发、vruntime、slice |
| Rust | `src/main.rs` | CLI、拓扑、主域、SMT、cpufreq、统计、热重启 |
| 接口 | `src/bpf/intf.h` | 用户态调 BPF 的 `cpu_arg` / `domain_arg` |
| 统计 | `src/stats.rs` | 从 BSS 读计数并做 delta |

`build.rs` 用 `scx_cargo` 把 `intf.h` / `main.bpf.c` 编进 skeleton。用户态不参与选谁跑。

---

## 2. README 与代码对不上

README 写的三件事，代码里都变了：

**交互任务分类**  
README：按自愿上下文切换率分 interactive / regular，进高低两个队列。  
实现：没有这两类，也没有双队列。交互性折进 deadline：

```
deadline = vruntime + awake_vtime
```

唤醒越勤、`awake_vtime` 越小，deadline 越靠前。

**时间片预算**  
README：派发时用「上次没用完的 slice，再加下限」。  
实现：按权重和队列深度现算：

```
slice = max(weight_scale(slice_max) / max(nr_wait, 1), slice_min)
```

**自愿切换**  
实现跟踪的是 `wakeup_freq`（`ops.runnable()` 里按唤醒间隔 EWMA），不是自愿切换次数。它只用来放大 `slice_lag`（睡眠任务能攒多少 vruntime 信用）。

---

## 3. 队列：每 CPU + 每 NUMA 节点

初始化建两类 DSQ：

- **per-CPU**：`dsq_id = cpu`
- **per-node**：`dsq_id = nr_cpu_ids + node`

再加内核 `SCX_DSQ_LOCAL`（直派、不走 vtime 排序）。

`dispatch` 同时 peek 两个队列，谁 deadline 更小先消费：

```1028:1034:scheds/rust/scx_bpfland/src/bpf/main.bpf.c
	if (!is_deadline_min(q, p)) {
		if (consume_first_task(cpu_dsq(cpu), p) || consume_first_task(node_dsq(cpu), q))
			return;
	} else {
		if (consume_first_task(node_dsq(cpu), q) || consume_first_task(cpu_dsq(cpu), p))
			return;
	}
```

两边都空且 `prev` 还能跑，就补 slice 继续跑（`keep_running`）。SMT 争用时不续跑，逼任务迁走。

---

## 4. 任务生命周期

```
runnable  →  清 awake_vtime，更新 wakeup_freq
select_cpu → 找 idle；找到则直插入 cpu DSQ（跳过 enqueue）
enqueue   →  sticky / kthread / pcpu / 再选 idle / 否则进 node DSQ
running   →  记 last_run_at，推全局 vtime_now
stopping  →  累加 vruntime、awake_vtime、avg_runtime
dispatch  →  cpu DSQ vs node DSQ 取更早 deadline
```

`enable` 把新任务 `dsq_vtime` 设成当前 `vtime_now`，避免新任务插队过猛。

---

## 5. Deadline：公平 + 交互

`task_dl()` 核心：

1. **`vruntime`**：累计运行时间 / 权重。睡眠时会落后全局 `vtime_now`，醒来更“便宜”。
2. **上限**：`vtime_min = vtime_now - weight * slice_lag * lag_scale`，防止睡太久攒无限信用。
3. **`lag_scale`**：`wakeup_freq` 越大（常睡常醒）信用越大；队列很深时压到 1，避免饿死。排队工作量超过 `STARVATION_MS/10` 时直接关掉 boost。
4. **`awake_vtime`**：本次醒来后的加权运行时间，上限 `weight_inv * slice_lag`。短突发任务这项小，deadline 更靠前。

所以「交互优先」是 deadline 倾斜，不是单独高优先级队列。

`slice_lag` 默认 40ms（`-l`），越大交互越猛、新任务/批处理越容易抖。

---

## 6. 入队路径（优先级从高到低）

`bpfland_enqueue`：

1. **sticky**：`avg_runtime < 10µs` 且 `-S`。高频短任务钉在 `SCX_DSQ_LOCAL`，减轻 node DSQ 锁。
2. **per-CPU kthread**：`-k` 或开了 throttle。直派 LOCAL，避免内核线程被节流饿死。
3. **pcpu 任务**（只能跑一核或 migration disabled）：
   - `-p`：LOCAL（更快，可能不公平/stall）
   - 否则：进该 CPU 的 cpu DSQ，仍按 deadline
4. **再找 idle**：`select_cpu` 没选过，或当前核 SMT 争用。找到就进目标 cpu DSQ 并 `kick`。
5. **否则**：进 **node DSQ**（`nr_shared_dispatches`）。

`select_cpu` 找到 idle 也会直插 cpu DSQ（`nr_direct_dispatches`）。

---

## 7. 选核

两条路：

**`-P` preferred idle scan**  
按容量从高到低扫 `preferred_cpus[]`：先主域满闲 SMT → 主域任意 idle → 全局满闲 SMT → 全局任意 idle。最多 1024 核。

**默认**  
- 关同步唤醒：清掉 `SCX_WAKE_SYNC`
- 混合核：waker 更快时，把 wakee 往 waker 靠；同 LLC 且 prev 满闲 SMT 则不迁
- 有主域：先 `scx_bpf_select_cpu_and(..., primary)`，再全局
- 内核 ≤ 6.16：回退 `scx_bpf_select_cpu_dfl`；从 enqueue 调时直接失败（旧 API 不能在 enqueue 里用）

SMT：sibling 忙且系统里还有满闲核 → 视为 contended。NUMA 开时 idle mask 按节点取。

---

## 8. TIMELY：接线了，控制环没写完

`-T` 和一堆增益/阈值从用户态写进 rodata；`task_ctx` 有 delay / gradient / gain。

实际用到的只有：

- enqueue/select_cpu 记 `timely_last_enqueued_at`
- `running` 里对排队时延、梯度做 EWMA
- `cpu_release` 里 `scx_bpf_reenqueue_local()`

**没有**用 delay 调 slice 或 deadline 的函数。`nr_delay_*` / `nr_gain_*` 等计数在 BPF 里从未自增（只有 `nr_cpu_release_reenqueue` 会加）。`cpu_ctx` 的 `l2_cpumask` / `l3_cpumask` 也没人用。

开 `-T` 目前几乎只是「多记一点延迟 + CPU 被抢时重入队」。

---

## 9. 用户态在补什么

`main.rs` 在 attach 前做完：

- **拓扑**：SMT / NUMA 节点数；单节点自动关 NUMA
- **主域** `-m`：`auto` / `performance` / `powersave` / `all` / 十六进制 mask。`auto` 跟电源档位；档位变了会 `user_restart`
- **容量表**：`cpu_capacity[]`、`preferred_cpus[]`（容量降序）
- **cpufreq**：`powersave`→0，`-f`→自动（`-1`，BPF 按利用率调），否则拉满
- **SMT sibling**：`enable_sibling_cpu` syscall
- **throttle**：`-t` 注入空闲；同时强制 `local_kthreads`
- **idle QoS**：`-I` 改 resume latency，退出时恢复

主循环只做：电源档位、stats 请求、退出/重启。调度路径不经过用户态。

ops flags：`ENQ_EXITING | ENQ_LAST | ENQ_MIGRATION_DISABLED | ALLOW_QUEUED_WAKEUP`，NUMA 时再加 `BUILTIN_IDLE_PER_NODE`。`timeout_ms = 5000`（stall 阈值）。

---

## 10. 和 README 用例怎么对上

游戏 / 直播 / 实时音频这类「常睡、短突发」仍然受益，机制换成了：

- `awake_vtime` 小 → deadline 靠前
- `wakeup_freq` 高 → 睡眠信用更大
- 队列不深时 slice 接近 `weight * slice_max`（默认 1ms）
- 直派 idle，少排队

和 CPU 大户共存时，大户 `vruntime` / `awake_vtime` 涨得快，自然往后排。不是「进高优先级队列」。

节流（`-t`）用 `throttle_timer` 在 `slice_max` 和 `throttle_ns` 之间翻转，`dispatch` 在节流窗口直接放空 CPU。

---

## 11. 默认值注意

BPF 里 `sticky_tasks` / `local_kthreads` / `local_pcpu` 写成 `true`，但 clap 是 `SetTrue`（默认 false）。用户态会覆盖，**不带参数跑时这三项是关的**。`slice_min` 默认 0。

---

**一句话**：`scx_bpfland` 是 BPF 里的加权 vruntime + 醒来突发惩罚（`awake_vtime`）+ 唤醒频率调节的 lag，队列是 **每 CPU / 每节点 DSQ**，再叠加 sticky、kthread、主域、SMT、混合核选核。README 的双队列和「剩余 slice 预算」已经过时；TIMELY 统计和字段在，控制律还没接到 `task_slice` / `task_dl` 上。