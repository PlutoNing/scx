# scx_wd40

An experimental fork of the `scx_rusty` scheduler that uses BPF arenas to simplify scheduler development. Found in the main [`sched_ext`](https://github.com/sched-ext/scx/tree/main) repository. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).
scx_wd40 是 scx_rusty 的实验性 fork：内核 BPF 做域内快速调度，用户态 Rust 做负载计算与跨域迁移。核心差异是用 BPF arena 共享内存，让用户态直接读写任务/域上下文，而不是靠 BPF map 来回拷贝。
## Overview

A multi-domain, BPF / user space hybrid scheduler. The BPF portion of the
scheduler does a simple round robin in each domain, and the user space portion
(written in Rust) calculates the load factor of each domain, and informs BPF of
how tasks should be load balanced accordingly.

## Goals

This scheduler ultimately aims to demonstrate how to build modular BPF schedulers
to enable easy code reuse between scheduler codebases. The main way of achieving
this is through the use of BPF arenas that make it possible to directly share memory
between the userspace and kernel scheduler components. This in turn lets us offload
most of the complexity of the scheduler to userspace. Userspace components can be
more easily combined, as opposed to scheduler BPF methods that are often mutually
exclusive.

## Production Ready?

No. This scheduler heavily uses BPF arenas and as such routinely requires a 
bleeding-edge kernel toolchain to even run and verify.
`scx_wd40` 是 `scx_rusty` 的实验性 fork：内核 BPF 做域内快速调度，用户态 Rust 做负载计算与跨域迁移。核心差异是用 **BPF arena 共享内存**，让用户态直接读写任务/域上下文，而不是靠 BPF map 来回拷贝。

---

## 1. 整体架构

调度器按 **NUMA 节点 → LLC domain → CPU** 分层。每个 LLC 是一个 domain（最多 64 个），每个 domain 有独立 DSQ。

```
用户态 (Rust, ~100ms / ~2s)
  Tuner          读 /proc 利用率 → 写 greedy cpumask、slice_ns
  LoadBalancer   读 arena 里的 duty-cycle → 写 task_ctx.target_dom
        ↕ BPF arena（同一块物理内存）
BPF (热路径)
  select_cpu / enqueue / dispatch
  域内 vtime 或 FIFO；greedy steal；执行 target_dom 迁移
```
- **Tuner**：默认 100ms，按利用率开关跨域直接派发 / kick，并在过载时缩短 slice
- **LoadBalancer**：默认 2s，算各 domain 负载，给过载域的任务写 `target_dom`

BPF 侧模块划分：

| 文件 | 职责 |
|---|---|
| `main.bpf.c` | `struct_ops` 入口：选核、入队、派发、生命周期 |
| `placement.bpf.c` | 任务选域、`target_dom` 迁移 |
| `deadline.bpf.c` | 交互性 deadline / vtime |
| `lb_domain.bpf.c` | domain 分配、duty-cycle 记账 |
| `common.bpf.c` | 统计、NUMA 映射、全局常量 |

`build.rs` 还会链入 arena、bitmap、cpumask、ravg、sdt_task、topology 等公共库。

---

## 2. BPF Arena：用户态与内核怎么共享状态

这是相对 `scx_rusty` 的真正改动。

启动顺序：

1. `ArenaLib::init()` 在 BPF object 上建 arena
2. 用 `test_run` 调 `SEC("syscall") wd40_setup`：分配全局 bitmap、buddy/stack 分配器、每个 domain 的 `dom_ctx`
3. 用户态把 topology 写进 arena 里的 `dom_ctx.cpumask`、`node_data`
4. attach `struct_ops`

关键共享结构在 `types.h`：

- **`task_ctx`**（arena）：`domc`、`target_dom`、`weight`、duty-cycle 滑动平均、`waker_freq` / `blocked_freq`、`cpumask`、`all_cpus`
- **`dom_ctx`**（arena）：`min_vruntime`、按 weight 分的 100 个 load bucket、最近活跃任务环（1024 槽）、三套 cpumask、`vtime_lock`

用户态负载均衡**不调 BPF helper**，而是直接改 `task_ctx.target_dom`。下次 `wd40_enqueue` 发现 `domc->id != taskc->target_dom`，就调用 `task_set_domain()` 真正迁域。

任务上下文用 `sdt_task` 挂在 `task_struct` 上：`lookup_task_ctx(p) = scx_task_data(p)`。domain 挂在 topology 树上：`topo_nodes[TOPO_LLC][dom_id]`。

---

## 3. Domain 怎么划

`domain.rs` 用 `Topology`：每个 NUMA 节点下的每个 LLC 变成一个连续编号的 domain。用户态再把 `dom_numa_id_map`、node/domain cpumask 写进 BSS/arena。

新任务在 `wd40_init_task` → `task_pick_and_set_domain()` 里 **round-robin 选第一个与 `cpus_ptr` 相交的 domain**。若开了 `--mempolicy-affinity`，会优先选 `set_mempolicy` 对应的 NUMA domain。

---

## 4. BPF 热路径

### `wd40_select_cpu`：尽量直接派发

优先级大致是：

1. 单 CPU 亲和（pinned / kthread local）
2. `WAKE_SYNC`：同 LLC 且 prev 空闲 → 留在 prev；否则 waker CPU 空闲且本域有空闲核 → 跟 waker
3. 保留 prev：本域且整核空闲；或 prev 在 `direct_greedy_cpumask` 上（跨域 linger）
4. 本域空闲整核 / 空闲 prev / 任意本域空闲 CPU
5. `all_cpus` 且 Tuner 标了 under-util CPU：先本域 greedy，再跨域（默认不跨 NUMA）
6. 否则返回本域 CPU，后续进 domain DSQ

选中直接派发时设 `taskc->dispatch_local = true`。

### `wd40_enqueue`：入队 + 执行用户态迁移意图

- `target_dom` 变了 → `task_set_domain()`，kick 目标域 CPU
- `dispatch_local` → 插入 `SCX_DSQ_LOCAL`
- 任务当前在外域 CPU → kick 本域 CPU（repatriate，避免 DSQ 有任务但本域全闲）
- FIFO：`scx_bpf_dsq_insert(dom)`；否则 `place_task_dl()` 按 vtime 入队
- 之后可 kick `kick_greedy_cpumask` 上的空闲 CPU，让它们来偷任务

### `wd40_dispatch`：本域消费 + greedy steal

1. `dsq_move_to_local(本域)`
2. `greedy_threshold != 0` 时，round-robin 偷同 NUMA 其他域
3. `greedy_threshold_x_numa != 0` 且多 socket 时，再偷跨 NUMA

Steal 是临时的：任务域归属不变，下次 enqueue 会 repatriate。

---

## 5. Deadline / vtime（默认，非 `--fifo-sched`）

思路接近 lavd：给 **生产者+消费者**（高 `waker_freq` 且高 `blocked_freq`）更紧的 deadline。

```
freq_factor = blocked_freq * waker_freq² * weight
lat_prio    = log2(freq_factor) - log2(avg_runtime / weight)
deadline    = dsq_vtime + avg_runtime * 100 / lat_scale(lat_prio)
```

运行时：

- `running`：更新 domain `min_vruntime`（arena spinlock）
- `stopping`：累加 runtime，按 weight 反比推进 `dsq_vtime`
- `place_task_dl`：把 vtime 钳在 `min_vruntime - slice`，防止睡很久的任务攒出巨大预算

`fifo_sched` 时这些全部跳过，域内 FIFO。

---

## 6. 用户态 Tuner（高频，默认 100ms）

读 `/proc/stat` 算每 CPU / 每 domain 利用率：

- domain 利用率 < `direct_greedy_under`（默认 90%）→ 该域 CPU 进入 `direct_greedy_cpumask`，select_cpu 可把任务直接推过去
- 利用率 < `kick_greedy_under`（默认 100%，即几乎总开）→ 进入 `kick_greedy_cpumask`，enqueue 后 kick 空闲核来偷
- 整机利用率 ≥ 99.999% → `slice_ns` 从 20ms 降到 1ms（`--slice-us-overutil`）

`fully_utilized` 还会关掉负载均衡里的 weight 缩放（过载时按 duty-cycle 而不是 `weight * dcycle`）。

---

## 7. 用户态 LoadBalancer（低频，默认 2s）

BPF 只记账，不算“该迁谁”。

**BPF 记账**：任务 runnable/quiescent 时，按 weight 落入 100 个 bucket，对 `dcycle` 做指数滑动平均（half-life 默认 1s）。迁域时 `dom_xfer_task()` 把该任务的 duty-cycle 从源 bucket 转到目标 bucket。

**用户态决策**：

1. 直接读 arena 里每个 domain 的 buckets → `LoadAggregator` 得到带 infeasible weight 修正的 load
2. 建层次：`LB Root → NumaNode → Domain → Task`
3. 先跨 NUMA（失衡阈值 17%），再节点内跨 domain（阈值 5%）
4. 过载域读最多 1024 个最近活跃任务，选 load 最接近目标迁移量、且 `dom_mask` 允许的任务
5. **只写 `taskc.target_dom`**；真正迁域发生在下次 enqueue

kworker 可用 `--balanced-kworkers` 排除，避免和内核 L3 均衡打架。

---

## 8. 数据流小结

```
任务首次出现
  init_task → arena 分配 task_ctx → RR 选 domain

任务变可运行
  select_cpu 尽量 direct dispatch
  否则 enqueue → 本域 DSQ（FIFO 或 deadline vtime）
  若用户态写了 target_dom → 改 domain、转 duty-cycle、kick 目标 CPU

CPU 空闲
  dispatch 先吃本域 DSQ，再 greedy steal（任务仍属原域）

~100ms Tuner
  利用率 → greedy mask + slice

~2s LoadBalancer
  buckets → 迁谁 → 写 target_dom
```

---

## 9. 设计意图 vs 实现现状

README 的目标是：**用 arena 把复杂逻辑放到用户态，BPF 只做简单、可组合的热路径**。实现上基本对齐：

- BPF 不决定长期放置，只执行 `target_dom` 和 greedy 临时偷
- 负载、利用率、slice、greedy 集合都在用户态
- 调度逻辑拆成 placement / deadline / lb_domain，而不是单文件 `struct_ops`

仍是实验性质：强依赖 arena、buddy allocator、sleepable `init_task`，需要较新内核才能通过 verifier。`Cargo.toml` 里 veristat 是关掉的。

---

## 10. 实现里值得注意的点

这些都在 `scx_wd40` 目录内可见：

1. **`is_offline_cpu()` 没看 `cpu`**，只判断 `topo_nodes[TOPO_CPU] == NULL`。热插拔路径上，后面 `select_cpu_idle_x_numa` 在 `domc == NULL` 时仍会解引用 `domc->direct_greedy_cpumask`。
2. **跨 NUMA steal 条件像写反了**：`dsq_nr_queued(dom) >= greedy_threshold_x_numa` 时 `continue`，等于只偷队列更短的域；注释和 CLI 说的是“队列够长才偷”。默认阈值 0 时整条路径被提前关掉，所以默认行为不受影响。
3. **`dom_dcycle_xfer_task` 里** `taskc->dcyc_rd = taskc->dcyc_rd` 是空操作；前面算好的 `task_dcyc_rd` 没有写回任务上下文。
4. **`Domain::ctx()`** 在 MutexGuard 释放后返回 `&mut dom_ctx`。指针指向 arena，实际寿命够用，但 Rust 生命周期是错的。
5. **`build.rs` 把 `deadline.bpf.c` 加了两次**。
6. **`deadline.h` 是空文件**；声明实际在 `lb_domain.h`。
7. 文档仍写“域内 round-robin”，默认其实是 **weighted vtime + 交互性 deadline**；RR/FIFO 要显式 `--fifo-sched`。

---

一句话：`scx_wd40` 把 rusty 的混合调度拆成 **arena 上的共享状态机**——BPF 负责选核、入队、临时 steal；用户态 Tuner/LB 通过直接改 arena 里的 mask 和 `target_dom` 控制长期放置。模块边界清楚，但离生产就绪还差 verifier 友好度和几处边界逻辑。