# scx_rustland

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_rustland` is based on `scx_rustland_core`, a BPF component that abstracts
the low-level `sched_ext` functionalities. The actual scheduling policy is
entirely implemented in user space and it is written in Rust.

## How To Install

Available as a [Rust crate](https://crates.io/crates/scx_rustland): `cargo add scx_rustland`

## Typical Use Case

`scx_rustland` is designed to prioritize interactive workloads over background
CPU-intensive workloads. For this reason the typical use case of this scheduler
involves low-latency interactive applications, such as gaming, video
conferencing and live streaming.

`scx_rustland` is also designed to be an "easy to read" template that can be used
by any developer to quickly experiment more complex scheduling policies fully
implemented in Rust.

## Production Ready?

For performance-critical production scenarios, other schedulers are likely
to exhibit better performance, as offloading all scheduling decisions to
user-space comes with a certain cost (even if it's minimal).

However, a scheduler entirely implemented in user-space holds the potential for
seamless integration with sophisticated libraries, tracing tools, external
services (e.g., AI), etc.

Hence, there might be situations where the benefits outweigh the overhead,
justifying the use of this scheduler in a production environment.

## Demo

[scx_rustland-terraria](https://github.com/sched-ext/scx/assets/1051723/42ec3bf2-9f1f-4403-80ab-bf5d66b7c2d5)

The key takeaway of this demo is to demonstrate that , despite the overhead of
running a scheduler in user-space, we can still obtain interesting results and,
in this particular case, even outperform the default Linux scheduler (EEVDF) in
terms of application responsiveness (FPS), while a CPU intensive workload
(parallel kernel build) is running in the background.
`scx_rustland` 的用户态策略是**全局有序队列 + 向空闲 CPU 推送**，不是经典的每 CPU 双端队列工作窃取。和“偷活”真正相关的，是选核、`RL_CPU_ANY`、bounce，以及把剩余任务数告知 BPF。

---

## 一、总体设计与特点

`scx_rustland` 把调度拆成两层：

| 层 | 职责 | 位置 |
|---|---|---|
| **用户态策略** | 算 deadline、排序、决定下一个跑谁 | 本目录 `src/main.rs` |
| **BPF 执行器** | enqueue/dequeue、选空闲 CPU、真正 dispatch | `scx_rustland_core`（本目录只调用接口） |

策略全部在用户态 Rust 里；BPF 对策略无感知。这是它作为“可读模板”的核心：改调度只要改 Rust，不必碰内核/BPF。

**定位**

- 交互优先：游戏、视频会议、直播等低延迟场景
- 用 deadline 把“经常睡眠的任务”排到“持续占 CPU 的任务”前面
- 用户态有额外开销，生产环境通常不是性能最优解；换来的是可接复杂库、tracing、外部服务

**调度公式**

```
deadline = vruntime + min(exec_runtime, 100 × slice)
```

- `vruntime`：按权重缩放的累计运行时间，保证公平
- `exec_runtime`：自上次睡眠以来的连续占用。常睡的任务这项小，deadline 更早
- 上限 `100 × slice`：防止 CPU 密集任务被饿死

**结构特点**

1. **单全局 `BTreeSet`**，按 deadline 排序，不是每 CPU 队列  
2. **每个调度周期只 dispatch 一个任务**，用 `notify_complete(剩余数)` 告诉 BPF 还有活  
3. **内置空闲 CPU 选择**（`builtin_idle = true`），可选 NUMA 亲和  
4. 默认时间片 20ms，最小 1ms，可按权重放大最小片

---

## 二、实现分析

### 1. 核心数据与排序

```131:166:scheds/rust/scx_rustland/src/main.rs
#[derive(Debug, PartialEq, Eq, Clone)]
struct Task {
    qtask: QueuedTask, // queued task
    deadline: u64,     // task deadline (that determines the order how tasks are dispatched)
    timestamp: u64,    // task enqueue timestamp
}

impl Ord for Task {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.deadline
            .cmp(&other.deadline)
            .then_with(|| self.timestamp.cmp(&other.timestamp))
            .then_with(|| self.qtask.pid.cmp(&other.qtask.pid))
    }
}

struct Scheduler<'a> {
    bpf: BpfScheduler<'a>,
    // ...
    tasks: BTreeSet<Task>,  // 按 deadline 有序
    vruntime_now: u64,      // 全局虚拟时钟
    // ...
}
```

注释里还写着“先 interactive 再 vruntime”，实际已经收进 deadline：交互性由 `exec_runtime` 体现。次序是 **deadline → enqueue 时间 → pid**。

### 2. 主循环：排空 → 派一个 → 通知

```349:377:scheds/rust/scx_rustland/src/main.rs
    fn schedule(&mut self) {
        self.drain_queued_tasks();
        self.dispatch_task();
        self.bpf.notify_complete(self.tasks.len() as u64);
    }

    fn run(&mut self) -> Result<UserExitInfo> {
        while !self.bpf.exited() {
            self.schedule();
            // 统计请求异步处理
        }
        self.bpf.shutdown_and_report()
    }
```

这是 tight loop，没有用户态 sleep：延迟靠“尽快把队头任务交给 BPF”。`notify_complete(n)` 是关键：n>0 时 BPF 可以踢空闲 CPU 来取后续任务。

### 3. Enqueue：更新 vruntime 并算 deadline

```252:274:scheds/rust/scx_rustland/src/main.rs
    fn update_enqueued(&mut self, task: &mut QueuedTask) -> u64 {
        task.vtime = if task.vtime == 0 {
            self.vruntime_now
        } else {
            let vruntime_min = self.vruntime_now.saturating_sub(self.slice_ns);
            task.vtime.max(vruntime_min)
        };

        let slice_ns = task.stop_ts.saturating_sub(task.start_ts);
        let vslice = Self::scale_by_task_weight_inverse(task, slice_ns);
        task.vtime += vslice;
        self.vruntime_now += vslice;

        task.vtime + task.exec_runtime.min(self.slice_ns.saturating_mul(100))
    }
```

含义：

1. **新任务** `vtime==0`：对齐到当前全局时钟，避免插队暴击  
2. **睡醒的任务**：vruntime 信用最多一个 slice（类似 CFS lag clamp），防止睡很久后饿死别人  
3. **权重**：`vslice = slice × 100 / weight`，nice 更高（weight 更大）的任务虚拟时间涨得更慢  
4. **deadline**：vruntime 之上再加封顶后的 `exec_runtime`

注释写 `vruntime_now` 是“观测到的 max vruntime”，实现却是对每次 `vslice` 做累加，更像全局虚拟时钟。多 CPU 并行时它会比单个任务的 vtime 涨得快；真正拉开交互/后台的，主要还是 `exec_runtime`。

### 4. Dispatch：选 CPU + 最小时间片

```280:317:scheds/rust/scx_rustland/src/main.rs
    fn dispatch_task(&mut self) -> bool {
        let Some(task) = self.tasks.pop_first() else {
            return true;
        };
        let mut dispatched_task = DispatchedTask::new(&task.qtask);
        dispatched_task.slice_ns = Self::scale_by_task_weight(&task.qtask, self.slice_ns_min);
        dispatched_task.vtime = task.deadline;

        dispatched_task.cpu = if self.opts.percpu_local {
            task.qtask.cpu
        } else {
            match self.bpf.select_cpu(task.qtask.pid, task.qtask.cpu, task.qtask.flags) {
                cpu if cpu >= 0 => cpu,
                _ => RL_CPU_ANY,
            }
        };

        if self.bpf.dispatch_task(&dispatched_task).is_err() {
            self.tasks.insert(task);
            return false;
        }
        true
    }
```

- 每次只取 **deadline 最小** 的一个  
- 发给 BPF 的 slice 是 **按权重放大的最小片**，不是完整 20ms；高优先级任务更早有机会被重新评估  
- `dispatch` 失败则塞回树并停止本轮，避免把队列打乱  
- 实际时间片/抢占仍由 BPF 侧按 `vtime`（这里传的是 deadline）执行

---

## 三、和工作窃取的关系

本目录 **没有** 经典 work stealing（每 CPU deque、空闲 CPU 从别人尾部偷任务）。用户态是 **一个全局有序堆**，属于 **work sharing / 集中式队列**。

相关机制如下。

### 1. 为什么这里不需要“偷”

工作窃取解决的是：任务在各 CPU 本地队列里，空闲者去别人队列拿活。  
rustland 里所有 runnable 任务都在用户态 `BTreeSet` 里，顺序全局唯一。空闲 CPU 要做的是 **被喂下一个 deadline 最小的任务**，而不是去别的 runqueue 里翻。

负载均衡发生在 **dispatch 选核**，不是 steal。

### 2. 向空闲 CPU 推送（idle push，不是 steal）

```297:307:scheds/rust/scx_rustland/src/main.rs
        dispatched_task.cpu = if self.opts.percpu_local {
            task.qtask.cpu
        } else {
            match self.bpf.select_cpu(...) {
                cpu if cpu >= 0 => cpu,
                _ => RL_CPU_ANY,
            }
        };
```

- `select_cpu`：内置空闲 CPU 策略（init 时 `true`）。找到空闲核就把任务 **推进去**  
- 找不到：`RL_CPU_ANY` —— 不绑死某一核，任意 CPU 都可以消费（共享池，接近 global DSQ）  
- `-n / --numa-local`：优先本 NUMA 节点空闲核，减少跨节点搬任务  
- `-l / --percpu-local`：**关掉** 跨 CPU 放置，per-CPU 任务只去唯一可用核（反窃取 / 保亲和）

这是 **push-to-idle**，不是 idle-pull-from-busy。

### 3. `notify_complete`：剩余工作的“可偷信号”

每个周期只 dispatch 一个，树上可能还有很多。`notify_complete(tasks.len())` 把积压数量交给 BPF：

- `0`：用户态没待派任务，空闲 CPU 不必再等用户态  
- `>0`：还有更高 deadline 的任务，BPF 可以 **kick 空闲 CPU**，让它们再次进入 `ops.dispatch`，形成“空闲核来取下一份活”

语义接近 **idle CPU 向全局队列拉活**，队列是用户态那棵树，不是别的 CPU 的本地队列。

### 4. BPF 侧暴露的“类窃取”计数

用户态策略不实现 steal，但统计里能看到执行器在做跨 DSQ 移动：

| 指标 | 含义 | 和工作窃取的关系 |
|---|---|---|
| `nr_user_dispatches` | 用户态成功派发 | 正常路径 |
| `nr_kernel_dispatches` | 内核/BPF 直接派发 | 空闲 CPU 不等用户态，自己从 DSQ 取 — 更像 **全局队列上的 pull** |
| `nr_bounce_dispatches` | dispatch 被弹到另一个 DSQ | 目标 local DSQ 不合适时改道 — **被迫迁移**，不是主动去偷 |
| `nr_cancel_dispatches` | 取消的 dispatch | 目标 CPU/任务状态已变 |
| `nr_failed_dispatches` | 失败 | 用户态会把任务插回 `BTreeSet` |
| `nr_sched_congested` | 调度拥塞 | 用户态跟不上，BPF 可能走快速路径 |

`bounce` 是 rustland 里最接近“工作被挪到另一核”的可见点：不是空闲者去偷，而是 **这次 dispatch 的目标 DSQ 放不下/不合法，弹到别的队列**。

### 5. 和经典 work stealing 的对比

```
经典 work stealing:
  每 CPU 一个 deque
  本地 push/pop 一端
  空闲 CPU 从其他 CPU 的另一端 steal

scx_rustland:
  用户态一个 BTreeSet（全局优先级）
  每轮只 pop_first 一个
  select_cpu → 推进空闲核
  否则 RL_CPU_ANY → 任意核可跑
  notify_complete(n) → 空闲核被 kick 来拉下一项
  bounce → BPF 把一次 dispatch 改挂到别的 DSQ
```

结果：

- **公平/交互顺序** 由全局 deadline 保证，不会出现“偷到错误优先级的任务”  
- **没有 steal 热点**：不用锁一堆远程 deque，瓶颈在用户态单线程排序 + 用户态↔BPF 往返  
- **代价**：所有调度决策过用户态，`nr_kernel_dispatches` 高说明 BPF 在走捷径补吞吐  
- **`-l`** 会削弱跨核搬迁，换亲和、隔离

### 6. 一次任务的路径（含“类窃取”分叉）

```
wakeup / 时间片用尽
    → BPF enqueue → 用户态 dequeue_task()
    → update_enqueued() 算 deadline
    → 插入 BTreeSet

schedule 循环:
    pop_first() 最小 deadline
    select_cpu?
        命中空闲核 → dispatch 到该 CPU local DSQ     [push-to-idle]
        未命中     → RL_CPU_ANY                     [全局可拉]
    dispatch 失败 → 插回树
    notify_complete(剩余) → 可能 kick 空闲 CPU        [idle pull 下一份]

BPF 实际执行时:
    直接上目标 CPU           → user dispatch
    目标不合法/忙            → bounce 到其他 DSQ      [被迫迁移]
    空闲 CPU 自己从 DSQ 取   → kernel dispatch        [pull]
```

---

**结论：** `scx_rustland` 用全局 deadline 队列做策略，用“找空闲核 / `RL_CPU_ANY` / 通知剩余任务数”做负载分布。真正的跨 DSQ 搬迁（bounce、kernel dispatch）在 `scx_rustland_core` 里，本目录只消费这些计数，不实现 steal 算法。