# scx_rlfifo

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_rlfifo` is a simple Round-Robin scheduler runs in user-space, based on the
`scx_rustland_core` framework.
It dequeues tasks in FIFO order and assigns dynamic time slices, preempting and
re-enqueuing tasks to achieve basic Round-Robin behavior.

## Typical Use Case

This scheduler is provided as a simple template that can be used as a baseline
to test more complex scheduling policies.

## Production Ready?

Definitely not. Using this scheduler in a production environment is not
recommended, unless there are specific requirements that necessitate a basic
FIFO scheduling approach. Even then, it's still recommended to use the kernel's
`SCHED_FIFO` real-time class.
`scx_rlfifo` 的调度策略几乎全部写在 `src/main.rs` 里。本目录没有自写 BPF 程序，内核侧由 `scx_rustland_core` 在构建时嵌入。

## 它是什么

这是一个跑在用户态的简易 **Round-Robin** 调度器模板：任务按 FIFO 出队，再按当前排队人数动态分配时间片。时间片用完后由框架抢占并重新入队，从而形成轮转。

它明确不是生产调度器。启动时会打印警告，建议真正要用户态决策时改用 `scx_rustland`。

## 目录里实际有什么

| 文件 | 作用 |
|------|------|
| `src/main.rs` | 全部调度逻辑 |
| `build.rs` | 调用 `RustLandBuilder` 编译框架自带的 BPF |
| `src/bpf_skel.rs` / `src/bpf_intf.rs` | 包含构建生成的 BPF skeleton / 接口 |
| `Cargo.toml` | 依赖 `scx_rustland_core`、`scx_utils` |
| `veristat/9950x.json` | BPF 只读数据的 veristat 快照 |

`mod bpf` 来自框架，不是本目录手写代码。用户态只通过 `BpfScheduler` 跟内核交互。

## 架构：用户态决策 + BPF 执行

```
内核 enqueue ──► BPF 队列 ──► dequeue_task()
                                    │
用户态 Scheduler.dispatch_tasks()   │
  选 CPU + 算 slice                 │
                                    ▼
                          dispatch_task()
                                    │
                          notify_complete(0)  ← 睡眠，等下一批任务
```

`BpfScheduler` 提供的核心 API：

- `dequeue_task()`：取出一个要跑的任务
- `select_cpu(pid, prev_cpu, flags)`：选空闲 CPU
- `dispatch_task(...)`：把任务派到指定 CPU，并带上时间片
- `notify_complete(nr_pending)`：把控制权交回 BPF，可睡眠

## 调度策略（核心循环）

```126:157:scheds/experimental/scx_rlfifo/src/main.rs
    fn dispatch_tasks(&mut self) {
        // Get the amount of tasks that are waiting to be scheduled.
        let nr_waiting = *self.bpf.nr_queued_mut();

        // Start consuming and dispatching tasks, until all the CPUs are busy or there are no more
        // tasks to be dispatched.
        while let Ok(Some(task)) = self.bpf.dequeue_task() {
            // Create a new task to be dispatched from the received enqueued task.
            let mut dispatched_task = DispatchedTask::new(&task);

            // Decide where the task needs to run (pick a target CPU).
            //
            // A call to select_cpu() will return the most suitable idle CPU for the task,
            // prioritizing its previously used CPU (task.cpu).
            //
            // If we can't find any idle CPU, run on the first CPU available.
            let cpu = self.bpf.select_cpu(task.pid, task.cpu, task.flags);
            dispatched_task.cpu = if cpu >= 0 { cpu } else { RL_CPU_ANY };

            // Determine the task's time slice: assign value inversely proportional to the number
            // of tasks waiting to be scheduled.
            dispatched_task.slice_ns = SLICE_NS / (nr_waiting + 1);

            // Dispatch the task.
            self.bpf.dispatch_task(&dispatched_task).unwrap();
        }

        // Notify the BPF component that tasks have been dispatched.
        //
        // This function will put the scheduler to sleep, until another task needs to run.
        self.bpf.notify_complete(0);
    }
```

策略可以拆成三步：

**1. 出队顺序：严格 FIFO**  
`dequeue_task()` 按入队顺序取任务。没有优先级、weight、vtime、cgroup。`QueuedTask` 里虽有 `weight`、`vtime`、`exec_runtime` 等字段，这里全部忽略。

**2. 选 CPU：优先空闲，尽量亲和**  
`select_cpu()` 优先上次跑过的 CPU；找不到空闲 CPU 时用 `RL_CPU_ANY`，交给 BPF 放到第一个可用 CPU。初始化时 `builtin_idle = true`，BPF 可以自己把任务派到空闲 CPU。

**3. 时间片：随排队人数缩小**

```
SLICE_NS = 5ms
slice = 5ms / (nr_waiting + 1)
```

`nr_waiting` 是本轮开始时 BPF 队列里的任务数，整轮调度共用同一个值，不是每派一个就更新。人越多，每人片越短，轮转越快。这是它被称为 Round-Robin 而不是纯 FIFO 的关键：FIFO 只决定谁先跑，动态 slice + 抢占再入队才形成轮转。

## 初始化参数

```110:123:scheds/experimental/scx_rlfifo/src/main.rs
    fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let open_opts = LibbpfOpts::default();
        let bpf = BpfScheduler::init(
            open_object,
            open_opts.clone().into_bpf_open_opts(),
            0,        // exit_dump_len (buffer size of exit info, 0 = default)
            false,    // partial (false = include all tasks)
            false,    // debug (false = debug mode off)
            true,     // builtin_idle (true = allow BPF to use idle CPUs if available)
            false,    // numa_local (false = ignore NUMA locality when selecting target CPUs)
            SLICE_NS, // default time slice (for tasks automatically dispatched by the backend)
            "rlfifo", // name of the scx ops
        )?;
        Ok(Self { bpf })
    }
```

含义：

- `partial = false`：接管全部普通任务，不是只调度一部分
- `builtin_idle = true`：空闲 CPU 可由 BPF 直接用，不必每次都回用户态
- `numa_local = false`：选 CPU 不考虑 NUMA
- 默认 slice 也是 5ms，给 BPF 自动派发的任务用

`veristat/9950x.json` 能对上：`slice_ns = 5000000`、`builtin_idle = true`、`numa_local = false`。

## 主循环

```186:233:scheds/experimental/scx_rlfifo/src/main.rs
    fn run(&mut self) -> Result<UserExitInfo> {
        let mut prev_ts = Self::now();

        while !self.bpf.exited() {
            self.dispatch_tasks();

            let curr_ts = Self::now();
            if curr_ts > prev_ts {
                self.print_stats();
                prev_ts = curr_ts;
            }
        }
        self.bpf.shutdown_and_report()
    }
}

// ...

fn main() -> Result<()> {
    print_warning();

    // Initialize and load the FIFO scheduler.
    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&mut open_object)?;
        if !sched.run()?.should_restart() {
            break;
        }
    }

    Ok(())
}
```

运行模型：

1. 加载 BPF，注册名为 `rlfifo` 的 sched_ext ops
2. 循环 `dispatch_tasks()`：抽干队列 → 睡眠等新任务
3. 每秒打印一次统计：`user/kernel/cancel/bounce/fail/cong`
4. 若 `should_restart()` 为真（例如热重启），重新 `init` 再跑

## 它刻意没做的事

从本目录代码可以直接看出：

- 不用 `weight` / `vtime`，没有公平调度或 deadline
- 不看 `exec_runtime`、`start_ts`、`stop_ts`，没有负载感知
- 不按 `nr_cpus_allowed` 自己过滤亲和性，交给 `select_cpu()`
- `notify_complete(0)` 始终报告用户态没有积压任务
- 没有命令行参数、配置文件、cgroup、NUMA、SMT 策略
- 本目录没有 BPF 源码，无法在这里改内核侧 enqueue/dispatch

因此它适合当 `scx_rustland_core` 的最小可运行模板：替换 `dispatch_tasks()` 就能试更复杂的策略。README 也写了：生产环境即使只要 FIFO，也应优先用内核 `SCHED_FIFO`。