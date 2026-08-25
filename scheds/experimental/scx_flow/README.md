# scx_flow

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature that enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_flow` is a budget-driven `sched_ext` scheduler with zero heuristic classification. Tasks accumulate budget while sleeping and spend it while running. Non-wakeup re-enqueues enter the **Waiting Room** — per-CPU vtime-ordered DSQs where each task receives an equal share of its target CPU's bandwidth: `FLOW_CARRIAGE_NS / tasks_on_cpu`, clamped to [50µs, 2ms]. Slices adjust dynamically as tasks arrive on the same core. Wakeups are dispatched immediately to the target CPU via `SCX_DSQ_LOCAL_ON`.

## Typical Use Case

Systems where scheduling decisions must be deterministic and explainable: embedded control, robotics, avionics, automotive, and other mission-critical workloads. The fair-share slice model ensures each task receives an equal portion of its target core's bandwidth, preventing both starvation and priority inversion.

General-purpose desktop and workstation use is also supported; interactive tasks (longer sleep → higher budget → longer slice) are naturally separated from bulk workers without requiring configuration or heuristics.

## Web UI

When scx_flow starts, it serves a live dashboard at `http://[::1]:50005/` or via Unix socket at `/tmp/scx_flow.sock`. The dashboard shows per-core cards (CPU ID, max frequency, LLC, SMT status), the Waiting Room carriage pool (producer slot index, filling count, 64-slot grid), and system statistics (on-CPU count, wake/pinned dispatches, budget exhaustions, CPU migrations). Values update every second. Disable with `--no-webui`.

## Production Ready?

Yes, for the use cases described above.

根据当前 README，`scx_flow` 的核心特点如下。

## 设计立场

这是一个**预算驱动、零启发式分类**的 `sched_ext` 调度器。任务类别不靠类型判断，只靠睡眠/运行对预算的影响。

## 调度模型

- **预算**：睡眠时积累，运行时消耗。交互任务睡得久、预算高、时间片更长；批量任务则相反。
- **Waiting Room**：非唤醒的重新入队进入按 CPU 划分、按 vtime 排序的 DSQ。
- **公平分带宽**：每个任务分到目标 CPU 带宽的等份：`FLOW_CARRIAGE_NS / tasks_on_cpu`，并夹在 **50µs–2ms**。同核任务增减时，时间片会跟着变。
- **唤醒路径**：wakeup 直接用 `SCX_DSQ_LOCAL_ON` 派到目标 CPU，不进 Waiting Room。

## 适用场景

面向需要**决策可解释、行为确定**的系统：嵌入式控制、机器人、航空电子、汽车等关键负载。等分带宽用来避免饥饿和优先级反转。桌面/工作站也能用：交互与批量任务靠预算自然分开，无需配置。

## 可观测性

启动后默认提供实时仪表盘（`http://[::1]:50005/` 或 `/tmp/scx_flow.sock`），每秒刷新：每核信息、Waiting Room 车厢池、系统统计。可用 `--no-webui` 关闭。

## 一句话

`scx_flow` 用「睡眠攒预算、运行花预算」代替启发式分类，用 Waiting Room 做核内等分带宽，唤醒则直达目标 CPU。
