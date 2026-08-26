<img src="logo.png" alt="scx_chaos" width="60%">

A general purpose `sched_ext` scheduler designed to amplify race conditions for testing and debugging.

## Overview

`scx_chaos` is a specialized scheduler that intentionally introduces various forms of latency and performance degradation to help expose race conditions and timing-dependent bugs in applications. Unlike traditional schedulers that aim for optimal performance, `scx_chaos` is designed to stress-test applications by introducing controlled chaos into the scheduling process.

**WARNING**: This scheduler is experimental and should not be used in production environments. It is specifically designed to degrade performance and may cause system instability.

## Features

The scheduler supports several "chaos traits" that can be enabled individually or in combination, with more to come:

### Random Delays

- Introduces random delays in task scheduling
- Configurable frequency, minimum, and maximum delay times
- Helps expose timing-dependent race conditions

### CPU Frequency Scaling

- Randomly scales CPU frequency for processes
- Configurable frequency range and application probability
- Tests application behavior under varying CPU performance

### Performance Degradation

- Applies configurable performance degradation to processes
- Uses a fractional degradation system
- Simulates resource contention scenarios

### Kprobe-based Delays

- **WARNING**: These delays are the most likely to break your system
- Attaches to kernel functions via kprobes
- Introduces delays when specific kernel functions are called
- Useful for testing specific kernel code paths

## Usage

### Basic Usage

Run without chaos features (baseline performance):

```bash
sudo scx_chaos
```

### Random Delays

```bash
sudo scx_chaos --random-delay-frequency 0.1 --random-delay-min-us 100 --random-delay-max-us 1000
```

### CPU Frequency Scaling

```bash
sudo scx_chaos --cpufreq-frequency 0.2 --cpufreq-min 400000 --cpufreq-max 2000000
```

### Performance Degradation

```bash
sudo scx_chaos --degradation-frequency 0.15 --degradation-frac7 64
```

### Kprobe Delays

```bash
sudo scx_chaos --kprobes-for-random-delays schedule do_exit --kprobe-random-delay-frequency 0.05 --kprobe-random-delay-min-us 50 --kprobe-random-delay-max-us 500
```

### Testing Specific Applications

Run a specific command under the chaos scheduler:

```bash
sudo scx_chaos [chaos-options] -- ./your-application --app-args
```

The scheduler will automatically detach when the application exits.

### Process Targeting

Focus chaos on a specific process and its children:

```bash
sudo scx_chaos --pid 1234 [chaos-options]
```

### Monitoring

Enable statistics monitoring:

```bash
sudo scx_chaos --stats 1.0 [chaos-options]  # Update every 1 second
```

Run in monitoring mode only (no scheduler):

```bash
sudo scx_chaos --monitor 2.0
```

### Repeat Testing

Automatically restart applications for continuous testing:

```bash
# Restart on failure
sudo scx_chaos --repeat-failure [chaos-options] -- ./test-app

# Restart on success
sudo scx_chaos --repeat-success [chaos-options] -- ./test-app
```

## Command Line Options

> **Note:** For the most up-to-date and complete CLI documentation, run `scx_chaos --help`. This includes all chaos-specific options as well as the full set of p2dq performance tuning options.

### Random Delays

- `--random-delay-frequency <FLOAT>`: Probability of applying random delays (0.0-1.0)
- `--random-delay-min-us <MICROSECONDS>`: Minimum delay time
- `--random-delay-max-us <MICROSECONDS>`: Maximum delay time

### CPU Frequency

- `--cpufreq-frequency <FLOAT>`: Probability of applying frequency scaling
- `--cpufreq-min <FREQ>`: Minimum CPU frequency
- `--cpufreq-max <FREQ>`: Maximum CPU frequency

### Performance Degradation

- `--degradation-frequency <FLOAT>`: Probability of applying degradation
- `--degradation-frac7 <0-128>`: Degradation fraction (7-bit scale)

### Kprobe Delays

- `--kprobes-for-random-delays <FUNCTION_NAMES>`: Kernel functions to probe
- `--kprobe-random-delay-frequency <FLOAT>`: Probability of kprobe delays
- `--kprobe-random-delay-min-us <MICROSECONDS>`: Minimum kprobe delay
- `--kprobe-random-delay-max-us <MICROSECONDS>`: Maximum kprobe delay

### General Options

- `--verbose`, `-v`: Increase verbosity (can be repeated)
- `--stats <SECONDS>`: Enable statistics with update interval
- `--monitor <SECONDS>`: Run in monitoring mode only
- `--ppid-targeting`: Focus on target process and children (default: true)
- `--repeat-failure`: Restart application on failure
- `--repeat-success`: Restart application on success
- `--pid <PID>`: Monitor specific process ID
- `--version`: Print version and exit

## Requirements

- Root privileges (required for `sched_ext` and kprobe operations)
- Modern Linux kernel with `sched_ext` support, chaos has very limited backward compatibility

## Use Cases

- **Race Condition Detection**: Expose timing-dependent bugs in multithreaded applications
- **Performance Testing**: Test application behavior under varying system performance
- **Stress Testing**: Validate application robustness under adverse conditions
- **Kernel Development**: Test kernel code paths with artificial delays
- **CI/CD Integration**: Automated testing with controlled chaos injection

## Statistics

The scheduler provides various statistics including:

- Random delay applications
- CPU frequency scaling events
- Performance degradation applications
- Kprobe delay triggers
- Process targeting exclusions

## Implementation Details

`scx_chaos` is built on the `sched_ext` framework and uses the `scx_p2dq` scheduler as its base. It implements chaos traits through BPF programs that intercept scheduling decisions and apply configured disruptions based on probability distributions.
`scx_chaos` 是一层挂在 **scx_p2dq** 上的 chaos 注入调度器：p2dq 负责正常选核与排队，chaos 在 `runnable` / `enqueue` / `dispatch` / `running` 等钩子上按概率插入延迟、降频、缩短时间片。目标不是性能，而是放大竞态。

---

## 1. 目录与职责

```
scx_chaos/
├── src/main.rs          # CLI 入口，禁止 ATQ
├── src/lib.rs           # 用户态：配置、加载 BPF、进程监控、统计
├── src/stats.rs         # 统计指标与 monitor
├── src/bpf/main.bpf.c   # 核心：trait 选择、delay DSQ、kprobe
├── src/bpf/intf.h       # 用户态/BPF 共享枚举与 per-task 上下文
├── src/bpf/scx_p2dq -> ../../../scx_p2dq/src/bpf   # 基座调度器
└── src/bpf/lib -> ../../../../../lib               # arena/bitmap 等公共 BPF
```

`main.bpf.c` 第一行关掉 p2dq 自己的 `struct_ops`，再把 chaos 钩子包在外面：

```8:9:scheds/rust/scx_chaos/src/bpf/main.bpf.c
#define P2DQ_CREATE_STRUCT_OPS 0
#include "scx_p2dq/main.bpf.c"
```

多数 ops 仍直接转给 p2dq（`update_idle` / `exit` / `stopping` / `set_cpumask`），chaos 只改调度决策点。

---

## 2. 整体数据流

```
init_task ──► calculate_chaos_match（PPID 过滤，写入 taskc->match）
     │
runnable ──► choose_chaos（按 CDF 抽 next_trait）
     │         或消费 kprobe 留下的 pending_trait
     │
select_cpu ──► 若是延迟类 trait，跳过 p2dq 选核，强制走 enqueue
     │
enqueue ──► 先 async_p2dq_enqueue 得到 promise
     │         ├─ RANDOM_DELAYS / KPROBE：插入 per-CPU delay DSQ
     │         ├─ DEGRADATION：改 slice / vtime
     │         └─ 否则 complete_p2dq_enqueue
     │
dispatch ──► 把 delay DSQ 里到期任务搬回 p2dq，再 p2dq_dispatch
     │
running ──► CPU_FREQ：scx_bpf_cpuperf_set
tick    ──► 若 pending kprobe 延迟，slice=0 强制重新 enqueue
```

每任务状态在 `BPF_MAP_TYPE_TASK_STORAGE` 的 `chaos_task_ctx` 里：

```39:47:scheds/rust/scx_chaos/src/bpf/intf.h
struct chaos_task_ctx {
	enum chaos_match      match;
	enum chaos_trait_kind next_trait;
	enum chaos_trait_kind pending_trait;
	u64		      enq_flags;
	u64		      p2dq_vtime;
};
```

- `match`：是否在 chaos 目标进程树上  
- `next_trait`：这次唤醒要用的 trait  
- `pending_trait`：kprobe 预置、下次 runnable 再生效  
- `p2dq_vtime`：进 delay DSQ 前保存的真实 vtime，dispatch 时还原

---

## 3. Trait 选择：定点概率 CDF

用户态把每个 trait 的频率 `f ∈ [0,1]` 编成 `frac32 = f * 2^32`，再做成**累积分布**：

```379:404:scheds/rust/scx_chaos/src/lib.rs
        let freq_array = &mut rodata.trait_delay_freq_frac32;
        // ...
        freq_array[CHAOS_TRAIT_NONE] = u32::MAX - freq_array.iter().sum::<u32>();
        for i in 1..freq_array.len() {
            freq_array[i] = freq_array[i].checked_add(freq_array[i - 1])...
        }
```

BPF 侧一次 `bpf_get_prandom_u32()`，落在哪个区间就选哪个 trait：

```129:135:scheds/rust/scx_chaos/src/bpf/main.bpf.c
	u32 roll = bpf_get_prandom_u32();
#pragma unroll
	for (int i = 0; i < CHAOS_TRAIT_MAX; ++i) {
		if (roll <= trait_delay_freq_frac32[i])
			return i;
	}
```

被 PPID 排除的任务直接 `CHAOS_TRAIT_NONE`，并记 `CHAOS_STAT_CHAOS_EXCLUDED`。

---

## 4. 四种 chaos 机制

### 4.1 Random Delays（调度延迟）

这是实现最完整的一条路径。

1. `runnable` 抽到 `RANDOM_DELAYS`  
2. `select_cpu` **故意不调 p2dq**，返回 `prev_cpu`，避免 p2dq 直接 dispatch 绕过 enqueue  
3. `enqueue_random_delay` 把任务插入 **per-CPU delay DSQ**，vtime = `now + U(min,max)`：

```284:291:scheds/rust/scx_chaos/src/bpf/main.bpf.c
	u64 vtime = bpf_ktime_get_ns() + chaos_get_uniform_u64(min_ns, max_ns);
	scx_bpf_dsq_insert_vtime(p, get_cpu_delay_dsq(-1), 0, vtime, enq_flags);
```

4. `dispatch` 按 vtime 扫 delay DSQ：到期则还原 `p2dq_vtime`，再走 `async_p2dq_enqueue` + `dsq_move` 交回 p2dq  
5. BPF timer（0.5–2ms，slack 2.5ms）扫所有 CPU 的 delay DSQ：超时较多用 `SCX_KICK_PREEMPT`，刚到期用 `SCX_KICK_IDLE`

均匀随机用的是 **Lemire algorithm 5**（无 128-bit 乘法），避免 `rand % n` 的取模偏差。

Delay DSQ ID：`CHAOS_DSQ_BASE | cpu_idx`（`1<<16 | cpu`）。注释里写了假设 CPU ID 线性，NUMA/非连续 ID 可能对不齐。

### 4.2 Kprobe Delays

用户态校验 `available_filter_functions` 后，把同一个 `generic` kprobe 程序挂到多个内核函数上（关掉 autoattach，手动 `attach_kprobe`）。

命中后按独立概率写 `pending_trait = KPROBE_RANDOM_DELAYS`。当前任务若正在跑，`chaos_tick` 把 `slice` 置 0，逼它马上再 enqueue，从而走进 delay DSQ。README 也标了：这条最容易把系统打挂。

### 4.3 CPU Frequency

`chaos_running` 里：抽中则 `scx_bpf_cpuperf_set(cpu, cpu_freq_min)`，否则拉回 `cpu_freq_max`。用户态同时把 `p2dq_config.freq_control = false`，避免和 p2dq 抢调频。

### 4.4 Performance Degradation

意图是改小时间片 / 推后 vtime。enqueue 里对 p2dq 的 FIFO/VTIME promise 动手：

```564:583:scheds/rust/scx_chaos/src/bpf/main.bpf.c
	if (taskc->next_trait == CHAOS_TRAIT_DEGRADATION) {
		if (promise.kind == P2DQ_ENQUEUE_PROMISE_FIFO) {
			promise.fifo.slice_ns = ((degradation_frac7 << 7) *
						 promise.fifo.slice_ns) >> 7;
```

这里有两处实现缺口（见第 7 节）。

---

## 5. PPID 定向：只打目标进程树

`calculate_chaos_match` 沿 `real_parent` 走到根（最多 `1<<20` 层），并缓存祖先的 `match`，避免每任务都全走一遍。

用户态三种语义：

| 场景 | `requires_ppid` | 效果 |
|---|---|---|
| 无 `--pid` / 无命令 | `ppid = -1` | 全系统都可被 chaos |
| `scx_chaos -- ./app` | `ExcludeParent(自己)` | 排除调度器自身，打其子进程（被测程序） |
| `scx_chaos --pid N` | `IncludeParent(N)` | 只打 N 及其子孙 |

`--ppid-targeting` 默认 true。

---

## 6. 用户态生命周期

`run()` 拆成三条线：

1. **调度线程**：`Builder` → 加载 skel → 调 p2dq `init_open_skel!` / `init_skel!` → arena 分配 task 结构 → attach struct_ops 和 kprobe → `observe()` 轮询 UEI 与 stats  
2. **统计线程**（`--stats`）：读 per-CPU `chaos_stats` 求和后做 delta  
3. **主线程**：  
   - `--monitor`：只看统计，不挂调度器  
   - `--pid`：`kill(pid, 0)` 轮询，进程退出则卸调度器  
   - `-- args`：spawn 被测程序；`--repeat-failure` / `--repeat-success` 决定是否重启

`BuilderIterator` 目前只产出 **一个** Builder（`idx > 1` 就停），像是给以后“多配置轮换”留的口子。

其它约束：

- `atq_enabled` 直接 `bail`（BPF 里 ATQ/DHQ promise 也会 `scx_bpf_error`）  
- 打开 `SCX_OPS_KEEP_BUILTIN_IDLE`，可选 `SCX_OPS_ALLOW_QUEUED_WAKEUP`  
- ARM 上按 tracepoint 是否存在决定是否加载 `on_thermal_pressure`

---

## 7. 实现上的缺口与风险

**Degradation 用户态没接上。** CLI 有 `--degradation-frequency` / `--degradation-frac7`，但 `BuilderIterator` 只把 `RandomDelays` 和 `CpuFreq` 推进 `traits`，从未构造 `Trait::PerfDegradation`。因此：

- `choose_chaos` 的 CDF 里 degradation 频率恒为 0，永远抽不到  
- `degradation_freq_frac32` 在 BPF 里是死变量，选择完全走 `trait_delay_freq_frac32`

**slice 公式可疑。** `((frac7 << 7) * slice) >> 7` 等价于 `frac7 * slice`。`frac7=64` 会把时间片放大 64 倍，而不是 README 说的 7-bit 分数（`64/128=0.5`）。更像漏写成 `(frac7 * slice) >> 7`。`frac7=0`（默认）还会把 slice 打成 0。

**Delay 与 p2dq 直接 dispatch 的缝。** 代码自己也写了：有亲和性时 p2dq 可能 direct dispatch，degradation 改 promise 不生效。延迟类用“跳过 `select_cpu`”规避，其它 trait 没有这层保护。

**Delay DSQ 的 CPU 编号。** `CHAOS_DSQ_BASE | smp_processor_id()` 假定 ID 连续；topology 不连续时 timer 扫 `0..nr_cpus` 会对错队列。

**Kprobe 最危险。** 挂在热路径（如 `schedule`）上等于在内核函数里给当前任务打“下次强制延迟”，再配合 tick 清 slice，很容易把延迟反馈进调度器自身。

**崩溃现场未实现。** 被测进程非 0 退出时只有一行 `TODO: report what the scheduler was doing when it crashed`。

---

## 8. 一句话归纳

`scx_chaos` = **p2dq 的调度骨架** + **按定点 CDF 抽取的 per-task trait** + **per-CPU vtime delay DSQ（定时 kick）** + **可选 kprobe 注入**。随机延迟和调频是完整闭环；性能降级在 BPF 里有半成品、用户态没接线；kprobe 是杀伤力最大、也最容易伤到调度器自己的路径。
