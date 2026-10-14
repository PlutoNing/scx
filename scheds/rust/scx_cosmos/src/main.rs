// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Andrea Righi <arighi@nvidia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;

mod stats;
use std::collections::{HashMap, HashSet};
use std::ffi::{c_int, c_ulong};
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::OpenObject;
use libbpf_rs::ProgramInput;
use log::{debug, info, warn};
use nvml_wrapper::bitmasks::InitFlags;
use nvml_wrapper::Nvml;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::get_primary_cpus;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::perf::parse_perf_event;
use scx_utils::perf::setup_perf_events;
use scx_utils::perf::PerfEventSpec;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::GpuIndex;
use scx_utils::Powermode;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
use stats::Metrics;

const SCHEDULER_NAME: &str = "scx_cosmos";

#[derive(Debug, clap::Parser)]
#[command(
    name = "scx_cosmos",
    version,
    disable_version_flag = true,
    about = "Lightweight scheduler optimized for preserving task-to-CPU locality."
)]
struct Opts {
    /// Exit debug dump buffer length. 0 indicates default.
    /// /* BPF 退出时调试信息转储缓冲区的长度，0 表示使用默认值。 */
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Maximum scheduling slice duration in microseconds.
    /// 任务最大调度时间片（微秒）。时间片越小响应性越好，但上下文切换开销越大。
    #[clap(short = 's', long, default_value = "1000")]
    slice_us: u64,

    /// Maximum runtime (since last sleep) that can be charged to a task in microseconds.
    /// 自上次睡眠以来，一个任务最多能被"计入"的运行时长（微秒），
    /// 用于限制长时间运行任务对公平性/延迟计算的影响。
    #[clap(short = 'l', long, default_value = "20000")]
    slice_lag_us: u64,

    /// CPU busy threshold.
    ///
    /// Specifies the CPU utilization percentage (0-100%) at which the scheduler considers the
    /// system to be busy.
    ///
    /// When the average CPU utilization reaches this threshold, the scheduler switches from using
    /// multiple per-CPU round-robin dispatch queues (which favor locality and reduced locking
    /// contention) to a global deadline-based dispatch queue (which improves load balancing).
    ///
    /// The global dispatch queue can increase task migrations and improve responsiveness for
    /// interactive tasks under heavy load. Lower values make the scheduler switch to deadline
    /// mode sooner, improving overall responsiveness at the cost of reducing single-task
    /// performance due to the additional migrations. Higher values makes task more "sticky" to
    /// their CPU, improving workloads that benefit from cache locality.
    ///
    /// A higher value is recommended for server-type workloads, while a lower value is recommended
    /// for interactive-type workloads.
    /// CPU 繁忙阈值（0-100%）。当平均 CPU 利用率达到此阈值时，调度器从"多个 per-CPU 轮询队列"
    /// （利于局部性、减少锁竞争）切换为"全局基于 deadline 的调度队列"
    /// （利于负载均衡，但增加迁移）。值越低越偏向交互式负载，越高越偏向服务器类吞吐负载。
    #[clap(short = 'c', long, default_value = "0")]
    cpu_busy_thresh: u64,

    /// Polling time (ms) to refresh the CPU utilization.
    ///
    /// This interval determines how often the scheduler refreshes the CPU utilization that is
    /// compared with the CPU busy threshold (option -c) to decide if the system is busy or not
    /// and trigger the switch between using multiple per-CPU dispatch queues or a single global
    /// deadline-based dispatch queue.
    ///
    /// Value is clamped to the range [10 .. 1000].
    ///
    /// 0 = disabled.
    /// 刷新 CPU 利用率的轮询周期（毫秒），用于驱动上面 cpu_busy_thresh 的判断。
    /// 会被 clamp 到 [10, 1000]，0 表示禁用该功能。
    #[clap(short = 'p', long, default_value = "0")]
    polling_ms: u64,

    /// Specifies a list of CPUs to prioritize.
    ///
    /// Accepts a comma-separated list of CPUs or ranges (i.e., 0-3,12-15) or the following special
    /// keywords:
    ///
    /// "turbo" = automatically detect and prioritize the CPUs with the highest max frequency,
    /// "performance" = automatically detect and prioritize the fastest CPUs,
    /// "powersave" = automatically detect and prioritize the slowest CPUs,
    /// "all" = all CPUs assigned to the primary domain.
    ///
    /// By default "all" CPUs are used.
    /// 指定优先使用的 CPU 列表。支持显式列表/区间（如 0-3,12-15），也支持关键字 turbo（最高频率）、
    /// performance（最快）、powersave（最慢）、all（默认，全部 CPU）。
    #[clap(short = 'm', long)]
    primary_domain: Option<String>,

    /// Hardware perf event to monitor (0x0 = disabled). Accepts hex (0xN) or symbolic names
    /// (e.g. cache-misses, LLC-load-misses, page-faults, branch-misses).
    /// 监控的硬件性能事件（如 cache-misses），以及事件速率阈值（每毫秒），超过该阈值的任务被视为
    /// "事件密集型"并触发迁移。perf_threshold=0 表示启用动态阈值算法（见下文 DynamicThresholdState）。
    #[clap(short = 'e', long, default_value = "0x0", value_parser = parse_perf_event)]
    perf_config: PerfEventSpec,

    /// Threshold (perf events/msec) to classify a task as event heavy; exceeding it triggers migration.
    #[clap(short = 'E', default_value = "0", long)]
    perf_threshold: u64,

    /// Sticky perf event (0x0 = disabled). When a task exceeds -Y for this event, keep it on the same CPU.
    /// Accepts hex (0xN) or symbolic names (e.g. cache-misses, LLC-load-misses).
    /// 另一组独立的"粘性"性能事件和阈值——当任务该事件计数超过阈值时，倾向于把它保持在同一 CPU 上（而非迁移）。
    #[clap(short = 'y', long, default_value = "0x0", value_parser = parse_perf_event)]
    perf_sticky: PerfEventSpec,

    /// Sticky perf threshold; task is kept on same CPU when its count for -y event exceeds this.
    #[clap(short = 'Y', default_value = "0", long)]
    perf_sticky_threshold: u64,

    /// Enable GPU-aware scheduling.
    /// 启用 GPU 感知调度（通过 NVML 同步 GPU 使用进程的 PID 到 NUMA 节点映射）
    #[clap(short = 'g', long, action = clap::ArgAction::SetTrue)]
    gpu: bool,

    /// Only treat a process as GPU-bound if its GPU utilization is at least this percentage (0–100).
    ///
    /// Uses NVML process utilization (SM + memory). 0 = no filter (all processes on the GPU are
    /// considered GPU-bound). Requires driver support (Maxwell or newer).
    /// 只有 GPU 利用率（SM 或显存，取较大值）达到该百分比的进程才被视为"GPU 绑定"，0 表示不过滤。
    #[clap(long, default_value = "0", value_parser = clap::value_parser!(u32).range(0..=100))]
    gpu_util_threshold: u32,

    /// Disable NUMA optimizations.
    /// 禁用 NUMA 优化 / CPU 调频控制。
    #[clap(short = 'n', long, action = clap::ArgAction::SetTrue)]
    disable_numa: bool,

    /// Disable CPU frequency control.
    #[clap(short = 'f', long, action = clap::ArgAction::SetTrue)]
    disable_cpufreq: bool,

    /// Enable flat idle CPU scanning.
    ///
    /// This option can help reducing some overhead when trying to allocate idle CPUs and it can be
    /// quite effective with simple CPU topologies.
    /// 启用"扁平化"空闲 CPU 扫描，拓扑简单时能降低扫描开销。
    #[arg(short = 'i', long, action = clap::ArgAction::SetTrue)]
    flat_idle_scan: bool,

    /// Enable preferred idle CPU scanning.
    ///
    /// With this option enabled, the scheduler will prioritize assigning tasks to higher-ranked
    /// cores before considering lower-ranked ones.
    /// 优先把任务分配到"排名更高"（容量更大）的核心上。
    #[clap(short = 'P', long, action = clap::ArgAction::SetTrue)]
    preferred_idle_scan: bool,

    /// Disable SMT.
    ///
    /// This option can only be used together with --flat-idle-scan or --preferred-idle-scan,
    /// otherwise it is ignored.
    /// 禁用 SMT（仅在配合 flat_idle_scan 或 preferred_idle_scan 时生效）。
    #[clap(long, action = clap::ArgAction::SetTrue)]
    disable_smt: bool,

    /// ***DEPRECATED*** SMT contention avoidance.
    #[clap(short = 'S', long, action = clap::ArgAction::SetTrue)]
    avoid_smt: bool,

    /// Disable early clearing of idle CPU state.
    ///
    /// When enabled, multiple concurrent wakeups can select the same idle CPU
    /// before it fully wakes up. This can improve performance in highly communicative
    /// workloads by aggressively stacking tasks on the same cache.
    /// 禁用"提前清除空闲 CPU 状态"，允许多个并发唤醒抢同一个空闲 CPU，利于强通信型负载的 cache 堆叠。
    #[clap(short = 'N', long, action = clap::ArgAction::SetTrue)]
    no_early_clear: bool,

    /// Disable direct dispatch during synchronous wakeups.
    ///
    /// Enabling this option can lead to a more uniform load distribution across available cores,
    /// potentially improving performance in certain scenarios. However, it may come at the cost of
    /// reduced efficiency for pipe-intensive workloads that benefit from tighter producer-consumer
    /// coupling.
    /// 禁用同步唤醒时的直接派发（direct dispatch），利于负载更均匀分布，但可能降低管道型负载的生产者-消费者耦合效率。
    #[clap(short = 'w', long, action = clap::ArgAction::SetTrue)]
    no_wake_sync: bool,

    /// ***DEPRECATED*** Disable deferred wakeups.
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    no_deferred_wakeup: bool,

    /// Enable high-resolution timer preemption.
    ///
    /// By default, the scheduler preempts tasks that exceed their time slice, measuring the time
    /// slice via the tick handler. Add an option to enforce preemption based on the high-precision
    /// timer and CPU occupancy. Enable this option to improve latency-sensitive workloads.
    /// 启用基于高精度定时器的抢占（而非仅靠 tick），改善延迟敏感型负载。
    #[clap(long, action = clap::ArgAction::SetTrue)]
    time_preemption: bool,

    /// Enable address space affinity.
    ///
    /// This option allows to keep tasks that share the same address space (e.g., threads of the
    /// same process) on the same CPU across wakeups.
    ///
    /// This can improve locality and performance in certain cache-sensitive workloads.
    /// 地址空间亲和性，让共享同一地址空间的线程倾向停留在同一 CPU，提升缓存局部性。
    #[clap(short = 'a', long, action = clap::ArgAction::SetTrue)]
    mm_affinity: bool,

    /// Enable stats monitoring with the specified interval.
    /// 以指定间隔启用统计监控（monitor 模式下不启动调度器本体，仅监控）。
    #[clap(long)]
    stats: Option<f64>,

    /// Run in stats monitoring mode with the specified interval. Scheduler
    /// is not launched.
    /// 以指定间隔启用统计监控（monitor 模式下不启动调度器本体，仅监控）。
    #[clap(long)]
    monitor: Option<f64>,

    /// Enable verbose output, including libbpf details.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Print scheduler version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,

    /// Show descriptions for statistics.
    #[clap(long)]
    help_stats: bool,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

pub fn parse_cpu_list(optarg: &str) -> Result<Vec<usize>, String> {
    let mut cpus = Vec::new();
    let mut seen = HashSet::new();

    // Handle special keywords
    /* 如果输入恰好是 powersave/performance/turbo/all 这四个关键字之一，
    直接调用 get_primary_cpus(mode)（基于硬件拓扑的频率/容量信息自动挑选
     CPU 集合）并返回，不走后续解析逻辑。 */
    if let Some(mode) = match optarg {
        "powersave" => Some(Powermode::Powersave),
        "performance" => Some(Powermode::Performance),
        "turbo" => Some(Powermode::Turbo),
        "all" => Some(Powermode::Any),
        _ => None,
    } {
        return get_primary_cpus(mode).map_err(|e| e.to_string());
    }

    // Validate input characters
    /* 对于非关键字输入，先检查字符串只能包含数字、-、,、空白字符，否则直接返回
     "Invalid character in CPU list" 错误。然后把空格替换为 tab（主要用于后续 trim）。 */
    if optarg
        .chars()
        .any(|c| !c.is_ascii_digit() && c != '-' && c != ',' && !c.is_whitespace())
    {
        return Err("Invalid character in CPU list".to_string());
    }

    // Replace all whitespace with tab (or just trim later)
    let cleaned = optarg.replace(' ', "\t");

    for token in cleaned.split(',') {
        let token = token.trim_matches(|c: char| c.is_whitespace());

        if token.is_empty() {
            continue;
        }

        if let Some((start_str, end_str)) = token.split_once('-') {
            let start = start_str
                .trim()
                .parse::<usize>()
                .map_err(|_| "Invalid range start")?;
            let end = end_str
                .trim()
                .parse::<usize>()
                .map_err(|_| "Invalid range end")?;

            if start > end {
                return Err(format!("Invalid CPU range: {}-{}", start, end));
            }

            for i in start..=end {
                if cpus.len() >= *NR_CPU_IDS {
                    return Err(format!("Too many CPUs specified (max {})", *NR_CPU_IDS));
                }
                if seen.insert(i) {
                    cpus.push(i);
                }
            }
        } else {
            let cpu = token
                .parse::<usize>()
                .map_err(|_| format!("Invalid CPU: {}", token))?;
            if cpus.len() >= *NR_CPU_IDS {
                return Err(format!("Too many CPUs specified (max {})", *NR_CPU_IDS));
            }
            if seen.insert(cpu) {
                cpus.push(cpu);
            }
        }
    }

    Ok(cpus)
}

/* 这组常量服务于基于 EMA（指数移动平均）+ 滞后区间（hysteresis）的自适应阈值调节算法，
用于当用户没有手动指定 perf_threshold/perf_sticky_threshold（即传 0）时，
由用户态程序动态调整 BPF 侧使用的阈值： */
/// Initial value for the dynamic threshold (in BPF units).
/// 阈值的初始值（BPF 单位）
const DYNAMIC_THRESHOLD_INIT_VALUE: u64 = 1000;

/// Minimum value for the dynamic threshold (in BPF units).
/// 阈值下限，避免被压到 0 或负数
const DYNAMIC_THRESHOLD_MIN_VALUE: u64 = 10;

/// Target event rate (per second) above which we consider migrations/sticky dispatches too high.
/// 事件速率（次/秒）上限：超过此值认为"迁移/粘性派发过多"，需要提高阈值使其更难触发
const DYNAMIC_THRESHOLD_RATE_HIGH: f64 = 4000.0;

/// Target event rate (per second) below which we consider migrations/sticky dispatches too low.
/// 事件速率下限：低于此值认为触发太少，需要降低阈值使其更容易触发
const DYNAMIC_THRESHOLD_RATE_LOW: f64 = 2000.0;

/// Hysteresis band: rate must move by this fraction beyond the target bounds before we act.
/// This prevents oscillation when the rate hovers near the threshold boundaries.
/// 滞后带宽度（10%），防止速率在边界附近抖动导致阈值反复调整(振荡)
const DYNAMIC_THRESHOLD_HYSTERESIS: f64 = 0.1;

/// EMA smoothing factor (alpha). Higher values give more weight to recent samples.
/// 0.3 provides good balance between responsiveness and stability.
/// EMA 平滑系数，新采样权重 30%，历史权重 70%
const DYNAMIC_THRESHOLD_EMA_ALPHA: f64 = 0.3;

/// Minimum scale factor when just outside the target band (slow convergence near optimal).
/// 刚越过目标区间边界时的最小调整步幅（缓慢收敛）
const DYNAMIC_THRESHOLD_SCALE_MIN: f64 = 0.0001;

/// Maximum scale factor when far from target (fast convergence when initial threshold is way off).
/// 远离目标区间时的最大调整步幅（快速收敛）
const DYNAMIC_THRESHOLD_SCALE_MAX: f64 = 1000.0;

/// Slope for "too high" case: scale grows with (rate/HIGH - 1) so we step much harder when rate is
/// many times over target.
/// "速率过高"情形下，调整幅度随超出比例增长的斜率
const DYNAMIC_THRESHOLD_SLOPE_HIGH: f64 = 0.35;

/// Slope for "too low" case: scale grows with deficit so we step harder when rate is near zero.
/// "速率过低"情形下，调整幅度随不足程度增长的斜率（更激进，因为要快速逼近 0 附近时的极端情况）
const DYNAMIC_THRESHOLD_SLOPE_LOW: f64 = 0.58;

/// Minimum interval between NVML GPU PID syncs. Kept separate from CPU polling so that fast
/// polling (e.g. 100 ms) does not trigger expensive NVML calls every tick.
/// NVML GPU PID 同步的最小间隔，避免轮询周期很短（如 100ms）时每个 tick 都触发昂贵的 NVML 调用
const GPU_SYNC_INTERVAL: Duration = Duration::from_secs(1);

/// State for EMA-based dynamic threshold adjustment with hysteresis.
///
/// This struct maintains the smoothed rate estimate and tracks whether we're
/// currently in an adjustment state (raising or lowering threshold) to implement
/// hysteresis and prevent oscillation.
#[derive(Debug, Clone)]
struct DynamicThresholdState {
    /// Current threshold value.
    /// 当前实际生效的阈值（即将写回 BPF bss 的 perf_threshold / perf_sticky_threshold）。
    threshold: u64,
    /// EMA-smoothed rate estimate.
    /// 事件速率的 EMA 平滑值，用于过滤瞬时抖动。
    smoothed_rate: f64,
    /// Previous raw counter value for delta calculation.
    /// BPF 侧累计计数器（如 nr_event_dispatches）的上一次采样值，用来算 delta。
    prev_counter: u64,
    /// Whether the EMA has been initialized with a valid sample.
    /// 标记 EMA 是否已经有过第一次采样（首次采样时直接赋值而非做加权平均）。
    initialized: bool,
    /// Current adjustment direction: None (stable), Some(true) = raising, Some(false) = lowering.
    /// Used for hysteresis: once we start adjusting in a direction, we continue until
    /// the rate crosses back into the stable band with hysteresis margin.
    /// 当前调整方向的状态机标志：None=稳定、Some(true)=正在升高阈值、Some(false)=正在降低阈值。这是
    /// 实现滞后（hysteresis）的关键——一旦进入某个调整方向，必须等速率"反向越过"更宽的边界才会停止调整，
    /// 防止来回震荡。
    adjustment_direction: Option<bool>,
}

impl DynamicThresholdState {
    /// Create a new dynamic threshold state with the given initial threshold.
    fn new(initial_threshold: u64) -> Self {
        Self {
            threshold: initial_threshold,
            smoothed_rate: 0.0,
            prev_counter: 0,
            initialized: false,
            adjustment_direction: None,
        }
    }

    /// Update the state with a new counter sample and elapsed time.
    /// Returns the new threshold if it changed, or None if unchanged.
    fn update(
        &mut self,
        counter: u64,
        elapsed_secs: f64,
        verbose: bool,
        name: &str,
    ) -> Option<u64> {
        if elapsed_secs <= 0.0 {
            return None;
        }

        // Calculate instantaneous rate.
        
        /* 根据 elapsed_secs 内计数器增量算出瞬时速率 raw_rate。 */
        let delta = counter.saturating_sub(self.prev_counter);
        self.prev_counter = counter;
        let raw_rate = delta as f64 / elapsed_secs;

        // Update EMA.
        /* 用 EMA 公式平滑速率：smoothed = α·raw + (1-α)·smoothed_prev（首次采样直接赋值）。 */
        if self.initialized {
            self.smoothed_rate = DYNAMIC_THRESHOLD_EMA_ALPHA * raw_rate
                + (1.0 - DYNAMIC_THRESHOLD_EMA_ALPHA) * self.smoothed_rate;
        } else {
            // First sample: initialize EMA directly.
            self.smoothed_rate = raw_rate;
            self.initialized = true;
        }

        // Determine if we should adjust the threshold using hysteresis.
        let rate = self.smoothed_rate;
        let old_threshold = self.threshold;

        // Calculate hysteresis-adjusted bounds based on current state.
        /* 根据当前 adjustment_direction 状态选择不同的"有效边界"（effective_high/effective_low） */
        let (effective_high, effective_low) = match self.adjustment_direction {
            Some(true) => {
                /* 若正在升高：维持升高直到速率跌破 LOW×(1-滞后)。 */
                // Currently raising threshold: need rate to drop below LOW - hysteresis to stop.
                (
                    DYNAMIC_THRESHOLD_RATE_HIGH,
                    DYNAMIC_THRESHOLD_RATE_LOW * (1.0 - DYNAMIC_THRESHOLD_HYSTERESIS),
                )
            }
            Some(false) => {
                /* 若正在降低：维持降低直到速率升破 HIGH×(1+滞后)。 */
                // Currently lowering threshold: need rate to rise above HIGH + hysteresis to stop.
                (
                    DYNAMIC_THRESHOLD_RATE_HIGH * (1.0 + DYNAMIC_THRESHOLD_HYSTERESIS),
                    DYNAMIC_THRESHOLD_RATE_LOW,
                )
            }
            None => {
                /* 若稳定：只有速率越过 HIGH×(1+滞后) 或跌破 LOW×(1-滞后) 才开始调整。 */
                // Stable state: need rate to exceed bounds + hysteresis to start adjusting.
                (
                    DYNAMIC_THRESHOLD_RATE_HIGH * (1.0 + DYNAMIC_THRESHOLD_HYSTERESIS),
                    DYNAMIC_THRESHOLD_RATE_LOW * (1.0 - DYNAMIC_THRESHOLD_HYSTERESIS),
                )
            }
        };

        // Determine new adjustment direction.
        /* 据此决定新方向 new_direction， */
        let new_direction = if rate > effective_high {
            Some(true) // Rate too high, raise threshold.
        } else if rate < effective_low && rate >= 0.0 {
            Some(false) // Rate too low, lower threshold.
        } else {
            // Rate in stable band (considering hysteresis).
            if self.adjustment_direction.is_some() {
                // We were adjusting; check if we should stop.
                if rate >= DYNAMIC_THRESHOLD_RATE_LOW && rate <= DYNAMIC_THRESHOLD_RATE_HIGH {
                    None // Back in target band, stop adjusting.
                } else {
                    self.adjustment_direction // Continue current direction.
                }
            } else {
                None // Already stable.
            }
        };

        // Apply adjustment if we have a direction.
        /* 若有方向则调用 compute_scale 计算调整幅度 scale，
        按 factor = 1±scale 对阈值做乘法调整，并 clamp 到 [MIN_VALUE, u64::MAX]。 */
        if let Some(raising) = new_direction {
            let scale = Self::compute_scale(rate, raising);
            let factor = if raising { 1.0 + scale } else { 1.0 - scale };
            let new_threshold = ((self.threshold as f64) * factor).round() as u64;
            self.threshold = new_threshold.clamp(DYNAMIC_THRESHOLD_MIN_VALUE, u64::MAX);
        }

        self.adjustment_direction = new_direction;

        // Return new threshold only if it changed.
        /* 若阈值发生变化，verbose 模式下打印日志，并返回 Some(新阈值)；
        否则返回 None（调用方据此判断要不要写回 BPF map）。 */
        if self.threshold != old_threshold {
            if verbose {
                info!(
                    "{}: {} -> {} (smoothed rate {:.1}/s, raw {:.1}/s, dir {:?})",
                    name,
                    old_threshold,
                    self.threshold,
                    self.smoothed_rate,
                    raw_rate,
                    self.adjustment_direction
                );
            }
            Some(self.threshold)
        } else {
            None
        }
    }

    /// Compute the scale factor for threshold adjustment based on how far the rate
    /// is from the target band.
    /// 这是一个带滞后区间的自适应 PID 式控制器，让 BPF 侧的"事件密集/粘性"派发阈值自动收敛到让触发速率落在
    ///  [2000, 4000] 次/秒区间内，既不会频繁触发也不会几乎不触发。
    fn compute_scale(rate: f64, too_high: bool) -> f64 {
        if too_high {
            /* 速率过高：excess = rate/HIGH - 1（越超标调整越猛，上限封顶 4 倍），
            scale = MIN + SLOPE_HIGH × min(excess, 4)。 */
            let excess = ((rate / DYNAMIC_THRESHOLD_RATE_HIGH) - 1.0).max(0.0);
            let scale =
                DYNAMIC_THRESHOLD_SCALE_MIN + DYNAMIC_THRESHOLD_SLOPE_HIGH * excess.min(4.0);
            scale.min(DYNAMIC_THRESHOLD_SCALE_MAX)
        } else {
            /* 速率过低：若速率 ≤ 0，直接用最大步幅 SCALE_MAX（极端情况快速拉低阈值）；
            否则 deficit = (LOW - rate)/LOW，scale = MIN + SLOPE_LOW × deficit。 */
            if rate <= 0.0 {
                return DYNAMIC_THRESHOLD_SCALE_MAX;
            }
            let deficit = (DYNAMIC_THRESHOLD_RATE_LOW - rate) / DYNAMIC_THRESHOLD_RATE_LOW;
            let t = deficit.clamp(0.0, 1.0);
            DYNAMIC_THRESHOLD_SCALE_MIN + DYNAMIC_THRESHOLD_SLOPE_LOW * t
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CpuTimes {
    user: u64,
    nice: u64,
    total: u64,
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    opts: &'a Opts,
    struct_ops: Option<libbpf_rs::Link>,
    /* 统计信息的 RPC 服务端，用于响应 scx_cosmos --stats / --monitor 等外部查询。 */
    stats_server: StatsServer<(), Metrics>,
    /// GPU device index -> NUMA node (for NVML PID sync). Only set when --gpu and NUMA enabled.
    /// GPU 索引（NVML id）→ NUMA 节点号的映射，仅在 --gpu 且 NUMA 启用时为 Some。
    gpu_index_to_node: Option<HashMap<u32, u32>>,
    /// Previous (pid, node) set so we can remove PIDs that stopped using the GPU.
    /// 上一轮同步时的 PID→节点 映射，用于计算哪些 PID 不再使用 GPU 需要从 BPF map 中删除。
    previous_gpu_pids: Option<HashMap<u32, u32>>,
    /// Reused NVML handle to avoid re-initializing on every sync (expensive).
    /// 复用的 NVML 句柄，避免每次同步都重新初始化（代价很高）
    nvml: Option<Nvml>,
    /// Dynamic threshold state for perf event migrations (when --perf-threshold is 0/dynamic).
    /// 对应上一节的动态阈值状态机，仅在用户未显式指定静态阈值（即传 0）时为 Some。
    perf_threshold_state: Option<DynamicThresholdState>,
    /// Dynamic threshold state for sticky perf events (when --perf-sticky-threshold is 0/dynamic).
    perf_sticky_threshold_state: Option<DynamicThresholdState>,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &'a Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        /* 解除 RLIMIT_MEMLOCK 限制，为加载 BPF 程序/map 做准备。 */
        try_set_rlimit_infinity();

        // Initialize CPU topology.
        /* 构建 Topology，判断 SMT 是否启用（smt_enabled，取决于硬件支持且用户未 --disable-smt） */
        let topo = Topology::new().unwrap();

        // Check host topology to determine if we need to enable SMT capabilities.
        let smt_enabled = !opts.disable_smt && topo.smt_enabled;

        // Determine the amount of non-empty NUMA nodes in the system.
        /* 统计非空 NUMA 节点数 nr_nodes，决定 numa_enabled（非 NUMA 系统或 --disable-numa 时自动关闭）。 */
        let nr_nodes = topo
            .nodes
            .values()
            .filter(|node| !node.all_cpus.is_empty())
            .count();
        info!("NUMA nodes: {}", nr_nodes);

        // Automatically disable NUMA optimizations when running on non-NUMA systems.
        let numa_enabled = !opts.disable_numa && nr_nodes > 1;
        if !numa_enabled {
            info!("Disabling NUMA optimizations");
        }

        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if smt_enabled { "SMT on" } else { "SMT off" }
        );

        // Print command line.
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        // Initialize BPF connector.
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, cosmos_ops, open_opts)?;

        skel.struct_ops.cosmos_ops_mut().exit_dump_len = opts.exit_dump_len;

        // Override default BPF scheduling parameters.
        /* 把命令行参数写入 BPF 的 rodata（只读数据段，加载前生效）：时间片、slice_lag、cpufreq 开关、
        flat_idle_scan、smt/numa 开关、node 数、各类禁用标志、perf 事件 ID 等。 */
        let rodata = skel.maps.rodata_data.as_mut().unwrap();
        rodata.slice_ns = opts.slice_us * 1000;
        rodata.slice_lag = opts.slice_lag_us * 1000;
        rodata.cpufreq_enabled = !opts.disable_cpufreq;
        rodata.flat_idle_scan = opts.flat_idle_scan;
        rodata.smt_enabled = smt_enabled;
        rodata.numa_enabled = numa_enabled;
        rodata.nr_node_ids = topo.nodes.len() as u32;
        rodata.no_wake_sync = opts.no_wake_sync;
        rodata.no_early_clear = opts.no_early_clear;
        rodata.time_preemption = opts.time_preemption;
        rodata.mm_affinity = opts.mm_affinity;

        // Enable perf event scheduling settings.
        rodata.perf_config = opts.perf_config.event_id;
        rodata.perf_sticky = opts.perf_sticky.event_id;

        // Normalize CPU busy threshold in the range [0 .. 1024].
        /* 归一化 CPU 繁忙阈值：busy_threshold = cpu_busy_thresh * 1024 / 100，
        把百分比换算成 BPF 侧用的 [0,1024] 定点数。 */
        rodata.busy_threshold = opts.cpu_busy_thresh * 1024 / 100;

        // Generate the list of available CPUs sorted by capacity in descending order.
        /* 按 CPU 容量排序并归一化：把所有 CPU 按 cpu_capacity 降序排列，归一化到 [1, 1024]
        （最大容量恒为 1024），写入 rodata.cpu_capacity[] 和按容量排序的 rodata.preferred_cpus[]
        （供 preferred_idle_scan 使用）。
        */
        let mut cpus: Vec<_> = topo.all_cpus.values().collect();
        cpus.sort_by_key(|cpu| std::cmp::Reverse(cpu.cpu_capacity));
        // Normalize CPU capacities to 1..1024 so the highest capacity is always 1024.
        let max_cap = cpus.first().map(|c| c.cpu_capacity).unwrap_or(1).max(1);
        for (i, cpu) in cpus.iter().enumerate() {
            let normalized = (cpu.cpu_capacity * 1024 / max_cap).clamp(1, 1024);
            rodata.cpu_capacity[cpu.id] = normalized as c_ulong;
            rodata.preferred_cpus[i] = cpu.id as u64;
        }
        /* 同时记录 all_cpus_same_capacity 标志（同构系统可以走更快路径）。  */
        rodata.all_cpus_same_capacity = cpus.iter().all(|cpu| cpu.cpu_capacity == max_cap);
        if opts.preferred_idle_scan {
            info!(
                "Preferred CPUs: {:?}",
                &rodata.preferred_cpus[0..cpus.len()]
            );
        }
        rodata.preferred_idle_scan = opts.preferred_idle_scan;

        // Define the primary scheduling domain.
        /* 解析 primary_domain（调用前面讲的 parse_cpu_list），得到主调度域 CPU 列表；
        若覆盖全部 CPU 则 primary_all = true。 */
        let primary_cpus = if let Some(ref domain) = opts.primary_domain {
            match parse_cpu_list(domain) {
                Ok(cpus) => cpus,
                Err(e) => bail!("Error parsing primary domain: {}", e),
            }
        } else {
            (0..*NR_CPU_IDS).collect()
        };
        if primary_cpus.len() < *NR_CPU_IDS {
            info!("Primary CPUs: {:?}", primary_cpus);
            rodata.primary_all = false;
        } else {
            rodata.primary_all = true;
        }

        // Enable GPU support and build GPU index -> node for NVML PID sync. Init NVML once here
        // so we reuse the handle in the run loop (re-initing every sync is very expensive).
        /* 初始化 GPU 支持：若 --gpu 且 NUMA 启用，尝试 Nvml::init_with_flags；成功则构建 gpu_index_to_node
        （遍历 topo.gpus()），
        previous_gpu_pids 置空 map；失败则告警并禁用 GPU 调度。 */
        let (gpu_index_to_node, previous_gpu_pids, nvml) = if opts.gpu && numa_enabled {
            match Nvml::init_with_flags(InitFlags::NO_GPUS) {
                Ok(nvml) => {
                    info!("NVIDIA GPU-aware scheduling enabled (NVML PID sync)");
                    rodata.gpu_enabled = true;
                    let mut idx_to_node = HashMap::new();
                    /*  */
                    for (id, gpu) in topo.gpus() {
                        /*  */
                        let GpuIndex::Nvidia { nvml_id } = id;
                        idx_to_node.insert(nvml_id, gpu.node_id as u32);
                    }
                    (Some(idx_to_node), Some(HashMap::new()), Some(nvml))
                }
                Err(e) => {
                    warn!("NVML init failed, disabling GPU-aware scheduling: {}", e);
                    rodata.gpu_enabled = false;
                    (None, None, None)
                }
            }
        } else {
            rodata.gpu_enabled = false;
            (None, None, None)
        };

        // Set scheduler flags.
        skel.struct_ops.cosmos_ops_mut().flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP
            | if numa_enabled {
                *compat::SCX_OPS_BUILTIN_IDLE_PER_NODE
            } else {
                0
            };

        info!(
            "scheduler flags: {:#x}",
            skel.struct_ops.cosmos_ops_mut().flags
        );

        // Load the BPF program for validation.
        let mut skel = scx_ops_load!(skel, cosmos_ops, uei)?;

        // Initial perf thresholds in bss. When threshold is 0 we use dynamic logic; when user
        // specifies a value > 0 we use it as a static threshold.
        let bss = skel.maps.bss_data.as_mut().unwrap();
        if opts.perf_config.event_id > 0 {
            bss.perf_threshold = if opts.perf_threshold == 0 {
                DYNAMIC_THRESHOLD_INIT_VALUE
            } else {
                opts.perf_threshold
            };
        }
        if opts.perf_sticky.event_id > 0 {
            bss.perf_sticky_threshold = if opts.perf_sticky_threshold == 0 {
                DYNAMIC_THRESHOLD_INIT_VALUE
            } else {
                opts.perf_sticky_threshold
            };
        }

        // Configure CPU->node mapping (must be done after skeleton is loaded).
        for node in topo.nodes.values() {
            for cpu in node.all_cpus.values() {
                if opts.verbose {
                    info!("CPU{} -> node{}", cpu.id, node.id);
                }
                skel.maps.cpu_node_map.update(
                    &(cpu.id as u32).to_ne_bytes(),
                    &(node.id as u32).to_ne_bytes(),
                    MapFlags::ANY,
                )?;
            }
        }

        // Setup performance events for all CPUs.
        // Counter indices must match PMU library install order: migration first (0), then sticky (1).
        // When only sticky is used, it gets index 0; when both are used, sticky gets index 1.
        let nr_cpus = *NR_CPU_IDS;
        info!("Setting up performance counters for {} CPUs...", nr_cpus);
        let mut perf_available = true;
        let sticky_counter_idx = if opts.perf_config.event_id > 0 { 1 } else { 0 };
        for cpu in 0..nr_cpus {
            if opts.perf_config.event_id > 0 {
                if let Err(e) =
                    setup_perf_events(&skel.maps.scx_pmu_map, cpu as i32, &opts.perf_config, 0)
                {
                    if cpu == 0 {
                        let err_str = e.to_string();
                        if err_str.contains("errno 2") || err_str.contains("os error 2") {
                            warn!("Performance counters not available on this CPU architecture");
                            warn!("PMU event '{}' not supported - scheduler will run without perf monitoring", opts.perf_config.display_name);
                        } else {
                            warn!("Failed to setup perf events: {}", e);
                        }
                        perf_available = false;
                        break;
                    }
                }
            }
            if opts.perf_sticky.event_id > 0 {
                if let Err(e) = setup_perf_events(
                    &skel.maps.scx_pmu_map,
                    cpu as i32,
                    &opts.perf_sticky,
                    sticky_counter_idx,
                ) {
                    if cpu == 0 {
                        let err_str = e.to_string();
                        if err_str.contains("errno 2") || err_str.contains("os error 2") {
                            warn!("Performance counters not available on this CPU architecture");
                            warn!("PMU event '{}' not supported - scheduler will run without perf monitoring", opts.perf_sticky.display_name);
                        } else {
                            warn!("Failed to setup perf events: {}", e);
                        }
                        perf_available = false;
                        break;
                    }
                }
            }
        }
        if perf_available {
            info!("Performance counters configured successfully for all CPUs");
        }

        // Configure GPU->node mapping.
        if opts.gpu && numa_enabled {
            for (id, gpu) in topo.gpus() {
                let GpuIndex::Nvidia { nvml_id } = id;
                if opts.verbose {
                    info!("GPU{} -> node{}", nvml_id, gpu.node_id);
                }
                skel.maps.gpu_node_map.update(
                    &(nvml_id as u32).to_ne_bytes(),
                    &(gpu.node_id as u32).to_ne_bytes(),
                    MapFlags::ANY,
                )?;
            }
        }

        // Enable primary scheduling domain, if defined.
        if primary_cpus.len() < *NR_CPU_IDS {
            for cpu in primary_cpus {
                if let Err(err) = Self::enable_primary_cpu(&mut skel, cpu as i32) {
                    bail!("failed to add CPU {} to primary domain: error {}", cpu, err);
                }
            }
        }

        // Initialize SMT domains.
        if smt_enabled {
            Self::init_smt_domains(&mut skel, &topo)?;
        }

        // Attach the scheduler.
        let struct_ops = Some(scx_ops_attach!(skel, cosmos_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;

        // Initialize dynamic threshold states for perf events (only when using dynamic mode).
        let perf_threshold_state = if opts.perf_config.event_id > 0 && opts.perf_threshold == 0 {
            Some(DynamicThresholdState::new(DYNAMIC_THRESHOLD_INIT_VALUE))
        } else {
            None
        };
        let perf_sticky_threshold_state =
            if opts.perf_sticky.event_id > 0 && opts.perf_sticky_threshold == 0 {
                Some(DynamicThresholdState::new(DYNAMIC_THRESHOLD_INIT_VALUE))
            } else {
                None
            };

        Ok(Self {
            skel,
            opts,
            struct_ops,
            stats_server,
            gpu_index_to_node,
            previous_gpu_pids,
            nvml,
            perf_threshold_state,
            perf_sticky_threshold_state,
        })
    }

    /* 这部分代码负责用户态的持续维护：把 GPU、CPU 的状态同步给 BPF，
    响应统计请求，并管理调度器的退出和重启。 
    真正选择 CPU、入队、派发任务的逻辑在 BPF 文件中。 */
    /// Sync PID -> GPU (node) map from NVML. When gpu_util_threshold > 0, only PIDs with
    /// GPU utilization (SM or memory) >= threshold are added. Map is keyed by task pid.
    /// Only processes using a single GPU are added; multi-GPU processes are excluded.
    
    /* 更新“线程 ID → GPU 所在 NUMA 节点”的映射
    让 BPF 知道哪些线程属于 GPU 相关进程，以及它们应该优先靠近哪个 NUMA 节点运行。 */
    fn sync_gpu_pids(&mut self) -> Result<()> {
        /* 检查 GPU 支持是否已初始化。 */
        let gpu_index_to_node = match &self.gpu_index_to_node {
            Some(m) => m,
            None => return Ok(()),
        };
        let nvml = match &self.nvml {
            Some(n) => n,
            None => return Ok(()),
        };
        let threshold = self.opts.gpu_util_threshold;
        let previous = self.previous_gpu_pids.as_ref().unwrap();
        // First collect pid -> set of nodes (GPUs) per process.
        let mut pid_to_nodes: HashMap<u32, HashSet<u32>> = HashMap::new();

        let count = nvml.device_count().context("NVML device count")?;
        /* 遍历 GPU，收集进程及其对应的节点。 */
        for i in 0..count {
            let node = match gpu_index_to_node.get(&i) {
                Some(&n) => n,
                None => continue,
            };
            let device = nvml.device_by_index(i).context("NVML device_by_index")?;

            /* 进程 100 → {节点 0}
进程 200 → {节点 0, 节点 1} */
            if threshold > 0 {
                /* 根据 GPU 利用率阈值决定收集哪些进程。 */
                // Use process utilization; only add PIDs above threshold.
                match device.process_utilization_stats(None::<u64>) {
                    /* 取 SM 利用率和内存利用率中的较大值，达到阈值才记录该进程。这里的 mem_util
                     是利用率指标，不是进程占用了多少显存容量。
如果查询利用率失败，就退回到收集所有正在使用该 GPU 的计算、图形进程。也就是说，查询失败时，
本轮不会继续执行利用率过滤。
当阈值为 0 时，也直接收集所有相关进程。 */
                    Ok(samples) => {
                        for sample in samples {
                            let util = sample.sm_util.max(sample.mem_util);
                            if util >= threshold {
                                pid_to_nodes.entry(sample.pid).or_default().insert(node);
                            }
                        }
                    }
                    Err(_) => {
                        // NotSupported or other: fall back to all running processes.
                        Self::add_running_gpu_processes_to_set(&device, node, &mut pid_to_nodes);
                    }
                }
            } else {
                Self::add_running_gpu_processes_to_set(&device, node, &mut pid_to_nodes);
            }
        }

        /* 只保留节点集合大小为 1 的进程，并展开其线程。 */
        // Only add PIDs that use exactly one GPU to the map.
        let mut current: HashMap<u32, u32> = HashMap::new();
        /* Linux 中，一个进程包含多个可被独立调度的线程。NVML 提供的是
        进程 ID，而 BPF 这里按线程 ID 查询，因此还需要把进程下的所有线程加入映射。 */
        /* NVML 发现进程 100 使用节点 0 上的 GPU
                  ↓
/proc/100/task 中找到线程 100、101、102
                  ↓
current = {100→0, 101→0, 102→0} */
        for (tgid, nodes) in pid_to_nodes {
            if nodes.len() == 1 {
                let node = nodes.into_iter().next().unwrap();
                current.insert(tgid, node);
                for tid in Self::task_tids(tgid) {
                    current.insert(tid, node);
                }
            }
        }

        /* 把本轮结果同步到 BPF map。 */
        let map = &self.skel.maps.gpu_pid_map;
        for (pid, node) in &current {
            map.update(&pid.to_ne_bytes(), &node.to_ne_bytes(), MapFlags::ANY)
                .context("gpu_pid_map update")?;
        }
        for pid in previous.keys() {
            if !current.contains_key(pid) {
                let _ = map.delete(&pid.to_ne_bytes());
            }
        }
        *self.previous_gpu_pids.as_mut().unwrap() = current;
        Ok(())
    }

    /// Record running compute/graphics process PIDs and the GPU node in pid_to_nodes.
    /// /* 收集使用某张 GPU 的进程 */
    fn add_running_gpu_processes_to_set(
        device: &nvml_wrapper::Device<'_>,
        node: u32,
        pid_to_nodes: &mut HashMap<u32, HashSet<u32>>,
    ) {
        /* 分别获取：
- 计算进程列表；
- 图形进程列表。
chain() 把两个列表串起来遍历，然后执行：pid_to_nodes.
entry(proc.pid).or_default().insert(node); */
        for proc in device
            .running_compute_processes()
            .unwrap_or_default()
            .into_iter()
            .chain(device.running_graphics_processes().unwrap_or_default())
        {
            /* 如果该 PID 还没有记录，先创建一个空节点集合；
再把当前 GPU 所在的节点加入集合。 */
            pid_to_nodes.entry(proc.pid).or_default().insert(node);
        }
    }

    /// Return all thread IDs (tids) of the process with the given pid (tgid).
    /// 列出一个进程的所有线程 ID
    fn task_tids(pid: u32) -> Vec<u32> {
        let task_dir = format!("/proc/{}/task", pid);
        let Ok(entries) = fs::read_dir(Path::new(&task_dir)) else {
            return Vec::new();
        };
        entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
            .collect()
    }

    /* 把一个 CPU 加入 BPF 的主调度域 */
    fn enable_primary_cpu(skel: &mut BpfSkel<'_>, cpu: i32) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_primary_cpu;
        let mut args = cpu_arg {
            cpu_id: cpu as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn enable_sibling_cpu(
        skel: &mut BpfSkel<'_>,
        cpu: usize,
        sibling_cpu: usize,
    ) -> Result<(), u32> {
        let prog = &mut skel.progs.enable_sibling_cpu;
        let mut args = domain_arg {
            cpu_id: cpu as c_int,
            sibling_cpu_id: sibling_cpu as c_int,
        };
        let input = ProgramInput {
            context_in: Some(unsafe {
                std::slice::from_raw_parts_mut(
                    &mut args as *mut _ as *mut u8,
                    std::mem::size_of_val(&args),
                )
            }),
            ..Default::default()
        };
        let out = prog.test_run(input).unwrap();
        if out.return_value != 0 {
            return Err(out.return_value);
        }

        Ok(())
    }

    fn init_smt_domains(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<(), std::io::Error> {
        let smt_siblings = topo.sibling_cpus();

        info!("SMT sibling CPUs: {:?}", smt_siblings);
        for (cpu, sibling_cpu) in smt_siblings.iter().enumerate() {
            Self::enable_sibling_cpu(skel, cpu, *sibling_cpu as usize).unwrap();
        }

        Ok(())
    }

    fn get_metrics(&self) -> Metrics {
        let bss_data = self.skel.maps.bss_data.as_ref().unwrap();
        Metrics {
            nr_event_dispatches: bss_data.nr_event_dispatches,
            nr_ev_sticky_dispatches: bss_data.nr_ev_sticky_dispatches,
            nr_gpu_dispatches: bss_data.nr_gpu_dispatches,
        }
    }

    pub fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn compute_user_cpu_pct(prev: &CpuTimes, curr: &CpuTimes) -> Option<u64> {
        // Evaluate total user CPU time as user + nice.
        let user_diff = (curr.user + curr.nice).saturating_sub(prev.user + prev.nice);
        let total_diff = curr.total.saturating_sub(prev.total);

        if total_diff > 0 {
            let user_ratio = user_diff as f64 / total_diff as f64;
            Some((user_ratio * 1024.0).round() as u64)
        } else {
            None
        }
    }

    /// Parse per-CPU times from /proc/stat (lines "cpu0", "cpu1", ...).
    /// Returns entries indexed by CPU id. Offline CPUs may be absent.
    fn parse_per_cpu_cpu_times<R: BufRead>(
        reader: R,
        nr_cpus: usize,
    ) -> Option<Vec<Option<CpuTimes>>> {
        let mut result = vec![None; nr_cpus];

        for line in reader.lines() {
            let line = line.ok()?;
            let line = line.trim();
            if !line.starts_with("cpu") {
                continue;
            }
            let rest = line.strip_prefix("cpu")?;
            if rest.starts_with(' ') {
                // Aggregate line "cpu " - skip.
                continue;
            }
            let cpu_id: usize = rest.split_whitespace().next()?.parse().ok()?;
            if cpu_id >= nr_cpus {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                return None;
            }
            let user: u64 = fields[1].parse().ok()?;
            let nice: u64 = fields[2].parse().ok()?;
            let total: u64 = fields
                .iter()
                .skip(1)
                .take(8)
                .filter_map(|v| v.parse::<u64>().ok())
                .sum();
            result[cpu_id] = Some(CpuTimes { user, nice, total });
        }

        result.iter().any(Option::is_some).then_some(result)
    }

    /// Read per-CPU times from /proc/stat.
    fn read_per_cpu_cpu_times(nr_cpus: usize) -> Option<Vec<Option<CpuTimes>>> {
        let file = File::open("/proc/stat").ok()?;
        Self::parse_per_cpu_cpu_times(BufReader::new(file), nr_cpus)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();

        // Periodically evaluate per-CPU user utilization from userspace and update the
        // cpu_util_map in BPF. The scheduler uses is_cpu_busy(cpu) with prev_cpu or
        // scx_bpf_task_cpu(p) to decide per-CPU whether to use local DSQs (round-robin)
        // or deadline-based shared DSQ.
        let polling_time = Duration::from_millis(self.opts.polling_ms).min(Duration::from_secs(1));
        let nr_cpus = *NR_CPU_IDS as usize;
        let mut prev_cputime = Self::read_per_cpu_cpu_times(nr_cpus).unwrap_or_else(|| {
            warn!("Failed to read initial per-CPU stats; starting with zero CPU utilization");
            vec![None; nr_cpus]
        });
        let mut last_update = Instant::now();
        let mut last_gpu_sync = Instant::now();

        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            // Update per-CPU utilization and GPU PID -> node map (NVML).
            if !polling_time.is_zero() && last_update.elapsed() >= polling_time {
                if let Some(curr_cputime) = Self::read_per_cpu_cpu_times(nr_cpus) {
                    let map = &self.skel.maps.cpu_util_map;
                    for cpu in 0..nr_cpus {
                        let util = match (&prev_cputime[cpu], &curr_cputime[cpu]) {
                            (Some(prev), Some(curr)) => Self::compute_user_cpu_pct(prev, curr),
                            _ => Some(0),
                        };

                        if let Some(util) = util {
                            let _ = map.update(
                                &(cpu as u32).to_ne_bytes(),
                                &util.to_ne_bytes(),
                                MapFlags::ANY,
                            );
                        }
                    }
                    prev_cputime = curr_cputime;
                }

                // Update dynamic perf thresholds using EMA + hysteresis.
                let elapsed_secs = last_update.elapsed().as_secs_f64();

                // Update migration threshold state if dynamic mode is enabled.
                if let Some(ref mut state) = self.perf_threshold_state {
                    let nr_event = self
                        .skel
                        .maps
                        .bss_data
                        .as_ref()
                        .unwrap()
                        .nr_event_dispatches;
                    if let Some(new_thresh) =
                        state.update(nr_event, elapsed_secs, self.opts.verbose, "perf_threshold")
                    {
                        self.skel.maps.bss_data.as_mut().unwrap().perf_threshold = new_thresh;
                    }
                }

                // Update sticky threshold state if dynamic mode is enabled.
                if let Some(ref mut state) = self.perf_sticky_threshold_state {
                    let nr_sticky = self
                        .skel
                        .maps
                        .bss_data
                        .as_ref()
                        .unwrap()
                        .nr_ev_sticky_dispatches;
                    if let Some(new_thresh) = state.update(
                        nr_sticky,
                        elapsed_secs,
                        self.opts.verbose,
                        "perf_sticky_threshold",
                    ) {
                        self.skel
                            .maps
                            .bss_data
                            .as_mut()
                            .unwrap()
                            .perf_sticky_threshold = new_thresh;
                    }
                }

                // GPU PID sync is throttled to GPU_SYNC_INTERVAL (NVML is expensive).
                if self.gpu_index_to_node.is_some() && last_gpu_sync.elapsed() >= GPU_SYNC_INTERVAL
                {
                    if let Err(e) = self.sync_gpu_pids() {
                        debug!("GPU PID sync: {}", e);
                    }
                    last_gpu_sync = Instant::now();
                }

                last_update = Instant::now();
            }

            // Update statistics and check for exit condition.
            let timeout = if polling_time.is_zero() {
                Duration::from_secs(1)
            } else {
                polling_time
            };
            match req_ch.recv_timeout(timeout) {
                Ok(()) => res_ch.send(self.get_metrics())?,
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }

        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    if opts.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    if opts.help_stats {
        stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
        return Ok(());
    }

    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    if let Some(intv) = opts.monitor.or(opts.stats) {
        let shutdown_copy = shutdown.clone();
        let jh = std::thread::spawn(move || {
            match stats::monitor(Duration::from_secs_f64(intv), shutdown_copy) {
                Ok(_) => {
                    debug!("stats monitor thread finished successfully")
                }
                Err(error_object) => {
                    warn!(
                        "stats monitor thread finished because of an error {}",
                        error_object
                    )
                }
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}

/* 从你已有的中文注释来看，后面主要从 [`sync_gpu_pids()`](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:925) 开始还没有详细说明。

**这部分代码负责用户态的持续维护：把 GPU、CPU 的状态同步给 BPF，响应统计请求，并管理调度器的退出和重启。** 真正选择 CPU、入队、派发任务的逻辑在 BPF 文件中。

下面按函数解释。

1. **`sync_gpu_pids()`：更新“线程 ID → GPU 所在 NUMA 节点”的映射**

   目的：让 BPF 知道哪些线程属于 GPU 相关进程，以及它们应该优先靠近哪个 NUMA 节点运行。

   执行过程如下：

   **① 检查 GPU 支持是否已初始化。**

   ```rust
   let gpu_index_to_node = match &self.gpu_index_to_node {
       Some(m) => m,
       None => return Ok(()),
   };
   ```

   如果没有 GPU 到节点的映射，或者没有 NVML 句柄，直接正常返回。本次不做同步。

   **② 遍历 GPU，收集进程及其对应的节点。**

   中间结果的类型是：

   ```rust
   HashMap<u32, HashSet<u32>>
   //      PID          NUMA 节点集合
   ```

   比如：

   ```text
   进程 100 → {节点 0}
   进程 200 → {节点 0, 节点 1}
   ```

   `HashSet` 用于去重，同一个进程被多次发现时，不会重复记录同一个节点。

   **③ 根据 GPU 利用率阈值决定收集哪些进程。**

   当 `gpu_util_threshold > 0` 时：

   ```rust
   let util = sample.sm_util.max(sample.mem_util);
   if util >= threshold {
       ...
   }
   ```

   取 SM 利用率和内存利用率中的较大值，达到阈值才记录该进程。这里的 `mem_util` 是利用率指标，不是进程占用了多少显存容量。

   如果查询利用率失败，就退回到收集所有正在使用该 GPU 的计算、图形进程。也就是说，**查询失败时，本轮不会继续执行利用率过滤。**

   当阈值为 `0` 时，也直接收集所有相关进程。

   **④ 只保留节点集合大小为 1 的进程，并展开其线程。**

   ```rust
   if nodes.len() == 1 {
       current.insert(tgid, node);
       for tid in Self::task_tids(tgid) {
           current.insert(tid, node);
       }
   }
   ```

   Linux 中，一个进程包含多个可被独立调度的线程。NVML 提供的是进程 ID，而 BPF 这里按线程 ID 查询，因此还需要把进程下的所有线程加入映射。

   例如：

   ```text
   NVML 发现进程 100 使用节点 0 上的 GPU
                     ↓
   /proc/100/task 中找到线程 100、101、102
                     ↓
   current = {100→0, 101→0, 102→0}
   ```

   **注意原注释的一个偏差：实际判断的是“只对应一个 NUMA 节点”，不是“只使用一张 GPU”。** 如果两张 GPU 都在节点 0，该进程仍然可能被保留。

   **⑤ 把本轮结果同步到 BPF map。**

   ```rust
   map.update(&pid.to_ne_bytes(), &node.to_ne_bytes(), MapFlags::ANY)
   ```

   - `to_ne_bytes()`：把整数转换为本机字节序的字节数组，作为 BPF map 的键和值。
   - `MapFlags::ANY`：键不存在就插入，已存在就覆盖。

   随后删除“上一轮存在、本轮不存在”的 PID，最后保存本轮结果，供下一轮比较。

   因此，GPU 关联会随周期更新，也会清理失效记录。

2. **`add_running_gpu_processes_to_set()`：收集使用某张 GPU 的进程**

   [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:995)

   核心逻辑：

   ```rust
   device
       .running_compute_processes()
       .unwrap_or_default()
       .into_iter()
       .chain(device.running_graphics_processes().unwrap_or_default())
   ```

   分别获取：

   - 计算进程列表；
   - 图形进程列表。

   `chain()` 把两个列表串起来遍历，然后执行：

   ```rust
   pid_to_nodes.entry(proc.pid).or_default().insert(node);
   ```

   可以理解为：

   ```text
   如果该 PID 还没有记录，先创建一个空节点集合；
   再把当前 GPU 所在的节点加入集合。
   ```

   因为集合会去重，同一个进程同时出现在计算和图形列表里也没有影响。

   `unwrap_or_default()` 表示查询失败时使用空列表，这个辅助函数本身不会向上传递查询错误。

3. **`task_tids()`：列出一个进程的所有线程 ID**

   [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:1011)

   它读取：

   ```text
   /proc/<进程 PID>/task/
   ```

   该目录下的子目录名就是各线程的 TID。例如：

   ```text
   /proc/100/task/100
   /proc/100/task/101
   /proc/100/task/102
   ```

   返回：

   ```rust
   vec![100, 101, 102]
   ```

   两次 `filter_map()` 分别负责：

   ```rust
   .filter_map(|e| e.ok())
   ```

   跳过读取失败的目录项。

   ```rust
   .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
   ```

   把目录名转成数字，转换失败则跳过。

   如果整个目录无法读取，例如进程已经退出，就返回空向量。

4. **`enable_primary_cpu()`：把一个 CPU 加入 BPF 的主调度域**

   [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:1022)

   它的逻辑是：

   ```text
   构造包含 CPU 编号的参数
          ↓
   调用 BPF 的 enable_primary_cpu 程序
          ↓
   BPF 将该 CPU 加入 primary_cpumask
          ↓
   根据 BPF 返回值判断成功或失败
   ```

   这里值得理解的是：

   ```rust
   std::slice::from_raw_parts_mut(
       &mut args as *mut _ as *mut u8,
       std::mem::size_of_val(&args),
   )
   ```

   这段把参数结构体的内存表示为一段可变字节切片，放进 `ProgramInput.context_in`，交给 BPF 读取。它没有另行序列化或复制结构体。

   ```rust
   let out = prog.test_run(input).unwrap();
   ```

   虽然 API 名叫 `test_run`，**这里确实执行了 BPF 程序，并修改内核中的状态**，并非只做一次无副作用的检查。

   错误有两层：

   - `test_run()` 调用本身失败：`unwrap()` 导致 panic。
   - 调用成功，但 BPF 返回非零：返回 `Err(out.return_value)`。

5. **`enable_sibling_cpu()` 和 `init_smt_domains()`：把 SMT 兄弟关系传给 BPF**

   [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:1044)

   `enable_sibling_cpu()` 的调用方式与上一函数基本相同，只是参数中有两个 CPU 编号：

   ```rust
   domain_arg {
       cpu_id: cpu as c_int,
       sibling_cpu_id: sibling_cpu as c_int,
   }
   ```

   BPF 据此把兄弟 CPU 加入当前 CPU 的 SMT 掩码，使调度器能够识别共享同一个物理核心的逻辑 CPU。

   `init_smt_domains()` 负责批量调用：

   ```rust
   let smt_siblings = topo.sibling_cpus();

   for (cpu, sibling_cpu) in smt_siblings.iter().enumerate() {
       Self::enable_sibling_cpu(skel, cpu, *sibling_cpu as usize).unwrap();
   }
   ```

   这里向量的**下标是 CPU 编号，值是其兄弟 CPU 编号**。例如：

   ```text
   smt_siblings[0] = 4
   smt_siblings[4] = 0
   ```

   表示 CPU 0 和 CPU 4 共享一个物理核心。

   注意，`init_smt_domains()` 虽然返回 `Result`，内部却使用了 `unwrap()`；配置失败时会直接 panic，并不会通过这个返回值逐层传递错误。

6. **`get_metrics()` 和 `exited()`：读取统计及退出状态**

   [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:1082)

   `get_metrics()` 从 BPF 的可变全局数据段 `.bss` 中复制三个累计计数：

   | 字段 | 含义 |
   |---|---|
   | `nr_event_dispatches` | 事件密集任务迁移到其他 CPU 并直接派发的次数 |
   | `nr_ev_sticky_dispatches` | 因 sticky 事件条件而在原 CPU 直接派发的次数 |
   | `nr_gpu_dispatches` | 因 GPU 亲和性直接派发的次数 |

   它只读取快照，不清零计数器。`stats.rs` 会对前后快照求差，得到监控间隔内的增量。

   `exited()` 则检查 BPF 写出的用户退出信息：

   ```rust
   uei_exited!(&self.skel, uei)
   ```

   宏内部以退出类型 `kind != 0` 判断调度器是否已经退出。这个状态和用户按 Ctrl-C 设置的 `shutdown` 是两个独立的停止来源。

7. **`compute_user_cpu_pct()`：用两次采样计算单个 CPU 的用户态利用率**

   [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:1095)

   `/proc/stat` 中的时间是累计值，因此先计算两次采样之间的差：

   ```rust
   user_diff = Δ(user + nice)
   total_diff = Δtotal
   ```

   再计算：

   ```text
   利用率 = user_diff / total_diff × 1024
   ```

   例如：

   ```text
   用户态累计时间增加 30
   总累计时间增加 100
   返回 round(0.3 × 1024) = 307
   ```

   所以函数名虽然带 `pct`，返回值实际采用 **1024 表示 100%** 的尺度，并不是返回 `30`。

   另外，这里只把 `user + nice` 算入分子，**不包含内核态 `system` 时间**。因此这里的“繁忙程度”具体指用户态利用率。

   `saturating_sub()` 防止计数回退时无符号减法下溢；如果总时间没有增加，返回 `None`，表示本次无法计算。

8. **`parse_per_cpu_cpu_times()` 和 `read_per_cpu_cpu_times()`：获取每个 CPU 的累计时间**

   [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:1110)

   解析函数逐行读取类似下面的内容：

   ```text
   cpu  ...
   cpu0 100 5 40 800 10 0 5 0 ...
   cpu1 ...
   ```

   处理步骤：

   - 跳过不以 `cpu` 开头的行。
   - 跳过汇总行 `cpu ...`。
   - 从 `cpu0`、`cpu1` 提取 CPU 编号。
   - 保存 `user`、`nice`。
   - 把前八个时间字段相加，作为 `total`。

   返回类型：

   ```rust
   Option<Vec<Option<CpuTimes>>>
   ```

   两层 `Option` 的用途不同：

   ```text
   外层 None：读取或解析失败，或没有找到任何有效 CPU 数据。
   内层 None：这个 CPU 没有对应数据，例如该 CPU 离线。
   ```

   因为结果按 CPU 编号索引，所以不能只把存在的 CPU 压缩成一个连续列表。

   `read_per_cpu_cpu_times()` 是一个包装函数：打开 `/proc/stat`，用 `BufReader` 包装后交给上述解析函数。

9. **`run()`：持续维护调度器的主循环**

   [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:1155)

   这个函数是后半部分的核心。调度器在 `init()` 中已经挂载；`run()` 负责运行期间的用户态工作。

   **① 准备初始采样和计时器。**

   ```rust
   let polling_time =
       Duration::from_millis(self.opts.polling_ms).min(Duration::from_secs(1));
   ```

   轮询间隔最多为 1 秒。注意：**这里没有实现前面参数注释所说的最小 10ms 限制**，例如传入 `1` 就是 1ms。

   接着读取初始 CPU 时间，记录 CPU 更新和 GPU 同步的起始时刻。

   **② 检查是否需要退出。**

   ```rust
   while !shutdown.load(Ordering::Relaxed) && !self.exited()
   ```

   用户请求停止，或者 BPF 调度器已经退出，都会结束循环。

   **③ 到达轮询时间后，更新各 CPU 的利用率。**

   ```text
   读取本轮 /proc/stat
          ↓
   与上一轮逐 CPU 比较
          ↓
   计算用户态利用率
          ↓
   写入 cpu_util_map
          ↓
   保存本轮数据，供下次比较
   ```

   如果某 CPU 缺少前后任一次数据，就写入 `0`。如果总时间差为零，则跳过本次写入。

   BPF 的 `is_cpu_busy(cpu)` 会读取这个 map，与 `busy_threshold` 比较，辅助决定使用本地队列还是共享 deadline 队列。

   **④ 更新动态 perf 阈值。**

   分别读取：

   ```rust
   nr_event_dispatches
   nr_ev_sticky_dispatches
   ```

   然后调用前面定义的 `DynamicThresholdState::update()`。

   如果返回 `Some(new_thresh)`，就把新阈值写回 BPF 的 `.bss`，后续调度随之使用新阈值。

   这里反馈给控制器的是**相关派发行为发生的次数**，不是直接把硬件 perf 事件原始计数拿来计算反馈速率。

   **⑤ 同步 GPU PID，但限制频率。**

   只有距离上次同步至少 1 秒时，才调用：

   ```rust
   self.sync_gpu_pids()
   ```

   因此，即使 CPU 每 100ms 更新一次，也不会每次都查询 NVML。

   **这里有一个关键的嵌套关系：GPU 同步和动态阈值更新，都放在 CPU 轮询的条件块里面。** 所以 `polling_ms = 0` 时，这三项周期工作都会停止：

   ```text
   CPU 利用率更新
   动态 perf 阈值调整
   GPU PID 同步
   ```

   统计请求仍然可以处理。

   **⑥ 等待统计请求，同时避免空转。**

   ```rust
   match req_ch.recv_timeout(timeout) {
       Ok(()) => res_ch.send(self.get_metrics())?,
       Err(RecvTimeoutError::Timeout) => {}
       Err(e) => Err(e)?,
   }
   ```

   - 收到请求：读取统计快照并回复。
   - 等待超时：继续下一轮，检查更新和退出条件。
   - 通道发生其他错误：返回错误。

   因此，这个等待既服务统计查询，也让主线程在没有工作时阻塞，避免一直占用 CPU。`timeout` 是等待上限，不是每轮都必须睡满的时间。

   **⑦ 退出时解除挂载并报告原因。**

   ```rust
   let _ = self.struct_ops.take();
   uei_report!(&self.skel, uei)
   ```

   `take()` 把 `Link` 从 `Option` 中取出，原字段变为 `None`。取出的 `Link` 随即被释放，解除调度器挂载。

   随后读取、报告退出信息，并把 `UserExitInfo` 返回给 `main()`，供它判断是否重启。

10. **`Drop::drop()`：对象销毁时打印日志**

    [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:1266)

    ```rust
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
    ```

    `Scheduler` 离开作用域时自动执行这个函数。

    **函数体本身只打印日志。** 资源释放依靠字段各自的析构逻辑；正常的 `run()` 退出路径已经提前释放了挂载用的 `Link`。如果运行中通过 `?` 提前返回错误，对象销毁时，仍持有的字段也会被自动释放。

11. **`main()`：解析参数，选择监控模式或启动调度器**

    [代码位置](/home/paulning/study/scx/scheds/rust/scx_cosmos/src/main.rs:1272)

    可以按下面的顺序理解：

    **① 解析参数，处理只需输出信息的选项。**

    ```rust
    let opts = Opts::parse();
    ```

    如果指定 `--version`，打印版本并退出；如果指定 `--help-stats`，打印统计字段说明并退出。

    **② 初始化日志。**

    设置日志输出到标准错误，最低输出级别为 `Info`，并隐藏代码位置、线程信息等。

    因此，这里的 `debug!()` 默认不会显示。`--verbose` 在其他位置控制额外日志和 libbpf 调试，但这里没有用它把全局日志级别改成 `Debug`。

    **③ 建立共享退出标志，注册 Ctrl-C 回调。**

    ```rust
    let shutdown = Arc::new(AtomicBool::new(false));
    ```

    - `Arc`：让主线程、监控线程和信号回调共享同一个标志。
    - `AtomicBool`：允许它们安全地读写这个布尔值。
    - `clone()`：增加共享引用，不会创建独立的布尔变量。

    按 Ctrl-C 后，回调把标志设置成 `true`，各运行循环看到后退出。这里 `Relaxed` 只用于传递停止标志，不承担其他数据的同步。

    **④ 按参数启动统计监控线程。**

    ```rust
    if let Some(intv) = opts.monitor.or(opts.stats)
    ```

    如果两者都指定，优先采用 `monitor` 的间隔。

    两个选项的区别是：

    | 选项 | 执行行为 |
    |---|---|
    | `--monitor` | 只监控已有调度器；等待监控线程结束后退出 |
    | `--stats` | 启动监控线程，同时继续启动本进程的调度器 |

    因而，你前面给 `stats` 写的中文注释需要区分：**只有 `--monitor` 不启动调度器，`--stats` 仍会启动。**

    **⑤ 初始化、运行，并根据退出信息决定是否重启。**

    ```rust
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    ```

    `MaybeUninit` 为打开 BPF 对象准备尚未初始化的存储空间，由初始化流程填充。

    每轮先创建并挂载调度器，再进入维护循环。`run()` 正常返回后：

    - 退出信息要求重启：销毁本轮对象，再重新初始化。
    - 不要求重启：结束程序。
    - `init()` 或 `run()` 返回错误：`?` 将错误向上传递，退出 `main()`。

    所以这里的重启由退出信息中的重启标志控制，并不是遇到任何错误都会自动重试。 */