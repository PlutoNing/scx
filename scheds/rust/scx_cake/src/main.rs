// SPDX-License-Identifier: GPL-2.0
// SPDX 许可证标识符：GPL-2.0。讲解：声明本文件采用 GPL-2.0 开源许可协议。
// scx_cake - sched_ext scheduler applying CAKE bufferbloat concepts to CPU scheduling
// scx_cake —— 一个把 CAKE 缓冲膨胀（bufferbloat）理念应用于 CPU 调度的 sched_ext 调度器。讲解：说明该程序借鉴网络 CAKE 排队算法来优化 CPU 任务调度。

mod topology;
mod tui;

use core::sync::atomic::Ordering;
use std::io::IsTerminal;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use log::{info, warn};

use scx_arena::ArenaLib;
use scx_utils::build_id;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPU_IDS;
// Include the generated interface bindings
// 引入自动生成的接口绑定。讲解：包含由构建脚本生成的 Rust 与 BPF 之间的接口定义。
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_intf {
    include!(concat!(env!("OUT_DIR"), "/bpf_intf.rs"));
}

// Include the generated BPF skeleton
// 引入自动生成的 BPF 骨架。讲解：包含编译后 BPF 程序的骨架代码，用于在用户态加载和操作 BPF。
#[allow(non_camel_case_types, non_upper_case_globals, dead_code)]
mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}
use bpf_skel::*;

const SCHEDULER_NAME: &str = "scx_cake";

/// Scheduler profile presets
/// 调度器配置文件预设。讲解：定义一组预设的调度参数组合，便于按场景一键切换。
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Profile {
    /// Ultra-low-latency for competitive esports (1ms quantum)
    /// 面向竞技电竞的超低延迟（1ms 时间片）。讲解：追求极致响应，时间片极短。
    Esports,
    /// Optimized for older/lower-power hardware (4ms quantum)
    /// 针对较老/低功耗硬件优化（4ms 时间片）。讲解：加大时间片以降低旧 CPU 上的调度开销。
    Legacy,
    /// Low-latency profile optimized for gaming and interactive workloads
    /// 针对游戏和交互式负载优化的低延迟配置。讲解：默认游戏场景，兼顾低延迟。
    Gaming,
    /// Balanced profile for general desktop use (same as gaming for now)
    /// 面向通用桌面的均衡配置（目前与 gaming 相同）。讲解：日常桌面使用，暂等同于游戏配置。
    Default,
    /// Power-efficient profile for handhelds/laptops on battery (DVFS enabled)
    /// 面向掌机/笔记本电池供电的节能配置（启用 DVFS）。讲解：优先省电，减少上下文切换。
    Battery,
}

impl Profile {
    /// Returns (quantum_us, new_flow_bonus_us, starvation_us)
    /// 返回三元组 (时间片_us, 新流奖励_us, 饥饿阈值_us)。讲解：把每种配置映射到具体的调度参数值。
    fn values(&self) -> (u64, u64, u64) {
        match self {
            // Esports: Ultra-aggressive, 1ms quantum for maximum responsiveness
            // 电竞：极度激进，1ms 时间片以获得最大响应速度。讲解：牺牲吞吐换取最低延迟。
            Profile::Esports => (1000, 4000, 50000),
            // Legacy: High efficiency, 4ms quantum to reduce overhead on older CPUs
            // 旧硬件：高效率，4ms 时间片以降低旧 CPU 的开销。讲解：加大时间片减少切换成本。
            Profile::Legacy => (4000, 12000, 200000),
            // Gaming: Aggressive latency, 2ms quantum
            // 游戏：激进的低延迟，2ms 时间片。讲解：在延迟与开销间取得游戏场景平衡。
            Profile::Gaming => (2000, 8000, 100000),
            // Default: Same as gaming for now
            // 默认：目前与游戏配置相同。讲解：占位配置，后续版本可能分化。
            Profile::Default => (2000, 8000, 100000),
            // Battery: 4ms quantum — fewer context switches = less power
            // 电池：4ms 时间片——更少的上下文切换意味着更省电。讲解：延长时间片以节能。
            Profile::Battery => (4000, 12000, 200000),
        }
    }

    // DVFS — disabled (tick architecture removed, no runtime effect).
    // DVFS —— 已禁用（tick 架构已移除，运行时无效果）。讲解：动态调频功能不再生效。
    // RODATA symbols retained in BPF for loader compat; JIT eliminates.
    // BPF 中保留 RODATA 符号以兼容加载器；JIT 会将其消除。讲解：保留符号仅为兼容，编译期会优化掉。
}

/// 🍰 scx_cake: A sched_ext scheduler applying CAKE bufferbloat concepts
///
/// This scheduler adapts CAKE's DRR++ (Deficit Round Robin++) algorithm
/// for CPU scheduling, providing low-latency scheduling for gaming and
/// interactive workloads while maintaining fairness.
///
/// PROFILES set all tuning parameters at once. Individual options override profile defaults.
///
/// 4-CLASS SYSTEM (classified by PELT utilization + game family detection):
///   GAME:    game process tree + audio + compositor (during GAMING)
///   NORMAL:  default class — interactive desktop tasks
///   HOG:     high PELT utilization (≥78% CPU) non-game tasks
///   BG:      low PELT utilization non-game tasks during GAMING
///
/// EXAMPLES:
///   scx_cake                          # Run with gaming profile (default)
///   scx_cake -p esports               # Ultra-low-latency for competitive play
///   scx_cake --quantum 1500           # Gaming profile with custom quantum
///   scx_cake -v                       # Run with live TUI stats display
///
/// 🍰 scx_cake：一个把 CAKE 缓冲膨胀理念应用于 CPU 调度的 sched_ext 调度器。
///
/// 本调度器把 CAKE 的 DRR++（赤字轮询++）算法改造用于 CPU 调度，
/// 在保持公平性的同时，为游戏和交互式负载提供低延迟调度。
///
/// PROFILES（配置文件）会一次性设置所有调优参数。单独的选项会覆盖配置文件的默认值。
///
/// 4 类系统（依据 PELT 利用率 + 游戏家族检测进行分类）：
///   GAME：   游戏进程树 + 音频 + 合成器（游戏期间）
///   NORMAL： 默认类别 —— 交互式桌面任务
///   HOG：    高 PELT 利用率（≥78% CPU）的非游戏任务
///   BG：     游戏期间低 PELT 利用率的非游戏任务
///
/// 示例：
///   scx_cake                          # 使用游戏配置运行（默认）
///   scx_cake -p esports               # 用于竞技的超低延迟
///   scx_cake --quantum 1500           # 游戏配置并自定义时间片
///   scx_cake -v                       # 运行并显示实时 TUI 统计界面
///
/// 讲解：这是命令行程序的顶层帮助文档，说明调度器的原理、任务分类体系与常用命令示例。
#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    disable_version_flag = true,
    about = "🍰 A sched_ext scheduler applying CAKE bufferbloat concepts to CPU scheduling",
    verbatim_doc_comment
)]
struct Args {
    /// Scheduler profile preset.
    ///
    /// Profiles configure all tier thresholds, quantum multipliers, and wait budgets.
    /// Individual CLI options (--quantum, etc.) override profile values.
    ///
    /// ESPORTS: Ultra-low-latency for competitive gaming.
    ///   - Quantum: 1000µs, Starvation: 50ms
    ///
    /// LEGACY: Optimized for older/lower-power hardware.
    ///   - Quantum: 4000µs, Starvation: 200ms
    ///
    /// GAMING: Optimized for low-latency gaming and interactive workloads.
    ///   - Quantum: 2000µs, Starvation: 100ms
    ///
    /// DEFAULT: Balanced profile for general desktop use.
    ///   - Currently same as gaming; will diverge in future versions
    ///
    /// BATTERY: Power-efficient for handhelds/laptops on battery.
    ///   - Quantum: 4000µs, reduced context switch overhead
    ///
    /// 调度器配置文件预设。
    ///
    /// 配置文件会设定所有层级阈值、时间片倍数和等待预算。
    /// 单独的命令行选项（如 --quantum 等）会覆盖配置文件的取值。
    ///
    /// ESPORTS：面向竞技游戏的超低延迟。
    ///   - 时间片：1000µs，饥饿阈值：50ms
    ///
    /// LEGACY：针对较老/低功耗硬件优化。
    ///   - 时间片：4000µs，饥饿阈值：200ms
    ///
    /// GAMING：针对低延迟游戏和交互式负载优化。
    ///   - 时间片：2000µs，饥饿阈值：100ms
    ///
    /// DEFAULT：面向通用桌面的均衡配置。
    ///   - 目前与游戏配置相同；未来版本会有所区分
    ///
    /// BATTERY：面向掌机/笔记本电池供电的节能配置。
    ///   - 时间片：4000µs，降低上下文切换开销
    ///
    /// 讲解：--profile 参数的帮助文本，列出各预设的用途及关键参数。
    #[arg(long, short, value_enum, default_value_t = Profile::Gaming, verbatim_doc_comment)]
    profile: Profile,

    /// Base scheduling time slice in MICROSECONDS [default: 2000].
    ///
    /// How long a task runs before potentially yielding.
    ///
    /// Smaller quantum = more responsive but higher overhead.
    /// Esports: 1000µs | Gaming: 2000µs | Legacy: 4000µs
    /// Recommended range: 1000-8000µs
    ///
    /// 基础调度时间片，单位为微秒 [默认：2000]。
    ///
    /// 表示一个任务在可能让出 CPU 前运行多久。
    ///
    /// 时间片越小 = 越灵敏但开销越高。
    /// 电竞：1000µs | 游戏：2000µs | 旧硬件：4000µs
    /// 推荐范围：1000-8000µs
    ///
    /// 讲解：--quantum 参数，控制每个任务单次运行的时长。
    #[arg(long, verbatim_doc_comment)]
    quantum: Option<u64>,

    /// Bonus time for newly woken tasks in MICROSECONDS [default: 8000].
    ///
    /// Tasks waking from sleep get this extra time added to their deficit,
    /// allowing them to run longer on first dispatch. Helps bursty workloads.
    ///
    /// Esports: 4000µs | Gaming: 8000µs
    /// Recommended range: 4000-16000µs
    ///
    /// 新唤醒任务的奖励时间，单位为微秒 [默认：8000]。
    ///
    /// 从睡眠中唤醒的任务会把这段额外时间加到它的赤字上，
    /// 使其在首次派发时能运行更久。有助于突发型负载。
    ///
    /// 电竞：4000µs | 游戏：8000µs
    /// 推荐范围：4000-16000µs
    ///
    /// 讲解：--new_flow_bonus 参数，给刚被唤醒的任务额外运行配额以改善响应。
    #[arg(long, verbatim_doc_comment)]
    new_flow_bonus: Option<u64>,

    /// Max run time before forced preemption in MICROSECONDS [default: 100000].
    ///
    /// Safety limit: tasks running longer than this are forcibly preempted.
    /// Prevents any single task from monopolizing the CPU.
    ///
    /// Esports: 50000µs (50ms) | Gaming: 100000µs (100ms) | Legacy: 200000µs (200ms)
    /// Recommended range: 50000-200000µs
    ///
    /// 强制抢占前的最大运行时长，单位为微秒 [默认：100000]。
    ///
    /// 安全上限：运行超过该时长的任务会被强制抢占。
    /// 防止任何单个任务独占 CPU。
    ///
    /// 电竞：50000µs (50ms) | 游戏：100000µs (100ms) | 旧硬件：200000µs (200ms)
    /// 推荐范围：50000-200000µs
    ///
    /// 讲解：--starvation 参数，作为防止任务饿死其他任务的抢占安全阀。
    #[arg(long, verbatim_doc_comment)]
    starvation: Option<u64>,

    /// Enable live TUI (Terminal User Interface) with real-time statistics.
    ///
    /// Shows dispatch counts per tier, tier transitions,
    /// wait time stats, and system topology information.
    /// Press 'q' to exit TUI mode.
    ///
    /// 启用带实时统计的实时 TUI（终端用户界面）。
    ///
    /// 显示各层级的派发计数、层级切换、
    /// 等待时间统计以及系统拓扑信息。
    /// 按 'q' 退出 TUI 模式。
    ///
    /// 讲解：--verbose 参数，开启终端内实时监控面板。
    #[arg(long, short, verbatim_doc_comment)]
    verbose: bool,

    /// Statistics refresh interval in SECONDS (only with --verbose).
    ///
    /// How often the TUI updates. Lower values = more responsive but
    /// higher overhead. Has no effect without --verbose.
    ///
    /// Default: 1 second
    ///
    /// 统计刷新间隔，单位为秒（仅在 --verbose 时生效）。
    ///
    /// 表示 TUI 多久更新一次。数值越小 = 越灵敏但开销越高。
    /// 不加 --verbose 时无效果。
    ///
    /// 默认：1 秒
    ///
    /// 讲解：--interval 参数，控制监控面板的刷新频率。
    #[arg(long, default_value_t = 1, verbatim_doc_comment)]
    interval: u64,

    /// Live in-kernel testing mode for automated benchmarking.
    ///
    /// Runs the scheduler for 10 seconds, collects BPF data points,
    /// and prints a structured JSON output to stdout.
    ///
    /// 用于自动化基准测试的实时内核内测试模式。
    ///
    /// 运行调度器 10 秒，收集 BPF 数据点，
    /// 并向标准输出打印结构化的 JSON。
    ///
    /// 讲解：--testing 参数，用于跑一段固定时长并输出可解析的性能数据。
    #[arg(long, verbatim_doc_comment)]
    testing: bool,

    /// Print scheduler version and exit.
    /// 打印调度器版本并退出。讲解：--version 参数，仅显示版本号后结束程序。
    #[arg(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
}

impl Args {
    /// Get effective values (profile defaults with CLI overrides applied)
    /// 获取生效值（在配置文件默认值基础上应用命令行覆盖）。讲解：合并预设与用户传入参数，得到最终使用的参数。
    fn effective_values(&self) -> (u64, u64, u64) {
        let (q, nfb, starv) = self.profile.values();
        (
            self.quantum.unwrap_or(q),
            self.new_flow_bonus.unwrap_or(nfb),
            self.starvation.unwrap_or(starv),
        )
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    args: Args,
    topology: topology::TopologyInfo,
    latency_matrix: Vec<Vec<f64>>,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn new(
        args: Args,
        open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};

        // ═══ scx_ops_open! equivalent ═══
        // ═══ 等价于 scx_ops_open! ═══。讲解：这一段手工实现宏 scx_ops_open! 的功能。
        // Matches scx_ops_open!(skel_builder, open_object, cake_ops, None)
        // 对应 scx_ops_open!(skel_builder, open_object, cake_ops, None)。讲解：与该宏调用行为一致。
        // Cake can't use the macro directly (custom arena architecture),
        // Cake 无法直接使用该宏（自定义 arena 架构）。讲解：因架构特殊需要内联展开。
        // so we inline the critical functionality.
        // 因此我们把关键功能内联实现。讲解：手动完成宏原本负责的初始化步骤。
        scx_utils::compat::check_min_requirements()?;

        let skel_builder = BpfSkelBuilder::default();
        let mut open_skel = skel_builder
            .open(open_object)
            .context("Failed to open BPF skeleton")?;

        // Inject version suffix into ops name: "cake" → "cake_1.1.0_g<hash>_<target>"
        // 将版本后缀注入 ops 名称："cake" → "cake_1.1.0_g<hash>_<target>"。讲解：给调度器操作名附加版本信息。
        // This is what scx_loader reads from /sys/kernel/sched_ext/root/ops
        // 这正是 scx_loader 从 /sys/kernel/sched_ext/root/ops 读取的内容。讲解：加载器据此识别调度器。
        {
            let ops = open_skel.struct_ops.cake_ops_mut();
            let name_field = &mut ops.name;

            let version_suffix = scx_utils::build_id::ops_version_suffix(env!("CARGO_PKG_VERSION"));
            let bytes = version_suffix.as_bytes();
            let mut i = 0;
            let mut bytes_idx = 0;
            let mut found_null = false;

            while i < name_field.len() - 1 {
                found_null |= name_field[i] == 0;
                if !found_null {
                    i += 1;
                    continue;
                }

                if bytes_idx < bytes.len() {
                    name_field[i] = bytes[bytes_idx] as i8;
                    bytes_idx += 1;
                } else {
                    break;
                }
                i += 1;
            }
            name_field[i] = 0;
        }

        // Read hotplug sequence number — enables kernel-requested restarts on CPU hotplug
        // 读取热插拔序列号 —— 允许在 CPU 热插拔时由内核请求重启。讲解：记录热插拔状态以便调度器在拓扑变化时重启。
        {
            let path = std::path::Path::new("/sys/kernel/sched_ext/hotplug_seq");
            let val = std::fs::read_to_string(path)
                .context("Failed to read /sys/kernel/sched_ext/hotplug_seq")?;
            open_skel.struct_ops.cake_ops_mut().hotplug_seq = val
                .trim()
                .parse::<u64>()
                .context("Failed to parse hotplug_seq")?;
        }

        // Honor SCX_TIMEOUT_MS environment variable (matches scx_ops_open! behavior)
        // 遵循 SCX_TIMEOUT_MS 环境变量（与 scx_ops_open! 行为一致）。讲解：允许通过环境变量设置调度器超时。
        if let Ok(s) = std::env::var("SCX_TIMEOUT_MS") {
            let ms: u32 = s.parse().context("SCX_TIMEOUT_MS has invalid value")?;
            info!("Setting timeout_ms to {} based on environment", ms);
            open_skel.struct_ops.cake_ops_mut().timeout_ms = ms;
        }

        // Populate SCX enum RODATA from kernel BTF (SCX_DSQ_LOCAL_ON, SCX_KICK_PREEMPT, etc.)
        // 从内核 BTF 填充 SCX 枚举 RODATA（如 SCX_DSQ_LOCAL_ON、SCX_KICK_PREEMPT 等）。讲解：把内核定义的枚举常量导入到 BPF 只读数据中。
        scx_utils::import_enums!(open_skel);

        // Detect system topology (CCDs, P/E cores)
        // 检测系统拓扑（CCD、性能核/能效核）。讲解：识别 CPU 布局以便做拓扑感知调度。
        let topo = topology::detect()?;

        // Get effective values (profile + CLI overrides)
        // 获取生效值（配置文件 + 命令行覆盖）。讲解：得到最终使用的调度参数。
        let (quantum, new_flow_bonus, _starvation) = args.effective_values();

        // Latency matrix: zeroed, populated by TUI Topology tab if --verbose
        // 延迟矩阵：初始化为零，若使用 --verbose 则由 TUI 拓扑页填充。讲解：预留存放核间延迟数据的矩阵。
        let latency_matrix = vec![vec![0.0; topo.nr_cpus]; topo.nr_cpus];

        // Configure the scheduler via rodata (read-only data)
        // 通过 rodata（只读数据）配置调度器。讲解：把用户态参数写入 BPF 只读区，加载后不可改。
        if let Some(rodata) = &mut open_skel.maps.rodata_data {
            rodata.quantum_ns = quantum * 1000;
            rodata.new_flow_bonus_ns = new_flow_bonus * 1000;
            // Stats/telemetry: only available in debug builds (CAKE_RELEASE omits the field).
            // 统计/遥测：仅在 debug 构建中可用（CAKE_RELEASE 会省略该字段）。讲解：发布版剔除统计以避免开销。
            // In release, --verbose is silently ignored — zero overhead for production gaming.
            // 在 release 版本中，--verbose 会被静默忽略 —— 面向生产游戏零开销。讲解：正式版忽略统计开关。
            #[cfg(debug_assertions)]
            {
                rodata.enable_stats = args.verbose || args.testing;
            }

            // has_hybrid removed: smt_sibling now uses pre-filled cpu_sibling_map only
            // 已移除 has_hybrid：smt_sibling 现在仅使用预填充的 cpu_sibling_map。讲解：SMT 兄弟核信息改由预置映射提供。
            // Per-LLC DSQ partitioning: populate CPU→LLC mapping
            // 按 LLC 划分 DSQ：填充 CPU→LLC 的映射。讲解：为每个末级缓存域建立独立派发队列的映射。
            let llc_count = topo.llc_cpu_mask.iter().filter(|&&m| m != 0).count() as u32;
            rodata.nr_llcs = llc_count.max(1);
            rodata.nr_cpus = topo.nr_cpus.min(256) as u32; // F2: widened from 64→256 for Threadripper
            // F2：为 Threadripper 从 64 扩展到 256。讲解：支持超多核 CPU。
            rodata.nr_phys_cpus = topo.nr_phys_cpus.min(256) as u32; // V3: PHYS_FIRST scan mask
            // V3：PHYS_FIRST 扫描掩码。讲解：记录物理核数量用于优先扫描物理核。

            // Ferry explicit 64-bit topology arrays down into BPF (O(1) execution replacements)
            // 将显式的 64 位拓扑数组传递到 BPF（用于 O(1) 执行替换）。讲解：预先算好拓扑数组，让 BPF 侧查表即得、避免运行时计算。

            // Heterogeneous Gaming Topology — u64[4] arrays (F2: 256-bit masks)
            // 异构游戏拓扑 —— u64[4] 数组（F2：256 位掩码）。讲解：用 4 个 u64 表示最多 256 个 CPU 的位掩码。
            rodata.big_core_phys_mask[0] = topo.big_core_phys_mask;
            rodata.big_core_smt_mask[0] = topo.big_core_smt_mask;
            rodata.little_core_mask[0] = topo.little_core_mask;
            rodata.vcache_llc_mask[0] = topo.vcache_llc_mask;
            rodata.has_vcache = topo.has_vcache;
            rodata.has_hybrid_cores = topo.big_core_phys_mask != 0;

            for i in 0..topo.cpu_sibling_map.len() {
                rodata.cpu_sibling_map[i] = topo.cpu_sibling_map[i];
            }
            for i in 0..topo.llc_cpu_mask.len().min(8) {
                rodata.llc_cpu_mask[i] = topo.llc_cpu_mask[i];
            }
            for i in 0..topo.core_cpu_mask.len().min(32) {
                rodata.core_cpu_mask[i] = topo.core_cpu_mask[i];
            }

            for (i, &llc_id) in topo.cpu_llc_id.iter().enumerate() {
                rodata.cpu_llc_id[i] = llc_id as u32;
            }

            // Performance-ordered CPU arrays: read prefcore ranking from sysfs,
            // 按性能排序的 CPU 数组：从 sysfs 读取 prefcore 排名，讲解：依据硬件性能提示排列 CPU 顺序。
            // sort by performance, group SMT pairs together.
            // 按性能排序，并把 SMT 兄弟对分组在一起。讲解：让超线程配对相邻，便于成对分配。
            // GAME tasks scan fast→slow, non-GAME scans slow→fast.
            // GAME 任务从快到慢扫描，非 GAME 从慢到快扫描。讲解：游戏任务优先占用最快的核。
            {
                let nr = topo.nr_cpus.min(256);
                // Read prefcore ranking per CPU (higher = faster)
                // 读取每个 CPU 的 prefcore 排名（越高 = 越快）。讲解：从 sysfs 获取各核的性能等级。
                let mut rankings: Vec<(usize, u32)> = (0..nr)
                    .map(|cpu| {
                        let path = format!(
                            "/sys/devices/system/cpu/cpu{}/cpufreq/amd_pstate_prefcore_ranking",
                            cpu
                        );
                        let rank = std::fs::read_to_string(&path)
                            .ok()
                            .and_then(|s| s.trim().parse::<u32>().ok())
                            .unwrap_or(100); // fallback: equal ranking
                        // 回退：使用相等排名。讲解：读取失败时默认所有核性能相同。
                        (cpu, rank)
                    })
                    .collect();

                // Sort by descending rank (fastest first), stable for SMT grouping
                // 按排名降序排序（最快在前），使用稳定排序以便 SMT 分组。讲解：保持同性能核的相对顺序稳定。
                rankings.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

                // Build fast→slow array with SMT pairs grouped together:
                // 构建从快到慢的数组，并把 SMT 兄弟对分组在一起：讲解：生成有序的 CPU 选择列表。
                // [best_phys, best_smt, second_phys, second_smt, ...]
                // [最快物理核, 其 SMT 兄弟, 次快物理核, 其 SMT 兄弟, ...]。讲解：物理核与其超线程相邻排列。
                let mut fast_to_slow: Vec<u8> = Vec::with_capacity(nr);
                let mut used = vec![false; nr];
                for &(cpu, _) in &rankings {
                    if used[cpu] {
                        continue;
                    }
                    fast_to_slow.push(cpu as u8);
                    used[cpu] = true;
                    // Add SMT sibling immediately after
                    // 紧接着添加 SMT 兄弟核。讲解：把该核的超线程配对放在其后。
                    let sib = topo.cpu_sibling_map.get(cpu).copied().unwrap_or(0xFF);
                    if (sib as usize) < nr && !used[sib as usize] {
                        fast_to_slow.push(sib);
                        used[sib as usize] = true;
                    }
                }

                // Populate RODATA arrays
                // 填充 RODATA 数组。讲解：把排好序的 CPU 列表写入 BPF 只读数据。
                for i in 0..64usize {
                    if i < fast_to_slow.len() {
                        rodata.cpus_fast_to_slow[i] = fast_to_slow[i];
                        // Reverse for slow→fast
                        // 反转以得到从慢到快的顺序。讲解：非游戏任务使用该逆序列表。
                        rodata.cpus_slow_to_fast[i] = fast_to_slow[fast_to_slow.len() - 1 - i];
                    } else {
                        rodata.cpus_fast_to_slow[i] = 0xFF; // sentinel
                        // 哨兵值。讲解：0xFF 表示该槽位无效/结束标记。
                        rodata.cpus_slow_to_fast[i] = 0xFF;
                    }
                }

                let top_cpus: Vec<_> = fast_to_slow.iter().take(4).collect();
                info!(
                    "Core steering: fast→slow order {:?} ({} CPUs)",
                    top_cpus, nr
                );
            }

            // ═══ Per-CPU capacity table (F1 correctness fix) ═══
            // ═══ 每 CPU 算力表（F1 正确性修复）═══。讲解：为每个核记录相对算力。
            // Read arch_scale_cpu_capacity from sysfs for P/E core vruntime scaling.
            // 从 sysfs 读取 arch_scale_cpu_capacity，用于性能核/能效核的 vruntime 缩放。讲解：按核算力调整虚拟运行时间。
            // Scale: 0-1024, where 1024 = fastest core. On SMP all = 1024 → JIT folds.
            // 取值：0-1024，其中 1024 = 最快的核。对称多处理器上全为 1024 → JIT 可折叠优化。讲解：同构系统无需缩放。
            // Intel hybrid: P-cores ~1024, E-cores ~600-700.
            // Intel 混合架构：性能核约 1024，能效核约 600-700。讲解：异构核算力差异明显。
            // AMD SMP: all 1024 → cap > 0 && cap < 1024 is always false → zero overhead.
            // AMD 对称多处理器：全为 1024 → 条件 cap > 0 && cap < 1024 恒为假 → 零开销。讲解：同构时缩放逻辑被跳过。
            {
                let nr = topo.nr_cpus.min(256);
                let mut all_equal = true;
                let mut first_cap: u32 = 0;

                for cpu in 0..nr {
                    let path = format!("/sys/devices/system/cpu/cpu{}/cpu_capacity", cpu);
                    let cap = std::fs::read_to_string(&path)
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok())
                        .unwrap_or(1024);

                    rodata.cpuperf_cap_table[cpu] = cap;

                    if cpu == 0 {
                        first_cap = cap;
                    } else if cap != first_cap {
                        all_equal = false;
                    }
                }

                if !all_equal {
                    info!(
                        "Capacity scaling: heterogeneous (P/E cores, range {}-{})",
                        rodata.cpuperf_cap_table[..nr].iter().min().unwrap_or(&0),
                        rodata.cpuperf_cap_table[..nr].iter().max().unwrap_or(&1024)
                    );
                }
            }

            // Arena library: nr_cpu_ids must be set before load() — arena_init
            // Arena 库：nr_cpu_ids 必须在 load() 之前设置 —— arena_init 会检查它，讲解：arena 初始化依赖该值。
            // checks this and returns -ENODEV (errno 19) if uninitialized.
            // 若未初始化则返回 -ENODEV（errno 19）。讲解：未设置会导致加载失败。
            rodata.nr_cpu_ids = *NR_CPU_IDS as u32;

            // ═══ Audio stack detection ═══
            // ═══ 音频栈检测 ═══。讲解：找出系统中的音频相关进程并特殊对待。
            // Phase 1: Core audio daemons by comm name.
            // 阶段 1：按进程名（comm）识别核心音频守护进程。讲解：匹配已知音频服务名。
            // Phase 2: PipeWire socket clients (mixers like goxlr-daemon).
            // 阶段 2：PipeWire 套接字客户端（如 goxlr-daemon 等混音器）。讲解：通过套接字连接找出音频客户端。
            // Both are session-persistent → bake into RODATA.
            // 二者在整个会话期间都持续存在 → 直接固化到 RODATA。讲解：一次检测后写入只读数据。
            {
                use std::collections::HashSet;

                const AUDIO_COMMS: &[&str] = &[
                    "pipewire",
                    "wireplumber",
                    "pipewire-pulse",
                    "pulseaudio",
                    "jackd",
                    "jackdbus",
                ];
                let mut audio_tgids: Vec<u32> = Vec::new();
                let mut audio_tgid_set: HashSet<u32> = HashSet::new();

                // Phase 1: comm-based detection
                // 阶段 1：基于进程名的检测。讲解：遍历 /proc 按 comm 匹配音频守护进程。
                if let Ok(entries) = std::fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if !name_str.chars().all(|c| c.is_ascii_digit()) {
                            continue;
                        }
                        let pid: u32 = match name_str.parse() {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
                            let comm = comm.trim();
                            if AUDIO_COMMS.contains(&comm) && audio_tgid_set.insert(pid) {
                                audio_tgids.push(pid);
                            }
                        }
                    }
                }

                // Phase 2: PipeWire socket client detection.
                // 阶段 2：PipeWire 套接字客户端检测。讲解：不依赖进程名，改用套接字连接关系发现音频客户端。
                // Scan /proc/net/unix for pipewire-0 socket inodes, then find
                // 扫描 /proc/net/unix 找出 pipewire-0 套接字的 inode，然后查找讲解：先定位套接字 inode。
                // processes with fds pointing to those inodes. This catches any
                // 打开了指向这些 inode 的文件描述符的进程。这样可以捕获任何讲解：通过 fd 反查连接进程。
                // audio mixer daemon (goxlr-daemon, easyeffects, etc.) without
                // 音频混音守护进程（goxlr-daemon、easyeffects 等），而无需讲解：覆盖各类音频客户端。
                // brittle comm lists.
                // 依赖脆弱的进程名列表。讲解：避免硬编码进程名带来的遗漏。
                let core_count = audio_tgids.len();
                'pw_detect: {
                    let uid = unsafe { libc::getuid() };
                    let pw_socket_path = format!("/run/user/{}/pipewire-0", uid);

                    // Collect inodes for the PipeWire socket
                    // 收集 PipeWire 套接字对应的 inode。讲解：从 /proc/net/unix 提取套接字 inode 集合。
                    let unix_content = match std::fs::read_to_string("/proc/net/unix") {
                        Ok(c) => c,
                        Err(_) => break 'pw_detect,
                    };
                    let mut pw_inodes: HashSet<u64> = HashSet::new();
                    for line in unix_content.lines().skip(1) {
                        if line.ends_with(&pw_socket_path)
                            || line.contains(&format!("{} ", pw_socket_path))
                        {
                            // Format: Num RefCount Protocol Flags Type St Inode Path
                            // 格式：Num RefCount Protocol Flags Type St Inode Path。讲解：说明该行各字段含义，Inode 在第 7 列。
                            let fields: Vec<&str> = line.split_whitespace().collect();
                            if fields.len() >= 7 {
                                if let Ok(inode) = fields[6].parse::<u64>() {
                                    if inode > 0 {
                                        pw_inodes.insert(inode);
                                    }
                                }
                            }
                        }
                    }
                    if pw_inodes.is_empty() {
                        break 'pw_detect;
                    }

                    // Scan /proc/*/fd for socket links matching PipeWire inodes.
                    // 扫描 /proc/*/fd 中匹配 PipeWire inode 的套接字链接。讲解：遍历各进程的文件描述符找出连接者。
                    // Only check thread-group leaders (dirs in /proc with numeric names).
                    // 仅检查线程组组长（/proc 下以数字命名的目录）。讲解：只看主进程，忽略线程目录。
                    if let Ok(proc_entries) = std::fs::read_dir("/proc") {
                        for entry in proc_entries.flatten() {
                            if audio_tgids.len() >= 8 {
                                break;
                            }
                            let name = entry.file_name();
                            let name_str = name.to_string_lossy();
                            if !name_str.chars().all(|c| c.is_ascii_digit()) {
                                continue;
                            }
                            let pid: u32 = match name_str.parse() {
                                Ok(p) => p,
                                Err(_) => continue,
                            };
                            // Skip PIDs already detected as core audio
                            // 跳过已被识别为核心音频的 PID。讲解：避免重复统计阶段 1 已找到的进程。
                            if audio_tgid_set.contains(&pid) {
                                continue;
                            }
                            let fd_dir = format!("/proc/{}/fd", pid);
                            let fd_entries = match std::fs::read_dir(&fd_dir) {
                                Ok(e) => e,
                                Err(_) => continue,
                            };
                            for fd_entry in fd_entries.flatten() {
                                if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                                    let link_str = link.to_string_lossy();
                                    // Socket links look like "socket:[12345]"
                                    // 套接字链接形如 "socket:[12345]"。讲解：从符号链接中解析出套接字 inode 号。
                                    if let Some(inode_str) = link_str
                                        .strip_prefix("socket:[")
                                        .and_then(|s| s.strip_suffix(']'))
                                    {
                                        if let Ok(inode) = inode_str.parse::<u64>() {
                                            if pw_inodes.contains(&inode) {
                                                if audio_tgid_set.insert(pid) {
                                                    audio_tgids.push(pid);
                                                }
                                                break; // Found one match, move to next PID
                                                // 找到一个匹配，转到下一个 PID。讲解：确认是客户端即可停止扫描该进程的 fd。
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                rodata.nr_audio_tgids = audio_tgids.len() as u32;
                for (i, &tgid) in audio_tgids.iter().enumerate() {
                    rodata.audio_tgids[i] = tgid;
                }
                let client_count = audio_tgids.len() - core_count;
                if !audio_tgids.is_empty() {
                    info!(
                        "Audio stack detected: {} daemons{} (TGIDs: {:?})",
                        audio_tgids.len(),
                        if client_count > 0 {
                            format!(
                                ", {} PipeWire client{}",
                                client_count,
                                if client_count == 1 { "" } else { "s" }
                            )
                        } else {
                            String::new()
                        },
                        audio_tgids
                    );
                }
            }

            // ═══ Compositor detection ═══
            // ═══ 合成器检测 ═══。讲解：识别桌面合成器进程以便优先调度。
            // Wayland compositors present every frame to the display.
            // Wayland 合成器负责把每一帧呈现到显示器。讲解：合成器延迟直接影响画面流畅度。
            // Session-persistent → bake into RODATA.
            // 在整个会话期间持续存在 → 固化到 RODATA。讲解：一次检测后写入只读数据。
            {
                const COMPOSITOR_COMMS: &[&str] = &[
                    "kwin_wayland",
                    "kwin_x11",
                    "mutter",
                    "gnome-shell",
                    "sway",
                    "Hyprland",
                    "weston",
                    "labwc",
                    "wayfire",
                    "river",
                    "gamescope",
                ];
                let mut compositor_tgids: Vec<u32> = Vec::new();
                if let Ok(entries) = std::fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if !name_str.chars().all(|c| c.is_ascii_digit()) {
                            continue;
                        }
                        let pid: u32 = match name_str.parse() {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
                            let comm = comm.trim();
                            if COMPOSITOR_COMMS.contains(&comm) {
                                compositor_tgids.push(pid);
                                if compositor_tgids.len() >= 4 {
                                    break;
                                }
                            }
                        }
                    }
                }
                rodata.nr_compositor_tgids = compositor_tgids.len() as u32;
                for (i, &tgid) in compositor_tgids.iter().enumerate() {
                    rodata.compositor_tgids[i] = tgid;
                }
                if !compositor_tgids.is_empty() {
                    info!(
                        "Compositor detected: {} (TGIDs: {:?})",
                        compositor_tgids.len(),
                        compositor_tgids
                    );
                }
            }
        }

        // ═══ scx_ops_load! equivalent ═══
        // ═══ 等价于 scx_ops_load! ═══。讲解：这一段手工实现宏 scx_ops_load! 的加载功能。
        // Set UEI dump buffer size before load (matches scx_ops_load! behavior)
        // 在加载前设置 UEI 转储缓冲区大小（与 scx_ops_load! 行为一致）。讲解：为退出信息预留缓冲区。
        scx_utils::uei_set_size!(open_skel, cake_ops, uei);

        let mut skel = open_skel.load().context("Failed to load BPF program")?;

        // Initialize the BPF arena library.
        // 初始化 BPF arena 库。讲解：设置 BPF 使用的自定义内存分配区。
        // Must happen after load() (BPF maps are now live) but before attach_struct_ops()
        // 必须在 load() 之后（此时 BPF map 已就绪）但在 attach_struct_ops() 之前进行，讲解：时序要求严格。
        // (scheduler not yet running, so init_task hasn't fired yet).
        // （此时调度器尚未运行，因此 init_task 还未触发）。讲解：确保初始化早于任务处理。
        // ArenaLib::setup() runs SEC("syscall") probes:
        // ArenaLib::setup() 会运行 SEC("syscall") 探针：讲解：通过 syscall 类 BPF 程序完成初始化。
        //   1. arena_init: allocates static pages, inits task stack allocator
        //   1. arena_init：分配静态页，初始化任务栈分配器。讲解：准备 arena 基础内存。
        //   2. arena_topology_node_init: registers topology nodes for arena traversal
        //   2. arena_topology_node_init：为 arena 遍历注册拓扑节点。讲解：登记拓扑信息供后续使用。
        let task_ctx_size = std::mem::size_of::<bpf_intf::cake_task_ctx>();
        let arena = ArenaLib::init(skel.object_mut(), task_ctx_size, topo.nr_cpus)
            .context("Failed to create ArenaLib")?;
        arena.setup().context("Failed to initialize BPF arena")?;
        info!(
            "BPF arena initialized (task_ctx_size={}B, nr_cpus={})",
            task_ctx_size, topo.nr_cpus
        );

        // Set initial BSS values before attach (zero-init'd in BPF for BSS placement).
        // 在 attach 之前设置初始 BSS 值（BPF 中为放入 BSS 段而做零初始化）。讲解：预置可读写全局变量的初值。
        // quantum_ceiling_ns: default IDLE/GAMING → 2ms. TUI updates at ~2Hz.
        // quantum_ceiling_ns：默认 IDLE/GAMING → 2ms。TUI 以约 2Hz 更新。讲解：设置时间片上限默认值。
        if let Some(bss) = &mut skel.maps.bss_data {
            bss.quantum_ceiling_ns = 2_000_000; // AQ_BULK_CEILING_NS
            // AQ_BULK_CEILING_NS。讲解：对应的常量名，表示批量任务的时间片上限（纳秒）。
        }

        Ok(Self {
            skel,
            args,
            topology: topo,
            latency_matrix,
            struct_ops: None,
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        use libbpf_rs::skel::Skel;

        // ═══ scx_ops_attach! equivalent ═══
        // ═══ 等价于 scx_ops_attach! ═══。讲解：这一段手工实现宏 scx_ops_attach! 的挂载功能。
        // Guard: prevent loading if another sched_ext scheduler is already active
        // 保护性检查：如果已有另一个 sched_ext 调度器在运行，则阻止加载。讲解：避免多个调度器冲突。
        if scx_utils::compat::is_sched_ext_enabled().unwrap_or(false) {
            anyhow::bail!("another sched_ext scheduler is already running");
        }

        // Attach non-struct_ops BPF programs first, then struct_ops
        // 先挂载非 struct_ops 的 BPF 程序，再挂载 struct_ops。讲解：按正确顺序挂载，最后启用调度器主体。
        self.skel
            .attach()
            .context("Failed to attach non-struct_ops BPF programs")?;
        self.struct_ops = Some(
            self.skel
                .maps
                .cake_ops
                .attach_struct_ops()
                .context("Failed to attach struct_ops BPF programs")?,
        );

        // Release builds: --verbose and --testing are unavailable (stats compiled out).
        // Release 构建：--verbose 和 --testing 不可用（统计功能已被编译剔除）。讲解：正式版无遥测。
        // Warn early so user knows these flags require a debug build.
        // 提前告警，让用户知道这些标志需要 debug 构建。讲解：避免用户误以为选项无效。
        #[cfg(not(debug_assertions))]
        if self.args.verbose || self.args.testing {
            warn!("--verbose and --testing require a debug build (telemetry is compiled out in release).");
            warn!("Rebuild without --release: cargo build -p scx_cake");
            self.args.verbose = false;
            self.args.testing = false;
        }

        // Standard startup banner: follows scx_cosmos/scx_bpfland convention
        // 标准启动横幅：遵循 scx_cosmos/scx_bpfland 的约定。讲解：打印调度器名称、版本和 SMT 状态。
        info!(
            "{} {} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION")),
            if self.topology.smt_enabled {
                "SMT on"
            } else {
                "SMT off"
            }
        );

        // Print command line.
        // 打印命令行。讲解：输出启动时使用的完整命令行参数，便于排查。
        info!(
            "scheduler options: {}",
            std::env::args().collect::<Vec<_>>().join(" ")
        );

        info!(
            "{} CPUs, {} LLCs, profile: {:?}",
            self.topology.nr_cpus,
            self.topology
                .llc_cpu_mask
                .iter()
                .filter(|&&m| m != 0)
                .count()
                .max(1),
            self.args.profile
        );
        if self.args.testing {
            info!("Running in benchmarking mode for 10 seconds...");
            std::thread::sleep(std::time::Duration::from_secs(1)); // Warmup
            // 预热。讲解：先等 1 秒让调度器进入稳定状态再开始采样。

            let mut start_dispatches = 0u64;
            for cpu in 0..self.topology.nr_cpus {
                let stats = &self.skel.maps.bss_data.as_ref().unwrap().global_stats[cpu];
                start_dispatches += stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches;
            }

            let start_time = std::time::Instant::now();
            let mut elapsed = 0;
            while elapsed < 10 && !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(1));
                elapsed += 1;
            }
            let duration = start_time.elapsed().as_secs_f64();

            let mut end_dispatches = 0u64;
            for cpu in 0..self.topology.nr_cpus {
                let stats = &self.skel.maps.bss_data.as_ref().unwrap().global_stats[cpu];
                end_dispatches += stats.nr_new_flow_dispatches + stats.nr_old_flow_dispatches;
            }

            let delta = end_dispatches.saturating_sub(start_dispatches);
            let throughput = delta as f64 / duration;
            println!("{{\"duration_sec\": {:.2}, \"total_dispatches\": {}, \"dispatches_per_sec\": {:.2}}}",
                     duration, delta, throughput);

            shutdown.store(true, Ordering::Relaxed);
        } else if self.args.verbose && std::io::stdout().is_terminal() {
            // Run TUI mode
            // 运行 TUI 模式。讲解：在终端中启动实时统计界面。
            tui::run_tui(
                &mut self.skel,
                shutdown.clone(),
                self.args.interval,
                self.topology.clone(),
                self.latency_matrix.clone(),
            )?;
        } else {
            if self.args.verbose && !std::io::stdout().is_terminal() {
                warn!("TUI disabled: no terminal detected (headless mode)");
            }
            // Simple headless mode: matches cosmos/bpfland pattern exactly.
            // 简单的无界面模式：与 cosmos/bpfland 的模式完全一致。讲解：无终端时仅循环等待退出。
            // ctrlc handler sets shutdown on SIGINT/SIGTERM.
            // ctrlc 处理器在收到 SIGINT/SIGTERM 时设置 shutdown。讲解：捕获信号以优雅退出。
            // 1-second sleep + UEI check = responsive shutdown.
            // 每 1 秒睡眠 + UEI 检查 = 及时响应的退出。讲解：定期检查内核退出信息以快速停止。
            while !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(1));
                if scx_utils::uei_exited!(&self.skel, uei) {
                    break;
                }
            }
        }

        info!("{SCHEDULER_NAME} scheduler shutting down");

        // Drop struct_ops link BEFORE uei_report — this triggers the kernel to
        // 在 uei_report 之前释放 struct_ops 链接 —— 这会触发内核讲解：先解绑调度器再读退出信息。
        // set UEI kind=SCX_EXIT_UNREG. Matches scx_bpfland/scx_cosmos/scx_lavd
        // 将 UEI kind 设为 SCX_EXIT_UNREG。与 scx_bpfland/scx_cosmos/scx_lavd 讲解：标记为正常注销退出。
        // pattern: `let _ = self.struct_ops.take(); uei_report!(...)`
        // 模式一致：`let _ = self.struct_ops.take(); uei_report!(...)`。讲解：遵循标准退出处理顺序。
        let _ = self.struct_ops.take();

        // Standard UEI exit report — returns UserExitInfo for should_restart().
        // 标准 UEI 退出报告 —— 返回用于 should_restart() 判断的 UserExitInfo。讲解：据此决定是否需要重启调度器。
        scx_utils::uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    // Handle --version before anything else (matches cosmos/bpfland)
    // 在其他一切之前处理 --version（与 cosmos/bpfland 一致）。讲解：请求版本时立即打印并退出。
    if args.version {
        println!(
            "{} {}",
            SCHEDULER_NAME,
            build_id::full_version(env!("CARGO_PKG_VERSION"))
        );
        return Ok(());
    }

    // Set up signal handler: ctrlc handles both SIGINT and SIGTERM on Linux.
    // 设置信号处理器：在 Linux 上 ctrlc 会同时处理 SIGINT 和 SIGTERM。讲解：统一捕获中断/终止信号。
    // This is the same pattern cosmos/bpfland use — no SigSet blocking or
    // 这与 cosmos/bpfland 使用的模式相同 —— 无需 SigSet 阻塞或讲解：沿用现成简单方案。
    // SignalFd complexity needed.
    // SignalFd 的复杂处理。讲解：避免引入更复杂的信号机制。
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        info!("Received shutdown signal");
        shutdown_clone.store(true, Ordering::Relaxed);
    })?;

    // Create open object for BPF - needs to outlive scheduler
    // 为 BPF 创建 open object —— 它的生命周期需长于调度器。讲解：先创建容器以承载 BPF 对象。
    let mut open_object = std::mem::MaybeUninit::uninit();

    // Restart loop: matches cosmos/bpfland pattern.
    // 重启循环：与 cosmos/bpfland 的模式一致。讲解：内核请求重启时重新创建并运行调度器。
    // Kernel can request restart via UEI (e.g., CPU hotplug).
    // 内核可通过 UEI 请求重启（例如 CPU 热插拔）。讲解：拓扑变化时循环重新初始化。
    loop {
        let mut scheduler = Scheduler::new(args.clone(), &mut open_object)?;
        if !scheduler.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
