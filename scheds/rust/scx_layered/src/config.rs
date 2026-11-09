// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
use std::fs;
use std::io::Read;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::bpf_intf;
use crate::LayerGrowthAlgo;

use scx_utils::Cpumask;

/// JSON 顶层是 layer 数组；`serde(transparent)` 让数组直接反序列化到
/// `specs`，而不是要求额外的 `{"specs": ...}` 包装。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LayerConfig {
    pub specs: Vec<LayerSpec>,
}

/// 一个 JSON layer 对象的用户态表示。
///
/// 以 `scx_layered-vllm.json` 为例，反序列化关系是：
///
/// - 顶层数组元素 -> `LayerSpec`
/// - `matches` 外层数组 -> OR，内层数组 -> AND
/// - `{"CgroupPrefix": "..."}` -> `LayerMatch::CgroupPrefix`
/// - `{"kind":{"Grouped":{...}}}` -> `LayerKind::Grouped`
///
/// 此结构仍是配置；`Scheduler::init_layers()` 才会把需要进入热路径的字段
/// 拷贝为 BPF 的 `struct layer`。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerSpec {
    /// 层名。用于日志、统计和 BPF 调试输出，不参与匹配。
    pub name: String,
    /// 模板展开时由用户态生成，不从普通 JSON 读取。
    #[serde(skip)]
    pub cpuset: Option<Cpumask>,
    /// 纯说明性元数据。当前实现不会把它拷贝到 BPF，也不会影响调度。
    pub comment: Option<String>,
    /// 可选模板规则。用户态启动时扫描 cgroup，为每个命中对象复制
    /// LayerSpec 并生成静态 cpuset；普通配置为 None。
    pub template: Option<LayerMatch>,
    /// OR-of-AND：任一内层数组整体匹配即命中该层。
    /// 末层必须是 `[[]]`；空 AND 恒真，因此成为 catch-all。
    pub matches: Vec<Vec<LayerMatch>>,
    /// 外部标签 enum；JSON 形状为 `{"Grouped": {...}}` 等。
    pub kind: LayerKind,
}

impl LayerSpec {
    /// 解析一个位置参数。`f:`/`file:` 后面按文件读取，否则把参数本身当
    /// JSON。`main()` 会按参数和数组顺序拼接多个结果，因此顺序也就是
    /// BPF 首次命中优先级。
    pub fn parse(input: &str) -> Result<Vec<Self>> {
        let config: LayerConfig = if input.starts_with("f:") || input.starts_with("file:") {
            let mut f = fs::OpenOptions::new()
                .read(true)
                .open(input.split_once(':').unwrap().1)?;
            let mut content = String::new();
            f.read_to_string(&mut content)?;
            serde_json::from_str(&content)?
        } else {
            serde_json::from_str(input)?
        };
        Ok(config.specs)
    }

    pub fn nodes(&self) -> &Vec<usize> {
        &self.kind.common().nodes
    }

    pub fn llcs(&self) -> &Vec<usize> {
        &self.kind.common().llcs
    }

    pub fn nodes_mut(&mut self) -> &mut Vec<usize> {
        &mut self.kind.common_mut().nodes
    }

    pub fn llcs_mut(&mut self) -> &mut Vec<usize> {
        &mut self.kind.common_mut().llcs
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub enum LayerPlacement {
    /// 正常执行分层 idle 搜索和 LLC/NUMA 局部性策略。
    #[default]
    Standard,
    /// select_cpu 优先保留 previous CPU；不是 growth_algo 的 CPU 所有权粘性。
    Sticky,
    /// 跳过 previous LLC/node 局部性阶段，更积极在允许集合中浮动。
    Floating,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerMatch {
    /// 匹配 BPF 构造的无前导 `/`、有结尾 `/` 的 cgroup 路径。
    ///
    /// 例如 service 路径是 `system.slice/foo.service/`。配置值也带结尾
    /// `/` 时只覆盖该 cgroup 子树；不带时还会前缀命中
    /// `foo.service-extra/`。
    CgroupPrefix(String),
    CgroupSuffix(String),
    CgroupContains(String),
    CgroupRegex(String),
    CommPrefix(String),
    CommPrefixExclude(String),
    PcommPrefix(String),
    PcommPrefixExclude(String),
    NiceAbove(i32),
    NiceBelow(i32),
    NiceEquals(i32),
    UIDEquals(u32),
    GIDEquals(u32),
    PIDEquals(u32),
    PPIDEquals(u32),
    TGIDEquals(u32),
    NSPIDEquals(u64, u32),
    NSEquals(u32),
    CmdJoin(String),
    IsGroupLeader(bool),
    IsKthread(bool),
    UsedGpuTid(bool),
    UsedGpuPid(bool),
    AvgRuntime(u64, u64),
    HintEquals(u64),
    SystemCpuUtilBelow(f64),
    DsqInsertBelow(f64),
    NumaNode(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerCommon {
    /// 微秒。任务实际运行不足该值时，`stopping()` 仍至少按该值推进
    /// `dsq_vtime`。这是公平性计费下限，不保证任务连续运行这么久。
    #[serde(default)]
    pub min_exec_us: u64,
    /// `yield(2)` 时忽略的 slice 比例：[0,1]；0 表示放弃完整 slice，
    /// 1 表示完全忽略 yield 对剩余 slice 的扣减。
    #[serde(default)]
    pub yield_ignore: f64,
    /// 微秒。转换成 `struct layer::slice_ns` 后用于 direct dispatch 和
    /// layer DSQ；0 会在 `main()` 中替换成全局 `--slice-us`。
    #[serde(default)]
    pub slice_us: u64,
    /// true 时 layer DSQ 按 FIFO 插入；false 时按 `dsq_vtime` 排序。
    #[serde(default)]
    pub fifo: bool,
    /// 无 idle CPU 时，允许该层任务抢占当前非 preempt 层任务。
    #[serde(default)]
    pub preempt: bool,
    /// 仅在 `preempt=true` 时有效：唤醒时先尝试抢占 previous CPU，
    /// 再搜索 idle CPU，以延迟/缓存局部性换取潜在的额外抢占。
    #[serde(default)]
    pub preempt_first: bool,
    /// 尽量让 SMT sibling 保持 idle，使任务独占物理 core；这是性能策略，
    /// 不是安全隔离保证。
    #[serde(default)]
    pub exclusive: bool,
    /// 已废弃。node-aligned 任务现在总是允许进入 layer DSQ。
    #[serde(default, skip_serializing)]
    pub allow_node_aligned: Option<bool>,
    /// dispatch 拉取 layer DSQ 时跳过远端 NUMA node。
    #[serde(default)]
    pub skip_remote_node: bool,
    /// SMT 上选 idle CPU 时，先尝试 previous CPU，即使另有完整 idle core。
    #[serde(default)]
    pub prev_over_idle_core: bool,
    /// 层间 CPU 供给不足时，用户态统一分配器使用的权重。它不是
    /// `p->scx.weight`，不会直接按比例改变任务的 vtime 或时间片。
    /// 0 会在 `main()` 中替换成 100，并夹到 [1, 10000]。
    #[serde(default)]
    pub weight: u32,
    /// CPU 连续繁忙多久后，阻止普通 Open/Grouped 工作借用 owned CPU。
    /// None 由 main() 填全局默认；preempt 层强制为无限。
    #[serde(default)]
    pub disallow_open_after_us: Option<u64>,
    /// CPU 连续繁忙多久后，连其他 preempt 层也不能抢占 owned 工作。
    #[serde(default)]
    pub disallow_preempt_after_us: Option<u64>,
    /// 微秒。跨 LLC 选核或从远端 LLC DSQ 拉任务前，要求源 LLC 至少有
    /// 这么多估算排队运行时间；0 表示不因该阈值阻止跨 LLC。
    #[serde(default)]
    pub xllc_mig_min_us: f64,
    /// 已废弃的 SMT idle 选核开关，仅保留兼容解析并产生警告。
    #[serde(default, skip_serializing)]
    pub idle_smt: Option<bool>,
    /// 决定层扩缩时“先分配哪些 core”，不是任务级粘滞策略；
    /// 默认 `Sticky`。
    #[serde(default)]
    pub growth_algo: LayerGrowthAlgo,
    /// 最近利用率峰值的半衰期（毫秒），只延缓缩容；0 禁用峰值保持。
    #[serde(default)]
    pub util_peak_half_life_ms: u64,
    /// CPU performance hint，0 表示本层不调用
    /// `scx_bpf_cpuperf_set()`；非零值在任务开始运行时设置。
    #[serde(default)]
    pub perf: u64,
    /// 可选 CPU idle resume latency QoS（微秒）；由用户态写入 PM QoS。
    #[serde(default)]
    pub idle_resume_us: Option<u32>,
    /// 允许拥有 CPU 的 NUMA node ID；与 llcs 对应 CPU 集合取并集。
    #[serde(default)]
    pub nodes: Vec<usize>,
    /// 允许层拥有 CPU 的 LLC ID 集合。它限制用户态 owned-CPU 分配，
    /// 但 Grouped/Open 仍可能按各自语义借用层外 unprotected CPU。
    #[serde(default)]
    pub llcs: Vec<usize>,
    /// layer 内任务的选核放置模式，区别于 CPU 所有权 growth_algo。
    #[serde(default)]
    pub placement: LayerPlacement,
    /// UsedGpuPid/Tid 等动态成员资格的有效期（毫秒）；0 表示不过期。
    #[serde(default)]
    pub member_expire_ms: u64,
    /// xNUMA 迁移源启停的 node load 低/高水位，形成滞回。
    #[serde(default = "default_xnuma_threshold")]
    pub xnuma_threshold: (f64, f64),
    /// 相对全层均衡水位的 surplus 低/高阈值；与上一字段、growth_denied
    /// 同时决定是否允许从该 node 向外迁移。
    #[serde(default = "default_xnuma_threshold_delta")]
    pub xnuma_threshold_delta: (f64, f64),
}

fn default_xnuma_threshold() -> (f64, f64) {
    (0.6, 0.7)
}

fn default_xnuma_threshold_delta() -> (f64, f64) {
    (0.2, 0.3)
}

/// 层的 CPU 所有权和溢出策略。
///
/// 三种 kind 都复用 `LayerCommon`，但只有 Confined/Grouped 根据
/// `util_range` 动态请求 owned CPU；Open 接收池中剩余 CPU。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LayerKind {
    /// 用户态分配 owned CPU，普通选核和 dispatch 原则上不允许任务
    /// 使用层外 CPU；affinity/fallback/rescue 路径仍可能例外。
    Confined {
        /// 目标每 CPU 利用率的低/高水位。用户态反推可接受 CPU 数区间，
        /// 当前 CPU 数在区间内时保持不变，从而形成滞回。
        util_range: (f64, f64),
        /// owned 逻辑 CPU 数上下界。默认 [0, 全机 CPU 数]；在默认的
        /// whole-core 分配模式下，实际数量按 SMT core 粒度变化。
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,

        /// 用全机 CPU 比例表示的 owned CPU 上下界，与 cpus_range 互斥。
        #[serde(default)]
        cpus_range_frac: Option<(f64, f64)>,

        /// 可选 GiB/s 层带宽上限；用户态按观测到的每 CPU 带宽下调 target。
        #[serde(default)]
        membw_gb: Option<f64>,

        /// true 时 owned CPU 从 unprotected 集合移除，其他层不主动借用。
        #[serde(default)]
        protected: bool,

        /// 三种 kind 共享的时间片、抢占、拓扑和性能字段。
        #[serde(flatten)]
        common: LayerCommon,
    },
    /// 同样拥有动态 owned CPU；先用本层 CPU，但可借用层外
    /// unprotected idle CPU，因此比 Confined 更 work-conserving。
    Grouped {
        /// 与 Confined 相同，控制用户态 owned CPU 目标。
        util_range: (f64, f64),
        /// CPU 目标计算是否把本层在 borrowed/open CPU 上的运行时间计入 util；
        /// 层当前无 owned CPU 时无论此值如何都会计入，才能重新扩容。
        #[serde(default)]
        util_includes_open_cputime: bool,
        /// 与 Confined 相同，限制 owned CPU 数，不限制压力下借用的 CPU。
        #[serde(default)]
        cpus_range: Option<(usize, usize)>,

        /// 与 Confined 相同，按全机 CPU 比例限制 owned CPU。
        #[serde(default)]
        cpus_range_frac: Option<(f64, f64)>,

        /// 与 Confined 相同的可选内存带宽上限。
        #[serde(default)]
        membw_gb: Option<f64>,

        /// 与 Confined 相同；protected 与是否允许本层任务向外溢出是两回事。
        #[serde(default)]
        protected: bool,

        /// true 时先只在 owned CPU 中找 idle CPU；一次完整搜索失败并置
        /// `check_no_idle`，或用户态置 `fully_allocated` 后，再允许借用
        /// unprotected CPU。它只约束 idle 选核，不把 Grouped 变成严格
        /// Confined。
        #[serde(default)]
        idle_confined: bool,

        /// 三种 kind 共享字段。
        #[serde(flatten)]
        common: LayerCommon,
    },
    /// 不参与 `util_range` 目标计算；用户态把 Confined/Grouped 分配后
    /// 剩余且在 allowed_cpus 内的 CPU 作为其 owned mask。需要时仍可在
    /// 其他 unprotected CPU 上运行。
    Open {
        /// Open 没有 util/cpus target，只有共享策略字段。
        #[serde(flatten)]
        common: LayerCommon,
    },
}

impl LayerKind {
    pub fn as_bpf_enum(&self) -> i32 {
        match self {
            LayerKind::Confined { .. } => bpf_intf::layer_kind_LAYER_KIND_CONFINED as i32,
            LayerKind::Grouped { .. } => bpf_intf::layer_kind_LAYER_KIND_GROUPED as i32,
            LayerKind::Open { .. } => bpf_intf::layer_kind_LAYER_KIND_OPEN as i32,
        }
    }

    pub fn common(&self) -> &LayerCommon {
        match self {
            LayerKind::Confined { common, .. }
            | LayerKind::Grouped { common, .. }
            | LayerKind::Open { common, .. } => common,
        }
    }

    pub fn common_mut(&mut self) -> &mut LayerCommon {
        match self {
            LayerKind::Confined { common, .. }
            | LayerKind::Grouped { common, .. }
            | LayerKind::Open { common, .. } => common,
        }
    }

    pub fn util_range(&self) -> Option<(f64, f64)> {
        match self {
            LayerKind::Confined { util_range, .. } | LayerKind::Grouped { util_range, .. } => {
                Some(*util_range)
            }
            _ => None,
        }
    }

    pub fn util_includes_open_cputime(&self) -> bool {
        match self {
            LayerKind::Grouped {
                util_includes_open_cputime,
                ..
            } => *util_includes_open_cputime,
            _ => false,
        }
    }
}

/* 已经把详细说明补进源码，覆盖 8 个文件，只改注释，不改逻辑。

## 一、核心结构体

建议按下面顺序理解。

### 1. `LayerSpec / LayerCommon / LayerKind`
位置：`src/config.rs`

这是 JSON 的直接反序列化结果：

- `LayerSpec`
  - `name`：层名。
  - `comment`：纯说明。
  - `matches`：OR-of-AND 匹配规则。
  - `template/cpuset`：动态模板展开结果。
  - `kind`：Grouped、Confined 或 Open。
- `LayerCommon`
  - 时间策略：`min_exec_us`、`slice_us`、`yield_ignore`、`fifo`。
  - 抢占策略：`preempt`、`preempt_first`、`exclusive`。
  - CPU 保护：`disallow_open_after_us`、`disallow_preempt_after_us`。
  - 拓扑：`nodes`、`llcs`、`growth_algo`、`placement`。
  - 迁移：`xllc_mig_min_us`、`xnuma_threshold*`。
  - 性能：`weight`、`perf`、`idle_resume_us`。
  - 动态匹配：`member_expire_ms`。
- `LayerKind`
  - `util_range`：CPU 数量滞回水位。
  - `cpus_range/cpus_range_frac`：owned CPU 上下界。
  - `membw_gb`：带宽限制。
  - `protected`：owned CPU 是否禁止其他层借用。
  - `idle_confined`：Grouped 何时允许向外借 CPU。

### 2. 用户态 `Layer`
位置：`src/main.rs` 的 `struct Layer`

它不是任务热路径对象，而是用户态 CPU 分配器状态：

- `name/kind/growth_algo`：静态策略。
- `core_order[node]`：每个 NUMA node 内 core 的分配顺序。
- `assigned_llcs`：StickyDynamic 已占用的完整 LLC。
- `cpus`：当前 owned CPU bitmap。
- `allowed_cpus`：由 `nodes/llcs/cpuset` 得到的最大允许范围。
- `nr_cpus`：当前 owned CPU 总数。
- `nr_llc_cpus`：每个 LLC 的 owned CPU 数。
- `nr_node_cpus`：每个 NUMA node 的 owned CPU 数。
- `nr_pinned_cpus`：为不能跨 node 移动的任务保留的 CPU 数。

最重要的区别是：

- `allowed_cpus`：最多可以分到哪里。
- `cpus`：当前实际拥有哪里。
- Grouped/Open 任务运行时还可能借用 `cpus` 之外的 unprotected CPU。

### 3. 用户态 `Scheduler`
位置：`src/main.rs` 的 `struct Scheduler`

它持有整个控制平面：

- `skel/struct_ops`：BPF maps/programs 和调度器 attach link。
- `layer_specs/layers`：静态配置与动态 CPU 所有权。
- `cpu_pool`：全局未分配 CPU 池。
- `sched_intv`：默认 100ms 的控制周期。
- `sched_stats`：BPF 统计及上一周期快照。
- `layer_peak_utils`：延迟缩容的利用率峰值。
- `topo`：CPU/core/LLC/NUMA 拓扑。
- `xnuma_mig_src/growth_denied`：跨 NUMA 迁移状态。
- `cgroup_regexes`：动态 cgroup regex watcher。
- `netdevs`：可选 IRQ affinity 控制。
- `gpu_task_handler`：可选 NVIDIA NUMA affinity。
- `stats_server`：monitor 数据服务。

### 4. BPF `struct layer`
位置：`src/bpf/intf.h`

这是 JSON 策略在 BPF 中的最终镜像。

匹配部分：

- `matches/nr_match_ors`：固定大小 OR-of-AND。
- `id`：JSON 数组下标，也是 DSQ、统计数组索引。
- `name`：日志名称。
- `nr_tasks`：当前归属任务数。

时间与公平：

- `min_exec_ns`：最低 vtime 计费。
- `slice_ns`：调度量子。
- `yield_step_ns`：yield 扣除的 slice。
- `fifo`：FIFO 或 vtime DSQ。
- `weight`：用户态权重的镜像，BPF 当前不读取。
- `max_exec_ns`：当前未使用，真正上限来自全局 CLI。

调度策略：

- `kind`：Open、Grouped、Confined。
- `preempt/preempt_first`：抢占策略。
- `excl`：SMT core 独占倾向。
- `prev_over_idle_core`：previous CPU 局部性偏好。
- `idle_confined/fully_allocated`：Grouped 外借状态。
- `skip_remote_node/xllc_mig_min_ns`：跨拓扑迁移限制。
- `growth_algo/task_place`：CPU 所有权增长与任务放置策略。
- `perf`：CPU performance target。

CPU 所有权同步：

- `cpus[]`：用户态序列化的 CPU bitmap。
- `nr_cpus/nr_llc_cpus/node[]`：总数及拓扑分布。
- `refresh_cpus`：用户态提交更新的标志。
- `cpus_seq`：BPF mask 版本。
- `check_no_idle`：最近完整搜索是否确认无 idle CPU。
- `cpuset/has_cpuset`：静态模板 cpuset。
- `is_protected`：是否从 unprotected 集合排除。
- `periodically_refresh/member_expire_ms`：动态匹配刷新。

### 5. BPF `task_ctx`
位置：`src/bpf/main.bpf.c`

每个任务一个，存在 BPF task storage：

- 分类状态：`layer_id`、`refresh_layer`、`layer_refresh_seq`。
- CPU 历史：`last_cpu`、`llc_id`、`last_waker`。
- 派生 mask：
  - `layered_mask`：affinity ∩ layer CPU。
  - `layered_llc_mask`：再与 LLC 相交。
  - `layered_node_mask`：再与 node 相交。
  - `layered_unprotected_mask`：加入可借用 CPU。
- mask 版本：四组 `cached_cpus{id, seq}`。
- affinity 快速状态：
  - `all_cpus_allowed`
  - `all_cpuset_cpus_allowed`
  - `cpus_node_aligned`
  - `pinned_node`
- 时间统计：
  - `runnable_at/running_at`
  - `runtime_avg`：运行片段长度 EWMA。
  - `duty_cycle`：runnable 比例 EWMA。
  - `last_stopped_at`
- 队列状态：
  - `dsq_id`
  - `qrt_layer_id/qrt_llc_id`：当前 queued_runtime 贡献位置。
- 动态规则：`join_layer`、`recheck_layer_membership`。

### 6. BPF `cpu_ctx`
位置：`src/bpf/intf.h`

每个逻辑 CPU 一个：

- 当前执行：
  - `current_preempt`
  - `current_excl/prev_excl/next_excl`
  - `yielding`
  - `try_preempt_first`
- 抢占仲裁：
  - `preempting_task`
  - `preempting_at`
- owned 保护：
  - `protect_owned`
  - `protect_owned_preempt`
  - `running_owned/running_open/running_fallback`
- 统计：
  - `layer_usages`
  - `layer_membw_agg`
  - `node_pinned_usage`
  - `layer_duty_sum`
  - `gstats/lstats`
- CPU 所有权：
  - `layer_id`
  - `in_open_layers`
  - `is_protected`
- 拓扑：`cpu/llc_id/node_id/is_big/prox_map`。
- fallback：`hi_fb_dsq_id/lo_fb_dsq_id/lo_fb_seq*`。
- dispatch 顺序：`op/on/gp/gn/ogp/ogn_layer_order`。
- `perf`：最近设置的 performance target。

### 7. `llc_ctx / node_ctx / layer_node_ctx`

`llc_ctx`：

- `cpumask/nr_cpus`：LLC CPU 集合。
- `vtime_now[layer]`：每层每 LLC 独立公平时钟。
- `queued_runtime[layer]`：DSQ 剩余工作量估计。
- `prox_maps`：跨 LLC 拉取顺序。
- `lo_fb_seq/lstats`：fallback 和延迟统计。

`node_ctx`：

- `cpumask`：node 全部 CPU。
- `unprotected_cpumask`：Grouped/Open 可借用 CPU。
- `llcs/nr_llcs`：node 内 LLC。
- `empty_layer_ids`：本 node 没有 owned CPU 的层，供 fallback rescue。
- `prox_map`：跨 node 顺序。

`layer_node_ctx`：

- `nr_cpus/nr_pinned_tasks`：本层在本 node 的资源和刚性任务。
- `llcs_to_drain`：需要排空的遗留 LLC DSQ。
- `xnuma_is_mig_src/xnuma[]`：跨 NUMA 迁移开关和 token bucket。

## 二、关键函数调用链

启动路径：

1. `LayerSpec::parse()`：读取 `file:` JSON。
2. `main()`：填默认 slice/weight，展开模板。
3. `verify_layer_specs()`：检查最后 `[[]]`、数组上限、匹配规则。
4. `Scheduler::init()`：探测拓扑、open/load BPF、初始化 maps。
5. `Scheduler::init_layers()`：把 Rust 配置转换为 BPF `layers[]`。
6. attach `struct_ops`，进入 `Scheduler::run()`。

用户态 CPU 动态分配：

1. `Scheduler::step()` 读取 BPF 增量统计。
2. `calc_target_nr_cpus()` 用 `util_range` 算各层需求。
3. `calc_raw_demands()` 拆成 pinned/unpinned。
4. `unified_alloc()` 用 weight 和 node 容量解决冲突。
5. `CpuPool::free/alloc_cpus()` 先缩容、后扩容。
6. `update_bpf_layer_cpumask()` 写 BPF bitmap。
7. BPF `refresh_cpumasks()` 更新真正的 kptr cpumask、CPU owner 和版本号。

任务热路径：

1. `layered_init_task()`：创建 `task_ctx`。
2. `layered_select_cpu()`：尝试早期 idle 直派；新任务此时可能尚未分类。
3. `layered_runnable()` → `maybe_refresh_layer()`：
   - 构造 cgroup 路径。
   - 按 layer ID 调 `match_layer()`。
   - `switch_to_layer()` 提交分类。
4. `layered_enqueue()`：
   - preempt-first；
   - idle CPU；
   - 普通抢占；
   - high/low fallback；
   - layer+LLC DSQ。
5. `layered_dispatch()`：CPU 从 owner、Open/Grouped 或 fallback DSQ 拉任务。
6. `layered_running()`：提交迁移、owned/open、perf 状态。
7. `layered_stopping()`：结算 runtime、usage、保护状态和 vtime。

其中 `pick_idle_cpu()` 是选核核心，综合检查 affinity、kind、SMT、previous LLC、xLLC 门槛、NUMA、xNUMA token、unprotected CPU 和 `idle_confined`。

验证结果：

- `cargo check -p scx_layered` 通过。
- Rust 格式检查通过。
- IDE 无新增诊断。
- 当前总注释改动为 8 个文件，`+623/-322`。 */