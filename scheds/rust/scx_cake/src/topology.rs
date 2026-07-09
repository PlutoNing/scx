// SPDX-License-Identifier: GPL-2.0
// 采用 GPL-2.0 许可证。讲解：SPDX 许可证标识，供工具机读，声明本文件遵循的开源协议。
// Topology detection - CPUs, CCDs, P/E cores. Results passed to BPF as const volatile.
// 拓扑探测——识别 CPU、CCD（计算核心晶片）、P/E 核。结果以 const volatile 传给 BPF。
// 用户态探测硬件布局后注入内核 BPF 程序供调度决策使用。

use anyhow::Result;
use scx_utils::{CoreType, Topology};

/// Maximum supported CPUs (matches BPF array sizes)
/// 支持的最大 CPU 数（需与 BPF 数组大小一致）。上限固定以匹配内核侧静态数组。
pub const MAX_CPUS: usize = 64;
/// Maximum supported LLCs (matches BPF array sizes)
/// 支持的最大 LLC（末级缓存域）数（需与 BPF 数组大小一致）。同样与 BPF 静态数组对齐。
pub const MAX_LLCS: usize = 8;

/// Detected topology information
/// 探测得到的拓扑信息。汇总所有硬件布局字段，供调度器与 BPF 使用。
#[derive(Debug, Clone)]
pub struct TopologyInfo {
    /// Number of online CPUs
    /// 在线 CPU 数量。
    pub nr_cpus: usize,
    /// Number of physical cores (for PHYS_FIRST scan)
    /// 物理核心数（用于 PHYS_FIRST 扫描）
    pub nr_phys_cpus: usize,

    /// True if system has multiple L3 cache domains (CCDs)
    /// 若系统存在多个 L3 缓存域（CCD）则为 true。用于判断跨 CCD 的拓扑差异。
    pub has_dual_ccd: bool,

    /// True if system has hybrid P/E cores (Intel hybrid or similar)
    /// 若系统为 P/E 混合核（Intel 混合架构或类似）则为 true。区分大小核以做差异化调度。
    pub has_hybrid_cores: bool,

    /// SMT enabled status
    /// SMT（超线程）是否启用的状态。
    pub smt_enabled: bool,
    /// Map of CPU ID -> Sibling CPU ID (or self if none/disabled)
    /// CPU ID -> 兄弟 CPU ID 的映射（无兄弟或关闭时指向自身）。记录同核 SMT 线程的配对关系。
    pub cpu_sibling_map: [u8; MAX_CPUS],

    // BPF Maps
    // BPF 映射表。以下数组会传给 BPF 侧作为查表数据。
    pub cpu_llc_id: [u8; MAX_CPUS],
    pub cpu_is_big: [u8; MAX_CPUS],
    pub cpu_core_id: [u8; MAX_CPUS],
    pub cpu_thread_bit: [u8; MAX_CPUS],
    pub cpu_dsq_id: [u32; MAX_CPUS],
    /// Pre-computed 64-bit mask of all CPUs in a physical core
    /// 预计算的 64 位掩码，表示一个物理核内的所有 CPU。便于快速判断某核包含哪些逻辑 CPU。
    pub core_cpu_mask: [u64; 32],
    /// Bitmask requirement for a core to be "fully idle" (e.g. 0x3 for dual SMT)
    /// 判定物理核“完全空闲”所需的位掩码（如双 SMT 为 0x3）。只有掩码内全部线程空闲才算整核空闲。
    pub core_thread_mask: [u8; 32],
    pub llc_cpu_mask: [u64; MAX_LLCS],
    pub big_cpu_mask: u64,

    /// Heterogeneous Routing Masks
    /// 异构路由掩码。用于大小核/缓存差异下的任务分派。
    pub big_core_phys_mask: u64,
    pub big_core_smt_mask: u64,
    pub little_core_mask: u64,
    pub vcache_llc_mask: u64,
    pub has_vcache: bool,

    // Info
    // 信息。以下为附带的统计信息字段。
    pub cpus_per_ccd: u32,
}

/* 调度器启动时感知拓扑 */
pub fn detect() -> Result<TopologyInfo> {
    // robustly detect topology using scx_utils
    // 借助 scx_utils 稳健地探测拓扑。复用成熟库解析内核暴露的拓扑信息。
    let topo = Topology::new()?;

    let nr_cpus = topo.all_cpus.len();
    let nr_llcs = topo.all_llcs.len();

    // Get sibling map directly from scx_utils
    // 直接从 scx_utils 获取兄弟核映射。得到每个 CPU 的 SMT 兄弟线程。
    let siblings = topo.sibling_cpus();
    let mut cpu_sibling_map = [0u8; MAX_CPUS];

    // Default to self-mapping
    // 默认映射到自身。无兄弟线程时以自身填充，保证映射合法。
    for (i, sibling) in cpu_sibling_map.iter_mut().enumerate().take(MAX_CPUS) {
        *sibling = i as u8;
    }

    // Populate with detected siblings
    // 用探测到的兄弟核填充。将实际的 SMT 配对写入映射表。
    for (cpu, &sibling) in siblings.iter().enumerate() {
        if cpu < MAX_CPUS && sibling >= 0 {
            let sib = sibling as usize;
            if sib < MAX_CPUS {
                cpu_sibling_map[cpu] = sib as u8;
            }
        }
    }

    let mut info = TopologyInfo {
        nr_cpus,
        nr_phys_cpus: topo.all_cores.len(),
        has_dual_ccd: nr_llcs > 1,
        has_hybrid_cores: false, // Will detect below
        // 稍后再探测。先置为 false，后续根据 P/E 核数量再判定。
        smt_enabled: topo.smt_enabled,
        cpu_sibling_map,
        cpu_llc_id: [0; MAX_CPUS],
        cpu_is_big: [1; MAX_CPUS], // Default to 1 (Big) to be safe
        // 出于安全默认置为 1（大核）。未知时按大核处理，避免误判为小核限流。
        cpu_core_id: [0; MAX_CPUS],
        cpu_thread_bit: [0; MAX_CPUS],
        cpu_dsq_id: [0; MAX_CPUS],
        core_cpu_mask: [0; 32],
        core_thread_mask: [0; 32],
        llc_cpu_mask: [0; MAX_LLCS],
        big_cpu_mask: 0,

        // Heterogeneous Masks
        // 异构掩码。初始化大小核/缓存相关掩码字段。
        big_core_phys_mask: 0,
        big_core_smt_mask: 0,
        little_core_mask: 0,
        vcache_llc_mask: 0,
        has_vcache: false,

        cpus_per_ccd: 0,
    };

    // 1. Map LLCs
    // 1. 映射各 LLC。为每个末级缓存域建立掩码与编号。
    // Note: topo.all_llcs keys are arbitrary kernel IDs. We must map them to 0..MAX_LLCS-1.
    // We'll just use a simple counter 0,1,2... as we iterate.
    // 注意：topo.all_llcs 的键是内核任意 ID，必须重映射到 0..MAX_LLCS-1。
    // 迭代时直接用简单计数器 0,1,2... 作为编号。将不连续的内核 LLC ID 规整为紧凑索引以匹配 BPF 数组。
    let mut llc_idx = 0;

    for llc in topo.all_llcs.values() {
        if llc_idx >= MAX_LLCS {
            break;
        }

        let mut mask = 0u64;
        let mut core_count = 0;

        for cpu_id in llc.all_cpus.keys() {
            let cpu = *cpu_id;
            if cpu < MAX_CPUS {
                info.cpu_llc_id[cpu] = llc_idx as u8;
                mask |= 1u64 << cpu;
                core_count += 1;
            }
        }

        info.llc_cpu_mask[llc_idx] = mask;
        if info.cpus_per_ccd == 0 {
            info.cpus_per_ccd = core_count;
        } // Estimate
        // 估算值。以首个 LLC 的核数近似作为每 CCD 的 CPU 数。

        llc_idx += 1;
    }

    // 2. Identify P-cores vs E-cores and V-Cache
    // 2. 识别 P 核、E 核与 V-Cache。区分大小核并检测堆叠缓存（3D V-Cache）差异。
    info.cpu_is_big = [0; MAX_CPUS];
    info.big_cpu_mask = 0;
    info.big_core_phys_mask = 0;
    info.big_core_smt_mask = 0;
    info.little_core_mask = 0;
    info.vcache_llc_mask = 0;
    info.has_vcache = false;

    let mut p_cores_found = 0;
    let mut e_cores_found = 0;

    for (core_id_usize, core) in &topo.all_cores {
        let core_id = *core_id_usize;

        // Determine is_big.
        // 判定是否为大核。Little 类型记为 0，其余记为 1（大核）。
        let is_big = match core.core_type {
            CoreType::Little => 0,
            _ => 1,
        };

        if is_big == 1 {
            p_cores_found += 1;
        } else {
            e_cores_found += 1;
        }

        // Calculate SMT requirement mask for this core
        // 计算该核的 SMT 需求掩码。按线程数生成低位全 1 掩码，表示整核空闲所需的线程位。
        if core_id < 32 {
            info.core_thread_mask[core_id] = ((1u16 << core.cpus.len()) - 1) as u8;
        }

        // Iterate over CPUs in this core
        // 遍历该核内的各个 CPU。按序为每个逻辑 CPU 填写归属信息。
        let mut thread_idx = 0;
        let mut sorted_cpus: Vec<_> = core.cpus.keys().collect();
        sorted_cpus.sort();

        for cpu_id in sorted_cpus {
            let cpu = *cpu_id;
            if cpu < MAX_CPUS {
                info.cpu_is_big[cpu] = is_big;
                info.cpu_core_id[cpu] = core_id as u8;
                info.cpu_thread_bit[cpu] = 1 << thread_idx;
                info.cpu_dsq_id[cpu] = 1000 /* CAKE_DSQ_LC_BASE */ + cpu as u32;
                /* CAKE_DSQ_LC_BASE（本地 CPU 派发队列基址）。讲解：1000 为本地 DSQ 起始编号，加 CPU 号得到每核专属队列 ID。 */

                if core_id < 32 {
                    info.core_cpu_mask[core_id] |= 1u64 << cpu;
                }

                if is_big == 1 {
                    info.big_cpu_mask |= 1u64 << cpu;
                    if thread_idx == 0 {
                        info.big_core_phys_mask |= 1u64 << cpu;
                    } else {
                        info.big_core_smt_mask |= 1u64 << cpu;
                    }
                } else {
                    info.little_core_mask |= 1u64 << cpu;
                }

                thread_idx += 1;
            }
        }
    }

    // Evaluate V-Cache / LLC Asymmetry
    // 评估 V-Cache / LLC 的非对称性。讲解：比较各 LLC 缓存大小以发现堆叠缓存 CCD。
    let mut max_llc_cache_size = 0;
    let mut max_llc_idx = 0;

    // Find the LLC cluster with the absolute largest cache_size
    // 找出 cache_size 绝对最大的 LLC 簇。讲解：最大缓存簇很可能就是带 V-Cache 的 CCD。
    for llc in topo.all_llcs.values() {
        let mut cluster_cache_size = 0;
        if let Some(cpu) = llc.all_cpus.values().next() {
            cluster_cache_size += cpu.cache_size;
            // All CPUs in the LLC report the same size
            // 同一 LLC 内所有 CPU 报告的缓存大小相同。取任一 CPU 的值即可代表整簇。
        }

        if cluster_cache_size > max_llc_cache_size {
            max_llc_cache_size = cluster_cache_size;
            max_llc_idx = llc.id;
        }
    }

    // Verify if there is actual Cache Asymmetry (V-Cache detection)
    // We only flag V-Cache if there is MORE THAN 1 LLC and they have UNEQUAL cache sizes.
    // 校验是否存在真正的缓存非对称（V-Cache 检测）。
    // 仅当 LLC 多于 1 个且它们缓存大小不相等时才标记为 V-Cache。避免把对称多 CCD 误判为堆叠缓存。
    if info.has_dual_ccd {
        for llc in topo.all_llcs.values() {
            let mut expected_size = 0;
            if let Some(cpu) = llc.all_cpus.values().next() {
                expected_size += cpu.cache_size;
            }
            // Significant cache disparity = Asymmetric CCD (V-CACHE)
            // 显著的缓存差异 = 非对称 CCD（V-CACHE）。最大缓存超过某簇两倍即判定为堆叠缓存。
            if expected_size > 0 && max_llc_cache_size > (expected_size * 2) {
                info.has_vcache = true;
                if max_llc_idx < 8 {
                    info.vcache_llc_mask = info.llc_cpu_mask[max_llc_idx];
                }
            }
        }
    }

    // Update hybrid flag
    // 更新混合架构标志。同时存在 P 核与 E 核时才判定为混合架构。
    if p_cores_found > 0 && e_cores_found > 0 {
        info.has_hybrid_cores = true;
    } else {
        info.has_hybrid_cores = false;
        // On Homogeneous CPUs (Like 9800X3D), everything is a "Big Phys" core.
        // If there's no V-Cache Asymmetry, everything collapses perfectly to prevent extra BPF scans.
        // 在同构 CPU（如 9800X3D）上，所有核都视为“大物理核”。
        // 若无 V-Cache 非对称，则全部退化归一，从而避免额外的 BPF 扫描。
    }

    // Log detected topology (debug level - use RUST_LOG=debug to see)
    // 输出探测到的拓扑（debug 级别——用 RUST_LOG=debug 查看）。
    log::debug!("Topology detected:");
    log::debug!("  CPUs:          {}", info.nr_cpus);
    log::debug!("  Phys cores:    {}", info.nr_phys_cpus);
    log::debug!("  SMT Enabled:   {}", info.smt_enabled);
    log::debug!("  Dual CCD:      {}", info.has_dual_ccd);
    if info.has_dual_ccd {
        log::debug!("    Masks:       {:x?}", &info.llc_cpu_mask[..llc_idx]);
    }
    log::debug!("  Hybrid cores:  {}", info.has_hybrid_cores);
    if info.has_hybrid_cores {
        log::debug!("    P-core Phys mask: {:016x}", info.big_core_phys_mask);
        log::debug!("    E-core mask:      {:016x}", info.little_core_mask);
    }
    log::debug!("  V-Cache CCD:   {}", info.has_vcache);
    if info.has_vcache {
        log::debug!("    V-Cache mask: {:016x}", info.vcache_llc_mask);
    }

    Ok(info)
}
