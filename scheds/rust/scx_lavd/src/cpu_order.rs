// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2025 Valve Corporation.
// Author: Changwoo Min <changwoo@igalia.com>

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::anyhow;
use anyhow::Result;
use combinations::Combinations;
use itertools::iproduct;
use scx_utils::CoreType;
use scx_utils::Cpumask;
use scx_utils::EnergyModel;
use scx_utils::PerfDomain;
use scx_utils::PerfState;
use scx_utils::Topology;
use scx_utils::NR_CPU_IDS;
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use tracing::debug;

/* 描述系统的一个cpu? */
#[derive(Debug, Clone)]
pub struct CpuId {
    // - *_adx: an absolute index within a system scope
    // - *_rdx: a relative index under a parent
    //
    // - numa_adx: a NUMA domain within a system
    // - pd_adx: a performance domain (CPU frequency domain) within a system
    //   - llc_rdx: an LLC domain (CCX) under a NUMA domain
    //   - llc_kernel_id: physical LLC domain ID provided by the kernel
    //     - core_rdx: a core under a LLC domain
    //       - cpu_rdx: a CPU under a core
    /* numa_adx该 CPU 所属 NUMA 节点的全局绝对索引 */
    pub numa_adx: usize,
    /* pd_adx 所属性能域（CPU 频率域）的全局绝对索引 */
    pub pd_adx: usize,
    /* llc_adx所属 LLC（末级缓存/CCX）的全局绝对索引 */
    pub llc_adx: usize,
    /* llc_rdxLLC 在当前 NUMA 节点下的相对索引 */
    pub llc_rdx: usize,
    /* llc_kernel_id内核提供的物理 LLC ID */
    pub llc_kernel_id: usize,
    /* core_rdx核心在 LLC 下的相对索引 */
    pub core_rdx: usize,
    /* cpu_rdx该 CPU 在核心内的相对索引（0 = 物理核，>0 = SMT 超线程） */
    pub cpu_rdx: usize,
    /* cpu_adxCPU 的全局绝对索引 */
    pub cpu_adx: usize,
    /* smt_levelSMT 层级（0 = 非超线程，越大越靠后） */
    pub smt_level: usize,
    /* cache_size 缓存大小 */
    pub cache_size: usize,
    /* cpu_capCPU 算力容量（Capacity，反映芯片分档/大小核差异） */
    pub cpu_cap: usize,
    /* big_core 是否为大核（true = 大核 / 非 Little 核） */
    pub big_core: bool,
    /* turbo_core 是否为 Turbo 大核 */
    pub turbo_core: bool,
    /* cpu_sibling SMT 兄弟 CPU 的绝对索引 */
    pub cpu_sibling: usize,
}


/* 用作 BTreeMap 的键，唯一标识一个计算域：同一 NUMA 节点
 + 同一 LLC + 同类核（大核/小核）的 CPU 集合构成一个计算域。 */
#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct ComputeDomainId {
    pub numa_adx: usize,
    pub llc_adx: usize,
    pub llc_rdx: usize,
    pub llc_kernel_id: usize,
    pub is_big: bool,
}

#[derive(Debug, Clone)]
pub struct ComputeDomain {
    /* 本计算域的 ID（全局唯一递增） */
    pub cpdom_id: usize,
    /* 对应的"另一类型"计算域 ID（大核对应最近小核域，反之亦然），用于大小核之间的快速查找 */
    pub cpdom_alt_id: Cell<usize>,
    /* 该域包含的所有 CPU 绝对索引列表 */
    pub cpu_ids: Vec<usize>,
    /* 邻居域映射：距离 → 邻居域 ID 列表，按环形排序便于任务窃取时保持局部性 */
    pub neighbor_map: RefCell<BTreeMap<usize, RefCell<Vec<usize>>>>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PerfCpuOrder {
    /* 该档位能覆盖的最大性能容量上界 */
    pub perf_cap: usize,                 // performance in capacity
    /* 该档位对应的系统利用率（perf_cap / tot_perf） */
    pub perf_util: f32,                  // performance in utilization, [0, 1]
    /* 在该性能范围内优先使用的 CPU 列表（按偏好排序） */
    pub cpus_perf: RefCell<Vec<usize>>,  // CPU adx order within the performance range by @perf_cap
    /* 超出该性能范围后需额外启用的 CPU 列表（溢出/扩展列表） */
    pub cpus_ovflw: RefCell<Vec<usize>>, // CPU adx order beyond @perf_cap
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct CpuOrder {
    /* 系统中所有 CPU 的掩码 */
    pub all_cpus_mask: Cpumask,
    /* 按性能优先顺序排列的 CPU 拓扑信息列表 */
    pub cpuids: Vec<CpuId>,
    /* 性能容量 → PerfCpuOrder 的表，用于根据负载选择最优 CPU */
    pub perf_cpu_order: BTreeMap<usize, PerfCpuOrder>,
    /* 所有计算域的映射表 */
    pub cpdom_map: BTreeMap<ComputeDomainId, ComputeDomain>,
    /* 各层级拓扑数量统计 */
    pub nr_cpus: usize,
    pub nr_cores: usize,
    pub nr_cpdoms: usize,
    pub nr_llcs: usize,
    pub nr_numa: usize,
    /* 系统是否启用 SMT（超线程） */
    pub smt_enabled: bool,
    /* 系统是否有大小核架构 */
    pub has_biglittle: bool,
    /* 内核是否提供了能耗模型 */
    pub has_energy_model: bool,
}

impl CpuOrder {
    /// Build a cpu preference order with optional topology configuration.
    /// When @no_use_em is set, ignore the energy model even if the kernel
    /// provides one, so the CPU preference order is built as on a machine
    /// without an energy model.
    pub fn new(
        topology_args: Option<&scx_utils::TopologyArgs>,
        no_use_em: bool,
    ) -> Result<CpuOrder> {
        let ctx = CpuOrderCtx::new(topology_args, no_use_em)?;
        let cpus_pf = ctx.build_topo_order(false).unwrap();
        let cpus_ps = ctx.build_topo_order(true).unwrap();
        let cpdom_map = CpuOrderCtx::build_cpdom(&cpus_pf).unwrap();
        let perf_cpu_order = if ctx.em.is_ok() {
            let em = ctx.em.unwrap();
            EnergyModelOptimizer::get_perf_cpu_order_table(&em, &cpus_pf)
        } else {
            EnergyModelOptimizer::get_fake_perf_cpu_order_table(&cpus_pf, &cpus_ps)
        };

        let nr_cpdoms = cpdom_map.len();
        Ok(CpuOrder {
            all_cpus_mask: ctx.topo.span,
            cpuids: cpus_pf,
            perf_cpu_order,
            cpdom_map,
            nr_cpus: ctx.topo.all_cpus.len(),
            nr_cores: ctx.topo.all_cores.len(),
            nr_cpdoms,
            nr_llcs: ctx.topo.all_llcs.len(),
            nr_numa: ctx.topo.nodes.len(),
            smt_enabled: ctx.smt_enabled,
            has_biglittle: ctx.has_biglittle,
            has_energy_model: ctx.has_energy_model,
        })
    }
}

/// CpuOrderCtx is a helper struct used to build a CpuOrder
struct CpuOrderCtx {
    topo: Topology,
    em: Result<EnergyModel>,
    smt_enabled: bool,
    has_biglittle: bool,
    has_energy_model: bool,
}

impl CpuOrderCtx {
    /* 
    构建整个 CPU 排序信息。流程为：
通过 CpuOrderCtx::new() 读取系统拓扑和能耗模型
调用 build_topo_order(false) 生成性能优先的 CPU 顺序
调用 build_topo_order(true) 生成省电优先的 CPU 顺序
调用 build_cpdom() 构建计算域
若有能耗模型，用 get_perf_cpu_order_table() 生成精确的性能档位表；否则用 get_fake_perf_cpu_order_table() 生成简化版本
     */
    fn new(topology_args: Option<&scx_utils::TopologyArgs>, no_use_em: bool) -> Result<Self> {
        let topo = match topology_args {
            Some(args) => Topology::with_args(args)?,
            None => Topology::new()?,
        };

        let em = if no_use_em {
            Err(anyhow!("energy model disabled (--no-use-em)"))
        } else {
            EnergyModel::new()
        };
        let smt_enabled = topo.smt_enabled;
        let has_biglittle = topo.has_little_cores();
        let has_energy_model = em.is_ok();

        debug!("{:#?}", topo);
        debug!("{:#?}", em);

        Ok(CpuOrderCtx {
            topo,
            em,
            smt_enabled,
            has_biglittle,
            has_energy_model,
        })
    }

    /// Build a CPU preference order based on its optimization target
/* 遍历所有 NUMA → LLC → Core → CPU，构建 Vec<CpuId>，然后根据目标排序：
省电模式（无大小核）：优先高算力 CPU，再按 SMT 层级排，让尽量少的核运行在高频
省电模式（有大小核）：优先 LITTLE 小核（cpu_cap 升序），节省功耗
性能模式（通用）：优先物理核（cpu_rdx=0），再优先高算力 CPU，充分利用所有大核 */
    fn build_topo_order(&self, prefer_powersave: bool) -> Option<Vec<CpuId>> {
        let mut cpu_ids = Vec::new();
        let smt_siblings = self.topo.sibling_cpus();

        // Build a vector of cpu ids.
        for (&numa_adx, node) in self.topo.nodes.iter() {
            for (llc_rdx, (&llc_adx, llc)) in node.llcs.iter().enumerate() {
                for (core_rdx, (_core_adx, core)) in llc.cores.iter().enumerate() {
                    for (cpu_rdx, (cpu_adx, cpu)) in core.cpus.iter().enumerate() {
                        let cpu_adx = *cpu_adx;
                        let pd_adx = Self::get_pd_id(&self.em, cpu_adx, llc_adx);
                        let cpu_id = CpuId {
                            numa_adx,
                            pd_adx,
                            llc_adx,
                            llc_rdx,
                            core_rdx,
                            cpu_rdx,
                            cpu_adx,
                            smt_level: cpu.smt_level,
                            cache_size: cpu.cache_size,
                            cpu_cap: cpu.cpu_capacity,
                            big_core: cpu.core_type != CoreType::Little,
                            turbo_core: cpu.core_type == CoreType::Big { turbo: true },
                            cpu_sibling: smt_siblings[cpu_adx] as usize,
                            llc_kernel_id: llc.kernel_id,
                        };
                        cpu_ids.push(RefCell::new(cpu_id));
                    }
                }
            }
        }

        // Convert a vector of RefCell to a vector of plain cpu_ids
        let mut cpu_ids2 = Vec::new();
        for cpu_id in cpu_ids.iter() {
            cpu_ids2.push(cpu_id.borrow().clone());
        }
        let mut cpu_ids = cpu_ids2;

        // Sort the cpu_ids
        match (prefer_powersave, self.has_biglittle) {
            // 1. powersave,      no  big/little
            //     * within the same LLC domain
            //         - numa_adx, llc_rdx,
            //     * prefer more capable CPU with higher capacity
            //       and larger cache
            //         - ^cpu_cap (chip binning), ^cache_size,
            //     * prefer the SMT core within the same performance domain
            //         - pd_adx, core_rdx, ^smt_level, cpu_rdx
            (true, false) => {
                cpu_ids.sort_by(|a, b| {
                    a.numa_adx
                        .cmp(&b.numa_adx)
                        .then_with(|| a.llc_rdx.cmp(&b.llc_rdx))
                        .then_with(|| b.cpu_cap.cmp(&a.cpu_cap))
                        .then_with(|| b.cache_size.cmp(&a.cache_size))
                        .then_with(|| a.pd_adx.cmp(&b.pd_adx))
                        .then_with(|| a.core_rdx.cmp(&b.core_rdx))
                        .then_with(|| b.smt_level.cmp(&a.smt_level))
                        .then_with(|| a.cpu_rdx.cmp(&b.cpu_rdx))
                        .then_with(|| a.cpu_adx.cmp(&b.cpu_adx))
                });
            }
            // 2. powersave,      yes big/little
            //     * within the same LLC domain
            //         - numa_adx, llc_rdx,
            //     * prefer energy-efficient LITTLE CPU with a larger cache
            //         - cpu_cap (big/little), ^cache_size,
            //     * prefer the SMT core within the same performance domain
            //         - pd_adx, core_rdx, ^smt_level, cpu_rdx
            (true, true) => {
                cpu_ids.sort_by(|a, b| {
                    a.numa_adx
                        .cmp(&b.numa_adx)
                        .then_with(|| a.llc_rdx.cmp(&b.llc_rdx))
                        .then_with(|| a.cpu_cap.cmp(&b.cpu_cap))
                        .then_with(|| b.cache_size.cmp(&a.cache_size))
                        .then_with(|| a.pd_adx.cmp(&b.pd_adx))
                        .then_with(|| a.core_rdx.cmp(&b.core_rdx))
                        .then_with(|| b.smt_level.cmp(&a.smt_level))
                        .then_with(|| a.cpu_rdx.cmp(&b.cpu_rdx))
                        .then_with(|| a.cpu_adx.cmp(&b.cpu_adx))
                });
            }
            // 3. performance,    no  big/little
            // 4. performance,    yes big/little
            //     * prefer the non-SMT core
            //         - cpu_rdx,
            //     * fill the same LLC domain first
            //         - numa_adx, llc_rdx,
            //     * prefer more capable CPU with higher capacity
            //       (chip binning or big/little) and larger cache
            //         - ^cpu_cap, ^cache_size, smt_level
            //     * within the same power domain
            //         - pd_adx, core_rdx
            _ => {
                cpu_ids.sort_by(|a, b| {
                    a.cpu_rdx
                        .cmp(&b.cpu_rdx)
                        .then_with(|| a.numa_adx.cmp(&b.numa_adx))
                        .then_with(|| a.llc_rdx.cmp(&b.llc_rdx))
                        .then_with(|| b.cpu_cap.cmp(&a.cpu_cap))
                        .then_with(|| b.cache_size.cmp(&a.cache_size))
                        .then_with(|| a.smt_level.cmp(&b.smt_level))
                        .then_with(|| a.pd_adx.cmp(&b.pd_adx))
                        .then_with(|| a.core_rdx.cmp(&b.core_rdx))
                        .then_with(|| a.cpu_adx.cmp(&b.cpu_adx))
                });
            }
        }

        Some(cpu_ids)
    }

    /// Build a list of compute domains
    /* 构建计算域
按 (NUMA节点, LLC, 核心类型) 三元组将 CPU 分组为计算域
用笛卡尔积计算每对计算域间的距离（核心类型差异 > NUMA 差异 > LLC 差异）
对每个域的邻居列表进行环形排序（circular_sort）：使得相邻域在任务窃取时被优先访问，减少缓存行颠簸
为每个域填充 cpdom_alt_id：找到同 LLC 下对应的另一种核（大核→小核，小核→大核），用于跨类型调度 */
    fn build_cpdom(cpu_ids: &Vec<CpuId>) -> Option<BTreeMap<ComputeDomainId, ComputeDomain>> {
        // Note that building compute domain is independent to CPU order
        // so it is okay to use any cpus_*.

        // Create a compute domain map, where a compute domain is a CPUs that
        // are under the same node and LLC (virtual and physical) and have the same core type.
        let mut cpdom_id = 0;
        let mut cpdom_map: BTreeMap<ComputeDomainId, ComputeDomain> = BTreeMap::new();
        let mut cpdom_types: BTreeMap<usize, bool> = BTreeMap::new();
        for cpu_id in cpu_ids.iter() {
            let key = ComputeDomainId {
                numa_adx: cpu_id.numa_adx,
                llc_adx: cpu_id.llc_adx,
                llc_rdx: cpu_id.llc_rdx,
                llc_kernel_id: cpu_id.llc_kernel_id,
                is_big: cpu_id.big_core,
            };
            let value = cpdom_map.entry(key.clone()).or_insert_with(|| {
                let val = ComputeDomain {
                    cpdom_id,
                    cpdom_alt_id: Cell::new(cpdom_id),
                    cpu_ids: Vec::new(),
                    neighbor_map: RefCell::new(BTreeMap::new()),
                };
                cpdom_types.insert(cpdom_id, key.is_big);

                cpdom_id += 1;
                val
            });
            value.cpu_ids.push(cpu_id.cpu_adx);
        }

        // Build a neighbor map for each compute domain, where neighbors are
        // ordered by core type, node, and LLC.
        for ((from_k, from_v), (to_k, to_v)) in iproduct!(cpdom_map.iter(), cpdom_map.iter()) {
            if from_k == to_k {
                continue;
            }

            let d = Self::dist(from_k, to_k);
            let mut map = from_v.neighbor_map.borrow_mut();
            match map.get(&d) {
                Some(v) => {
                    v.borrow_mut().push(to_v.cpdom_id);
                }
                None => {
                    map.insert(d, RefCell::new(vec![to_v.cpdom_id]));
                }
            }
        }

        // Circular sort compute domains within the same distance to preserve
        // proximity between domains.
        //
        // Suppose that domains 0, 1, 2, 3, 4, 5, 6, 7 are at the same distance.
        //            0
        //         7     1
        //       6         2
        //         5     3
        //            4
        //
        // We want to traverse the domains from 0. The circular-sorted order
        // starting from domain 0 is 0, 1, 7, 2, 6, 3, 5, 4. Similarly,
        // the order starting from domain 1 is 1, 0, 2, 3, 7, 4, 6, 5.
        // The one from 7 is 7, 0, 6, 1, 5, 2, 4, 3. As follows, circularly
        // sorted orders in task stealing preserve proximity between domains
        // (e.g., 0, 1, 7 in the example), so we can achieve less cacheline
        // bouncing than with random-ordered task stealing.
        for (_, cpdom) in cpdom_map.iter() {
            for (_, neighbors) in cpdom.neighbor_map.borrow_mut().iter() {
                let mut neighbors_csorted =
                    Self::circular_sort(cpdom.cpdom_id, &neighbors.borrow_mut().to_vec());
                neighbors.borrow_mut().clear();
                neighbors.borrow_mut().append(&mut neighbors_csorted);
            }
        }

        // Fill up cpdom_alt_id for each compute domain.
        for (k, v) in cpdom_map.iter() {
            let mut key = k.clone();
            key.is_big = !k.is_big;

            if let Some(alt_v) = cpdom_map.get(&key) {
                // First, try to find an alternative domain
                // under the same node/LLC.
                v.cpdom_alt_id.set(alt_v.cpdom_id);
            } else {
                // If there is no alternative domain in the same node/LLC,
                // choose the closest one.
                //
                // Note that currently, the idle CPU selection (pick_idle_cpu)
                // is not optimized for this kind of architecture, where big
                // and LITTLE cores are in different node/LLCs.
                'outer: for (_dist, ncpdoms) in v.neighbor_map.borrow().iter() {
                    for ncpdom_id in ncpdoms.borrow().iter() {
                        if let Some(is_big) = cpdom_types.get(ncpdom_id) {
                            if *is_big == key.is_big {
                                v.cpdom_alt_id.set(*ncpdom_id);
                                break 'outer;
                            }
                        }
                    }
                }
            }
        }

        Some(cpdom_map)
    }

    /// Circular sorting of a list from a starting point
    
    /* 环形排序
给定起点 start 和其他域 ID，将它们按"距离起点的环形距离"从近到远排序。例如 8 个域排成一圈，
从域 0 出发的顺序是 0, 1, 7, 2, 6, 3, 5, 4，保证任务窃取时优先访问最近的邻居。 */
    fn circular_sort(start: usize, the_rest: &Vec<usize>) -> Vec<usize> {
        // Create a full list including 'start'
        let mut list = the_rest.clone();
        list.push(start);
        list.sort();

        // Get the index of 'start'
        let s = list
            .binary_search(&start)
            .expect("start must appear exactly once");

        // Get the circularly sorted index list.
        let n = list.len();
        let dist = |x: usize| {
            let d = (x + n - s) % n;
            d.min(n - d)
        };
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&x| (dist(x), x));

        // Rearrange the full list
        // according to the circularly sorted index list.
        let list_csorted: Vec<_> = order.iter().map(|&i| list[i]).collect();

        // Drop 'start' from the rearranged full list.
        list_csorted[1..].to_vec()
    }

    /// Get the performance domain (i.e., CPU frequency domain) ID for a CPU.
    /// If the energy model is not available, use LLC ID instead.
    fn get_pd_id(em: &Result<EnergyModel>, cpu_adx: usize, llc_adx: usize) -> usize {
        match em {
            Ok(em) => em.get_pd_by_cpu_id(cpu_adx).unwrap().id,
            Err(_) => llc_adx,
        }
    }

    /// Calculate distance from two compute domains
    fn dist(from: &ComputeDomainId, to: &ComputeDomainId) -> usize {
        let mut d = 0;
        // core type > numa node > llc
        if from.is_big != to.is_big {
            d += 100;
        }
        if from.numa_adx != to.numa_adx {
            d += 10;
        } else {
            if from.llc_rdx != to.llc_rdx {
                d += 1;
            }
            if from.llc_kernel_id != to.llc_kernel_id {
                d += 1;
            }
        }
        d
    }
}

#[derive(Debug)]
struct EnergyModelOptimizer<'a> {
    /* 系统能耗模型引用 */
    // Energy model of performance domains
    em: &'a EnergyModel,

    // CPU preference order in a performance mode purely based on topology
    /* 按拓扑顺序排列的 CPU 绝对索引，用于最终排序 */
    cpus_topological_order: Vec<usize>,

    // CPU preference order within a performance domain
    /* 每个性能域内的 CPU 偏好顺序 */
    pd_cpu_order: BTreeMap<usize, RefCell<Vec<usize>>>,

    // Total performance capacity of the system
    /* 系统总性能容量 */
    tot_perf: usize,

    // All possible combinations of performance domains & states
    // indexed by performance.
    /* 所有可能的性能域+状态组合，以性能容量为键，保留相同性能下功耗最低的组合集 */
    pdss_infos: RefCell<BTreeMap<usize, RefCell<HashSet<PDSetInfo<'a>>>>>,

    // Performance domains and states to achieve a certain performance level,
    // which is derived from @pdss_infos.
    /* 经过筛选后的"性能 → 最优域集合"表，最终用于构建 perf_cpu_order */
    perf_pdsi: RefCell<BTreeMap<usize, PDSetInfo<'a>>>,

    // CPU orders indexed by performance
    /* 最终生成的性能档位 CPU 排序表 */
    perf_cpu_order: RefCell<BTreeMap<usize, PerfCpuOrder>>,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialOrd)]
struct PDS<'a> {
    pd: &'a PerfDomain,
    ps: &'a PerfState,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialOrd)]
struct PDCpu<'a> {
    pd: &'a PerfDomain, // performance domain
    cpu_vid: usize,     // virtual ID of a CPU on the performance domain
}

#[derive(Debug, Clone, Eq)]
struct PDSetInfo<'a> {
    performance: usize,
    power: usize,
    pdcpu_set: BTreeSet<PDCpu<'a>>,
    pd_id_set: BTreeSet<usize>, // pd:id:0, pd:id:1
}

const PD_UNIT: usize = 100_000_000;
const CPU_UNIT: usize = 100_000;
const LOOKAHEAD_CNT: usize = 10;

impl<'a> EnergyModelOptimizer<'a> {
    fn new(em: &'a EnergyModel, cpus_pf: &'a Vec<CpuId>) -> EnergyModelOptimizer<'a> {
        let tot_perf = em.perf_total();

        let pdss_infos: BTreeMap<usize, RefCell<HashSet<PDSetInfo<'a>>>> = BTreeMap::new();
        let pdss_infos = pdss_infos.into();

        let perf_pdsi: BTreeMap<usize, PDSetInfo<'a>> = BTreeMap::new();
        let perf_pdsi = perf_pdsi.into();

        let mut pd_cpu_order: BTreeMap<usize, RefCell<Vec<usize>>> = BTreeMap::new();
        let mut cpus_topological_order: Vec<usize> = vec![];
        for cpuid in cpus_pf.iter() {
            match pd_cpu_order.get(&cpuid.pd_adx) {
                Some(v) => {
                    let mut v = v.borrow_mut();
                    v.push(cpuid.cpu_adx);
                }
                None => {
                    let v = vec![cpuid.cpu_adx];
                    pd_cpu_order.insert(cpuid.pd_adx, v.into());
                }
            }
            cpus_topological_order.push(cpuid.cpu_adx);
        }

        let perf_cpu_order: BTreeMap<usize, PerfCpuOrder> = BTreeMap::new();
        let perf_cpu_order = perf_cpu_order.into();

        debug!("# pd_cpu_order");
        debug!("{:#?}", pd_cpu_order);

        EnergyModelOptimizer {
            em,
            cpus_topological_order,
            pd_cpu_order,
            tot_perf,
            pdss_infos,
            perf_pdsi,
            perf_cpu_order,
        }
    }

    /* 第一步 gen_all_pds_combinations()：枚举所有性能域+P-state 的组合，用二分递归探索 0%~100%
     利用率区间，对每种性能容量保留功耗最低的域集合。

第二步 gen_perf_pds_table()：从上述组合中，针对 5%, 10%, 20%...100% 等利用率目标，各选一个最优的域集合
（PDSetInfo），优先最小化活跃性能域数量（减少漏电），并最大化与前一档位的重叠（减少域切换开销）。

第三步 assign_cpu_vids()：将每个性能档位的域集合映射到具体 CPU，生成按拓扑顺序排列的 cpus_perf
（主要 CPU 列表）和 cpus_ovflw（超载溢出 CPU 列表），最终填入 perf_cpu_order 表中。 */
    fn get_perf_cpu_order_table(
        em: &'a EnergyModel,
        cpus_pf: &'a Vec<CpuId>,
    ) -> BTreeMap<usize, PerfCpuOrder> {
        let emo = EnergyModelOptimizer::new(em, &cpus_pf);
        emo.gen_perf_cpu_order_table();
        let perf_cpu_order = emo.perf_cpu_order.borrow().clone();

        perf_cpu_order
    }

    fn get_fake_perf_cpu_order_table(
        cpus_pf: &'a Vec<CpuId>,
        cpus_ps: &'a Vec<CpuId>,
    ) -> BTreeMap<usize, PerfCpuOrder> {
        let tot_perf: usize = cpus_pf.iter().map(|cpuid| cpuid.cpu_cap).sum();

        let pco_pf = Self::fake_pco(tot_perf, cpus_pf, false);
        let pco_ps = Self::fake_pco(tot_perf, cpus_ps, true);

        let mut perf_cpu_order: BTreeMap<usize, PerfCpuOrder> = BTreeMap::new();
        perf_cpu_order.insert(pco_pf.perf_cap, pco_pf);
        perf_cpu_order.insert(pco_ps.perf_cap, pco_ps);

        perf_cpu_order
    }

    fn fake_pco(tot_perf: usize, cpuids: &'a Vec<CpuId>, powersave: bool) -> PerfCpuOrder {
        let perf_cap;

        if powersave {
            perf_cap = cpuids[0].cpu_cap;
        } else {
            perf_cap = tot_perf;
        }

        let perf_util: f32 = (perf_cap as f32) / (tot_perf as f32);
        let cpus: Vec<usize> = cpuids.iter().map(|cpuid| cpuid.cpu_adx).collect();
        let cpus_perf: Vec<usize> = cpus[..1].iter().map(|&cpuid| cpuid).collect();
        let cpus_ovflw: Vec<usize> = cpus[1..].iter().map(|&cpuid| cpuid).collect();
        PerfCpuOrder {
            perf_cap,
            perf_util,
            cpus_perf: cpus_perf.clone().into(),
            cpus_ovflw: cpus_ovflw.clone().into(),
        }
    }

    /// Generate the performance versus CPU preference order table based on
    /// the system's CPU topology and energy model. The table consists of the
    /// following information (PerfCpuOrder):
    ///
    ///   - PerfCpuOrder::perf_cap: The upper bound of the performance
    ///     capacity covered by this tuple.
    ///
    ///   - PerfCpuOrder::cpus_perf: Primary CPUs to be used is ordered
    ///     by preference.
    ///
    ///   - PerfCpuOrder::cpus_ovrflw: When the system load goes beyond
    ///     @perf_cap, the list of CPUs to be used is ordered by preference.
    fn gen_perf_cpu_order_table(&'a self) {
        // First, generate all possible combinations of CPUs (e.g., two CPUs
        // in performance domain 0 and three CPUs in performance domain 1) to
        // achieve the possible performance capacities with minimal energy
        // consumption. We assume a reasonable load balancer, so the
        // utilization of the used CPUs is similar.
        self.gen_all_pds_combinations();

        // Then, from all the possible combinations of performance versus
        // CPU sets, select a list of combinations that minimize the number of
        // active performance domains and reduce the number of performance
        // domain switches when changing performance levels.
        self.gen_perf_pds_table();

        // Finally, assign CPUs (@cpu_adx) to the virtual CPU ID (@cpu_vid) of
        // a performance domain.
        self.assign_cpu_vids();
    }

    /// Generate a CPU order table for each performance range.
    fn assign_cpu_vids(&'a self) {
        // Generate CPU order within the performance range (@cpus_perf).
        for (&perf_cap, pdsi) in self.perf_pdsi.borrow().iter() {
            let mut cpus_perf: Vec<usize> = vec![];

            for pdcpu in pdsi.pdcpu_set.iter() {
                let pd_id = pdcpu.pd.id;
                let cpu_vid = pdcpu.cpu_vid;
                let cpu_order = self.pd_cpu_order.get(&pd_id).unwrap().borrow();
                let cpu_adx = cpu_order[cpu_vid];
                cpus_perf.push(cpu_adx);
            }

            let perf_util: f32 = (perf_cap as f32) / (self.tot_perf as f32);
            let cpus_perf = self.sort_cpus_by_topological_order(&cpus_perf);
            let cpus_ovflw: Vec<usize> = vec![];

            let mut perf_cpu_order = self.perf_cpu_order.borrow_mut();
            perf_cpu_order.insert(
                perf_cap,
                PerfCpuOrder {
                    perf_cap,
                    perf_util,
                    cpus_perf: cpus_perf.clone().into(),
                    cpus_ovflw: cpus_ovflw.clone().into(),
                },
            );
        }

        // Generate CPU order beyond the performance range (@cpus_ovflw).
        let perf_cpu_order = self.perf_cpu_order.borrow();
        let perf_caps: Vec<_> = self.perf_pdsi.borrow().keys().cloned().collect();
        for o in 1..perf_caps.len() {
            // Gather all @cpus_perf from the upper performance ranges.
            let ovrflw_perf_caps = &perf_caps[o..];
            let mut ovrflw_cpus_all: Vec<usize> = vec![];
            for perf_cap in ovrflw_perf_caps.iter() {
                let cpu_order = perf_cpu_order.get(perf_cap).unwrap();
                let cpus_perf = cpu_order.cpus_perf.borrow();
                ovrflw_cpus_all.extend(cpus_perf.iter().cloned());
            }

            // Filter out already taken CPUs from the @ovrflw_cpus_all,
            // and build @cpus_ovrflw.
            let mut cpu_set = HashSet::<usize>::new();
            let perf_cap = perf_caps[o - 1];
            let cpu_order = perf_cpu_order.get(&perf_cap).unwrap();
            let cpus_perf = cpu_order.cpus_perf.borrow();
            for &cpu_adx in cpus_perf.iter() {
                cpu_set.insert(cpu_adx);
            }

            let mut cpus_ovflw: Vec<usize> = vec![];
            for &cpu_adx in ovrflw_cpus_all.iter() {
                if cpu_set.get(&cpu_adx).is_none() {
                    cpus_ovflw.push(cpu_adx);
                    cpu_set.insert(cpu_adx);
                }
            }

            // Inject the constructed @cpus_ovrflw to the table.
            let mut v = cpu_order.cpus_ovflw.borrow_mut();
            v.extend(cpus_ovflw.iter().cloned());
        }

        // Debug print of the generated table
        debug!("## gen_perf_cpu_order_table");
        debug!("{:#?}", perf_cpu_order);
    }

    /// Sort the CPU IDs by topological order (@self.cpus_topological_order).
    fn sort_cpus_by_topological_order(&'a self, cpus: &Vec<usize>) -> Vec<usize> {
        let mut sorted: Vec<usize> = vec![];
        for &cpu_adx in self.cpus_topological_order.iter() {
            if let Some(_) = cpus.iter().find(|&&x| x == cpu_adx) {
                sorted.push(cpu_adx);
            }
        }
        sorted
    }

    /// Generate a table of performance vs. performance domain sets
    /// (@self.perf_pdss) from all the possible performance domain & state
    /// combinations (@self.pdss_infos).
    ///
    /// An example result is as follows:
    ///     PERF: [_, 300]
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 0 -- cpu_vid: 1
    ///     PERF: [_, 1138]
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 0 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///     PERF: [_, 3386]
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///     PERF: [_, 3977]
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///     PERF: [_, 4508]
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 0 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///     PERF: [_, 5627]
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 0 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///             pd:id: 3 -- cpu_vid: 0
    fn gen_perf_pds_table(&'a self) {
        let utils = vec![0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];

        // Find the best performance domains for each system utilization target.
        for &util in utils.iter() {
            let mut best_pdsi: Option<PDSetInfo<'a>>;
            let mut del_pdsi: Option<PDSetInfo<'a>> = None;

            match self.perf_pdsi.borrow().last_key_value() {
                Some((_, base)) => {
                    best_pdsi = self.find_perf_pds_for(util, Some(base));

                    // If the next performance level (@best_pdsi) is subsumed
                    // by the previous level (@base), extend the base to the
                    // next level. To this end, insert the extended base (with
                    // updated performance and power values) and delete the old
                    // base.
                    if let Some(ref best) = best_pdsi {
                        if best.pdcpu_set.is_subset(&base.pdcpu_set) {
                            let ext_pdcpu = PDSetInfo {
                                performance: best.performance,
                                power: best.power,
                                pdcpu_set: base.pdcpu_set.clone(),
                                pd_id_set: base.pd_id_set.clone(),
                            };
                            best_pdsi = Some(ext_pdcpu);
                            del_pdsi = Some(base.clone());
                        }
                    }
                }
                None => {
                    best_pdsi = self.find_perf_pds_for(util, None);
                }
            };

            if let Some(best_pdsi) = best_pdsi {
                self.perf_pdsi
                    .borrow_mut()
                    .insert(best_pdsi.performance, best_pdsi);
            }

            if let Some(del_pdsi) = del_pdsi {
                self.perf_pdsi.borrow_mut().remove(&del_pdsi.performance);
            }
        }

        // Debug print of the generated table
        debug!("## gen_perf_pds_table");
        for (perf, pdsi) in self.perf_pdsi.borrow().iter() {
            debug!("PERF: [_, {}]", perf);
            for pdcpu in pdsi.pdcpu_set.iter() {
                debug!(
                    "        pd:id: {:?} -- cpu_vid: {}",
                    pdcpu.pd.id, pdcpu.cpu_vid
                );
            }
        }
    }

    fn find_perf_pds_for(
        &'a self,
        util: f32,
        base: Option<&PDSetInfo<'a>>,
    ) -> Option<PDSetInfo<'a>> {
        let target_perf = (util * self.tot_perf as f32) as usize;
        let mut lookahead = 0;
        let mut min_dist: usize = usize::MAX;
        let mut best_pdsi: Option<PDSetInfo<'a>> = None;

        let pdss_infos = self.pdss_infos.borrow();
        for (&pdsi_perf, pdsi_set) in pdss_infos.iter() {
            if pdsi_perf >= target_perf {
                let pdsi_set_ref = pdsi_set.borrow();
                for pdsi in pdsi_set_ref.iter() {
                    let dist = pdsi.dist(base);
                    if dist < min_dist {
                        min_dist = dist;
                        best_pdsi = Some(pdsi.clone());
                    }
                }
                lookahead += 1;
                if lookahead >= LOOKAHEAD_CNT {
                    break;
                }
            }
        }

        best_pdsi
    }

    /// Generate all possible performance domain & state combinations,
    /// @self.pdss_infos. Each combination represents a set of performance
    /// domains (and their corresponding performance states) that achieve the
    /// requested performance with minimal power consumption.
    ///
    /// We assume a 'reasonable load balancer,' so the CPU utilization of all
    /// the involved CPUs is similar.
    ///
    /// An example result is as follows:
    ///
    ///     PERF: [_, 5135]
    ///         perf: 5135 -- power: 5475348
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///             pd:id: 3 -- cpu_vid: 0
    ///     PERF: [_, 5187]
    ///         perf: 5187 -- power: 4844969
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 0 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///             pd:id: 3 -- cpu_vid: 0
    ///     PERF: [_, 5195]
    ///         perf: 5195 -- power: 5924606
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///             pd:id: 3 -- cpu_vid: 0
    ///     PERF: [_, 5217]
    ///         perf: 5217 -- power: 4894911
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 0 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///             pd:id: 3 -- cpu_vid: 0
    ///     PERF: [_, 5225]
    ///         perf: 5225 -- power: 5665770
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///             pd:id: 3 -- cpu_vid: 0
    ///     PERF: [_, 5316]
    ///         perf: 5316 -- power: 5860568
    ///             pd:id: 0 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 0
    ///             pd:id: 1 -- cpu_vid: 1
    ///             pd:id: 1 -- cpu_vid: 2
    ///             pd:id: 2 -- cpu_vid: 0
    ///             pd:id: 2 -- cpu_vid: 1
    ///             pd:id: 3 -- cpu_vid: 0
    fn gen_all_pds_combinations(&'a self) {
        // Start from the min (0%) and max (100%) CPU utilizations
        let pdsi_vec = self.gen_pds_combinations(0.0);
        self.insert_pds_combinations(&pdsi_vec);

        let pdsi_vec = self.gen_pds_combinations(100.0);
        self.insert_pds_combinations(&pdsi_vec);

        // Then dive into the range between the min and max.
        self.gen_perf_cpuset_table_range(0, 100);

        // Debug print performance table
        debug!("## gen_all_pds_combinations");
        for (perf, pdss_info) in self.pdss_infos.borrow().iter() {
            debug!("PERF: [_, {}]", perf);
            for pdsi in pdss_info.borrow().iter() {
                debug!("    perf: {} -- power: {}", pdsi.performance, pdsi.power);
                for pdcpu in pdsi.pdcpu_set.iter() {
                    debug!(
                        "        pd:id: {:?} -- cpu_vid: {}",
                        pdcpu.pd.id, pdcpu.cpu_vid
                    );
                }
            }
        }
    }

    fn gen_perf_cpuset_table_range(&'a self, low: isize, high: isize) {
        if low > high {
            return;
        }

        // If there is a new performance point in the middle,
        // let's further explore. Otherwise, stop it here.
        let mid: isize = low + (high - low) / 2;
        let pdsi_vec = self.gen_pds_combinations(mid as f32);
        let found_new = self.insert_pds_combinations(&pdsi_vec);
        if found_new {
            self.gen_perf_cpuset_table_range(mid + 1, high);
            self.gen_perf_cpuset_table_range(low, mid - 1);
        }
    }

    fn gen_pds_combinations(&'a self, util: f32) -> Vec<PDSetInfo<'a>> {
        let mut pdsi_vec = Vec::new();

        let pds_set = self.gen_pds_set(util);
        let n = pds_set.len();
        for k in 1..n {
            let pdss = pds_set.clone();
            let pds_cmbs: Vec<_> = Combinations::new(pdss, k)
                .map(|cmb| PDSetInfo::new(cmb.clone()))
                .collect();
            pdsi_vec.extend(pds_cmbs);
        }

        let pdsi = PDSetInfo::new(pds_set.clone());
        pdsi_vec.push(pdsi);

        pdsi_vec
    }

    fn insert_pds_combinations(&self, new_pdsi_vec: &Vec<PDSetInfo<'a>>) -> bool {
        // For the same performance, keep the PDS combinations with the lowest
        // power consumption. If there are more than one lowest, keep them all
        // to choose one later when assigning CPUs from the selected
        // performance domains.
        let mut found_new = false;

        for new_pdsi in new_pdsi_vec.iter() {
            let mut pdss_infos = self.pdss_infos.borrow_mut();
            let v = pdss_infos.get(&new_pdsi.performance);
            match v {
                // There are already PDSetInfo in the list.
                Some(v) => {
                    let mut v = v.borrow_mut();
                    let pdsi = &v.iter().next().unwrap();
                    if pdsi.power == new_pdsi.power {
                        // If the power consumptions are the same, keep both.
                        if v.insert(new_pdsi.clone()) {
                            found_new = true;
                        }
                    } else if pdsi.power > new_pdsi.power {
                        // If the new one takes less power, keep the new one.
                        v.clear();
                        v.insert(new_pdsi.clone());
                        found_new = true;
                    }
                }
                // This is the first for the performance target.
                None => {
                    // Let's add it and move on.
                    let mut v: HashSet<PDSetInfo<'a>> = HashSet::new();
                    v.insert(new_pdsi.clone());
                    pdss_infos.insert(new_pdsi.performance, v.into());
                    found_new = true;
                }
            }
        }
        found_new
    }

    /// Get a vector of (performance domain, performance state) to achieve
    /// the given CPU utilization, @util.
    fn gen_pds_set(&self, util: f32) -> Vec<PDS<'_>> {
        let mut pds_set = vec![];
        for (_, pd) in self.em.perf_doms.iter() {
            let ps = pd.select_perf_state(util).unwrap();
            let pds = PDS::new(pd, ps);
            pds_set.push(pds);
        }
        self.expand_pds_set(&mut pds_set);
        pds_set
    }

    /// Expand a PDS vector such that a performance domain with X CPUs
    /// has N elements in the vector. This is purely for generating
    /// combinations easy.
    fn expand_pds_set(&self, pds_set: &mut Vec<PDS<'_>>) {
        let mut xset = vec![];
        // For a performance domain having nr_cpus, add nr_cpus-1 more
        // PDS to make the PDS nr_cpus in the vector.
        for pds in pds_set.iter() {
            let nr_cpus = pds.pd.span.weight();
            for _ in 1..nr_cpus {
                xset.push(pds.clone());
            }
        }
        pds_set.append(&mut xset);

        // Sort the pds_set for easy comparison.
        pds_set.sort();
    }
}

impl<'a> PDS<'_> {
    fn new(pd: &'a PerfDomain, ps: &'a PerfState) -> PDS<'a> {
        PDS { pd, ps }
    }
}

impl PartialEq for PDS<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.pd == other.pd && self.ps == other.ps
    }
}

impl<'a> PDCpu<'_> {
    fn new(pd: &'a PerfDomain, cpu_vid: usize) -> PDCpu<'a> {
        PDCpu { pd, cpu_vid }
    }
}

impl PartialEq for PDCpu<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.pd == other.pd && self.cpu_vid == other.cpu_vid
    }
}

impl fmt::Display for PDS<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "pd:id:{}/pd:weight:{}/ps:cap:{}/ps:power:{}",
            self.pd.id,
            self.pd.span.weight(),
            self.ps.performance,
            self.ps.power,
        )?;
        Ok(())
    }
}

impl<'a> PDSetInfo<'_> {
    fn new(pds_set: Vec<PDS<'a>>) -> PDSetInfo<'a> {
        // Create a pd_id_set and calculate performance and power.
        let mut performance = 0;
        let mut power = 0;
        let mut pd_id_set: BTreeSet<usize> = BTreeSet::new();

        for pds in pds_set.iter() {
            performance += pds.ps.performance;
            power += pds.ps.power;
            pd_id_set.insert(pds.pd.id);
        }

        // Create a pdcpu_set, so first gather the same PDS entries.
        let mut pds_map: BTreeMap<PDS<'a>, RefCell<Vec<PDS<'a>>>> = BTreeMap::new();

        for pds in pds_set.iter() {
            let v = pds_map.get(&pds);
            match v {
                Some(v) => {
                    let mut v = v.borrow_mut();
                    v.push(pds.clone());
                }
                None => {
                    let mut v: Vec<PDS<'a>> = Vec::new();
                    v.push(pds.clone());
                    pds_map.insert(pds.clone(), v.into());
                }
            }
        }
        // Then assign cpu virtual ids to pdcpu_set.
        let mut pdcpu_set: BTreeSet<PDCpu<'a>> = BTreeSet::new();
        let pds_map = pds_map;

        for (_, v) in pds_map.iter() {
            for (cpu_vid, pds) in v.borrow().iter().enumerate() {
                let pdcpu = PDCpu::new(pds.pd, cpu_vid);
                pdcpu_set.insert(pdcpu);
            }
        }

        PDSetInfo {
            performance,
            power,
            pdcpu_set,
            pd_id_set,
        }
    }

    /// Calculate the distance from @base to @self. We minimize the number of
    /// performance domains involved to reduce the leakage power consumption.
    /// We then maximize the overlap between the previous (i.e., base)
    /// performance domains and the new one for a smooth transition to the new
    /// cpuset with higher cache locality. Finally, we minimize the number of
    /// CPUs involved, thereby reducing the chance of contention for shared
    /// hardware resources (e.g., shared cache).
    
    
    /* 优先最小化新增活跃性能域数（权重最大，PD_UNIT=1e8），其次最大化CPU 数量
    （避免用太少 CPU），最后用最小 PD ID 作为平局决胜，整体目标是在性能档位切换时
    降低功耗跳变和缓存热度损失。 */
    fn dist(&self, base: Option<&PDSetInfo<'a>>) -> usize {
        let nr_pds = self.pd_id_set.len();
        let nr_pds_overlap = match base {
            Some(base) => self.pd_id_set.intersection(&base.pd_id_set).count(),
            None => 0,
        };
        let nr_cpus = self.pdcpu_set.len();

        ((nr_pds - nr_pds_overlap) * PD_UNIT) +         // # non-overlapping PDs
        ((*NR_CPU_IDS - nr_cpus) * CPU_UNIT) +          // # of CPUs
        (*NR_CPU_IDS - self.pd_id_set.first().unwrap()) // PD ID as a tiebreaker
    }
}

impl PartialEq for PDSetInfo<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.performance == other.performance
            && self.power == other.power
            && self.pdcpu_set == other.pdcpu_set
    }
}

impl Hash for PDSetInfo<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // We don't need to hash performance, power, and pd_id_set
        // since they are a kind of cache for pds_set.
        self.pdcpu_set.hash(state);
    }
}

impl PartialEq for PerfCpuOrder {
    fn eq(&self, other: &Self) -> bool {
        self.perf_cap == other.perf_cap
    }
}

impl fmt::Display for PerfCpuOrder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "capacity bound:  {} ({}%)\n",
            self.perf_cap,
            self.perf_util * 100.0
        )?;
        write!(f, "  primary CPUs:  {:?}\n", self.cpus_perf.borrow())?;
        write!(f, "  overflow CPUs: {:?}", self.cpus_ovflw.borrow())?;
        Ok(())
    }
}
