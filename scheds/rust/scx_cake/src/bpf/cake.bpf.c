// SPDX-License-Identifier: GPL-2.0
/* scx_cake - CAKE DRR++ adapted for CPU scheduling: yield-gated priority, direct dispatch, per-LLC DSQ */
/* scx_cake——把网络 CAKE 的 DRR++ 算法改造用于 CPU 调度：让出门控优先级、直接派发、每 LLC 独立 DSQ。 */
/* 讲解：这是整个 BPF 调度器的主文件，实现了所有 sched_ext 回调与分类引擎。 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <lib/arena_map.h> /* BPF_MAP_TYPE_ARENA definition */
			   /* BPF_MAP_TYPE_ARENA 的定义。讲解：arena 是可当普通内存用的 BPF 内存区。 */
#include <lib/sdt_task.h> /* scx_task_data, scx_task_alloc, scx_task_free */
			  /* 每任务数据的分配/释放接口。讲解：用于给每个任务申请 arena 存储。 */
#include "intf.h"
#include "bpf_compat.h"

char _license[] SEC("license") = "GPL";

/* Scheduler RODATA config - JIT constant-folds these for ~200 cycle savings per decision */
/* 调度器只读配置——JIT 会把它们常量折叠，每次决策约省 200 个周期。 */
/* 讲解：RODATA 常量在加载后不变，JIT 可当立即数内联，比读变量快得多。 */
const u64  quantum_ns	     = CAKE_DEFAULT_QUANTUM_NS;
const u64  new_flow_bonus_ns = CAKE_DEFAULT_NEW_FLOW_BONUS_NS;

/* Hog Squeeze RODATA — self-regulating triple-gate deprioritization.
 * Vtime penalties only matter under contention (zero contention = zero impact).
 * Set by loader, derivable from hardware config. */
/* 大户压制只读配置——自调节的三重门降权。
 * vtime 惩罚只有在争用时才起作用（无争用则零影响）。
 * 由加载器根据硬件配置推导设置。 */
/* 讲解：压制只是提高 vtime 排序键，空闲时大家都能跑，不会无谓地限制吞吐。 */

/* RODATA BAKING: hot-path constants promoted from #define for JIT folding
 * + per-profile tunability. JIT treats these identically to immediates.
 * Rust loader can override for esports/battery profiles. */
/* RODATA 烘焙：把热路径常量从 #define 提升为 const，既能被 JIT 折叠，
 * 又能按配置调整。JIT 对它们与立即数一视同仁。
 * Rust 加载器可为 esports/battery 等配置覆盖这些值。 */
/* 讲解：用 const 变量而非宏，兼得“运行前可调”和“运行时零开销”两个好处。 */
const u64  aq_yielder_ceiling_ns = AQ_YIELDER_CEILING_NS; /* 50ms ceiling for yielders */
							 /* 让出者时间片上限 50ms。讲解：合作型任务给足余量。 */
const u64  aq_min_ns             = AQ_MIN_NS;             /* 50µs quantum floor */
							 /* 时间片下限 50µs。讲解：防止切换开销超过有效工作。 */
const u32  preempt_vip_ns        = CAKE_PREEMPT_VIP_THRESHOLD_NS;     /* 50µs VIP preempt */
								     /* VIP 抢占阈值 50µs。讲解：游戏家族更快夺回家 CPU。 */
const u32  preempt_yielder_ns    = CAKE_PREEMPT_YIELDER_THRESHOLD_NS; /* 100µs normal preempt */
								     /* 普通抢占阈值 100µs。讲解：平衡收益与切换成本。 */

/* JITTER REDUCTION: RODATA lookup tables indexed by task_class (0-3).
 * Eliminates branching chains — single indexed load is constant-time
 * regardless of class, zero pipeline misprediction variance. */
/* 降低抖动：以 task_class（0-3）为下标的 RODATA 查表。
 * 消除分支链——不论哪类，单次带下标加载都是常数时间，
 * 没有分支预测失败带来的时序波动。 */
/* 讲解：用查表代替 if/else，保证每类任务的处理时间一致，减少调度抖动。 */
/* ── TIERED DSQ ORDERING ──
 * Non-overlapping offsets guarantee class ordering in vtime DSQ.
 * GAME [0,4096] < NORMAL [8192,12288] < BG [32768,36864] < HOG [49152,53248].
 * HOG = worst offender (75%+ quantum), gets heaviest penalty (6× NORMAL).
 * BG = passive background, moderate penalty (4× NORMAL).
 * Index: [NORMAL=0, GAME=1, HOG=2, BG=3] (matches CAKE_CLASS_* enum) */
/* ── 分层 DSQ 排序 ──
 * 不重叠的偏移量保证 vtime DSQ 中的类别顺序：
 * GAME [0,4096] < NORMAL [8192,12288] < BG [32768,36864] < HOG [49152,53248]。
 * HOG = 最严重的占用者（≥75% 时间片），惩罚最重（6× NORMAL）。
 * BG = 被动后台，中等惩罚（4× NORMAL）。
 * 下标：[NORMAL=0, GAME=1, HOG=2, BG=3]（与 CAKE_CLASS_* 枚举一致）。 */
/* 讲解：给每类一个不重叠的 vtime 基值，仅凭排序即可实现“GAME 永远先于 NORMAL”等严格分层。 */
const u32  tier_base[4]           = { 8192, 0, 49152, 32768 };  /* NORMAL=8192, GAME=0, HOG=49152(6×), BG=32768(4×) */
							       /* 各类 vtime 基值表。讲解：基值越小越先派发。 */
/* VRUNTIME COST: max rt_cost per class (clamped to inter-bucket gap).
 * Prevents runtime cost from pushing a task across bucket boundaries.
 * All gaps ≥3072 — uniform cap of 4096 is safe for every class. */
/* 虚拟运行时代价：每类的 rt_cost 上限（钳制到桶间间隔内）。
 * 防止运行时代价把任务推过桶边界。
 * 所有间隔 ≥3072——统一上限 4096 对每类都安全。 */
/* 讲解：限制单次运行累积的 vtime，避免某任务因跑得久而“越界”混入其它类别的排序区间。 */
const u32  rt_cost_cap[4]        = { 4096, 4096, 4096, 4096 };  /* uniform cap */
							       /* 统一的运行代价上限。讲解：四类都用 4096，简单且安全。 */
const u32  preempt_thresh_ns[4]  = { 100000, 50000, 100000, 100000 }; /* NORMAL=100µs, GAME=50µs(VIP), HOG/BG=100µs */
								     /* 各类抢占阈值表。讲解：GAME 用更低的 50µs 更激进。 */
/* OPT-4: EEVDF nice scaling — pre-computed reciprocal multiplier.
 * vtime_mult = 102400 / weight, where 1024 = nice0 baseline (weight 100).
 * Replaces the 30-insn binary tree nice_shift system with a 5-insn
 * division (1/64 stops) + 4-insn multiply (every stop).
 * nice_scale_table REMOVED — was Shadow State (Rule 74). */
/* OPT-4：EEVDF 的 nice 缩放——预计算的倒数乘子。
 * vtime_mult = 102400 / weight，其中 1024 = nice0 基线（weight 100）。
 * 用 5 条指令的除法（每 64 次 stop 一次）+ 4 条指令的乘法（每次 stop）
 * 取代了原先 30 条指令的二叉树 nice_shift 系统。
 * nice_scale_table 已移除——它曾是“影子状态”（规则74）。 */
/* 讲解：把除法降频到每 64 次算一次，热路径只做乘法，用倒数把 nice 权重换成 vtime 缩放。 */

/* CAKE_STATS_ENABLED: compile-time elimination for release builds.
 *
 * RELEASE (CAKE_RELEASE=1, set by build.rs in --release):
 *   CAKE_STATS_ENABLED is a compile-time constant 0. Clang eliminates ALL
 *   stats/telemetry branches entirely — zero instructions, zero overhead.
 *   The --verbose flag is unavailable in release builds.
 *
 * DEBUG (CAKE_RELEASE not defined):
 *   volatile RODATA toggle — loader patches enable_stats to true when
 *   --verbose is passed. Volatile prevents Clang DCE while the initial
 *   value is still 'false'. JIT replaces the volatile load with an
 *   immediate compare after loader patching — negligible cost. */
/* CAKE_STATS_ENABLED：为发布版做编译期裁剪的开关。
 *
 * 发布版（CAKE_RELEASE=1，由 build.rs 在 --release 时设置）：
 *   CAKE_STATS_ENABLED 是编译期常量 0，Clang 会彻底删除所有
 *   统计/遥测分支——零指令、零开销。发布版中 --verbose 不可用。
 *
 * 调试版（未定义 CAKE_RELEASE）：
 *   使用 volatile 的 RODATA 开关——传入 --verbose 时加载器把 enable_stats 打成 true。
 *   volatile 可防止初值仍为 false 时被 Clang 死代码消除。加载器打补丁后，
 *   JIT 把该 volatile 读取替换为立即数比较——开销可忽略。 */
/* 讲解：发布版把遥测“编译没”，调试版则保留并可运行时开关，兼顾性能与可观测性。 */
#ifdef CAKE_RELEASE
#define CAKE_STATS_ENABLED 0
#else
const bool enable_stats __attribute__((used)) = false;
#define CAKE_STATS_ENABLED (*(volatile const bool *)&enable_stats)
#endif
/* CAKE_STATS_ACTIVE: runtime-suppressible telemetry.
 * False during BenchLab runs (bench_active=1) so kfunc measurements
 * aren't polluted by ~15 extra scx_bpf_now() + arena writes per event. */
/* CAKE_STATS_ACTIVE：可在运行时临时关闭的遥测。
 * BenchLab 运行期间（bench_active=1）为假，避免每次事件多出约 15 次
 * scx_bpf_now() 与 arena 写入而污染 kfunc 的测量结果。 */
/* 讲解：测量本身有开销，跑基准时暂停遥测才能测准“被测代码”的真实成本。 */
#define CAKE_STATS_ACTIVE (CAKE_STATS_ENABLED && !bench_active)
const bool enable_dvfs =
	false; /* RODATA — loader-compat only (tick removed, DVFS dead) */
	       /* RODATA——仅为兼容加载器（tick 已移除，DVFS 功能作废）。讲解：保留字段防止加载器报错。 */

/* Topology config - JIT eliminates unused SMT steering when nr_cpus <= nr_phys_cpus.
 * has_hybrid removed: Rust loader pre-fills cpu_sibling_map for ALL topologies
 * via scx_utils::Topology::sibling_cpus(). No runtime branching needed. */
/* 拓扑配置——当 nr_cpus <= nr_phys_cpus 时 JIT 会删除用不上的 SMT 引导逻辑。
 * has_hybrid 已移除：Rust 加载器借 scx_utils::Topology::sibling_cpus()
 * 为所有拓扑预填 cpu_sibling_map，运行时无需再分支。 */
/* 讲解：把拓扑判断挪到加载期，运行时直接查预填好的表，避免热路径分支。 */

/* Per-LLC DSQ partitioning — populated by loader from topology detection.
 * Eliminates cross-CCD lock contention: each LLC has its own DSQ.
 * Single-CCD (9800X3D): nr_llcs=1, identical to single-DSQ behavior.
 * Multi-CCD (9950X): nr_llcs=2, halves contention, eliminates cross-CCD atomics. */
/* 每 LLC 的 DSQ 分区——由加载器根据拓扑探测填充。
 * 消除跨 CCD 的锁争用：每个 LLC 拥有独立的 DSQ。
 * 单 CCD（9800X3D）：nr_llcs=1，等同单 DSQ 行为。
 * 多 CCD（9950X）：nr_llcs=2，争用减半，消除跨 CCD 原子操作。 */
/* 讲解：把队列按 LLC 切分，不同芯片小片各管各的队列，避免昂贵的跨片同步。 */
const u32 nr_llcs = 1;
const u32 nr_cpus = 8; /* Set by loader — bounds kick scan loop (Rule 39) */
		       /* 由加载器设置——用作踢核扫描循环的上界（规则39）。讲解：给验证器一个静态上界。 */
const u32 nr_phys_cpus =
	8; /* Set by loader — physical core count for PHYS_FIRST */
	   /* 由加载器设置——物理核数，用于 PHYS_FIRST 逻辑。讲解：区分逻辑核与物理核。 */
const u32 nr_nodes = 1; /* Set by loader — NUMA node count for bench competitor */
			/* 由加载器设置——NUMA 节点数，供基准对照使用。讲解：多路系统的节点数量。 */
const u32 cpu_llc_id[CAKE_MAX_CPUS] = {};
			/* 每 CPU 的 LLC 归属表。讲解：加载器填入，用于 DSQ 分片与本地判断。 */
const u32 cpuperf_cap_table[CAKE_MAX_CPUS] = {}; /* Set by loader — per-CPU max perf */
						/* 由加载器设置——每 CPU 最大性能容量。讲解：异构核 vtime 缩放用。 */

/* Performance-ordered CPU scan arrays (populated by Rust loader).
 * cpus_fast_to_slow: GAME tasks scan highest-perf cores first → maximum boost.
 * cpus_slow_to_fast: non-GAME tasks scan lowest-perf cores first → power parking.
 * Source: amd_pstate_prefcore_ranking (Zen 4) or cpufreq_cap (fallback).
 * Terminated by 0xFF sentinel when nr_cpus < CAKE_MAX_CPUS. */
/* 按性能排序的 CPU 扫描数组（由 Rust 加载器填充）。
 * cpus_fast_to_slow：GAME 任务优先扫描最高性能核 → 最大加速。
 * cpus_slow_to_fast：非 GAME 任务优先扫描最低性能核 → 让高性能核歇着省电。
 * 来源：amd_pstate_prefcore_ranking（Zen 4）或 cpufreq_cap（回退）。
 * 当 nr_cpus < CAKE_MAX_CPUS 时以 0xFF 哨兵结尾。 */
/* 讲解：给游戏任务优先分配最快的核，把慢核留给后台，兼顾性能与能效。 */
const u8 cpus_fast_to_slow[CAKE_MAX_CPUS] = {};
const u8 cpus_slow_to_fast[CAKE_MAX_CPUS] = {};

/* Topological O(1) Arrays — populated by loader */
/* 拓扑 O(1) 查表数组——由加载器填充 */
/* 讲解：把 LLC/物理核成员、SMT 兄弟等关系预存成表，运行时 O(1) 查询。 */
const u64 llc_cpu_mask[CAKE_MAX_LLCS]	 = {};
			/* 每 LLC 的 CPU 位掩码。讲解：标识该 LLC 包含哪些 CPU。 */
const u64 core_cpu_mask[32]		 = {};
			/* 每物理核的 CPU 位掩码。讲解：标识一个物理核的 SMT 逻辑核。 */
const u8  cpu_sibling_map[CAKE_MAX_CPUS] = {};
			/* 每 CPU 的 SMT 兄弟核映射。讲解：Gate 2 用它做类别不匹配过滤。 */

/* BSS bench state: xorshift32 PRNG seed */
/* BSS 基准状态：xorshift32 伪随机种子 */
u32 bench_xorshift_state = 0xDEADBEEF;
			/* 讲解：BenchLab 中自实现的随机数状态，用于对比 kfunc 随机源。 */

/* F2 FIX: 256-bit CPU mask support for Threadripper/EPYC */
/* F2 修复：支持 256 位 CPU 掩码，兼容 Threadripper/EPYC。 */
/* 讲解：高核数平台超过 64 核，需用 u64[4] 表示完整的 CPU 掩码。 */
#define CAKE_CPU_MASK_WORDS (CAKE_MAX_CPUS / 64)
			    /* 掩码字数 = 最大 CPU 数 / 64。讲解：256/64=4，即用 4 个 u64。 */

/* Heterogeneous Routing Masks — u64[4] for 256 CPUs */
/* 异构路由掩码——用 u64[4] 覆盖 256 个 CPU */
/* 讲解：区分大核/小核/V-Cache 等，用于按硬件特性选核。 */
const u64  big_core_phys_mask[CAKE_CPU_MASK_WORDS] = {};
			/* 大核（物理）掩码。讲解：Intel 混合架构的 P 核物理核。 */
const u64  big_core_smt_mask[CAKE_CPU_MASK_WORDS]  = {};
			/* 大核（SMT 兄弟）掩码。讲解：P 核的超线程逻辑核。 */
const u64  little_core_mask[CAKE_CPU_MASK_WORDS]   = {};
			/* 小核掩码。讲解：Intel 的能效核 E 核。 */
const u64  vcache_llc_mask[CAKE_CPU_MASK_WORDS]    = {};
			/* V-Cache LLC 掩码。讲解：AMD 3D V-Cache 所在的 CCD 核集合。 */
const bool has_vcache	      = false;
			/* 是否存在 V-Cache。讲解：决定是否启用 V-Cache 相关引导。 */
const bool has_hybrid_cores   = false; /* Set by loader — gate for Gate 2 scan */
				       /* 由加载器设置——Gate 2 扫描的启用门。讲解：仅异构平台才做性能排序扫描。 */
/* has_cpuperf_control REMOVED: cpuperf 768/1024 scaling was removed.
 * All CPUs run at full speed during GAMING. */
/* has_cpuperf_control 已移除：768/1024 的 cpuperf 缩放被取消。
 * 游戏期间所有 CPU 都以全速运行。 */
/* 讲解：简化频率策略，游戏时不再区分档位，全部拉满。 */

/* Audio stack TGIDs — detected once at startup, baked into RODATA.
 * PipeWire/PulseAudio/JACK daemons + PipeWire socket clients (mixers like
 * goxlr-daemon, easyeffects). Session-persistent (started at login, same
 * PID until logout). JIT constant-folds these to immediates.
 * Zero-terminated: unused slots = 0 (no valid TGID matches pid 0). */
/* 音频栈 TGID——启动时检测一次，烘焙进 RODATA。
 * 包括 PipeWire/PulseAudio/JACK 守护进程 + PipeWire 套接字客户端
 *（如 goxlr-daemon、easyeffects 这类混音器）。会话期内稳定
 *（登录时启动、注销前 PID 不变）。JIT 会把它们折叠成立即数。
 * 以 0 结尾：未用槽位为 0（不会有合法 TGID 匹配 pid 0）。 */
/* 讲解：游戏时把音频进程提升到 GAME 优先级，保证声音与画面延迟一致、不爆音。 */
const u32 nr_audio_tgids = 0;
const u32 audio_tgids[CAKE_MAX_AUDIO_TGIDS] = {};

/* Compositor TGIDs — detected once at startup, baked into RODATA.
 * Wayland compositors (kwin_wayland, mutter, sway, Hyprland, etc.) present
 * every frame to the display. Must dispatch promptly during GAMING.
 * Session-persistent like audio daemons. */
/* 合成器 TGID——启动时检测一次，烘焙进 RODATA。
 * Wayland 合成器（kwin_wayland、mutter、sway、Hyprland 等）负责每帧
 * 呈现到显示器，游戏期间必须及时派发。与音频守护进程一样会话期内稳定。 */
/* 讲解：合成器决定画面何时上屏，游戏时给它 GAME 优先级以保证呈现延迟对等。 */
const u32 nr_compositor_tgids = 0;
const u32 compositor_tgids[CAKE_MAX_COMPOSITOR_TGIDS] = {};



/* ═══════════════════════════════════════════════════════════════════════════
 * PER-CPU ARENA BLOCK: Unified mailbox (C1 spatial consolidation).
 *
 * Single per-CPU allocation sized by CAKE_MBOX_SIZE:
 *   - release: 64B/CPU (1 CL) — struct is dead stub (all reads DCE'd)
 *   - debug:  128B/CPU (2 CL) — CL0 telemetry + CL1 BenchLab handoff
 *   - 1 BSS global pointer, 1 TLB entry, 1 null-check
 * ═══════════════════════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════════════════════
 * 每 CPU arena 块：统一邮箱（C1 空间合并）。
 *
 * 单块每 CPU 分配，大小由 CAKE_MBOX_SIZE 决定：
 *   - 发布版：64B/CPU（1 缓存行）——结构体为死桩（所有读被 DCE）
 *   - 调试版：128B/CPU（2 缓存行）——CL0 遥测 + CL1 BenchLab 交接
 *   - 只需 1 个 BSS 全局指针、1 个 TLB 项、1 次空指针检查
 * ═══════════════════════════════════════════════════════════════════════════ */
/* 讲解：把每 CPU 的邮箱合并成一整块 arena 分配，减少指针、TLB 项与判空的数量。 */
struct cake_per_cpu {
	struct mega_mailbox_entry
		mbox; /* release: 64B (1 CL), debug: 128B (2 CL) */
		      /* 发布：64B（1 缓存行），调试：128B（2 缓存行）。讲解：尺寸随构建模式变化。 */
} __attribute__((aligned(CAKE_MBOX_ALIGN)));
_Static_assert(sizeof(struct cake_per_cpu) == CAKE_MBOX_SIZE,
	       "cake_per_cpu must match CAKE_MBOX_SIZE for per-CPU isolation");
	       /* 讲解：编译期断言尺寸正确，保证每 CPU 块严格隔离在各自缓存行。 */
struct cake_per_cpu __arena *per_cpu;

/* Global stats BSS array - 0ns lookup vs 25ns helper, 256-byte aligned per CPU */
/* 全局统计 BSS 数组——查表 0ns（对比辅助函数 25ns），每 CPU 按 256 字节对齐。 */
/* 讲解：直接索引 BSS 数组比调用 per-cpu kfunc 快得多，对齐则避免跨 CPU 伪共享。 */
struct cake_stats global_stats[CAKE_MAX_CPUS] SEC(".bss")
	__attribute__((aligned(256)));

/* DSQ Work Hint: DELETED.
 * dsq_gen was a unidirectional generation counter that caused CPUs to
 * permanently skip checking the shared DSQ after pulling one task.
 * With 18.8M hint_skips, OS threads (ksoftirqd, rcu) starved for 6.5s.
 * Replaced by O(1) scx_bpf_dsq_nr_queued() in cake_dispatch. */
/* DSQ 工作提示：已删除。
 * dsq_gen 曾是单向的世代计数器，会导致 CPU 取走一个任务后
 * 永久跳过对共享 DSQ 的检查。实测 1880 万次跳过，使
 * 操作系统线程（ksoftirqd、rcu）饿死达 6.5 秒。
 * 现改用 cake_dispatch 中 O(1) 的 scx_bpf_dsq_nr_queued()。 */
/* 讲解：过度“优化”的缓存提示反而导致饥饿，改回精确的队列计数才正确。 */


/* BSS tail guard - absorbs BTF truncation bugs instead of corrupting real data */
/* BSS 尾部护栏——吸收 BTF 截断类 bug，避免污染真实数据。 */
/* 讲解：在 BSS 末尾放一段哨兵区，越界写入会落在这里而不是破坏有效数据。 */
u8 __bss_tail_guard[64] SEC(".bss") __attribute__((aligned(64)));

/* pid_to_tctx (BPF_MAP_TYPE_HASH) removed — replaced by SEC("iter/task") cake_task_iter.
 * cake_init_task and cake_exit_task are now fully lockless: no map_update_elem or
 * map_delete_elem calls. Userspace reads fixed-size cake_iter_record records from the
 * iter fd instead of walking a 65536-entry global hash table. */
/* pid_to_tctx（哈希表）已移除——改用 SEC("iter/task") 的 cake_task_iter。
 * cake_init_task 与 cake_exit_task 现已完全无锁：不再有 map 更新/删除调用。
 * 用户态从 iter fd 读取定长的 cake_iter_record 记录，而不再遍历 65536 项的全局哈希表。 */
/* 讲解：用 BPF iter 取代带全局锁的哈希表，让任务创建/销毁路径彻底无锁。 */



/* ARENA_ASSOC: Force arena map association for struct_ops programs.
 * BSS loads don't create arena map relocations — only direct &arena references do.
 * Inline asm constraint forces &arena into a register (ld_imm64 relocation)
 * without emitting a stack store. 2 insns vs 3 with volatile. */
/* ARENA_ASSOC：为 struct_ops 程序强制建立 arena map 关联。
 * BSS 加载不会产生 arena map 重定位——只有直接引用 &arena 才会。
 * 内联汇编约束把 &arena 强制放入寄存器（ld_imm64 重定位），
 * 且不产生栈存储。相比 volatile 写法是 2 条指令而非 3 条。 */
/* 讲解：这是让验证器认得 arena map 的一个必要“把戏”，同时尽量少产生指令。 */
#define ARENA_ASSOC() asm volatile("" : : "r"(&arena))

static __always_inline struct cake_stats *get_local_stats(void)
{
#ifndef CAKE_RELEASE
	asm volatile("" : : "r"(enable_stats) : "memory");
#endif
	u32 cpu = bpf_get_smp_processor_id();
	return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* Rule 30: Avoid redundant bpf_get_smp_processor_id() kfunc trampoline (~15ns)
 * when caller already has CPU ID in a register. */
/* 规则30：当调用方已在寄存器里持有 CPU 号时，避免重复调用
 * bpf_get_smp_processor_id() 这个 kfunc（约 15ns 的跳板开销）。 */
/* 讲解：提供一个直接传入 CPU 号的版本，省去重复取 CPU 号。 */
static __always_inline struct cake_stats *get_local_stats_for(u32 cpu)
{
	return &global_stats[cpu & (CAKE_MAX_CPUS - 1)];
}

/* User exit info for graceful scheduler exit */
/* 用户退出信息，用于调度器优雅退出。 */
/* 讲解：UEI 记录退出原因，卸载调度器时回传给用户态。 */
UEI_DEFINE(uei);

/* Per-LLC DSQs with vtime-encoded priority.
 * Single vtime-ordered DSQ per LLC. Weighted vtime ordering:
 * yielders sort first (lower vtime), non-yielders sort later.
 * Dispatch: 1 kfunc always.
 * DSQ IDs: LLC_DSQ_BASE + 0, LLC_DSQ_BASE + 1, ... (one per LLC). */
/* 每 LLC 一个、优先级编码进 vtime 的 DSQ。
 * 每个 LLC 只有一个按 vtime 排序的队列。加权 vtime 排序：
 * 让出者排前（vtime 更小），非让出者排后。
 * 派发：始终只需 1 次 kfunc。
 * DSQ ID：LLC_DSQ_BASE + 0、+1……（每 LLC 一个）。 */
/* 讲解：单队列 + vtime 排序即可同时表达“分层优先级”和“层内公平”，派发只需一次 kfunc。 */

/* ── Kfunc BenchLab: BSS globals ──
 * bench_request: TUI writes 1 → BPF runs bench on next stopping → clears to 0.
 * bench_results: populated by run_kfunc_bench(), read by TUI. */
/* ── Kfunc BenchLab：BSS 全局变量 ──
 * bench_request：TUI 写 1 → BPF 在下次 stopping 运行基准 → 清回 0。
 * bench_results：由 run_kfunc_bench() 填充，供 TUI 读取。 */
/* 讲解：这几个变量是 TUI 与 BPF 之间触发/回传基准测试的握手通道。 */
u32 bench_request = 0;
u32 bench_active = 0;  /* 1 while benchmark is running — suppresses telemetry */
		       /* 基准运行期间为 1——用于抑制遥测。讲解：避免测量被遥测开销污染。 */
struct kfunc_bench_results bench_results = {};

/* ── Game Family Boost: PPID-based process-level yielder promotion ──
 * Written by Rust TUI every poll (~500ms) with detected game tgid + ppid.
 * Read in cake_stopping and select_cpu to identify game family members.
 * game_tgid == 0 means no game detected (system behaves as before).
 * Own cache line: written rarely (~2/s), read on every dispatch (~6K/s).
 * After settling, lives in shared-S state across all cores (~1ns read). */
/* ── 游戏家族提升：基于 PPID 的进程级让出者提升 ──
 * 由 Rust TUI 每次轮询（约 500ms）写入检测到的游戏 tgid + ppid。
 * 在 cake_stopping 与 select_cpu 中读取，以识别游戏家族成员。
 * game_tgid == 0 表示未检测到游戏（系统行为如常）。
 * 独占缓存行：写入很少（约 2 次/秒），每次派发都读（约 6K 次/秒）。
 * 稳定后在所有核上处于 shared-S 状态（读取约 1ns）。 */
/* 讲解：写少读多的变量单独占一条缓存行，稳定后各核共享只读副本，读取几乎零成本。 */
u32 game_tgid __attribute__((aligned(64))) = 0;
/* Parent PID of game process — all Proton/Wine siblings share the same
 * pv-adverb container PPID.  Written by Rust TUI alongside game_tgid.
 * Same cache-line lifecycle: written rarely (~2/s), read in cake_stopping. */
/* 游戏进程的父 PID——所有 Proton/Wine 兄弟进程共享同一个 pv 容器 PPID。
 * 由 Rust TUI 与 game_tgid 一起写入。缓存行生命周期相同：写入很少（约 2 次/秒），在 cake_stopping 中读取。 */
/* 讲解：靠共同父进程把游戏相关的一整族进程都识别为 GAME。 */
u32 game_ppid = 0;
/* Scheduler operating state: IDLE=0, COMPILATION=1, GAMING=2.
 * Written by Rust TUI every poll (~500ms). Read by BPF hot path to select
 * the appropriate policy profile (squeeze, vprot kick, quantum ceiling).
 * Lives on the same cache line as game_tgid/game_ppid — written rarely,
 * read-shared across cores in MESI-S state at ~1ns cost. */
/* 调度器运行状态：IDLE=0、COMPILATION=1、GAMING=2。
 * 由 Rust TUI 每次轮询（约 500ms）写入。BPF 热路径读取它来选择
 * 相应策略（压制、vprot 踢核、时间片上限）。
 * 与 game_tgid/game_ppid 处于同一缓存行——写入很少，
 * 各核以 MESI-S 状态共享读取，约 1ns 代价。 */
/* 讲解：这是全局“模式开关”，决定调度器当前采用哪套策略。 */
u32 sched_state = CAKE_STATE_IDLE;
/* Precomputed quantum ceiling — set by userspace when sched_state changes.
 * Eliminates sched_state == COMPILATION branch from stopping hot path.
 * COMPILATION → 8ms, else → 2ms. Zero-init for BSS placement; Rust sets
 * initial value (AQ_BULK_CEILING_NS) at startup. Written at ~2Hz by TUI. */
/* 预计算的时间片上限——sched_state 变化时由用户态设置。
 * 从 stopping 热路径中消除了 sched_state == COMPILATION 的分支。
 * 编译态 → 8ms，否则 → 2ms。为 BSS 摆放而零初始化；Rust 启动时
 * 设初值（AQ_BULK_CEILING_NS）。TUI 以约 2Hz 写入。 */
/* 讲解：把“该用哪个上限”提前算好存起来，热路径直接读，省掉一次分支判断。 */
u64 quantum_ceiling_ns = 0;
/* Confidence score for game detection: 100=Steam-confirmed, 90=Wine .exe,
 * 50=native/unknown, 0=none. Written by Rust TUI alongside sched_state.
 * Same cache line — available for future BPF hot-path policy scaling. */
/* 游戏检测置信度：100=Steam 确认，90=Wine .exe，50=原生/未知，0=无。
 * 由 Rust TUI 与 sched_state 一起写入。同一缓存行——为将来 BPF 热路径策略缩放预留。 */
/* 讲解：置信度越高说明游戏识别越可靠，可据此决定锁定/让位策略。 */
u8 game_confidence = 0;

/* G1+G4: EEVDF intra-tier virtual clock.
 * Tracks the latest dispatched task's vtime. Used to initialize
 * new/waking tasks and cap sleep credit. Updated in cake_running. */
/* G1+G4：EEVDF 层内虚拟时钟。
 * 跟踪最近派发任务的 vtime，用于初始化新任务/唤醒任务并限制睡眠积分。
 * 在 cake_running 中更新。 */
/* 讲解：虚拟时钟是 EEVDF 排序的基准，防止长睡任务醒来后无限抢先。 */
/* vtime_now REMOVED: was a global BSS u64 written by every CPU on every
 * context switch, causing 15-core MESI invalidation. Replaced by per-CPU
 * bss->vtime_local — each CPU advances its own monotonic max. */
/* vtime_now 已移除：它曾是每个 CPU 每次上下文切换都写的全局 BSS u64，
 * 导致 15 核的 MESI 失效风暴。现改用每 CPU 的 bss->vtime_local——
 * 每个 CPU 各自推进自己的单调递增最大值。 */
/* 讲解：全局单变量被高频跨核写是性能杀手，改成每核本地维护即可避免。 */

/* PID→task_class cache: tunnels task_class from stopping → select_cpu Gate 2.
 * Eliminates bpf_task_storage_get (28ns avg, 1982ns worst-case jitter)
 * from the select_cpu wakeup path. BSS read = 14ns avg, 96ns jitter.
 * 4096 entries (4KB) indexed by p->pid & 4095. Hash collision risk with
 * ~100 gaming tasks is <0.1%. Written in stopping, read in select_cpu. */
/* PID→task_class 缓存：把 task_class 从 stopping 隧道传到 select_cpu 的 Gate 2。
 * 从 select_cpu 唤醒路径中消除了 bpf_task_storage_get（平均 28ns，最坏抖动 1982ns）。
 * BSS 读取平均 14ns、抖动 96ns。4096 项（4KB），以 p->pid & 4095 为下标。
 * 约 100 个游戏任务下的哈希冲突概率 <0.1%。在 stopping 写、在 select_cpu 读。 */
/* 讲解：用一个小数组缓存 pid→类别，避免选核时做昂贵且抖动大的 task_storage 查找。 */
#define PID_CLASS_CACHE_SIZE 4096
static u8 pid_class_cache[PID_CLASS_CACHE_SIZE];

/* O(1) GAME preemption bitmask: bit N set = CPU N running a GAME task.
 * Written atomically (or/and) in cake_running. Read in cake_enqueue.
 * F2 FIX: widened to u64[4] for 256 CPUs.
 * find-victim scans words with tzcnt (1 cycle per word). */
/* O(1) 的 GAME 抢占位掩码：第 N 位置 1 表示 CPU N 正跑 GAME 任务。
 * 在 cake_running 中原子（or/and）写入，在 cake_enqueue 中读取。
 * F2 修复：扩宽为 u64[4] 以支持 256 个 CPU。
 * 找抢占目标时用 tzcnt 逐字扫描（每字 1 个周期）。 */
/* 讲解：位掩码让“找一个非游戏 CPU 来抢占”变成一条位运算指令，极快。 */
static u64 game_cpu_mask[CAKE_CPU_MASK_WORDS];

/* Phase 5: Per-CPU BSS — arena-free running.
 * Each entry is 64B aligned (one cache line per CPU).
 * running writes, stopping reads (same CPU) + vprot kick reads (remote CPU). */
/* 阶段 5：每 CPU BSS——不依赖 arena 的运行态存储。
 * 每项 64B 对齐（每 CPU 一条缓存行）。
 * running 写、stopping 读（同 CPU）+ vprot 踢核读（远端 CPU）。 */
/* 讲解：把运行态热数据放进独占缓存行的 BSS 数组，单写多读、无锁、无跨核抖动。 */
struct cake_cpu_bss cpu_bss[CAKE_MAX_CPUS];

/* DSQ MAILBOX: per-LLC flag tracks whether a kick has been sent to drain
 * the LLC DSQ. Set on enqueue (0→1 transition only, check-before-write).
 * Cleared in cake_dispatch after successful move_to_local.
 * Prevents tasks from rotting in DSQ when all CPUs use Gate 1 direct
 * dispatch (which bypasses cake_dispatch entirely).
 * MESI: read-first — stays Shared if already set, no cache bounce. */
/* DSQ 邮箱：每 LLC 一个标志，记录是否已发过“排空该 LLC DSQ”的踢核。
 * 入队时置位（仅 0→1 跳变，先读后写）。cake_dispatch 成功把任务移入本地队列后清零。
 * 防止当所有 CPU 都走 Gate 1 直接派发（完全绕过 cake_dispatch）时，任务烂在 DSQ 里。
 * MESI：先读——若已置位则保持 Shared，不产生缓存抖动。 */
/* 讲解：直接派发会绕过 dispatch，此标志确保 DSQ 里的任务总有 CPU 被唤醒来消费。 */
u8 dsq_kick_needed[CAKE_MAX_LLCS];

/* BenchLab ringbuf: tiny ringbuf for measuring reserve+submit overhead.
 * Size 4096 = minimum page-aligned allocation. Never consumed by userspace;
 * benchmarks use reserve+discard to measure the API cost. */
/* BenchLab ringbuf：用于测量 reserve+submit 开销的小型环形缓冲。
 * 大小 4096 = 最小的页对齐分配。用户态从不消费它；
 * 基准通过 reserve+discard 来测量该 API 的成本。 */
/* 讲解：这是只为测量 ringbuf API 开销而存在的“空跑”缓冲区。 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} bench_ringbuf SEC(".maps");

/* BenchLab task storage: measures bpf_task_storage_get() cost.
 * This is the standard per-task storage approach that cake replaced with arena.
 * Only used in benchmarks to measure what we're saving. */
/* BenchLab 任务存储：测量 bpf_task_storage_get() 的成本。
 * 这是 cake 用 arena 替代掉的标准每任务存储方式。仅在基准中用于衡量我们节省了多少。 */
/* 讲解：保留一份标准 task_storage 作对照，量化改用 arena 带来的收益。 */
struct bench_task_val {
	u64 dummy;
};
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bench_task_val);
} bench_task_storage SEC(".maps");

/* Phase 6: Per-task hot fields in kernel task_storage (~10ns lookup).
 * Replaces Arena CL0 reads in running+stopping (saves 2× 19ns = 38ns).
 * Arena CL0 still exists for telemetry but is dead in release builds. */
/* 阶段 6：把每任务热字段放进内核 task_storage（查找约 10ns）。
 * 取代 running+stopping 中对 Arena CL0 的读取（省下 2×19ns=38ns）。
 * Arena CL0 仍存在用于遥测，但在发布版中是死代码。 */
/* 讲解：真正的调度热存储用查找更快的 task_storage，arena 只留给遥测。 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct cake_task_hot);
} task_hot_stor SEC(".maps");

/* BenchLab spin lock: measures bpf_spin_lock + unlock cycle cost. */
/* BenchLab 自旋锁：测量 bpf_spin_lock + unlock 一轮的成本。 */
/* 用于与 cake 的无锁读取方案做性能对比。 */
struct bench_lock_data {
	struct bpf_spin_lock lock;
	u64 counter;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct bench_lock_data);
} bench_lock_map SEC(".maps");

/* Benchmark a single kfunc iteration: call twice, delta = cost.
 * Macro to avoid function pointer overhead (BPF doesn't support them). */
/* 对单次 kfunc 迭代计时：取两次时间，差值即成本。
 * 用宏而非函数指针，因为 BPF 不支持函数指针。 */
/* 宏在调用点展开，避免额外调用开销，测得的就是被测操作本身。 */
#define BENCH_ONE(entry, call_expr, idx) do {                     \
	u64 _s = bpf_ktime_get_ns();                                 \
	u64 _v = (u64)(call_expr);                                    \
	u64 _e = bpf_ktime_get_ns();                                 \
	u64 _d = _e - _s;                                            \
	if (_d < (entry)->min_ns) (entry)->min_ns = _d;               \
	if (_d > (entry)->max_ns) (entry)->max_ns = _d;               \
	(entry)->total_ns += _d;                                      \
	(entry)->last_value = _v;                                     \
	(entry)->samples[idx] = _d;                                   \
} while (0)

static __always_inline void run_kfunc_bench(struct kfunc_bench_results *r,
					     struct task_struct *p);

/* Forward declare get_task_ctx — defined later, needed by bench */
/* 前向声明 get_task_ctx——定义在后面，基准测试需要用到。 */
/* 讲解：C 语言需要先声明后使用，这里为基准函数提前声明。 */
static __always_inline struct cake_task_ctx __arena *
get_task_ctx(struct task_struct *p);

static __always_inline void run_kfunc_bench(struct kfunc_bench_results *r,
					     struct task_struct *p)
{
	/* Suppress CAKE_STATS_ACTIVE on all cores during benchmark */
	/* 基准期间在所有核上抑制 CAKE_STATS_ACTIVE。 */
	/* 置位 bench_active 让遥测暂停，避免污染测量结果。 */
	*(volatile u32 *)&bench_active = 1;
	r->cpu = bpf_get_smp_processor_id();
	r->iterations = BENCH_ITERATIONS;

	/* Zero all entries */
	/* 清零所有条目。 */
	/* min 置为最大值以便后续取最小，其余清零。 */
	#pragma unroll
	for (int i = 0; i < BENCH_MAX_ENTRIES; i++) {
		r->entries[i].min_ns = ~0ULL;
		r->entries[i].max_ns = 0;
		r->entries[i].total_ns = 0;
		r->entries[i].last_value = 0;
	}

	/* Bench: bpf_ktime_get_ns() — legacy CLOCK_MONOTONIC */
	/* bpf_ktime_get_ns()——传统 CLOCK_MONOTONIC 时钟。常规取时开销。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_KTIME_GET_NS], bpf_ktime_get_ns(), i);

	/* Bench: scx_bpf_now() — SCX cached clock */
	/* scx_bpf_now()——SCX 缓存时钟。sched_ext 优化过的取时。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_BPF_NOW], scx_bpf_now(), i);

	/* Bench: bpf_get_smp_processor_id() — CPU identification */
	/* bpf_get_smp_processor_id()——取当前 CPU 号。热路径常用操作。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_GET_SMP_PROC_ID], bpf_get_smp_processor_id(), i);

	/* Bench: bpf_task_from_pid() — PID lookup (kfunc) */
	/* bpf_task_from_pid()——由 PID 查任务（kfunc）。涉及查表，较慢。 */
	{
		s32 pid = p->pid;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct task_struct *t = bpf_task_from_pid(pid);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			if (t) bpf_task_release(t);
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_FROM_PID];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)(t != NULL);
		}
	}

	/* Bench: scx_bpf_test_and_clear_cpu_idle() — idle probe (gate 1 hot path) */
	/* 基准：scx_bpf_test_and_clear_cpu_idle()——空闲探测（Gate 1 热路径）。选核最关键的原子操作。 */
	{
		u32 cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			bool idle = scx_bpf_test_and_clear_cpu_idle(cpu);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TEST_CLEAR_IDLE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)idle;
		}
	}

	/* Bench: scx_bpf_nr_cpu_ids() — topology constant read */
	/* 基准：scx_bpf_nr_cpu_ids()——读取拓扑常量。对比 RODATA 常量的开销。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_NR_CPU_IDS], scx_bpf_nr_cpu_ids(), i);

	/* Bench: get_task_ctx() — scx_task_data arena direct pointer deref */
	/* 基准：get_task_ctx()——arena 直接指针解引用。反映 arena 访问成本。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct cake_task_ctx __arena *t = get_task_ctx(p);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_GET_TASK_CTX];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)(t != NULL);
		}
	}

	/* Bench: scx_bpf_dsq_nr_queued() — DSQ depth query (read-only kfunc) */
	/* 基准：scx_bpf_dsq_nr_queued()——查询 DSQ 深度（只读 kfunc）。派发决策会读它。 */
	{
		u64 dsq_id = LLC_DSQ_BASE + cpu_llc_id[r->cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			s32 nr = scx_bpf_dsq_nr_queued(dsq_id);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_DSQ_NR_QUEUED];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)nr;
		}
	}

	/* Bench: BSS array access — raw global_stats[cpu] field read */
	/* 基准：BSS 数组访问——裸读 global_stats[cpu] 字段。最快的全局数据访问基线。 */
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 v = global_stats[bcpu].total_stopping_ns;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_BSS_ARRAY_ACCESS];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v;
		}
	}

	/* Bench: Arena per_cpu deref — read field from per_cpu[cpu].mbox */
	/* 基准：arena per_cpu 解引用——读取 per_cpu[cpu].mbox 字段。与 BSS 访问对比成本。 */
#ifndef CAKE_RELEASE
	{
		ARENA_ASSOC();
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 v = per_cpu[bcpu].mbox.tick_slice;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_DEREF];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v;
		}
	}
#endif

	/* Bench: Back-to-back scx_bpf_now() pair — calibration baseline.
	 * Measures the overhead of the timing harness itself (2× bpf_ktime_get_ns). */
	/* 基准：连续两次 scx_bpf_now()——校准基线。
	 * 测量计时框架本身的开销（2 次 bpf_ktime_get_ns）。 */
	/* 其它测量结果需减去这个基线，才是被测操作的净耗时。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++) {
		u64 _s = bpf_ktime_get_ns();
		u64 _e = bpf_ktime_get_ns();
		u64 _d = _e - _s;
		struct kfunc_bench_entry *e = &r->entries[BENCH_NOW_PAIR];
		if (_d < e->min_ns) e->min_ns = _d;
		if (_d > e->max_ns) e->max_ns = _d;
		e->total_ns += _d;
		e->samples[i] = _d;
		e->last_value = _d; /* Shows raw overhead of timing harness */
				    /* 展示计时框架的原始开销。即基线本身的数值。 */
	}

	/* Bench: Read cached CPU from mailbox CL0 (Disruptor handoff pattern).
	 * Simulates cake_stopping reading CPU from mailbox instead of calling
	 * bpf_get_smp_processor_id(). Mailbox is L1-hot from prior tick_slice read. */
	/* 基准：从邮箱 CL0 读缓存的 CPU 号（Disruptor 交接模式）。
	 * 模拟 cake_stopping 从邮箱读 CPU，而非调用 bpf_get_smp_processor_id()。
	 * 因为之前读过 tick_slice，邮箱在 L1 中是热的。 */
	/* 验证“从已热的缓存行取值”比调用 kfunc 更省。 */
#ifndef CAKE_RELEASE
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 v = mbox->tick_last_run_at; /* Same CL0 as CPU would be */
								 /* 与 CPU 号同属 CL0。讲解：模拟同一缓存行内取值。 */
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_MBOX_CPU_READ];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v;
		}
	}
#endif

	/* Bench: Read cached tctx pointer from mailbox + field deref.
	 * Simulates reading a pre-cached arena pointer from mailbox CL0,
	 * then dereferencing a field. Compares against get_task_ctx() kfunc. */
	/* 基准：从邮箱读缓存的 tctx 指针并解引用字段。
	 * 模拟先从邮箱 CL0 读预缓存的 arena 指针，再解引用一个字段。
	 * 与 get_task_ctx() kfunc 做对比。 */
	/* 验证缓存指针后再解引用是否比每次调 kfunc 更快。 */
#ifndef CAKE_RELEASE
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		/* Simulate: read a u64 from mailbox (where ptr would be cached),
		 * then read a field from the tctx we already have. */
		/* 模拟：从邮箱读一个 u64（指针本应缓存在此），
		 * 再从已持有的 tctx 读一个字段。 */
		/* 还原“缓存指针+解引用”的真实访问序列。 */
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				volatile u64 ptr_val = mbox->tick_slice; /* Simulate ptr read from CL0 */
									 /* 模拟从 CL0 读指针。代表取缓存指针那一步。 */
				volatile u16 field = tctx->deficit_u16; /* Deref cached ptr */
									/* 解引用缓存指针。代表读字段那一步。 */
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_TCTX_FROM_MBOX];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = field + (u32)ptr_val;
			}
		}
	}
#endif

	/* Bench: bpf_ringbuf_reserve + discard cycle.
	 * Measures the cost of the BPF ringbuf API (Disruptor pattern #3).
	 * Uses reserve+discard (not submit) to avoid requiring a consumer. */
	/* 基准：bpf_ringbuf_reserve + discard 一轮。
	 * 测量 BPF ringbuf API 的成本（Disruptor 模式 #3）。
	 * 用 reserve+discard（而非 submit）以免需要消费者。 */
	/* 评估用 ringbuf 做数据交接的固有开销。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			void *slot = bpf_ringbuf_reserve(&bench_ringbuf, 8, 0);
			if (slot)
				bpf_ringbuf_discard(slot, 0);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_RINGBUF_CYCLE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)(slot != NULL);
		}
	}

	/* Bench: task_struct field reads — p->scx.slice + p->nvcsw */
	/* 基准：读取 task_struct 字段——p->scx.slice + p->nvcsw。热路径直接读内核字段的代价。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 sl = p->scx.slice;
			volatile u64 nv = p->nvcsw;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_STRUCT_READ];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = sl + nv;
		}
	}

	/* Bench: RODATA array lookup — cpu_llc_id[cpu] + quantum_ns */
	/* 基准：RODATA 数组查表——cpu_llc_id[cpu] + quantum_ns。只读常量访问，通常极快。 */
	{
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 llc = cpu_llc_id[bcpu];
			volatile u64 ts = quantum_ns; /* RODATA const read */
						      /* 读取 RODATA 常量。JIT 可折叠为立即数。 */
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_RODATA_LOOKUP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ts + llc;
		}
	}

	/* Bench: Bitflag operations — shift+mask+branchless yielder pattern.
	 * Simulates the full yielder detection + branchless flag set from stopping. */
	/* 基准：位标志操作——位移+掩码+无分支的让出者判断模式。
	 * 模拟 stopping 中完整的让出者检测 + 无分支置标志。 */
	/* 验证无分支写法能否避免分支预测失败带来的抖动。 */
	{
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			u32 packed = tctx->packed_info;
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				/* Extract yielder flag */
				/* 提取让出者标志。从 packed 中取出对应位。 */
				u32 yl_mask = (u32)CAKE_FLOW_YIELDER << SHIFT_FLAGS;
				volatile u32 result = (packed & ~yl_mask) | (yl_mask & -(u32)1);
				/* Extract nf + yl bits */
				/* 提取新流位 + 让出位。验证多位提取的组合开销。 */
				volatile u8 nf = (result >> SHIFT_FLAGS) & 1;
				volatile u8 yl = (result >> SHIFT_FLAGS) & (u32)CAKE_FLOW_YIELDER;
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_BITFLAG_OPS];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = nf + yl + result;
			}
		}
	}

	/* Bench: EWMA computation (legacy, slot preserved for comparison).
	 * Reads tick_slice from cpu_bss. compute_ewma() removed in PELT transition. */
	/* 基准：EWMA 计算（遗留项，槽位保留以便对比）。
	 * 从 cpu_bss 读 tick_slice。转向 PELT 后 compute_ewma() 已移除。 */
	/* 保留旧算法测量点，方便与新的 PELT 分类做对比。 */
	{
		s32 ewma_cpu = bpf_get_smp_processor_id();
		u64 tick_sl_bss = cpu_bss[ewma_cpu & (CAKE_MAX_CPUS - 1)].tick_slice;
		u32 fused_val = 0x00C80064; /* Simulated: avg=200, deficit=100 */
					    /* 模拟值：平均=200，赤字=100。给算法一个固定输入。 */
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* 1.0.4 path: tick_slice from BSS, remaining from p->scx */
			/* 1.0.4 路径：tick_slice 取自 BSS，剩余片取自 p->scx。还原真实数据来源。 */
			u64 tick_sl = tick_sl_bss;   /* cpu_bss — already L1 hot */
						     /* cpu_bss——已在 L1 中。模拟热缓存访问。 */
			u64 rem_sl = p->scx.slice;   /* task_struct — already read */
						     /* task_struct——已读过。复用已加载的字段。 */
			u16 old_avg = (u16)(fused_val >> 16);
			u16 deficit = (u16)(fused_val & 0xFFFF);
			u64 used = (tick_sl > rem_sl) ? (tick_sl - rem_sl) : 0;
			u16 rt_us = (u16)(used >> 10);
			volatile u16 new_avg = (old_avg * 7 + rt_us) >> 3;
			volatile u16 new_def = (deficit > rt_us) ? deficit - rt_us : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_RESERVED_17];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = new_avg + new_def;
		}
	}

	/* Bench: Mailbox CL0 multi-field read simulation.
	 * Reads cached_tctx_ptr + cached_deficit + cached_packed from CL0.
	 * Simulates the full cake_stopping mailbox-only path (zero arena). */
	/* 基准：邮箱 CL0 多字段读取模拟。
	 * 从 CL0 读取 cached_tctx_ptr + cached_deficit + cached_packed。
	 * 模拟 cake_stopping 纯邮箱路径（不碰 arena）。 */
	/* 验证把所需数据集中在一条缓存行时的并行读取收益。 */
#ifndef CAKE_RELEASE
	{
		ARENA_ASSOC();
		u32 bcpu = r->cpu & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[bcpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 ptr = mbox->cached_tctx_ptr;
			volatile u32 fused = mbox->cached_deficit;
			volatile u32 packed = mbox->cached_packed;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PSYCHIC_HIT_SIM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ptr + fused + packed;
		}
	}
#endif

	/* Bench: scx_bpf_test_and_clear_cpu_idle(sibling) — cross-CPU contention.
	 * Simulates cross-CPU idle probing where we probe a DIFFERENT CPU's idle state.
	 * This reveals MESI contention cost: the idle bitmap cache line must
	 * be snooped from the remote CPU owner (30-100ns on Zen 5).
	 * Compare against BENCH_TEST_CLEAR_IDLE (local CPU, ~15ns). */
	/* 基准：scx_bpf_test_and_clear_cpu_idle(兄弟核)——跨 CPU 争用。
	 * 模拟探测另一个 CPU 的空闲状态。
	 * 这揭示 MESI 争用成本：空闲位图缓存行必须从远端 CPU 拥有者处窥探
	 *（Zen 5 上 30-100ns）。与 BENCH_TEST_CLEAR_IDLE（本地，约 15ns）对比。 */
	/* 量化“探测别的核”比“探测自己”贵多少，指导选核策略。 */
	{
		u32 local_cpu = bpf_get_smp_processor_id();
		/* Pick SMT sibling (XOR 1 gives the hyper-thread pair on Zen) */
		/* 选 SMT 兄弟核（Zen 上异或 1 即得到超线程配对）。兄弟核最可能共享缓存。 */
		s32 remote_cpu = (s32)((local_cpu ^ 1) & (CAKE_MAX_CPUS - 1));
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			bool idle = scx_bpf_test_and_clear_cpu_idle(remote_cpu);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_IDLE_REMOTE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)idle;
		}
	}

	/* Bench: Read-only idle smtmask check — zero-contention alternative.
	 * scx_bpf_get_idle_smtmask() returns a reference to the SMT idle mask
	 * (per-core fully-idle tracking). cpumask_test_cpu is a pure read —
	 * no atomic test-and-clear, no cache line invalidation.
	 * This is the fastest way to CHECK if a CPU is idle without CLAIMING it.
	 * Use case: pre-screen before committing with test_and_clear. */
	/* 基准：只读的空闲 smtmask 检查——零争用替代方案。
	 * scx_bpf_get_idle_smtmask() 返回 SMT 空闲掩码的引用（按核跟踪整核是否全空闲）。
	 * cpumask_test_cpu 是纯读——无原子测试清、无缓存行失效。
	 * 这是“只检查不占用”一个 CPU 是否空闲的最快方式。
	 * 用途：在用 test_and_clear 正式认领前先做预筛。 */
	/* 只读检查可先廉价过滤，减少昂贵的原子认领次数。 */
	{
		u32 local_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			const struct cpumask *smtmask = scx_bpf_get_idle_smtmask();
			volatile bool fully_idle = bpf_cpumask_test_cpu(local_cpu, smtmask);
			scx_bpf_put_idle_cpumask(smtmask);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_IDLE_SMTMASK];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)fully_idle;
		}
	}

	/* Bench: Full Disruptor handoff read — simulates cake_stopping.
	 * Reads all 5 CL0 fields from the local CPU mailbox in sequence.
	 * Measures MLP benefit of concentrating all handoff data on one CL. */
	/* 基准：完整 Disruptor 交接读取——模拟 cake_stopping。
	 * 依次读取本地 CPU 邮箱 CL0 的全部 5 个字段。
	 * 测量把所有交接数据集中在一条缓存行带来的内存级并行(MLP)收益。 */
	/* 字段同行时 CPU 可并行发起加载，验证这种布局的优势。 */
#ifndef CAKE_RELEASE
	{
		u32 local_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		struct mega_mailbox_entry __arena *mbox = &per_cpu[local_cpu].mbox;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 _ptr = mbox->cached_tctx_ptr;
			volatile u32 _fused = mbox->cached_deficit;
			volatile u32 _packed = mbox->cached_packed;
			volatile u64 _nvcsw = mbox->cached_nvcsw;
			volatile u64 _slice = mbox->tick_slice;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_DISRUPTOR_READ];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = _ptr + _fused + _packed + _nvcsw + _slice;
		}
	}
#endif

	/* Bench: get_task_ctx + arena CL0 read — simulates cake_running.
	 * Measures the kfunc + dependent arena load chain.
	 * Uses bpf_get_current_task_btf() as the task source. */
	/* 基准：get_task_ctx + 读 arena CL0——模拟 cake_running。
	 * 测量 kfunc + 依赖式 arena 加载链。
	 * 用 bpf_get_current_task_btf() 作为任务来源。 */
	/* 还原 running 回调“取上下文再读字段”的真实依赖链成本。 */
	{
		struct task_struct *cur = bpf_get_current_task_btf();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct cake_task_ctx __arena *tctx = get_task_ctx(cur);
			volatile u32 _packed = tctx ? tctx->packed_info : 0;
			volatile u16 _fused = tctx ? tctx->deficit_u16 : 0;
			volatile u64 _nvcsw = tctx ? tctx->nvcsw_snapshot : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TCTX_COLD_SIM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = _packed + _fused + _nvcsw;
		}
	}

	/* Bench: Arena stride — walk 16 per_cpu mailbox entries.
	 * Forces TLB walks across arena pages. With 4KB pages, each per_cpu
	 * block (64B release / 128B debug) may share pages. With hugepages
	 * (2MB), all 16 fit in one TLB entry. Delta vs BENCH_ARENA_DEREF
	 * (single hot access) reveals the TLB miss tax. */
	/* 基准：arena 跨步——遍历 16 个 per_cpu 邮箱项。
	 * 强制跨 arena 页做 TLB 遍历。4KB 页时各 per_cpu 块（发布 64B/调试 128B）
	 * 可能共享页；用大页（2MB）时 16 个都落在一个 TLB 项里。
	 * 与 BENCH_ARENA_DEREF（单次热访问）的差值即 TLB 缺失的代价。 */
	/* 量化 TLB 缺失开销，判断是否值得用大页。 */
#ifndef CAKE_RELEASE
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 sum = 0;
			#pragma unroll
			for (int c = 0; c < 16; c++) {
				sum += per_cpu[c & (CAKE_MAX_CPUS - 1)].mbox.tick_last_run_at;
			}
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_STRIDE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = sum;
		}
	}
#endif

	/* ═══ NEW ENTRIES (24–42): eBPF helpers + SCX kfuncs ═══ */
	/* ═══ 新增条目（24–42）：eBPF 辅助函数 + SCX kfunc ═══ */
	/* 这一组对比各类内核辅助函数的开销。 */

	/* Bench: bpf_ktime_get_boot_ns() — suspend-aware monotonic clock */
	/* bpf_ktime_get_boot_ns()——含休眠时间的单调时钟。跨挂起仍连续但略慢。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_KTIME_BOOT_NS], bpf_ktime_get_boot_ns(), i);

	/* NOTE: bpf_ktime_get_coarse_ns (slot 25), bpf_jiffies64 (slot 26),
	 * and bpf_ktime_get_tai_ns (slot 27) are NOT available for struct_ops
	 * programs — the kernel rejects them at load time. Slots left empty. */
	/* 注意：bpf_ktime_get_coarse_ns（槽 25）、bpf_jiffies64（槽 26）、
	 * bpf_ktime_get_tai_ns（槽 27）对 struct_ops 程序不可用——内核在加载时拒绝。槽位留空。 */
	/* 讲解：这些时钟函数在调度器类型程序里被内核禁用，故无法测量。 */

	/* Bench: bpf_get_current_pid_tgid() — PID+TGID in single call */
	/* 基准：bpf_get_current_pid_tgid()——一次取回 PID+TGID。讲解：合并读取更省。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_CURRENT_PID_TGID], bpf_get_current_pid_tgid(), i);

	/* Bench: bpf_get_current_task_btf() — get task_struct directly */
	/* 基准：bpf_get_current_task_btf()——直接取 task_struct。讲解：省去查表可直接读字段。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_CURRENT_TASK_BTF], (u64)bpf_get_current_task_btf(), i);

	/* Bench: bpf_get_current_comm() — read task comm name (16 bytes) */
	/* 基准：bpf_get_current_comm()——读任务名（16 字节）。讲解：涉及拷贝，成本较高。 */
	{
		char comm[16];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			long ret = bpf_get_current_comm(comm, sizeof(comm));
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CURRENT_COMM];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)ret;
		}
	}

	/* Bench: bpf_get_numa_node_id() — current NUMA node */
	/* 基准：bpf_get_numa_node_id()——取当前 NUMA 节点。讲解：多路系统归属判断。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_NUMA_NODE_ID], bpf_get_numa_node_id(), i);

	/* Bench: scx_bpf_task_running(p) — check if task is currently on-CPU */
	/* 基准：scx_bpf_task_running(p)——检查任务是否正在 CPU 上运行。讲解：抢占决策用。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_TASK_RUNNING], scx_bpf_task_running(p), i);

	/* Bench: scx_bpf_task_cpu(p) — get task's current CPU */
	/* 基准：scx_bpf_task_cpu(p)——取任务当前 CPU。讲解：对比邮箱缓存 CPU 的开销。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_TASK_CPU], scx_bpf_task_cpu(p), i);

	/* Bench: scx_bpf_nr_node_ids() — NUMA node count (topology constant) */
	/* 基准：scx_bpf_nr_node_ids()——取 NUMA 节点数（拓扑常量）。讲解：对比 RODATA 方式。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_SCX_NR_NODE_IDS], scx_bpf_nr_node_ids(), i);

	/* Bench: scx_bpf_cpuperf_cur(cpu) — current CPU performance level */
	/* 基准：scx_bpf_cpuperf_cur(cpu)——取当前性能档位。讲解：频率调控相关。 */
	{
		s32 bench_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_CPUPERF_CUR], scx_bpf_cpuperf_cur(bench_cpu), i);
	}

	/* Bench: bpf_task_storage_get() — standard per-task map lookup.
	 * This is the approach cake replaced with arena. Measuring the cost
	 * validates our arena design decision. */
	/* 基准：bpf_task_storage_get()——标准的每任务 map 查找。
	 * 这是 cake 用 arena 替代掉的方式，测量它可验证我们采用 arena 的决策。 */
	/* 讲解：量化标准存储的开销，佐证改用 arena 的收益。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			struct bench_task_val *v = bpf_task_storage_get(
				&bench_task_storage, p, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_STORAGE_GET];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = v ? v->dummy : 0;
		}
	}

	/* Bench: scx_bpf_pick_idle_cpu() — kernel's idle CPU scanner */
	/* 基准：scx_bpf_pick_idle_cpu()——内核的空闲核扫描器。讲解：Gate 3 回退所用，较慢。 */
	{
		const struct cpumask *online = scx_bpf_get_online_cpumask();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_PICK_IDLE_CPU],
				  scx_bpf_pick_idle_cpu(online, 0), i);
		scx_bpf_put_cpumask(online);
	}

	/* Bench: scx_bpf_get_idle_cpumask() + put — full idle mask cycle */
	/* 基准：scx_bpf_get_idle_cpumask() + put——完整的空闲掩码取放一轮。讲解：整块掩码方式的成本。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			const struct cpumask *idle = scx_bpf_get_idle_cpumask();
			scx_bpf_put_idle_cpumask(idle);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SCX_IDLE_CPUMASK];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = 0;
		}
	}

	/* Bench: scx_bpf_kick_cpu() — IPI preemption cost.
	 * Kicks current CPU with no flags (cheapest IPI). */
	/* 基准：scx_bpf_kick_cpu()——IPI 抢占成本。
	 * 无标志地踢当前 CPU（最便宜的 IPI）。 */
	/* 讲解：注意踢自己是近乎空操作，真实跨核 IPI 见 BENCH_KICK_REMOTE。 */
	{
		s32 self_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_KICK_CPU],
				  (scx_bpf_kick_cpu(self_cpu, 0), 0), i);
	}

	/* Bench: bpf_get_prandom_u32() — pseudo-RNG cost */
	/* 基准：bpf_get_prandom_u32()——伪随机数成本。讲解：对比自实现 xorshift。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_PRANDOM_U32], bpf_get_prandom_u32(), i);

	/* Bench: bpf_spin_lock + unlock cycle — lock contention baseline */
	/* 基准：bpf_spin_lock + unlock 一轮——锁争用基线。讲解：对比无锁读的代价。 */
	{
		u32 key = 0;
		struct bench_lock_data *ld = bpf_map_lookup_elem(&bench_lock_map, &key);
		if (ld) {
			#pragma unroll
			for (int i = 0; i < BENCH_ITERATIONS; i++) {
				u64 _s = bpf_ktime_get_ns();
				bpf_spin_lock(&ld->lock);
				ld->counter++;
				bpf_spin_unlock(&ld->lock);
				u64 _e = bpf_ktime_get_ns();
				u64 _d = _e - _s;
				struct kfunc_bench_entry *e = &r->entries[BENCH_SPIN_LOCK];
				if (_d < e->min_ns) e->min_ns = _d;
				if (_d > e->max_ns) e->max_ns = _d;
				e->total_ns += _d;
				e->samples[i] = _d;
				e->last_value = ld->counter;
			}
		}
	}

	/* Bench: scx_bpf_cpuperf_cap(cpu) — max performance capacity */
	/* 基准：scx_bpf_cpuperf_cap(cpu)——取最大性能容量。讲解：异构核容量缩放会用到。 */
	{
		s32 cap_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_SCX_CPUPERF_CAP], scx_bpf_cpuperf_cap(cap_cpu), i);
	}

	/* ═══ CAKE COMPETITOR ENTRIES (43–49) ═══ */
	/* ═══ cake 自研对照条目（43–49） ═══ */
	/* 讲解：这一组把 cake 的优化写法与等价 kfunc 做对比。 */

	/* Bench: RODATA nr_cpus read — JIT-constant, should be ~0ns overhead */
	/* 基准：读 RODATA nr_cpus——JIT 常量，开销应约 0ns。讲解：对比 nr_cpu_ids kfunc。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_RODATA_NR_CPUS], (u64)nr_cpus, i);

	/* Bench: RODATA nr_nodes read — JIT-constant vs scx_bpf_nr_node_ids() */
	/* 基准：读 RODATA nr_nodes——JIT 常量，对比 scx_bpf_nr_node_ids()。讲解：常量读更省。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_RODATA_NR_NODES], (u64)nr_nodes, i);

	/* Bench: RODATA cpuperf_cap_table[cpu] — per-CPU array vs kfunc */
	/* 基准：读 RODATA cpuperf_cap_table[cpu]——每 CPU 数组，对比 kfunc。讲解：预烘焙常量替代运行时查询。 */
	{
		s32 perf_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_RODATA_CPUPERF_CAP],
				  (u64)cpuperf_cap_table[perf_cpu & (CAKE_MAX_CPUS - 1)], i);
	}

	/* Bench: p->pid + p->tgid direct read — same cost as arena-cached fields
	 * (both are fixed-offset reads from an already-hot struct base pointer) */
	/* 基准：直接读 p->pid + p->tgid——与 arena 缓存字段成本相同
	 *（两者都是从已热的结构体基址做固定偏移读取）。 */
	/* 讲解：说明既然内核字段读同样便宜，某些场景无需再缓存。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 cached_pid = ((u64)p->tgid << 32) | p->pid;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_PID_TGID];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = cached_pid;
		}
	}

	/* Bench: Mbox CL0 cached_cpu read — already-hot CL0 vs scx_bpf_task_cpu kfunc */
	/* 基准：读邮箱 CL0 缓存 CPU——已热的 CL0 对比 scx_bpf_task_cpu kfunc。讲解：本地缓存优于 kfunc。 */
#ifndef CAKE_RELEASE
	{
		s32 mbox_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++)
			BENCH_ONE(&r->entries[BENCH_MBOX_TASK_CPU],
				  (u64)per_cpu[mbox_cpu & (CAKE_MAX_CPUS - 1)].mbox.cached_cpu, i);
	}
#endif

	/* Bench: CL0 lock-free atomic read — Disruptor pattern vs spin_lock cycle.
	 * Reads 3 adjacent CL0 fields with zero locking overhead. */
	/* 基准：CL0 无锁原子读——Disruptor 模式对比自旋锁一轮。
	 * 零加锁开销地读取 3 个相邻 CL0 字段。 */
	/* 讲解：单写多读场景无需上锁，验证无锁读的显著优势。 */
#ifndef CAKE_RELEASE
	{
		s32 lf_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 lf_val =
				per_cpu[lf_cpu & (CAKE_MAX_CPUS - 1)].mbox.cached_cpu +
				per_cpu[lf_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_tier +
				cpu_bss[lf_cpu & (CAKE_MAX_CPUS - 1)].is_yielder;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CL0_LOCKFREE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = lf_val;
		}
	}
#endif

	/* Bench: BSS xorshift32 PRNG — zero-kfunc RNG vs bpf_get_prandom_u32 */
	/* 基准：BSS xorshift32 伪随机——无 kfunc 的随机源，对比 bpf_get_prandom_u32。讲解：自算随机更快。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			u32 x = bench_xorshift_state;
			x ^= x << 13;
			x ^= x >> 17;
			x ^= x << 5;
			bench_xorshift_state = x;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_BSS_XORSHIFT];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)x;
		}
	}

	/* ═══ KERNEL FREE DATA PROBES (50–54) ═══
	 * These read kernel-maintained task_struct fields at ~3ns to validate
	 * whether they can replace BPF-side computation (EWMA, classification).
	 * Critical question: Does PELT still update under sched_ext? */
	/* ═══ 内核“免费”数据探测（50–54） ═══
	 * 以约 3ns 读取内核维护的 task_struct 字段，验证它们能否
	 * 取代 BPF 侧的计算（EWMA、分类）。
	 * 关键问题：在 sched_ext 下 PELT 是否仍在更新？ */
	/* 讲解：若内核已免费维护 PELT，就没必要在 BPF 里自算利用率。 */

	/* Bench: PELT util_avg — kernel's PELT utilization metric (0-1024).
	 * Non-zero and changing confirms PELT is maintained under sched_ext.
	 * Zero BPF compute cost — kernel does all the work. */
	/* 基准：PELT util_avg——内核的 PELT 利用率指标（0-1024）。
	 * 非零且变化即证明 sched_ext 下 PELT 仍在维护。
	 * BPF 计算成本为零——全部工作由内核完成。 */
	/* 讲解：这是 cake 分类的核心数据来源，先确认它可靠再依赖它。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 util = p->se.avg.util_avg;
			volatile u64 runnable = p->se.avg.runnable_avg;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PELT_UTIL_AVG];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (util << 16) | runnable; /* Pack both for TUI */
								 /* 把两者打包给 TUI。讲解：一个 u64 同时回传两项指标。 */
		}
	}

	/* Bench: PELT runnable_avg alone — single field read baseline.
	 * Should be ~3ns (fixed offset from p, already in register). */
	/* 基准：单读 PELT runnable_avg——单字段读取基线。
	 * 应约 3ns（相对 p 固定偏移，p 已在寄存器里）。 */
	/* 讲解：给出单个内核字段读取的最小成本参照。 */
	#pragma unroll
	for (int i = 0; i < BENCH_ITERATIONS; i++)
		BENCH_ONE(&r->entries[BENCH_PELT_RUNNABLE_AVG], p->se.avg.runnable_avg, i);

	/* Bench: schedstats nr_wakeups — cumulative wakeup count.
	 * Requires CONFIG_SCHEDSTATS=y. Guarded for release builds where
	 * the target kernel may have CONFIG_SCHEDSTATS=n (common on aarch64). */
	/* 基准：schedstats nr_wakeups——累计唤醒次数。
	 * 需要 CONFIG_SCHEDSTATS=y。发布版做了保护，因为目标内核
	 * 可能 CONFIG_SCHEDSTATS=n（aarch64 上常见）。 */
	/* 讲解：该字段依赖内核配置，缺失时读它会出错，故仅调试版启用。 */
#ifndef CAKE_RELEASE
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u64 wakeups = p->stats.nr_wakeups;
			volatile u64 wakeups_sync = p->stats.nr_wakeups_sync;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SCHEDSTATS_WAKEUPS];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (wakeups << 32) | wakeups_sync;
		}
	}
#endif

	/* Bench: p->policy + p->in_iowait — free classification signals.
	 * policy: SCHED_NORMAL=0, SCHED_BATCH=3, SCHED_IDLE=5.
	 * in_iowait: 1 if task is waiting for I/O. */
	/* 基准：p->policy + p->in_iowait——免费的分类信号。
	 * policy：SCHED_NORMAL=0、SCHED_BATCH=3、SCHED_IDLE=5。
	 * in_iowait：任务在等 I/O 时为 1。 */
	/* 讲解：这些字段几乎零成本，可辅助判断任务性质。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 policy = p->policy;
			volatile u32 prio = p->prio;
			volatile u32 flags = p->flags;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_TASK_POLICY_FLAGS];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ((u64)policy << 32) | ((u64)prio << 16) | (flags & 0xFFFF);
		}
	}

	/* Bench: PELT read + tier classify.
	 * The critical comparison: 3ns PELT read replaces 12ns compute_ewma().
	 * Reads util_avg and does tier boundary compare. */
	/* 基准：PELT 读取 + 分层。
	 * 关键对比：3ns 的 PELT 读取取代 12ns 的 compute_ewma()。
	 * 读 util_avg 并做层边界比较。 */
	/* 讲解：量化改用 PELT 的净收益，佐证放弃自算 EWMA 的决策。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			u64 util = p->se.avg.util_avg;
			/* Tier classification using PELT util_avg */
			/* 用 PELT util_avg 做分层。讲解：按利用率阈值划入不同层。 */
			volatile u8 tier = (util > 512) ? 2 : ((util > 128) ? 1 : 0);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PELT_VS_EWMA];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = ((u64)tier << 32) | util;
		}
	}

	/* ═══ END-TO-END WORKFLOW COMPARISONS (55–62) ═══
	 * These simulate FULL scheduler operations as they'd be used in practice,
	 * not isolated micro-ops. Compare storage backends, idle selection
	 * strategies, classification algorithms, and SMT probing approaches. */
	/* ═══ 端到端流程对比（55–62） ═══
	 * 这些模拟实际使用中的完整调度操作，而非孤立的微操作。
	 * 对比存储后端、空闲选择策略、分类算法与 SMT 探测方式。 */
	/* 讲解：整段流程一起测才能反映真实调度成本，指导整体设计取舍。 */

	/* Bench 55: BSS cpu_bss write+read roundtrip — cake 1.0.4 storage.
	 * Write idle_hint+is_yielder+run_start (like running), read back
	 * (like select_cpu gate checks). This is the REAL cost of BSS storage. */
	/* 基准 55：BSS cpu_bss 写+读往返——cake 1.0.4 的存储方式。
	 * 写 idle_hint+is_yielder+run_start（如 running），再回读
	 *（如 select_cpu 的门检查）。这是 BSS 存储的真实成本。 */
	/* 讲解：还原“running 写、select_cpu 读”的真实往返，衡量 BSS 方案代价。 */
	{
		s32 bss_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Write (like cake_running writes to cpu_bss) */
			/* 写入（如 cake_running 写 cpu_bss）。讲解：模拟切入时的状态写。 */
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].idle_hint = 1;
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].is_yielder = 0;
			cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].run_start = 12345678ULL;
			asm volatile("" ::: "memory");
			/* Read back (like cake_select_cpu reads cpu_bss) */
			/* 回读（如 cake_select_cpu 读 cpu_bss）。讲解：模拟选核时的状态读。 */
			volatile u8 hint = cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].idle_hint;
			volatile u8 yielder = cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].is_yielder;
			volatile u64 start = cpu_bss[bss_cpu & (CAKE_MAX_CPUS - 1)].run_start;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_STORAGE_ROUNDTRIP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = hint + yielder + start;
		}
	}

	/* Bench 56: Arena write+read roundtrip — same operation via arena.
	 * Compare against slot 55 to see the TLB walk penalty. */
	/* 基准 56：arena 写+读往返——同样操作但走 arena。
	 * 与槽 55 对比即可看出 TLB 遍历的额外代价。 */
	/* 讲解：直接量化 arena 相对 BSS 的 TLB 开销差异。 */
#ifndef CAKE_RELEASE
	{
		s32 ar_cpu = bpf_get_smp_processor_id();
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Write to arena mbox (like old cake_running) */
			/* 写入 arena 邮箱（如旧版 cake_running）。讲解：模拟旧的写路径。 */
			per_cpu[ar_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_last_run_at = 0xCAFEBABE;
			asm volatile("" ::: "memory");
			/* Read back from arena (like old cake_select_cpu gate check) */
			/* 从 arena 回读（如旧版 cake_select_cpu 门检查）。讲解：模拟旧的读路径。 */
			volatile u64 readback = per_cpu[ar_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_last_run_at;
			volatile u32 tier = per_cpu[ar_cpu & (CAKE_MAX_CPUS - 1)].mbox.tick_tier;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_ARENA_ROUNDTRIP];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = readback + tier;
		}
	}
#endif

	/* Bench 57: 3-probe cascade simulation — cake's select_cpu flow.
	 * Tests: prev idle check → BSS[sib] idle_hint → BSS[home] idle_hint.
	 * This is the FULL cascade data access pattern. */
	/* 基准 57：三探测级联模拟——cake 的 select_cpu 流程。
	 * 测试：prev 空闲检查 → BSS[兄弟].idle_hint → BSS[归属].idle_hint。
	 * 这是完整的级联数据访问模式。 */
	/* 讲解：还原自研多级选核的真实数据访问，与内核 pick_idle 对比。 */
	{
		s32 self = bpf_get_smp_processor_id();
		s32 sib = cpu_sibling_map[self & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Probe 1: prev idle? (test_and_clear is the real op) */
			/* 探测 1：prev 是否空闲？（真实操作是 test_and_clear）。讲解：最优的第一门。 */
			volatile bool prev_idle = scx_bpf_test_and_clear_cpu_idle(self);
			/* Probe 2: sibling idle_hint from BSS? */
			/* 探测 2：从 BSS 读兄弟核的 idle_hint。讲解：廉价的只读提示。 */
			volatile u8 sib_idle = cpu_bss[sib & (CAKE_MAX_CPUS - 1)].idle_hint;
			/* Probe 3: home CPU idle_hint from BSS? (simulated as prev) */
			/* 探测 3：从 BSS 读归属核的 idle_hint（此处用 prev 模拟）。讲解：回到家 CPU 的尝试。 */
			volatile u8 home_idle = cpu_bss[self & (CAKE_MAX_CPUS - 1)].idle_hint;
			/* Gate decision */
			/* 门决策。讲解：按优先级挑出最终 CPU。 */
			volatile s32 result = prev_idle ? self :
						(sib_idle ? sib : (home_idle ? self : -1));
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CASCADE_VS_PICK];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)result;
		}
	}

	/* Bench 58: pick_idle_cpu full path — bpfland/cosmos approach.
	 * kfunc + cpumask allowed check + SMT filter. Compare vs slot 57. */
	/* 基准 58：pick_idle_cpu 完整路径——bpfland/cosmos 的做法。
	 * kfunc + 亲和掩码校验 + SMT 过滤。与槽 57 对比。 */
	/* 讲解：对照其它调度器的选核方案，验证 cake 级联是否更优。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Full pick_idle path: kfunc scan + affinity verify */
			/* 完整 pick_idle 路径：kfunc 扫描 + 亲和校验。讲解：内核选核的真实成本。 */
			s32 found_cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
			/* Verify found CPU is valid (bpfland does this) */
			/* 校验选中的 CPU 是否合法（bpfland 会做）。讲解：确保结果在允许集合内。 */
			volatile bool valid = (found_cpu >= 0) &&
				bpf_cpumask_test_cpu(found_cpu, p->cpus_ptr);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PICK_IDLE_FULL];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = (u64)found_cpu + (u64)valid;
		}
	}

	/* Bench 59: Weight-based classification (bpfland approach).
	 * Reads p->scx.weight and computes vtime offset — the FULL
	 * classification path of bpfland. Compare vs slot 17 (legacy EWMA, now reserved). */
	/* 基准 59：基于权重的分类（bpfland 做法）。
	 * 读 p->scx.weight 并算出 vtime 偏移——bpfland 完整的分类路径。
	 * 与槽 17（遗留 EWMA，现为保留）对比。 */
	/* 讲解：对照 bpfland 的权重分类，评估各算法的计算成本。 */
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			volatile u32 weight = p->scx.weight;
			/* bpfland: vtime += slice_lag * 100 / weight */
			/* bpfland：vtime += 滞后 * 100 / weight。讲解：权重越大 vtime 增长越慢。 */
			volatile u64 vtime_offset = (40ULL * 1000000ULL * 100ULL) /
				(weight ? weight : 1);
			/* bpfland: task_slice(p) = slice_ns * 100 / weight */
			/* bpfland：时间片 = slice_ns * 100 / weight。讲解：按权重缩放时间片。 */
			volatile u64 slice = (5000000ULL * 100ULL) /
				(weight ? weight : 1);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CLASSIFY_WEIGHT];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = vtime_offset + slice;
		}
	}

	/* Bench 60: Latency-critical classification (lavd approach).
	 * Reads task wakeup stats + computes latency criticality score.
	 * Simulates lavd's update_stat_for_running key path. Compare vs 17.
	 * Requires CONFIG_SCHEDSTATS=y for p->stats.nr_wakeups access. */
	/* 基准 60：延迟关键度分类（lavd 做法）。
	 * 读任务唤醒统计并算出延迟关键度分数。
	 * 模拟 lavd 的 update_stat_for_running 关键路径。与槽 17 对比。
	 * 访问 p->stats.nr_wakeups 需要 CONFIG_SCHEDSTATS=y。 */
	/* 讲解：对照 lavd 的打分式分类，评估其计算开销。 */
#ifndef CAKE_RELEASE
	{
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* lavd reads these per-task stats to compute lat_cri */
			/* lavd 读取这些每任务统计来算延迟关键度。讲解：还原其输入数据。 */
			volatile u64 wakeups = p->stats.nr_wakeups;
			volatile u64 sync_wakeups = p->stats.nr_wakeups_sync;
			volatile u64 nvcsw = p->nvcsw;
			volatile u64 nivcsw = p->nivcsw;
			/* lavd's lat_cri = f(sync_ratio, run_freq) */
			/* lavd 的延迟关键度 = f(同步比, 运行频率)。讲解：由多项比率合成一个分数。 */
			u64 total = wakeups ? wakeups : 1;
			volatile u64 sync_ratio = (sync_wakeups * 1000) / total;
			volatile u64 cs_ratio = (nvcsw * 1000) / (nvcsw + nivcsw + 1);
			volatile u64 lat_score = sync_ratio + cs_ratio;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_CLASSIFY_LATCRI];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = lat_score;
		}
	}
#endif

	/* Bench 61: cake SMT probe — test_and_clear(sibling) + BSS check.
	 * This is cake's idle sibling probe: atomic idle clear + BSS idle_hint read.
	 * The FULL SMT probe path as used in select_cpu. */
	/* 基准 61：cake 的 SMT 探测——test_and_clear(兄弟) + BSS 检查。
	 * 这是 cake 的空闲兄弟探测：原子清空闲位 + 读 BSS idle_hint。
	 * 与 select_cpu 中所用的完整 SMT 探测路径一致。 */
	/* 讲解：还原 cake 判断兄弟核可用性的真实序列。 */

	{
		s32 self_cpu = bpf_get_smp_processor_id();
		s32 sib_cpu = cpu_sibling_map[self_cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* Cake: atomic test_and_clear on sibling */
			/* cake：对兄弟核做原子 test_and_clear。讲解：认领兄弟核为空闲。 */
			volatile bool sib_idle = scx_bpf_test_and_clear_cpu_idle(
				sib_cpu & (CAKE_MAX_CPUS - 1));
			/* Plus BSS hint read (what running wrote) */
			/* 再加读 BSS 提示（running 写入的）。讲解：结合廉价提示辅助判断。 */
			volatile u8 hint = cpu_bss[sib_cpu & (CAKE_MAX_CPUS - 1)].idle_hint;
			volatile bool should_use = sib_idle || hint;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SMT_CAKE_PROBE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = should_use;
		}
	}

	/* Bench 62: bpfland/cosmos SMT probe — cpumask-based contention check.
	 * is_smt_contended(): get idle smtmask → cpumask_test_cpu(sibling).
	 * Requires kfunc for smtmask + cpumask ops. Compare vs slot 61. */
	/* 基准 62：bpfland/cosmos 的 SMT 探测——基于 cpumask 的争用检查。
	 * is_smt_contended()：取空闲 smtmask → cpumask_test_cpu(兄弟)。
	 * 需要 kfunc 取掩码 + cpumask 操作。与槽 61 对比。 */
	/* 讲解：对照掩码扫描方案，验证 cake 的原子探测是否更快。 */
	{
		s32 smt_cpu = bpf_get_smp_processor_id();
		s32 smt_sib = cpu_sibling_map[smt_cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			/* bpfland: get idle SMT mask + test if sibling is in it */
			/* bpfland：取空闲 SMT 掩码 + 测试兄弟核是否在其中。讲解：整块掩码方式。 */
			const struct cpumask *idle_smt = scx_bpf_get_idle_smtmask();
			volatile bool sib_fully_idle =
				bpf_cpumask_test_cpu(smt_sib & (CAKE_MAX_CPUS - 1), idle_smt);
			scx_bpf_put_idle_cpumask(idle_smt);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_SMT_CPUMASK_PROBE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = sib_fully_idle;
		}
	}

	/* ═══ FAIRNESS FIXES: COLD-CACHE + REMOTE ═══
	 * These probes simulate production conditions where data may not be L1-hot.
	 * Cold simulation: read 32 unrelated arena cache lines (2KB) between
	 * iterations to evict the target data from L1D (32KB, 8-way).
	 * This models the real cost when a different task ran between accesses. */
	/* ═══ 公平性修正：冷缓存 + 远端 ═══
	 * 这些探测模拟生产环境下数据可能不在 L1 的情形。
	 * 冷模拟：在两次迭代之间读取 32 条无关的 arena 缓存行（2KB），
	 * 把目标数据从 L1D（32KB，8 路）中逐出。
	 * 这还原了两次访问之间跑过别的任务时的真实成本。 */
	/* 讲解：只测热缓存会低估成本，特意制造缓存缺失才能反映最坏情况。 */

#ifndef CAKE_RELEASE
	/* Bench: bpf_task_storage_get — COLD task (first access per-task).
	 * Evict the storage cache between iterations to measure the slow path:
	 * hlist walk + spinlock cache insertion, not the cached fast path. */
	/* 基准：bpf_task_storage_get——冷任务（每任务首次访问）。
	 * 在迭代间逐出存储缓存，测量慢路径：hlist 遍历 + 自旋锁缓存插入，
	 * 而非已缓存的快路径。 */
	/* 讲解：反映首次查找 task_storage 的真实高成本。 */
	{
		ARENA_ASSOC();
		u32 ccpu = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			/* Pollute L1: stride through arena to evict storage cache lines */
			/* 污染 L1：跨步遍历 arena 以逐出存储缓存行。讲解：制造冷缓存环境。 */
			volatile u64 sink = 0;
			#pragma unroll
			for (int j = 0; j < 16; j++) {
				u32 idx = (ccpu + j + 1) & (CAKE_MAX_CPUS - 1);
				sink += per_cpu[idx].mbox.cached_cpu;
			}
			u64 _s = bpf_ktime_get_ns();
			struct cake_task_hot *hot_cold = bpf_task_storage_get(
				&task_hot_stor, p, 0, 0);
			volatile u16 cold_val = hot_cold ? hot_cold->deficit_u16 : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_STORAGE_GET_COLD];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = cold_val + sink;
		}
	}
#endif

#ifndef CAKE_RELEASE
	/* Bench: PELT util_avg — COLD p->se.avg (evicted from L1).
	 * In production, each stopping() call processes a DIFFERENT task.
	 * p->se.avg may be in a cold cache line if the task hasn't run recently. */
	/* 基准：PELT util_avg——冷的 p->se.avg（已从 L1 逐出）。
	 * 生产中每次 stopping() 处理的是不同任务，
	 * 若任务近期没跑过，p->se.avg 可能在冷缓存行里。 */
	/* 讲解：反映读取内核 PELT 字段在冷缓存下的真实代价。 */
	{
		ARENA_ASSOC();
		u32 ccpu2 = r->cpu & (CAKE_MAX_CPUS - 1);
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			/* Pollute L1: stride through arena to evict p->se.avg cache line */
			/* 污染 L1：跨步遍历 arena 以逐出 p->se.avg 缓存行。讲解：制造冷缓存环境。 */
			volatile u64 sink2 = 0;
			#pragma unroll
			for (int j = 0; j < 16; j++) {
				u32 idx = (ccpu2 + j + 1) & (CAKE_MAX_CPUS - 1);
				sink2 += per_cpu[idx].mbox.tick_slice;
			}
			u64 _s = bpf_ktime_get_ns();
			u64 util_cold = p->se.avg.util_avg;
			volatile u8 tier = (util_cold > 600) ? 2 : (util_cold > 200) ? 1 : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_PELT_COLD];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = tier + sink2;
		}
	}
#endif

#ifndef CAKE_RELEASE
	/* Bench: Legacy EWMA compute — COLD cpu_bss (evicted from L1).
	 * In production, cpu_bss[cpu] may be evicted if another BPF program
	 * or kernel path displaced the cache line between scheduling events. */
	/* 基准：遗留 EWMA 计算——冷的 cpu_bss（已从 L1 逐出）。
	 * 生产中若两次调度事件之间有别的 BPF 程序或内核路径挤占了缓存行，
	 * cpu_bss[cpu] 可能被逐出。 */
	/* 讲解：反映冷缓存下自算 EWMA 的真实成本，与冷读 PELT 对比。 */
	{
		u32 ewma_c = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
		ARENA_ASSOC();
		u32 fused_c = 0x00C80064;
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			/* Pollute L1: stride through arena */
			/* 污染 L1：跨步遍历 arena。讲解：制造冷缓存环境。 */
			volatile u64 sink3 = 0;
			#pragma unroll
			for (int j = 0; j < 16; j++) {
				u32 idx = (ewma_c + j + 1) & (CAKE_MAX_CPUS - 1);
				sink3 += per_cpu[idx].mbox.cached_deficit;
			}
			u64 _s = bpf_ktime_get_ns();
			u64 tick_c = cpu_bss[ewma_c].tick_slice;
			u64 rem_c = p->scx.slice;
			u16 oavg = (u16)(fused_c >> 16);
			u16 odef = (u16)(fused_c & 0xFFFF);
			u64 used_c = (tick_c > rem_c) ? (tick_c - rem_c) : 0;
			u16 rt_c = (u16)(used_c >> 10);
			volatile u16 navg = (oavg * 7 + rt_c) >> 3;
			volatile u16 ndef = (odef > rt_c) ? odef - rt_c : 0;
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_EWMA_COLD];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = navg + ndef + sink3;
		}
	}
#endif

	/* Bench: kick_cpu — REMOTE sibling (real IPI, not self-noop).
	 * scx_bpf_kick_cpu(self) is a bit-set noop. Production kicks remote
	 * CPUs which triggers deferred IPI via irq_work. */
	/* 基准：kick_cpu——远端兄弟核（真实 IPI，而非自踢空操作）。
	 * scx_bpf_kick_cpu(自己) 只是置位的空操作；生产中踢远端 CPU
	 * 会经 irq_work 触发延迟 IPI。 */
	/* 讲解：只有踢别的核才有真实中断成本，这才是抢占的实际开销。 */
	{
		s32 kick_cpu = bpf_get_smp_processor_id();
		s32 kick_sib = cpu_sibling_map[kick_cpu & (CAKE_MAX_CPUS - 1)];
		#pragma unroll
		for (int i = 0; i < BENCH_ITERATIONS; i++) {
			u64 _s = bpf_ktime_get_ns();
			scx_bpf_kick_cpu(kick_sib & (CAKE_MAX_CPUS - 1), 0);
			u64 _e = bpf_ktime_get_ns();
			u64 _d = _e - _s;
			struct kfunc_bench_entry *e = &r->entries[BENCH_KICK_REMOTE];
			if (_d < e->min_ns) e->min_ns = _d;
			if (_d > e->max_ns) e->max_ns = _d;
			e->total_ns += _d;
			e->samples[i] = _d;
			e->last_value = kick_sib;
		}
	}

	r->bench_timestamp = bpf_ktime_get_ns();
	*(volatile u32 *)&bench_active = 0;  /* Re-enable CAKE_STATS_ACTIVE */
					     /* 重新启用 CAKE_STATS_ACTIVE。讲解：基准结束，恢复正常遥测。 */
}





/* Per-task context: arena-backed direct pointer dereference.
 * Replaces BPF_MAP_TYPE_TASK_STORAGE (hash lookup, ~25-40ns cold)
 * Fast, direct lookups utilizing Arena pointers rather than BPF task storage.
 * Storage allocated in cake_init_task (sleepable), freed in cake_exit_task. */
/* 每任务上下文：基于 arena 的直接指针解引用。
 * 取代 BPF_MAP_TYPE_TASK_STORAGE（哈希查找，冷时约 25-40ns）。
 * 用 arena 指针做快速直接访问，而非 BPF task 存储。
 * 存储在 cake_init_task（可睡眠）分配，在 cake_exit_task 释放。 */
/* 讲解：arena 指针可直接解引用，省去哈希查找，适合放遥测这类大块数据。 */

/* Get task context — arena direct pointer dereference.
 * Arena storage allocated upfront in cake_init_task (sleepable).
 * No null check needed in hot paths: init_task guarantees allocation
 * before any scheduling callbacks fire for this task.
 * __arena qualifier: verifier knows this pointer is arena-backed. */
/* 获取任务上下文——arena 直接指针解引用。
 * arena 存储在 cake_init_task（可睡眠）中预先分配。
 * 热路径无需判空：init_task 保证在该任务任何调度回调触发前已完成分配。
 * __arena 限定符：让验证器知道这是 arena 支持的指针。 */
/* 因初始化时已保证分配，热路径可放心省去判空以节省指令。 */
static __always_inline struct cake_task_ctx __arena *
get_task_ctx(struct task_struct *p)
{
	return (struct cake_task_ctx __arena *)scx_task_data(p);
}

/* Phase 6: Fast per-task hot field lookup (~10ns vs 29ns arena).
 * Used by running + stopping + select_cpu + enqueue for CL0 fields.
 * Returns NULL if task_storage not yet allocated (init_task not called). */
/* 阶段 6：快速的每任务热字段查找（约 10ns，对比 arena 的 29ns）。
 * running + stopping + select_cpu + enqueue 都用它读取 CL0 字段。
 * 若 task_storage 尚未分配（init_task 未调用）则返回 NULL。 */
/* 真正的调度热字段走这个更快的查找，与放遥测的 arena 分离。 */
static __always_inline struct cake_task_hot *
get_task_hot(struct task_struct *p)
{
	return bpf_task_storage_get(&task_hot_stor, p, 0, 0);
}

/* ═══ DEDUP HELPERS (F1/F2/F3) ═══
 * Extracted from repeated inline blocks to reduce BPF insn footprint,
 * i-cache pressure, and source maintenance burden.
 * All __always_inline: zero call overhead, compiler CSE applies. */
/* ═══ 去重辅助函数（F1/F2/F3） ═══
 * 从重复的内联代码块中提取出来，以减少 BPF 指令体积、
 * 指令缓存压力和源代码维护负担。
 * 全部 __always_inline：零调用开销，且编译器可做公共子表达式消除。 */
/* 讲解：把重复逻辑抽成内联函数，既不增加运行开销又便于维护。 */


/* build_cached_cpumask REMOVED: after scx_bpf_select_cpu_and refactor,
 * the kernel handles affinity via p->cpus_ptr natively.
 * cached_cpumask had 0 read sites across the entire codebase (Rule 74). */
/* build_cached_cpumask 已移除：改用 scx_bpf_select_cpu_and 后，
 * 内核经 p->cpus_ptr 原生处理亲和性。
 * cached_cpumask 在整个代码库中已无任何读取点（规则74）。 */
/* 讲解：无人读取的“影子状态”应删除，重构后交给内核处理更简单。 */

/* smt_sibling removed — 3-gate select_cpu delegates SMT handling
 * to scx_bpf_select_cpu_dfl (Gate 3) which handles it natively. */
/* smt_sibling 已移除——3 门 select_cpu 把 SMT 处理交给
 * scx_bpf_select_cpu_dfl（Gate 3）原生处理。 */
/* 讲解：内核默认选核已能处理 SMT，无需自己维护兄弟核逻辑。 */

/* ═══════════════════════════════════════════════════════════════════════════
 * S2 SELECT_CPU: 3-GATE IDLE CPU SELECTION
 * Gate hierarchy: prev_cpu idle → perf-ordered scan → kernel default → DSQ tunnel.
 * ZERO bpf_task_storage_get: identity is in p->scx (task_struct, L1-hot).
 *
 * PRINCIPLE: "Where to run" is orthogonal to "how long to run".
 *   1. Gate 1: prev_cpu idle (91% hit, L1/L2 warm, zero arena)
 *   2. Gate 2: perf-ordered scan (P/E topology, GAMING active)
 *   3. Gate 3: kernel scx_bpf_select_cpu_dfl (any idle CPU)
 *   4. Tunnel: all busy → enqueue to per-LLC DSQ, wait for dispatch
 *
 * Results (100K event sim, 40 recurring gaming tasks):
 *   S0 → S2: migration 93.1% → 8.9%, cache warm 84.1% → 98.7%
 *   Per-frame savings: 53.4µs/frame, +1.1 avg FPS, +1.1 1% low FPS
 *   Decision cost: ~17ns vs ~100ns (6x faster)
 *
 * SYNC STRIP: In gaming, wakes are signal-only (vsync, GPU completion,
 * futex unlock). SYNC dispatch migrates wakee to waker's CPU, destroying
 * L1/L2 cache warmth (1.6-3.5µs refill) for zero data-locality benefit.
 * Confirmed: Elden Ring main thread bounced across 5+ cores/frame due to
 * SYNC wakes from vkd3d_queue, GXWorkers on random cores.
 * ═══════════════════════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════════════════════
 * S2 SELECT_CPU：3 门空闲 CPU 选择
 * 门层次：prev_cpu 空闲 → 按性能排序扫描 → 内核默认 → DSQ 隧道。
 * 零 bpf_task_storage_get：身份信息在 p->scx（task_struct，L1 热）。
 *
 * 原则：“在哪跑”与“跑多久”彼此正交。
 *   1. Gate 1：prev_cpu 空闲（命中 91%，L1/L2 缓存热，无 arena）
 *   2. Gate 2：按性能排序扫描（P/E 拓扑，游戏态激活时）
 *   3. Gate 3：内核 scx_bpf_select_cpu_dfl（任意空闲 CPU）
 *   4. 隧道：全忙 → 入每 LLC DSQ，等待派发
 *
 * 结果（10 万事件仿真，40 个复现的游戏任务）：
 *   S0 → S2：迁移 93.1% → 8.9%，缓存热度 84.1% → 98.7%
 *   每帧节省：53.4µs/帧，平均 +1.1 FPS，1% low +1.1 FPS
 *   决策成本：约 17ns 对比约 100ns（快 6 倍）
 *
 * SYNC 剥离：游戏里唤醒多为纯信号（vsync、GPU 完成、futex 解锁）。
 * SYNC 派发会把被唤醒者迁到唤醒者的 CPU，摧毁 L1/L2 缓存热度
 *（重填 1.6-3.5µs），却换不来任何数据局部性好处。
 * 已确认：《艾尔登法环》主线程因 vkd3d_queue、GXWorkers 在随机核上的
 * SYNC 唤醒，每帧在 5+ 个核之间弹跳。 */
/* 讲解：选核核心是“尽量留在原核保缓存”，并主动剥离会破坏缓存的 SYNC 迁移。 */


/* ═══ Kfunc out-param wrappers (Rule 73: zero r10 refs in caller) ═══
 *
 * scx_bpf_select_cpu_dfl requires &is_idle out-param (3 r10 refs).
 * scx_bpf_select_cpu_and requires struct arg on stack (2 r10 refs).
 * Wrapping in __noinline isolates stack usage to these frames.
 * cake_select_cpu gets 0 r10 refs.
 * Cost: 1 extra call per select_cpu — negligible vs kfunc overhead. */
/* ═══ kfunc 出参包装（规则73：调用方零 r10 引用） ═══
 *
 * scx_bpf_select_cpu_dfl 需要 &is_idle 出参（3 次 r10 引用）。
 * scx_bpf_select_cpu_and 需要在栈上传结构体参数（2 次 r10 引用）。
 * 用 __noinline 包装把栈使用隔离在这些帧里，
 * cake_select_cpu 便可获得 0 次 r10 引用。
 * 代价：每次 select_cpu 多一次调用——相对 kfunc 开销可忽略。 */
/* r10 是栈帧寄存器，减少对它的引用有利于验证器与寄存器分配。 */

/* Returns cpu if idle found, -1 otherwise. */
/* 找到空闲则返回该 cpu，否则返回 -1。封装内核默认选核并简化返回值。 */
static __noinline s32 select_cpu_dfl_idle(
	struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	return is_idle ? cpu : -1;
}

/* Returns cpu >= 0 if idle found, < 0 otherwise. */
/* 找到空闲返回 >=0 的 cpu，否则 <0。封装带亲和过滤的内核选核。 */
static __noinline s32 select_cpu_and_idle(
	struct task_struct *p, s32 prev_cpu, u64 wake_flags,
	u64 enq_flags)
{
	return scx_bpf_select_cpu_and(p, prev_cpu, wake_flags,
				      p->cpus_ptr, enq_flags);
}

/* 为进程选择cpu */
s32 BPF_STRUCT_OPS(cake_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	/* RELEASE: zero arena dereferences in this callback — all behind
	 * stats_on / #ifndef CAKE_RELEASE. Skip ARENA_ASSOC to free a
	 * callee-saved register + 2 insns (Rule 36). */
	/* 发布版：本回调无任何 arena 解引用——都在 stats_on / #ifndef CAKE_RELEASE 之后。
	 * 跳过 ARENA_ASSOC 以腾出一个被调用者保存寄存器 + 省 2 条指令（规则36）。 */
	/* 选核热路径在发布版彻底不碰 arena，因而省掉关联开销。 */
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

#ifndef CAKE_RELEASE
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 start_time = 0;
	if (stats_on)
		start_time = scx_bpf_now();
#else
	#define stats_on 0
	u64 start_time = 0;
#endif

	/* SYNC STRIP: In gaming, wakes are signal-only (vsync, futex, GPU done)
	 * — no data locality from SYNC. A/B tested: SYNC enabled = same or
	 * slightly worse FPS in Arc Raiders during GAMING. */
	/* SYNC 剥离：游戏中唤醒都是纯信号（vsync、futex、GPU 完成）——
	 * SYNC 带不来数据局部性。A/B 测试：在 Arc Raiders 游戏态开启 SYNC，
	 * FPS 持平或略差。 */
	/* 游戏态清除 SYNC 标志，避免把任务无谓迁到唤醒者的核而毁掉缓存。 */
	/* Per-CPU sched_state_local: use prev_cpu (always valid, Rust syncs
	 * all per-CPU copies identically). Avoids bpf_get_smp_processor_id()
	 * kfunc which forces r1 spill across call (Rule 73). */
	/* 每 CPU 的 sched_state_local：用 prev_cpu（总有效，Rust 会把所有
	 * 每 CPU 副本同步成一致）。避免 bpf_get_smp_processor_id() kfunc
	 * 导致跨调用溢出 r1（规则73）。 */
	/* 用已有的 prev_cpu 下标读本地状态，省一次取 CPU 号的 kfunc。 */
	if (cpu_bss[prev_cpu & (CAKE_MAX_CPUS - 1)].sched_state_local == CAKE_STATE_GAMING)
		wake_flags &= ~SCX_WAKE_SYNC;

	/* ── KERNEL IDLE SELECTION ──
	 * scx_bpf_select_cpu_and (6.17+) or scx_bpf_select_cpu_dfl (6.12+).
	 * CO-RE dead-code eliminates the unused path at load time — zero
	 * instruction overhead on the live kernel. Both provide:
	 *   1. prev_cpu idle test   2. SYNC wake-affine   3. SMT full-idle
	 *   4. LLC-scoped scan      5. NUMA-scoped scan   6. Global scan
	 *   7. Proper affinity for restricted tasks (Wine/Proton)
	 * Rule 62: Grounded in kernel source. Rule 4: Topology-correct.
	 * Rule 54: Works on all consumer gaming topologies + all kernels. */
	/* ── 内核空闲选择 ──
	 * scx_bpf_select_cpu_and（6.17+）或 scx_bpf_select_cpu_dfl（6.12+）。
	 * CO-RE 在加载时删除用不上的分支——在实际内核上零指令开销。两者都提供：
	 *   1. prev_cpu 空闲测试  2. SYNC 唤醒亲和  3. SMT 整核空闲
	 *   4. LLC 范围扫描       5. NUMA 范围扫描  6. 全局扫描
	 *   7. 对受限任务（Wine/Proton）的正确亲和处理
	 * 规则62：以内核源码为依据。规则4：拓扑正确。
	 * 规则54：适配所有消费级游戏拓扑与所有内核。 */
	/* 优先复用内核成熟的空闲选核逻辑，按内核版本自动选正确 kfunc。 */
	if (!__COMPAT_HAS_scx_bpf_select_cpu_and) {
		/* Kernel ≤ 6.16: scx_bpf_select_cpu_dfl via noinline wrapper.
		 * CO-RE prunes this entire block on 6.17+. */
		/* 内核 ≤6.16：经 noinline 包装调用 scx_bpf_select_cpu_dfl。
		 * 在 6.17+ 上 CO-RE 会整块裁掉。 */
		/* 老内核走这个回退分支。 */
		s32 cpu = select_cpu_dfl_idle(p, prev_cpu, wake_flags);
		if (cpu >= 0) {
			u64 slice = p->scx.slice ?: quantum_ns;
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					    slice, wake_flags);
			return cpu;
		}
		/* !idle: fall through to Gate 2 (hybrid P/E scan). */
		/* 非空闲：落到 Gate 2（混合 P/E 扫描）。内核未找到空闲则继续尝试。 */
		goto gate2;
	}

	{
		s32 cpu = select_cpu_and_idle(p, prev_cpu, wake_flags, 0);
		if (cpu >= 0) {
			/* 成功找到了， 返回 */
			u64 slice = p->scx.slice ?: quantum_ns;
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu,
					    slice, wake_flags);
			if (stats_on) {
				struct cake_stats *s = get_local_stats();
				s->total_gate1_latency_ns += scx_bpf_now() - start_time;
#ifndef CAKE_RELEASE
				struct cake_task_ctx __arena *tctx = get_task_ctx(p);
				if (tctx) {
					tctx->telemetry.gate_1_hits++;
					tctx->telemetry.direct_dispatch_count++;
					if (cpu != prev_cpu)
						tctx->telemetry.migration_count++;
				}
#endif
			}
			return cpu;
		}
	}

gate2:
	/* ── GATE 2: Performance-ordered idle scan ──
	 * Scan CPUs in performance order for idle cores:
	 *   GAME:     fast→slow (P-cores first for max boost)
	 *   non-GAME: slow→fast (E-cores first for power parking)
	 * Uses RODATA cpus_fast_to_slow / cpus_slow_to_fast (populated by
	 * Rust loader from amd_pstate_prefcore_ranking).
	 * EEVDF TOPOLOGY: Always active when P/E cores exist, not just GAMING.
	 * Ensures GAME tasks always land on P-cores, BG on E-cores.
	 * Cost: 0ns on SMP (has_hybrid_cores=false → JIT eliminates). */
	/* ── Gate 2：按性能排序的空闲扫描 ──
	 * 按性能顺序扫描空闲核：
	 *   GAME：    快→慢（先 P 核以获最大加速）
	 *   非 GAME： 慢→快（先 E 核以让高性能核歇着省电）
	 * 使用 RODATA cpus_fast_to_slow / cpus_slow_to_fast（Rust 加载器
	 * 从 amd_pstate_prefcore_ranking 填充）。
	 * EEVDF 拓扑：只要存在 P/E 核就一直生效，不限于游戏态。
	 * 保证 GAME 任务总落在 P 核、BG 落在 E 核。
	 * 对称多处理器上 0ns（has_hybrid_cores=false → JIT 删除）。 */
	/* 异构平台上按核性能有序找空闲核，让对的任务落在对的核上。 */
	if (has_hybrid_cores) {
		/* READ TASK CLASS from BSS pid_class_cache (tunneled from stopping).
		 * Zero bpf_task_storage_get → eliminates 1982ns tail jitter.
		 * BSS read = 14ns avg, 96ns jitter (vs 28ns/1982ns task_storage).
		 * p->pid is L1-hot (same CL as p->scx.slice). */
		/* 从 BSS pid_class_cache 读任务类别（由 stopping 隧道传来）。
		 * 零 bpf_task_storage_get → 消除 1982ns 的尾部抖动。
		 * BSS 读平均 14ns、抖动 96ns（对比 task_storage 的 28ns/1982ns）。
		 * p->pid 在 L1 中（与 p->scx.slice 同一缓存行）。 */
		/* 选核时用便宜的缓存读类别，避开慢且抖动大的存储查找。 */
		u8 g2_tc = pid_class_cache[p->pid & (PID_CLASS_CACHE_SIZE - 1)];
		bool is_game = (g2_tc == CAKE_CLASS_GAME);
		const u8 *scan_order = is_game
			? cpus_fast_to_slow
			: cpus_slow_to_fast;

		for (u32 i = 0; i < CAKE_MAX_CPUS && i < nr_cpus; i++) {
			u8 candidate = scan_order[i];
			if (candidate >= nr_cpus)
				break;  /* 0xFF sentinel or out of range */
				/* 遇到 0xFF 哨兵或越界即停。扫描到有效核末尾。 */

			/* SMT-aware: XOR detects class mismatch in 1 insn.
			 * Branchless: is_game ^ sib_game = true when mismatched. */
			/* 感知 SMT：用异或一条指令检测类别不匹配。
			 * 无分支：is_game ^ sib_game 为真即表示不匹配。 */
			/* 避免把游戏与非游戏任务放到同一物理核的两个超线程上互相干扰。 */
			u8 sib = cpu_sibling_map[candidate & (CAKE_MAX_CPUS - 1)];
			if (sib < nr_cpus && sib != candidate) {
				bool sib_game = (game_cpu_mask[sib >> 6] >> (sib & 63)) & 1;
				if (is_game ^ sib_game)
					continue;  /* class mismatch — skip */
					   /* 类别不匹配——跳过。不与异类兄弟核共核。 */
			}

			if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
				u64 slice = p->scx.slice ?: quantum_ns;
				scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | candidate,
						   slice, wake_flags);
				return candidate;
			}
		}
	}

	/* ── TUNNEL: All CPUs busy — return prev_cpu ──
	 * FunSearch: cached_now staging REMOVED (−12 insns).
	 * bss->cached_now was written but had ZERO READERS in the codebase.
	 * Enqueue paths call scx_bpf_now() directly — the staging was dead
	 * code from pre-optimization. Rule 5: no work < some work.
	 * Tiered weights guarantee GAME [0,5120] sorts before NORMAL [8192,13312].
	 * DSQ ordering handles all priority — no preemption or kicks needed. */
	/* ── 隧道：所有 CPU 都忙——返回 prev_cpu ──
	 * FunSearch：cached_now 暂存已移除（−12 条指令）。
	 * bss->cached_now 曾被写入但代码库中无任何读取者。
	 * 入队路径直接调用 scx_bpf_now()——该暂存是早期优化遗留的死代码。规则5：不做事优于瞎做事。
	 * 分层权重保证 GAME [0,5120] 排在 NORMAL [8192,13312] 之前。
	 * 优先级完全由 DSQ 排序负责——无需抢占或踢核。 */
	/* 讲解：全忙时返回原核并入队，靠 vtime 分层排序保证优先级，无需额外抢占。 */
#ifdef CAKE_RELEASE
	#undef stats_on
#endif
	return prev_cpu;
}
/* Cut 3: enqueue_depth_scale_slice DELETED — zero callers after removal.
 * Gaming DSQs have 0-1 tasks, making depth-scaled slicing dead weight. */
/* 精简 3：enqueue_depth_scale_slice 已删除——移除后无调用者。
 * 游戏 DSQ 只有 0-1 个任务，按队深缩放时间片成了无用负担。 */
/* 讲解：游戏场景队列极浅，队深相关的复杂逻辑纯属多余，直接删掉。 */

/* OPT-17: enqueue_dsq_dispatch — DSQ insert + mailbox kick.
 * Follows kernel enqueue_entity pattern: all state lives in the entity.
 *   - p is PARENT for: vtime (p->scx.dsq_vtime), slice (p->scx.slice)
 *   - packed is PARENT for: enq_cpu, enq_llc (derived just-in-time)
 * 3 args: p, enq_flags, packed_cpu_llc.
 * kfuncs: scx_bpf_dsq_insert_vtime, scx_bpf_kick_cpu.
 * Only packed (parent of enq_cpu+enq_llc) survives insert → 1 callee-save.
 * 3 args + 1 survivor = 0 spills. */
/* OPT-17：enqueue_dsq_dispatch——DSQ 插入 + 邮箱踢核。
 * 遵循内核 enqueue_entity 模式：所有状态都存在实体里。
 *   - p 是以下的“父”：vtime（p->scx.dsq_vtime）、时间片（p->scx.slice）
 *   - packed 是以下的“父”：enq_cpu、enq_llc（即时派生）
 * 3 个参数：p、enq_flags、packed_cpu_llc。
 * kfunc：scx_bpf_dsq_insert_vtime、scx_bpf_kick_cpu。
 * 插入后仅 packed（enq_cpu+enq_llc 之父）存活 → 1 个被调用者保存寄存器。
 * 3 参数 + 1 存活 = 0 溢出。 */
/* 精心控制参数与存活变量数量，使编译后不产生栈溢出，追求极致精简。 */
static __noinline void enqueue_dsq_dispatch(
	struct task_struct *p,
	u64 enq_flags,
	u64 packed_cpu_llc)
{
	/* Derive enq_llc from parent (packed) — used for DSQ ID */
	/* 从父值 packed 派生 enq_llc——用于 DSQ ID。讲解：低 16 位是 LLC 号。 */
	u32 enq_llc = (u32)(packed_cpu_llc & 0xFFFF);

	/* Derive vtime+slice from parent (p) — consumed by insert, die immediately */
	/* 从父值 p 派生 vtime+时间片——被插入消费后立即失效。讲解：按 vtime 有序插入 DSQ。 */
	scx_bpf_dsq_insert_vtime(p, LLC_DSQ_BASE + enq_llc,
				 p->scx.slice ?: quantum_ns,
				 p->scx.dsq_vtime, enq_flags);

	/* After insert: only packed_cpu_llc needed (parent of enq_cpu+enq_llc) */
	/* 插入后：只还需要 packed_cpu_llc（enq_cpu+enq_llc 之父）。讲解：其余变量已可释放。 */
	if (!dsq_kick_needed[enq_llc]) {
		dsq_kick_needed[enq_llc] = 1;
		/* Derive enq_cpu from parent (packed) — just-in-time for kick */
		/* 从父值 packed 派生 enq_cpu——踢核时即时取用。讲解：高位是入队 CPU 号。 */
		u32 enq_cpu = (u32)(packed_cpu_llc >> 32) & 0xFFFF;
		u64 kick_flags = (u64)cpu_bss[enq_cpu].idle_hint * SCX_KICK_IDLE;
		scx_bpf_kick_cpu(enq_cpu, kick_flags);
	}
}


/* OPT-18: enqueue_nostaged — cold path, no staged context.
 * kthread or first dispatch. 2 args: p, enq_flags.
 * Always uses scx_bpf_now() (cold path — ~10ns irrelevant).
 * Fetches CPU/LLC internally → isolated register frame. */
/* OPT-18：enqueue_nostaged——冷路径，无暂存上下文。
 * 用于内核线程或首次派发。2 个参数：p、enq_flags。
 * 总是用 scx_bpf_now()（冷路径——约 10ns 无关紧要）。
 * 内部自取 CPU/LLC → 独立的寄存器帧。 */
/* 没有 stopping 预算好的暂存值时走这条冷路径，一切现算即可。 */
static __noinline void enqueue_nostaged(struct task_struct *p, u64 enq_flags)
{
	u32 enq_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	u32 enq_llc = 0;
	if (nr_llcs > 1) {
		u32 task_cpu = scx_bpf_task_cpu(p);
		enq_llc = cpu_llc_id[task_cpu < nr_cpus ? task_cpu : enq_cpu];
	}
	/* Cold path: scx_bpf_now() always — cache miss irrelevant here. */
	/* 冷路径：一律用 scx_bpf_now()——此处缓存缺失无所谓。讲解：冷路径不追求极致省时。 */
	p->scx.dsq_vtime = scx_bpf_now();
	p->scx.slice = quantum_ns;
	enqueue_dsq_dispatch(p, enq_flags,
			    ((u64)enq_cpu << 32) | enq_llc);
}

/* OPT-19: enqueue_requeue_path — requeue (yield/slice exhaust).
 * 3 args: p, enq_flags, hot. Fetches CPU/LLC/now internally. */
/* OPT-19：enqueue_requeue_path——重新入队（让出/时间片耗尽）。
 * 3 个参数：p、enq_flags、hot。内部自取 CPU/LLC/now。 */
/* 任务让出或跑完时间片后重新排队走这条路径。 */
static __noinline void enqueue_requeue_path(
	struct task_struct *p, u64 enq_flags,
	struct cake_task_hot *hot, u32 enq_cpu)
{
	/* FunSearch: enq_cpu hoisted from caller (enqueue_body).
	 * Eliminates bpf_get_smp_processor_id() kfunc from this path.
	 * Rule 62: EEVDF pattern — kernel derives CPU from rq struct. */
	/* FunSearch：enq_cpu 从调用方（enqueue_body）上提传入。
	 * 从这条路径消除 bpf_get_smp_processor_id() kfunc。
	 * 规则62：EEVDF 模式——内核从 rq 结构体推导 CPU。 */
	/* 讲解：把取 CPU 号提到上层复用，避免本函数再调一次 kfunc。 */
	u64 now_cached = scx_bpf_now();  /* always fresh for non-wakeup */
					 /* 非唤醒场景总取最新时间。重入队需要当前 vtime 基准。 */
	u32 enq_llc = 0;
	if (nr_llcs > 1) {
		u32 task_cpu = scx_bpf_task_cpu(p);
		enq_llc = cpu_llc_id[task_cpu < nr_cpus ? task_cpu : enq_cpu];
	}
	/* FunSearch: hot null check removed — provably dead.
	 * Proof: enqueue_body gates requeue_path behind staged & VALID.
	 * If hot were NULL → staged=0 → VALID not set → nostaged path.
	 * hot is guaranteed non-NULL here. Rule 5: no work < some work. */
	/* FunSearch：hot 的空指针检查已移除——可证明是死代码。
	 * 证明：enqueue_body 只有在 staged & VALID 时才进入 requeue_path。
	 * 若 hot 为 NULL → staged=0 → VALID 未置位 → 会走 nostaged 路径。
	 * 因此此处 hot 保证非 NULL。规则5：不做工作 < 做无用工作。 */
	/* 讲解：靠上层不变式省掉判空，减少一条分支。 */
	u64 staged = hot->staged_vtime_bits;
	u64 requeue_slice = p->scx.slice ?: quantum_ns;
	u32 dsq_weight = (u32)(staged & 0xFFFFFFFF);
	p->scx.dsq_vtime = now_cached + dsq_weight;
	/* Cut 5: flat 50% requeue slice for all classes.
	 * GAME 75%/non-GAME 50% differentiation removed — vtime ordering
	 * already provides GAME priority. Saves yl_flag + variable multiply. */
	/* 精简5：所有类别统一按 50% 计算重入队时间片。
	 * 移除 GAME 75%/非GAME 50% 的区分——vtime 排序本身
	 * 已提供 GAME 优先级。省掉 yl_flag 与一次变量乘法。 */
	/* 优先级交给 vtime 排序，时间片折半即可。 */
	requeue_slice >>= 1;
	/* 若时间片不足 200µs，则补足到 200µs（下限保护）。位运算实现无分支下限钳制。 */
	requeue_slice += (200000 - requeue_slice) & -(requeue_slice < 200000);
	p->scx.slice = requeue_slice;
	enqueue_dsq_dispatch(p, enq_flags,
			    ((u64)enq_cpu << 32) | enq_llc);
}

/* OPT-20: enqueue_wakeup_path — main wakeup dispatch (~90%).
 * PARENT-DERIVATION + FUSION pattern (Rules 24/37/41):
 *   hot is PARENT for 6 derivatives: staged, dsq_weight, new_flow,
 *   dsq_vtime, is_game, task_class. All fused into vtime computation
 *   and entity pre-write BEFORE any kfunc. hot dies immediately.
 *
 * Liveness across bpf_get_smp_processor_id:
 *   p(r6), enq_flags(r7), is_game(r8) = 3 values < 4 callee-saves.
 * After kfunc: + enq_cpu(r9) = 4 values = 4 callee-saves.
 * → 0 spills. */
/* OPT-20：enqueue_wakeup_path——主唤醒派发路径（约 90%）。
 * 父值派生 + 融合模式（规则24/37/41）：
 *   hot 是 6 个派生值之父：staged、dsq_weight、new_flow、
 *   dsq_vtime、is_game、task_class。全部在任何 kfunc 之前
 *   融合进 vtime 计算与实体预写，hot 随即立刻失效。
 *
 * 跨 bpf_get_smp_processor_id 的活跃变量：
 *   p(r6)、enq_flags(r7)、is_game(r8) = 3 个值 < 4 个被调用者保存寄存器。
 * kfunc 之后：+ enq_cpu(r9) = 4 个值 = 4 个被调用者保存寄存器。
 * → 0 次溢出。 */
/* 绝大多数入队都走这里，用父值派生把所有计算压到 kfunc 之前，实现零栈溢出。 */
static __noinline void enqueue_wakeup_path(
	struct task_struct *p, u64 enq_flags,
	struct cake_task_hot *hot, u32 enq_cpu)
{
	/* ── Phase 1: FUSE all hot derivatives into entity pre-write ──
	 * hot is parent for: staged_vtime_bits → dsq_weight, new_flow
	 *                     dsq_vtime → vtime base
	 *                     task_class → is_game (single bool)
	 * After this block, hot is DEAD — all data consumed.
	 * FunSearch: hot null checks removed — provably dead.
	 * Proof: enqueue_body gates wakeup_path behind staged & VALID.
	 * If hot were NULL → staged=0 → VALID not set → nostaged path. */
	/* ── 阶段1：把 hot 的所有派生值融合进实体预写 ──
	 * hot 是以下值之父：staged_vtime_bits → dsq_weight、new_flow
	 *                     dsq_vtime → vtime 基准
	 *                     task_class → is_game（单个布尔）
	 * 本块结束后 hot 即失效——数据全部被消费。
	 * FunSearch：hot 判空已移除——可证明是死代码。
	 * 证明：enqueue_body 只在 staged & VALID 时进入 wakeup_path。
	 * 若 hot 为 NULL → staged=0 → VALID 未置位 → 走 nostaged 路径。 */
	/* 一次性从 hot 榨出全部派生量，随后 hot 立即可释放。 */
	u64 staged = hot->staged_vtime_bits;
	u32 dsq_weight = (u32)(staged & 0xFFFFFFFF);
	u8 new_flow = (staged >> STAGED_BIT_NEW_FLOW) & 1;
	u64 vtime = dsq_weight + hot->dsq_vtime;
	vtime -= new_flow_bonus_ns & -(u64)new_flow;
	u8 is_game = (hot->task_class == CAKE_CLASS_GAME);
	/* Write vtime to entity — kernel enqueue_entity pattern.
	 * vtime, staged, dsq_weight, new_flow all DIE here. */
	/* 把 vtime 写入实体——对应内核 enqueue_entity 模式。
	 * vtime、staged、dsq_weight、new_flow 在此全部失效。新流可得奖励使 vtime 前移。 */
	p->scx.dsq_vtime = vtime;
	/* GAME DOUBLE-SLICE: frame-time headroom during GAMING.
	 * Only GAME+GAMING gets an explicit 2× quantum for frame pacing. */
	/* GAME 双倍时间片：游戏中为帧时间留出余量。
	 * 只有 GAME 类且处于 GAMING 状态才显式获得 2× 量子用于帧节奏。 */
	/* Per-CPU sched_state_local: use enq_cpu (already have it from caller).
	 * Avoids bpf_get_smp_processor_id() kfunc which causes 3 spills (Rule 73). */
	/* 每 CPU 的 sched_state_local：使用 enq_cpu（已由调用方传入）。
	 * 避免 bpf_get_smp_processor_id() kfunc 导致 3 次溢出（规则73）。 */
	/* 游戏任务在游戏态下拿双倍时间片，减少帧内被抢占。 */
	if (is_game && cpu_bss[enq_cpu].sched_state_local == CAKE_STATE_GAMING)
		p->scx.slice = quantum_ns << 1;
	/* hot is now DEAD — all 6 derivatives consumed or stored.
	 * FunSearch: bpf_get_smp_processor_id() kfunc removed.
	 * enq_cpu hoisted to enqueue_body (caller) — eliminates
	 * the root cause of 2 stack spills. EEVDF pattern: kernel
	 * gets CPU from rq struct; we get it from caller's frame.
	 * Without any kfunc here, p and enq_flags stay in arg regs
	 * or callee-saves — no spill/reload cycle. */
	/* hot 现已失效——6 个派生值均已消费或存储。
	 * FunSearch：已移除 bpf_get_smp_processor_id() kfunc。
	 * enq_cpu 上提到 enqueue_body（调用方）——消除
	 * 2 次栈溢出的根因。EEVDF 模式：内核从 rq 结构体
	 * 取 CPU；我们则从调用方的栈帧取。
	 * 此处不调任何 kfunc，p 与 enq_flags 便可留在实参寄存器
	 * 或被调用者保存寄存器中——无溢出/重载循环。 */
	/* 讲解：整个热路径不调 kfunc，寄存器分配零溢出。 */

	/* ── Phase 3: LLC (dead-coded on single-CCD via RODATA nr_llcs=1) ── */
	/* ── 阶段3：LLC（单 CCD 时借 RODATA nr_llcs=1 变为死代码） ── */
	/* 单 LLC 机器上该分支被 JIT 直接消除。 */
	u32 enq_llc = 0;
	if (nr_llcs > 1) {
		u32 task_cpu = scx_bpf_task_cpu(p);
		enq_llc = cpu_llc_id[task_cpu < nr_cpus ? task_cpu : enq_cpu];
	}

	/* ── Phase 5: Dispatch (3 args, 0 spills) ── */
	/* ── 阶段5：派发（3 个参数，0 次溢出） ── */
	/* 把 CPU 与 LLC 打包成一个 u64 传入派发函数。 */
	u64 packed = ((u64)enq_cpu << 32) | enq_llc;
	enqueue_dsq_dispatch(p, enq_flags, packed);


}

/* OPT-14: enqueue_body — thin router. get_task_hot + branch to path.
 * FunSearch: bpf_get_smp_processor_id hoisted here from wakeup/requeue paths.
 * Live after kfuncs: p(r6), enq_flags(r7), enq_cpu(r8), hot(r9) = 4 callee-saves.
 * Eliminates 2 spills from enqueue_wakeup_path. EEVDF-inspired:
 * kernel derives CPU from rq struct, passed to enqueue_entity. */
/* OPT-14：enqueue_body——轻量路由器。get_task_hot + 分支到具体路径。
 * FunSearch：把 bpf_get_smp_processor_id 从 wakeup/requeue 路径上提到这里。
 * kfunc 之后活跃：p(r6)、enq_flags(r7)、enq_cpu(r8)、hot(r9) = 4 个被调用者保存寄存器。
 * 从 enqueue_wakeup_path 消除 2 次溢出。受 EEVDF 启发：
 * 内核从 rq 结构体推导 CPU 并传给 enqueue_entity。 */
/* 入口只负责取 hot 并按 staged/flags 三分支路由到具体入队路径。 */
static __noinline void enqueue_body(struct task_struct *p, u64 enq_flags)
{
	u32 enq_cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	struct cake_task_hot *hot = get_task_hot(p);
	u64 staged = hot ? hot->staged_vtime_bits : 0;

	/* 无有效暂存值：走冷路径 nostaged。首次派发或内核线程通常在此。 */
	if (unlikely(!(staged & (1ULL << STAGED_BIT_VALID)))) {
		enqueue_nostaged(p, enq_flags);
		return;
	}
	/* 非唤醒且非抢占：让出/时间片耗尽的重入队。区别对待可复用暂存的 vtime。 */
	if (!(enq_flags & (SCX_ENQ_WAKEUP | SCX_ENQ_PREEMPT))) {
		enqueue_requeue_path(p, enq_flags, hot, enq_cpu);
		return;
	}
	/* 其余为唤醒/抢占：走主热路径。占约 90% 的最常见分支。 */
	enqueue_wakeup_path(p, enq_flags, hot, enq_cpu);
}

/* Enqueue — trivial struct_ops stub → __noinline enqueue_body.
 * Stub isolates BPF struct_ops arg extraction from core logic.
 * enqueue_body gets its own register frame (Rule 23: 0 spills). */
/* Enqueue——极薄的 struct_ops 桩函数 → __noinline enqueue_body。
 * 桩函数把 BPF struct_ops 的参数提取与核心逻辑隔离开。
 * enqueue_body 获得独立寄存器帧（规则23：0 次溢出）。 */
/*
入队时执行这个回调
入口桩只负责取参并转调实际逻辑，保证寄存器分配干净。 */
void BPF_STRUCT_OPS(cake_enqueue, struct task_struct *p, u64 enq_flags)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif
	enqueue_body(p, enq_flags);
}

/* Dispatch: single DSQ per LLC + cross-LLC steal.
 * Direct-dispatched tasks (SCX_DSQ_LOCAL_ON) bypass this callback entirely —
 * kernel handles them natively. Only tasks that went through
 * cake_enqueue → per-LLC DSQ arrive here.
 * CPU在pick时，缺任务了，让scx的dispatch来选，填充dsq。.
 * FIX: dsq_gen blindfold REMOVED. The generation counter caused CPUs to
 * permanently skip checking the shared DSQ after pulling one task, because
 * all CPUs synced to the same global gen after consuming a single task.
 * Result: 18.8M hint_skips, OS threads (ksoftirqd, rcu) starved for 6.5s.
 * Replaced with O(1) scx_bpf_dsq_nr_queued() — true queue depth, no drift. */
/* Dispatch：每个 LLC 一个 DSQ + 跨 LLC 窃取。
 * 直接派发的任务（SCX_DSQ_LOCAL_ON）完全绕过此回调——
 * 由内核原生处理。只有经过 cake_enqueue → 每 LLC DSQ 的
 * 任务才会到达这里。
 *
 * 修复：移除了 dsq_gen“蒙眼”机制。该代际计数器会导致 CPU
 * 在拉取一个任务后永久跳过检查共享 DSQ，因为所有 CPU 在消费
 * 单个任务后都同步到同一个全局代际。
 * 后果：1880 万次 hint_skips，OS 线程（ksoftirqd、rcu）饿死 6.5 秒。
 * 改用 O(1) 的 scx_bpf_dsq_nr_queued()——真实队列深度，无漂移。 */
/* 本地 LLC 队列优先消费，空了再跨 LLC 窃取，避免代际计数带来的饥饿。 */
void BPF_STRUCT_OPS(cake_dispatch, s32 raw_cpu, struct task_struct *prev)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif
	u32 cpu_idx = raw_cpu & (CAKE_MAX_CPUS - 1);
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 dispatch_start = stats_on ? scx_bpf_now() : 0;

	u32 my_llc = cpu_bss[cpu_idx].llc_id;  /* per-CPU cache (Rule 41) */
					       /* 每 CPU 缓存的 LLC 号（规则41）。*/
	u64 my_dsq_id = LLC_DSQ_BASE + my_llc;

	/* 1. Fast Path: Check if our local LLC DSQ actually has tasks */
	/* 1. 快路径：检查本地 LLC 的 DSQ 是否真的有任务。本地优先，命中率最高。 */
	{
		s32 depth = scx_bpf_dsq_nr_queued(my_dsq_id);
		/* P2B: dsq_depth_cached pruned — Rule 5/74.
		 * Zero BPF + zero Rust consumers (sleep_lag removed). */
		/* P2B：dsq_depth_cached 已裁剪——规则5/74。
		 * BPF 与 Rust 侧均无消费者（sleep_lag 已移除）。讲解：无人用的缓存字段直接删掉。 */

		if (depth > 0) {
		if (scx_bpf_dsq_move_to_local(my_dsq_id, 0)) {
			/* MAILBOX CLEAR: DSQ drained. Check-before-write (Rule 11).
			 * Stays Shared if already 0 (MESI no-op on fast path). */
			/* 邮箱清零：DSQ 已抽干。先读后写（规则11）。
			 * 若已是 0 则保持 Shared 状态（快路径上 MESI 无操作）。讲解：避免无谓写导致缓存失效。 */
			if (dsq_kick_needed[my_llc]) dsq_kick_needed[my_llc] = 0;
			if (stats_on) {
				struct cake_stats *s = get_local_stats_for(cpu_idx);
				s->nr_local_dispatches++;
				s->nr_dsq_consumed++;
				u64 d_oh = scx_bpf_now() - dispatch_start;
				s->total_dispatch_ns += d_oh;
				s->max_dispatch_ns = s->max_dispatch_ns + ((d_oh - s->max_dispatch_ns) & -(d_oh > s->max_dispatch_ns));
			}
			return;
		}
		}
	}

	/* 2. Steal Path: Look at other LLCs (Active on multi-CCD setups) */
	/* 2. 窃取路径：查看其他 LLC（多 CCD 配置下生效）。本地空闲时跨 LLC 借任务。 */
	if (nr_llcs > 1) {
		for (u32 i = 1; i < CAKE_MAX_LLCS; i++) {
			if (i >= nr_llcs) break;
			u32 victim = my_llc + i;
			if (victim >= nr_llcs) victim -= nr_llcs;

			u64 victim_dsq = LLC_DSQ_BASE + victim;
			/* EEVDF TOPOLOGY: only cross-CCD steal when victim has 2+ tasks.
			 * Prevents cache-cold migration of single tasks that are better
			 * served waiting for their CCD's core to free up. Mirrors EEVDF's
			 * imbalance_pct threshold for cross-domain migration. */
			/* EEVDF 拓扑：仅当受害 LLC 有 2 个以上任务时才跨 CCD 窃取。
			 * 避免把单个任务做缓存冷迁移——它们更适合等待自己 CCD 的核空出来。
			 * 对应 EEVDF 跨域迁移的 imbalance_pct 阈值。 */
			/* 只偷“富队列”，防止把孤立任务搬到冷缓存反而更慢。 */
			if (scx_bpf_dsq_nr_queued(victim_dsq) > 1 && scx_bpf_dsq_move_to_local(victim_dsq, 0)) {
				/* MAILBOX CLEAR: stolen DSQ drained. */
				/* 邮箱清零：被窃取的 DSQ 已抽干。清除踢核标志避免重复唤醒。 */
				if (dsq_kick_needed[victim]) dsq_kick_needed[victim] = 0;
				if (stats_on) {
					struct cake_stats *s = get_local_stats_for(cpu_idx);
					s->nr_stolen_dispatches++;
					s->nr_dsq_consumed++;
				}
				return;
			}
		}
	}

	if (stats_on) get_local_stats_for(cpu_idx)->nr_dispatch_misses++;

	/* G3 FIX: keep_running — if no tasks in any DSQ and prev task is
	 * still queued (wants to run), replenish its slice instead of forcing
	 * a pointless context switch. Saves ~2-4µs per cycle under light load.
	 * Cosmos/bpfland both implement this. Especially important for gaming
	 * where single-task-per-core is the common steady state. */
	/* G3 修复：keep_running——若所有 DSQ 都无任务，而 prev 任务
	 * 仍在排队（想继续跑），则给它补充时间片，而不是强制做一次
	 * 无意义的上下文切换。轻载下每周期省约 2-4µs。
	 * Cosmos/bpfland 都实现了此机制。对游戏尤其重要，
	 * 因为“单核单任务”是常见稳态。 */
	/* 没别的可跑就让当前任务续跑，避免空切换开销。 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED))
		prev->scx.slice = quantum_ns;

	/* Check-before-write: if CPU is already marked idle from a previous
	 * dispatch miss, skip the store (Rule 11: MESI optimization). */
	/* 先读后写：若该 CPU 因上次派发落空已被标记为空闲，则跳过写入
	 *（规则11：MESI 优化）。避免重复写触发缓存行失效。 */
	if (!cpu_bss[cpu_idx].idle_hint) cpu_bss[cpu_idx].idle_hint = 1;
}

/* DVFS RODATA: unused by BPF (tick removed) but written by Rust loader.
 * Kept to prevent loader panic on missing RODATA symbol. JIT dead-code eliminates. */
/* DVFS RODATA：BPF 未使用（tick 已移除），但 Rust 加载器会写入。
 * 保留它以防加载器因缺少 RODATA 符号而 panic。JIT 会做死代码消除。 */
/* 仅为兼容加载器保留的占位常量，实际运行时被优化掉。 */
const u32 tier_perf_target[8] = {
	1024, 1024, 1024, 1024, 1024, 1024, 1024, 1024,
};

/* OPT-13: __noinline running_task_change — isolates task-change kfuncs
 * from cake_running's register frame. Contains get_task_hot, game_cpu_mask
 * atomics, scx_bpf_cpuperf_set. 4 args: p, bss, cpu, slice. */
/* OPT-13：__noinline running_task_change——把任务切换相关的 kfunc
 * 从 cake_running 的寄存器帧中隔离出来。含 get_task_hot、game_cpu_mask
 * 原子操作、scx_bpf_cpuperf_set。4 个参数：p、bss、cpu、slice。 */
/* 仅在真正切换任务时才调用，避免污染 cake_running 的热路径寄存器。 */
static __noinline void running_task_change(
	struct task_struct *p,
	struct cake_cpu_bss *bss,
	u32 cpu)
{
	/* FunSearch: slice load moved here from cake_running.
	 * On 75% same-task re-runs, cake_running skips this function entirely,
	 * avoiding a wasted p->scx.slice load. Rule 5: no work < some work. */
	/* FunSearch：slice 的读取从 cake_running 移到这里。
	 * 在 75% 的“同任务重跑”情形下，cake_running 完全跳过本函数，
	 * 从而省掉一次无用的 p->scx.slice 读取。规则5：不做工作 < 做无用工作。 */
	/* 只有换任务时才需要 slice，故把读取下沉到此。 */
	u64 slice = p->scx.slice;
	bss->last_pid = p->pid;
	bss->tick_slice = slice ?: quantum_ns;
	struct cake_task_hot *hot = get_task_hot(p);

	/* FunSearch V10: Early exit on !hot — flatten control flow.
	 * Without hot: tc defaults to NORMAL, vtime_now untouched,
	 * game_cpu_mask would clear our bit (NORMAL != GAME),
	 * cpuperf would set 768. These are safe to skip:
	 * - game_cpu_mask: next task switch will correct it
	 * - game_cpu_mask + cpuperf eliminated → mask-only block
	 * Trade-off: 1-cycle stale mask for NULL hot (rare edge case). */
	/* FunSearch V10：!hot 时提前返回——摊平控制流。
	 * 若无 hot：tc 默认 NORMAL，vtime_now 不动，
	 * game_cpu_mask 本会清掉我们的位（NORMAL != GAME），
	 * cpuperf 本会设为 768。这些都可安全跳过：
	 * - game_cpu_mask：下次任务切换会自动纠正
	 * - game_cpu_mask + cpuperf 消除 → 只剩掩码块
	 * 权衡：NULL hot（罕见边界）下掩码有 1 周期陈旧。 */
	/* hot 缺失是极罕见边界，直接早退换取更简单的控制流。 */
	if (!hot)
		return;

	u8 tc = hot->task_class;

	/* vtime_local monotonic max — EEVDF global clock advancement.
	 * Per-CPU: eliminates cross-core cache line bouncing (Rule 8).
	 * Kernel analog: update_min_vruntime() in update_curr().
	 * Rule 62: verified against /home/ritz/Documents/Repo/linux/kernel/sched/fair.c */
	/* vtime_local 单调取最大——对应 EEVDF 全局时钟推进。
	 * 每 CPU 存储：消除跨核缓存行弹跳（规则8）。
	 * 内核对应物：update_curr() 中的 update_min_vruntime()。
	 * 规则62：已对照 linux/kernel/sched/fair.c 校验。 */
	/* 讲解：本地 vtime 只增不减，逼近全局虚拟时钟又不引发跨核争用。 */
	u64 tv = hot->dsq_vtime;
	if (tv > bss->vtime_local)
		bss->vtime_local = tv;

	/* Per-CPU sched_state_local: eliminates remote global BSS fetch (Rule 78). */
	/* 每 CPU 的 sched_state_local：消除对远端全局 BSS 的读取（规则78）。状态本地化避免跨核读。 */
	if (bss->sched_state_local == CAKE_STATE_GAMING) {
		/* game_cpu_mask — only needed during GAMING (Gate 2 scan).
		 * Rule 5: no work < some work. Non-GAMING: skip entirely. */
		/* game_cpu_mask——仅在 GAMING 期间需要（第2门扫描）。
		 * 规则5：不做工作 < 做无用工作。非 GAMING：整体跳过。只有游戏态才维护游戏核掩码。 */
		u8 game_flag = (tc == CAKE_CLASS_GAME);
		u32 word = cpu >> 6;
		u64 bit = 1ULL << (cpu & 63);
		u64 cur = READ_ONCE(game_cpu_mask[word]);
		u64 want = (cur & ~bit) | (bit & -(u64)game_flag);
		/* 仅当目标值变化时才写回。先读后写，减少原子写与缓存失效。 */
		if (want != cur)
			WRITE_ONCE(game_cpu_mask[word], want);

		/* cpuperf scaling REMOVED: the 768/1024 split throttled
		 * non-GAME tasks to 75% frequency during GAMING. This hurt
		 * game loading threads (not yet reclassified to GAME),
		 * audio, compositor, and wineserver. All CPUs should run at
		 * full speed during GAMING. Saves ~6 insns. */
		/* cpuperf 频率缩放已移除：原先 768/1024 的划分会在 GAMING 期间
		 * 把非 GAME 任务限到 75% 频率。这会拖累游戏加载线程（尚未
		 * 被重分类为 GAME）、音频、合成器与 wineserver。GAMING 期间
		 * 所有 CPU 都应满速运行。省约 6 条指令。 */
		/* 游戏时全核满频，避免误伤尚未识别的关键辅助线程。 */
	}
}

/* OPT-12: __noinline running_telemetry — cold-path extraction for cake_running.
 * Rule 23: Isolates register pressure so p doesn't survive the task-change block.
 * Rule 13: Telemetry is cold path (~1/64 of calls write heavy CL1-CL3).
 * 4 args: p, cpu, now_full, overhead_start (== mbox_start).
 * 'hot' is NOT passed — removing it frees r6 for p in the caller,
 * eliminating the last spill. Fetched internally (cold path). */
/* OPT-12：__noinline running_telemetry——从 cake_running 抽出的冷路径。
 * 规则23：隔离寄存器压力，使 p 不必跨越任务切换块存活。
 * 规则13：遥测是冷路径（约 1/64 的调用会重写 CL1-CL3）。
 * 4 个参数：p、cpu、now_full、overhead_start（== mbox_start）。
 * 不传入 'hot'——去掉它可为调用方腾出 r6 给 p，
 * 消除最后一次溢出。内部自取（冷路径）。 */
/* 把重量级遥测写入从热路径剥离，仅按采样比例执行。 */
#ifndef CAKE_RELEASE
static __noinline void running_telemetry(
	struct task_struct *p,
	u32 cpu,
	u64 now_full,
	u64 overhead_start)
{
	/* Phase 8: mailbox staging stopwatch end (before arena work) */
	/* 阶段8：邮箱暂存计时结束（在 arena 操作之前）。讲解：先量出暂存耗时。 */
	u64 mbox_end = scx_bpf_now();

	/* Phase 6: Deferred arena fetch — only in telemetry path */
	/* 阶段6：延迟的 arena 取用——仅在遥测路径中进行。讲解：arena 较慢，能省则省。 */
	struct cake_task_ctx __arena *tctx = get_task_ctx(p);
	if (!tctx)
		return;

	u64 start = now_full;

	/* F4: Save OLD run_start BEFORE overwriting for dispatch_gap calc. */
	/* F4：覆写前先保存旧的 run_start，用于计算派发间隔。讲解：新旧时间戳求差得到间隔。 */
	u64 prev_run_start = tctx->telemetry.run_start_ns;
	tctx->telemetry.run_start_ns = start;

	/* Fetch hot internally (cold path, ~10ns). */
	/* 内部取 hot（冷路径，约 10ns）。讲解：用重分类计数器做采样门控。 */
	struct cake_task_hot *hot_tel = get_task_hot(p);
	u32 rc = hot_tel ? hot_tel->reclass_counter : 0;
	if ((rc & 63) != 0)
		return;

	/* 1. DISPATCH GAP */
	/* 1. 派发间隔：从上次开始运行到本次的时间差。讲解：反映任务被调度的延迟。 */
	if (prev_run_start > 0 && start > prev_run_start) {
		u64 gap = start - prev_run_start;
		tctx->telemetry.dispatch_gap_ns = gap;
		u64 old_max_g = tctx->telemetry.max_dispatch_gap_ns;
		/* 无分支更新最大值。讲解：仅当 gap 更大时才替换。 */
		tctx->telemetry.max_dispatch_gap_ns = old_max_g + ((gap - old_max_g) & -(gap > old_max_g));
	}

	tctx->telemetry.llc_id = (u16)cpu_bss[cpu & (CAKE_MAX_CPUS - 1)].llc_id;

	/* 2. WAIT HISTOGRAM */
	/* 2. 等待时间直方图：入队到开始运行的等待时长分桶。讲解：观察排队延迟分布。 */
	if (tctx->telemetry.enqueue_start_ns > 0 && start > tctx->telemetry.enqueue_start_ns) {
		u64 wait = start - tctx->telemetry.enqueue_start_ns;
		tctx->telemetry.wait_duration_ns = wait;
		tctx->telemetry.enqueue_start_ns = 0;

		u64 wait_us = wait >> 10;
		/* 按微秒将等待时间落入四个桶。讲解：<10µs/<100µs/<1ms/≥1ms 分级统计。 */
		if (wait_us < 10)
			tctx->telemetry.wait_hist_lt10us++;
		else if (wait_us < 100)
			tctx->telemetry.wait_hist_lt100us++;
		else if (wait_us < 1000)
			tctx->telemetry.wait_hist_lt1ms++;
		else
			tctx->telemetry.wait_hist_ge1ms++;
	}

	struct cake_stats *s_run = get_local_stats_for(cpu);
	u64 oh_run = scx_bpf_now() - overhead_start;
	tctx->telemetry.running_duration_ns = (u32)oh_run;
	s_run->total_running_ns += oh_run;
	/* 无分支更新运行耗时最大值。讲解：仅当更大时替换。 */
	s_run->max_running_ns = s_run->max_running_ns + ((oh_run - s_run->max_running_ns) & -(oh_run > s_run->max_running_ns));

	/* Phase 8: mailbox staging duration (overhead_start == mbox_start) */
	/* 阶段8：邮箱暂存耗时（overhead_start == mbox_start）。记录暂存阶段花的时间。 */
	tctx->telemetry.mbox_staging_ns = (u32)(mbox_end - overhead_start);
}
#endif

/* cake_running — stamp per-CPU mailbox with run start + slice.
 * cake_stopping reads from the same cache line. Per-task telemetry
 * tracked via arena for zero cross-CPU cache invalidation. */
/* cake_running——在每 CPU 邮箱中打上运行起始时间与时间片。
 * cake_stopping 会读取同一条缓存行。每任务遥测通过 arena
 * 跟踪，实现零跨 CPU 缓存失效。 */
/* 任务开始运行时的回调，记录起点供 stopping 计算实际运行时长。 */
void BPF_STRUCT_OPS(cake_running, struct task_struct *p)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
	bool stats_on = CAKE_STATS_ACTIVE;
	u64 running_overhead_start = 0;
	if (stats_on)
		running_overhead_start = scx_bpf_now();
#endif

	/* Batch kfuncs first: only p=r6 survives both calls (1 callee-save).
	 * p->scx.slice read DEFERRED until after both kfuncs to avoid
	 * forcing p through 2 separate spill/reload cycles. */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);

	/* CLOCK DOMAIN FIX: tick_last_run_at MUST come from scx_bpf_now(),
	 * NOT p->se.exec_start. exec_start is rq_clock_task() which subtracts
	 * IRQ + steal time. Consumers (anti-starvation clamp in cake_enqueue,
	 * Gate 2/3 idle checks in cake_select_cpu) compare against scx_bpf_now().
	 * After ~22 min of gaming, accumulated IRQ time drift exceeds the u32
	 * wrap boundary (4.295s), corrupting elapsed-time checks → unconditional
	 * anti-starvation firing (priority inversion) + constant preemption. */
	/* 时钟域修复：tick_last_run_at 必须来自 scx_bpf_now()，
	 * 而非 p->se.exec_start。exec_start 是 rq_clock_task()，会扣除
	 * IRQ + steal 时间。而其消费方（cake_enqueue 的抗饥饿钳制、
	 * cake_select_cpu 的第2/3门空闲检查）都是与 scx_bpf_now() 比较。
	 * 游戏约 22 分钟后，累积的 IRQ 时间漂移会越过 u32 回绕边界
	 *（4.295 秒），破坏“已过时间”检查 → 抗饥饿无条件触发
	 *（优先级反转）+ 持续抢占。 */
	/* 讲解：统一用 scx_bpf_now() 时钟域，避免与 exec_start 混用导致回绕。 */
	u64 now_full = scx_bpf_now();
	u32 now = (u32)now_full;

	/* ── WRITE: BSS per-CPU (always needed) ── */
	/* ── 写入：每 CPU 的 BSS（总是需要） ── */
	struct cake_cpu_bss *bss = &cpu_bss[cpu];
	bss->run_start   = now;
	/* Check-before-write: ~75% of calls (same-task re-run), idle_hint
	 * is already 0. Skip the store to avoid unnecessary L1 dirty-mark
	 * and store buffer pressure (Rule 11: MESI optimization). */
	/* 先读后写：约 75% 的调用（同任务重跑）中 idle_hint 已是 0。
	 * 跳过写入以避免无谓的 L1 脏标记与写缓冲压力（规则11：MESI 优化）。 */
	if (bss->idle_hint) bss->idle_hint = 0;

	/* FAST PATH: Same task re-running on same CPU (~75% in gaming).
	 * FunSearch: slice load deferred into running_task_change.
	 * On 75% same-task re-runs, avoids wasted p->scx.slice load.
	 * Rule 5: no work < some work. */
	/* 快路径：同任务在同 CPU 上重跑（游戏中约占 75%）。
	 * FunSearch：slice 的读取被下沉到 running_task_change。
	 * 在 75% 的同任务重跑中避免无用的 p->scx.slice 读取。
	 * 规则5：不做工作 < 做无用工作。讲解：只有真换任务才走重活。 */
	if (bss->last_pid != p->pid)
		running_task_change(p, bss, cpu);

	/* ARENA TELEMETRY: Record run start time for task-level tracking.
     * Extracted to __noinline: isolates register pressure so p doesn't
     * need to survive the task-change block's internal kfunc calls.
     * Phase 6: Arena access ONLY in stats_on (dead in release). */
	/* ARENA 遥测：记录运行起始时间用于任务级跟踪。
	 * 抽取为 __noinline：隔离寄存器压力，使 p 不必跨越
	 * 任务切换块内部的 kfunc 调用存活。
	 * 阶段6：arena 访问仅在 stats_on 时进行（release 下为死代码）。 */
	/* 讲解：遥测仅在开启统计时执行，release 构建完全消除。 */
#ifndef CAKE_RELEASE
	if (stats_on)
		running_telemetry(p, cpu, now_full, running_overhead_start);
#endif
}

/* ═══════════════════════════════════════════════════════════════════════════
 * YIELD-GATED CLASSIFICATION + DRR++: Dynamic reclassification on every stop.
 * CPU analog of network CAKE's flow classification:
 * - Cooperative flows (game, audio, input) → voluntary yields → yielder boost
 * - Bulk flows (compilation, background) → run until preempted → tight ceiling
 *
 * This is the engine that makes yield-gated weighted vtime differentiate
 * traffic. Without it, all tasks compete at the same priority.
 * ═══════════════════════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════════════════════
 * 让出门控分类 + DRR++：每次停止运行时做动态重分类。
 * 对应网络 CAKE 流分类的 CPU 版：
 * - 协作型流（游戏、音频、输入）→ 主动让出 → 让出者加成
 * - 批量型流（编译、后台）→ 跑到被抢占 → 收紧上限
 *
 * 这是让“让出门控加权 vtime”得以区分不同流量的引擎。
 * 没有它，所有任务都会以相同优先级竞争。
 * ═══════════════════════════════════════════════════════════════════════════ */
/* 讲解：核心思想——主动让 CPU 的任务被判为交互型并获奖励，霸占 CPU 的被压制。 */
/* stopping_reclassify — confidence-gated cold path (1/64 stops).
 * __noinline: verifier tracks typed args across function boundary.
 * Must remain separate to prevent register spills in drr_ewma.
 *
 * OPTIMIZATION: !GAMING early exit (Rule 5).
 * When sched_state != GAMING: game_tgid=0, game_ppid=0 (Rust contract),
 * all cls_* clauses false, classification always yields NORMAL.
 * Skips ~25 insns → pays only ~5 (load + cmp + jnz + vtime_mult).
 *
 * GAMING path: null-check elimination (Rule 16).
 * Rust guarantees game_tgid != 0 and game_ppid != 0 when sched_state == GAMING.
 * Removes 2 redundant test instructions from cls_game computation.
 * Kthread clause simplified: is_kthread (GAMING already confirmed). */
/* stopping_reclassify——置信度门控的冷路径（每 64 次停止执行 1 次）。
 * __noinline：校验器可跨函数边界跟踪带类型的参数。
 * 必须独立成函数，以防止 drr_ewma 中出现寄存器溢出。
 *
 * 优化：非 GAMING 提前退出（规则5）。
 * 当 sched_state != GAMING 时：game_tgid=0、game_ppid=0（Rust 约定），
 * 所有 cls_* 子句为假，分类结果恒为 NORMAL。
 * 跳过约 25 条指令 → 只付出约 5 条（load + cmp + jnz + vtime_mult）。
 *
 * GAMING 路径：消除判空（规则16）。
 * Rust 保证 sched_state == GAMING 时 game_tgid != 0 且 game_ppid != 0。
 * 从 cls_game 计算中去掉 2 条冗余 test 指令。
 * kthread 子句简化为 is_kthread（GAMING 已确认）。 */
/* 讲解：仅按 1/64 采样重分类，非游戏态直接判 NORMAL 走极短路径。 */
static __noinline void stopping_reclassify(
	struct cake_task_hot *hot,
	struct task_struct *p,
	u32 rt_raw,
	u32 packed,
	u64 tick_slice)
{
	/* EEVDF NICE: always runs regardless of state.
	 * Hoisted before the GAMING gate so non-GAMING tasks still get
	 * correct vtime_mult updates (nice changes apply everywhere).
	 * BPF division: ~20-40 cycles, but runs only 1/64 stops (Rule 40). */
	/* EEVDF NICE：无论何种状态都执行。
	 * 上提到 GAMING 门之前，使非 GAMING 任务也能得到
	 * 正确的 vtime_mult 更新（nice 值变化处处生效）。
	 * BPF 除法：约 20-40 周期，但仅每 64 次停止执行 1 次（规则40）。 */
	/* 讲解：nice 权重换算成 vtime 乘子，权重越大乘子越小、虚拟时间走得越慢。 */
	{
		u32 w = p->scx.weight ?: 100;
		u16 mult = (u16)(102400 / w);
		if (hot->vtime_mult != mult)
			hot->vtime_mult = mult;
	}

	/* !GAMING early exit: when sched_state != GAMING, game_tgid/ppid == 0
	 * (Rust writes both atomically), so cls_game = false. All penalty
	 * clauses require GAMING. Result is always CAKE_CLASS_NORMAL.
	 * Rule 5: no work < some work. Saves ~25 insns on the non-gaming path. */
	/* 非 GAMING 提前退出：当 sched_state != GAMING 时 game_tgid/ppid == 0
	 *（Rust 原子写入两者），故 cls_game = false。所有惩罚子句都
	 * 要求 GAMING。结果恒为 CAKE_CLASS_NORMAL。
	 * 规则5：不做工作 < 做无用工作。非游戏路径省约 25 条指令。 */
	/* sched_state: global BSS read on 1/64 cold path.
	 * Per-CPU bss->sched_state_local not used here — adding
	 * bpf_get_smp_processor_id() kfunc causes 10 spills due to
	 * call-frame overhead in this register-heavy function.
	 * sched_state is rarely written (MESI-S). Acceptable. */
	/* sched_state：在 1/64 冷路径上读取全局 BSS。
	 * 此处不用每 CPU 的 bss->sched_state_local——因为加入
	 * bpf_get_smp_processor_id() kfunc 会在这个寄存器密集的
	 * 函数里因调用帧开销导致 10 次溢出。
	 * sched_state 极少被写（MESI-S 共享态）。可接受。 */
	/* 讲解：非游戏态直接判 NORMAL 并返回，跳过全部游戏分类逻辑。 */
	u32 snap_sched_state = sched_state;
	if (snap_sched_state != CAKE_STATE_GAMING) {
		if (hot->task_class != CAKE_CLASS_NORMAL)
			hot->task_class = CAKE_CLASS_NORMAL;
		return;
	}

	/* ── GAMING path: full classification ── */
	/* ── GAMING 路径：完整分类 ── */
	u8 is_kthread = (packed >> BIT_KTHREAD) & 1;

	/* cls_game: Rust contract guarantees game_tgid != 0 and game_ppid != 0
	 * when sched_state == GAMING. Null-checks eliminated (Rule 16).
	 * Kthread clause: GAMING confirmed above → just test is_kthread. */
	/* cls_game：Rust 约定保证 sched_state == GAMING 时 game_tgid != 0 且
	 * game_ppid != 0。判空已消除（规则16）。
	 * kthread 子句：上文已确认 GAMING → 仅测试 is_kthread。 */
	/* 讲解：进程组匹配游戏、父进程匹配游戏、或为内核线程，均判为 GAME。 */
	bool cls_game = (p->tgid == game_tgid)
		     || (hot->ppid == game_ppid)
		     || is_kthread;

	/* AUDIO PROTECTION: promote audio daemons during GAMING.
	 * JIT-constant: nr_audio_tgids==0 → dead-code eliminated. */
	/* 音频保护：GAMING 期间提升音频守护进程优先级。
	 * JIT 常量：nr_audio_tgids==0 → 该块被死代码消除。讲解：防止游戏中爆音。 */
	bool cls_audio = false;
	u32 task_tgid = p->tgid;
	if (!cls_game && nr_audio_tgids) {
		#pragma unroll
		for (u32 i = 0; i < CAKE_MAX_AUDIO_TGIDS; i++) {
			if (i >= nr_audio_tgids)
				break;
			if (task_tgid == audio_tgids[i]) {
				cls_audio = true;
				break;
			}
		}
	}

	/* COMPOSITOR PROTECTION: promote compositors during GAMING.
	 * JIT-constant: nr_compositor_tgids==0 → dead-code eliminated. */
	/* 合成器保护：GAMING 期间提升合成器优先级。
	 * JIT 常量：nr_compositor_tgids==0 → 该块被死代码消除。讲解：保证画面呈现流畅。 */
	bool cls_compositor = false;
	if (!cls_game && !cls_audio && nr_compositor_tgids) {
		#pragma unroll
		for (u32 i = 0; i < CAKE_MAX_COMPOSITOR_TGIDS; i++) {
			if (i >= nr_compositor_tgids)
				break;
			if (task_tgid == compositor_tgids[i]) {
				cls_compositor = true;
				break;
			}
		}
	}

	/* Rule 37: Fuse cls_squeeze + !is_kthread into cls_penalty.
	 * GAMING already confirmed — snap_sched_state check removed. */
	/* 规则37：把 cls_squeeze + !is_kthread 融合进 cls_penalty。
	 * GAMING 已确认——移除 snap_sched_state 检查。讲解：非游戏、无唤醒加成、非内核线程者受罚。 */
	bool cls_penalty = !cls_game
		&& !(((packed >> SHIFT_FLAGS) & CAKE_FLOW_WAKER_BOOST))
		&& !is_kthread;
	/* HOG detection: rt_raw >= 75% of quantum. Zero cold CL reads.
	 * Rule 14: bit testing / comparison-based classification. */
	/* HOG（占用大户）检测：运行时长 >= 量子的 75%。无冷缓存行读取。
	 * 规则14：基于位测试/比较的分类。讲解：几乎跑满时间片者判为 CPU 大户。 */
	u32 hog_thresh = ((u32)tick_slice >> 2) * 3;
	bool cls_hog = cls_penalty && (rt_raw >= hog_thresh);
	bool cls_bg  = cls_penalty && !cls_hog;

	/* 按优先级归类：游戏/音频/合成器→GAME，大户→HOG，其余受罚→BG，否则 NORMAL。讲解：三元链一次定级。 */
	u8 new_tc = cls_game       ? CAKE_CLASS_GAME
		  : cls_audio      ? CAKE_CLASS_GAME
		  : cls_compositor ? CAKE_CLASS_GAME
		  : cls_hog        ? CAKE_CLASS_HOG
		  : cls_bg         ? CAKE_CLASS_BG
		  : CAKE_CLASS_NORMAL;
	/* Rule 11: MESI check-before-write (~95% stable). */
	/* 规则11：MESI 先读后写（约 95% 稳定不变）。讲解：类别多数不变，写前先比对省缓存失效。 */
	if (hot->task_class != new_tc)
		hot->task_class = new_tc;
}
/* ═══ Phase 7A-1: Compute rt_raw (pure compute, 0 internal calls → 0 spills) ═══
 *
 * Pure computation: no kfunc calls, no sub-function calls.
 * Takes cpu_run (with cpu in bits 0-7), reads bss/p->scx.slice,
 * applies capacity scaling. Returns rt_raw (u32). */
/* ═══ 阶段 7A-1：计算 rt_raw（纯计算，0 内部调用 → 0 溢出） ═══
 *
 * 纯计算：无 kfunc 调用、无子函数调用。
 * 接收 cpu_run（CPU 号在 0-7 位），读取 bss/p->scx.slice，
 * 施加算力缩放。返回 rt_raw（u32）。 */
/* stopping_get_rt_raw: REMOVED — merged into stopping_drr_ewma.
 * BSS indexing was duplicated between the two functions.
 * Rule 24: operation fusion. Rule 64: A→D path compression. */
/* stopping_get_rt_raw：已移除——并入 stopping_drr_ewma。
 * 两函数间的 BSS 索引计算是重复的。
 * 规则24：操作融合。规则64：A→D 路径压缩。讲解：合并重复索引，减少调用与传参开销。 */


/* FunSearch: stopping_get_rt_raw MERGED into stopping_drr_ewma.
 * Both functions computed identical BSS indexing (cpu & 0xFF, &cpu_bss[cpu]).
 * Merge eliminates: (1) 4-insn call overhead in cake_stopping,
 * (2) 4-insn BSS indexing duplication, (3) rt_raw arg passing.
 * Returns rt_raw for eevdf_weight consumer.
 * Rule 24: operation fusion. Rule 64: A→D path compression. */
/* FunSearch：stopping_get_rt_raw 已并入 stopping_drr_ewma。
 * 两函数都做相同的 BSS 索引（cpu & 0xFF、&cpu_bss[cpu]）。
 * 合并消除了：(1) cake_stopping 里 4 条指令的调用开销，
 * (2) 4 条指令的 BSS 索引重复，(3) rt_raw 参数传递。
 * 返回 rt_raw 供 eevdf_weight 消费方使用。
 * 规则24：操作融合。规则64：A→D 路径压缩。 */
/* 讲解：DRR++ 记账 + 唤醒频率 EWMA + 重分类三合一，均在停止运行时执行。 */
static __noinline u32 stopping_drr_ewma(
	struct cake_task_hot *hot,
	struct task_struct *p,
	u32 cpu_run)
{
	u32 cpu = cpu_run & 0xFF;
	struct cake_cpu_bss *bss = &cpu_bss[cpu];

	/* ════ EWMA BLOCK (no p dependency) ════
	 * Compute EWMA BEFORE rt_raw so p does not need to survive
	 * across the EWMA block. This shrinks p liveness from ~38
	 * instructions to ~5, eliminating 2 spills (Rule 73). */
	/* ════ EWMA 块（不依赖 p） ════
	 * 在 rt_raw 之前先算 EWMA，使 p 不必跨越 EWMA 块存活。
	 * 这将 p 的活跃范围从约 38 条指令缩到约 5 条，消除 2 次溢出（规则73）。 */
	u32 rc = hot->reclass_counter++;

	/* FunSearch DRR V8: EWMA FIRST, reclassify AFTER.
	 * EWMA has no dependency on reclassify output.
	 * Reclassify call at function END means hot doesn't need to
	 * survive past it — saves r6 callee-save reservation.
	 * Rule 13: reclassify is cold (1/64), EWMA is hot (100%). */
	/* FunSearch DRR V8：先 EWMA，后重分类。
	 * EWMA 不依赖重分类的输出。
	 * 把重分类调用放到函数末尾，意味着 hot 无需在其后存活——
	 * 省下 r6 被调用者保存寄存器的占用。
	 * 规则13：重分类是冷路径（1/64），EWMA 是热路径（100%）。 */
	/* 讲解：唤醒间隔短则拉高 wake_counter（交互性强），长则减半衰减。 */
	{
		u32 rs = bss->run_start;
		u32 interval = rs - hot->last_run_at;
		hot->last_run_at = rs;
		u16 wc = hot->wake_counter;
		wc = (interval < 1024) ? (wc + ((1023 - wc) >> 2)) : (wc >> 1);
		hot->wake_counter = wc;
	}

	/* ════ RT_RAW + RECLASSIFY (p alive here) ════
	 * p->scx.slice read and reclassify call are adjacent,
	 * so p survives < 10 instructions. Zero spills (Rule 73). */
	/* ════ RT_RAW + 重分类（p 在此存活） ════
	 * p->scx.slice 的读取与重分类调用相邻，
	 * 故 p 只需存活不到 10 条指令。零溢出（规则73）。 */
	/* 讲解：本次实际运行时长 = 起始时间片 − 剩余时间片。 */
	u32 rt_raw = (u32)(bss->tick_slice - p->scx.slice);
	/* 上限钳制到约 64ms，防止异常大值。讲解：无分支饱和处理。 */
	rt_raw -= (rt_raw - (65535U << 10)) & -(rt_raw > (65535U << 10));
	/* EEVDF TOPOLOGY: capacity-scale dead-coded (9800X3D symmetric). */
	/* EEVDF 拓扑：算力缩放在对称 CPU（9800X3D）上为死代码。讲解：异构核上按算力折算运行时长。 */
	{
		u32 cap = cpuperf_cap_table[cpu];
		if (cap > 0 && cap < 1024)
			rt_raw = (u32)((u64)rt_raw * cap >> 10);
	}

	/* Confidence-gated reclassification (1/64 stops).
	 * Now at function END — call doesn't require hot survival past it.
	 * Separate __noinline to prevent register spills (Rule 23). */
	/* 置信度门控的重分类（每 64 次停止 1 次）。
	 * 现置于函数末尾——调用后无需 hot 继续存活。
	 * 独立 __noinline 以防止寄存器溢出（规则23）。讲解：按采样清除唤醒加成位并重判类别。 */
	if (unlikely((rc & 63) == 0)) {
		u32 packed = hot->packed_info;
		packed &= ~(((u32)CAKE_FLOW_WAKER_BOOST) << SHIFT_FLAGS);
		if (hot->packed_info != packed)
			hot->packed_info = packed;
		stopping_reclassify(hot, p, rt_raw, packed,
					 bss->tick_slice);
	}

	return rt_raw;
}

/* ═══ Phase 7B: EEVDF vtime + DSQ weight ═══
 *
 * Rule 74 (Intrinsic State Exploitation):
 * - sleep_lag REMOVED: vtime gap from not advancing IS the sleeper credit.
 *   Kernel EEVDF derives lag from vruntime delta — no separate variable.
 * - nice_scale_table REMOVED: vtime rate via nice_shift IS the nice scaling.
 *   Double-scaling vtime AND dsq_weight by nice was a Shadow State.
 * - Tiered weight simplified: vtime rate handles proportional ordering;
 *   dsq_weight is a fixed tier offset + optional GAME wake bonus.
 *
 * Returns: dsq_weight (u32) for Phase C quantum/staged pack.
 * Reads: hot->task_class, nice_shift, wake_counter, dsq_vtime.
 * Writes: hot->dsq_vtime. */
/* ═══ 阶段 7B：EEVDF vtime + DSQ 权重 ═══
 *
 * 规则74（内在状态利用）：
 * - 移除 sleep_lag：不推进 vtime 所形成的差距本身就是睡眠者信用。
 *   内核 EEVDF 也从 vruntime 差值推导 lag——无需单独变量。
 * - 移除 nice_scale_table：借 nice_shift 得到的 vtime 速率就是 nice 缩放。
 *   同时用 nice 缩放 vtime 与 dsq_weight 属于“影子状态”重复。
 * - 分层权重简化：vtime 速率负责层内的比例排序；
 *   dsq_weight 只是固定的层偏移 + 可选的 GAME 唤醒加成。
 *
 * 返回：dsq_weight（u32），供阶段 C 的量子/暂存打包使用。
 * 读取：hot->task_class、nice_shift、wake_counter、dsq_vtime。
 * 写入：hot->dsq_vtime。 */
/* 核心是推进任务虚拟时间，vtime 越小越优先被调度。 */
static __noinline u32 stopping_eevdf_weight(
	struct cake_task_hot *hot,
	u32 rt_raw,
	u32 cpu_run,
	u64 vtime_local)
{
	u8 tc = hot->task_class;

	/* Non-runnable: no vtime advancement, return 0.
	 * Rule 74: The vtime gap from NOT advancing IS the sleeper credit.
	 * No side effects needed — intrinsic state. */
	/* 不可运行（睡眠）：不推进 vtime，返回 0。
	 * 规则74：不推进所形成的 vtime 差距本身就是睡眠者信用。
	 * 无需额外副作用——这是内在状态。讲解：睡眠越久 vtime 越落后，醒来自然更优先。 */
	if (!(cpu_run >> 8))
		return 0;

	/* EEVDF vtime advancement — the core operation.
	 * vtime_mult is pre-computed reciprocal (102400/weight).
	 * Rule 74: vtime rate IS the nice/priority scaling — no separate table.
	 *
	 * Kernel equivalent: curr->vruntime += calc_delta_fair(delta_exec, curr)
	 * which does: delta * NICE_0_LOAD / weight. We do: rt_raw * vtime_mult >> 10.
	 * Same math, BPF-optimized. */
	/* EEVDF vtime 推进——核心操作。
	 * vtime_mult 是预先算好的倒数（102400/权重）。
	 * 规则74：vtime 速率就是 nice/优先级缩放——无需单独查表。
	 *
	 * 内核等价：curr->vruntime += calc_delta_fair(delta_exec, curr)，
	 * 即 delta * NICE_0_LOAD / weight。我们做 rt_raw * vtime_mult >> 10。
	 * 数学相同，只是做了 BPF 优化。讲解：权重越大 vtime 走得越慢，越易抢到 CPU。 */
	{
		u64 vt_delta = (u64)rt_raw * (u32)hot->vtime_mult >> 10;
		hot->dsq_vtime += vt_delta;

		/* Vtime floor: prevent infinite credit from long sleep.
		 * Analogous to kernel's update_min_vruntime().
		 * Per-CPU vtime_local: eliminates cross-core BSS read (Rule 8). */
		/* vtime 下限：防止长睡眠积累出无限信用。
		 * 类比内核的 update_min_vruntime()。
		 * 每 CPU 的 vtime_local：消除跨核 BSS 读取（规则8）。讲解：给睡眠信用封顶，避免饿死他人。 */
		u64 vt_min = vtime_local - 200000000ULL;
		if (hot->dsq_vtime < vt_min)
			hot->dsq_vtime = vt_min;
	}

	/* DSQ weight: fixed tier offset for class separation.
	 * Vtime rate handles proportional ordering within tiers;
	 * tier_base provides absolute priority gaps between classes.
	 *
	 * FunSearch V6: wake_bonus block REMOVED — provably dead code.
	 * tier_base[CAKE_CLASS_GAME] == 0, so the branchless subtraction
	 * dsq_weight -= wb & -(dsq_weight > wb) always yields:
	 * 0 - (wb & -(0 > wb)) = 0 - (wb & 0) = 0.
	 * Zero instructions wasted on a nop. */
	/* DSQ 权重：用于类别分隔的固定层偏移。
	 * vtime 速率负责层内比例排序；
	 * tier_base 提供类别间的绝对优先级间隔。
	 *
	 * FunSearch V6：wake_bonus 块已移除——可证明是死代码。
	 * 因 tier_base[CAKE_CLASS_GAME] == 0，故无分支减法
	 * dsq_weight -= wb & -(dsq_weight > wb) 恒等于：
	 * 0 - (wb & -(0 > wb)) = 0 - (wb & 0) = 0。
	 * 无一条指令浪费在空操作上。讲解：直接返回该类别的层基值即可。 */
	return tier_base[tc & 3];
}

/* ═══ Phase 7C: Quantum + Staged Pack (≤4 live values → 0 spills) ═══
 *
 * Does: PID class cache tunnel, quantum/slice computation,
 *       staged_vtime_bits packing (dsq_weight + new_flow flag).
 * P2C: cpu_run arg removed — only consumer was dead home_cpu staging.
 * P2C: packed_info load for wb_val removed — wb_dup had zero read sites.
 * Reads: hot->task_class, hot->packed_info (new_flow bit only).
 * Writes: p->scx.slice, hot->staged_vtime_bits, pid_class_cache[]. */
/* ═══ 阶段 7C：量子 + 暂存打包（活跃值 ≤4 → 0 溢出） ═══
 *
 * 职责：PID 类别缓存隧道、量子/时间片计算、
 *       staged_vtime_bits 打包（dsq_weight + new_flow 标志）。
 * P2C：移除 cpu_run 参数——其唯一消费者是已废弃的 home_cpu 暂存。
 * P2C：移除为 wb_val 而做的 packed_info 读取——wb_dup 无任何读取点。
 * 读取：hot->task_class、hot->packed_info（仅 new_flow 位）。
 * 写入：p->scx.slice、hot->staged_vtime_bits、pid_class_cache[]。 */
/* 讲解：把下次入队要用的 vtime 权重与标志预先打包好，供 enqueue 路径直接消费。 */
static __noinline void stopping_quantum_pack(
	struct cake_task_hot *hot,
	struct task_struct *p,
	u32 dsq_weight)
{
	u8 tc = hot->task_class;

	/* PID class cache tunnel for Gate 2. MESI check-before-write. */
	/* 供第2门使用的 PID 类别缓存隧道。MESI 先读后写。讲解：让 select_cpu 快速查到任务类别。 */
	{
		u32 pid_idx = p->pid & (PID_CLASS_CACHE_SIZE - 1);
		if (pid_class_cache[pid_idx] != (u8)tc)
			pid_class_cache[pid_idx] = (u8)tc;
	}

	/* ANTI-STARVATION: p->scx.slice NOT set here.
	 * Writing slice in stopping caused the kernel's balance_one()
	 * to set SCX_RQ_BAL_KEEP (ext.c:2197), which skips local_dsq
	 * and ops.dispatch() entirely — starving all other tasks on
	 * this CPU. Verified: no other sched-ext scheduler (bpfland,
	 * cosmos, lavd) writes p->scx.slice in stopping.
	 * Slice lifecycle: natural tick decay → 0 → balance_one enters
	 * full dispatch → local DSQ + LLC DSQ checked → fair scheduling.
	 * GAME double-slice moved to enqueue_wakeup_path. */
	/* 抗饥饿：此处不设置 p->scx.slice。
	 * 在 stopping 中写 slice 会使内核 balance_one() 置位
	 * SCX_RQ_BAL_KEEP（ext.c:2197），从而完全跳过 local_dsq
	 * 与 ops.dispatch()——饿死本 CPU 上的所有其他任务。已核实：
	 * 其他 sched-ext 调度器（bpfland、cosmos、lavd）都不在 stopping
	 * 中写 p->scx.slice。
	 * 时间片生命周期：自然 tick 衰减 → 0 → balance_one 进入
	 * 完整派发 → 检查 local DSQ + LLC DSQ → 公平调度。
	 * GAME 双倍时间片已移到 enqueue_wakeup_path。讲解：切勿在停止回调里写 slice，否则触发内核保持标志导致饥饿。 */

	/* P2C: home_cpu (STAGED_SHIFT_HOME) and wb_dup (STAGED_BIT_WB_DUP) pruned —
	 * Rule 5/74: both have zero BPF read sites. Only dsq_weight, new_flow,
	 * and VALID are consumed by enqueue paths. packed_info load eliminated. */
	/* P2C：home_cpu（STAGED_SHIFT_HOME）与 wb_dup（STAGED_BIT_WB_DUP）已裁剪——
	 * 规则5/74：二者在 BPF 侧都无读取点。enqueue 路径只消费 dsq_weight、
	 * new_flow 与 VALID。已消除 packed_info 的读取。讲解：只打包真正被用到的位。 */
	{
		u64 nf_val = (tc == CAKE_CLASS_GAME) ? 1 : (u64)((hot->packed_info >> SHIFT_FLAGS) & 1);
		hot->staged_vtime_bits = (1ULL << STAGED_BIT_VALID) |
					(nf_val << STAGED_BIT_NEW_FLOW) |
					(u64)dsq_weight;
	}
}

/* cake_stopping — direct arena access + confidence-gated PELT
任务被dequeue或者put时调用
 * Inputs read directly from task_storage via get_task_hot:
 *   deficit_u16 = DRR deficit (standalone)
 *   packed_info = yield/flow flags
 *   nvcsw_snapshot = yield detection baseline
 *
 * Per-CPU BSS (cpu_bss) provides run_start and tick_slice
 * (staged by cake_running from task_struct fields).
 *
 * Cost: get_task_ctx (~29ns) + arena CL0 reads (~4ns) + work (~15ns). */
/* cake_stopping——直接 arena 访问 + 置信度门控 PELT。
 *
 * 经 get_task_hot 直接从 task_storage 读取的输入：
 *   deficit_u16 = DRR 赤字（独立）
 *   packed_info = 让出/流标志
 *   nvcsw_snapshot = 让出检测基线
 *
 * 每 CPU 的 BSS（cpu_bss）提供 run_start 与 tick_slice
 *（由 cake_running 从 task_struct 字段暂存）。
 *
 * 成本：get_task_ctx（约 29ns）+ arena CL0 读取（约 4ns）+ 工作（约 15ns）。 */
/* 讲解：任务停止运行时（下cpu)的回调，是记账、重分类、推进 vtime、打包下次调度信息的枢纽。 */
void BPF_STRUCT_OPS(cake_stopping, struct task_struct *p, bool runnable)
{
#ifndef CAKE_RELEASE
	ARENA_ASSOC();
#endif

	/* Call ordering: bpf_get_smp_processor_id FIRST (only p=r6,
	 * runnable=r7 survive = 2 callee-saves). Then compute cpu_run.
	 * Then get_task_hot (p=r6, cpu_run=r7 survive = 2 callee-saves).
	 * Neither call exceeds 4 callee-saves → 0 spills. */
	/* 调用顺序：先 bpf_get_smp_processor_id（仅 p=r6、runnable=r7
	 * 需存活 = 2 个被调用者保存寄存器）。再计算 cpu_run。
	 * 然后 get_task_hot（p=r6、cpu_run=r7 存活 = 2 个）。
	 * 两次调用都不超过 4 个被调用者保存寄存器 → 0 溢出。讲解：精心排序调用以压低寄存器占用。 */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	/* FunSearch: explicit (runnable & 1) forces branchless packing.
	 * BPF struct_ops extracts runnable as u64 — compiler doesn't trust
	 * it to be 0/1 and generates a branch. The & 1 constrains the value,
	 * enabling shift-OR instead of branch. Rule 14: bitwise ops. */
	/* FunSearch：显式 (runnable & 1) 强制无分支打包。
	 * BPF struct_ops 把 runnable 提取为 u64——编译器不信任它
	 * 一定是 0/1，会生成分支。& 1 约束取值范围，
	 * 从而用移位-或代替分支。规则14：位运算。讲解：把布尔塞进第 8 位与 CPU 号合并。 */
	u32 cpu_run = cpu | (((u32)runnable & 1) << 8);

	struct cake_task_hot *hot = get_task_hot(p);
	if (unlikely(!hot))
		return;

	/* ═══ Phase 7A: DRR + Classify + EWMA + rt_raw (fused) ═══
	 * stopping_get_rt_raw merged into stopping_drr_ewma.
	 * BSS indexing shared, rt_raw returned. Rule 24: operation fusion. */
	/* ═══ 阶段 7A：DRR + 分类 + EWMA + rt_raw（已融合） ═══
	 * stopping_get_rt_raw 已并入 stopping_drr_ewma。
	 * 共享 BSS 索引，返回 rt_raw。规则24：操作融合。 */
	u32 rt_raw = stopping_drr_ewma(hot, p, cpu_run);
	u8 tc = hot->task_class;

	bool stats_on = CAKE_STATS_ACTIVE;
	u64 stopping_overhead_start = 0;
	if (stats_on) {
		stopping_overhead_start = scx_bpf_now();
		per_cpu[cpu].mbox.last_stopped_pid = p->pid;
	}

	/* P3-2: nvcsw tracking — stats-gated (telemetry only). */
	/* P3-2：nvcsw（主动上下文切换）跟踪——仅统计开启时（用于遥测）。讲解：估算任务的主动让出频率。 */
	u64 cur_nv = 0;
	u32 __maybe_unused nvcsw_accum = 0;
	if (stats_on && tc != CAKE_CLASS_GAME) {
		cur_nv = p->nvcsw;
		u64 prev_nv = hot->nvcsw_snapshot;
		if (prev_nv > 0)
			nvcsw_accum = (u32)(cur_nv - prev_nv);
		hot->nvcsw_snapshot = cur_nv;
	}

	/* P2 OPT-7: deferred_ts_start/classify_end/tctx_stop REMOVED.
	 * All were always-zero in release (stats_on=0) and in debug
	 * (deferred_ts_start=0 → classify_end=0 → tctx_stop=NULL).
	 * Eliminates 3 dead variable inits + 2 dead branches (−4 insns). */
	/* P2 OPT-7：deferred_ts_start/classify_end/tctx_stop 已移除。
	 * 它们在 release（stats_on=0）与 debug（deferred_ts_start=0 →
	 * classify_end=0 → tctx_stop=NULL）下恒为零。
	 * 消除 3 个死变量初始化 + 2 个死分支（−4 条指令）。讲解：删除永远为零的中间量。 */

	/* ═══ Phase 7B: EEVDF vtime + DSQ weight ═══
	 * Extracted to __noinline — handles sleep_lag, warm_cpus, vtime,
	 * DSQ weight, rt_cost, nice scaling, lag credit.
	 * Returns 0 if non-runnable (skip quantum/pack), dsq_weight otherwise. */
	/* ═══ 阶段 7B：EEVDF vtime + DSQ 权重 ═══
	 * 抽取为 __noinline——处理 sleep_lag、warm_cpus、vtime、
	 * DSQ 权重、rt_cost、nice 缩放、lag 信用。
	 * 若不可运行返回 0（跳过量子/打包），否则返回 dsq_weight。 */
	u32 dsq_weight = stopping_eevdf_weight(hot, rt_raw, cpu_run,
		cpu_bss[cpu_run & 0xFF].vtime_local);

	/* Gate Phase C on dsq_weight instead of runnable.
	 * stopping_eevdf_weight returns 0 for non-runnable tasks,
	 * so dsq_weight > 0 ≡ runnable && has_weight. This eliminates
	 * the compiler's need to keep the original ctx 'runnable' bool
	 * alive across all function calls (was causing 4 spills). */
	/* 用 dsq_weight 而非 runnable 作为阶段 C 的门控。
	 * stopping_eevdf_weight 对不可运行任务返回 0，
	 * 故 dsq_weight > 0 等价于 runnable && 有权重。这样编译器
	 * 就无需让原始 ctx 的 'runnable' 布尔跨越所有函数调用
	 * 存活（此前导致 4 次溢出）。讲解：用返回值代替布尔活跃，省寄存器。 */
	if (dsq_weight) {
#ifndef CAKE_RELEASE
		/* P3-3: classify/warm telemetry — tctx_stop removed (P2 OPT-7).
		 * deferred_ts_start/classify_end were always-zero → dead code. */
		/* P3-3：分类/预热遥测——tctx_stop 已移除（P2 OPT-7）。
		 * deferred_ts_start/classify_end 恒为零 → 死代码。 */
#endif

		/* ═══ Phase 7C: Quantum + Staged Pack ═══
		 * Extracted to __noinline — handles PID class cache,
		 * quantum/slice computation, staged_vtime_bits packing. */
		/* ═══ 阶段 7C：量子 + 暂存打包 ═══
		 * 抽取为 __noinline——处理 PID 类别缓存、
		 * 量子/时间片计算、staged_vtime_bits 打包。 */
		stopping_quantum_pack(hot, p, dsq_weight);
	}

	/* Phase 8: vtime staging stopwatch — tctx_stop removed (P2 OPT-7). */
	/* 阶段8：vtime 暂存计时——tctx_stop 已移除（P2 OPT-7）。 */
#ifndef CAKE_RELEASE
#endif

	/* ── Telemetry + aggregate profiling (verbose only) ──
	 * Split into ALWAYS (lightweight CL0/BSS) + DEFERRED (heavy CL1-CL3).
	 * Deferred block runs every 64th stop via reclass_counter gate. */
	/* last_run_at: moved up to co-locate with deficit/packed writes (Change B). */
	/* ── 遥测 + 汇总性能剖析（仅 verbose 构建） ──
	 * 分为 ALWAYS（轻量 CL0/BSS）+ DEFERRED（重量级 CL1-CL3）。
	 * DEFERRED 块借 reclass_counter 门控，每 64 次停止执行 1 次。
	 * last_run_at：已上移与 deficit/packed 写入放一起（变更 B）。讲解：重量遥测按采样执行以摊薄开销。 */

	if (stats_on) {
#ifndef CAKE_RELEASE
		/* ALWAYS: nvcsw_delta accumulator (must not skip deltas) */
		/* Note: nvcsw_delta write is on telemetry CL, but accumulator
		 * correctness requires every-stop update. The CL fetch is
		 * amortized since stopping already read nvcsw_snapshot from CL0. */
		/* ALWAYS：nvcsw_delta 累加器（不能漏掉任何增量）。
		 * 注意：nvcsw_delta 写在遥测缓存行上，但累加器的正确性
		 * 要求每次停止都更新。该缓存行读取是摊薄的，因为 stopping
		 * 已从 CL0 读过 nvcsw_snapshot。 */

		/* DEFERRED TELEMETRY: Heavy per-task writes every 64th stop.
		 * Saves ~13 arena writes + 1 scx_bpf_now() + 1 div64 on 63/64 stops.
		 * SIMPLIFY #3: Single get_task_ctx + shared timestamp for entire block.
		 * FIX: Use pre-increment rc (matches classify block at line 2582).
		 * Was using hot->reclass_counter (post-increment = rc+1) — fired on
		 * different stop than classify, wasting a 29ns get_task_ctx call.
		 * Now reuses tctx_stop (already fetched under same gate). */
		/* DEFERRED 遥测：每 64 次停止做一次重量级的每任务写入。
		 * 在 63/64 的停止上省下约 13 次 arena 写 + 1 次 scx_bpf_now() + 1 次 div64。
		 * 简化 #3：整块共用一次 get_task_ctx + 一个共享时间戳。
		 * 修复：使用前递增的 rc（与分类块的门控一致）。
		 * 此前用 hot->reclass_counter（后递增 = rc+1）——与分类触发在
		 * 不同的停止上，白白浪费一次 29ns 的 get_task_ctx 调用。
		 * 现复用同一门控下已取到的 tctx。讲解：让分类与遥测共用同一采样点。 */
		if (((hot->reclass_counter - 1) & 63) == 0) {
			struct cake_task_ctx __arena *tctx = get_task_ctx(p);
			if (tctx) {
				/* P3-2: Use pre-computed nvcsw_accum from above
				 * (eliminates redundant p->nvcsw + hot->nvcsw_snapshot reads) */
				/* P3-2：复用上文预算的 nvcsw_accum
				 *（消除对 p->nvcsw 与 hot->nvcsw_snapshot 的重复读取）。 */
				if (nvcsw_accum)
					tctx->telemetry.nvcsw_delta += nvcsw_accum;

				if (tctx->telemetry.run_start_ns > 0) {
				/* SIMPLIFY #4: Single scx_bpf_now() for dur + stopping overhead */
				/* 简化 #4：一次 scx_bpf_now() 同时用于运行时长与 stopping 开销。 */
				u64 now_deferred = scx_bpf_now();
				u64 dur = now_deferred - tctx->telemetry.run_start_ns;
				tctx->telemetry.run_duration_ns = dur;

				/* Branchless same-CPU streak */
				/* 无分支的“同 CPU 连跑次数”统计。讲解：连续落在同一核则计数递增，否则清零。 */
				bool same = ((u16)cpu == tctx->telemetry.core_placement);
				tctx->telemetry.same_cpu_streak = (tctx->telemetry.same_cpu_streak + 1) & -(u16)same;
				tctx->telemetry.core_placement = (u16)cpu;

				/* Jitter: |actual_run - PELT_expected| */
				/* 抖动：|实际运行时长 − PELT 预期|。讲解：衡量调度时长的稳定性。 */
				u64 expected_ns = (u64)(rt_raw >> 10) * 1000ULL;
				u64 d = dur - expected_ns;
				u64 mask = -(u64)(dur < expected_ns);
				u64 jitter = (d ^ mask) - mask;
				tctx->telemetry.jitter_accum_ns += jitter;
				tctx->telemetry.total_runs++;

				/* Branchless max */
				/* 无分支取最大运行时长（微秒）。讲解：仅当更大时替换。 */
				u16 old_max_rt = tctx->telemetry.max_runtime_us;
				u16 ps = (u16)(rt_raw >> 10);
				tctx->telemetry.max_runtime_us = old_max_rt + ((ps - old_max_rt) & -(u16)(ps > old_max_rt));

				/* Slice utilization — shift-approximate, no div64 (Rule 5)
				 * (dur << 7) / tslice ≈ dur * 128 / tslice.
				 * Rescaled by 100/128 = 0.78, close enough for TUI display. */
				/* 时间片利用率——用移位近似，避免 div64（规则5）。
				 *（dur << 7）/ tslice ≈ dur * 128 / tslice。
				 * 相当于按 100/128=0.78 缩放，对 TUI 显示足够近似。讲解：牺牲少许精度换取免除 64 位除法。 */
				u64 tslice = cpu_bss[cpu].tick_slice ?: quantum_ns;
				tctx->telemetry.slice_util_pct =
					(u16)((dur << 7) / tslice);

				/* Involuntary context switch delta */
				/* 被动上下文切换增量。讲解：反映任务被抢占的频率。 */
				u64 cur_nivcsw = p->nivcsw;
				u64 prev_nivcsw = tctx->telemetry.nivcsw_snapshot;
				if (prev_nivcsw > 0)
					tctx->telemetry.nivcsw_delta += (u32)(cur_nivcsw - prev_nivcsw);
				tctx->telemetry.nivcsw_snapshot = cur_nivcsw;

				/* Per-task stopping overhead — reuse now_deferred */
				/* 每任务的 stopping 开销——复用 now_deferred。讲解：避免再取一次时间。 */
				tctx->telemetry.stopping_duration_ns =
					(u32)(now_deferred - stopping_overhead_start);
				}

				/* Phase 8: quantum completion tracking */
				/* 阶段8：量子完成情况统计。讲解：区分跑满/主动让出/被抢占三种结束方式。 */
				u64 rem = p->scx.slice;
				if (rem == 0)
					tctx->telemetry.quantum_full_count++;
				else if (!(cpu_run >> 8))
					tctx->telemetry.quantum_yield_count++;
				else
					tctx->telemetry.quantum_preempt_count++;

				/* Phase 8: CPU core distribution histogram */
				/* 阶段8：CPU 核分布直方图。讲解：统计任务在各核上运行的次数。 */
				tctx->telemetry.cpu_run_count[cpu & (CAKE_TELEM_MAX_CPUS - 1)]++;

				/* CL0 → arena sync: iter reads these from tctx, not hot.
				 * Values computed in reclassify path above (every 64th stop).
				 * Check-before-write avoids cache invalidation on unchanged fields. */
				/* CL0 → arena 同步：iter 从 tctx 读取这些值，而非 hot。
				 * 这些值由上方重分类路径算出（每 64 次停止 1 次）。
				 * 先读后写避免对未变字段造成缓存失效。讲解：把热态字段镜像到 arena 供 TUI 读取。 */
				if (tctx->vtime_mult != hot->vtime_mult)
					tctx->vtime_mult = hot->vtime_mult;
				if (tctx->task_class != hot->task_class)
					tctx->task_class = hot->task_class;
			}
		}
#endif /* !CAKE_RELEASE */

		/* ALWAYS: Aggregate overhead timing (per-CPU BSS, cheap)
		 * Rule 30: reuse cpu from top of function, skip kfunc trampoline.
		 * Rule 7: single scx_bpf_now() for both deferred + always paths. */
		/* ALWAYS：汇总开销计时（每 CPU BSS，代价低）。
		 * 规则30：复用函数开头的 cpu，跳过 kfunc 跳板。
		 * 规则7：deferred 与 always 路径共用一次 scx_bpf_now()。 */
		struct cake_stats *s = get_local_stats_for(cpu);
		u64 oh_agg = scx_bpf_now() - stopping_overhead_start;
		s->total_stopping_ns += oh_agg;
		s->max_stopping_ns = s->max_stopping_ns + ((oh_agg - s->max_stopping_ns) & -(oh_agg > s->max_stopping_ns));
		/* Phase 7A: rc moved inside stopping_drr_classify.
		 * Read post-increment counter and subtract 1 to match. */
		/* 阶段7A：rc 已移入 stopping_drr_classify。
		 * 读取后递增计数器并减 1 以对齐。区分本次是重分类还是被采样跳过。 */
		if (((hot->reclass_counter - 1) & 63) == 0)
			s->nr_stop_classify++;
		else
			s->nr_stop_confidence_skip++;

		/* BenchLab trigger (cold — only fires on TUI demand) */
		/* BenchLab 触发器（冷路径——仅在 TUI 请求时触发）。按需运行 kfunc 微基准。 */
		if (unlikely(bench_request)) {
			bench_request = 0;
			run_kfunc_bench(&bench_results, p);
		}
	}
}

/* Initialize per-task arena storage.
 * Sleepable: bpf_arena_alloc_pages is sleepable-only, so all arena
 * allocation must happen here, not in hot paths.
 * Called before any scheduling ops fire for this task. */
/* 初始化每任务的 arena 存储。
 * 可睡眠：bpf_arena_alloc_pages 只能在可睡眠上下文调用，
 * 故所有 arena 分配都必须放在这里，不能放热路径。
 * 在该任务的任何调度回调触发之前调用。讲解：任务创建时一次性分配并初始化上下文。 */

 /* 每任务的arena存储作用是:
 
  */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct cake_task_ctx __arena *tctx;

	/* 分配arena内存 */
	tctx = (struct cake_task_ctx __arena *)scx_task_alloc(p);
	if (!tctx) {
		if (CAKE_STATS_ACTIVE) {
			struct cake_stats *s = get_local_stats();
			s->nr_dropped_allocations++;
		}
		return -ENOMEM;
	}

	/* NOTE: pid_to_tctx registration removed — iter/task program provides
	 * full task visibility without any map update. Fully lockless. */
	/* 注意：pid_to_tctx 注册已移除——iter/task 程序无需任何 map 更新
	 * 即可提供完整的任务可见性。完全无锁。靠任务迭代器遍历，省去映射维护。 */

	/* MULTI-SIGNAL INITIAL CLASSIFICATION (moved from alloc_task_ctx_cold)
     *
     * Signal 1: Nice value (u32 field read, ~2 cycles)
     *   - nice < 0 (prio < 120): OS/user explicitly prioritized → T0
     *   - nice > 10 (prio > 130): explicitly deprioritized → T3
     *   - nice 0-10: default → T1, avg_runtime adjusts naturally
     *
     * R1 sum-of-cmp: branchless non-monotonic mapping.
     * (prio >= 120) = 0 for negative nice (→ CRITICAL=0), 1 for default (→ INTERACT=1)
     * (prio > 130) * 2 = 0 for normal, 2 for high nice (1+2 = BULK=3) */
	/* 多信号初始分类（从 alloc_task_ctx_cold 移来）
	 *
	 * 信号1：nice 值（u32 字段读取，约 2 周期）
	 *   - nice < 0（prio < 120）：OS/用户显式提优 → T0
	 *   - nice > 10（prio > 130）：显式降优 → T3
	 *   - nice 0-10：默认 → T1，avg_runtime 会自然调整
	 *
	 * R1 比较求和：无分支的非单调映射。
	 *（prio >= 120）负 nice 为 0（→ CRITICAL=0），默认为 1（→ INTERACT=1）
	 *（prio > 130）* 2：正常为 0，高 nice 为 2（1+2 = BULK=3）。用 nice 给任务一个初始层级。 */
	/* init_deficit: shared by arena init (stats-gated) and task_hot init. */
	/* init_deficit：由 arena 初始化（受统计门控）与 task_hot 初始化共用。初始 DRR 赤字预算。 */
	u16 init_deficit = (u16)((quantum_ns + new_flow_bonus_ns) >> 10);

	/* SIMPLIFY #1: Arena CL0 fields are only read by cake_task_iter (telemetry).
	 * Hot-path readers (running, stopping, select_cpu, enqueue) use task_hot.
	 * Gate arena CL0 init behind CAKE_STATS_ENABLED to save ~10 arena writes. */
	/* 简化 #1：arena CL0 字段只被 cake_task_iter（遥测）读取。
	 * 热路径读取方（running、stopping、select_cpu、enqueue）用 task_hot。
	 * 把 arena CL0 初始化放在 CAKE_STATS_ENABLED 门控后，省约 10 次 arena 写。 */
	if (CAKE_STATS_ENABLED) {
		tctx->deficit_u16      = init_deficit;
		tctx->last_run_at      = 0;
		tctx->reclass_counter  = 0;
		tctx->warm_cpus[0]     = 0xFFFF;
		tctx->warm_cpus[1]     = 0xFFFF;
		tctx->warm_cpus[2]     = 0xFFFF;
		tctx->waker_cpu        = 0xFFFF;
		tctx->task_class       = CAKE_CLASS_NORMAL;
	}

	/* PPID: deferred — derived after bpf_task_storage_get to avoid
	 * carrying init_ppid across build_cached_cpumask (Rule 23: 0 spills).
	 * Set in tctx and hot together below. */
	/* PPID：延迟处理——在 bpf_task_storage_get 之后再派生，避免
	 * 让 init_ppid 跨越 build_cached_cpumask 存活（规则23：0 溢出）。
	 * 在下方与 hot 一起写入 tctx。讲解：父进程号用于游戏子进程识别。 */

	/* TUI telemetry: identity fields only needed with --verbose.
	 * Gated to avoid unnecessary arena writes on task creation. */
	/* TUI 遥测：身份字段仅在 --verbose 时需要。
	 * 加门控以避免任务创建时的无谓 arena 写。pid/tgid/comm 仅供界面展示。 */
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ACTIVE) {
		tctx->telemetry.pid = p->pid;
		tctx->telemetry.tgid = p->tgid;
		u64 *comm_src = (u64 *)p->comm;
		u64 __arena *comm_dst = (u64 __arena *)tctx->telemetry.comm;
		comm_dst[0] = comm_src[0];
		comm_dst[1] = comm_src[1];
		/* nivcsw_snapshot: TUI delta only (nvcsw gated separately below) */
		/* nivcsw_snapshot：仅供 TUI 求增量（nvcsw 在下方单独门控）。 */
		tctx->telemetry.nivcsw_snapshot = p->nivcsw;
	}
#endif

	/* nvcsw_snapshot: hot-path reads hot->nvcsw_snapshot (task_storage).
	 * Arena copy only needed for iter/task (TUI). Gate to save arena write. */
	/* nvcsw_snapshot：热路径读取 hot->nvcsw_snapshot（task_storage）。
	 * arena 副本仅 iter/task（TUI）需要。加门控以省一次 arena 写。 */
	if (CAKE_STATS_ENABLED)
		tctx->nvcsw_snapshot = p->nvcsw;


	u32 packed		= 0;
	/* Fused FLAGS: bits [27:24] = [flags:4], FLOW_NEW set on creation */
	/* 融合 FLAGS：位 [27:24] = [flags:4]，创建时置 FLOW_NEW。新任务标记为新流以获入队奖励。 */
	packed |= ((u32)CAKE_FLOW_NEW & MASK_FLAGS) << SHIFT_FLAGS;
	/* Cache PF_KTHREAD branchless (Rule 14+41: relocate cold read to init).
	 * Kernel threads are immune to bg_noise squeeze.
	 * Branchless: extract bit 21 (PF_KTHREAD) from p->flags, shift to BIT_KTHREAD. */
	/* 无分支缓存 PF_KTHREAD（规则14+41：把冷读取移到 init）。
	 * 内核线程不受 bg_noise 压制影响。
	 * 无分支：从 p->flags 取第 21 位（PF_KTHREAD），移位到 BIT_KTHREAD。预先缓存是否内核线程。 */
	packed |= (((u32)(p->flags >> 21) & 1u) << BIT_KTHREAD);
	/* Arena copy: only read by iter/task (TUI). Hot-path uses hot->packed_info. */
	/* arena 副本：仅 iter/task（TUI）读取。热路径用 hot->packed_info。 */
	if (CAKE_STATS_ENABLED)
		tctx->packed_info = packed;

	/* CACHED AFFINITY REMOVED: after scx_bpf_select_cpu_and refactor,
	 * kernel handles affinity via p->cpus_ptr natively.
	 * build_cached_cpumask + bpf_rcu_read_lock/unlock eliminated (Rule 64). */
	/* 缓存亲和性已移除：在改用 scx_bpf_select_cpu_and 后，
	 * 内核通过 p->cpus_ptr 原生处理亲和性。
	 * build_cached_cpumask + bpf_rcu_read_lock/unlock 已消除（规则64）。亲和性交给内核，去掉自维护掩码。 */

	/* Phase 6: Allocate task_storage and mirror CL0 hot fields.
	 * BPF_LOCAL_STORAGE_GET_F_CREATE allocates on first call. */
	/* 阶段6：分配 task_storage 并镜像 CL0 热字段。
	 * BPF_LOCAL_STORAGE_GET_F_CREATE 在首次调用时分配。热字段放 task_storage，访问比 arena 快。 */
	struct cake_task_hot *hot = bpf_task_storage_get(
		&task_hot_stor, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (hot) {
		hot->deficit_u16 = init_deficit;
		hot->wake_counter      = 0;
		hot->packed_info       = packed;
		u32 init_ppid = p->real_parent ? p->real_parent->tgid : 0;
		if (CAKE_STATS_ENABLED)
			tctx->ppid = init_ppid;
		hot->ppid              = init_ppid;
		hot->last_run_at       = 0;
		hot->reclass_counter   = 0;
		/* Rule 24 (Operation Fusion): warm_cpus[0..2] + waker_cpu are
		 * contiguous u16s at struct offsets 28-35 (8 bytes total).
		 * Single u64 store writes all 4 sentinel values (0xFFFF). */
		/* 规则24（操作融合）：warm_cpus[0..2] + waker_cpu 是结构体
		 * 偏移 28-35 处连续的 u16（共 8 字节）。
		 * 用一次 u64 存储写入全部 4 个哨兵值（0xFFFF）。讲解：一条写指令初始化四个字段。 */
		*(u64 *)&hot->warm_cpus[0] = 0xFFFFFFFFFFFFFFFFULL;
		hot->nvcsw_snapshot    = p->nvcsw;
		hot->task_class        = CAKE_CLASS_NORMAL;
		hot->vtime_mult        = 1024;  /* nice0 baseline (102400/100) */
						/* nice0 基线（102400/100）。讲解：默认权重对应乘子 1024。 */

		hot->dsq_vtime         = cpu_bss[bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1)].vtime_local;
	}

	return 0;
}

/* G1 FIX: .enable callback — initialize task vtime when it becomes schedulable.
 * Like cosmos/bpfland: p->scx.dsq_vtime = vtime_now.
 * For cake, we store in arena (avoids kernel dsq_insert_vtime overwrite). */
/* G1 修复：.enable 回调——任务变为可调度时初始化其 vtime。比如刚刚变成scx, 或者刚刚fork出来
 * 类似 cosmos/bpfland：p->scx.dsq_vtime = vtime_now。
 * cake 则存到 arena（避免被内核 dsq_insert_vtime 覆盖）。
 以当前本地 vtime 为起点，防止新任务优先级畸高。 */
void BPF_STRUCT_OPS(cake_enable, struct task_struct *p)
{
	struct cake_task_hot *hot = get_task_hot(p);
	if (hot)
		hot->dsq_vtime = cpu_bss[bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1)].vtime_local;
}

/* EVENT-DRIVEN AFFINITY UPDATE — telemetry counter only.
 * cached_cpumask field removed: scx_bpf_select_cpu_and handles affinity
 * natively via p->cpus_ptr (Rule 64: A→D path compression).
 * Only the telemetry counter survives for TUI cpumask change tracking. */
/* 事件驱动的亲和性更新——仅遥测计数器。
 * cached_cpumask 字段已移除：scx_bpf_select_cpu_and 经 p->cpus_ptr
 * 原生处理亲和性（规则64：A→D 路径压缩）。
 * 仅保留遥测计数器供 TUI 跟踪 cpumask 变化。亲和性变更时只记一次数供界面观察。 */
void BPF_STRUCT_OPS(cake_set_cpumask, struct task_struct *p __arg_trusted,
		    const struct cpumask *cpumask __arg_trusted)
{
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ENABLED) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx)
			tctx->telemetry.cpumask_change_count++;
	}
#endif
}

/* Handle manual yields (e.g. sched_yield syscall).
 * yield_count is TUI-only telemetry (stats-gated). Game family detection
 * uses PPID matching in cake_stopping, not per-task yield counts.
 * Cost in debug: 1 get_task_ctx (~16ns) per yield. Zero cost in release. */
/* 处理手动让出（如 sched_yield 系统调用）。
基本上就是core -> sched class -> scx这里回调 （其实也是直接计数, 没什么可做的）
 * yield_count 仅供 TUI 遥测（受统计门控）。游戏家族检测在 cake_stopping
 * 中用 PPID 匹配，而非每任务的让出计数。
 * debug 代价：每次让出 1 次 get_task_ctx（约 16ns）。release 下零代价。仅记数，不改变让出行为。 */
bool BPF_STRUCT_OPS(cake_yield, struct task_struct *p)
{
#ifndef CAKE_RELEASE
	/* F3: Gate behind CAKE_STATS_ENABLED — yield_count is TUI-only.
	 * Saves ~16ns get_task_ctx per sched_yield() in release builds. */
	/* F3：放在 CAKE_STATS_ENABLED 门控后——yield_count 仅供 TUI。
	 * release 构建下每次 sched_yield() 省约 16ns 的 get_task_ctx。 */
	if (CAKE_STATS_ACTIVE) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) tctx->telemetry.yield_count++;
	}
#endif
	return false;
}

/* Handle preemption when a task is pushed off the CPU. */
/* 任务被推离 CPU（变为可运行）时的处理。
入队时调用
记录抢占次数与唤醒来源用于唤醒链分析。 */
void BPF_STRUCT_OPS(cake_runnable, struct task_struct *p, u64 enq_flags)
{
#ifndef CAKE_RELEASE
	if (CAKE_STATS_ACTIVE) {
		struct cake_task_ctx __arena *tctx = get_task_ctx(p);
		if (tctx) {
			if (enq_flags & SCX_ENQ_PREEMPT)
				tctx->telemetry.preempt_count++;
			/* Wakeup source: the currently running task is the waker */
			/* 唤醒来源：当前正在运行的任务即唤醒者, 谁唤醒了 p 就记谁。 */
			struct task_struct *waker = bpf_get_current_task_btf();
			if (waker) {
				tctx->telemetry.wakeup_source_pid = waker->pid;
				/* Phase 8: wake chain enhancement */
				/* 阶段8：唤醒链增强。讲解：额外记录唤醒者所在 CPU 与进程组。 */
				tctx->telemetry.waker_cpu = (u16)bpf_get_smp_processor_id();
				tctx->telemetry.waker_tgid = waker->tgid;
			}
		}
	}
#endif
}

/* Free per-task arena storage on task exit. */
/* 任务退出时释放其每任务 arena 存储。回收资源避免泄漏。 */
void BPF_STRUCT_OPS(cake_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	/* Remove from PID→tctx map: removed — iter/task program handles visibility
	 * without explicit cleanup. Task storage freed below. */
	/* 从 PID→tctx 映射移除：已移除——iter/task 程序无需显式清理即可
	 * 提供可见性。task 存储在下方释放。 */
	scx_task_free(p);
}

/* Initialize the scheduler */
/* 初始化调度器。创建各 LLC 的 DSQ 并分配全局 arena 块。 */
s32 BPF_STRUCT_OPS_SLEEPABLE(cake_init)
{
	/* Per-CPU DSQs eliminated — SCX_DSQ_LOCAL_ON dispatches directly to
     * the kernel's built-in local DSQ, skipping dispatch callback entirely.
     * Per-LLC DSQs used for enqueue → dispatch path. */
	/* 每 CPU DSQ 已取消——SCX_DSQ_LOCAL_ON 直接派发到内核内建的
	 * 本地 DSQ，完全跳过 dispatch 回调。
	 * 每 LLC 的 DSQ 用于 enqueue → dispatch 路径。 */
	/* Single vtime-ordered DSQ per LLC.
     * Priority encoded in vtime: (vtime_tier << 56) | timestamp.
     * T0 always dispatches first (lowest vtime). Eliminates 3 empty probes.
     * Single-CCD (9800x3d): 1 DSQ. Multi-CCD: N DSQs (one per LLC).
     * DSQ ID = LLC_DSQ_BASE + llc_index. */
	/* 每 LLC 一个按 vtime 排序的 DSQ。
	 * 优先级编码进 vtime：(vtime_tier << 56) | 时间戳。
	 * T0 总是最先派发（vtime 最小）。消除 3 次空探测。
	 * 单 CCD（9800x3d）：1 个 DSQ。多 CCD：N 个 DSQ（每 LLC 一个）。
	 * DSQ ID = LLC_DSQ_BASE + llc 索引。讲解：用 vtime 高位编码层级，实现优先级与公平并存。 */
	for (u32 i = 0; i < CAKE_MAX_LLCS; i++) {
		if (i >= nr_llcs)
			break;
		s32 ret = scx_bpf_create_dsq(LLC_DSQ_BASE + i, -1);
		if (ret < 0)
			return ret;
	}

	/* Unified per-CPU arena block — conditional sizing.
	 * RELEASE: 64B/CPU × 64 = 4KB = 1 page (CL0 only, all DCE'd)
	 * DEBUG:  128B/CPU × 64 = 8KB = 2 pages (CL0 telemetry + CL1 BenchLab)
	 * Pages rounded up: (CAKE_MBOX_SIZE * CAKE_MAX_CPUS + 4095) / 4096 */
	/* 统一的每 CPU arena 块——按构建条件确定大小。
	 * RELEASE：64B/CPU × 64 = 4KB = 1 页（仅 CL0，其余全被 DCE）
	 * DEBUG：128B/CPU × 64 = 8KB = 2 页（CL0 遥测 + CL1 BenchLab）
	 * 页数向上取整：(CAKE_MBOX_SIZE * CAKE_MAX_CPUS + 4095) / 4096。讲解：release 只留必要一页省内存。 */
#ifdef CAKE_RELEASE
	per_cpu = (struct cake_per_cpu __arena *)bpf_arena_alloc_pages(
		&arena, NULL, 1, NUMA_NO_NODE, 0);
#else
	per_cpu = (struct cake_per_cpu __arena *)bpf_arena_alloc_pages(
		&arena, NULL, 2, NUMA_NO_NODE, 0);
#endif
	if (!per_cpu)
		return -ENOMEM;


	/* Populate per-CPU LLC ID cache from RODATA (Rule 41).
	 * Set once at init — llc_id never changes for a given CPU. */
	/* 从 RODATA 填充每 CPU 的 LLC ID 缓存（规则41）。
	 * 仅在 init 时设置一次——某 CPU 的 llc_id 永不改变。讲解：预缓存拓扑，热路径免查表。 */
	for (u32 i = 0; i < CAKE_MAX_CPUS; i++) {
		if (i >= nr_cpus)
			break;
		cpu_bss[i].llc_id = (u8)cpu_llc_id[i];
	}

	return 0;
}

/* Scheduler exit - record exit info */
/* 调度器退出——记录退出信息。讲解：保存退出原因供加载器打印。 */
void BPF_STRUCT_OPS(cake_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/* ── cake_task_iter: SEC("iter/task") — replaces pid_to_tctx hash map ──
 * Iterates all kernel tasks. For each task managed by cake (tctx != NULL,
 * telemetry.pid != 0), emits a cake_iter_record via bpf_seq_write.
 * Userspace opens the link fd and reads fixed-size records synchronously.
 * Zero overhead in scheduling hot path: never called during scheduling.
 * No init/exit map ops: cake_init_task and cake_exit_task are now lockless.
 *
 * OPT-25: telemetry copy split into noinline batches (Rule 30: group to
 * reduce trampolining). Each batch: 2 args (tctx+rec) = 2 callee-saves,
 * r8-r9 free for temporaries → 0 spills per batch. */
/* ── cake_task_iter：SEC("iter/task")——取代 pid_to_tctx 哈希表 ──
 * 遍历所有内核任务。对每个由 cake 管理的任务（tctx != NULL、
 * telemetry.pid != 0），经 bpf_seq_write 输出一条 cake_iter_record。
 * 用户空间打开 link fd 并同步读取定长记录。
 * 调度热路径零开销：调度期间从不调用它。
 * 无 init/exit 的 map 操作：cake_init_task 与 cake_exit_task 现已无锁。
 *
 * OPT-25：遥测拷贝拆成多个 noinline 批次（规则30：分组以减少跳板）。
 * 每批次：2 个参数（tctx+rec）= 2 个被调用者保存寄存器，
 * r8-r9 空出作临时用 → 每批次 0 溢出。讲解：用迭代器一次性导出所有任务遥测给 TUI。 */

#ifndef CAKE_RELEASE
/* Batch 1: timing fields (u64-heavy, 4 u64s + 3 u32s = ~44 bytes) */
/* 批次1：计时字段（以 u64 为主，4 个 u64 + 3 个 u32 ≈ 44 字节）。 */
static __noinline void iter_copy_timing(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.run_start_ns          = tctx->telemetry.run_start_ns;
	rec->telemetry.run_duration_ns       = tctx->telemetry.run_duration_ns;
	rec->telemetry.enqueue_start_ns      = tctx->telemetry.enqueue_start_ns;
	rec->telemetry.wait_duration_ns      = tctx->telemetry.wait_duration_ns;
	rec->telemetry.select_cpu_duration_ns= tctx->telemetry.select_cpu_duration_ns;
	rec->telemetry.enqueue_duration_ns   = tctx->telemetry.enqueue_duration_ns;
	rec->telemetry.dsq_insert_ns         = tctx->telemetry.dsq_insert_ns;
	rec->telemetry.jitter_accum_ns       = tctx->telemetry.jitter_accum_ns;
	rec->telemetry.stopping_duration_ns  = tctx->telemetry.stopping_duration_ns;
	rec->telemetry.running_duration_ns   = tctx->telemetry.running_duration_ns;
	rec->telemetry.max_runtime_us        = tctx->telemetry.max_runtime_us;
	rec->telemetry._pad4                 = 0;
	rec->telemetry.dispatch_gap_ns       = tctx->telemetry.dispatch_gap_ns;
	rec->telemetry.max_dispatch_gap_ns   = tctx->telemetry.max_dispatch_gap_ns;
}

/* Batch 2: gate hits + counters (all u32/u16 — compact) */
/* 批次2：门命中数 + 各类计数器（均为 u32/u16，紧凑）。讲解：拷贝各门与调度事件计数。 */
static __noinline void iter_copy_gates(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.gate_1_hits           = tctx->telemetry.gate_1_hits;
	rec->telemetry.gate_2_hits           = tctx->telemetry.gate_2_hits;
	rec->telemetry.gate_1w_hits          = tctx->telemetry.gate_1w_hits;
	rec->telemetry.gate_3_hits           = tctx->telemetry.gate_3_hits;
	rec->telemetry.gate_1p_hits          = tctx->telemetry.gate_1p_hits;
	rec->telemetry.gate_1c_hits          = tctx->telemetry.gate_1c_hits;
	rec->telemetry.gate_1cp_hits         = tctx->telemetry.gate_1cp_hits;
	rec->telemetry.gate_1d_hits          = tctx->telemetry.gate_1d_hits;
	rec->telemetry.gate_1wc_hits         = tctx->telemetry.gate_1wc_hits;
	rec->telemetry.gate_tun_hits         = tctx->telemetry.gate_tun_hits;
	rec->telemetry._pad2                 = 0;
	rec->telemetry.total_runs            = tctx->telemetry.total_runs;
	rec->telemetry.core_placement        = tctx->telemetry.core_placement;
	rec->telemetry.migration_count       = tctx->telemetry.migration_count;
	rec->telemetry.preempt_count         = tctx->telemetry.preempt_count;
	rec->telemetry.yield_count           = tctx->telemetry.yield_count;
	rec->telemetry.direct_dispatch_count = tctx->telemetry.direct_dispatch_count;
	rec->telemetry.enqueue_count         = tctx->telemetry.enqueue_count;
	rec->telemetry.cpumask_change_count  = tctx->telemetry.cpumask_change_count;
	rec->telemetry._pad3                 = 0;
}

/* Batch 3: histogram + identity fields */
/* 批次3：直方图 + 身份字段。讲解：拷贝等待分布与 pid/tgid/comm 等标识。 */
static __noinline void iter_copy_hist(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.wait_hist_lt10us      = tctx->telemetry.wait_hist_lt10us;
	rec->telemetry.wait_hist_lt100us     = tctx->telemetry.wait_hist_lt100us;
	rec->telemetry.wait_hist_lt1ms       = tctx->telemetry.wait_hist_lt1ms;
	rec->telemetry.wait_hist_ge1ms       = tctx->telemetry.wait_hist_ge1ms;
	rec->telemetry.slice_util_pct        = tctx->telemetry.slice_util_pct;
	rec->telemetry.llc_id                = tctx->telemetry.llc_id;
	rec->telemetry.same_cpu_streak       = tctx->telemetry.same_cpu_streak;
	rec->telemetry._pad_recomp           = 0;
	rec->telemetry.wakeup_source_pid     = tctx->telemetry.wakeup_source_pid;
	rec->telemetry.nivcsw_snapshot       = tctx->telemetry.nivcsw_snapshot;
	rec->telemetry.nvcsw_delta           = tctx->telemetry.nvcsw_delta;
	rec->telemetry.nivcsw_delta          = tctx->telemetry.nivcsw_delta;
	rec->telemetry.pid_inner             = tctx->telemetry.pid;
	rec->telemetry.tgid                  = tctx->telemetry.tgid;
	/* comm: 16 bytes as two u64 reads via arena cast */
	/* comm：经 arena 强转，用两次 u64 读取共 16 字节。讲解：进程名批量拷贝更快。 */
	*((__u64 *)&rec->telemetry.comm[0]) = *((__u64 __arena *)&tctx->telemetry.comm[0]);
	*((__u64 *)&rec->telemetry.comm[8]) = *((__u64 __arena *)&tctx->telemetry.comm[8]);
}

/* 
tui遍历cake任务时调用
Batch 4: enqueue substage timing + quantum + waker + per-CPU run counts */
/* 批次4：入队子阶段计时 + 量子 + 唤醒者 + 每 CPU 运行次数 */
static __noinline void iter_copy_substage(
	struct cake_task_ctx __arena *tctx,
	struct cake_iter_record *rec)
{
	rec->telemetry.gate_cascade_ns       = tctx->telemetry.gate_cascade_ns;
	rec->telemetry.idle_probe_ns         = tctx->telemetry.idle_probe_ns;
	rec->telemetry.vtime_compute_ns      = tctx->telemetry.vtime_compute_ns;
	rec->telemetry.mbox_staging_ns       = tctx->telemetry.mbox_staging_ns;
	rec->telemetry._pad_ewma             = 0;
	rec->telemetry.classify_ns           = tctx->telemetry.classify_ns;
	rec->telemetry.vtime_staging_ns      = tctx->telemetry.vtime_staging_ns;
	rec->telemetry.warm_history_ns       = tctx->telemetry.warm_history_ns;
	rec->telemetry.quantum_full_count    = tctx->telemetry.quantum_full_count;
	rec->telemetry.quantum_yield_count   = tctx->telemetry.quantum_yield_count;
	rec->telemetry.quantum_preempt_count = tctx->telemetry.quantum_preempt_count;
	rec->telemetry._pad_quantum          = 0;
	rec->telemetry.waker_cpu             = tctx->telemetry.waker_cpu;
	rec->telemetry._pad_waker            = 0;
	rec->telemetry.waker_tgid            = tctx->telemetry.waker_tgid;
	/* cpu_run_count: per-element arena reads */
	/* cpu_run_count：逐元素的 arena 读取。讲解：数组无法整块拷贝，只能逐个搬。 */
	for (int _ci = 0; _ci < CAKE_TELEM_MAX_CPUS; _ci++)
		rec->telemetry.cpu_run_count[_ci] = tctx->telemetry.cpu_run_count[_ci];
}
#endif /* !CAKE_RELEASE */

/* 挂载在 iter/task 钩子上。它的作用是让用户态可以通过读取一个 fd
（类似读文件）来批量遍历所有任务，每个任务调用一次这个函数，把信息序列化输出。
================
tui用它获取cake 任务 */
SEC("iter/task")
int cake_task_iter(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	if (!task)
		return 0;

	/* Only emit tasks managed by this scheduler instance. */
	/* 仅输出由本调度器实例管理的任务。讲解：过滤掉无 tctx 的无关任务。 */
	struct cake_task_ctx __arena *tctx = get_task_ctx(task);
#ifndef CAKE_RELEASE
	if (!tctx || !tctx->telemetry.pid)
		return 0;
#else
	if (!tctx)
		return 0;
#endif

	/* Build iter record from arena tctx data.
	 * Zero-init: in release builds, telemetry block is skipped —
	 * without this, bpf_seq_write emits stack garbage. */
	/* 从 arena 的 tctx 数据构建 iter 记录。
	 * 零初始化：release 构建会跳过遥测块——若不清零，
	 * bpf_seq_write 会输出栈上垃圾数据。讲解：{} 确保未填字段为 0。 */
	struct cake_iter_record rec = {};
	rec.pid         = task->pid;
	rec.ppid        = tctx->ppid;
	rec.packed_info = tctx->packed_info;
	rec.pelt_util = (u16)task->se.avg.util_avg;
	rec.deficit_us     = tctx->deficit_u16;
	rec.vtime_mult     = tctx->vtime_mult;

#ifndef CAKE_RELEASE
	/* Telemetry: batched noinline copies → 0 spills per batch.
	 * Each batch: 2 args (tctx+rec) = 2 callee-saves. */
	/* 遥测：分批次的 noinline 拷贝 → 每批次 0 溢出。
	 * 每批次：2 个参数（tctx+rec）= 2 个被调用者保存寄存器。 */
	iter_copy_timing(tctx, &rec);
	iter_copy_gates(tctx, &rec);
	iter_copy_hist(tctx, &rec);
	iter_copy_substage(tctx, &rec);
#endif

	bpf_seq_write(seq, &rec, sizeof(rec));
	return 0;
}

/* F3 FIX: Tick callback for cross-LLC load balance hinting.
 * Runs once per tick (~1ms) per CPU. Throttled to every 8th tick (~8ms)
 * to minimize overhead. On single-CCD (nr_llcs==1), JIT eliminates
 * the entire function body (RODATA constant fold).
 *
 * Kernel source truth (ext.c:2798-2817): task_tick_scx() calls this
 * AFTER update_curr_scx() has already decremented p->scx.slice.
 * Slice enforcement is FREE — we only use this for load balance hinting.
 *
 * Algorithm: if my LLC's DSQ has 2+ tasks queued AND another LLC's DSQ
 * is empty, kick one of that LLC's CPUs to trigger cross-LLC steal.
 * This turns passive "discover work on idle" into proactive "notify idle". */
/* F3 修复：用于跨 LLC 负载均衡提示的 tick 回调。
 * 每 CPU 每 tick（约 1ms）运行一次。节流到每 8 个 tick（约 8ms）
 * 才执行以尽量降低开销。单 CCD（nr_llcs==1）时 JIT 会消除
 * 整个函数体（RODATA 常量折叠）。
 *
 * 内核源码事实（ext.c:2798-2817）：task_tick_scx() 在 update_curr_scx()
 * 已递减 p->scx.slice 之后才调用本回调。
 * 时间片强制执行是“免费”的——我们只用它做负载均衡提示。
 *
 * 算法：若本 LLC 的 DSQ 排了 2 个以上任务，而另一 LLC 的 DSQ 为空，
 * 就踢那个 LLC 的某个 CPU 以触发跨 LLC 窃取。
 * 这把被动的“空闲时自己找活”变为主动的“通知空闲者”。多 CCD 下主动均衡，单 CCD 下整段被优化掉。 */
void BPF_STRUCT_OPS(cake_tick, struct task_struct *p)
{
	/* Single-LLC: nothing to balance. JIT dead-code eliminates. */
	/* 单 LLC：无需均衡 */
	if (nr_llcs <= 1)
		return;

	/* Throttle: only check every 8th tick (~8ms) to minimize overhead.
	 * 1ms per-tick × 8 = 8ms period. Cost on fast path: 1 byte load + AND.
	 * tick_count wraps at 255 — no concern, only low 3 bits matter. */
	/* 节流：每 8 个 tick（约 8ms）才检查一次以降低开销。
	 * 每 tick 1ms × 8 = 8ms 周期。快路径代价：1 字节读取 + 与运算。
	 * tick_count 在 255 处回绕——无妨，只关心低 3 位。讲解：低频检查避免过度均衡。 */
	u32 cpu = bpf_get_smp_processor_id() & (CAKE_MAX_CPUS - 1);
	cpu_bss[cpu].tick_count++;
	if (cpu_bss[cpu].tick_count & 7)
		return;

	/* Check my LLC's DSQ depth — only rebalance when overloaded */
	/* 检查本 LLC 的 DSQ 深度——仅在过载时才均衡。 */
	u32 my_llc = cpu_bss[cpu].llc_id;  /* per-CPU cache (Rule 41) */
	s32 my_depth = scx_bpf_dsq_nr_queued(LLC_DSQ_BASE + my_llc);
	if (my_depth < 2)
		return;

	/* Find an empty LLC and kick one of its CPUs to trigger steal.
	 * Round-robin from my_llc+1 to avoid always kicking the same LLC.
	 * llc_cpu_mask[] is RODATA — zero cache bounce on read. */
	/* 找一个空 LLC 并kick它的某个 CPU 以触发窃取。
	 * 从 my_llc+1 开始轮转，避免总是踢同一个 LLC。
	 * llc_cpu_mask[] 是 RODATA——读取零缓存弹跳 */
	for (u32 i = 1; i < CAKE_MAX_LLCS && i < nr_llcs; i++) {
		u32 other = (my_llc + i);
		if (other >= nr_llcs) other -= nr_llcs;
		s32 other_depth = scx_bpf_dsq_nr_queued(LLC_DSQ_BASE + other);
		if (other_depth == 0) {
			u64 mask = llc_cpu_mask[other];
			if (mask) {
				/* 从掩码里面找到第一个空闲 */
				u32 target = __builtin_ctzll(mask);
				if (target < nr_cpus)
					scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
			}
			break;
		}
	}
}

/* F6 FIX: Cgroup weight callback — enables framework weight propagation.
 * The kernel calls this when p->scx.weight changes via cgroup or nice.
 * No-op: actual weight application happens in cake_stopping via F4's
 * multiplicative scaling (102400 / p->scx.weight). Registering this
 * callback signals to the framework that cake is weight-aware. */
/* F6 修复：cgroup 权重回调——启用框架的权重传播。
 * 当 p->scx.weight 因 cgroup 或 nice 变化时内核会调用它。
 * 空操作：实际的权重应用发生在 cake_stopping 中，经 F4 的
 * 乘法缩放（102400 / p->scx.weight）完成。注册此回调是向框架
 * 表明 cake 是“感知权重”的。仅作声明，实际换算在停止回调里做。 */
void BPF_STRUCT_OPS(cake_set_weight, struct task_struct *p, u32 weight)
{
	/* Weight already stored in p->scx.weight by kernel.
	 * F4 reads it in cake_stopping. Nothing to do here. */
	/* 权重已由内核存入 p->scx.weight。
	 * F4 在 cake_stopping 中读取它。此处无需任何操作。 */
}

/* 注册 sched_ext 操作表：把上面各回调绑定到调度框架的对应钩子。 */
SCX_OPS_DEFINE(cake_ops, .select_cpu = (void *)cake_select_cpu,
	       .enqueue	 = (void *)cake_enqueue,
	       .dispatch = (void *)cake_dispatch,
	       .tick         = (void *)cake_tick,
	       .running	    = (void *)cake_running,
	       .stopping    = (void *)cake_stopping,
	       .yield = (void *)cake_yield,
	       .runnable = (void *)cake_runnable,
	       .set_weight   = (void *)cake_set_weight,
	       .enable       = (void *)cake_enable,
	       .set_cpumask = (void *)cake_set_cpumask,
	       .init_task   = (void *)cake_init_task,
	       .exit_task = (void *)cake_exit_task, .init = (void *)cake_init,
	       .exit = (void *)cake_exit, .flags = SCX_OPS_KEEP_BUILTIN_IDLE,
	       .timeout_ms = 5000, /* G2 FIX: starvation watchdog — matches cosmos/bpfland */
				   /* G2 修复：饥饿看门狗——与 cosmos/bpfland 一致。5 秒无进展则内核回退。 */
	       .name = "cake");
