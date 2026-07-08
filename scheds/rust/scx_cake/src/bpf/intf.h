/* SPDX-License-Identifier: GPL-2.0 */
/* scx_cake BPF/userspace interface - shared data structures and constants */
/* scx_cake 的 BPF 与用户态接口——共享的数据结构与常量定义。 */
/* 这个头文件同时被 BPF 内核侧和 Rust 用户态侧包含，保证两边的内存布局完全一致。 */

#ifndef __CAKE_INTF_H
#define __CAKE_INTF_H

#include <limits.h>

/* Type defs for BPF/userspace compat - defined when vmlinux.h is not included */
/* 为 BPF/用户态兼容定义的类型别名——仅在未包含 vmlinux.h 时生效。 */
/* BPF 侧包含 vmlinux.h 时已有这些类型，用户态编译时则需要在此手动定义。 */
#ifndef __VMLINUX_H__
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long  u64;

typedef signed char    s8;
typedef signed short   s16;
typedef signed int     s32;
typedef signed long    s64;
#endif

/* CAKE TIER SYSTEM — 4-tier classification
 *
 * Tiers group tasks with similar scheduling needs. Classification uses
 * kernel PELT util_avg (0-1024). DRR++ deficit handles intra-tier
 * fairness (yield vs preempt). */
/* CAKE 分层系统——4 层分类。
 *
 * 分层把调度需求相近的任务归为一组。分类依据内核 PELT util_avg（0-1024）；
 * 层内公平（让出 vs 抢占）则由 DRR++ 的赤字机制处理。 */
/* 借鉴网络 CAKE 的思路，把任务按延迟敏感度分成 4 层，越靠前的层调度优先级越高。 */
enum cake_tier {
	CAKE_TIER_CRITICAL = 0, /* <100µs:  IRQ, input, audio, network */
				/* 关键层：<100µs，如中断、输入、音频、网络。讲解：延迟最敏感，必须最快响应。 */
	CAKE_TIER_INTERACT = 1, /* <2ms:    compositor, physics, AI */
				/* 交互层：<2ms，如合成器、物理、AI。讲解：影响交互流畅度，次高优先级。 */
	CAKE_TIER_FRAME	   = 2, /* <8ms:    game render, encoding */
				/* 帧层：<8ms，如游戏渲染、编码。讲解：对应一帧的时间预算。 */
	CAKE_TIER_BULK	   = 3, /* ≥8ms:    compilation, background */
				/* 批处理层：≥8ms，如编译、后台任务。讲解：吞吐型任务，优先级最低。 */
	CAKE_TIER_MAX	   = 4,
				/* 层数上限（哨兵值）。用于数组维度和边界判断。 */
};

/* ═══ TASK CLASS — Pre-stamped by userspace classifier (Phase 2) ═══
 * Replaces per-stop is_game/is_hog/bg_noise computation in BPF stopping.
 * Written by Rust classifier (60Hz), read by BPF stopping+enqueue.
 * Eliminates BSS game_tgid/game_ppid MESI-S reads from hot path (~5ns). */
/* ═══ 任务类别——由用户态分类器预先打标（阶段 2） ═══
 * 取代了原先在 BPF stopping 中每次都要计算的 is_game/is_hog/bg_noise。
 * 由 Rust 分类器以 60Hz 写入，由 BPF 的 stopping+enqueue 读取。
 * 从而在热路径上省去对 BSS game_tgid/game_ppid 的 MESI-S 读取（约 5ns）。 */
/* 把耗时的分类计算挪到用户态低频完成，BPF 侧只读结果，大幅降低热路径开销。 */
enum cake_class {
	CAKE_CLASS_NORMAL  = 0, /* Default: no squeeze, no boost */
				/* 普通类：默认，既不压制也不加速。桌面交互任务的基线类别。 */
	CAKE_CLASS_GAME    = 1, /* Game family: tgid/ppid match + kthread(gaming) */
				/* 游戏家族类：tgid/ppid 匹配 + 游戏相关内核线程。享受最高调度优先级。 */
	CAKE_CLASS_HOG     = 2, /* BULK + squeeze: 4× vtime penalty */
				/* 资源大户类：批处理 + 压制，vtime 惩罚 4 倍。CPU 消耗比较多的，延后调度。 */
	CAKE_CLASS_BG      = 3, /* Background noise: 2× vtime penalty */
				/* 后台噪声类：vtime 惩罚 2 倍。低利用率后台任务，游戏时被降权。 */
	CAKE_CLASS_MAX     = 4,
				/* 类别数上限（哨兵值）。用于数组维度和范围校验。 */
};

/* ═══ TASK HOT FIELDS — bpf_task_storage (Phase 6) ═══
 * Mirrors Arena CL0 but lives in kernel task_storage (~10ns lookup
 * vs 29ns arena TLB walk). All release-mode hot fields live here.
 * Arena CL0 is only used for telemetry (stats_on gated, dead in release).
 *
 * Accessed by: cake_running, cake_stopping, cake_select_cpu, cake_enqueue.
 * Allocated in: cake_init_task (BPF_NOEXIST → creates on first alloc). */
/* ═══ 任务热字段——bpf_task_storage（阶段 6） ═══
 * 与 Arena 的 CL0 内容对应，但存放在内核 task_storage 中（查找约 10ns，
 * 而 arena 需 29ns 的 TLB 遍历）。release模式下所有热字段都放在这里。
 * Arena 的 CL0 仅用于遥测（受 stats_on 控制，release版中被裁掉）。
 *
 * 访问者：cake_running、cake_stopping、cake_select_cpu、cake_enqueue。
 * 分配处：cake_init_task（BPF_NOEXIST → 首次分配时创建）。 */
/* 把最常访问的调度字段放进查找更快的 task_storage，避免每次都走慢速 arena。 */
struct cake_task_hot {
	u64 staged_vtime_bits; /* 8B: VALID|HOME|WB|WB_DUP|NF|weight */
			       /* 8字节：暂存的 vtime 位域（有效位|归属CPU|唤醒提升|重复提升|新流|权重）。由 stopping 预打包，enqueue 直接取用。 */
	u16 deficit_u16;       /* 2B: DRR deficit (drain from slice delta) */
			       /* 2字节：DRR 赤字（按时间片增量消耗）。DRR++ 公平算法的核心配额。 */
	u16 wake_counter;      /* 2B: EWMA wakeup frequency (0–1023), higher=more critical */
			       /* 2字节：唤醒频率的 EWMA（0–1023），越高越关键。频繁唤醒常意味着延迟敏感。会考虑进程被唤醒的次数 */
	u32 packed_info;       /* 4B: flags + tier + flow_id */
			       /* 4字节：标志位 + 层级 + 流ID 的打包字段。把多字段编码进一个 u32，减少内存访问。 */
	u32 ppid;              /* 4B: Parent PID (game family detection) */
			       /* 4字节：父进程 PID（用于游戏家族识别）。靠父进程匹配把整族进程归为 GAME。 */
	u32 last_run_at;       /* 4B: (u32)scx_bpf_now() from stopping */
			       /* 4字节：stopping 时记录的 (u32)scx_bpf_now()。用于计算运行间隔与防饿死。 */
	u32 reclass_counter;   /* 4B: Per-task stop counter */
			       /* 4字节：每任务的 stop 计数器。每 64 次才重新分类。stop counter是什么? */
	u16 warm_cpus[3];      /* 6B: [0]=current, [1]=home, [2]=oldest */
			       /* 6字节：热点CPU历史 [0]=当前 [1]=归属 [2]=最旧。用于缓存亲和的 CPU 选择。 */
	u16 waker_cpu;         /* 2B: CPU where waker last ran */
			       /* 2字节：唤醒者上次运行的 CPU。把被唤醒任务放到唤醒者附近以获得缓存局部性。 */
	u64 nvcsw_snapshot;    /* 8B: Last nvcsw for yield detection */
			       /* 8字节：上次的自愿上下文切换计数快照。与当前值比较即可判断任务是否让出。 */
	u8  task_class;        /* 1B: CAKE_CLASS_* enum */
			       /* 1字节：CAKE_CLASS_* 类别枚举。由用户态分类器写入的最终类别。 */
	u8  _pad_hot;          /* 1B: alignment */
			       /* 1字节：对齐填充。保证后续字段按对齐边界排列。 */
	u16 vtime_mult;        /* 2B: EEVDF vtime reciprocal (102400/weight, 1024=nice0) */
			       /* 2字节：EEVDF vtime 倒数系数（102400/weight，1024=nice0）。把 nice 权重换算成 vtime 缩放因子。 */
	/* cached_cpumask REMOVED: after scx_bpf_select_cpu_and refactor,
	 * kernel handles affinity via p->cpus_ptr natively. 0 read sites. */
	/* cached_cpumask 已移除：在改用 scx_bpf_select_cpu_and 后，
	 * 亲和性由内核经 p->cpus_ptr 原生处理，已无任何读取点。 */
	/* 重构后不再需要自缓存 CPU 掩码，减小了结构体并省去维护成本。 */
	u64 dsq_vtime;         /* 8B: G1+G4: EEVDF intra-tier vruntime (arena, no kernel overwrite) */
			       /* 8字节：EEVDF 层内虚拟运行时（自管理，内核不覆盖）。决定同层任务的先后顺序。 */
}; /* Total: 64B (1 cache line) */


/* ═══ PER-CPU BSS — Arena-free running (Phase 5) ═══
 * Written by cake_running (local CPU only), read by:
 *   - cake_stopping (same CPU, L1 hit)
 *   - Gate 1P/1C-P (remote CPU, MESI-S → L3 hit)
 *
 * 64-byte aligned — one cache line per CPU.
 * SAFETY:
 *   - No false sharing: each CPU owns its own 64B line.
 *   - No atomics needed: single-writer (local running), multi-reader.
 *   - MESI-S for remote reads: same cost as current arena mbox reads.
 *   - stopping bridges BSS→arena mbox for consumers that still read mbox. */
/* ═══ 每CPU BSS——不依赖 arena 的运行态存储（阶段 5） ═══
热点数据不放arena里面, 避免性能开销?
 * 由 cake_running 写入（仅本地 CPU），读取方：
 *   - cake_stopping（同一 CPU，命中 L1）
 *   - Gate 1P/1C-P（远端 CPU，MESI-S → 命中 L3）
 *
 * 64 字节对齐——每个 CPU 独占一条缓存行。
 * 安全性：
 *   - 无伪共享：每个 CPU 拥有自己的 64B 行。
 *   - 无需原子操作：单写者（本地 running）、多读者。
 *   - 远端读走 MESI-S：与现有 arena 邮箱读取代价相同。
 *   - stopping 会把 BSS 桥接到 arena 邮箱，兼容仍读邮箱的消费者。 */
/* 把每 CPU 的热状态放进独占缓存行的 BSS，单写多读且无锁，避免跨核缓存抖动。 */
struct cake_cpu_bss {
	u32 run_start;          /* 4B  off  0: (u32)scx_bpf_now() when task started */
				/* 4字节 偏移0：任务开始运行时的 (u32)scx_bpf_now()。用于计算已运行时长。 */
	u8  is_yielder;         /* 1B  off  4: task_class-derived yielder + waker_boost */
				/* 1字节 偏移4：由类别推导的让出者标志 + 唤醒提升。让出者可享更宽松的时间片。 */
	u8  idle_hint;          /* 1B  off  5: 0=busy, 1=idle */
				/* 1字节 偏移5：空闲提示，0=忙 1=空闲。供选核时快速判断该 CPU 是否空闲。 */
	u8  tick_count;         /* 1B  off  6: cake_tick throttle counter */
				/* 1字节 偏移6：cake_tick 的节流计数器。限制 tick 相关逻辑的执行频率。 */
	u8  llc_id;             /* 1B  off  7: per-CPU LLC ID cache (Rule 41).
				 *     Populated once at init from cpu_llc_id RODATA.
				 *     Eliminates indexed RODATA load for local-CPU
				 *     LLC lookups in dispatch/tick/telemetry. */
				/* 1字节 偏移7：每CPU 的 LLC ID 缓存（规则41）。
				 *     初始化时从 cpu_llc_id RODATA 填入一次。
				 *     省去 dispatch/tick/telemetry 中对本地 CPU LLC 的带下标 RODATA 加载。
				 *     把常用的本地 LLC 归属缓存下来，减少间接寻址。 */
	u64 tick_slice;         /* 8B  off  8: p->scx.slice ?: quantum_ns */
				/* 8字节 偏移8：p->scx.slice，若为0则取 quantum_ns。当前任务的时间片长度。 */
	u64 vtime_local;        /* 8B  off 16: per-CPU vtime_now — eliminates
				 *     cross-core cache line bouncing. Each CPU
				 *     advances its own monotonic max (Rule 8). */
				/* 8字节 偏移16：每CPU 的 vtime_now——消除跨核缓存行抖动。
				 *     每个 CPU 各自推进自己的单调递增最大值（规则8）。
				 *     本地维护虚拟时钟，避免全局 vtime 造成的缓存争用。 */
	u32 last_pid;           /* 4B  off 24: Fast path — skip get_task_hot if same pid */
				/* 4字节 偏移24：快速路径——若 pid 相同则跳过 get_task_hot。连续运行同一任务时省一次查找。 */
	u8  sched_state_local;  /* 1B  off 28: per-CPU sched_state snapshot (Rule 78).
				 *     Updated by Rust TUI on state transitions.
				 *     Eliminates remote global BSS cache line
				 *     fetch at 5 hot-path sites. */
				/* 1字节 偏移28：每CPU 的 sched_state 快照（规则78）。
				 *     由 Rust TUI 在状态切换时更新, 省去 5 处热路径对全局 BSS 缓存行的远端读取。
				 *     把全局调度状态复制到本地行，读它时不再触发跨核同步。 */
	u8  _reserved[3];       /* 3B  off 29: available for future use */
				/* 3字节 偏移29：预留待用。*/
	u64 cached_now;         /* 8B  off 32: scx_bpf_now() from select_cpu tunnel */
				/* 8字节 偏移32：select_cpu“隧道”缓存的 scx_bpf_now()。enqueue 复用该值可以省一次 kfunc 调用。 */
	u8  _pad[88];           /* 88B off 40: pad to 128B (V-Cache sector) */
				/* 88字节 偏移40：填充至 128B（V-Cache 扇区大小）。为啥对齐大128B? */
} __attribute__((aligned(128)));
/* 128B alignment (Rule 15): 9800X3D V-Cache uses 128B sectors.
 * At 64B, adjacent CPUs shared one sector — writes to CPU N's vtime_local
 * invalidated CPU N+1's idle_hint in L3. Each CPU now owns its sector. */
/* 128B 对齐（规则15）：9800X3D 的 V-Cache 使用 128B 扇区。
 * 若只对齐 64B，相邻 CPU 会共享同一扇区——CPU N 写 vtime_local 会使
 * CPU N+1 在 L3 中的 idle_hint 失效。现在每个 CPU 独占一个扇区。 */
/* 按硬件扇区粒度对齐，彻底杜绝跨 CPU 的伪共享导致的缓存失效。
那其他型号cpu呢? */

/* Global bitmask: bit N set = CPU N is running a GAME task.
 * Written atomically in cake_running, read in cake_enqueue.
 * find-victim = __builtin_ctzll(~game_cpu_mask & online_mask)
 * = single tzcnt instruction on Zen 4 (1-cycle latency). */
/* 全局位掩码：第 N 位置 1 表示 CPU N 正在运行 GAME 任务。
 * 在 cake_running 中原子写入，在 cake_enqueue 中读取。
 * 寻找抢占目标 = __builtin_ctzll(~game_cpu_mask & online_mask)
 * = 在 Zen 4 上一条 tzcnt 指令（1 个周期延迟）。 */
/* 用位掩码 + 取反后数末尾零，O(1) 找到一个正跑非游戏任务的 CPU 作为抢占目标。 */

#define CAKE_MAX_CPUS 256
			/* 支持的最大 CPU 数。决定各类每CPU数组的静态维度。 */
#define CAKE_TELEM_MAX_CPUS 64  /* Telemetry-only: cpu_run_count histogram dimension */
				/* 仅用于遥测：cpu_run_count 直方图的维度。限制每任务 CPU 分布统计的规模。 */
#define CAKE_MAX_LLCS 8
			/* 支持的最大 LLC（末级缓存/CCD）数量。决定每 LLC DSQ 及掩码数组的规模。 */
#define CAKE_MAX_AUDIO_TGIDS 8       /* Max tracked audio daemon TGIDs (RODATA) */
				     /* 最多跟踪的音频守护进程 TGID 数（RODATA）。游戏时把音频进程提升到 GAME 优先级。 */
#define CAKE_MAX_COMPOSITOR_TGIDS 4  /* Max tracked compositor TGIDs (RODATA) */
				     /* 最多跟踪的合成器 TGID 数（RODATA）。游戏时保证合成器与游戏线程延迟对等。 */

/* Per-LLC DSQ base — DSQ IDs are LLC_DSQ_BASE + llc_index (0..nr_llcs-1).
 * V3: Single vtime-ordered DSQ per LLC. Priority encoded in vtime:
 * (vtime_tier << 56) | timestamp. T0 always has lowest vtime → dispatches
 * first. Eliminates 3 empty-DSQ probes vs old 4-tier split. */
/* 每 LLC 的 DSQ 基址——DSQ ID = LLC_DSQ_BASE + llc_index（0..nr_llcs-1）。
 * V3：每个 LLC 只用一个按 vtime 排序的 DSQ。优先级编码进 vtime：
 * (vtime_tier << 56) | 时间戳。T0 层永远 vtime 最小 → 最先派发。
 * 相比旧的 4 层拆分，省去了 3 次空 DSQ 探测。 */
/* 把“层级优先级”编码进 vtime 高位，用单队列排序即可实现严格分层，简化派发逻辑。 */
#define LLC_DSQ_BASE 200
		     /* DSQ ID 的起始基址。低号段留给内核内置 DSQ，200 起分配自定义队列避免冲突。 */

/* ── dsq_vtime STAGED BIT LAYOUT (Rule 54: no magic positions) ──
 * Written by cake_stopping, read by cake_running + cake_select_cpu.
 *   [63]       = VALID (set once context exists)
 *   [62:55]    = HOME_CPU (warm_cpus[1] & 0xFF, prev home)
 *   [53]       = BG_NOISE (non-game, non-wb, non-kernel squeeze)
 *   [52]       = WAKER_BOOST (propagated via waker chain)
 *   [51]       = GAME_MEMBER (tgid match)
 *   [50]       = HOG (BULK tier + non-boosted)
 *   [49]       = WAKER_BOOST_DUP (Gate 1P — was VCSW yielder)
 *   [48]       = NEW_FLOW (first enqueue after init)
 *   [31:0]     = DSQ_WEIGHT (dsq_weight: tier_base + pelt_scaled, or inverted PELT for GAME during GAMING) */
/* ── dsq_vtime 暂存位布局, 不使用魔法位置 ──
 * 由 cake_stopping 写入，由 cake_running + cake_select_cpu 读取。
 *   [63]     = VALID（上下文已存在时置位）
 *   [62:55]  = HOME_CPU（warm_cpus[1] & 0xFF，上一个归属 CPU）
 *   [53]     = BG_NOISE（非游戏、非唤醒提升、非内核线程的压制）
 *   [52]     = WAKER_BOOST（经唤醒链传播的提升）
 *   [51]     = GAME_MEMBER（tgid 匹配游戏进程）
 *   [50]     = HOG（BULK 层且未被提升）
 *   [49]     = WAKER_BOOST_DUP（Gate 1P——曾是自愿切换的让出者）
 *   [48]     = NEW_FLOW（初始化后首次入队）
 *   [31:0]   = DSQ_WEIGHT（派发权重：层基值 + PELT 缩放；游戏中的 GAME 则用反相 PELT） */
/* 把多种调度提示打包进一个 u64，stopping 预算好、enqueue 直接取，避免热路径重复计算。
下面这几个是进程的flag? */
#define STAGED_BIT_VALID        63
				/* 有效位。讲解：置位表示该暂存数据已由 stopping 填好、可被使用。 */
#define STAGED_SHIFT_HOME       55
				/* 归属 CPU 字段的起始位移。把上次归属 CPU 存高位，供缓存亲和选核。 */
#define STAGED_BIT_BG_NOISE     53  /* Background noise squeeze */
				    /* 后台噪声压制位。标记该任务应被降权处理。 */
#define STAGED_BIT_WAKER_BOOST  52
				/* 唤醒提升位。被游戏线程唤醒的任务临时继承游戏优先级。 */
#define STAGED_BIT_GAME_MEMBER  51
				/* 游戏成员位。标识属于游戏进程家族，享 VIP 抢占阈值。 */
#define STAGED_BIT_HOG          50
				/* 资源大户位。批处理层且未被提升的任务，抢占保护最弱。 */
#define STAGED_BIT_WB_DUP       49  /* Gate 1P: waker_boost duplicate */
				    /* 唤醒提升副本位（Gate 1P）。记录曾为自愿让出者，用于抢占决策。 */
#define STAGED_BIT_NEW_FLOW     48
				/* 新流位。新唤醒任务享受新流赤字加成，抢先入队一次。 */

/* ── Kfunc BenchLab: extensible per-kfunc stopwatch ──
 * Each kfunc gets a slot. Run N iterations, capture min/max/avg + return value.
 * Triggered from TUI via bench_request BSS variable. */
/* ── Kfunc BenchLab：可扩展的逐 kfunc 计时器 ──
 * 每个 kfunc 占一个槽位。运行 N 次迭代，记录最小/最大/平均值 + 返回值。
 * 通过 BSS 变量 bench_request 由 TUI 触发。 */
/* 这是一套内核内微基准，用于测量各调度原语（kfunc、内存访问等）的真实纳秒开销。 */
#define BENCH_ITERATIONS 8
			  /* 每项基准的迭代次数。讲解：多次取样以便计算最小/平均/百分位。 */

			  /* 能不能把下面也理解为cake声明了自己使用的kfunc? */
enum kfunc_bench_id {
	/* ── Existing entries (0–23) ── */
	/* ── 已有条目（0–23） ── */
	/* 以下每个枚举对应一项被测操作，注释标明其测量目标。 */
	BENCH_KTIME_GET_NS       = 0, /* bpf_ktime_get_ns() */
				      /* 测量 bpf_ktime_get_ns()。常规单调纳秒时钟的取时开销。 */
	BENCH_SCX_BPF_NOW        = 1, /* scx_bpf_now() */
				      /* 测量 scx_bpf_now()。sched_ext 优化过的取时 kfunc。 */
	BENCH_GET_SMP_PROC_ID    = 2, /* bpf_get_smp_processor_id() */
				      /* 测量取当前 CPU 号,热路径常用，需知其成本。 */
	BENCH_TASK_FROM_PID      = 3, /* bpf_task_from_pid() */
				      /* 测量由 pid 反查 task。涉及查表，相对较慢。 */
	BENCH_TEST_CLEAR_IDLE    = 4, /* scx_bpf_test_and_clear_cpu_idle() */
				      /* 测量“测试并清除 CPU 空闲位”。Gate 1 选核的核心原子操作。 */
	BENCH_NR_CPU_IDS         = 5, /* scx_bpf_nr_cpu_ids() */
				      /* 测量取 CPU 总数。对比 RODATA 常量方式的开销。 */
	BENCH_GET_TASK_CTX       = 6, /* get_task_ctx() → arena deref */
				      /* 测量取任务 ctx（arena 解引用）。反映 arena 访问的 TLB 成本。
					  任务ctx存放内容? */
	BENCH_DSQ_NR_QUEUED      = 7, /* scx_bpf_dsq_nr_queued() */
				      /* 测量查询 DSQ 排队数。派发决策时会读它。 */
	BENCH_BSS_ARRAY_ACCESS   = 8, /* Raw BSS global_stats[cpu] access */
				      /* 测量裸 BSS 数组访问。最快的全局数据读取方式基线。 */
	BENCH_ARENA_DEREF        = 9, /* Arena per_cpu[cpu].mbox field read */
				      /* 测量 arena 每CPU mailbox 字段读取。与 BSS 访问对比成本。 */
	BENCH_NOW_PAIR           = 10, /* Back-to-back scx_bpf_now() pair (calibration) */
				       /* 测量连续两次 scx_bpf_now()。用于扣除计时自身开销的校准。 */
	BENCH_MBOX_CPU_READ      = 11, /* Read cached CPU from mailbox CL0 (alternative) */
				       /* 从邮箱 CL0 读缓存 CPU 号（替代方案）。对比 kfunc 取 CPU 的省时程度。 */
	BENCH_TCTX_FROM_MBOX     = 12, /* Read cached tctx ptr from mailbox CL0 (alternative) */
				       /* 从邮箱 CL0 读缓存的 tctx 指针。省去重复的 arena 查找。 */
	BENCH_RINGBUF_CYCLE      = 13, /* bpf_ringbuf_reserve + discard cycle */
				       /* 测量 ringbuf 预留+丢弃一轮。评估 ringbuf 通信的固有成本。 */
	BENCH_TASK_STRUCT_READ   = 14, /* p->scx.slice + p->nvcsw (task_struct fields) */
				       /* 读取 task_struct 字段。热路径直接读内核任务字段的代价。 */
	BENCH_RODATA_LOOKUP      = 15, /* cpu_llc_id[cpu] + tier_slice_ns[tier] RODATA */
				       /* 读取 RODATA 表项。只读常量数组访问，通常极快。这个也有开销吗? */
	BENCH_BITFLAG_OPS        = 16, /* Shift+mask+branchless yielder pattern */
				       /* 测量位移+掩码的无分支让出者判断。验证无分支写法的高效性。 */
	BENCH_RESERVED_17        = 17, /* (was compute_ewma — removed in PELT transition) */
				       /* 预留（原 compute_ewma，转向 PELT 后移除）。占位以保持枚举编号稳定。 */
	BENCH_PSYCHIC_HIT_SIM    = 18, /* Psychic cache pointer compare + fused read */
				       /* 模拟“预知缓存”指针比较+融合读。评估指针命中快速路径。 */
	BENCH_IDLE_REMOTE        = 19, /* scx_bpf_test_and_clear_cpu_idle(sibling) — cross-CPU */
				       /* 对兄弟核做测试清空闲——跨 CPU。跨核原子操作更贵。 */
	BENCH_IDLE_SMTMASK       = 20, /* cpumask_test_cpu on smtmask — read-only, no atomic */
				       /* 在 SMT 掩码上做只读位测试。无原子写，比测试清更便宜。 */
	BENCH_DISRUPTOR_READ     = 21, /* Full CL0 Disruptor handoff read (cake_stopping sim) */
				       /* 完整 CL0 交接读取（模拟 cake_stopping）。评估 stopping 读取负担。
					   stopping是什么 */
	BENCH_TCTX_COLD_SIM      = 22, /* get_task_ctx + arena CL0 read (cake_running sim) */
				       /* 取 ctx + 读 arena CL0（模拟 cake_running）。评估 running 冷读成本。 */
	BENCH_ARENA_STRIDE       = 23, /* Stride across arena per_cpu array to test TLB/hugepage */
				       /* 跨步遍历 arena 每CPU 数组。测试 TLB/大页命中的影响。 */

	/* ── New entries (24–42): eBPF helpers + SCX kfuncs ── */
	/* ── 新增条目（24–42）：eBPF 辅助函数 + SCX kfunc ── */
	/* 讲解：这一组对比各类内核辅助函数的开销。 */
	/* Timing variants */
	/* 各种取时变体 */
	BENCH_KTIME_BOOT_NS      = 24, /* bpf_ktime_get_boot_ns() — suspend-aware */
				       /* 含休眠时间的启动纳秒钟。讲解：跨挂起仍连续，但略慢。 */
	BENCH_KTIME_COARSE_NS    = 25, /* bpf_ktime_get_coarse_ns() — jiffies-based low-res */
				       /* 基于 jiffies 的低精度时钟。讲解：精度低但取时极快。 */
	BENCH_JIFFIES64           = 26, /* bpf_jiffies64() — raw jiffies */
				       /* 原始 jiffies 计数。讲解：最粗粒度的时间来源。 */
	BENCH_KTIME_TAI_NS       = 27, /* bpf_ktime_get_tai_ns() — TAI clock */
				       /* TAI 原子时时钟。讲解：不含闰秒的连续时基。 */

	/* Process info */
	/* 进程信息 */
	BENCH_CURRENT_PID_TGID   = 28, /* bpf_get_current_pid_tgid() — PID+TGID in one */
				       /* 一次取回 PID+TGID。讲解：合并读取比分开更省。 */
	BENCH_CURRENT_TASK_BTF   = 29, /* bpf_get_current_task_btf() — direct task ptr */
				       /* 直接取当前 task 指针。讲解：省去查表，可直接读字段。 */
	BENCH_CURRENT_COMM       = 30, /* bpf_get_current_comm() — task comm name */
				       /* 取当前任务名。讲解：涉及拷贝，成本相对较高。 */

	/* CPU / topology info */
	/* CPU / 拓扑信息 */
	BENCH_NUMA_NODE_ID       = 31, /* bpf_get_numa_node_id() — NUMA node */
				       /* 取 NUMA 节点号。讲解：多路系统上的归属判断。 */
	BENCH_SCX_TASK_RUNNING   = 32, /* scx_bpf_task_running(p) — task running check */
				       /* 判断任务是否在运行。讲解：抢占决策时的状态检查。 */
	BENCH_SCX_TASK_CPU       = 33, /* scx_bpf_task_cpu(p) — task's current CPU */
				       /* 取任务当前 CPU。讲解：对比邮箱缓存 CPU 的开销。 */
	BENCH_SCX_NR_NODE_IDS    = 34, /* scx_bpf_nr_node_ids() — NUMA node count */
				       /* 取 NUMA 节点数。讲解：对比 RODATA 常量方式。 */
	BENCH_SCX_CPUPERF_CUR    = 35, /* scx_bpf_cpuperf_cur(cpu) — current perf level */
				       /* 取当前性能档位。讲解：CPUPERF 频率调控相关。 */

	/* Task storage (what cake replaced with arena) */
	/* 任务存储（cake 用 arena 替代了它） */
	BENCH_TASK_STORAGE_GET   = 36, /* bpf_task_storage_get() — standard per-task map */
				       /* 标准每任务存储读取。讲解：与 arena 方案做性能对比。 */

	/* Idle probing alternatives */
	/* 空闲探测的其它方案 */
	BENCH_SCX_PICK_IDLE_CPU  = 37, /* scx_bpf_pick_idle_cpu() — kernel idle scan */
				       /* 内核空闲核扫描。讲解：Gate 3 回退所用，代价较高。 */
	BENCH_SCX_IDLE_CPUMASK   = 38, /* scx_bpf_get_idle_cpumask() + put cycle */
				       /* 取/放空闲掩码一轮。讲解：整块掩码方式的开销。 */
	BENCH_SCX_KICK_CPU       = 39, /* scx_bpf_kick_cpu() — IPI preemption cost */
				       /* 踢 CPU（发 IPI）抢占。讲解：跨核中断代价，抢占时衡量。 */

	/* Utility */
	/* 工具类 */
	BENCH_PRANDOM_U32        = 40, /* bpf_get_prandom_u32() — RNG cost */
				       /* 取伪随机数。讲解：对比自实现 xorshift 的成本。 */
	BENCH_SPIN_LOCK          = 41, /* bpf_spin_lock + unlock cycle */
				       /* 自旋锁加解锁一轮。讲解：对比无锁读的代价。 */
	BENCH_SCX_CPUPERF_CAP    = 42, /* scx_bpf_cpuperf_cap(cpu) — max perf capacity */
				       /* 取最大性能容量。讲解：异构核容量缩放会用到。 */

	/* ── Cake competitor entries (43–49) ── */
	/* ── cake 自研对照条目（43–49） ── */
	/* 讲解：这组把 cake 自己的优化写法与等价 kfunc 对比。 */
	BENCH_RODATA_NR_CPUS     = 43, /* RODATA const nr_cpus read (vs nr_cpu_ids kfunc) */
				       /* RODATA 常量读 CPU 数（对比 kfunc）。讲解：常量读通常快得多。 */
	BENCH_RODATA_NR_NODES    = 44, /* RODATA const nr_nodes read (vs nr_node_ids kfunc) */
				       /* RODATA 常量读节点数（对比 kfunc）。讲解：同理省去 kfunc 调用。 */
	BENCH_RODATA_CPUPERF_CAP = 45, /* RODATA cpuperf_cap[cpu] read (vs kfunc) */
				       /* RODATA 读性能容量（对比 kfunc）。讲解：预烘焙常量替代运行时查询。 */
	BENCH_ARENA_PID_TGID     = 46, /* Arena tctx.pid+tgid read (vs current_pid_tgid kfunc) */
				       /* arena 读 pid+tgid（对比 kfunc）。讲解：已缓存字段更省。 */
	BENCH_MBOX_TASK_CPU      = 47, /* Mbox CL0 cached_cpu (vs scx_bpf_task_cpu kfunc) */
				       /* 邮箱读缓存 CPU（对比 kfunc）。讲解：本地缓存优于 kfunc。 */
	BENCH_CL0_LOCKFREE       = 48, /* CL0 lock-free atomic read (vs bpf_spin_lock cycle) */
				       /* CL0 无锁原子读（对比自旋锁）。讲解：单写多读无需上锁。 */
	BENCH_BSS_XORSHIFT       = 49, /* BSS xorshift32 PRNG (vs bpf_get_prandom_u32 kfunc) */
				       /* BSS 自实现 xorshift 随机（对比 kfunc）。讲解：自算随机比 kfunc 更快。 */

	/* ═══ KERNEL FREE DATA PROBES (50–54) ═══ */
	/* ═══ 内核“免费”数据探测（50–54） ═══ */
	/* 讲解：这些数据内核已维护好，读取近乎零成本，可直接用于分类。 */
	BENCH_PELT_UTIL_AVG      = 50, /* p->se.avg.util_avg — kernel EWMA (0-1024) */
				       /* 读 PELT 利用率均值。讲解：cake 分类的核心指标。 */
	BENCH_PELT_RUNNABLE_AVG  = 51, /* p->se.avg.runnable_avg — kernel runnable EWMA */
				       /* 读 PELT 可运行均值。讲解：反映排队压力的辅助指标。 */
	BENCH_SCHEDSTATS_WAKEUPS = 52, /* p->stats.nr_wakeups — cumulative wakeup count */
				       /* 读累计唤醒次数。讲解：可用于判断交互性。 */
	BENCH_TASK_POLICY_FLAGS  = 53, /* p->policy + p->in_iowait — free classification */
				       /* 读调度策略+iowait 标志。讲解：几乎免费的分类线索。 */
	BENCH_PELT_VS_EWMA       = 54, /* PELT read + tier classify (was PELT vs EWMA comparison) */
				       /* 读 PELT 并做分层。讲解：测量完整的 PELT 分类路径。 */

	/* ═══ END-TO-END WORKFLOW COMPARISONS (55–62) ═══ */
	/* ═══ 端到端流程对比（55–62） ═══ */
	/* 讲解：这组把完整的操作序列作为整体来测，更贴近真实调度成本。 */
	BENCH_STORAGE_ROUNDTRIP  = 55, /* task_storage: write field → read back (full cycle) */
				       /* task_storage 写后回读一轮。讲解：完整读写往返成本。 */
	BENCH_ARENA_ROUNDTRIP    = 56, /* Arena: write field → read back (full cycle) */
				       /* arena 写后回读一轮。讲解：与 task_storage 往返对比。 */
	BENCH_CASCADE_VS_PICK    = 57, /* 6-gate cascade sim: prev→sib→home BSS vs pick_idle */
				       /* 多级门级联 vs 内核 pick_idle。讲解：验证自研选核是否更快。 */
	BENCH_PICK_IDLE_FULL     = 58, /* pick_idle_cpu full: kfunc + affinity check + result */
				       /* 完整 pick_idle 流程。讲解：含亲和校验的真实回退成本。 */
	BENCH_CLASSIFY_WEIGHT    = 59, /* bpfland-style: p->scx.weight → vtime calc */
				       /* bpfland 风格权重→vtime。讲解：对比其它调度器的分类算法。 */
	BENCH_CLASSIFY_LATCRI    = 60, /* lavd-style: wakeup_sync + run_freq → score */
				       /* lavd 风格延迟评分。讲解：对比基于唤醒/频率的打分法。 */
	BENCH_SMT_CAKE_PROBE     = 61, /* cake SMT: test_and_clear(sib) + BSS[sib].idle_hint */
				       /* cake 的 SMT 兄弟核探测。讲解：结合原子测试与 BSS 提示。 */
	BENCH_SMT_CPUMASK_PROBE  = 62, /* bpfland SMT: is_smt_contended via cpumask scan */
				       /* bpfland 的 SMT 争用检测。讲解：对比基于掩码扫描的方案。 */

	/* ═══ FAIRNESS FIXES (63–66) ═══ */
	/* ═══ 公平性修正测量（63–66） ═══ */
	/* 讲解：这组特意在缓存被逐出后测量“冷”访问，反映最坏情况。 */
	BENCH_STORAGE_GET_COLD   = 63, /* task_storage_get after L1 eviction (cold task) */
				       /* L1 逐出后取 task_storage。讲解：冷缓存下的真实查找成本。 */
	BENCH_PELT_COLD          = 64, /* PELT util_avg after L1 eviction (cold p->se.avg) */
				       /* L1 逐出后读 PELT。讲解：冷读内核字段的代价。 */
	BENCH_EWMA_COLD          = 65, /* EWMA compute after L1 eviction (cold cpu_bss) */
				       /* L1 逐出后算 EWMA。讲解：冷 cpu_bss 访问成本。 */
	BENCH_KICK_REMOTE        = 66, /* kick_cpu(sibling) — real IPI, not self-noop */
				       /* 踢兄弟核（真实 IPI）。讲解：区别于自踢空操作的真实中断开销。 */

	BENCH_MAX_ENTRIES        = 67,
				 /* 条目总数（哨兵值）。讲解：作为结果数组维度。 */
};

struct kfunc_bench_entry {
	u64 min_ns;         /* Best-case cost */
			    /* 最优（最小）耗时。讲解：多次迭代中的最快一次。 */
	u64 max_ns;         /* Worst-case cost */
			    /* 最差（最大）耗时。讲解：反映抖动上限。 */
	u64 total_ns;       /* Sum for avg calc */
			    /* 总和，用于求平均。讲解：除以迭代次数得平均耗时。 */
	u64 last_value;     /* Last return value from the helper */
			    /* 辅助函数最后一次的返回值。讲解：兼作正确性校验。 */
	u64 samples[BENCH_ITERATIONS]; /* Raw per-iteration ns for percentile calc */
				       /* 每次迭代的原始纳秒值。讲解：用于计算百分位数。 */
};

struct kfunc_bench_results {
	struct kfunc_bench_entry entries[BENCH_MAX_ENTRIES];
	u32 cpu;            /* CPU that ran the bench */
			    /* 运行基准测试的 CPU 号。讲解：结果与具体核心相关。 */
	u32 iterations;     /* Iterations per helper */
			    /* 每个辅助函数的迭代次数。讲解：与 BENCH_ITERATIONS 对应。 */
	u64 bench_timestamp; /* When bench completed (ktime_ns) */
			     /* 基准完成时刻（ktime_ns）。讲解：供 TUI 判断结果新鲜度。 */
};

/* Gate cascade (simplified 3-gate design):
 *   Gate 1: prev_cpu idle (91% hit, L1/L2 warm, zero arena)
 *   Gate 2: perf-ordered idle scan (P/E topology, GAMING active)
 *   Gate 3: kernel scx_bpf_select_cpu_dfl (any idle)
 *   Tunnel: all CPUs busy → DSQ fallback (vtime ordering) */
/* 选核门级联（简化的 3 门设计）：
 *   Gate 1：prev_cpu 空闲（命中率 91%，L1/L2 缓存热，无需 arena）
 *   Gate 2：按性能排序的空闲扫描（P/E 拓扑，游戏态激活时）
 *   Gate 3：内核 scx_bpf_select_cpu_dfl（任意空闲核）
 *   隧道：所有 CPU 都忙 → 回退入 DSQ（按 vtime 排序） */
/* 讲解：按“最省→最贵”的顺序逐门尝试选核，大部分请求在第一门就命中，兼顾速度与正确性。 */

/* Flow state flags (packed_info bits 24-27) */
/* 流状态标志（打包进 packed_info 的 24-27 位） */
/* 讲解：这些标志描述任务的临时调度状态，紧凑地存放在 packed_info 中。 */
enum cake_flow_flags {
	CAKE_FLOW_NEW          = 1 << 0, /* Task is newly created */
					 /* 任务是新建的。讲解：新任务享新流赤字加成。 */
	CAKE_FLOW_YIELDER      = 1 << 1, /* Task voluntarily yielded since last stop */
					 /* 自上次 stop 后曾自愿让出。讲解：让出者获更宽松时间片。 */
	CAKE_FLOW_WAKER_BOOST  = 1 << 2, /* Waker was a yielder — propagate priority (1-cycle) */
					 /* 唤醒者是让出者——传播优先级（仅 1 个周期）。讲解：自动提升生产-消费链。 */
	CAKE_FLOW_HOG          = 1 << 3, /* Background hog: BULK + non-yielder + deprioritized */
					 /* 后台大户：批处理+非让出+被降权。讲解：CPU 吞噬者，抢占保护最弱。 */
};

/* Record emitted by SEC("iter/task") cake_task_iter program.
 * One record per managed task. Userspace reads fixed-size records from the
 * iter fd instead of walking the pid_to_tctx hash map.
 * Replaces: pid_to_tctx BPF_MAP_TYPE_HASH (65536 entries, global bucket lock).
 * Benefit: cake_init_task + cake_exit_task become fully lockless (no map ops). */
/* 由 SEC("iter/task") 的 cake_task_iter 程序输出的记录。
 * 每个受管任务一条记录。用户态从 iter fd 读取定长记录，
 * 而不再遍历 pid_to_tctx 哈希表。
 * 取代了：pid_to_tctx 哈希表（65536 项，带全局桶锁）。
 * 好处：cake_init_task 与 cake_exit_task 变为完全无锁（不再有 map 操作）。 */
/* 讲解：用 BPF iter 导出任务快照，避免哈希表的全局锁，让任务创建/销毁热路径无锁化。 */
struct cake_iter_record {
	u32 pid;         /* pid of this task */
			 /* 本任务的 pid。讲解：TUI 据此定位并展示任务。 */
	u32 ppid;        /* parent pid (promoted from tctx CL0) */
			 /* 父进程 pid（从 tctx CL0 提升而来）。讲解：用于游戏家族归属判断。 */
	u32 packed_info; /* tier + flags — same field read in Rust telemetry loop */
			 /* 层级 + 标志的打包字段。讲解：与 Rust 遥测循环读取的是同一字段。 */
	u16 pelt_util;       /* PELT util_avg (0-1024) from p->se.avg */
			     /* 来自 p->se.avg 的 PELT 利用率（0-1024）。讲解：分类的主要依据。 */
	u16 deficit_us;      /* DRR deficit in µs */
			     /* DRR 赤字（微秒）。讲解：DRR++ 剩余配额。 */
	u16 vtime_mult;      /* EEVDF vtime reciprocal (102400/weight, 1024=nice0) */
			     /* EEVDF vtime 倒数系数。讲解：由 nice 权重换算而来。 */
	u16 _pad_iter;       /* alignment */
			     /* 对齐填充。讲解：保证后续 telemetry 块对齐。 */
	/* telemetry block: everything the TUI currently reads from arena pointers */
	/* 遥测块：TUI 目前从 arena 指针读取的全部内容。 */
	/* 讲解：把展示所需的统计字段集中在此，方便一次性导出给用户态。 */
	struct {
		u64 run_start_ns;
		u64 run_duration_ns;
		u64 enqueue_start_ns;
		u64 wait_duration_ns;
		u32 select_cpu_duration_ns;
		u32 enqueue_duration_ns;
		u32 dsq_insert_ns;
		u32 gate_1_hits;
		u32 gate_2_hits;
		u32 gate_1w_hits;
		u32 gate_3_hits;
		u32 gate_1p_hits;
		u32 gate_1c_hits;
		u32 gate_1cp_hits;
		u32 gate_1d_hits;
		u32 gate_1wc_hits;
		u32 gate_tun_hits;
		u32 _pad2;
		u64 jitter_accum_ns;
		u32 total_runs;
		u16 core_placement;
		u16 migration_count;
		u16 preempt_count;
		u16 yield_count;
		u16 direct_dispatch_count;
		u16 enqueue_count;
		u16 cpumask_change_count;
		u16 _pad3;
		u32 stopping_duration_ns;
		u32 running_duration_ns;
		u32 max_runtime_us;
		u32 _pad4;
		u64 dispatch_gap_ns;
		u64 max_dispatch_gap_ns;
		u32 wait_hist_lt10us;
		u32 wait_hist_lt100us;
		u32 wait_hist_lt1ms;
		u32 wait_hist_ge1ms;
		u16 slice_util_pct;
		u16 llc_id;
		u16 same_cpu_streak;
		u16 _pad_recomp;
		u32 wakeup_source_pid;
		u64 nivcsw_snapshot;
		u32 nvcsw_delta;
		u32 nivcsw_delta;
		u32 pid_inner;  /* matches telemetry.pid */
		u32 tgid;
		char comm[16];
		u32 gate_cascade_ns;
		u32 idle_probe_ns;
		u32 vtime_compute_ns;
		u32 mbox_staging_ns;
		u32 _pad_ewma;
		u32 classify_ns;
		u32 vtime_staging_ns;
		u32 warm_history_ns;
		u16 quantum_full_count;
		u16 quantum_yield_count;
		u16 quantum_preempt_count;
		u16 _pad_quantum;
		u16 waker_cpu;
		u16 _pad_waker;
		u32 waker_tgid;
		u16 cpu_run_count[CAKE_TELEM_MAX_CPUS];
	} telemetry;
};

/* ═══════════════════════════════════════════════════════════════════════════
 * CONDITIONAL SIZE MACROS — Release/Debug struct sizing pattern
 *
 * DESIGN PHILOSOPHY: In release (CAKE_RELEASE=1, CAKE_STATS_ENABLED=0),
 * Clang dead-code eliminates every telemetry/BenchLab access. Structs
 * shrink to their scheduling-essential footprint by #ifdef-gating
 * debug-only fields. This saves arena memory, TLB footprint, and
 * cache pollution in production builds.
 *
 * Structs using this pattern:
 *   mega_mailbox_entry:  64B release (1 CL) / 128B debug (2 CL)
 *   cake_task_ctx:       64B release (1 CL) / 512B debug (8 CL)
 *   cake_per_cpu:        matches mailbox size
 * ═══════════════════════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════════════════════
 * 条件尺寸宏——发布/调试版结构体尺寸模式
 *
 * 设计理念：在发布版（CAKE_RELEASE=1，CAKE_STATS_ENABLED=0）中，
 * Clang 会删除所有遥测/BenchLab 访问代码。结构体通过 #ifdef 门控
 * 仅调试用的字段，收缩到调度必需的最小体积，从而在生产构建里
 * 节省 arena 内存、TLB 占用并减少缓存污染。
 *
 * 采用此模式的结构体：
 *   mega_mailbox_entry：发布 64B（1 缓存行）/ 调试 128B（2 缓存行）
 *   cake_task_ctx：      发布 64B（1 缓存行）/ 调试 512B（8 缓存行）
 *   cake_per_cpu：       与邮箱尺寸一致
 * ═══════════════════════════════════════════════════════════════════════════ */
/* 讲解：同一份结构体定义在两种构建下体积不同，发布版删掉遥测字段以追求极致缓存效率。 */
#ifdef CAKE_RELEASE
#define CAKE_MBOX_SIZE  64
			/* 发布版邮箱大小 64B。讲解：仅保留调度必需，占一条缓存行。 */
#define CAKE_MBOX_ALIGN 64
			/* 发布版邮箱对齐 64B。讲解：与大小一致，独占缓存行。 */
#define CAKE_TCTX_SIZE  64
			/* 发布版任务 ctx 大小 64B。讲解：遥测被裁掉后只剩 CL0。 */
#define CAKE_TCTX_ALIGN 64
			/* 发布版任务 ctx 对齐 64B。讲解：一条缓存行装下热字段。 */
#else
#define CAKE_MBOX_SIZE  128
			/* 调试版邮箱大小 128B。讲解：多出 CL1 用于 BenchLab 交接。 */
#define CAKE_MBOX_ALIGN 128
			/* 调试版邮箱对齐 128B。讲解：两条缓存行。 */
#define CAKE_TCTX_SIZE  512
			/* 调试版任务 ctx 大小 512B。讲解：CL0 热字段 + CL1-7 遥测。 */
#define CAKE_TCTX_ALIGN 512
			/* 调试版任务 ctx 对齐 512B。讲解：整块对齐便于 arena 扫描。 */
#endif

/* Per-task flow state — conditional sizing (Release/Debug pattern).
 *   RELEASE: 64B (1 CL) — scheduling hot fields only, telemetry compiled out
 *   DEBUG:  512B (8 CL) — CL0 hot + CL1-7 telemetry for TUI analytics
 *
 * CACHE LINE SEGREGATION (Ghost Struct):
 *   CL0 (bytes 0-63): Every field needed for release-mode scheduling.
 *     In --release, CAKE_STATS_ENABLED=0 → Clang dead-codes all telemetry.
 *     The CPU prefetcher only ever loads CL0 — telemetry bytes stay in RAM.
 *   CL1+ (bytes 64+): Debug-only telemetry for TUI analytics.
 *     Compiled out in release → 448B savings per task in BPF arena.
 *
 * staged_vtime_bits at offset 0: most-read field across all 4 callbacks
 *   (select_cpu, enqueue, running, stopping). JIT emits [reg+0] instead
 *   of [reg+48], saving one ADD instruction per access. */
/* 每任务流状态——条件尺寸（发布/调试模式）。
 *   发布版：64B（1 缓存行）——仅调度热字段，遥测被编译裁掉
 *   调试版：512B（8 缓存行）——CL0 热字段 + CL1-7 供 TUI 分析的遥测
 *
 * 缓存行隔离（“幽灵结构体”）：
 *   CL0（字节 0-63）：发布模式调度所需的全部字段。
 *     --release 下 CAKE_STATS_ENABLED=0 → Clang 删除所有遥测代码。
 *     CPU 预取器只加载 CL0——遥测字节始终留在内存里。
 *   CL1+（字节 64+）：仅调试用的 TUI 分析遥测。
 *     发布版中被裁掉 → 每任务在 BPF arena 里省 448B。
 *
 * staged_vtime_bits 放在偏移 0：它是 4 个回调（select_cpu、enqueue、
 *   running、stopping）中读取最频繁的字段。JIT 生成 [reg+0] 而非
 *   [reg+48]，每次访问省一条 ADD 指令。 */
/* 讲解：核心技巧是把最热字段放偏移 0、把冷字段分到独立缓存行，让热路径只碰一条缓存行。 */
struct cake_task_ctx {
	/* ═══ CACHE LINE 0 (bytes 0-63): HOT / RELEASE MODE ═══ */
	/* ═══ 缓存行 0（字节 0-63）：热字段 / 发布模式 ═══ */
	/* 讲解：这部分即使在发布版也保留，是调度真正依赖的数据。 */

	/* STAGED VTIME BITS — offset 0 for JIT-optimal [reg+0] addressing. */
	/* 暂存 vtime 位——放偏移 0 以获得 JIT 最优的 [reg+0] 寻址。 */
	/* 讲解：最热字段置于首位可省去地址偏移加法。 */
	u64 staged_vtime_bits; /* 8B: VALID|HOME|WB|GAME|HOG|BG|WB_DUP|NF|weight */
			       /* 8字节：有效|归属|唤醒提升|游戏|大户|后台|重复提升|新流|权重。讲解：多提示打包成一个 u64。 */
	/* cached_cpumask REMOVED: after scx_bpf_select_cpu_and refactor,
	 * kernel handles affinity via p->cpus_ptr natively. 0 read sites. */
	/* cached_cpumask 已移除：改用 scx_bpf_select_cpu_and 后，
	 * 亲和性由内核经 p->cpus_ptr 原生处理，已无读取点。 */
	/* 讲解：重构后不再需要自缓存的 CPU 掩码。 */

	/* DRR deficit + packed bitfield. */
	/* DRR 赤字 + 打包位域。 */
	/* 讲解：把小字段紧凑排布以省空间。 */
	u16 deficit_u16;     /* 2B: DRR deficit */
			     /* 2字节：DRR 赤字。讲解：DRR++ 剩余配额。 */
	u16 _ctx_pad;        /* 2B: alignment padding */
			     /* 2字节：对齐填充。讲解：使 packed_info 按 4B 对齐。 */
	u32 packed_info;     /* 4B: Bitfield */
			     /* 4字节：位域字段。讲解：层级+标志+标记压进一个 u32。 */

	/* Game family detection */
	/* 游戏家族识别 */
	u32 ppid;             /* 4B: Parent PID (Proton/Wine siblings) */
			      /* 4字节：父进程 PID（Proton/Wine 兄弟进程）。讲解：靠父进程把整族归为 GAME。 */

	/* Anti-starvation + confidence gating */
	/* 防饿死 + 置信度门控 */
	u32 last_run_at;      /* 4B: Last run timestamp (ns), wraps 4.2s */
			      /* 4字节：上次运行时间戳（ns），约 4.2s 回绕。讲解：用于间隔与防饿死计算。 */
	u32 reclass_counter;  /* 4B: Per-task stop counter for confidence backoff */
			      /* 4字节：每任务 stop 计数器，用于置信度退避。讲解：每 64 次才重分类。 */

	/* Warm CPU history — Gate 1c (home CPU) + Gate 1D (tgid affinity) */
	/* 热点 CPU 历史——Gate 1c（归属 CPU）+ Gate 1D（tgid 亲和） */
	u16 warm_cpus[3];     /* 6B: [0]=current, [1]=prev (home), [2]=oldest */
			      /* 6字节：[0]=当前 [1]=上一个(归属) [2]=最旧。讲解：用于缓存亲和选核。 */
	u16 waker_cpu;        /* 2B: CPU where waker last ran (Gate 1W-chain) */
			      /* 2字节：唤醒者上次运行的 CPU（Gate 1W 链）。讲解：让消费者靠近生产者。 */

	/* Yield detection — read+written unconditionally every stop */
	/* 让出检测——每次 stop 都无条件读写 */
	u64 nvcsw_snapshot;   /* 8B: Last read of p->nvcsw */
			      /* 8字节：p->nvcsw 的上次快照。讲解：与当前值比较判断是否自愿让出。 */

	/* Phase 2: Userspace-stamped task class */
	/* 阶段 2：由用户态打标的任务类别 */
	u8  task_class;        /* 1B: CAKE_CLASS_* enum, written by reclassifier */
			       /* 1字节：CAKE_CLASS_* 枚举，由重分类器写入。讲解：BPF 侧只读该结果。 */
	u8  _pad_ctx;          /* 1B: alignment */
			       /* 1字节：对齐填充。讲解：使 vtime_mult 对齐。 */
	u16 vtime_mult;        /* 2B: mirrors hot->vtime_mult */
			       /* 2字节：镜像 hot->vtime_mult。讲解：与热存储保持同步。 */

	/* ─── CL0 total: 8+(2+2+4)+4+(4+4)+(6+2)+8+(1+1+2) = 48B ─── */
	/* ─── CL0 合计：8+(2+2+4)+4+(4+4)+(6+2)+8+(1+1+2) = 48B ─── */
	/* Pad to 64B CL0 boundary: 64 - 48 = 16B, but u64 alignment
	 * holes consume 4B implicitly (nvcsw at offset 36→pad→40), so 12B explicit. */
	/* 填充到 64B 的 CL0 边界：64 - 48 = 16B，但 u64 对齐空洞
	 * 隐式占了 4B（nvcsw 在偏移 36→补齐→40），故显式补 12B。 */
	/* 讲解：精确计算填充量，保证结构体恰好占满一条缓存行。 */
	u8  _pad_cl0[12];     /* 12B: Pad to 64B CL0 boundary */
			      /* 12字节：填充到 64B CL0 边界。讲解：对齐用途。 */

#ifndef CAKE_RELEASE
	/* ═══ CL1+ (bytes 64-511): DEBUG-ONLY TELEMETRY ═══
	 * Compiled out in release → struct shrinks from 512B to 64B.
	 * Zero-cost pointer access via BPF Arena. User-space sweeps memory
	 * asynchronously to build 1% Lows and average runtimes. */
	/* ═══ CL1+（字节 64-511）：仅调试用遥测 ═══
	 * 发布版中被裁掉 → 结构体从 512B 缩到 64B。
	 * 经 BPF Arena 做零成本指针访问。用户态异步扫描这块内存，
	 * 计算 1% Low 帧与平均运行时长。 */
	/* 讲解：所有 TUI 分析数据都在此，且只在调试版存在。 */
	struct {
		/* Timing Metrics */
		/* 计时指标 */
		u64 run_start_ns;
		u64 run_duration_ns; /* Total runtime (end - begin) */
				     /* 总运行时长（结束-开始）。讲解：单次执行占用 CPU 的时间。 */
		u64 enqueue_start_ns; /* Start of DSQ sorting */
				      /* 入队排序开始时刻。讲解：用于统计 DSQ 等待时长。 */
		u64 wait_duration_ns; /* Time spent in DSQ (run_start - enq_end) */
				      /* 在 DSQ 中等待的时长。讲解：反映排队延迟。 */
		u32 select_cpu_duration_ns; /* Total routing overhead */
					    /* 选核总开销。讲解：衡量 select_cpu 回调成本。 */
		u32 enqueue_duration_ns; /* Time spent sorting DSQ */
					 /* 入队排序耗时。讲解：衡量 enqueue 回调成本。 */
		u32 dsq_insert_ns;       /* Insert/vtime overhead */
					 /* 插入/vtime 计算开销。讲解：DSQ 有序插入的代价。 */

		/* Topographic / Cache Data */
		/* 拓扑 / 缓存数据 */
		u32 gate_1_hits; /* Number of local cache hit wakeups */
				 /* Gate 1（prev_cpu 空闲）命中次数。讲解：缓存最热的最优路径。 */
		u32 gate_2_hits; /* SMT sibling hits */
				 /* Gate 2（性能排序扫描）命中次数。讲解：按 P/E 顺序找空闲核。 */
		u32 gate_1w_hits; /* Waker affinity hits (SMT sibling or LLC) */
				  /* 唤醒者亲和命中次数。讲解：靠近唤醒者放置。 */
		u32 gate_3_hits; /* Kernel fallback hits */
				 /* Gate 3（内核回退）命中次数。讲解：自研门都失败时的兜底。 */
		u32 gate_1p_hits; /* Yielder-preempts-bulk hits (Gate 1P) */
				  /* Gate 1P（让出者抢占大户）命中次数。讲解：让延迟敏感任务抢占吞吐任务。 */
		u32 gate_1c_hits; /* Home CPU warm set hits (Gate 1c) */
				  /* Gate 1c（归属 CPU 热集）命中次数。讲解：回到之前的家 CPU。 */
		u32 gate_1cp_hits; /* Home CPU preempt-hog hits (Gate 1c-P) */
				   /* Gate 1c-P（归属 CPU 抢占大户）命中次数。讲解：抢回被大户占用的家 CPU。 */
		u32 gate_1d_hits; /* Domestic: same-process cache affinity (Gate 1D) */
				  /* Gate 1D（同进程缓存亲和）命中次数。讲解：同 tgid 任务聚在一起。 */
		u32 gate_1wc_hits; /* Waker-chain: producer-consumer locality (Gate 1WC) */
				   /* Gate 1WC（唤醒链局部性）命中次数。讲解：生产-消费者相邻放置。 */
		u32 gate_tun_hits; /* Complete miss tunneling */
				   /* 隧道（全部未命中）次数。讲解：所有核都忙，回退进 DSQ。 */
		u64 jitter_accum_ns; /* Mathematical running variant vs AVG */
				     /* 抖动累加（相对均值的方差）。讲解：衡量调度时序稳定性。 */
		u32 total_runs; /* Total executions over lifetime */
				/* 生命周期内总执行次数。讲解：各类速率的分母。 */
		u16 core_placement; /* Physical CPU task last executed on */
				    /* 上次执行所在的物理 CPU。讲解：展示核放置情况。 */

		/* State Change Counters */
		/* 状态变化计数器 */
		u16 migration_count; /* Inter-cpu bounces inside select_cpu */
				     /* 跨 CPU 迁移次数。讲解：迁移多说明缓存亲和差。 */
		u16 preempt_count;   /* Task kicked/preempted */
				     /* 被踢/被抢占次数。讲解：反映被打断的频度。 */
		u16 yield_count;     /* Task willingly gave up execution */
				     /* 自愿让出次数。讲解：合作型任务的标志。 */

		/* Lifecycle Counters */
		/* 生命周期计数器 */
		u16 direct_dispatch_count; /* SCX_DSQ_LOCAL_ON bypasses (no DSQ) */
					   /* 直接派发次数（绕过 DSQ）。讲解：命中空闲核直投本地队列。 */
		u16 enqueue_count;         /* Total enqueue calls */
					   /* 入队总次数。讲解：进入 DSQ 排队的次数。 */
		u16 cpumask_change_count;  /* sched_setaffinity changes */
					   /* 亲和掩码变更次数。讲解：sched_setaffinity 引起。 */

		/* Callback Overhead (last-write-wins, ns) */
		/* 回调开销（后写覆盖，ns） */
		u32 stopping_duration_ns;  /* cake_stopping BPF overhead */
					   /* cake_stopping 的耗时。讲解：分类/暂存路径成本。 */
		u32 running_duration_ns;   /* cake_running BPF overhead */
					   /* cake_running 的耗时。讲解：上下文切入时的成本。 */

		/* Worst-Case Tracking */
		/* 最坏情况跟踪 */
		u32 max_runtime_us;        /* Max runtime in current TUI interval */
					   /* 当前 TUI 周期内最大运行时长。讲解：捕捉长占用尖峰。 */


		/* Scheduling Period (inter-dispatch gap) */
		/* 调度周期（两次派发间隔） */
		u64 dispatch_gap_ns;       /* Time since previous run start */
					   /* 距上次运行开始的时间。讲解：反映任务运行频率。 */
		u64 max_dispatch_gap_ns;   /* Worst-case gap in current TUI interval */
					   /* 当前周期内最大间隔。讲解：捕捉最长“饿等”。 */

		/* Wait Latency Histogram (bucket counts, lifetime) */
		/* 等待延迟直方图（各桶计数，累计） */
		u32 wait_hist_lt10us;      /* wait < 10µs */
					   /* 等待 <10µs 的次数。讲解：最快派发桶。 */
		u32 wait_hist_lt100us;     /* 10µs <= wait < 100µs */
					   /* 等待 10-100µs 的次数。讲解：中等延迟桶。 */
		u32 wait_hist_lt1ms;       /* 100µs <= wait < 1ms */
					   /* 等待 100µs-1ms 的次数。讲解：较高延迟桶。 */
		u32 wait_hist_ge1ms;       /* wait >= 1ms */
					   /* 等待 ≥1ms 的次数。讲解：明显卡顿桶。 */

		/* Blind Spot Metrics (Phase B) */
		/* 盲点指标（阶段 B） */
		u16 slice_util_pct;        /* (actual_run / slice) * 100 */
					   /* 时间片利用率百分比。讲解：跑满还是提前让出。 */
		u16 llc_id;                /* LLC node this task last ran on */
					   /* 上次运行所在 LLC 节点。讲解：观察跨 LLC 情况。 */
		u16 same_cpu_streak;       /* Consecutive runs on same CPU */
					   /* 连续在同一 CPU 运行的次数。讲解：越大缓存越热。 */
		u16 _pad_recomp;           /* (was _deprecated_recomp — removed) */
					   /* 预留（原废弃字段）。讲解：占位保持布局。 */
		u32 wakeup_source_pid;     /* PID that woke this task */
					   /* 唤醒本任务的 PID。讲解：还原唤醒链。 */

		/* Voluntary/involuntary context switch tracking (GPU detection) */
		/* 自愿/非自愿上下文切换跟踪（用于 GPU 检测） */
		u64 nivcsw_snapshot;       /* Last read of p->nivcsw (for delta) */
					   /* p->nivcsw 上次快照（求增量用）。讲解：非自愿切换=被抢占。 */
		u32 nvcsw_delta;           /* nvcsw delta since last TUI interval */
					   /* 自上周期的自愿切换增量。讲解：合作性变化。 */
		u32 nivcsw_delta;          /* nivcsw delta since last TUI interval */
					   /* 自上周期的非自愿切换增量。讲解：被抢占程度。 */

		u32 pid;
		u32 tgid;  /* Thread group ID (process) for TUI grouping */
			   /* 线程组 ID（进程），供 TUI 分组。讲解：把同进程线程聚在一起显示。 */
		char comm[16];

		/* Per-callback sub-function stopwatch (Phase 8: Verbose Health) */
		/* 逐回调的子函数计时器（阶段 8：详细健康度） */
		u32 gate_cascade_ns;       /* select_cpu: full gate cascade duration */
					   /* select_cpu：完整门级联耗时。讲解：全部门尝试的总时间。 */
		u32 idle_probe_ns;         /* select_cpu: winning gate idle probe cost */
					   /* select_cpu：命中门的空闲探测成本。讲解：定位最终成本来源。 */
		u32 vtime_compute_ns;      /* enqueue: vtime calculation + tier weighting */
					   /* enqueue：vtime 计算+层加权耗时。讲解：排序键计算成本。 */
		u32 mbox_staging_ns;       /* running: mailbox CL0 write burst */
					   /* running：邮箱 CL0 写入耗时。讲解：切入时的状态暂存成本。 */
		u32 _pad_ewma;             /* (was _deprecated_ewma_ns — removed) */
					   /* 预留（原废弃 EWMA 字段）。讲解：占位保持布局。 */
		u32 classify_ns;           /* stopping: tier classify + squeeze fusion */
					   /* stopping：分层+压制融合耗时。讲解：分类路径成本。 */
		u32 vtime_staging_ns;      /* stopping: dsq_vtime bit packing + slice/vtime write */
					   /* stopping：dsq_vtime 打包+片/vtime 写入耗时。讲解：暂存路径成本。 */
		u32 warm_history_ns;       /* stopping: warm CPU ring shift (migration-gated) */
					   /* stopping：热点 CPU 环移位耗时（仅迁移时）。讲解：维护缓存历史成本。 */

		/* Quantum completion tracking (Phase 8) */
		/* 时间片完成情况跟踪（阶段 8） */
		u16 quantum_full_count;    /* Task consumed entire slice */
					   /* 跑满整个时间片的次数。讲解：吞吐型行为。 */
		u16 quantum_yield_count;   /* Task yielded before slice exhaustion */
					   /* 未用完就让出的次数。讲解：合作型行为。 */
		u16 quantum_preempt_count; /* Task was kicked/preempted mid-slice */
					   /* 片中被抢占的次数。讲解：被更高优先级打断。 */
		u16 _pad_quantum;          /* Align to 4B boundary */
					   /* 对齐到 4B。讲解：填充用途。 */

		/* Wake chain enhancement (Phase 8) */
		/* 唤醒链增强（阶段 8） */
		u16 waker_cpu;             /* CPU the waker was running on */
					   /* 唤醒者所在 CPU。讲解：辅助生产-消费者就近放置。 */
		u16 _pad_waker;            /* Align to 4B */
					   /* 对齐到 4B。讲解：填充用途。 */
		u32 waker_tgid;            /* TGID of the waker (process group) */
					   /* 唤醒者的 TGID（进程组）。讲解：识别跨进程唤醒关系。 */

		/* CPU core distribution histogram (Phase 8) */
		/* CPU 核分布直方图（阶段 8） */
		u16 cpu_run_count[CAKE_TELEM_MAX_CPUS]; /* 128 bytes: per-CPU run count */
							/* 128字节：每 CPU 运行次数。讲解：展示任务在各核的分布。 */
	} telemetry;
#endif /* !CAKE_RELEASE */
} __attribute__((aligned(CAKE_TCTX_ALIGN)));
_Static_assert(
	sizeof(struct cake_task_ctx) == CAKE_TCTX_SIZE,
	"cake_task_ctx size mismatch (64B release, 512B debug)");
/* 讲解：编译期断言，确保结构体尺寸严格等于预期（发布 64B / 调试 512B），布局出错立即报错。 */

/* Bitfield layout for packed_info (write-set co-located, Rule 24 mask fusion):
 * [Stable:2][Tier:2][Flags:4][KTH:1][BG:1][Rsvd:14][Rsvd:8]
 *  31-30     29-28   27-24    23     22    21-8       7-0
 * TIER+STABLE adjacent → fused 4-bit clear/set in reclassify (2 ops vs 4)
 * KTH = cached PF_KTHREAD (set once in cake_init_task, Rule 41)
 * BG  = background noise squeeze (toggled in cake_stopping) */
/* packed_info 的位域布局（写集合并放置，规则24 掩码融合）：
 * [稳定:2][层级:2][标志:4][内核线程:1][后台:1][保留:14][保留:8]
 *  31-30    29-28   27-24   23         22      21-8      7-0
 * 层级+稳定相邻 → 重分类时可融合成一次 4 位清/置（2 条指令而非 4 条）
 * KTH = 缓存的 PF_KTHREAD（在 cake_init_task 中设置一次，规则41）
 * BG  = 后台噪声压制（在 cake_stopping 中切换） */
/* 讲解：把一起写的字段排在相邻位，便于用一次掩码操作同时更新，减少指令数。 */
#define SHIFT_FLAGS 24 /* 4 bits: flow flags */
		       /* 流标志字段位移（4 位）。讲解：CAKE_FLOW_* 存于此。 */
#define SHIFT_TIER 28 /* 2 bits: tier 0-3 (coalesced with STABLE) */
		      /* 层级字段位移（2 位，与稳定位合并）。讲解：0-3 对应 4 个层。 */
#define SHIFT_STABLE 30 /* 2 bits: tier-stability counter (0-3) */
			/* 层级稳定计数器位移（2 位）。讲解：连续同层达 3 次才认定稳定。 */
#define BIT_KTHREAD 23 /* 1 bit: cached PF_KTHREAD (Rule 41: cold→init) */
		       /* 内核线程标记位。讲解：初始化时缓存，避免热路径重复判断。 */
#define BIT_BG_NOISE 22 /* 1 bit: background noise squeeze active */
			/* 后台噪声压制位。讲解：标记该任务当前被降权。 */

#define MASK_TIER 0x03 /* 2 bits: 0-3 */
		       /* 层级掩码（2 位）。讲解：提取层级值用。 */
#define MASK_FLAGS 0x0F /* 4 bits */
			/* 标志掩码（4 位）。讲解：提取流标志用。 */

/* HOG detection: rt_raw >= tick_slice * 3/4 (inline, no RODATA).
 * Task consumed ≥ 75% of allocated quantum = resource hog.
 * Both values already in BPF registers in cake_stopping.
 * Zero cold CL: replaces old PELT p->se.avg.util_avg read. */
/* HOG 检测：rt_raw >= tick_slice * 3/4（内联，无需 RODATA）。
 * 任务用掉 ≥75% 的分配时间片即视为资源大户。
 * 这两个值在 cake_stopping 中已在 BPF 寄存器里。
 * 零冷缓存行：取代了原来读 PELT p->se.avg.util_avg 的做法。 */
/* 讲解：用“已跑时间 vs 时间片”直接判大户，避免再去读会引发缓存缺失的内核 PELT 字段。 */

/* ═══════════════════════════════════════════════════════════════════════════
 * MEGA-MAILBOX: Per-CPU arena state
 *   RELEASE: 64B (1 CL) — all fields DCE'd, struct is dead stub
 *   DEBUG:  128B (2 CL) — CL0 telemetry + CL1 BenchLab handoff
 *
 * In release, Clang dead-code eliminates every mbox read/write.
 * The struct exists only for type correctness.
 *
 * In debug, CL0 holds telemetry + hints. CL1 holds BenchLab
 * snapshot fields for kfunc benchmarking.
 * ═══════════════════════════════════════════════════════════════════════════ */
/* ═══════════════════════════════════════════════════════════════════════════
 * 超级邮箱：每 CPU 的 arena 状态
 *   发布版：64B（1 缓存行）——全部字段被 DCE，结构体只是死桩
 *   调试版：128B（2 缓存行）——CL0 遥测 + CL1 BenchLab 交接
 *
 * 发布版中 Clang 会删除对邮箱的所有读写，结构体仅为类型正确而存在。
 * 调试版中 CL0 存遥测+提示，CL1 存供 kfunc 基准使用的快照字段。
 * ═══════════════════════════════════════════════════════════════════════════ */
/* 讲解：调度热路径实际从 cpu_bss 读提示，此邮箱在发布版中完全消失，只服务于调试遥测。 */
struct mega_mailbox_entry {
	/* ═══ CACHE LINE 0 (bytes 0-63): TELEMETRY + HINTS ═══
	 * In release: entire struct is DCE'd (zero scheduling reads from mbox).
	 * In debug: stats_on telemetry + shadow hints for BenchLab validation.
	 * Scheduling hot paths read idle_hint/last_tgid from cpu_bss, not mbox. */
	/* ═══ 缓存行 0（字节 0-63）：遥测 + 提示 ═══
	 * 发布版：整个结构体被删除（调度不再从邮箱读取）。
	 * 调试版：stats_on 遥测 + 供 BenchLab 校验的影子提示。
	 * 调度热路径从 cpu_bss 读 idle_hint/last_tgid，而非邮箱。 */
	/* 讲解：邮箱里的提示是“影子副本”，真正热路径用的是 cpu_bss。 */

	/* --- Telemetry (stats-gated) --- */
	/* --- 遥测（受统计开关门控） --- */
	u32 last_stopped_pid;  /* PID of last task that stopped on this CPU */
			       /* 本 CPU 上最后停止的任务 PID。讲解：用于调试展示。 */

	/* --- Idle shadow hint --- */
	/* --- 空闲影子提示 --- */
	u32 idle_hint;         /* 0=busy (default), 1=likely idle */
			       /* 0=忙（默认），1=可能空闲。讲解：邮箱侧的空闲提示副本。 */

	/* --- Cluster hint --- */
	/* --- 集群提示 --- */
	u32 last_tgid;         /* tgid of last task that ran on this CPU */
			       /* 本 CPU 上最后运行任务的 tgid。讲解：用于同进程聚集判断。 */

	/* --- Padding CL0 --- */
	/* --- CL0 填充 --- */
	u8  _pad_cl0[52];     /* 52B pad to end of CL0 */
			      /* 52字节，填充到 CL0 末尾。讲解：占满一条缓存行。 */

#ifndef CAKE_RELEASE
	/* ═══ CACHE LINE 1 (bytes 64-127): BENCHLAB HANDOFF (DEBUG ONLY) ═══
	 * These fields are ONLY read by BenchLab instrumentation (run_kfunc_bench).
	 * All scheduling hot paths read equivalent data from cpu_bss or task_hot.
	 * Compiled out in release → struct shrinks to 64B (1 CL). */
	/* ═══ 缓存行 1（字节 64-127）：BenchLab 交接（仅调试） ═══
	 * 这些字段仅由 BenchLab 探针（run_kfunc_bench）读取。
	 * 所有调度热路径都从 cpu_bss 或 task_hot 读取等价数据。
	 * 发布版中被裁掉 → 结构体缩到 64B（1 缓存行）。 */
	/* 讲解：CL1 纯为基准测试提供“快照”输入，不参与真实调度。 */

	/* --- Tick staging (bytes 64-71) --- */
	/* --- tick 暂存（字节 64-71） --- */
	u8  is_yielder;        /* BenchLab: yielder flag snapshot */
			       /* BenchLab：让出者标志快照。讲解：供基准复现场景。 */
	u8  tick_tier;         /* BenchLab: tier snapshot */
			       /* BenchLab：层级快照。讲解：基准输入。 */
	u16 cached_cpu;        /* BenchLab: CPU ID snapshot */
			       /* BenchLab：CPU 号快照。讲解：基准输入。 */
	u32 tick_last_run_at;  /* BenchLab: run_start snapshot */
			       /* BenchLab：运行开始时刻快照。讲解：基准输入。 */

	/* --- Cached fields (bytes 72-95) --- */
	/* --- 缓存字段（字节 72-95） --- */
	u64 tick_slice;        /* 8B — BenchLab: slice snapshot */
			       /* 8字节——BenchLab：时间片快照。讲解：基准输入。 */
	u64 cached_tctx_ptr;   /* 8B — BenchLab: arena tctx pointer */
			       /* 8字节——BenchLab：arena tctx 指针。讲解：测 arena 解引用用。 */
	u32 cached_deficit;    /* 4B — BenchLab: deficit snapshot */
			       /* 4字节——BenchLab：赤字快照。讲解：基准输入。 */
	u32 cached_packed;     /* 4B — BenchLab: packed_info snapshot */
			       /* 4字节——BenchLab：packed_info 快照。讲解：基准输入。 */

	/* --- nvcsw (bytes 96-103) --- */
	/* --- nvcsw（字节 96-103） --- */
	u64 cached_nvcsw;      /* 8B — BenchLab: nvcsw_snapshot */
			       /* 8字节——BenchLab：nvcsw 快照。讲解：测让出检测用。 */

	/* --- Padding CL1 (bytes 104-127) --- */
	/* --- CL1 填充（字节 104-127） --- */
	u8  _pad_cl1[24];     /* 24B pad to end of CL1 */
			      /* 24字节，填充到 CL1 末尾。讲解：占满第二条缓存行。 */
#endif /* !CAKE_RELEASE */
} __attribute__((aligned(CAKE_MBOX_ALIGN)));
_Static_assert(
	sizeof(struct mega_mailbox_entry) == CAKE_MBOX_SIZE,
	"mega_mailbox_entry size mismatch (64B release, 128B debug)");
/* 讲解：编译期断言邮箱结构体尺寸符合预期，布局出错立刻在编译时暴露。 */

/* Statistics shared with userspace */
/* 与用户态共享的统计数据 */
/* 讲解：BPF 侧累加这些计数，TUI 读取后展示调度器的运行状况。 */
struct cake_stats {
	u64 nr_new_flow_dispatches; /* Tasks dispatched from new-flow */
				    /* 以新流身份派发的任务数。讲解：享新流赤字加成的任务。 */
	u64 nr_old_flow_dispatches; /* Tasks dispatched from old-flow */
				    /* 以老流身份派发的任务数。讲解：赤字耗尽、正常竞争的任务。 */
	u64 nr_tier_dispatches[CAKE_TIER_MAX]; /* Per-tier dispatch counts */
					       /* 各层的派发计数。讲解：观察各层负载分布。 */
	u64 nr_starvation_preempts_tier
		[CAKE_TIER_MAX]; /* Per-tier starvation preempts */
				 /* 各层的防饿死抢占次数。讲解：反映饥饿保护触发频度。 */
	u64 total_gate1_latency_ns; /* Total time spent in Gate 1 */
				    /* Gate 1 累计耗时。讲解：最优选核路径的总开销。 */
	u64 total_gate2_latency_ns; /* Total time spent in Gate 2 */
				    /* Gate 2 累计耗时。讲解：性能排序扫描的总开销。 */
	u64 total_enqueue_latency_ns; /* Total time spent in enqueue */
				      /* enqueue 累计耗时。讲解：入队路径总开销。 */
	u64 nr_dropped_allocations; /* Count of failed scx_task_alloc requests */
				    /* 分配失败次数。讲解：arena/存储分配失败计数。 */
	u64 nr_local_dispatches;    /* Dispatched from local LLC DSQ */
				    /* 从本地 LLC DSQ 派发的次数。讲解：理想情况，无跨 LLC。 */
	u64 nr_stolen_dispatches;   /* Dispatched from remote LLC DSQ (steal) */
				    /* 从远端 LLC DSQ 偷取派发的次数。讲解：本地空时跨 LLC 取任务。 */
	u64 nr_dispatch_misses;     /* dispatch() kfunc found no work (DSQ empty after probe) */
				    /* 派发扑空次数（探测后 DSQ 为空）。讲解：无活可派。 */
	u64 nr_dispatch_hint_skip;  /* dispatch() skipped kfunc via dsq_pending hint (counter==0) */
				    /* 借 dsq_pending 提示跳过 kfunc 的次数。讲解：无待派时省一次 kfunc。 */
	u64 nr_dsq_queued;          /* Per-LLC DSQ enqueue count (for depth calc) */
				    /* 每 LLC DSQ 入队计数（用于算队深）。讲解：入队总量。 */
	u64 nr_dsq_consumed;        /* Per-LLC DSQ consume count (dispatched from DSQ) */
				    /* 每 LLC DSQ 消费计数。讲解：从 DSQ 取走的总量。 */

	/* Callback aggregate timing (cumulative ns, system-wide) */
	/* 回调累计计时（全系统累计 ns） */
	u64 total_select_cpu_ns;     /* Total time in cake_select_cpu */
				     /* cake_select_cpu 累计耗时。讲解：选核总成本。 */
	u64 total_stopping_ns;       /* Total time in cake_stopping */
				     /* cake_stopping 累计耗时。讲解：分类/暂存总成本。 */
	u64 total_running_ns;        /* Total time in cake_running */
				     /* cake_running 累计耗时。讲解：切入总成本。 */

	/* Callback max tracking (worst single invocation, ns) */
	/* 回调最大值跟踪（单次最坏耗时 ns） */
	u64 max_select_cpu_ns;       /* Worst single cake_select_cpu */
				     /* 单次最坏的 select_cpu。讲解：捕捉尾延迟。 */
	u64 max_stopping_ns;         /* Worst single cake_stopping */
				     /* 单次最坏的 stopping。讲解：捕捉尾延迟。 */
	u64 max_running_ns;          /* Worst single cake_running */
				     /* 单次最坏的 running。讲解：捕捉尾延迟。 */

	/* Stopping path breakdown (invocation counts) */
	/* stopping 路径分解（各分支调用次数） */
	u64 nr_stop_confidence_skip; /* Confidence skip — fast path (~4ns) */
				     /* 置信度跳过——快路径（约 4ns）。讲解：63/64 次走这里，不重分类。 */
	u64 nr_stop_classify;        /* PELT classify path (~14ns, was nr_stop_ewma) */
				     /* PELT 分类路径（约 14ns）。讲解：每 64 次做一次真正分类。 */
	u64 nr_stop_ramp;            /* Stability ramp (stable < 3) */
				     /* 稳定性爬坡（stable<3）。讲解：分类尚未稳定的过渡态。 */
	u64 nr_stop_miss;            /* Cold/self-seed miss path (~30ns) */
				     /* 冷/自播种缺失路径（约 30ns）。讲解：首次或缓存缺失的慢路径。 */

	/* ═══ DISPATCH CALLBACK TIMING (Phase 8: Verbose Health) ═══ */
	/* ═══ dispatch 回调计时（阶段 8：详细健康度） ═══ */
	u64 total_dispatch_ns;       /* Total time in cake_dispatch */
				     /* cake_dispatch 累计耗时。讲解：派发总成本。 */
	u64 max_dispatch_ns;         /* Worst single cake_dispatch */
				     /* 单次最坏的 dispatch。讲解：捕捉派发尾延迟。 */

	/* ═══ EEVDF TOPOLOGY TELEMETRY ═══ */
	/* ═══ EEVDF 与拓扑相关遥测 ═══ */
	u64 nr_vprot_suppressed;     /* Kicks suppressed by vprot guard */
				     /* 被 vprot 保护抑制的抢占次数。讲解：避免微切片而未抢占的计数。 */
	u64 nr_lag_applied;          /* Enqueues where sleep_lag credit was used */
				     /* 用到睡眠滞后积分的入队次数。讲解：让出者获优先派发的计数。 */
	u64 nr_capacity_scaled;      /* Stops where CPU capacity < 1024 (P/E active) */
				     /* CPU 容量<1024（P/E 生效）的 stop 次数。讲解：异构核 vtime 缩放触发计数。 */
} __attribute__((aligned(64)));

/* Default values (Gaming profile) */
/* 默认值（gaming 配置） */
#define CAKE_DEFAULT_QUANTUM_NS (2 * 1000 * 1000) /* 2ms */
						  /* 默认基础时间片 2ms。讲解：gaming 配置的平衡取值。 */
#define CAKE_DEFAULT_NEW_FLOW_BONUS_NS (3 * 1000 * 1000) /* 3ms — EEVDF half-slice */
							 /* 新流赤字加成 3ms（约 EEVDF 半个时间片）。讲解：让新唤醒任务抢先一次。 */

/* ═══ ADAPTIVE QUANTUM — YIELD-GATED (Phase 4.0) ═══
 * Per-task runtime-proportional quantum modulated by voluntary yield signal.
 * Yielders (nvcsw > 0 since last stop) get generous headroom + high ceiling.
 * Non-yielders get tight headroom + low ceiling, forcing faster CPU release.
 *
 * Quantum = clamp(pelt_scaled × HEADROOM, MIN, MAX/CEILING)
 * Yielders: game render, audio, input, network → 50ms ceiling (cooperators)
 * Non-yielders: compilation, background tasks → PELT × 1, capped 2ms */
/* ═══ 自适应时间片——由让出信号门控（阶段 4.0） ═══
 * 每任务的时间片与其运行时长成比例，并由自愿让出信号调节。
 * 让出者（自上次 stop 后 nvcsw>0）获得宽裕余量 + 高上限。
 * 非让出者获得紧凑余量 + 低上限，迫使其更快释放 CPU。
 *
 * 时间片 = clamp(pelt 缩放值 × 余量, 最小值, 最大值/上限)
 * 让出者：游戏渲染、音频、输入、网络 → 50ms 上限（合作型）
 * 非让出者：编译、后台任务 → PELT × 1，封顶 2ms */
/* 讲解：核心思想是奖励合作让出的任务、约束霸占 CPU 的任务，从而制造更多抢占点。 */
#define AQ_BULK_HEADROOM     1               /* 1× PELT runtime for non-yielders */
					     /* 非让出者余量倍数 = 1×PELT。讲解：不给额外余量，尽快释放。 */
#define AQ_MIN_NS            (50 * 1000)     /* 50µs floor — below this overhead > work */
					     /* 时间片下限 50µs。讲解：再小则切换开销超过有效工作。 */
#define AQ_YIELDER_CEILING_NS (50 * 1000000)  /* 50ms ceiling — yielders (covers 20fps+) */
					      /* 让出者上限 50ms（覆盖 20fps 以上）。讲解：反正会在 vsync 让出，不会真跑满。 */
#define AQ_BULK_CEILING_NS        (2 * 1000000)   /* 2ms ceiling — non-yielders (forces release) */
						  /* 非让出者上限 2ms。讲解：强制其频繁释放 CPU。 */
#define AQ_BULK_CEILING_COMPILE_NS (8 * 1000000)   /* 8ms ceiling — COMPILATION state only (reduce ctx-switch overhead) */
						   /* 编译态专用上限 8ms。讲解：编译时放宽以减少上下文切换开销。 */

/* Scheduler operating state — set by Rust TUI, read by BPF hot path.
 * Priority: GAMING > COMPILATION > IDLE.
 * Written to sched_state BSS u32 by userspace, read-only from BPF. */
/* 调度器运行状态——由 Rust TUI 设置，BPF 热路径读取。
 * 优先级：GAMING > COMPILATION > IDLE。
 * 由用户态写入 sched_state 这个 BSS u32，BPF 侧只读。 */
/* 讲解：整个调度行为（类别、权重、时间片上限、频率提升）都随该状态切换。 */
#define CAKE_STATE_IDLE        0  /* Fair, unthrottled — desktop/browsing */
				  /* 空闲态：公平、不限流——桌面/浏览。讲解：基线行为，仅 NORMAL/HOG。 */
#define CAKE_STATE_COMPILATION 1  /* Compile jobs: 8ms bulk ceiling, no squeeze */
				  /* 编译态：批处理上限 8ms，不压制。讲解：为构建局部性做集群协同调度。 */
#define CAKE_STATE_GAMING      2  /* Game mode: HOG+bg squeeze, Gate 1P active */
				  /* 游戏态：压制 HOG+后台，启用 Gate 1P。讲解：完整优先级系统生效。 */

/* Gate 1C-P / Gate 1P: adaptive preemption thresholds.
 * STANDARD: 100µs — hog has done meaningful work before yielding to normal tasks.
 *           Below this, preemption context-switch cost (~1.5µs) exceeds benefit.
 * VIP:       50µs — game-family threads (wineserver, WoW workers) get aggressive
 *           preemption to avoid cold-cache migration. WoW data showed wineserver
 *           at 125 MIG/s because the standard threshold blocked reclaiming its home
 *           CPU from hogs that ran <100µs. 50µs ensures the hog got a reasonable
 *           quantum while the VIP avoids the ~10-40ns L3 penalty of migration.
 *           Selected via STAGED_BIT_GAME_MEMBER (already in register, ~0ns). */
/* Gate 1C-P / Gate 1P：自适应抢占阈值。
 * 标准：100µs——大户先干够有意义的活，再让给普通任务。
 *       低于此值，抢占的上下文切换成本（约 1.5µs）超过收益。
 * VIP：50µs——游戏家族线程（wineserver、WoW 工作线程）采用更激进的抢占，
 *       以避免冷缓存迁移。WoW 实测中 wineserver 迁移达 125 次/秒，正是因为
 *       标准阈值阻止它从跑不到 100µs 的大户手里收回归属 CPU。50µs 既保证
 *       大户拿到合理时间片，又让 VIP 避免约 10-40ns 的 L3 迁移代价。
 *       通过 STAGED_BIT_GAME_MEMBER 选择（已在寄存器里，约 0ns）。 */
/* 讲解：对游戏关键线程用更低的抢占门槛，快速夺回其“家”CPU，减少代价高昂的迁移。 */
#define CAKE_PREEMPT_YIELDER_THRESHOLD_NS (100 * 1000) /* 100µs — normal tasks */
						       /* 普通任务抢占阈值 100µs。讲解：平衡收益与切换成本。 */
#define CAKE_PREEMPT_VIP_THRESHOLD_NS      (50 * 1000) /*  50µs — game family VIPs */
						       /* 游戏家族 VIP 抢占阈值 50µs。讲解：更激进以减少迁移。 */

#endif /* __CAKE_INTF_H */
