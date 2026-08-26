# scx_rusty

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

A multi-domain, BPF / user space hybrid scheduler. The BPF portion of the
scheduler does a simple round robin in each domain, and the user space portion
(written in Rust) calculates the load factor of each domain, and informs BPF of
how tasks should be load balanced accordingly.

## How To Install

Available as a [Rust crate](https://crates.io/crates/scx_rusty): `cargo add scx_rusty`

## Typical Use Case

`scx_rusty` is designed to be flexible, accommodating different architectures and
workloads. Various load balancing thresholds (e.g. greediness, frequency, etc),
as well as how `scx_rusty` should partition the system into scheduling domains, can
be tuned to achieve the optimal configuration for any given system or workload.

## Production Ready?

Yes. If tuned correctly, `scx_rusty` should be performant across various CPU
architectures and workloads. By default, `scx_rusty` creates a separate scheduling
domain per-LLC, so its default configuration may be performant as well. Note
however that `scx_rusty` does not yet disambiguate between LLCs in different NUMA
nodes, so it may perform better on multi-CCX machines where all the LLCs share
the same socket, as opposed to multi-socket machines.

Note as well that you may run into an issue with infeasible weights, where a
task with a very high weight may cause the scheduler to incorrectly leave cores
idle because it thinks they're necessary to accommodate the compute for a
single task. This can also happen in CFS, and should soon be addressed for
`scx_rusty`.
`scx_rusty` 是一个 **多域（multi-domain）、BPF + 用户态混合** 的 `sched_ext` 调度器。BPF 负责热路径上的选核、入队和域内调度；用户态负责较慢的负载计算和跨域迁移决策。工作守恒（work conservation）主要靠 BPF 里的 **greedy 临时窃取**，长期均衡靠用户态 **改写 `target_dom`**。

---

## 一、总体设计与特点

### 1. 按拓扑切域，域内简单、域间复杂

默认按 **LLC（L3）** 建域（也可用 `--cpumasks` 手工划分）。每个域有：

- 自己的 DSQ（dispatch queue），ID 就是 `dom_id`
- 自己的 CPU 集合、所属 NUMA 节点
- 按权重分桶的 duty-cycle 负载

域内调度很轻：默认是 **带交互性加权的 vtime/deadline**，也可 `--fifo-sched`。跨域才引入负载均衡和工作窃取。

拓扑假设比较强：文档写明当前假定 **各域算力相近、彼此距离相近**；默认按 LLC 切，但 **还不区分不同 NUMA 上的 LLC**，多 socket 上可能不如同 socket 多 CCX。

### 2. 两层时间尺度，刻意把开销放在用户态低频路径

| 路径 | 周期 | 职责 |
|------|------|------|
| BPF 热路径 | 每次 wakeup / enqueue / dispatch | 选核、域内排队、**临时** greedy 窃取 |
| Tuner | 默认 100ms | 根据利用率标出“可以去偷/被踢醒”的 CPU，并切换 slice |
| LoadBalancer | 默认 2s | 看域负载差，挑选任务 **永久改域** |

注释里的设计意图是：负载均衡不必很勤，work-conservation 靠 tuning + greedy 维持；用户态只读每域聚合指标，再对过载域最多扫 **1024** 个最近活跃任务。

### 3. 混合调度的核心契约

- BPF 维护：任务权重、可运行域掩码、当前域、duty cycle、活跃任务环
- 用户态决定：谁该迁到哪个域，写 `task_ctx.target_dom`
- BPF 在后续 `enqueue` 里应用迁移（`dom_xfer_task` 把 duty cycle 一起带走）

历史上这类调度器在 6-chiplet AMD 上能接近当时的 CFS。它被标成 production-ready，但有已知问题：**infeasible weight**（极高权重任务会让调度器误以为必须留核给它，从而让核空闲）。

### 4. 工作守恒拆成“临时偷”和“永久搬”

这是 rusty 最有特点的一点：

- **Greedy execution（工作窃取）**：任务仍属于原域，只是跑到别的空闲核上。便宜、快、可逆。
- **Load balance（负载均衡）**：改 `target_dom`，任务换家。贵、慢、考虑 NUMA 成本。

偷完还要能“送回去”（repatriate），否则任务会长期漂在外域，打坏局部性。

---

## 二、实现结构

```
用户态 (Rust)                         BPF (C)
─────────────                         ──────
main.rs  主循环 / 参数
domain.rs  DomainGroup（LLC→域）
tuner.rs  100ms：direct/kick mask、slice
load_balance.rs  2s：层次化 LB
stats.rs  指标

                                      rusty_select_cpu   选核 + DIRECT_GREEDY
                                      rusty_enqueue      入队 + 迁域 + KICK_GREEDY
                                      rusty_dispatch     本域 DSQ + greedy steal
                                      runnable/running/  负载、vtime、活跃任务环
                                      stopping/quiescent
```

### 域的建立

`DomainGroup::new()`：无 `--cpumasks` 时遍历 `Topology` 的 NUMA → LLC，每个 LLC 一个域，域 ID 连续（LLC ID 可能有洞）。初始化时写入 BPF rodata：`cpu_dom_id_map`、`dom_cpumasks`、`numa_cpumasks`、`dom_numa_id_map`。每个域 `scx_bpf_create_dsq(dom_id, node_id)`。

任务进系统时 `task_pick_domain()` 从当前 CPU 的 RR 起点扫域，找与 `cpus_ptr` 相交的第一个域；若开了 `mempolicy_affinity`，优先 mempolicy 对应节点上的域。

### 域内调度：vtime + 交互性 deadline

非 FIFO 时，入队用 `scx_bpf_dsq_insert_vtime`。deadline 来自 `task_compute_dl()`，思路接近 lavd：

- `waker_freq`：当生产者的频率  
- `blocked_freq`：当消费者的频率  
- `freq_factor ≈ blocked * waker²`，再按权重放大  
- 减去（按权重惩罚的）平均运行时间  
- 映射到 nice 表得到 `lat_scale`，再反比缩放 `avg_runtime`

长时间睡眠的任务最多攒 **一个 slice** 的 vruntime 盈余（`clamp_task_vtime`），避免睡一天后霸占 CPU。

Tuner 按整机是否打满切换 slice：空闲默认 20ms，打满默认 1ms。

### 负载怎么记

BPF 不直接算“load”，只记 **duty cycle**：

- 任务：`ravg` 跟踪 runnable 时间  
- 域：权重映射到 100 个 bucket，bucket 里累加 runnable 任务数，再做半衰期平均（默认 1s）

用户态 `LoadAggregator` 读这些 bucket：未打满时用 `duty_cycle * 100`；打满时用 `weight * duty_cycle`，并处理 infeasible weight。

---

## 三、工作窃取：三条 BPF 路径 + 一层用户态调节

代码里不叫 work stealing，叫 **greedy**。目标是：本域没空闲核时，别让别的核闲着；但尽量先核内、先 LLC、先 NUMA。

整体是 **push + kick + pull** 三件套：

```
任务 wakeup
    │
    ├─ select_cpu：本域有闲核？直接放上去
    │         本域满了？DIRECT_GREEDY 推到低利用率闲核（临时）
    │
    └─ enqueue：进本域 DSQ
              └─ KICK_GREEDY：踢醒一个低利用率闲核
                        │
                        ▼
              被踢醒的 CPU 进入 dispatch
                        │
                        ├─ 先吃自己域的 DSQ
                        └─ 没有再 greedy steal 别人域的 DSQ（临时）
```

Tuner（100ms）决定 **哪些 CPU 允许参与 greedy**。

### 1. Tuner：谁可以被偷、谁该被踢

`tuner.rs` 用 procfs 算每 CPU、每域利用率：

- 域利用率 < `direct_greedy_under`（默认 90%）→ 加入 `direct_greedy_cpumask`  
- 域利用率 < `kick_greedy_under`（默认 100%，即几乎总开）→ 加入 `kick_greedy_cpumask`  
- 整机 `avg_util >= 0.99999` → `fully_utilized`，缩短 slice，LB 开始按真实权重算

写进 `tune_input`，BPF `refresh_tune_params()` 在 `select_cpu` 里看到 generation 变化后刷新全局和每域 mask。

含义：只有 **还不太忙的域** 才接外来任务，避免把已经很忙的 LLC 再砸一遍。打满后 DIRECT_GREEDY 会自然收紧。

### 2. DIRECT_GREEDY：唤醒时把任务推到外域闲核（push）

`rusty_select_cpu` 的优先级大致是：

1. 单 CPU 绑定 → 直接上该核（kthread 可走 local DSQ）  
2. `WAKE_SYNC`：waker 域里有闲核则同步唤醒到 prev 或 waker CPU  
3. prev 在本域且整个物理核空闲 → 留 prev（`PREV_IDLE`）  
4. prev 在外域，但该核在 `direct_greedy_cpumask` 且物理核空闲 → **继续留在外域**（`GREEDY_IDLE`）。这是“上次被偷走，这次还接着跑”，保持缓存热度。  
5. 本域空闲物理核 / 空闲 prev / 任意本域闲 CPU → 直接派发（`DIRECT_DISPATCH`）  
6. 本域没空闲，且任务 `all_cpus`（未被 cpuset 限制）→ **DIRECT_GREEDY**

DIRECT_GREEDY 的搜索顺序：

1. 先要空闲 **物理核**（`SCX_PICK_IDLE_CORE`），再退到任意闲 CPU  
2. 先本域的 `lb_domain->direct_greedy_cpumask`，再跨域的 `tmp_direct_greedy`  
3. 默认 **不跨 NUMA**（`--direct-greedy-numa` 才允许）；跨域用 `node_cpumask ∩ direct_greedy_cpumask`

命中后设 `dispatch_local = true`，`enqueue` 直接进 `SCX_DSQ_LOCAL`。  
**任务的 `target_dom` 不变**——只是借用外域的核。

统计上：同节点外域是 `DIRECT_GREEDY`，更远是 `DIRECT_GREEDY_FAR`。

### 3. KICK_GREEDY：入队后踢醒外域闲核去偷（kick-to-pull）

若 `select_cpu` 没找到闲核，任务进本域 DSQ。若任务 `all_cpus`，`enqueue` 会：

```c
cpu = bpf_cpumask_any_and_distribute(kick_greedy_cpumask, idle_cpumask);
scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
```

被踢醒的 CPU 走 `dispatch`：先消费自己域，没有再去偷刚入队的那个任务。

注释写得很明确：DIRECT_GREEDY 和 KICK_GREEDY 目的相近，但：

- DIRECT_GREEDY 把任务 **直接放到** 外域 CPU 上  
- KICK_GREEDY 只 **叫醒** 外域 CPU，让它先顾自己再偷  

高负载下 DIRECT_GREEDY 可能伤吞吐（把任务推到已经不该接活的地方），KICK_GREEDY 更贵但更稳，中高利用率仍能改善 work-conservation。所以默认 kick 阈值是 100%（几乎总开），direct 阈值是 90%。

### 4. `rusty_dispatch`：空闲 CPU 主动去偷（pull）

这是最接近经典 work stealing 的路径：

```1341:1398:scheds/rust/scx_rusty/src/bpf/main.bpf.c
void BPF_STRUCT_OPS(rusty_dispatch, s32 cpu, struct task_struct *prev)
{
	u32 curr_dom = cpu_to_dom_id(cpu), dom;
	// ...
	if (scx_bpf_dsq_move_to_local(curr_dom, 0)) {
		stat_add(RUSTY_STAT_DSQ_DISPATCH, 1);
		return;
	}

	if (!greedy_threshold)
		return;
	// 同 NUMA 其它域：RR 扫描，move_to_local
	// 若 greedy_threshold_x_numa：再扫跨 NUMA
}
```

顺序：

1. **先吃自己域 DSQ**（`GREEDY` 之前的正常路径，`DSQ_DISPATCH`）  
2. `greedy_threshold == 0` 则完全关闭窃取  
3. 用 per-CPU `dom_rr_cur` **轮转**扫其它域，避免总偷同一个受害者  
4. 先同 NUMA（`GREEDY_LOCAL`），再跨 NUMA（`GREEDY_XNUMA`）

被偷的任务进该 CPU 的 local DSQ 跑起来，**域归属不变**。下次时间片用完，会走 repatriate。

`--greedy-threshold` 默认 1：用户态注释说“对方域队列里至少这么多任务才偷”。实现上：

- **同 NUMA**：只当开关用，非 0 就扫，**没有**用队列长度做门槛  
- **跨 NUMA**：默认 0（关）。开启后条件是  
  `scx_bpf_dsq_nr_queued(dom) >= greedy_threshold_x_numa` 则 `continue` 跳过  

也就是说跨 NUMA 实际是在 **队列短于阈值** 时才尝试 steal，和注释里“至少 N 个才偷”相反。同 NUMA 也没实现“至少 N 个”的门槛。若按注释理解，同 NUMA 应在 `nr_queued >= greedy_threshold` 时才 `move_to_local`，跨 NUMA 的比较方向也应反过来。

### 5. 归还：临时偷必须可逆

`enqueue` 里如果任务当前 CPU 不在本域 cpumask 上（上次 greedy 跑到外域，slice 用完再入队），会：

```c
scx_bpf_kick_cpu(domestic_cpu, 0);
stat_add(RUSTY_STAT_REPATRIATE, 1);
```

任务仍排进 **本域 DSQ**，并踢醒本域 CPU。这样：

- 本域有活了会优先回家（局部性）  
- 本域暂时没空、外域仍闲，dispatch steal 还可以再偷回来  

`select_cpu` 的 `GREEDY_IDLE` 是另一面：若外域核仍闲且仍在 direct_greedy 集合里，wakeup 可以继续留在外域，避免无意义来回跳。

### 6. 和“永久搬迁”的分工

| | Greedy 窃取 | Userspace LB |
|--|--|--|
| 触发 | 每次调度 | ~2s |
| 改 `target_dom` | 否 | 是 |
| 局部性 | 尽量 NUMA 内、低利用率域 | 先跨 NUMA 再域内，阈值更严 |
| 目的 | 别让核闲着 | 长期负载摊平 |
| 可选关闭 | `--greedy-threshold 0` | `--no-load-balance` |

LB 的层次：Root → NumaNode → Domain → Task。跨 NUMA 失衡阈值是平均负载的 **17%**，域内是 **5%**（跨 NUMA 更贵）。每次最多推走失衡量的 50%，目标转移量是双方失衡绝对值最小值的 50%。选任务时在按 load 排好的列表上，找最接近目标转移量、且能在目标域跑的任务；先试 `preferred_dom_mask`（mempolicy），再任意可运行域。kworker 可用 `--balanced-kworkers` 排除，避免和内核 L3 均衡打架。

`running` 里把任务记进域的 `active_tasks` 环（最多 1024），LB 只看最近一代活跃任务，best-effort。

---

## 四、设计上的取舍

1. **局部性默认，work-conservation 用 greedy 补**  
   任务有 home domain（LLC）。偷是借用，不是搬家。这比每次 wakeup 全局找最闲核更稳。

2. **Push 有利用率闸门，Pull 几乎总开**  
   把任务推进忙域代价高（DIRECT_GREEDY 有 90% 闸）；空闲 CPU 自己去偷代价低（kick 默认全开，dispatch 同 NUMA 无队列门槛）。

3. **NUMA 是硬边界，LLC 是软边界**  
   跨 LLC 临时偷默认允许；跨 NUMA 的 direct greedy、dispatch steal 都默认关或需显式打开。LB 跨 NUMA 要用更高失衡才搬。

4. **用户态决策、BPF 执行**  
   BPF 热路径不做复杂最优化；2s 一次的 Rust 代码可以建层次、算 infeasible weight、挑 victim。

5. **已知限制**（文档和代码都承认）  
   域算力/距离同质假设；infeasible weight；LB 不考虑 cgroup / “这个域更适合隔离”等多元代价；`active_tasks` 可能挑错 victim，靠下一轮重试。

---

## 五、工作窃取相关的实现细节

`enqueue` 注释写的是：用户态写好 `target_dom` 后，BPF 在入队时迁过去。`task_set_domain()` 的契约是：**`target_dom` 表示当前域，参数 `new_dom_id` 才是目的域**。当前调用是：

```c
if (domc->id != taskc->target_dom &&
    task_set_domain(p, domc->id, false))
```

用户态 `transfer_load()` 只改 `target_dom` 为目的域，`domc` 指针仍指向旧域。按 `task_set_domain` 的契约，这里传入的是旧域 ID，会把 `target_dom` 当“源”、旧域当“目的”，和注释中的迁域方向不一致。真正生效的跨域 **临时** 均衡，仍然主要靠上面的 greedy 三条路径。

---

**一句话**：rusty 把机器切成 LLC 域，域内做加权 vtime；跨域用“快路径 greedy 临时偷 + 慢路径用户态永久搬”。工作窃取是 push（DIRECT_GREEDY）+ kick（KICK_GREEDY）+ pull（dispatch RR steal），并用 Tuner 的利用率 mask 限制谁能接活，从而在局部性和 work-conservation 之间做折中。