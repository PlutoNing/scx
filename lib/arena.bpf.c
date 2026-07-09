/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/arena.h>
#include <lib/percpu.h>
#include <lib/cpumask.h>
#include <lib/topology.h>
#include <lib/rbtree.h>
#include <lib/atq.h>

/*
 * "System-call" based API for arenas.
 */
/* arena.bpf.c 是整个 scx arena 子系统的用户态调用入口文件（"系统调用层"）。
它把内部各子模块的初始化函数包装成一组 SEC("syscall") BPF 程序，让用户态可以通过
BPF_PROG_RUN 在程序加载后、调度器启动前，按顺序完成 arena 各组件的初始化。
用户态进程
   │
   ├─ BPF_PROG_RUN(arena_init)             ← 第一步：核心资源初始化
   ├─ BPF_PROG_RUN(arena_topology_init)    ← 第二步：拓扑层级配置
   ├─ BPF_PROG_RUN(arena_topology_node_init) × N ← 第三步：逐节点初始化
   ├─ BPF_PROG_RUN(arena_alloc_mask)       ← 按需：分配 CPU 位图
   └─ BPF_PROG_RUN(arena_topology_print)   ← 调试：打印拓扑树
 */
struct task_ctx;

SEC("syscall")
int arena_init(struct arena_init_args *args)
{
	int ret;

	/* 静态分配器
scx_static_init
Bump 分配器，分配全局静态数据 */
	ret = scx_static_init(args->static_pages);
	if (ret)
		return ret;

	if (nr_cpu_ids == NR_CPU_IDS_UNINIT) {
		bpf_printk("uninitialized nr_cpu_ids variable");
		return -ENODEV;
	}

	/* How many types to store all CPU IDs? */
	/* CPU 位图
scx_bitmap_init
scx_bitmap_t，arena 内的 CPU 掩码 */
	ret = scx_bitmap_init(div_round_up(nr_cpu_ids, 8));
	if (ret) {
		bpf_printk("scx_bitmap_init failed with %d", ret);
		return ret;
	}

	/* Per-CPU 存储
scx_percpu_storage_init
每个 CPU 的临时工作缓冲区 */
	ret = scx_percpu_storage_init();
	if (ret) {
		bpf_printk("scx_percpu_storage_init failed with %d", ret);
		return ret;
	}

	/* 任务上下文
scx_task_init
每个任务的调度器私有数据结构 */
	ret = scx_task_init(args->task_ctx_size);
	if (ret) {
		bpf_printk("scx_task_init failed with %d", ret);
		return ret;
	}

	/* 红黑树
scx_rb_init
arena 内的红黑树对象池 */
	ret = scx_rb_init();
	if (ret) {
		bpf_printk("scx_rb_init failed with %d", ret);
		return ret;
	}

	/* ATQ
scx_atq_init
Atomic Task Queue，无锁任务队列 */
	ret = scx_atq_init();
	if (ret) {
		bpf_printk("scx_atq_init failed with %d", ret);
		return ret;
	}

	return 0;
}

/* 在 arena 内分配一个 scx_bitmap_t（CPU 位图），并把它的 bits 字段地址通过 args->bitmap 返回给用户态。

args->bitmap = (u64)&bitmap->bits：返回的不是 bitmap 本身的地址，而是其内部 bits 数组的地址。这样用户态拿到的是一个"裸位图指针"，后续传给 arena_topology_node_init 时再通过 container_of 还原出完整的 struct scx_bitmap *。这种设计的好处是接口不暴露内部结构体类型。

scx_bitmap_t 的类型定义（来自 cpumask.h）：

typedef struct scx_bitmap __arena * __arg_arena scx_bitmap_t;
三重修饰：__arena 修饰指针（arena 地址空间），__arg_arena 修饰函数参数（验证器规则），* 本身是指针。 */
SEC("syscall")
int arena_alloc_mask(struct arena_alloc_mask_args *args)
{
	scx_bitmap_t bitmap;

	bitmap = scx_bitmap_alloc();
	if (!bitmap)
		return -ENOMEM;

	args->bitmap = (u64)&bitmap->bits;

	return 0;
}

/* 设置拓扑树每层节点的最大子节点数。 拓扑层级定义（来自 topology.h）：
TOPO_TOP  (0) — 整个系统（唯一根节点）
TOPO_NODE (1) — NUMA Node
TOPO_LLC  (2) — Last Level Cache
TOPO_CORE (3) — 物理核
TOPO_CPU  (4) — 逻辑 CPU（超线程）
用户态在调用前需要探测好硬件拓扑（例如 /sys/devices/system/cpu/ 或 libnuma），
计算出每层的最大子节点数后传入。
为什么不用循环？ 注释已解释：SEC("syscall") 的上下文指针（args）不允许变量偏移访问
（BPF 验证器限制），只能用常量索引 [0]、[1]... 手工展开，_Static_assert 保证展开数量
与 TOPO_MAX_LEVEL 同步。
topo_max_children[] 是全局 arena 变量，后续所有 topo_init 调用会用它来决定分配多大的
 struct topology（含变长子节点指针数组 children[]）。 */
SEC("syscall")
int arena_topology_init(struct arena_topology_init_args *args)
{
	/*
	 * Variable-offset access into a SEC("syscall") context pointer is
	 * disallowed by the BPF verifier. Access each element with a constant
	 * index to avoid the restriction.
	 */
	_Static_assert(TOPO_MAX_LEVEL == 5, "unroll below must match TOPO_MAX_LEVEL");
	topo_max_children[0] = args->max_children[0];
	topo_max_children[1] = args->max_children[1];
	topo_max_children[2] = args->max_children[2];
	topo_max_children[3] = args->max_children[3];
	topo_max_children[4] = args->max_children[4];

	return 0;
}

/* arena_topology_node_init —— 初始化单个拓扑节点 */
SEC("syscall")
int arena_topology_node_init(struct arena_topology_node_init_args *args)
{
	scx_bitmap_t bitmap = (scx_bitmap_t)container_of(args->bitmap, struct scx_bitmap, bits);
	int ret;

	ret = topo_init(bitmap, args->data_size, args->id);
	if (ret)
		return ret;

	return 0;
}

/* 调试用途，遍历整个拓扑树并通过 bpf_printk 输出，可在 trace_pipe 中查看。

scx_arena_subprog_init() 是一个初始化调用，确保在调用子函数（subprog）之前
 arena 的上下文被正确设置，这是 BPF 子程序机制的要求。 */
SEC("syscall")
int arena_topology_print(void)
{
	scx_arena_subprog_init();

	topo_print();

	return 0;
}
