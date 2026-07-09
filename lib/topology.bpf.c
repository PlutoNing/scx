#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/cpumask.h>
#include <lib/topology.h>

volatile topo_ptr topo_all;

/* 这个文件是 sched_ext (scx) BPF 调度器框架的内核侧 CPU 拓扑管理库，
运行在 eBPF 虚拟机中。它的职责是：在 BPF 程序里构建并查询一棵描述服务器硬件
 CPU 层级关系的树，让调度器能感知 NUMA、LLC、Core 等拓扑边界，
 从而做出更优的调度决策。 */
/*
 * XXXETSAL: This is a (hopefully) temporary measure that
 * makes it easier to integrate with existing schedulers that
 * use arbitrary IDs to index CPUs/LLCs/nodes. In the future we
 * will just keep a CPU id to CPU topology node array, but for
 * now we will have an array for each level.
 */
 /* topo_nodes[level][id]：O(1) 查找——给定层级和节点 id，直接取到对应的 topo_ptr
nr_topo_nodes[level]：记录每层节点总数 */
u64 topo_nodes[TOPO_MAX_LEVEL][NR_CPUS];

int nr_topo_nodes[TOPO_MAX_LEVEL];

/*
 * Per-level maximum number of children. Set by arena_topology_init() before
 * any topo_init() calls. Each topology node at level L is allocated with
 * topo_max_children[L] child pointer slots.
 */
u32 topo_max_children[TOPO_MAX_LEVEL];

__hidden
int topo_contains(topo_ptr topo, u32 cpu)
{
	return scx_bitmap_test_cpu(cpu, topo->mask);
}

static
int topo_subset(topo_ptr topo, scx_bitmap_t mask)
{
	return scx_bitmap_subset(topo->mask, mask);
}

/* 分配并初始化一个节点

关键点：
在 BPF arena 内分配 struct topology + max_children * ptr 大小的连续内存
level_ids[] 把祖先链上每层的 id 都缓存下来，快速路径不必回溯父节点
用双重边界检查 + barrier_var() 对抗 BPF verifier 的代码消除*/
static
topo_ptr topo_node(topo_ptr parent, scx_bitmap_t mask, s16 id)
{
	volatile topo_ptr topo; /* add volatile to satisfy the verifier. */
	u32 level = parent ? parent->level + 1 : 0;
	u32 max_ch;
	int i;

	if (level >= TOPO_MAX_LEVEL) {
		bpf_printk("topology is too deep");
		return NULL;
	}

	if (id < 0 || id >= NR_CPUS) {
		bpf_printk("invalid node id");
		return NULL;
	}

	max_ch = topo_max_children[level];
	topo = scx_static_alloc(sizeof(struct topology) + max_ch * sizeof(topo_ptr), 1);
	if (!topo) {
		bpf_printk("static allocation failed");
		return NULL;
	}

	topo->parent = parent;
	topo->nr_children = 0;
	topo->level = level;
	/*
	 * The passed-in mask is deliberately consumed; topo_node takes ownership.
	 * Do not reuse the same mask elsewhere after this call.
	 */
	topo->mask = mask;

	/*
	 * Re-assert bounds for the verifier. barrier_var() prevents the compiler
	 * from treating these checks as dead code (since level/id are local
	 * variables that it knows were already checked above). Without it, clang
	 * eliminates the re-check, and the verifier loses the narrowed bounds
	 * after scx_static_alloc().
	 */
	barrier_var(level);
	barrier_var(id);
	if (level >= TOPO_MAX_LEVEL || id < 0 || id >= NR_CPUS)
		return NULL;

	/*
	 * Populate level_ids: levels below this node are copied from the
	 * parent, this node's own level gets id, levels above are -EINVAL.
	 */
	bpf_for(i, 0, TOPO_MAX_LEVEL) {
		if (i < (int)level && parent)
			topo->level_ids[i] = parent->level_ids[i];
		else if (i == (int)level)
			topo->level_ids[i] = id;
		else
			topo->level_ids[i] = -EINVAL;
	}

	topo_nodes[level][id] = (u64)topo;

	return topo;
}


static __noinline
int topo_add(topo_ptr parent, scx_bitmap_t mask, s16 id)
{
	topo_ptr child;

	if (unlikely(!mask)) {
		bpf_printk("NULL mask pointer");
		return -EINVAL;
	}

	if (parent->level >= TOPO_MAX_LEVEL) {
		bpf_printk("topology tree is too deep");
		return -EINVAL;
	}

	if (parent->nr_children >= topo_max_children[parent->level]) {
		bpf_printk("topology fanout is too large");
		return -EINVAL;
	}

	child = topo_node(parent, mask, id);
	if (!child)
		return -ENOMEM;

	parent->children[parent->nr_children++] = child;

	return 0;
}

/* 参数 struct arena_topology_node_init_args：

bitmap：之前通过 arena_alloc_mask 分配的位图的 bits 地址（用 container_of 还原）。
data_size：该节点关联的用户自定义数据结构大小（struct topology 内的 void *data 指向的对象大小）。
id：拓扑节点 ID（在该层级内的唯一编号）。
container_of(args->bitmap, struct scx_bitmap, bits) 还原 scx_bitmap_t：

args->bitmap                  ← bits字段的地址
  │
  │ - offsetof(struct scx_bitmap, bits)
  │
  ▼
struct scx_bitmap *           ← bitmap结构体起始地址
topo_init 会在 arena 内分配 struct topology（含 topo_max_children[level] 个子节点指针槽）并初始化，插入全局拓扑树。用户态需要按从根到叶的顺序逐层调用，每个物理拓扑节点（NUMA Node、LLC、Core、CPU）调用一次。 */

/* 用户态驱动的拓扑树插入入口
插入算法是自适应位图包含关系匹配：

从根节点出发，逐层检查当前节点的每个子节点
若新 mask ⊆ 某子节点的 mask → 进入该子节点继续递归
若新 mask 与某子节点的 mask 相交但不包含 → 报错（拓扑矛盾）
若不属于任何子节点 → 直接挂在当前层节点下 */
__weak
int topo_init(scx_bitmap_t __arg_arena mask, u64 data_size, s16 id)
{
	/* Initializing the child to appease the verifier. */
	topo_ptr topo, child = NULL;
	int i, j, ret;

	topo = topo_all;
	if (!topo_all) {
		topo_all = topo_node(NULL, mask, id);
		if (!topo_all) {
			bpf_printk("couldn't initialize topology");
			return -EINVAL;
		}

		return 0;
	}

	for (i = 0; i < TOPO_MAX_LEVEL && can_loop; i++) {
		if (!topo_subset(topo, mask)) {
			bpf_printk("mask not a subset of a topology node");
			topo_print();
			return -EINVAL;
		}

		for (j = 0; j < topo->nr_children && can_loop; j++) {
			child = topo->children[j];
			if (topo_subset(child, mask))
				break;

			if (scx_bitmap_intersects(child->mask, mask)) {
				bpf_printk("partially intersecting topology nodes");
				return -EINVAL;
			}
		}

		/*
		 * If we don't fit in any child, we belong right below the
		 * parent topology node.
		 */
		if (j == topo->nr_children) {
			ret = topo_add(topo, mask, id);
			if (ret)
				return ret;
			nr_topo_nodes[i]++;
			return 0;
		}

		if (!child) {
			bpf_printk("child is not valid");
			return 0;
		}

		topo = child;
	}

	topo->data = NULL;
	if (data_size) {
		topo->data = scx_static_alloc(data_size, 1);
		if (!topo->data)
			return -ENOMEM;
	}

	bpf_printk("topology is too deep");
	return -EINVAL;
}

/* 从某节点出发，向下找包含该 cpu 的叶节点 */
__weak
topo_ptr topo_find_descendant(topo_ptr topo, u32 cpu)
{
	topo_ptr child;
	int lvl, i;

	if (!topo_contains(topo, cpu)) {
		bpf_printk("missing cpu from topology");
		return NULL;
	}

	for (lvl = 0; lvl < TOPO_MAX_LEVEL && can_loop; lvl++) {
		if (topo->nr_children == 0)
			return topo;

		for (i = 0; i < topo->nr_children && can_loop; i++) {
			child = topo->children[i];
			if (topo_contains(child, cpu))
				break;
		}

		if (i == topo->nr_children) {
			bpf_printk("missing cpu from inner topology nodes");
			return NULL;
		}

		topo = child;
	}

	return topo;
}

/* 从某节点出发，向上找包含该 cpu 的祖先 */
__weak
topo_ptr topo_find_ancestor(topo_ptr topo, u32 cpu)
{
	while (topo->parent && !topo_contains(topo, cpu))
		topo = topo->parent;

	if (!topo_contains(topo, cpu))
		bpf_printk("could not find cpu");

	return topo;

}

/* 在同层找包含该 cpu 的兄弟节点 */
__weak
topo_ptr topo_find_sibling(topo_ptr topo, u32 cpu)
{
	topo_ptr parent = topo->parent;
	topo_ptr child;
	int i;

	if (!parent) {
		bpf_printk("node is at the top level");
		return NULL;
	}

	for (i = 0; i < parent->nr_children && can_loop; i++) {
		child = parent->children[i];
		if (topo_contains(child, cpu))
			return child;
	}

	return NULL;

}

/* 获取某节点在指定层级的 cpumask */
__weak
u64 topo_mask_level_internal(topo_ptr topo, enum topo_level level)
{
	if (unlikely(level < 0 || level >= TOPO_MAX_LEVEL)) {
		bpf_printk("invalid topology level %d", level);
		return (u64)NULL;
	}

	if (unlikely(topo->level < level)) {
		bpf_printk("requesting cpumask from lower level %d, starting from %d", level, topo->level);
		return (u64)NULL;
	}

	while (topo->level > level && can_loop)
		topo = topo->parent;

	return (u64)topo->mask;
}

static int __maybe_unused
topo_iter_start_from(struct topo_iter *iter, topo_ptr topo)
{
	topo_ptr parent;
	enum topo_level lvl;
	int ind;

	if (!topo_all)
		return -EINVAL;

	iter->topo = topo;
	bpf_for(ind, 0, TOPO_MAX_LEVEL)
		iter->indices[ind] = -1;

	parent = topo->parent;
	for (lvl = topo->level; lvl > 0 && can_loop; lvl--) {
		for (ind = 0; ind < parent->nr_children && can_loop; ind++) {
			if (parent->children[ind] == topo)
				break;
		}

		if (ind == parent->nr_children) {
			bpf_printk("could not find topology node in parent");
			return -EINVAL;
		}


		if (unlikely(lvl >= TOPO_MAX_LEVEL)) {
			bpf_printk("invalid level %d", lvl);
			return -EINVAL;
		}

		iter->indices[lvl] = ind;

		/* Go one level up. */
		parent = parent->parent;
		topo = topo->parent;
	}

	/* We know we only have one root topology node. */
	iter->indices[0] = 0;

	return 0;
}

/* We choose in-order traversal. */
__weak bool
topo_iter_next(struct topo_iter *iter)
{
	topo_ptr parent;
	enum topo_level lvl;

	if (unlikely(!iter)) {
		bpf_printk("passing NULL iterator");
		return false;
	}

	/* Case 1: We have children. Go one step down and get the left most one. */
	if (iter->topo->nr_children > 0) {
		iter->topo = iter->topo->children[0];

		lvl = iter->topo->level;
		if (unlikely(lvl < 0 || lvl >= TOPO_MAX_LEVEL)) {
			/*
			 * XXXETSAL: We have both bpf_printk and bpf_printk
			 * out of an abundance of caution: In some cases bpf_printk
			 * does not fire at all, making debugging more difficult.
			 */
			bpf_printk("invalid child level %d", lvl);
			bpf_printk("invalid child level %d", lvl);
			return false;
		}

		iter->indices[lvl] = 0;

		return true;
	}


	/*
	 * Case 2: We have no children. Go up until we find a rightmost sibling,
	 * then choose that sibling.
	 */
	while (iter->topo->level > 0 && can_loop) {
		lvl = iter->topo->level;
		if (unlikely(lvl < 0 || lvl >= TOPO_MAX_LEVEL)) {
			bpf_printk("invalid level %d", lvl);
			return false;
		}

		iter->indices[lvl] += 1;

		parent = iter->topo->parent;
		if (iter->indices[lvl] == parent->nr_children) {
			/* Done with parent, go up a level. */
			iter->indices[lvl] = -1;
			iter->topo = parent;
			continue;
		}

		iter->topo = parent->children[iter->indices[lvl]];
		return true;
	}

	/* Could not find a right sibling for any ancestor. */

	return false;
}

__weak u64
topo_iter_level_internal(struct topo_iter *iter, enum topo_level lvl)
{
	if (!iter)
		return (u64)NULL;

	do  {
		if (!topo_iter_next(iter))
			return (u64)NULL;
	} while (iter->topo->level != lvl && can_loop);

	return (u64)iter->topo;
}

/* O(1) 查询某个 CPU 属于哪个 LLC */
__weak int
topo_cpu_to_llc_id(u32 cpu)
{
	topo_ptr topo;

	if (cpu >= nr_cpu_ids) {
		bpf_printk("invalid cpu id: %u", cpu);
		return -EINVAL;
	}

	topo = (topo_ptr)topo_nodes[TOPO_CPU][cpu];
	if (!topo) {
		bpf_printk("cpu %u has no topology node set", cpu);
		return -EINVAL;
	}

	return topo->level_ids[TOPO_LLC];
}

/* 真实企业 CPU 举例：双路 AMD EPYC 9654 服务器
AMD EPYC 9654（Genoa 架构）的硬件规格：

2 个 Socket（NUMA 节点）
每 Socket：96 个物理核，
12 个 CCD（Core Complex Die），12 个 L3
每 CCD 8 个核，每 CCD 共享一个 32MB L3
SMT 开启：每物理核 2 个超线程
总计：384 个逻辑 CPU
TOPO_TOP (root)
  mask: [CPU 0 ~ 383, 全部 384 个]
  │
  ├── TOPO_NODE 0   (Socket 0)
  │     mask: [CPU 0 ~ 191]
  │     │
  │     ├── TOPO_LLC 0   (Socket0 CCD0, L3 #0)
  │     │     mask: [CPU 0~15]  (8 cores × 2 SMT)
  │     │     ├── TOPO_CORE 0   mask:[0,1]
  │     │     ├── TOPO_CORE 1   mask:[2,3]
  │     │     ├── ...
  │     │     └── TOPO_CORE 7   mask:[14,15]
  │     │
  │     ├── TOPO_LLC 1   (Socket0 CCD1, L3 #1)
  │     │     mask: [CPU 16~31]
  │     │     └── ...
  │     │
  │     └── ... (共 12 个 LLC)
  │
  └── TOPO_NODE 1   (Socket 1)
        mask: [CPU 192 ~ 383]
        ├── TOPO_LLC 12  (Socket1 CCD0, L3 #12)
        │     mask: [CPU 192~207]
        └── ...
*/
volatile u64 a;

/* 输出到 trace pipe？ */
__weak __maybe_unused
int topo_print(void)
{
	struct topo_iter iter;
	char indent[TOPO_MAX_LEVEL];
	int ret;
	int i;

	if (!topo_all) {
		bpf_printk("[NO TOPOLOGY]");
		return 0;
	}

	ret = topo_iter_start(&iter);
	if (ret)
		return ret;

	do {
		bpf_for(i, 0, TOPO_MAX_LEVEL) {
			if (i == iter.topo->level) {
				indent[i] = '\0';
				break;
			}

			indent[i] = '\t';
		}
		bpf_printk("%s (LEVEL %d) [%d, %d, %d ,%d, %d]",
			indent,
			iter.topo->level,
			iter.indices[TOPO_TOP],
			iter.indices[TOPO_NODE],
			iter.indices[TOPO_LLC],
			iter.indices[TOPO_CORE],
			iter.indices[TOPO_CPU]);

		scx_bitmap_print(iter.topo->mask);
	} while (topo_iter_next(&iter) && can_loop);

	return 0;
}


__weak __maybe_unused
int topo_print_by_level(void)
{
	struct topo_iter iter;
	topo_ptr topo;

	bpf_printk("TOP-LEVEL MASK");
	scx_bitmap_print(topo_all->mask);
	bpf_printk("\n");

	bpf_printk("NODE MASKS");
	TOPO_FOR_EACH_NODE(&iter, topo)
		scx_bitmap_print(topo->mask);
	bpf_printk("\n");

	bpf_printk("LLC MASKS");
	TOPO_FOR_EACH_LLC(&iter, topo)
		scx_bitmap_print(topo->mask);
	bpf_printk("\n");

	bpf_printk("CORE MASKS");
	TOPO_FOR_EACH_CORE(&iter, topo)
		scx_bitmap_print(topo->mask);
	bpf_printk("\n");

	bpf_printk("CPU MASKS");
	TOPO_FOR_EACH_CPU(&iter, topo)
		scx_bitmap_print(topo->mask);
	bpf_printk("\n");

	return 0;
}
/* // 场景：当前任务运行在 CPU 5，调度器想找同 LLC 内最空闲的 CPU
s32 prev_cpu = 5;
topo_ptr cpu_node = (topo_ptr)topo_nodes[TOPO_CPU][prev_cpu];

// 1. 获取该 CPU 所在 LLC 的 cpumask
scx_bitmap_t llc_mask = topo_mask_level(cpu_node, TOPO_LLC);
// llc_mask 现在包含 [CPU 0~15]，即同 CCD 的全部 16 个逻辑 CPU

// 2. 在 llc_mask 里挑选最空闲的 CPU 运行任务（L3 cache 热）
s32 target = scx_select_cpu_dfl(p, prev_cpu, 0, llc_mask);

// 场景：LLC 内全满，需要跨 LLC 但留在同 NUMA 节点内（避免远端内存访问）
scx_bitmap_t node_mask = topo_mask_level(cpu_node, TOPO_NODE);
target = scx_select_cpu_dfl(p, prev_cpu, 0, node_mask);

// 场景：遍历所有 LLC，做负载均衡统计
struct topo_iter iter;
topo_ptr llc;
TOPO_FOR_EACH_LLC(&iter, llc) {
    u64 load = compute_load(llc->mask);  // 统计该 LLC 的负载
    // ...
} */
