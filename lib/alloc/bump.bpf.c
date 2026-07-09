/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

/*
 * Static allocation module used to allocate arena memory for
 * whose lifetime is that of the BPF program. Data is rarely
 * allocated, mostly at program init, and never freed. The
 * memory returned by this code is typeless so it avoids us
 * having to define an allocator for each type.
 */
/* bump.bpf.c 实现了一个线性分配器（Bump Allocator / Arena Allocator），也叫"指针碰撞分配器"。

它的设计思想极其简单：维护一个内存块和一个偏移量，每次分配只需把偏移往前推进（bump），
永远不支持单独释放。适用于"只分配、不释放、随程序终止而统一回收"的场景，即 BPF 程序
初始化阶段的全局静态数据。 */
#include <alloc/common.h>
#include <alloc/asan.h>
#include <alloc/bump.h>

/* Maximum memory that can be allocated by the arena. */
#define ARENA_MAX_MEMORY (1ULL << 20)

/* 作用：把变量放进一个具名 ELF data section。BPF 加载器可以按 section 名称把不同
变量分组，便于 BTF 类型信息关联和 map pinning。bpf_spin_lock 必须放在 BPF map
 的数据段里才能被验证器识别，private() 就是实现这一点的标准手段。 */
private(STATIC_ALLOC_LOCK) struct bpf_spin_lock static_lock;

private(STATIC_ALLOC) struct bump bump;

const s8 STATIC_POISON_UNINIT = 0xff;

extern volatile u64 asan_violated;

/* 以及一个内嵌链表节点，用于在扩容时把历史内存块串联起来（销毁时遍历回收）： */
struct bump_ll;
struct bump_ll {
	struct bump_ll __arena *next;
};
typedef struct bump_ll __arena bump_ll_t;

__weak u64 bump_alloc_internal(size_t bytes, size_t alignment)
{
	void __arena *memory, *old;
	bump_ll_t     *oldll, *newll;
	size_t	      alloc_bytes;
	size_t	      alloc_pages;
	void __arena *ptr;
	size_t	      padding;
	u64	      addr;

	/* 
	 * Allocated addresses must be aligned to the nearest granule,
	 * and since we're stack allocating this implies that allocations
	 * sizes are also aligned.
	 */
	alignment = round_up(alignment, 1 << ASAN_SHADOW_SHIFT);

	bpf_spin_lock(&static_lock);

	/* Round up the current offset.
	从 addr 开始分配内存 */
	addr	    = (__u64)bump.memory + bump.off;

	padding	    = round_up(addr, alignment) - addr;
	/* 要分配的数量 */
	alloc_bytes = bytes + padding;

	if (alloc_bytes > bump.max_contig_bytes) {
		bpf_spin_unlock(&static_lock);
		bpf_printk("invalid request %ld, max is %ld\n", alloc_bytes,
			   bump.max_contig_bytes);
		return (u64)NULL;
	}

	/*
	 * The code assumes that the maximum static allocation
	 * size is significantly larger than the typical allocation
	 * size, so it does not attempt to alleviate memory
	 * fragmentation.
	 超过了 bump 目前大小，需要新申请内存了
	 */
	if (bump.off + alloc_bytes > bump.max_contig_bytes) {
		if (bump.cur_memusage + bump.max_contig_bytes >
		    bump.lim_memusage) {
			bpf_spin_unlock(&static_lock);
			bpf_printk("allocator memory limit exceeded");
			return (u64)NULL;
		}

		old = bump.memory;

		bpf_spin_unlock(&static_lock);

		/*
		 * No free operation so just forget about the previous
		 * allocation memory.
		 */

		alloc_pages = bump.max_contig_bytes / PAGE_SIZE;

		/* 分配内存 */
		memory	    = bpf_arena_alloc_pages(&arena, NULL, alloc_pages,
						    NUMA_NO_NODE, 0);
		if (!memory)
			return (u64)NULL;

		asan_poison(memory, STATIC_POISON_UNINIT,
			    bump.max_contig_bytes);

		bpf_spin_lock(&static_lock);

		/* Error out if we raced with another allocation. */
		if (bump.memory != old) {
			/* 可能别人给 bump 分配内存了 */
			bpf_spin_unlock(&static_lock);
			asan_unpoison(memory, bump.max_contig_bytes);
			bpf_arena_free_pages(&arena, memory, alloc_pages);

			bpf_printk(
				"concurrent static memory allocations unsupported");
			return (u64)NULL;
		}

		/* Keep a list of allocated blocks to free on allocator destruction. */
		/* 分配前后的内存地址 前部视为连接件*/
		oldll = (bump_ll_t *)old;
		newll = (bump_ll_t *)memory;
		asan_unpoison(newll, sizeof(*newll));
		/* 把内存块串起来 */
		newll->next = oldll;

		/*
		 * Switch to new memory block, reset offset,
		 * and recalculate base address.
		 指向最新的内存块
		 */
		bump.memory = memory;
		bump.off	  = sizeof(*newll);
		addr		  = (__u64)bump.memory + bump.off;

		/*
		 * We changed the base address. Recompute the padding.
		 */
		padding	    = round_up(addr, alignment) - addr;
		alloc_bytes = bytes + padding;

		bump.cur_memusage += bump.max_contig_bytes;
	}

	ptr = (void __arena *)(addr + padding);
	asan_unpoison(ptr, bytes);

	bump.off += alloc_bytes;

	bpf_spin_unlock(&static_lock);

	return (u64)ptr;
}

__weak int bump_destroy(void)
{
	size_t	  alloc_pages = bump.max_contig_bytes / PAGE_SIZE;
	bump_ll_t *ll, *llnext;

	for (ll = bump.memory; ll && can_loop; ll = llnext) {
		llnext = ll->next;
		asan_unpoison(ll, bump.max_contig_bytes);
		bpf_arena_free_pages(&arena, ll, alloc_pages);
	}

	for (int i = 0; i < sizeof(bump) && can_loop; i++) {
		((u8 *)&bump)[i] = 0;
	}

	return 0;
}

__weak int bump_init(size_t alloc_pages)
{
	size_t	      max_bytes = alloc_pages * PAGE_SIZE;
	void __arena *memory;
	bump_ll_t     *ll;
	int	      ret;

	memory = bpf_arena_alloc_pages(&arena, NULL, alloc_pages, NUMA_NO_NODE,
				       0);
	if (!memory) {
		bpf_printk("Failed to allocate %d pages", alloc_pages);
		return -ENOMEM;
	}

	ret = asan_poison(memory, STATIC_POISON_UNINIT, max_bytes);
	if (ret)
		bpf_printk("Error %d: by poisoning", ret);

	ret = asan_unpoison(memory, sizeof(*ll));
	if (ret)
		bpf_printk("Error %d: by poisoning", ret);

	ll	 = (bump_ll_t *)memory;
	ll->next = NULL;

	bpf_spin_lock(&static_lock);

	/* We reserve sizeof(*ll) for the embedded linked list. */
	bump = (struct bump){
		.max_contig_bytes = max_bytes,
		.off		  = sizeof(*ll),
		.memory		  = memory,
		.lim_memusage	  = ARENA_MAX_MEMORY,
		.cur_memusage	  = max_bytes,
	};
	bpf_spin_unlock(&static_lock);

	return 0;
}

__weak int bump_memlimit(u64 lim_memusage)
{
	bpf_spin_lock(&static_lock);

	if (lim_memusage > ARENA_MAX_MEMORY)
		goto error;

	/* We always allocate at a page granularity. */
	if (lim_memusage % PAGE_SIZE)
		goto error;

	/* Have we already overshot the limit? */
	if (lim_memusage < bump.cur_memusage)
		goto error;

	bump.lim_memusage = lim_memusage;

	bpf_spin_unlock(&static_lock);

	return 0;

error:
	bpf_spin_unlock(&static_lock);

	return -EINVAL;
}
