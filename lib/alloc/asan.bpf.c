/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */
#include <alloc/common.h>
#include <alloc/asan.h>
/* 这个文件是为 BPF Arena 内存分配器实现的 AddressSanitizer（ASAN）运行时。

ASAN 是一种内存安全检测机制，原本用于用户态/内核态 C 程序。它通过在每次内存读写
前插入检查代码，发现越界访问、use-after-free 等问题。编译器（Clang）在插桩时会自动调用一批
以 __asan_ 开头的运行时函数——这个文件就是在 BPF 环境下实现这些函数。 */
#ifdef BPF_ARENA_ASAN

/* 意思是对该区间内的所有函数关闭 AddressSanitizer (ASAN) 插桩。
这个文件本身就是 ASAN 的"幕后实现"，如果对它自己也插桩，就会无限递归/循环，所以必须豁免。 */
#pragma clang attribute push(__attribute__((no_sanitize("address"))), \
			     apply_to = function)

#define SHADOW_ALL_ZEROES ((u64)-1)

/*
 * Implementation based on mm/kasan/generic.c.
 */

/*
 * Canary variable for ASAN violations.
 */
volatile u64 asan_violated = 0;

/*
 * XXX Shadow map occupancy map (see comment in arena_init.c and the 
 * item in the README).
 */
u64 __asan_shadow_memory_dynamic_address;

static bool reported = false;
static bool inited = false;

/*
 * BPF does not currently support the memset/memcpy/memcmp intrinsics.
 __arena — 修饰指针，表示指向 BPF arena 地址空间的指针（arena 是 BPF 的一种动态内存分配机制，地址空间和普通指针不同）。
__arg_arena — 用于函数参数，告诉 BPF 验证器该参数是一个 arena 指针，触发不同的验证规则。
 */
__always_inline int asan_memset(s8a __arg_arena *dst, s8 val, size_t size)
{
	int i;

	/*
	 * XXX Switching this to a may_goto confuses the verifier and
	 * prevents verification on bpf-next as of late December 2025.
	 */
	bpf_for(i, 0, size) {
		dst[i] = val;
	}

	return 0;
}

/* Validate a 1-byte access, always within a single byte.
检查 1 字节访问是否命中毒化内存。 步骤：

取出该地址对应的 shadow 字节。
若 shadow 为 0，直接合法（最常见路径，用 likely 优化）。
若 shadow 非 0，判断该字节在 granule 内的偏移是否超出合法范围
（ASAN_GRANULE(addr) 是在 8 字节块内的偏移）。 */
static __always_inline bool memory_is_poisoned_1(s8a *addr)
{
	s8 shadow_value = asan_shadow_value(addr);

	/* Byte is 0, access is valid. */
	if (likely(!shadow_value))
		return false;

	/* 
	 * Byte is non-zero. Access is valid if granule offset in [0, shadow_value),
	 * so the memory is poisoned if shadow_value is negative or smaller than
	 * the granule's value.
	 */

	return ASAN_GRANULE(addr) >= shadow_value;
}

/* Validate a 2- 4-, 8-byte access, spans up to 2 bytes.
检查 2/4/8 字节访问是否命中毒化内存。 这类访问最多横跨 2 个 shadow 字节（granule）：

如果整个访问区间在同一个 granule 内，只需检查末尾字节。
如果跨越了 granule 边界，需要同时检查：起始 granule 完全合法
（shadow == 0）+ 末尾 granule 的末字节合法。 */
static __always_inline bool memory_is_poisoned_2_4_8(s8a *addr, u64 size)
{
	u64 end = (u64)addr + size - 1;

	/*
	 * Region fully within a single byte (addition didn't
	 * overflow above ASAN_GRANULE).
	 */
	if (likely(ASAN_GRANULE(end) >= size - 1))
		return memory_is_poisoned_1((s8a *)end);

	/*
	 * Otherwise first byte must be fully unpoisoned, and second byte
	 * must be unpoisoned up to the end of the accessed region.
	 */

	return asan_shadow_value(addr) || memory_is_poisoned_1((s8a *)end);
}

/* 检查某地址对应的 shadow 是否被设置 */
__weak bool asan_shadow_set(void __arena __arg_arena *addr)
{
	return memory_is_poisoned_1(addr);
}

/* 在 shadow map 的一段范围内，找到第一个非零字节的地址。 
非零字节意味着那里有毒化标记。如果全部为零，返回特殊哨兵值 SHADOW_ALL_ZEROES
（即 (u64)-1）。这是大块内存检查的"快速扫描"步骤。 */
static __always_inline u64 first_nonzero_byte(u64 addr, size_t size)
{
	while (size && can_loop) {
		if (unlikely(*(s8a *)addr))
			return addr;
		addr += 1;
		size -= 1;
	}

	return SHADOW_ALL_ZEROES;
}

/* 检查任意长度 n 字节访问是否命中毒化内存。 思路：

把 [addr, addr+size) 映射到 shadow map 区间 [start, end]。
用 first_nonzero_byte 快速扫描整段 shadow。
若找到了非零字节，还要排除一种特殊情况：非零字节正好在末尾 granule，且实际访问没有超过合法的部分毒化边界。 */
static __always_inline bool memory_is_poisoned_n(s8a *addr, u64 size)
{
	u64 ret;
	u64 start;
	u64 end;

	/* Size of [start, end] is end - start + 1. */
	start = (u64)mem_to_shadow(addr);
	end = (u64)mem_to_shadow(addr + size - 1);

	ret = first_nonzero_byte(start, (end - start) + 1);
	if (likely(ret == SHADOW_ALL_ZEROES))
		return false;

	return __builtin_expect(ret != end || ASAN_GRANULE(addr + size - 1) >=
						      *(s8a *)end, false);
}

/* 记录 ASAN 违规事件。 把违规的内存地址写入全局变量 asan_violated
（它是 volatile u64，用户态可以读取）。 */
static __always_inline int asan_report(s8a __arg_arena *addr, size_t sz,
				       bool write)
{
#if 0
	/* Only report the first ASAN violation. */
	if (likely(!reported)) {
		//bpf_printk("[ARENA ASAN] Poisoned %s at address [%p, %p)", "[TODO]", NULL, NULL);
		reported = true;
	}
#endif
	reported = true;

	asan_violated = (u64)addr;
	//	if ((u64)addr)
	//		asan_violated = (u64)addr;
	//	else
	//		asan_violated = (u64)-1;

	/* XXX Flesh out. */

	return 0;
}

static __always_inline bool check_asan_args(s8a *addr, size_t size,
					    bool *result)
{
	bool valid = true;

	/* Size 0 accesses are valid even if the address is invalid. */
	if (unlikely(size == 0))
		goto confirmed_valid;

	/*
	 * Wraparound is possible for extremely high size. Possible if the size
	 * is a misinterpreted negative number.
	 */
	if (unlikely(addr + size < addr))
		goto confirmed_invalid;

	return false;

confirmed_invalid:
	valid = false;

	/* FALLTHROUGH */
confirmed_valid:
	*result = valid;

	return true;
}

/*
 * XXX The "explicit" call to be used from outside without worrying
 * about size. 
 */
/* 核心调度函数，所有内存访问检查的统一入口。 逻辑：

先做参数预检（size=0 / 溢出）。
根据 size 分发到对应的专门检查函数（1、2/4/8、n 字节三类）。
若毒化，调用 asan_report 记录违规。 */
static __always_inline bool check_region_inline(void *ptr, size_t size,
						bool write)
{
	s8a *addr = (s8a *)(u64)ptr;
	bool is_poisoned, is_valid;

	if (check_asan_args(addr, size, &is_valid)) {
		if (!is_valid)
			asan_report(addr, size, write);
		return is_valid;
	}

	switch (size) {
	case 1:
		is_poisoned = memory_is_poisoned_1(addr);
		break;
	case 2:
	case 4:
	case 8:
		is_poisoned = memory_is_poisoned_2_4_8(addr, size);
		break;
	default:
		is_poisoned = memory_is_poisoned_n(addr, size);
	}

	if (is_poisoned) {
		asan_report(addr, size, write);
		return false;
	}

	return true;
}

/*
 * __alias is not supported for BPF so define *__noabort() variants
  as wrappers.
 通过 DEFINE_ASAN_LOAD_STORE(1/2/4/8) 展开，生成 Clang ASAN 插桩需要的运行时
 钩子函数。编译器在每个 load/store 指令前会自动插入对 __asan_loadN /
  __asan_storeN 的调用，这里就是 BPF 环境下的具体实现，内部都调用
   check_region_inline。_noabort 后缀版本在语义上相同（标准 ASAN 中 noabort
    版本报告后继续执行，这里两者行为一致）。*/
#define DEFINE_ASAN_LOAD_STORE(size)                                           \
	__hidden void __asan_store##size(void *addr)                           \
	{                                                                      \
		check_region_inline(addr, size, true);                         \
	}                                                                      \
	__hidden void __always_inline __asan_store##size##_noabort(void *addr) \
	{                                                                      \
		check_region_inline(addr, size, true);                         \
	}                                                                      \
	__hidden void __asan_load##size(void *addr)                            \
	{                                                                      \
		check_region_inline(addr, size, false);                        \
	}                                                                      \
	__hidden void __asan_load##size##_noabort(void *addr)                  \
	{                                                                      \
		check_region_inline(addr, size, false);                        \
	}                                                                      \
	__hidden void __asan_report_store##size(void *addr)                    \
	{                                                                      \
		asan_report((s8a *)addr, size, true);                          \
	}                                                                      \
	__hidden void __asan_report_store##size##_noabort(void *addr)          \
	{                                                                      \
		asan_report((s8a *)addr, size, true);                          \
	}                                                                      \
	__hidden void __asan_report_load##size(void *addr)                     \
	{                                                                      \
		asan_report((s8a *)addr, size, false);                         \
	}                                                                      \
	__hidden void __asan_report_load##size##_noabort(void *addr)           \
	{                                                                      \
		asan_report((s8a *)addr, size, false);                         \
	}

DEFINE_ASAN_LOAD_STORE(1);
DEFINE_ASAN_LOAD_STORE(2);
DEFINE_ASAN_LOAD_STORE(4);
DEFINE_ASAN_LOAD_STORE(8);

void __asan_storeN(void *addr, ssize_t size)
{
	check_region_inline(addr, size, true);
}

void __asan_loadN(void *addr, ssize_t size)
{
	check_region_inline(addr, size, false);
}

void __asan_register_globals(void *globals, size_t n)
{
	/* XXX What is the format in which we are passing the globals? */
	/* XXX Build the poisoning function. Should use asan_poisoning.cpp as a guide. */
	bpf_printk("Emitted %s", __func__);
}

void __asan_unregister_globals(void *globals, size_t n)
{
	bpf_printk("Emitted %s", __func__);
}

/* 内存批量操作的 ASAN 拦截钩子（目前是桩实现）。 Clang 在开启 ASAN 时会把
 memcpy/memmove/memset 替换成 __asan_memcpy 等，以便同时做内存合法性检查。 */
// Functions concerning block memory destinations
void *__asan_memcpy(void *d, const void *s, size_t n)
{
	bpf_printk("Emitted %s", __func__);
	return NULL;
}

void *__asan_memmove(void *d, const void *s, size_t n)
{
	bpf_printk("Emitted %s", __func__);
	return NULL;
}

void *__asan_memset(void *p, int c, size_t n)
{
	bpf_printk("Emitted %s", __func__);
	return NULL;
}

/*
 * Poisoning code, used when we add more freed memory to the allocator by:
 * 	a) pulling memory from the arena segment using bpf_arena_alloc_pages()
 * 	b) freeing memory from application code
 将一段内存标记为"毒化"（不可访问）。 使用场景：

从 arena 获取新页面后，立即毒化（全标为不可访问）。
free 释放内存后，毒化释放区域，捕获 use-after-free。
要求 addr 和 size 都必须 granule 对齐（8 字节），否则返回 -EINVAL。实现就是在
 shadow map 对应区域批量写入 val（通常是负数，表示完全毒化）。
 */
__hidden __noasan int asan_poison(void __arena *addr, s8 val, size_t size)
{
	s8a *shadow;
	size_t len;

	/*
	 * Poisoning from a non-granule address makes no sense: We can only allocate
	 * memory to the application that with a granule-aligned starting address,
	 * and bpf_arena_alloc_pages returns page-aligned memory. A non-aligned
	 * addr then implies we're freeing a different address than the one we
	 * allocated.
	 */
	if (unlikely((u64)addr & ASAN_GRANULE_MASK))
		return -EINVAL;

	/*
	 * We cannot free an unaligned region because it's possible that we
	 * cannot describe the resulting poisoning state of the granule in 
	 * the ASAN encoding.
	 *
	 * Every granule represents a region of memory that looks like the
	 * following (P for poisoned bytes, C for clear):
	 *
	 * <Clear>  <Poisoned>
	 * [ C C C ... P P ]
	 *
	 * The value of the granule's shadow map is the number of clear bytes in
	 * it. We cannot represent granules with the following state:
	 *
	 * [ P P ... C C ... P P ]
	 *
	 * That would be possible if we could free unaligned regions, so prevent that.
	 * 
	 */
	if (unlikely(size & ASAN_GRANULE_MASK))
		return -EINVAL;

	shadow = mem_to_shadow(addr);
	len = size >> ASAN_SHADOW_SHIFT;

	asan_memset(shadow, val, len);

	return 0;
}

/*
 * Unpoisoning code for marking memory as valid during allocation calls.
 *
 * Very similar to asan_poison, except we need to round up instead of
 * down, the partially poison the last granule if necessary.
 *
 * Partial poisoning is useful for keeping the padding poisoned. Allocations
 * are granule-aligned, so we we're reserving granule-aligned sizes for the
 * allocation. However, we want to still treat accesses to the padding as 
 * invalid. Partial poisoning takes care of that. Freeing and poisoning the
 * memory is still done in granule-aligned sizes and repoisons the already
 * poisoned padding.
 将一段内存标记为"合法可访问"（解毒）。 使用场景：分配内存给应用层时调用，把分配区域在 shadow map 中清零（表示可访问）。
 */
__hidden __noasan int asan_unpoison(void __arena *addr, size_t size)
{
	size_t partial = size & ASAN_GRANULE_MASK;
	s8a *shadow;
	size_t len;

	/*
	 * We cannot allocate in the middle of the granule. The ASAN shadow
	 * map encoding only describes regions of memory where every granule
	 * follows this format (P for poisoned, C for clear):
	 *
	 * <Clear>  <Poisoned>
	 * [ C C C ... P P ]
	 *
	 * This is so we can use a single number in [0, ASAN_SHADOW_SCALE)
	 * to represent the poison state of the granule.
	 */
	if (unlikely((u64)addr & ASAN_GRANULE_MASK))
		return -EINVAL;

	shadow = mem_to_shadow(addr);
	len = size >> ASAN_SHADOW_SHIFT;

	asan_memset(shadow, 0, len);

	/* 
	 * If we are allocating a non-granule aligned region, we need to adjust
	 * the last byte of the shadow map to list how many bytes in the granule
	 * are unpoisoned. If the region is aligned, then the memset call above
	 * was enough.
	 */
	if (partial)
		shadow[len] = partial;

	return 0;
}

/*
 * Initialize ASAN state when necessary. Triggered from userspace before
 * allocator startup.
 */
/* 把函数放入 ELF 的 "syscall" 节（section）。BPF 加载器（libbpf）会根据 section
 名称决定 BPF 程序类型：

"syscall" — 表示这个 BPF 程序可由用户态通过 bpf(BPF_PROG_RUN, ...) 直接调用，
相当于一个"用户态可触发的 BPF 函数"。
其他常见的有 "tp/...", "kprobe/...", "xdp" 等。 */
SEC("syscall")
__hidden __noasan int asan_init(struct asan_init_args *args)
{
	u64 globals_pages = args->arena_globals_pages;
	u64 all_pages = args->arena_all_pages;
	u64 shadowmap, shadow_pgoff;
	u64 shadow_pages;

	if (inited)
		return 0;

	/* 
	 * Retrieve how many pages in the arena are already mapped in.
	 * This is equal to or higher than the size of the arena globals.
	 * We use this to place the mapping right before the globals.
	 */
	shadow_pages = all_pages >> ASAN_SHADOW_SHIFT;

	/*
	 * Make sure the numbers provided by userspace are sane.
	 */
	if (all_pages > (1ULL << 32) >> PAGE_SHIFT) {
		bpf_printk("error: arena size %lx too large", all_pages);
		return -EINVAL;
	}

	if (globals_pages > all_pages) {
		bpf_printk("error: globals %lx do not fit in arena %lx", globals_pages, all_pages);
		return -EINVAL;
	}

	if (globals_pages + shadow_pages > all_pages) {
		bpf_printk("error: globals %lx do not leave room for shadow map %lx (arena pages %lx)",
			globals_pages, shadow_pages, all_pages);
		return -EINVAL;
	}

	shadow_pgoff = all_pages - shadow_pages - globals_pages;
	__asan_shadow_memory_dynamic_address = shadow_pgoff * PAGE_SIZE;

	/*
	 * XXX Fail for arenas that are < 32KiB, or are not 32KiB aligned. 
	 * Handling them would require extra edge case handling that would
	 * complicate things, and there is no good reason to support them.
	 */

	/* 
	 * Allocate the last (1/ASAN_GRANULE_SIZE)th of an arena's pages for the map
	 * We find the offset and size from the arena map.
	 *
	 * The allocated map pages are zeroed out, meaning all memory is marked as valid
	 * even if it's not allocated already. This is expected: Since the actual memory
	 * pages are not allocated, accesses to it will trigger page faults and will be
	 * reported through BPF streams. Any pages allocated through bpf_arena_alloc_pages
	 * should be poisoned by the allocator right after the call succeeds.
	 *
	 * XXX Do this lazily as denoted in the README item. Scale this with the arena
	 * size - right now we assume both in the offset and the size are for a 4GiB
	 * arena. Even for a 4GiB arena, the space overhead for lazy shadow map 
	 * allocation is 4KiB.
	 */
	shadowmap = (u64)bpf_arena_alloc_pages(
		&arena, (void __arena *)__asan_shadow_memory_dynamic_address,
		shadow_pages, NUMA_NO_NODE, 0);
	if (!shadowmap) {
		arena_stderr("Could not allocate shadow map\n");
		return -ENOMEM;
	}

	inited = true;

	return 0;
}

#pragma clang attribute pop

#endif /* BPF_ARENA_ASAN */
