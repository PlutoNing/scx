/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024-2025 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2024-2025 Emil Tsalapatis <etsal@meta.com>
 */

#include <alloc/common.h>
#include <alloc/asan.h>
#include <alloc/stack.h>

/*
 * Necessary for cond_break/can_loop's semantics. According to kernel commit
 * 011832b, the loop counter variable must be seen as imprecise and bounded
 * by the verifier. Initializing it from a constant (e.g., i = 0;), then,
 * makes it precise and prevents may_goto from helping with converging the
 * loop. For these loops we must initialize the loop counter from a variable
 * whose value the verifier cannot reason about when checking the program, so
 * that the loop counter's value is imprecise.
 */
/* stack.bpf.c 实现了一个固定大小对象的栈式分配器（Stack/Pool Allocator），也称为"对象池"。

与前两个分配器的对比：

特性	Bump	Buddy	Stack
分配粒度 任意大小 2的幂次 固定大小
支持free 不支持 支持，O(log n) 支持，O(1)
适用场景 程序级静态数据 通用动态内存 大量同类型对象
实现方式 指针碰撞 二叉树 指针栈
它的核心思想：维护一个"空闲对象指针"的栈，分配时弹出（pop）一个指针，释放时把指针压回
（push）。栈为空时从 arena 申请新内存批量填充。 */
static __u64 zero = 0;

enum {
	STACK_POISONED = (s8)0xef,
};

__hidden int stk_init(struct stk		       *stack,
			  arena_spinlock_t __arg_arena __arena *lock,
			  __u64 data_size, __u64 nr_pages_per_alloc)
{
	if (!stack)
		return -EINVAL;

	stack->data_size = data_size;
	stack->nr_pages_per_alloc = nr_pages_per_alloc;
	stack->lock = lock;

	return 0;
}

__hidden void stk_destroy(struct stk *stack)
{
	stk_seg_t *seg, *next;
	__u64 nr_pages;

	/* Operation happens unlocked since we are called last. */

	if (!stack)
		return;

	nr_pages = stack->nr_pages_per_alloc;

	/*
	 * While we have allocated in batches of either 1
	 * or 2, and broken the allocation into multiple
	 * segments, the arena kfunc API lets us free
	 * each segment separately.
	 */
	for (seg = stack->reserve; seg && can_loop; seg = next) {
		next = seg->next;
		asan_unpoison(seg, sizeof(*seg));
		bpf_arena_free_pages(&arena, seg, nr_pages);
	}

	for (seg = stack->first; seg && can_loop; seg = next) {
		next = seg->next;
		asan_unpoison(seg, sizeof(*seg));
		bpf_arena_free_pages(&arena, seg, nr_pages);
	}

	stack->first = NULL;
	stack->last = NULL;

	stack->current = NULL;
	stack->cind = 0;

	stack->capacity = 0;
	stack->available = 0;
	stack->data_size = 0;
	stack->nr_pages_per_alloc = 0;

	stack->reserve = NULL;
}

static int stk_push(struct stk *stack, void __arena *elem)
{
	stk_seg_t *stk_seg = stack->current;
	int ridx = stack->cind;

	stack->current->elems[stack->cind] = elem;

	ridx += 1;

	/* Possibly loop into the next segment. */
	if (ridx == STK_SEG_MAX) {
		ridx = 0;
		stk_seg = stk_seg->next;
		if (!stk_seg)
			return -ENOSPC;
	}

	stack->current = stk_seg;
	stack->cind = ridx;

	stack->capacity -= 1;
	stack->available += 1;

	return 0;
}

static void __arena *stk_pop(struct stk *stack)
{
	stk_seg_t *stk_seg = stack->current;
	void __arena *elem;
	int ridx = stack->cind;

	/* Possibly loop into previous segment. */
	if (ridx == 0) {
		ridx = STK_SEG_MAX;
		stk_seg = stack->current->prev;
		/* Possibly loop back into the last segment. */
		if (!stk_seg)
			return NULL;
	}

	ridx -= 1;

	stack->current = stk_seg;
	stack->cind = ridx;

	elem = stack->current->elems[stack->cind];

	stack->capacity += 1;
	stack->available -= 1;

	return elem;
}

static int stk_seg_to_data(struct stk *stack, size_t nelems)
{
	int ret, i;
	u64 data;

	/* Do we have enough empty segments for the conversion? */
	if (!stack->first || stack->first == stack->last)
		return -ENOMEM;

	data = (u64)stack->last;

	stack->last->prev->next = NULL;
	stack->last = stack->last->prev;

	/* We removed a segment. */
	stack->capacity -= STK_SEG_MAX;

	for (i = zero; i < nelems && can_loop; i++) {
		asan_poison((void __arena *)data, STACK_POISONED,
			    sizeof(struct stk_seg));

		ret = stk_push(stack, (void __arena *)data);
		if (ret)
			return ret;
		data += stack->data_size;
	}

	return 0;
}

static void stk_extend(struct stk *stack, stk_seg_t *stk_seg)
{
	if (stack->last)
		stack->last->next = stk_seg;

	stk_seg->prev = stack->last;
	stk_seg->next = NULL;

	stack->last = stk_seg;
	stack->capacity += STK_SEG_MAX;

	if (!stack->first)
		stack->current = stack->first = stk_seg;

	/*
	 * Do not adjust the current segment/idx because we did not add
	 * any elements. The new segment will be pushed into during the next
	 * allocation.
	 */
}

static int stk_free_unlocked(struct stk *stack, void __arena *elem)
{
	if (!stack)
		return -EINVAL;

	asan_poison(elem, STACK_POISONED, stack->data_size);

	/* If no more room, repurpose the allocation into a segment. */
	if (stack->capacity == 0) {
		asan_unpoison(elem, sizeof(struct stk_seg));

		stk_extend(stack, (stk_seg_t *)elem);
		return 0;
	}

	return stk_push(stack, elem);
}

__weak int stk_free_internal(struct stk *stack, __u64 elem)
{
	int ret;

	if (!stack)
		return -EINVAL;

	ret = arena_spin_lock(stack->lock);
	if (ret)
		return ret;

	ret = stk_free_unlocked(stack, (void __arena *)elem);

	arena_spin_unlock(stack->lock);

	return ret;
}

static int stk_get_arena_memory(struct stk *stack, __u64 nr_pages,
				    __u64 nstk_segs)
{
	stk_seg_t *stk_seg;
	int ret, i;
	u64 mem;

	/*
	 * The code allocates new memory only as segments. The allocation and
	 * free code freely typecasts the segment buffer into data that can be
	 * allocated, and vice versa to avoid either ending up with too many
	 * empty segments under memory pressure, or having no space in the segment
	 * buffer for a buffer currently being freed.
	 */

	/*
	 * On error, we return with the segment buffer unlocked.
	 */
	if (!stack)
		return -EINVAL;

	arena_spin_unlock(stack->lock);

	mem = (__u64)bpf_arena_alloc_pages(&arena, NULL, nstk_segs * nr_pages,
					   NUMA_NO_NODE, 0);
	if (!mem)
		return -ENOMEM;

	ret = arena_spin_lock(stack->lock);
	if (ret)
		return ret;

	asan_poison((void __arena *)mem, STACK_POISONED,
		    nstk_segs * nr_pages * PAGE_SIZE);

	_Static_assert(sizeof(struct stk_seg) <= PAGE_SIZE,
		       "segment must fit into a page");

	/* Attach the segments to the reserve linked list. */
	for (i = zero; i < nstk_segs && can_loop; i++) {
		/* Keep the memory that hosts metadata unpoisoned.*/
		stk_seg = (stk_seg_t *)mem;
		asan_unpoison(stk_seg, sizeof(*stk_seg));

		stk_seg->next  = stack->reserve;
		stack->reserve = stk_seg;

		mem += nr_pages * PAGE_SIZE;
	}

	return 0;
}

static int stk_fill_new_elems(struct stk *stack)
{
	size_t nelems, nstk_segs;
	stk_seg_t *stk_seg;
	__u64 nr_pages;
	int ret, i;
	u64 mem;

	nr_pages = stack->nr_pages_per_alloc;
	nelems = (nr_pages * PAGE_SIZE) / stack->data_size;
	if (nelems > STK_SEG_MAX) {
		ret = -EINVAL;
		goto error;
	}

	/* How many segments should we allocate? */
	nstk_segs = stack->capacity ? 1 : 2;

	/*
	 * If we have more than two empty segments available,
	 * repurpose one of them into an allocation.
	 */
	ret = stk_seg_to_data(stack, nelems);
	if (!ret)
		return 0;

	/* If we haven't set aside enough memory from before, allocate. */
	if (!stack->reserve || !stack->reserve->next) {
		/* This call drops and retakes the lock. */
		ret = stk_get_arena_memory(stack, nr_pages, nstk_segs);
		if (ret) {
			/* No need to unlock, we dropped the lock in the call. */
			return ret;
		}
	}

	/*
	 * If somebody replenished the stack while we were asleep, no need
	 * to do anything. Keep the allocated memory in the reserve linked
	 * list for subsequent allocations.
	 */
	if (stack->available > 0)
		return 0;

	/* Otherwise add elements and possibly capacity to the stack. */
	if (!stack->capacity) {
		stk_seg = stack->reserve;
		stack->reserve = stack->reserve->next;

		stk_extend(stack, stk_seg);
	}

	/* Pop out the reserve and attach to the stack. */
	stk_seg = stack->reserve;
	stack->reserve = stk_seg->next;

	mem = (u64)stk_seg;
	for (i = zero; i < nelems && can_loop; i++) {
		ret = stk_push(stack, (void __arena *)mem);
		if (ret)
			goto error;
		mem += stack->data_size;
	}

	return 0;

	/* 
	 * Drop the arena lock on error. On error we cannot
	 * guarantee we can return with the lock held, so
	 * make sure the lock is not taken for all error
	 * paths.
	 */
error:
	arena_spin_unlock(stack->lock);
	return ret;
}

static inline __u64 stk_alloc_unlocked(struct stk *stack)
{
	void __arena *elem;
	int ret;

	/* If segment buffer is empty, we have to populate it. */
	if (stack->available == 0) {
		/* The call drops the lock on error. */
		ret = stk_fill_new_elems(stack);
		if (ret)
			return 0ULL;
	}

	/* An elem value of 0 implies error, drop the lock. */
	elem = stk_pop(stack);
	if (elem)
		asan_unpoison(elem, stack->data_size);
	else
		arena_spin_unlock(stack->lock);

	return (__u64)elem;
}

__weak __u64 stk_alloc(struct stk *stack)
{
	u64 elem;

	if (!stack) {
		bpf_printk("using uninitialized stack allocator");
		return 0ULL;
	}

	if (arena_spin_lock(stack->lock))
		return 0ULL;

	elem = stk_alloc_unlocked(stack);

	if (elem)
		arena_spin_unlock(stack->lock);

	return (u64)elem;
}
/* 

---

## 文件整体作用

`stack.bpf.c` 实现了一个**固定大小对象的栈式分配器（Stack/Pool Allocator）**，也称为"对象池"。

与前两个分配器的对比：

| 特性 | Bump | Buddy | Stack |
|------|------|-------|-------|
| 分配粒度 | 任意大小 | 任意大小（2的幂次） | 固定大小 |
| 支持 free | 不支持 | 支持，O(log n) | 支持，O(1) |
| 适用场景 | 程序级静态数据 | 通用动态内存 | 大量同类型对象 |
| 实现方式 | 指针碰撞 | 二叉树 | 指针栈 |

它的核心思想：维护一个"空闲对象指针"的栈，分配时弹出（pop）一个指针，释放时把指针压回（push）。栈为空时从 arena 申请新内存批量填充。

---

## 核心数据结构（来自 stack.h）

```
struct stk_seg（1页 = 4096字节，双向链表节点）
┌─────────────────────────────────────────────┐
│  elems[510]  ← 存放空闲对象指针的数组       │
│              (510 = (4096 - 16) / 8)        │
│  *prev       ← 上一个 seg                   │
│  *next       → 下一个 seg                   │
└─────────────────────────────────────────────┘

STK_SEG_MAX = (PAGE_SIZE - 2*sizeof(void*)) / sizeof(void*) = 510
```

```
struct stk（分配器主结构）
┌────────────────────────────────────────────────────────┐
│  *first, *last    ← seg双向链表（存指针的缓冲区）      │
│  *current, cind   ← 当前操作的seg和下标（栈顶）        │
│  capacity         ← 当前可接受push的空槽数             │
│  available        ← 当前可pop的对象数                  │
│  data_size        ← 每个对象的字节大小                 │
│  nr_pages_per_alloc ← 每次向arena申请几页              │
│  *reserve         ← 预备seg链表（单向，next-only）      │
└────────────────────────────────────────────────────────┘
```

**内存布局示意图（两个 seg 时）：**

```
first                          last
  │                              │
  ▼                              ▼
┌─────────────┐  next  ┌─────────────┐
│ seg[0]      │───────▶│ seg[1]      │
│ elems[0] →obj│        │ elems[0] →obj│
│ elems[1] →obj│        │ elems[1] →obj│
│    ...      │        │    ...      │
│ elems[509]  │◀───────│ prev        │
└─────────────┘        └─────────────┘
                              ▲
                           current
                           cind = 当前栈顶位置
```

---

## 关键概念：`capacity` vs `available`

这两个字段容易混淆，需要重点理解：

- **`capacity`**：seg 缓冲区里还有多少**空槽**可以接受新的 push（即 free 操作）。
- **`available`**：缓冲区里当前存放了多少**有效对象指针**可以被 pop（即 alloc 操作）。

两者之和 = 所有 seg 的总槽位数（`段数 × STK_SEG_MAX`）。

---

## 逐函数详解

### 1. `stk_init`（第 26 行）—— 初始化

```26:38:lib/alloc/stack.bpf.c
__hidden int stk_init(struct stk		       *stack,
			  arena_spinlock_t __arg_arena __arena *lock,
			  __u64 data_size, __u64 nr_pages_per_alloc)
{
	if (!stack)
		return -EINVAL;

	stack->data_size = data_size;
	stack->nr_pages_per_alloc = nr_pages_per_alloc;
	stack->lock = lock;

	return 0;
}
```

**轻量初始化，仅记录参数，不分配任何内存。** 第一次实际分配发生在 `stk_alloc` 时懒加载。

注意 `__hidden` 和 `arena_spinlock_t __arg_arena __arena *lock`：
- `__hidden` = 符号不导出（前文已讲）。
- `__arg_arena` = 告知 BPF 验证器：此参数是 arena 指针（验证器会用不同规则检查它）。
- `__arena` = 修饰指针本身，表示它指向 arena 地址空间。两者叠加：参数类型是"指向 arena 内 spinlock 的 arena 指针"。

---

### 2. `stk_destroy`（第 40 行）—— 销毁

```40:82:lib/alloc/stack.bpf.c
__hidden void stk_destroy(struct stk *stack)
{
	stk_seg_t *seg, *next;
	__u64 nr_pages;

	nr_pages = stack->nr_pages_per_alloc;

	for (seg = stack->reserve; seg && can_loop; seg = next) {
		next = seg->next;
		asan_unpoison(seg, sizeof(*seg));
		bpf_arena_free_pages(&arena, seg, nr_pages);
	}

	for (seg = stack->first; seg && can_loop; seg = next) {
		next = seg->next;
		asan_unpoison(seg, sizeof(*seg));
		bpf_arena_free_pages(&arena, seg, nr_pages);
	}

	stack->first = NULL; stack->last = NULL;
	stack->current = NULL; stack->cind = 0;
	...
}
```

分两轮遍历：先清理 `reserve` 链表（备用 seg），再清理 `first→last` 链表（正在使用的 seg）。每次释放前必须先 `asan_unpoison`，因为 `bpf_arena_free_pages` 操作的地址不能有毒化标记干扰。

---

### 3. `stk_push`（第 84 行）—— 把对象地址压入栈

```84:108:lib/alloc/stack.bpf.c
static int stk_push(struct stk *stack, void __arena *elem)
{
	stk_seg_t *stk_seg = stack->current;
	int ridx = stack->cind;

	stack->current->elems[stack->cind] = elem;

	ridx += 1;

	// Possibly loop into the next segment.
	if (ridx == STK_SEG_MAX) {
		ridx = 0;
		stk_seg = stk_seg->next;
		if (!stk_seg)
			return -ENOSPC;
	}

	stack->current = stk_seg;
	stack->cind = ridx;

	stack->capacity -= 1;
	stack->available += 1;

	return 0;
}
```

**将 `elem` 的地址写入当前 seg 的 `cind` 位置，然后把 `cind` 向前推进一格。** 若 `cind` 到达 seg 的末尾（`STK_SEG_MAX`），自动跳入链表的下一个 seg，`cind` 归零。

这是一个**跨多 seg 的线性栈**，由 `current + cind` 共同描述"栈顶"（下一个空槽的位置）。

---

### 4. `stk_pop`（第 110 行）—— 从栈取出对象地址

```110:136:lib/alloc/stack.bpf.c
static void __arena *stk_pop(struct stk *stack)
{
	stk_seg_t *stk_seg = stack->current;
	void __arena *elem;
	int ridx = stack->cind;

	// Possibly loop into previous segment.
	if (ridx == 0) {
		ridx = STK_SEG_MAX;
		stk_seg = stack->current->prev;
		if (!stk_seg)
			return NULL;
	}

	ridx -= 1;

	stack->current = stk_seg;
	stack->cind = ridx;

	elem = stack->current->elems[stack->cind];

	stack->capacity += 1;
	stack->available -= 1;

	return elem;
}
```

**与 push 方向相反：先把 `cind` 退后一格，再读取该位置的指针。** 若 `cind` 已经是 0（当前 seg 没有可读项），跳回 `prev` seg，`cind` 设为 `STK_SEG_MAX`，再退后一格到 `STK_SEG_MAX - 1`。

push/pop 的关系图示：

```
push 方向  →→→→→→→→→→→→→→→→→→→→→→→→→→
         [seg0.elems: 0 1 2 ... 509][seg1.elems: 0 1 2 ...]
                                  ↑cind（栈顶，下一个空槽）
pop 方向   ←←←←←←←←←←←←←←←←←←←←←←
```

---

### 5. `stk_extend`（第 168 行）—— 向链表追加一个新 seg（扩容槽位）

```168:187:lib/alloc/stack.bpf.c
static void stk_extend(struct stk *stack, stk_seg_t *stk_seg)
{
	if (stack->last)
		stack->last->next = stk_seg;

	stk_seg->prev = stack->last;
	stk_seg->next = NULL;

	stack->last = stk_seg;
	stack->capacity += STK_SEG_MAX;

	if (!stack->first)
		stack->current = stack->first = stk_seg;
}
```

把新 seg 追加到链表尾部，增加 `capacity`（空槽数）。**注意不改变 `current` 和 `cind`**（除非是第一个 seg），新 seg 只有在 push 时 `cind` 溢出才会被用到。

---

### 6. `stk_seg_to_data`（第 138 行）—— 把多余 seg 变成数据对象（内存复用）

```138:166:lib/alloc/stack.bpf.c
static int stk_seg_to_data(struct stk *stack, size_t nelems)
{
	int ret, i;
	u64 data;

	if (!stack->first || stack->first == stack->last)
		return -ENOMEM;

	data = (u64)stack->last;  // 取最后一个seg的地址

	stack->last->prev->next = NULL;
	stack->last = stack->last->prev;   // 把最后一个seg从链表摘除

	stack->capacity -= STK_SEG_MAX;   // 减少容量

	for (i = zero; i < nelems && can_loop; i++) {
		asan_poison((void __arena *)data, STACK_POISONED,
			    sizeof(struct stk_seg));   // 毒化整块
		ret = stk_push(stack, (void __arena *)data);  // 当成对象指针压栈
		data += stack->data_size;   // 按data_size步进
	}

	return 0;
}
```

**这是这个分配器最巧妙的设计：seg 内存和数据对象内存可以互相转化。**

当栈缓冲区有**多余的空 seg**（capacity 过大）时，把最后一个 seg 摘下来，把它的内存按 `data_size` 切片，每片当成一个对象压入栈，供后续 alloc 使用。

这样避免了"太多空 seg 浪费内存"的问题。

---

### 7. `stk_free_unlocked`（第 189 行）—— 释放对象（无锁内部版本）

```189:205:lib/alloc/stack.bpf.c
static int stk_free_unlocked(struct stk *stack, void __arena *elem)
{
	if (!stack)
		return -EINVAL;

	asan_poison(elem, STACK_POISONED, stack->data_size);

	// If no more room, repurpose the allocation into a segment.
	if (stack->capacity == 0) {
		asan_unpoison(elem, sizeof(struct stk_seg));
		stk_extend(stack, (stk_seg_t *)elem);
		return 0;
	}

	return stk_push(stack, elem);
}
```

**与 `stk_seg_to_data` 方向相反的转化：对象变 seg。**

释放流程：
1. 先毒化被释放的内存（ASAN 保护，防止 use-after-free）。
2. 若 seg 缓冲区已满（`capacity == 0`，没有空槽接受 push），就把这块内存直接当成新 seg 使用（解毒 seg 头部，调 `stk_extend`）。
3. 否则把对象地址压入栈，等待下次 alloc。

---

### 8. `stk_free_internal`（第 207 行）—— 对外的释放接口

```207:223:lib/alloc/stack.bpf.c
__weak int stk_free_internal(struct stk *stack, __u64 elem)
{
	int ret;

	if (!stack)
		return -EINVAL;

	ret = arena_spin_lock(stack->lock);
	if (ret)
		return ret;

	ret = stk_free_unlocked(stack, (void __arena *)elem);

	arena_spin_unlock(stack->lock);

	return ret;
}
```

加锁后调用内部版本。对外通过宏暴露：

```c
#define stk_free(stack, elem) stk_free_internal(stack, (__u64)elem)
```

---

### 9. `stk_get_arena_memory`（第 225 行）—— 向 arena 申请新内存

```225:276:lib/alloc/stack.bpf.c
static int stk_get_arena_memory(struct stk *stack, __u64 nr_pages,
				    __u64 nstk_segs)
{
	arena_spin_unlock(stack->lock);   // ← 释放锁（避免持锁睡眠）

	mem = (__u64)bpf_arena_alloc_pages(&arena, NULL, nstk_segs * nr_pages,
					   NUMA_NO_NODE, 0);

	ret = arena_spin_lock(stack->lock);  // ← 重新加锁

	asan_poison((void __arena *)mem, STACK_POISONED,
		    nstk_segs * nr_pages * PAGE_SIZE);

	for (i = zero; i < nstk_segs && can_loop; i++) {
		stk_seg = (stk_seg_t *)mem;
		asan_unpoison(stk_seg, sizeof(*stk_seg));

		stk_seg->next = stack->reserve;
		stack->reserve = stk_seg;       // 头插到reserve链表

		mem += nr_pages * PAGE_SIZE;
	}

	return 0;
}
```

与 `buddy_chunk_get` / `bump_alloc_internal` 扩容段一样，**先释放锁再申请内存，完成后重新加锁**（避免持锁睡眠）。

申请到的内存切成 `nstk_segs` 个 seg，全部头插到 `stack->reserve` 备用链表，**不立即加入主链表**（因为可能在锁外期间有其他线程已经完成了扩容，见下方 `stk_fill_new_elems` 的处理）。

`_Static_assert(sizeof(struct stk_seg) <= PAGE_SIZE, ...)` — 编译期断言：一个 seg 必须能放进一页，否则按页释放的逻辑会出错。

---

### 10. `stk_fill_new_elems`（第 278 行）—— 填充新对象（最复杂的函数）

```278:353:lib/alloc/stack.bpf.c
static int stk_fill_new_elems(struct stk *stack)
{
	nr_pages = stack->nr_pages_per_alloc;
	nelems = (nr_pages * PAGE_SIZE) / stack->data_size;

	nstk_segs = stack->capacity ? 1 : 2;  // ① 需要几个seg？

	// ② 尝试把空seg直接转成数据（复用内存，避免申请）
	ret = stk_seg_to_data(stack, nelems);
	if (!ret)
		return 0;

	// ③ reserve不够就去arena申请（会释放锁再重新加锁）
	if (!stack->reserve || !stack->reserve->next) {
		ret = stk_get_arena_memory(stack, nr_pages, nstk_segs);
		if (ret) return ret;
	}

	// ④ 锁外期间，别的线程可能已经填充好了
	if (stack->available > 0)
		return 0;

	// ⑤ 如果槽位也为0，先扩容
	if (!stack->capacity) {
		stk_seg = stack->reserve;
		stack->reserve = stack->reserve->next;
		stk_extend(stack, stk_seg);  // 从reserve取一个seg加入主链表
	}

	// ⑥ 把另一个reserve seg的内存切成对象压栈
	stk_seg = stack->reserve;
	stack->reserve = stk_seg->next;
	mem = (u64)stk_seg;
	for (i = zero; i < nelems && can_loop; i++) {
		stk_push(stack, (void __arena *)mem);
		mem += stack->data_size;
	}

	return 0;
}
```

这是分配器扩容的核心逻辑，按**优先级递进**尝试四种策略：

```
策略① 复用空 seg（stk_seg_to_data）
    └ 成功 → 直接返回
    └ 失败 ↓
策略② 检查 reserve 是否充足
    └ 不足 → stk_get_arena_memory（释放锁去申请）
           → 重新加锁后检查是否有竞争者已补充（available > 0）
策略③ 用 reserve 扩容 seg 链表（如果 capacity == 0）
    └ 从 reserve 取一个 seg，stk_extend 加入主链表
策略④ 用另一个 reserve seg 的内存切片成对象，压栈
```

`nstk_segs = stack->capacity ? 1 : 2` 的含义：若当前 `capacity == 0`（没有空槽），就需要两个 seg：一个用于扩容槽位（seg），一个用于提供数据。若已有槽位，只需要一个 seg 提供数据。

---

### 11. `stk_alloc_unlocked`（第 355 行）—— 无锁分配

```355:376:lib/alloc/stack.bpf.c
static inline __u64 stk_alloc_unlocked(struct stk *stack)
{
	void __arena *elem;
	int ret;

	// If segment buffer is empty, we have to populate it.
	if (stack->available == 0) {
		ret = stk_fill_new_elems(stack);
		if (ret)
			return 0ULL;
	}

	elem = stk_pop(stack);
	if (elem)
		asan_unpoison(elem, stack->data_size);
	else
		arena_spin_unlock(stack->lock);  // pop失败时主动释放锁

	return (__u64)elem;
}
```

逻辑简洁：
1. 若 `available == 0`，先填充（`stk_fill_new_elems`，此时锁可能被释放和重新获取）。
2. `stk_pop` 取出指针。
3. 解毒分配出去的内存（告知 ASAN 这块内存现在合法）。

注意：`stk_fill_new_elems` 在**错误路径**下会主动释放锁（见其 `error:` 标签），所以调用者不能假设失败后锁还在手里。

---

### 12. `stk_alloc`（第 378 行）—— 对外的分配接口

```378:396:lib/alloc/stack.bpf.c
__weak __u64 stk_alloc(struct stk *stack)
{
	u64 elem;

	if (!stack) {
		bpf_printk("using uninitialized stack allocator");
		return 0ULL;
	}

	if (arena_spin_lock(stack->lock))
		return 0ULL;

	elem = stk_alloc_unlocked(stack);

	if (elem)
		arena_spin_unlock(stack->lock);

	return (u64)elem;
}
```

加锁后调用内部版本。**`if (elem) arena_spin_unlock`** 的原因：若 `elem == 0`（失败），锁已经在 `stk_alloc_unlocked` 内部的错误路径释放了，不能再解一次。

---

## 整体调用流程

```
stk_alloc(stack)
  └─ 加锁
  └─ stk_alloc_unlocked()
       ├─ available > 0 → stk_pop() → asan_unpoison → 返回
       └─ available == 0 → stk_fill_new_elems()
               ├─ stk_seg_to_data()     ← 复用空 seg（优先）
               ├─ stk_get_arena_memory() ← 释放锁 → arena申请 → 加锁
               │       └─ 新 seg 放入 reserve 链表
               ├─ stk_extend()          ← reserve → 主链表（扩容槽位）
               └─ stk_push() × nelems  ← reserve内存切片成对象

stk_free(stack, ptr)
  └─ 加锁
  └─ stk_free_unlocked()
       ├─ asan_poison(ptr)
       ├─ capacity == 0 → stk_extend(ptr) ← 对象变 seg
       └─ capacity > 0  → stk_push(ptr)  ← 压回栈
  └─ 解锁
```

---

## 特殊语法点

**`static __u64 zero = 0`（第 20 行）**

```20:20:lib/alloc/stack.bpf.c
static __u64 zero = 0;
```

这不是普通的零值变量，是为了绕过 BPF 验证器的限制。注释（第 11-19 行）解释得很清楚：

> `can_loop` / `may_goto` 机制要求循环计数器对验证器来说是"不精确"的（imprecise）。如果写 `i = 0`（常量初始化），验证器会把 `i` 标记为精确值，`may_goto` 就无法帮助收敛循环。必须从一个**验证器无法静态推断值**的变量（`zero`）初始化，让计数器保持不精确，验证器才能接受循环。*/