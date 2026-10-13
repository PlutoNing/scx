#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

#include <lib/atq.h>

/*
 * Arena task queue implementation.
 */
/* atq.bpf.c 实现了 ATQ（Arena Task Queue，Arena 任务队列），这是 scx 调度框架在
 BPF arena 内部使用的任务排队数据结构。

ATQ 的核心：以红黑树为底层，支持两种模式：

FIFO 模式：按先进先出顺序出队，内部用单调递增的 seq 作为红黑树键。
优先级（vtime）模式：按 virtual time 出队，最小 vtime 的任务最先被调度。
与普通内核队列的区别：ATQ 完全运行在 BPF arena 地址空间内，配合 arena 自旋锁实现并发安全，
且支持并发竞争插入（同一任务可能被多个 CPU 同时尝试插入不同的 ATQ）。 */
static struct scx_allocator scx_atq_allocator;

/* 初始化一个静态全局的 scx_allocator，用于后续 scx_atq_create 时分配 scx_atq_t
 对象。scx_alloc_init 内部使用栈式对象池（stk.bpf.c），所有 ATQ 对象大小固定为
  sizeof(scx_atq_t)。 */
__weak
int scx_atq_init(void)
{
	return scx_alloc_init(&scx_atq_allocator, sizeof(scx_atq_t));
}

/* scx_alloc 返回的内存是零初始化的（注释明确说明），所以 atq->size = 0、atq->seq = 0、
atq->lock = 0 都自动成立。

rb_create(RB_NOALLOC, RB_DUPLICATE)：创建红黑树实例。

RB_NOALLOC：红黑树节点内嵌在任务结构体中（scx_task_common.node），不需要红黑树自己分配节点
内存。
RB_DUPLICATE：允许重复键（FIFO 模式下 seq 单调递增不会重复，vtime 模式下可能多个任务有
相同 vtime）。
atq = (scx_atq_t *)data->payload：scx_alloc 返回的是 sdt_data（SDT = Slab Data
Task），它的 payload 才是实际数据区。这是分配器的内部约定，调用者需要自己转型。 */

/* 主要是为了实现 cgroup bw 引入的 */
__weak
u64 scx_atq_create_internal(bool fifo, size_t capacity)
{
	struct sdt_data __arena *data = NULL;
	scx_atq_t *atq;

	/* Note that scx_alloc() returns a zero-initialized memory. */
	data = scx_alloc(&scx_atq_allocator);
	if (unlikely(!data))
		return (u64)NULL;

	atq = (scx_atq_t *)data->payload;
	atq->tid = data->tid;

	atq->tree = rb_create(RB_NOALLOC, RB_DUPLICATE);
	if (!atq->tree) {
		scx_alloc_free_idx(&scx_atq_allocator, atq->tid.idx);
		return (u64)NULL;
	}

	atq->fifo = fifo;
	atq->capacity = capacity;

	return (u64)atq;
}

/* scx_arena_subprog_init()：在调用任何子函数前初始化 arena 上下文（BPF 子程序机制要求，参见 arena_topology_print 的解释）。

销毁流程：

先把所有任务出队（只是为了清理 taskc->atq 指针，不做其他处理）。
销毁红黑树。
把 ATQ 对象还给分配器（通过 tid.idx 标识）。 */
__weak
int scx_atq_destroy(scx_atq_t __arg_arena *atq)
{
	scx_arena_subprog_init();

	while (scx_atq_pop(atq) && can_loop) {
		/* Do nothing. Just drain all the queued tasks. */
	}
	rb_destroy(atq->tree);

	scx_alloc_free_idx(&scx_atq_allocator, atq->tid.idx);
	return 0;
}

/* 核心插入逻辑（无锁版本）
cmpxchg(ptr, expected, new) 原子地：若 *ptr == expected，则把 *ptr 设为 new 并返回旧值；否则不做任何操作，返回旧值。

这里的含义：若 taskc->atq 当前为 0（NULL，任务不在任何队列），就原子地设置为 atq，返回 0（假）；若非 0（任务已在某队列），什么都不做，返回非 0（真）→ 函数返回 -EALREADY。

为什么用 CAS 而不是锁？ 注释解释：多个 CPU 可能同时尝试把同一个任务插入不同的 ATQ，taskc->atq 不受 ATQ 锁保护（因为 ATQ 锁是队列级别的，不是任务级别的）。用原子 CAS 保证只有一个插入者成功，其余返回 -EALREADY。

键的选择：

node->key = (vtime == SCX_ATQ_FIFO) ? atq->seq++ : vtime;
FIFO 模式：用 seq++（单调递增），保证先插入的任务键更小，出队时先出。
vtime 模式：直接用 vtime 作为键，最小 vtime 先出。
注释说 FIFO 模式下 seq 在插入失败后会"泄漏"（不回退），这是刻意设计——只要序列号单调，不要求连续。

__hidden __inline：__inline 即 __attribute__((always_inline))，但此处搭配 __hidden 而非 __weak，见下方的注释讲解。 */
__hidden __inline
int scx_atq_insert_vtime_unlocked(scx_atq_t __arg_arena *atq, scx_task_common __arg_arena *taskc, u64 vtime)
{
	rbnode_t *node = &taskc->node;
	int ret;

	if (unlikely(atq->size == atq->capacity))
		return -ENOSPC;

	if ((vtime == SCX_ATQ_FIFO) != atq->fifo)
		return -EINVAL;

	/*
	 * The ->atq field is not protected by the ATQ
	 * lock, since multiple callers may be trying to
	 * add the same task to differnt ATQs. Use atomic
	 * cmpxchg so that races have a single winner.
	 指向哪就在哪
	 */
	if (cmpxchg(&taskc->atq, 0, atq))
		return -EALREADY;

	/*
	 * For FIFO, "Leak" the seq on error. We only want
	 * sequence numbers to be monotonic, not
	 * consecutive.
	 初始化连接件 node 的 k 和 v
	 */
	node->key = (vtime == SCX_ATQ_FIFO) ? atq->seq++ : vtime;
	node->value = (u64)taskc;

	ret = rb_insert_node(atq->tree, node);
	if (ret) {
		taskc->atq = NULL;
		return ret;
	}

	atq->size += 1;

	return 0;
}

/* 
 * XXXETSAL: We are using the __hidden antipattern for API functions because some
 * older kernels do not allow function calls with preemption disabled. We will replace
 * these annotations with the proper ones (__weak) at some point in the future.
 加锁的 vtime 插入
 */

__hidden
int scx_atq_insert_vtime(scx_atq_t __arg_arena *atq, scx_task_common __arg_arena *taskc, u64 vtime)
{
	int ret;

	/* 标准的"加锁 → 调用无锁版本 → 解锁"模式。 */
	ret = scx_atq_lock(atq);
	if (ret)
		return ret;

	ret = scx_atq_insert_vtime_unlocked(atq, taskc, vtime);

	scx_atq_unlock(atq);

	return ret;
}

__hidden
int scx_atq_insert_unlocked(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
	return scx_atq_insert_vtime_unlocked(atq, taskc, SCX_ATQ_FIFO);
}

__hidden
int scx_atq_insert(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
	return scx_atq_insert_vtime(atq, taskc, SCX_ATQ_FIFO);
}

__hidden
int scx_atq_remove_unlocked(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
	int ret;

       /*
	* Are we in this ATQ in the first place?
	*
	* Note: Unlike in the insert path, the ATQ
	* lock is valid enough protection here.
	*/
       if (taskc->atq != atq)
	       return -EINVAL;

       ret = rb_remove_node(atq->tree, &taskc->node);
       if (ret)
	       return ret;

       taskc->atq = NULL;

       atq->size -= 1;

       return 0;
}

__hidden
int scx_atq_remove(scx_atq_t *atq, scx_task_common __arg_arena *taskc)
{
       int ret;

       ret = scx_atq_lock(atq);
       if (ret)
               return ret;

       ret = scx_atq_remove_unlocked(atq, taskc);

       scx_atq_unlock(atq);

       return ret;
}

/* rb_pop 从红黑树中取出最小键的节点（FIFO 模式下 seq 最小 = 最早入队；vtime 模式下
 vtime 最小 = 最高优先级），同时把键和值（任务指针）通过 out 参数返回。 */
__hidden
u64 scx_atq_pop(scx_atq_t *atq)
{
	scx_task_common *taskc;
	u64 vtime, taskc_ptr;
	int ret;

	ret = scx_atq_lock(atq);
	if (ret)
		return (u64)NULL;

	if (!scx_atq_nr_queued(atq)) {
		scx_atq_unlock(atq);
		return (u64)NULL;
	}

	ret = rb_pop(atq->tree, &vtime, &taskc_ptr);
	if (ret) {
		scx_atq_unlock(atq);

		if (ret != -ENOENT)
			bpf_printk("%s: error %d", __func__, ret);
		return (u64)NULL;
	}

	atq->size -= 1;

	taskc = (scx_task_common *)taskc_ptr;
	taskc->atq = NULL;

	scx_atq_unlock(atq);

	return taskc_ptr;
}

/* rb_least 只读取红黑树最小键节点，不删除。用于调度器决策前"看一眼"队头，
不影响队列状态。 */
__hidden
u64 scx_atq_peek(scx_atq_t *atq)
{
	u64 vtime, taskc_ptr;
	int ret;

	ret = scx_atq_lock(atq);
	if (ret)
		return (u64)NULL;

	if (!scx_atq_nr_queued(atq)) {
		scx_atq_unlock(atq);
		return (u64)NULL;
	}

	ret = rb_least(atq->tree, &vtime, &taskc_ptr);

	scx_atq_unlock(atq);

	return taskc_ptr;
}

__hidden
int scx_atq_nr_queued(scx_atq_t *atq)
{
	return atq->size;
}

/*
 * Cancel ATQ membership for the task. Find any ATQs it is
 * in and pop it out.
 带竞争处理的任务注销
 */
__weak
int scx_atq_cancel(scx_task_common __arg_arena *taskc)
{
	scx_atq_t *atq;
	int ret;

	/*
	 * Copy the ATQ pointer over to the stack and use it to avoid
	 * a racing scx_atq_pop() from overwriting it. Check the
	 * pointer is valid, as expected by the caller.
	 */
	atq = taskc->atq;
	if (!atq)
		return 0;

	if ((ret = scx_atq_lock(atq))) {
		bpf_printk("Failed to lock ATQ for task");
		return ret;
	}

	/* We lost the race, assume whoever popped the task will handle it. */
	if (taskc->atq != atq) {
		/* 发生了 race */
		scx_atq_unlock(atq);
		return 0;
	}
/* 锁定成功 */
	/* Protected from races by the lock. */
	if ((ret = scx_atq_remove_unlocked(taskc->atq, taskc))) {
		/* There is an unavoidable race with scx_atq_pop. */
		bpf_printk("Failed to remove node from task");
	}

	scx_atq_unlock(atq);
	return ret;
}

