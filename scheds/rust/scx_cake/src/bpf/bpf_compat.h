/* scx_cake/bpf/bpf_compat.h */
#ifndef __CAKE_BPF_COMPAT_H
#define __CAKE_BPF_COMPAT_H

/* Compiler abstraction: Clang 21+ uses formal atomics for MLP; <21 uses scalpel-optimized ASM */
/* 编译器抽象层：Clang 21+ 使用正式的原子操作以支持内存级并行(MLP)；21 以下则退回手工优化的内联汇编。 */
/* 讲解：这一层封装屏蔽了不同 Clang 版本对 relaxed 原子读写支持的差异，保证上层代码统一。 */

#if defined(__clang__) && __clang_major__ >= 21

    /* MODERN PATH: Formal Atomics (Max Performance) */
    /* 现代路径：正式的原子内建函数（性能最佳） */
    /* 讲解：__ATOMIC_RELAXED 表示只保证原子性、不施加内存序，是最轻量的原子访问方式。 */
    #define cake_relaxed_load_u32(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define cake_relaxed_store_u32(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)

#else

    /* COMPAT PATH: Scalpel-Optimized Inline Assembly */
    /* 兼容路径：手工精调的内联汇编 */
    /* 讲解：旧版 Clang 缺少理想的 relaxed 原子代码生成，这里直接手写 BPF 汇编避免多余的寄存器溢出。 */

    static __always_inline u32 cake_relaxed_load_u32(const volatile u32 *ptr) {
        u32 val;
        asm volatile(
            "%0 = *(u32 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr), "m"(*ptr)  /* Targeted dependency, no global spill */
                                   /* 精确指定内存依赖，避免全局寄存器溢出 */
                                   /* 讲解："m"(*ptr) 让编译器知道只依赖该地址，从而生成更紧凑的代码。 */
        );
        return val;
    }

    static __always_inline void cake_relaxed_store_u32(volatile u32 *ptr, u32 val) {
        asm volatile(
            "*(u32 *)(%1 + 0) = %2"
            : "=m"(*ptr)           /* Only this address modified */
                                   /* 仅修改这一个地址 */
                                   /* 讲解：显式声明输出内存位置，防止编译器误判有其它副作用。 */
            : "r"(ptr), "r"(val)
        );
    }

#endif

#endif /* __CAKE_BPF_COMPAT_H */
