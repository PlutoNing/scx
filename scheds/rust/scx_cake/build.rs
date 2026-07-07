// SPDX-License-Identifier: GPL-2.0
// Build script for scx_cake - compiles BPF code and generates bindings
// scx_cake 的构建脚本——负责编译 BPF 代码并生成 Rust 绑定。
// 讲解：Cargo 会在编译主程序前先运行 build.rs，这里用它来驱动 BPF 侧的编译流程。

fn main() {
    // Detect build profile: release builds pass CAKE_RELEASE=1 to BPF Clang,
    // which eliminates ALL stats/telemetry code at compile time (zero overhead).
    // Debug builds retain full --verbose/TUI support via volatile RODATA toggle.
    // 检测构建配置：release 构建会向 BPF 的 Clang 传入 CAKE_RELEASE=1，
    // 从而在编译期彻底删除所有统计/遥测代码（零运行时开销）；
    // debug 构建则通过 volatile 的 RODATA 开关保留完整的 --verbose/TUI 支持。
    // 讲解：用编译期宏区分发布版与调试版，发布版把遥测代码整段裁掉以追求最低调度延迟。
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let base_flags = "-O2 -mcpu=v3 -fno-stack-protector -fno-asynchronous-unwind-tables";
    let cflags = if profile == "release" {
        format!("{} -DCAKE_RELEASE=1", base_flags)
    } else {
        base_flags.to_string()
    };
    std::env::set_var("BPF_EXTRA_CFLAGS_PRE_INCL", &cflags);
    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/cake.bpf.c", "bpf")
        .add_source("src/bpf/lib/arena.bpf.c")
        .add_source("src/bpf/lib/rbtree.bpf.c")
        .add_source("src/bpf/lib/atq.bpf.c")
        .add_source("src/bpf/lib/sdt_alloc.bpf.c")
        .add_source("src/bpf/lib/sdt_task.bpf.c")
        .add_source("src/bpf/lib/bitmap.bpf.c")
        .add_source("src/bpf/lib/cpumask.bpf.c")
        .add_source("src/bpf/lib/topology.bpf.c")
        .compile_link_gen()
        .unwrap();
}
