// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

/* 利用 scx_cargo 库（Meta 的 scx 项目提供的构建工具）自动完成 BPF 相关的编译、绑定生成和骨架（skeleton）代码生成工作。 */
fn main() {
    /* 创建一个 BpfBuilder 构建器实例，用于配置 BPF 编译流程。 */
    scx_cargo::BpfBuilder::new()
        .unwrap()
        /* 指定一个 接口头文件 src/bpf/intf.h（通常定义了内核态 BPF 程序和用户态 Rust 程序共享的数据结构、常量等），
        通过 bindgen 将其转换为 Rust 绑定代码，输出文件名为 bpf_intf.rs（放在 $OUT_DIR 下） */
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        /* 指定主 BPF 程序源文件 src/bpf/main.bpf.c，将其编译为 BPF 字节码，并生成对应的骨架（skeleton）代码 */
        .enable_skel("src/bpf/main.bpf.c", "bpf")
        /* 添加额外的 BPF 源文件参与编译（比如定时器逻辑、工具函数、PMU 性能计数器相关逻辑） */
        .add_source("src/bpf/timer.bpf.c")
        .add_source("src/bpf/util.bpf.c")
        .add_source("src/bpf/lib/pmu.bpf.c")
        .compile_link_gen()
        .unwrap();
}
