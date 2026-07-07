// SPDX-License-Identifier: GPL-2.0
// 采用 GPL-2.0 许可证。讲解：SPDX 许可证标识，供工具机读，声明本文件遵循的开源协议。
// ETD for scx_cake - measures inter-core latency via CAS ping-pong (adapted from nviennot/core-to-core-latency)
// scx_cake 的 ETD：通过 CAS 乒乓法测量核间延迟（改编自 nviennot/core-to-core-latency）。讲解：用原子比较交换在两核间反复传递标志位，据往返耗时估算通信延迟。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};

use log::{debug, info};
use quanta::Clock;

/// Cache-line padded atomic to avoid false sharing
/// 经缓存行填充的原子布尔，用于避免伪共享。讲解：按 64 字节对齐，防止相邻数据落入同一缓存行而引发跨核缓存失效。
#[repr(align(64))]
struct PaddedAtomicBool {
    val: AtomicBool,
    _pad: [u8; 63],
}

impl PaddedAtomicBool {
    fn new(v: bool) -> Self {
        Self {
            val: AtomicBool::new(v),
            _pad: [0u8; 63],
        }
    }
}

/// Shared state for two-buffer ping-pong (avoids SMT contention)
/// 双缓冲乒乓所用的共享状态（规避 SMT 争用）。讲解：包含同步栅栏与标志位，供两个线程协调收发。
struct SharedState {
    barrier: Barrier,
    flag: PaddedAtomicBool,
}

const PING: bool = false;
const PONG: bool = true;

/// Configuration for ETD calibration
/// ETD 校准的配置项。讲解：集中管理迭代次数、采样数等测量参数。
pub struct EtdConfig {
    /// Number of round-trips per sample
    /// 每个样本的往返次数。讲解：一次采样内乒乓往返的循环轮数。
    pub iterations: u32,
    /// Number of samples to collect
    /// 需要采集的样本数量。讲解：重复测量的次数，用于统计。
    pub samples: u32,
    /// Warmup iterations to stabilize boost clocks (discarded)
    /// 用于稳定睿频的预热迭代次数（结果丢弃）。讲解：先空跑让 CPU 频率进入稳态，避免影响正式测量。
    pub warmup: u32,
    /// Maximum acceptable standard deviation (ns) - samples exceeding this trigger retry
    /// 可接受的最大标准差（纳秒）——超过则触发重测。讲解：抖动过大说明受干扰，需要重新采样。
    pub max_stddev: f64,
}

impl Default for EtdConfig {
    fn default() -> Self {
        Self {
            // Display-grade: 500 iterations @ 50 samples (sufficient for heatmap accuracy)
            // 展示级精度：500 次迭代 @ 50 个样本（足以保证热力图精度）。讲解：在精度与耗时之间取折中。
            iterations: 500,
            samples: 50,
            // 200 warmup iters to stabilize boost clocks
            // 200 次预热迭代以稳定睿频。讲解：正式计时前先热身，减少频率漂移误差。
            warmup: 200,
            // Discard samples with σ > 15ns (relaxed for faster calibration)
            // 丢弃 σ > 15ns 的样本（为加快校准而放宽阈值）。讲解：过滤抖动过大的异常样本。
            max_stddev: 15.0,
        }
    }
}

/// Measure round-trip latency between two CPUs using CAS ping-pong. Returns per-sample latencies (ns).
/// 使用 CAS 乒乓测量两个 CPU 间的往返延迟，返回每个样本的延迟（纳秒）。讲解：核心测量函数，输出各次采样结果供上层统计。
fn measure_pair(cpu_a: usize, cpu_b: usize, config: &EtdConfig) -> Option<Vec<f64>> {
    let state = Arc::new(SharedState {
        barrier: Barrier::new(2),
        flag: PaddedAtomicBool::new(PING),
    });

    let clock = Arc::new(Clock::new());
    let num_round_trips = config.iterations as usize;
    let num_samples = config.samples as usize;
    let warmup_trips = config.warmup as usize;

    let state_pong = Arc::clone(&state);
    let state_ping = Arc::clone(&state);
    let clock_ping = Arc::clone(&clock);

    crossbeam_utils::thread::scope(|s| {
        // PONG thread: waits for PING, sets to PONG
        // PONG 线程：等待 PING，然后置为 PONG。讲解：被动方，收到对方信号后立即回应。
        let pong = s.spawn(move |_| {
            let core_id = core_affinity::CoreId { id: cpu_b };
            if !core_affinity::set_for_current(core_id) {
                return;
            }

            // Set real-time priority to minimize preemption jitter
            // 设置实时优先级以最小化被抢占造成的抖动。讲解：用 SCHED_FIFO 高优先级减少调度干扰。
            unsafe {
                #[cfg(target_env = "gnu")]
                let param = libc::sched_param { sched_priority: 99 };
                #[cfg(target_env = "musl")]
                let param = libc::sched_param {
                    sched_priority: 99,
                    sched_ss_low_priority: 0,
                    sched_ss_repl_period: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    sched_ss_init_budget: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    sched_ss_max_repl: 0,
                };
                libc::sched_setscheduler(0, libc::SCHED_FIFO, &param);
            }

            state_pong.barrier.wait();

            // Warmup phase (not timed, stabilizes boost clocks)
            // 预热阶段（不计时，用于稳定睿频）。讲解：空跑若干轮让频率进入稳态。
            for _ in 0..warmup_trips {
                while state_pong
                    .flag
                    .val
                    .compare_exchange(PING, PONG, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
                {
                    std::hint::spin_loop();
                }
            }

            // Measurement phase
            // 测量阶段。讲解：正式计时的乒乓循环。
            for _ in 0..(num_round_trips * num_samples) {
                while state_pong
                    .flag
                    .val
                    .compare_exchange(PING, PONG, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
                {
                    std::hint::spin_loop();
                }
            }

            // Reset to normal priority before thread exit
            // 线程退出前恢复为普通优先级。讲解：还原为 SCHED_OTHER，避免影响系统其他任务。
            unsafe {
                #[cfg(target_env = "gnu")]
                let param = libc::sched_param { sched_priority: 0 };
                #[cfg(target_env = "musl")]
                let param = libc::sched_param {
                    sched_priority: 0,
                    sched_ss_low_priority: 0,
                    sched_ss_repl_period: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    sched_ss_init_budget: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    sched_ss_max_repl: 0,
                };
                libc::sched_setscheduler(0, libc::SCHED_OTHER, &param);
            }
        });

        // PING thread: sets to PING, waits for PONG, measures time
        // PING 线程：置为 PING，等待 PONG，并测量耗时。讲解：主动方，负责计时统计。
        let ping = s.spawn(move |_| {
            let core_id = core_affinity::CoreId { id: cpu_a };
            if !core_affinity::set_for_current(core_id) {
                return None;
            }

            // Set real-time priority to minimize preemption jitter
            // 设置实时优先级以最小化被抢占造成的抖动。讲解：用 SCHED_FIFO 高优先级减少调度干扰。
            unsafe {
                #[cfg(target_env = "gnu")]
                let param = libc::sched_param { sched_priority: 99 };
                #[cfg(target_env = "musl")]
                let param = libc::sched_param {
                    sched_priority: 99,
                    sched_ss_low_priority: 0,
                    sched_ss_repl_period: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    sched_ss_init_budget: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    sched_ss_max_repl: 0,
                };
                libc::sched_setscheduler(0, libc::SCHED_FIFO, &param);
            }

            let mut results = Vec::with_capacity(num_samples);

            state_ping.barrier.wait();

            // Warmup phase (not timed, stabilizes boost clocks)
            // 预热阶段（不计时，用于稳定睿频）。讲解：空跑若干轮让频率进入稳态。
            for _ in 0..warmup_trips {
                while state_ping
                    .flag
                    .val
                    .compare_exchange(PONG, PING, Ordering::AcqRel, Ordering::Relaxed)
                    .is_err()
                {
                    std::hint::spin_loop();
                }
            }

            // Measurement phase
            // 测量阶段。讲解：按样本数分批计时的乒乓循环。
            for _ in 0..num_samples {
                let start = clock_ping.raw();

                for _ in 0..num_round_trips {
                    while state_ping
                        .flag
                        .val
                        .compare_exchange(PONG, PING, Ordering::AcqRel, Ordering::Relaxed)
                        .is_err()
                    {
                        std::hint::spin_loop();
                    }
                }

                let end = clock_ping.raw();
                let duration_ns = clock_ping.delta(start, end).as_nanos() as f64;
                // One-way latency = total time / (round_trips * 2 hops)
                // 单向延迟 = 总耗时 / (往返次数 × 2 跳)。讲解：一次往返含去回两跳，故除以 2 得单向延迟。
                results.push(duration_ns / (num_round_trips as f64 * 2.0));
            }

            // Reset to normal priority before thread exit
            // 线程退出前恢复为普通优先级。讲解：还原为 SCHED_OTHER，避免影响系统其他任务。
            unsafe {
                #[cfg(target_env = "gnu")]
                let param = libc::sched_param { sched_priority: 0 };
                #[cfg(target_env = "musl")]
                let param = libc::sched_param {
                    sched_priority: 0,
                    sched_ss_low_priority: 0,
                    sched_ss_repl_period: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    sched_ss_init_budget: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                    sched_ss_max_repl: 0,
                };
                libc::sched_setscheduler(0, libc::SCHED_OTHER, &param);
            }

            Some(results)
        });

        pong.join().unwrap();
        ping.join().unwrap()
    })
    .ok()?
}

/// Perform full topology calibration. Returns matrix[i][j] = latency from CPU i to CPU j.
/// 执行完整的拓扑校准，返回 matrix[i][j] 表示从 CPU i 到 CPU j 的延迟。讲解：两两测量所有 CPU，生成对称延迟矩阵。
pub fn calibrate_full_matrix<F>(
    nr_cpus: usize,
    config: &EtdConfig,
    mut progress_callback: F,
) -> Vec<Vec<f64>>
where
    F: FnMut(usize, usize, bool),
{
    let mut matrix = vec![vec![0.0; nr_cpus]; nr_cpus];

    info!(
        "ETD: Starting calibration for {} CPUs ({} iterations × {} samples)",
        nr_cpus, config.iterations, config.samples
    );

    let start = std::time::Instant::now();

    // Calculate total pairs to measure
    // 计算需要测量的 CPU 对总数。讲解：n*(n-1)/2 为无序对数量，用于进度显示。
    let total_pairs = (nr_cpus * (nr_cpus - 1)) / 2;
    let mut current_pair = 0;

    #[allow(clippy::needless_range_loop)]
    for cpu_a in 0..nr_cpus {
        for cpu_b in (cpu_a + 1)..nr_cpus {
            current_pair += 1;
            let mut retry_count = 0;
            const MAX_RETRIES: u32 = 3;

            while let Some(samples) = measure_pair(cpu_a, cpu_b, config) {
                if !samples.is_empty() {
                    // Calculate mean and standard deviation
                    // 计算均值与标准差。讲解：用于评估样本抖动是否可接受。
                    let n = samples.len() as f64;
                    let mean = samples.iter().sum::<f64>() / n;
                    let variance = samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
                    let stddev = variance.sqrt();

                    // Check if variance is acceptable (no IRQ interference)
                    // 检查方差是否可接受（无 IRQ 干扰）。讲解：抖动小说明测量未被中断打断。
                    if stddev <= config.max_stddev || retry_count >= MAX_RETRIES {
                        // Use median for final value (more robust than mean)
                        // 采用中位数作为最终值（比均值更稳健）。讲解：中位数抗离群点，减少偶发抖动影响。
                        let mut sorted = samples;
                        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
                        let median = sorted[sorted.len() / 2];

                        matrix[cpu_a][cpu_b] = median;
                        matrix[cpu_b][cpu_a] = median;

                        if stddev > config.max_stddev {
                            debug!(
                                "ETD: CPU {}<->{} stddev={:.1}ns (exceeded threshold after {} retries)",
                                cpu_a, cpu_b, stddev, retry_count
                            );
                        }

                        // Report progress (not complete yet)
                        // 上报进度（尚未完成）。讲解：回调通知调用方当前进度，false 表示未结束。
                        progress_callback(current_pair, total_pairs, false);
                        break;
                    } else {
                        retry_count += 1;
                        debug!(
                            "ETD: CPU {}<->{} stddev={:.1}ns > {:.1}ns, retrying ({}/{})",
                            cpu_a, cpu_b, stddev, config.max_stddev, retry_count, MAX_RETRIES
                        );
                    }
                } else {
                    break; // Empty samples, skip
                    // 空样本，跳过。讲解：无有效数据时直接退出该对的测量。
                }
            }
        }
    }

    // Final progress update to signal completion
    // 最终进度更新，用于通知已完成。讲解：以 true 标记校准结束。
    progress_callback(total_pairs, total_pairs, true);

    let elapsed = start.elapsed();
    info!("ETD: Calibration complete in {:.2}s", elapsed.as_secs_f64());

    // Log the matrix for debugging
    // 输出矩阵用于调试。讲解：以 debug 日志打印完整延迟矩阵。
    debug!("ETD: Latency matrix (ns):");
    for (i, row) in matrix.iter().enumerate() {
        debug!(
            "  CPU {:2}: {:?}",
            i,
            row.iter().map(|v| format!("{:.1}", v)).collect::<Vec<_>>()
        );
    }

    matrix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measure_pair_smoke() {
        // Just verify it doesn't panic on a 2-CPU system
        // 仅验证在 2 核系统上不会 panic。讲解：冒烟测试，确保基本调用路径可用。
        let config = EtdConfig {
            iterations: 100,
            samples: 2,
            warmup: 10,
            max_stddev: 100.0,
        };
        let result = measure_pair(0, 1, &config);
        // Result might be None if pinning fails, that's OK in tests
        // 若绑核失败结果可能为 None，测试中可接受。讲解：CI 环境可能无法固定核，允许跳过。
        if let Some(latencies) = result {
            for latency in &latencies {
                assert!(*latency > 0.0, "Latency should be positive");
                assert!(
                    *latency < 1_000_000.0,
                    "Latency should be reasonable (<1ms)"
                );
            }
        }
    }
}
