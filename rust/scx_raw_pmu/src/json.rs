use anyhow::bail;
use csv::Reader;
use procfs::CpuInfo;
use procfs::Current as _;
use regex::Regex;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use std::env;
use std::env::consts::ARCH;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crate::resources::ResourceDir;
use anyhow::Result;

use std::collections::HashMap;

fn hex_to_u64<'de, D>(de: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    let s = s.to_lowercase();
    let s = s.trim_start_matches("0x");
    u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)
}

// Intel offcore (OCR) events return two event codes, because
// codes represent event slots and not the events themselves.
fn hexlist<'de, D>(de: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut result = vec![];
    let s: &str = Deserialize::deserialize(de)?;
    for token in s.split(',') {
        let radix = if token.to_lowercase().starts_with("0x") {
            16
        } else {
            10
        };
        let event = u64::from_str_radix(token.to_lowercase().trim_start_matches("0x"), radix)
            .map_err(serde::de::Error::custom)?;

        result.push(event);
    }

    Ok(result)
}

fn num_to_bool<'de, D>(de: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let s: &str = Deserialize::deserialize(de)?;
    let num = u64::from_str_radix(s, 16).map_err(serde::de::Error::custom)?;
    Ok(num != 0)
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PMUSpec {
    // There's a typo in the AMD Zen4/5 JSON for
    // one of the PMUs.
    #[serde(alias = "BriefDescription", alias = "BriefDescript6ion")]
    desc: Option<String>,

    #[serde(alias = "PublicDescription")]
    desc_public: Option<String>,

    #[serde(alias = "EventCode")]
    #[serde(deserialize_with = "hexlist")]
    pub event: Vec<u64>,

    #[serde(alias = "EventName")]
    pub name: String,

    #[serde(alias = "UMask")]
    #[serde(deserialize_with = "hex_to_u64")]
    pub umask: u64,

    #[serde(alias = "Unit")]
    pmu: Option<String>,

    #[serde(alias = "ConfigCode")]
    #[serde(deserialize_with = "hex_to_u64")]
    config: u64,

    // Derived fields
    #[serde(alias = "MetricExpr")]
    metric_expr: Option<String>,

    #[serde(alias = "MetricName")]
    metric_name: Option<String>,

    #[serde(alias = "MetricGroup")]
    metric_group: Option<String>,

    #[serde(alias = "MetricConstraint")]
    metric_constraint: Option<String>,

    #[serde(alias = "PerPkg")]
    #[serde(deserialize_with = "num_to_bool")]
    per_pkg: bool,

    #[serde(alias = "Invert")]
    #[serde(deserialize_with = "num_to_bool")]
    invert: bool,

    #[serde(alias = "MSRIndex")]
    #[serde(deserialize_with = "hexlist", default)]
    msr_index: Vec<u64>,

    #[serde(alias = "MSRValue")]
    #[serde(deserialize_with = "hex_to_u64")]
    msr_value: u64,

    #[serde(alias = "Counter")]
    counter: Option<String>,

    #[serde(alias = "CounterNumFixed")]
    counters_num_fixed: Option<u64>,

    #[serde(alias = "CounterNumGeneric")]
    counters_num_generic: Option<u64>,
}

pub struct PMUManager {
    pub dataroot: OsString,
    pub arch: String,
    pub tuple: String,
    pub codename: String,
    pub pmus: HashMap<String, PMUSpec>,
}
/* 为什么必须区分不同架构
普通调度逻辑，例如：

任务属于哪个 layer；
哪些 CPU 可以使用；
CPU 利用率；
NUMA/LLC 拓扑；
idle CPU 选择；
大部分可以通过统一的内核接口实现。

但是 PMU 原始事件不是统一接口。PMU 可以理解为 CPU 内部的硬件统计器，它统计：
指令、周期；
cache miss；
DRAM 数据填充；
分支预测失败；
解码器、执行单元、load/store queue 是否阻塞。
这些事件的编号和含义由具体 CPU 厂商及微架构定义。即使都运行 x86：

AMD Zen 5 和 Intel Sapphire Rapids 的事件编号不同；
Zen 3 和 Zen 5 的同类事件也可能换名字、换编码或改变语义；
某个 CPU 有的事件，另一个 CPU 可能根本没有。
因此不能写死一个全平台通用编号。例如：
AMD Zen 5:
  ls_any_fills_from_sys.dram_io_all
  EventCode = 0x44
  UMask     = 0x48

Intel:
  LONGEST_LAT_CACHE.MISS
 它们都是用来近似内存流量的事件，但名字和硬件编码不同。

如果把 Zen 5 编码用在 Intel 上，可能出现：

perf_event_open() 直接失败；
事件可以打开，但统计的是完全不同的东西；
数值看似正常，实际语义错误，这是最危险的情况；
最终导致 layer 内存带宽估算错误，CPU 数量限制失效或误限流。
  */
impl PMUManager {
    /// Identify the architecture of the local machine and
    /// retrieve the paths to the relevant JSON files.
    fn identify_architecture() -> Result<String> {
        let cpuinfo = CpuInfo::current()?;
        Ok(format!(
            "{}-{}-{:X}",
            cpuinfo.fields["vendor_id"],
            cpuinfo.fields["cpu family"],
            cpuinfo.fields["model"].parse::<i32>().unwrap()
        ))
    }

    /// List all available counters for the current machine.
    pub fn list_counters(&self) -> Result<()> {
        for pmu in self.pmus.iter() {
            println!("{}", serde_json::to_string_pretty(&pmu)?);
        }

        Ok(())
    }

    pub fn list_metadata(&self) -> () {
        println!("Dataroot {}", self.dataroot.to_string_lossy());
        println!("Arch: {}", self.arch);
        println!("Tuple: {}", self.tuple);
        println!("Codename: {}", self.codename);
    }

    fn read_file_counters(json_bytes: &[u8]) -> Result<Vec<PMUSpec>> {
        Ok(serde_json::from_slice(json_bytes)?)
    }
/* 
程序如何识别 CPU
PMUManager 首先读取 /proc/cpuinfo，组成：


vendor_id-cpu_family-model
例如 Zen 5 会匹配类似：


AuthenticAMD-26-*
mapfile.csv 把它映射到 amdzen5。然后加载 arch/x86/amdzen5/ 下的所有 JSON：
最终得到类似：


PMUManager {
    arch: "x86",
    codename: "amdzen5",
    pmus: {
        "de_op_queue_empty" -> ...
        "ls_any_fills_from_sys.dram_io_all" -> ...
    }
}
*/
    fn arch_code() -> String {
        String::from(match ARCH {
            "x86" => "x86",
            "x86_64" => "x86",
            "aarch64" => "arm64",
            "powerpc" => "powerpc",
            "powerpc64" => "powerpc",
            "riscv32" => "riscv",
            "riscv64" => "riscv",
            "s390x" => "s390",
            "loongarch32" => "x86",
            "loongarch64" => "x86",
            _ => panic!("unsupported architecture"),
        })
    }

    fn spec_dir(resource_dir: &ResourceDir, arch: &str, tuple: &str) -> Result<String> {
        let arch_dir = resource_dir.get_dir(arch)?;
        let mapfile = arch_dir.get_file("mapfile.csv")?;
        let mapfile_contents = mapfile.read()?;

        for record in Reader::from_reader(mapfile_contents.as_ref()).records() {
            let record = record?;
            let regex = record.get(0).expect("no regex found in csv");
            let codename = record.get(2).expect("no codename found in csv");
            let re = Regex::new(regex)?;

            if re.is_match(tuple) {
                return Ok(codename.to_string());
            }
        }

        bail!("No matching config for tuple")
    }

    fn new_with_resource_dir(
        resource_dir: ResourceDir,
        dataroot_display: OsString,
    ) -> Result<Self> {
        let tuple = Self::identify_architecture()?;
        let arch = Self::arch_code();
        let codename = Self::spec_dir(&resource_dir, &arch, &tuple)?;

        let arch_dir = resource_dir.get_dir(&arch)?;
        let spec_dir = arch_dir.get_dir(&codename)?;

        let mut pmus = HashMap::new();
        for file in spec_dir.files()? {
            // metricgroups.json isn't actually PMU definitions.
            if file.path().ends_with("metricgroups.json") {
                continue;
            }

            let file_contents = file.read()?;
            let counters = Self::read_file_counters(file_contents.as_ref())?;

            for counter in counters.iter() {
                pmus.insert(String::from(&counter.name), counter.clone());
            }
        }

        Ok(Self {
            dataroot: dataroot_display,
            arch,
            tuple,
            codename,
            pmus,
        })
    }

    pub fn new() -> Result<Self> {
        let mut dataroot: OsString = env::current_exe()?.into();
        dataroot.push(":embedded");

        let resource_dir = ResourceDir::default();
        Self::new_with_resource_dir(resource_dir, dataroot)
    }

    pub fn new_with_dataroot(dataroot: Option<&Path>) -> Result<Self> {
        let dataroot = match dataroot {
            Some(path) => fs::canonicalize(path)?,
            None => env::current_dir()?.to_path_buf(),
        };

        let resource_dir = ResourceDir::new_filesystem(dataroot.clone());
        Self::new_with_resource_dir(resource_dir, dataroot.into())
    }
}
