# LoongBleed

[English](README.md)

LoongBleed 是一种硬件漏洞，概念上类似于 [ZenBleed (CVE-2023-20593)](https://lock.cmpxchg8b.com/zenbleed.html)，影响同时实现了 LSX（128 位 SIMD）和 LASX（256 位 SIMD）的龙芯 LA464/LA664 处理器。

在 LoongArch 架构中，LSX `$vr` 寄存器（128 位）与 LASX `$xr` 寄存器（256 位）的低 128 位重叠。LSX 指令和基础浮点操作在架构上只应操作低 128 位（或其子集）；对应 `$xr` 寄存器的高位应当保持不变。然而，由于微架构缺陷，这些操作**可能通过** `$xr` 的高 128 位**泄露数据**，从而将敏感数据暴露到特权边界之外或 SMT 线程之间。

> **独立发现说明** — CISPA Helmholtz 信息安全中心的研究人员也独立发现了相同的底层硬件缺陷，并以 **LoongLeak** 之名公开发表（[https://loongleakattack.com/](https://loongleakattack.com/)），相关论文发表于 USENIX Security 2026："LoongLeak: Architectural Cross-Privilege-Boundary Data Leakage on LoongArch CPUs"。我们的工作独立于 LoongLeak 团队开展；两个团队得出了相同的结论：龙芯 LA464/LA664 处理器会通过 LASX `$xr` 寄存器未定义的高位泄露数据。需要说明的是，我们触发泄露所用的指令与 LoongLeak 论文中报告的指令并不完全一致：我们的 PoC 使用了一组不同的探测指令（`vor.v`、`vld`、`fld.d`、`fld.s`）来复现同一底层硬件缺陷。此外，由于不使用任何 load 指令（如纯寄存器指令 `vor.v`）也能触发泄露，我们的分析倾向于认为根因是物理寄存器复用：被复用的物理寄存器高位未被清零，从而泄露了先前占用者的陈旧数据。这与 LoongLeak 论文将泄露数据归因于 L1 数据缓存的分析有所不同。

## 时间线

- **2026-05-12** — 将漏洞上报给龙芯公司。
- **2026-06-09** — 龙芯公司确认这是对已有漏洞的独立发现。
- **2026-08-17** — 龙芯官方公开发布了关于 LoongLeak 漏洞的说明（[官方公告](https://www.loongson.cn/news/show?id=850)）

## 工作原理

概念验证程序的工作流程如下：

1. **加载**：通过 `xvld` 将全零数据加载到 `$xrN` 寄存器中。
2. **执行**：运行一条仅应触及低 128 位（或其子集）的指令（LSX 或基础浮点操作）。
3. **存储**：通过 `xvst` 将完整的 256 位寄存器内容读回。
4. **比较**：对比全部 256 位与原始值。如果高 128 位或低 128 位与预期的零值不同，则说明发生了泄露。

该 PoC 在绑定到物理核心的线程上，对 16 个架构向量寄存器（`$xr0`–`$xr15`）重复执行上述探测。若操作后出现非零值，表明微架构已将陈旧数据或跨上下文数据传播到架构寄存器状态中。

## 探测指令（Gadgets）

PoC 支持多种测试指令，通过 `--gadget` 选择：

| Gadget  | 指令                     | 说明                                   | LA664 泄露 | LA464 泄露 |
|---------|--------------------------|----------------------------------------|------------|------------|
| `vor`   | `vor.v $vrN, $vrN, $vrN` | $vrN 自身的按位或                      | 是         | 否         |
| `vld`   | `vld $vrN, …`            | 128 位内存加载到 $vrN                  | 是         | 是         |
| `fld.d` | `fld.d $fN, …`           | 64 位浮点加载到 $fN（$vrN 低 64 位别名） | 是         | 是         |
| `fld.s` | `fld.s $fN, …`           | 32 位浮点加载到 $fN（$vrN 低 32 位别名） | 是         | 是         |

在 **LA664** 上，全部四个 gadget 均能触发泄露，每条向量最多泄露 192 位。
在 **LA464** 上，`vld`、`fld.d`、`fld.s` 可触发泄露（每条向量最多泄露 224 位）；
默认的 `vor.v` gadget 在 LA464 上无效。

## 用法

```text
用法：./loongbleed_poc [选项]

选项：
  -a, --all                在每个物理核心上启动一个探测线程。
                            默认仅在 CPU 0 上启动单线程。
  -g, --gadget [vor|vld|fld.d|fld.s]
                            使用不同的指令进行测试。
  -h, --help               显示此帮助信息并退出。
```

### 示例

```shell
# 单线程模式，CPU 0
./run.sh

# 单线程模式，使用 vld gadget（LA464 必需）
./run.sh --gadget vld

# 所有物理核心，默认 gadget
./run.sh -a

# 所有核心，使用 fld.d gadget
./run.sh --all --gadget fld.d
```

## 攻击场景

### LA664（例如龙芯 3C6000/D）

受害线程在一个逻辑 CPU 上处理敏感数据，同时 PoC 在其 SMT 兄弟线程上探测寄存器。嗅探线程可以在泄露的高位比特中观察到受害数据的片段。

```shell
# 终端 1 — 在 CPU 0 上启动 LoongBleed
./run.sh

# 终端 2 — 在 SMT 兄弟线程（CPU 1）上运行受害负载
while true; do numactl -C 1 sort < /etc/shadow > /dev/null; done
```

也可使用自动化脚本：

```shell
./poc_la664.sh
```

该脚本在 CPU 1（CPU 0 的 SMT 兄弟）上启动 `sort` 负载，并在 CPU 0 上使用默认 gadget 启动 LoongBleed。

### LA464

受害线程在一个 CPU 上处理敏感数据，同时 PoC 在同一个核上探测寄存器。需要 `--gadget vld` 参数，因为默认的 `vor.v` gadget 在 LA464 上不会泄露数据。

```shell
# 终端 1 — 在 CPU 0 上启动 LoongBleed
./run.sh --gadget vld

# 终端 2 — 在同一个 CPU 上运行受害负载
while true; do numactl -C 0 sort < /etc/shadow > /dev/null; done
```

也可使用自动化脚本：

```shell
./poc_la464.sh
```

该脚本在 CPU 0 上启动 `sort` 负载，并使用 `--gadget vld` 启动 LoongBleed。

## 编译

PoC 是一个单文件 C++ 程序，无外部依赖。

```shell
g++ -std=c++11 -O2 -march=native -pthread -o loongbleed_poc loongbleed_poc.cpp
```

或者使用提供的脚本：

```shell
./run.sh
# 或者，对 LA464：
./run.sh --gadget vld
```

## 输出解读

当检测到泄露且泄露字节中包含至少 8 个连续的可打印 ASCII 字符（0x20–0x7e）时，PoC 会输出：

```
[cpu   0] LEAK chunk=14 data=0x7461646e756f4620_6572617774666f53_0000000000000000_0000000000000000 ascii=............Software Foundat
```

- **cpu** — 检测线程所绑定的逻辑 CPU
- **chunk** — 触发泄露的向量寄存器槽位（`$xr0`–`$xr15`）
- **data** — 指令后从 `$xrN` 读回的全部 256 位值，以 `data3_data2_data1_data0` 格式显示，其中：
  - `data0` = 位 [63:0]（结果的最低 64 位）
  - `data1` = 位 [127:64]（低 128 位半部分的高 64 位）
  - `data2` = 位 [191:128]（高 128 位半部分的低 64 位）
  - `data3` = 位 [255:192]（高 128 位半部分的高 64 位）
- **ascii** — 28 字节窗口（结果字节 4–31，即高 224 位减去最低 32 位）的可打印字符解释。不可打印字节显示为 `.`。

高 128 位（`data2` 或 `data3`）中的任何非零值均表示微架构数据泄露。

## 发现过程

该漏洞是在阅读 Chips and Cheese 的文章《[Loongson's LSX and LASX Vector Extensions](https://chipsandcheese.com/p/loongsons-lsx-and-lasx-vector-extensions)》时发现的。文中提到向量指令会残留一些随机数据，这让我们联想到：会不会是寄存器重命名没有清空寄存器——这与 ZenBleed 的机制类似——理论上就可以泄露内核态数据。于是我们做了实验验证这一假设，发现确实如此，并且在龙芯 3A5000 和 3A6000 上都能复现。

## 免责声明

本项目仅供教育和安全研究目的使用。
