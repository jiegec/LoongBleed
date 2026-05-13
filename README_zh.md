# LoongBleed

[English](README.md)

LoongBleed 是一种硬件漏洞，概念上类似于 [ZenBleed (CVE-2023-20593)](https://lock.cmpxchg8b.com/zenbleed.html)，影响同时实现了 LSX（128 位 SIMD）和 LASX（256 位 SIMD）的龙芯 LA464/LA664 处理器。

在 LoongArch 架构中，LSX `$vr` 寄存器（128 位）与 LASX `$xr` 寄存器（256 位）的低 128 位重叠。LSX 指令被定义为仅操作低 128 位；对应 `$xr` 寄存器的高 128 位在架构上未定义。然而，由于微架构缺陷，LSX 指令**可能通过** `$xr` 的高 128 位**泄露数据**，从而将敏感数据暴露到特权边界之外或 SMT 线程之间。

## 工作原理

概念验证程序的工作流程如下：

1. **加载**：通过 `xvld` 将全零数据加载到 `$xrN` 寄存器中。
2. **执行**：运行一条仅应触及低 128 位的 LSX 指令（例如 `vor.v $vrN, $vrN, $vrN`）。
3. **存储**：通过 `xvst` 将完整的 256 位寄存器内容读回。
4. **比较**：将高 128 位与原始值进行比较。如果存在差异，则说明发生了泄露。

该 PoC 在绑定到物理核心的线程上，对 16 个架构向量寄存器（`$xr0`–`$xr15`）重复执行上述探测。若 LSX 操作后高 128 位出现非零值，表明微架构已将陈旧数据或跨上下文数据传播到架构寄存器状态中。

### 攻击场景（LA664）

受害线程在一个逻辑 CPU 上处理敏感数据（例如 `sort < /etc/shadow`），同时 PoC 在其 SMT 兄弟线程上探测寄存器。嗅探线程可以在泄露的高位比特中观察到受害数据的片段。

```shell
# 终端 1 — 在 CPU 0 上启动 LoongBleed
./run.sh

# 终端 2 — 在 SMT 兄弟线程（CPU 1）上运行受害负载
while true; do numactl -C 1 sort < /etc/shadow > /dev/null; done
```

### 攻击场景（LA464）

受害线程在一个 CPU 上处理敏感数据（例如 `sort < /etc/shadow`），同时 PoC 在同一个核上探测寄存器。嗅探线程可以在泄露的高位比特中观察到受害数据的片段。注意需要传入 `--gadget vld` 参数，因为 LA464 不会通过 `vor.v` 指令泄漏数据。

```shell
# 终端 1 — 在 CPU 0 上启动 LoongBleed
./run.sh --gadget vld

# 终端 2 — 在同一个 CPU 上运行受害负载
while true; do numactl -C 0 sort < /etc/shadow > /dev/null; done
```

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

当检测到泄露且泄露字节均为可打印 ASCII 字符（0x20–0x7e）时，PoC 会输出：

```
[cpu   0] LEAK chunk= 0  upper=0x7461646e756f4620_6572617774666f53  ascii=Software Foundat
```

- **chunk** — 触发泄露的向量寄存器槽位（`$xr0`–`$xr15`）
- **upper** — 在 `$xrN` 高 128 位中找到的值（以 `高64位_低64位` 格式显示）。只要有任一位非零，即表示发生泄露。
- **ascii** — 泄露字节的可打印字符解释。这里可见的任何 ASCII 文本都是从其他上下文泄露的数据。

未能解码为可打印 ASCII 的泄露会被静默忽略（以减少噪声），但任何非零的高位比特都代表安全相关的可观测现象。

## 免责声明

本项目仅供教育和安全研究目的使用。
