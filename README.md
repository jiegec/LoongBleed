# LoongBleed

[中文](README_zh.md)

LoongBleed is a hardware vulnerability, conceptually similar to
[ZenBleed (CVE-2023-20593)](https://lock.cmpxchg8b.com/zenbleed.html) —
affecting Loongson LA464/LA664 processors that implement both LSX (128-bit SIMD)
and LASX (256-bit SIMD).

On LoongArch, the LSX `$vr` registers (128-bit) alias the lower half of the LASX
`$xr` registers (256-bit). LSX instructions and basic floating-point operations
are only defined to operate on the lower 128 bits (or a subset thereof); the
upper bits of the corresponding `$xr` register are undefined. However, due
to a microarchitectural flaw, these operations **can leak data** through the
upper 128 bits of `$xr`, exposing sensitive data across privilege boundaries or
between SMT siblings.

## How It Works

The proof-of-concept works as follows:

1. **Load** all-zero data into an `$xrN` register via `xvld`.
2. **Execute** an instruction (LSX or basic floating-point) that should only
   touch the lower 128 bits (or a portion thereof).
3. **Store** the full 256-bit register back via `xvst`.
4. **Compare** all 256 bits against the original value. If the upper or lower
   128 bits differ from the expected zero value, a leak has occurred.

The PoC runs this gadget repeatedly across 16 architectural vector registers
(`$xr0`–`$xr15`) on threads pinned to physical cores. Non-zero values that
appear after the instruction indicate that the microarchitecture has propagated
stale or cross-context data into the architectural register state.

## Gadgets

The PoC supports multiple test instructions, selectable via `--gadget`:

| Gadget  | Instruction              | Description                                                     | Leaks on LA664 | Leaks on LA464 |
|---------|--------------------------|-----------------------------------------------------------------|----------------|----------------|
| `vor`   | `vor.v $vrN, $vrN, $vrN` | Bitwise OR of $vrN with itself                                  | Yes            | No             |
| `vld`   | `vld $vrN, …`            | 128-bit load from memory into $vrN                              | Yes            | Yes            |
| `fld.d` | `fld.d $fN, …`           | 64-bit floating-point load into $fN (alias of $vrN low 64 bits) | Yes            | Yes            |
| `fld.s` | `fld.s $fN, …`           | 32-bit floating-point load into $fN (alias of $vrN low 32 bits) | Yes            | Yes            |

On **LA664**, all four gadgets expose the leak, leaking at most 192 bits per
vector. On **LA464**, `vld`, `fld.d`, and `fld.s` leak (at most 224 bits per
vector); the default `vor.v` gadget does not leak on LA464.

## Usage

```text
Usage: ./loongbleed_poc [OPTIONS]

Options:
  -a, --all                Launch one thread pinned to each physical core.
                           By default only thread on CPU 0 is launched.
  -g, --gadget [vor|vld|fld.d|fld.s]
                           Use different instructions for testing.
  -h, --help               Show this help and exit.
```

### Examples

```shell
# Single-thread mode on CPU 0
./run.sh

# Single-thread mode with vld gadget (required for LA464)
./run.sh --gadget vld

# All physical cores, default gadget
./run.sh -a

# All cores with fld.d gadget
./run.sh --all --gadget fld.d
```

## Attack Scenarios

### LA664 (e.g., Loongson 3C6000/D)

A victim thread processes sensitive data on one logical CPU while the PoC
probes registers on its SMT sibling. The snooping thread can observe fragments
of the victim's data in the leaked upper bits.

```shell
# Terminal 1 — start LoongBleed on CPU 0
./run.sh

# Terminal 2 — victim workload on the SMT sibling (CPU 1)
while true; do numactl -C 1 sort < /etc/shadow > /dev/null; done
```

For an automated setup, use the provided script:

```shell
./poc_la664.sh
```

This spawns a `sort` workload on CPU 1 (the SMT sibling of CPU 0) and launches
LoongBleed on CPU 0 with the default gadget.

### LA464

A victim thread processes sensitive data on a CPU while the PoC probes
registers on the same core. Requires `--gadget vld` since the default `vor.v`
gadget does not leak on LA464.

```shell
# Terminal 1 — start LoongBleed on CPU 0
./run.sh --gadget vld

# Terminal 2 — victim workload on the same core
while true; do numactl -C 0 sort < /etc/shadow > /dev/null; done
```

For an automated setup:

```shell
./poc_la464.sh
```

This spawns a `sort` workload on CPU 0 and launches LoongBleed with `--gadget vld`.

## Building

The PoC is a single-file C++ program with no external dependencies.

```shell
g++ -std=c++11 -O2 -march=native -pthread -o loongbleed_poc loongbleed_poc.cpp
```

Or use the provided script:

```shell
./run.sh
# or, on LA464:
./run.sh --gadget vld
```

## Interpreting Output

When a leak is detected and the leaked bytes contain a run of at least 8
contiguous printable ASCII characters (0x20–0x7e), the PoC prints:

```
[cpu   0] LEAK chunk=14 data=0x7461646e756f4620_6572617774666f53_0000000000000000_0000000000000000 ascii=............Software Foundat
```

- **cpu** — the logical CPU the detecting thread is pinned to
- **chunk** — which of the 16 vector register slots (`$xr0`–`$xr15`) triggered
- **data** — the full 256-bit value read back from `$xrN` after the
  instruction, displayed as `data3_data2_data1_data0` where:
  - `data0` = bits [63:0]   (lowest 64 bits of the result)
  - `data1` = bits [127:64] (upper 64 bits of the lower 128-bit half)
  - `data2` = bits [191:128] (lower 64 bits of the upper 128-bit half)
  - `data3` = bits [255:192] (upper 64 bits of the upper 128-bit half)
- **ascii** — printable interpretation of the leaked 28-byte window
  (bytes 4–31 of the result, i.e., the upper 224 bits minus the lowest 32 bits).
  Non-printable bytes are shown as `.`.

Any non-zero value in the upper 128 bits (`data2` or `data3`) indicates a
microarchitectural data leak.

## Disclaimer

This project is provided for educational and security research purposes only.
