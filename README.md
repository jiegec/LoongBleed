# LoongBleed

[中文](README_zh.md)

LoongBleed is a hardware vulnerability, conceptually similar to
[ZenBleed (CVE-2023-20593)](https://lock.cmpxchg8b.com/zenbleed.html) —
affecting Loongson LA464/LA664 processors that implement both LSX (128-bit SIMD)
and LASX (256-bit SIMD).

On LoongArch, the LSX `$vr` registers (128-bit) alias the lower half of the LASX
`$xr` registers (256-bit). LSX instructions are only defined to operate on the
lower 128 bits; the upper 128 bits of the corresponding `$xr` register are
undefined. However, due to a microarchitectural flaw, LSX instructions **can
leak data** through the upper 128 bits of `$xr`, exposing sensitive data across
privilege boundaries or between SMT siblings.

## How It Works

The proof-of-concept works as follows:

1. **Load** all-zero data into an `$xrN` register via `xvld`.
2. **Execute** an LSX instruction (e.g., `vor.v $vrN, $vrN, $vrN`) that should
   only touch the lower 128 bits.
3. **Store** the full 256-bit register back via `xvst`.
4. **Compare** the upper 128 bits against the original value. If they differ,
   a leak has occurred.

The PoC runs this gadget repeatedly across 16 architectural vector registers
(`$xr0`–`$xr15`) on threads pinned to physical cores. Non-zero upper 128-bit
values that appear after an LSX operation indicate that the microarchitecture has
propagated stale or cross-context data into the architectural register state.

### Attack Scenario (LA664)

A victim thread processes sensitive data (e.g., `sort < /etc/shadow`) on one
logical CPU while the PoC probes registers on its SMT sibling. The snooping
thread can observe fragments of the victim's data in the leaked upper bits.

```shell
# Terminal 1 — start LoongBleed on CPU 0
./run.sh

# Terminal 2 — victim workload on the SMT sibling (CPU 1)
while true; do numactl -C 1 sort < /etc/shadow > /dev/null; done
```

### Attack Scenario (LA464)

A victim thread processes sensitive data (e.g., `sort < /etc/shadow`) while the
PoC probes registers on the same core. The snooping thread can observe fragments
of the victim's data in the leaked upper bits. Note that `--vld` is required,
since the default gadget does not leak data on LA464.

```shell
# Terminal 1 — start LoongBleed on CPU 0
./run.sh --vld

# Terminal 2 — victim workload on same core
while true; do numactl -C 0 sort < /etc/shadow > /dev/null; done
```

## Building

The PoC is a single-file C++ program with no external dependencies.

```shell
g++ -std=c++11 -O2 -march=native -pthread -o loongbleed_poc loongbleed_poc.cpp
```

Or use the provided script:

```shell
./run.sh
# or, on LA464:
./run.sh --vld
```

## Interpreting Output

When a leak is detected and the leaked bytes are all valid printable ASCII
(0x20–0x7e), the PoC prints:

```
[cpu   0] LEAK chunk= 0  upper=0x7461646e756f4620_6572617774666f53  ascii=Software Foundat
```

- **chunk** — which of the 16 vector register slots (`$xr0`–`$xr15`) triggered
- **upper** — the 128-bit value found in the upper half of `$xrN` (displayed as
  `hi_64bits_lo_64bits`). If any bit is non-zero, a leak occurred.
- **ascii** — printable interpretation of the leaked bytes. Any ASCII text
  visible here is data that leaked from another context.

Leaks that do not happen to decode as printable ASCII are silently suppressed
(to avoid noise), but any non-zero upper bits represent a security-relevant
observation.

## Disclaimer

This project is provided for educational and security research purposes only.
