#![allow(dead_code)]
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;
use unicorn_engine::unicorn_const::{self as uc_const, Prot};
use unicorn_engine::{Context, RegisterARM64, Unicorn};

const BASE_ADDR: u64 = 0x400000;
const STACK_BASE: u64 = 0x80000000;
const STACK_SIZE_MAIN: u64 = 0x200000;
const STACK_SIZE_THREAD: u64 = 0x100000; // 1MB per thread
const MAGIC_BASE: u64 = 0x20000000; // Import hooks (Relocated to Low Mem)
const MAGIC_EXIT: u64 = 0x20000004; // Thread Exit Trap
const HEAP_START: u64 = 0x10000000;

#[derive(Clone, PartialEq)]
enum ThreadStatus {
    Running,
    Ready,
    // Waiting, // Implemented later if needed
    Dead,
}

struct Thread {
    tid: u32,
    context: Option<Context>, // None if currently loaded in CPU
    stack_base: u64,
    status: ThreadStatus,
}

struct EmulatorState {
    imports_map: HashMap<u64, String>,
    magic_map: HashMap<u64, String>,
    magic_counter: u64,
    heap_ptr: u64,
    // Scheduler
    threads: Vec<Thread>,
    current_thread_idx: usize,
    next_tid: u32,
    last_log: String,
    log_count: u32,
    mapped_pages: u64,
    simulate_live_list: bool,
    simulate_live_list_remaining: usize,
    simulate_seed: u64,
    auto_restart: bool,
    restart_limit: u32,
    restart_count: u32,
    ignore_exceptions: bool,
    exception_skip_limit: u32,
    exception_skip_count: u32,
}

fn lcg_next(seed: &mut u64) -> u64 {
    // 64-bit LCG constants (numerical recipes style)
    *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *seed
}

fn build_fake_live_list_json(seed: &mut u64, count: usize) -> String {
    let categories = ["Popular", "Hero", "New", "Pro", "Nearby", "Ranked"];
    let regions = ["ID", "SG", "TH", "VN", "PH", "MY", "BR", "MX", "TR"];
    let mut items = Vec::with_capacity(count);

    for i in 0..count {
        let r1 = lcg_next(seed);
        let r2 = lcg_next(seed);
        let r3 = lcg_next(seed);
        let viewers = (r1 % 2_500_000) + 100;
        let duration = (r2 % 7_200) + 30;
        let streamer_id = format!("{}{}{}", (r3 % 900_000) + 100_000, i, (r2 % 97));
        let category = categories[(r2 as usize) % categories.len()];
        let region = regions[(r1 as usize) % regions.len()];
        let room_id = format!("{}", (r3 % 9_000_000) + 1_000_000);

        items.push(format!(
            "{{\"streamer_id\":\"{}\",\"room_id\":\"{}\",\"category\":\"{}\",\"region\":\"{}\",\"viewers\":{},\"duration_seconds\":{}}}",
            streamer_id, room_id, category, region, viewers, duration
        ));
    }

    format!("{{\"live_list\":[{}],\"source\":\"emulator\",\"timestamp\":\"{}\"}}", items.join(","), chrono_timestamp())
}

fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    format!("{}", secs)
}

fn reset_main_thread(
    uc: &mut Unicorn<EmulatorState>,
    entry: u64,
    stack_top: u64,
    jvm_base: u64,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    uc.reg_write(RegisterARM64::X0, jvm_base)?; // vm
    uc.reg_write(RegisterARM64::X1, 0)?; // reserved
    uc.reg_write(RegisterARM64::SP, stack_top)?;
    uc.reg_write(RegisterARM64::PC, entry)?;
    uc.reg_write(RegisterARM64::LR, 0x30000000)?; // EXIT MAGIC
    uc.reg_write(RegisterARM64::CPACR_EL1, 0x300000)?; // VFP
    uc.reg_write(RegisterARM64::TPIDR_EL0, HEAP_START + 0x100000)?; // TLS

    uc.get_data_mut().threads.clear();
    uc.get_data_mut().threads.push(Thread {
        tid: 0,
        context: None,
        stack_base: STACK_BASE,
        status: ThreadStatus::Running,
    });
    uc.get_data_mut().current_thread_idx = 0;
    uc.get_data_mut().exception_skip_count = 0;
    Ok(())
}

fn scan_memory_for_strings(uc: &Unicorn<EmulatorState>) {
    println!("\n[Analysis] Scanning Memory for API Strings...");
    // Scan Heap (0x10000000 - 0x12000000)
    let start = 0x10000000;
    let size = 0x2000000; // 32MB
    if let Ok(data) = uc.mem_read_as_vec(start, size) {
        print_strings(&data, "HEAP");
    }
    // Scan Stack (0x80000000 - 0x81000000)
    if let Ok(data) = uc.mem_read_as_vec(0x80000000, 0x1000000) {
        print_strings(&data, "STACK");
    }
}

fn print_strings(data: &[u8], region: &str) {
    let mut i = 0;
    while i < data.len() {
        if data[i] >= 32 && data[i] <= 126 {
            let start = i;
            while i < data.len() && data[i] >= 32 && data[i] <= 126 {
                i += 1;
            }
            if i - start > 10 {
                let s = std::str::from_utf8(&data[start..i]).unwrap();
                if s.contains("http")
                    || s.contains("json")
                    || s.contains("sign")
                    || s.contains("token")
                    || s.contains("Bearer")
                    || s.to_lowercase().contains("live")
                    || s.to_lowercase().contains("stream")
                    || s.to_lowercase().contains("streamer")
                    || s.to_lowercase().contains("room")
                    || s.to_lowercase().contains("anchor")
                    || s.to_lowercase().contains("popular")
                    || s.to_lowercase().contains("hot")
                {
                    println!("[Found in {}] {}", region, s);
                }
            }
        } else {
            i += 1;
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Init Rust Emulator (Multi-Threaded)...");

    let mut simulate_live_list = false;
    let mut simulate_live_list_count: usize = 20;
    let mut auto_restart = false;
    let mut restart_limit: u32 = 5;
    let mut ignore_exceptions = false;
    let mut exception_skip_limit: u32 = 200;
    let mut entry_override: Option<u64> = None;
    let mut entry_offset_override: Option<u64> = None;
    for arg in std::env::args().skip(1) {
        if arg == "--simulate-live-list" {
            simulate_live_list = true;
        } else if let Some(v) = arg.strip_prefix("--simulate-live-list=") {
            if let Ok(n) = v.parse::<usize>() {
                simulate_live_list = true;
                simulate_live_list_count = n.max(1).min(200);
            }
        } else if arg == "--auto-restart" {
            auto_restart = true;
        } else if let Some(v) = arg.strip_prefix("--restart-limit=") {
            if let Ok(n) = v.parse::<u32>() {
                restart_limit = n.max(1).min(100);
            }
        } else if arg == "--ignore-exceptions" {
            ignore_exceptions = true;
        } else if let Some(v) = arg.strip_prefix("--exception-skip-limit=") {
            if let Ok(n) = v.parse::<u32>() {
                exception_skip_limit = n.max(1).min(10_000);
            }
        } else if let Some(v) = arg.strip_prefix("--entry=") {
            if let Ok(parsed) = u64::from_str_radix(v.trim_start_matches("0x"), 16) {
                entry_override = Some(parsed);
            }
        } else if let Some(v) = arg.strip_prefix("--entry-offset=") {
            if let Ok(parsed) = u64::from_str_radix(v.trim_start_matches("0x"), 16) {
                entry_offset_override = Some(parsed);
            }
        }
    }
    if simulate_live_list {
        auto_restart = true;
    }

    // Load Imports
    let imports_path = "../imports_map.txt";
    let mut imports_map = HashMap::new();
    if let Ok(file) = fs::File::open(imports_path) {
        for line in io::BufReader::new(file).lines() {
            if let Ok(l) = line {
                let parts: Vec<&str> = l.split('=').collect();
                if parts.len() == 2 {
                    let addr_str = parts[0].trim_start_matches("0x");
                    if let Ok(off) = u64::from_str_radix(addr_str, 16) {
                        imports_map.insert(off, parts[1].to_string());
                    } else {
                        println!("Failed to parse import offset: {}", parts[0]);
                    }
                }
            }
        }
    }

    // Load Binary (Relocated Dump)
    let lib_path = "../memory_dump.bin";
    let code = match fs::read(lib_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            if simulate_live_list {
                eprintln!("[WARN] memory_dump.bin not found ({}). Running in simulate-only mode.", e);
                let mut seed = 0xC0FFEE_u64;
                let payload = build_fake_live_list_json(&mut seed, simulate_live_list_count);
                println!("[SIMULATED LIVE LIST]\n{}", payload);
                let _ = std::fs::write("simulated_live_list.json", payload);
                return Ok(());
            }
            return Err(Box::new(e));
        }
    };

    // Init State
    let mut state = EmulatorState {
        imports_map: imports_map.clone(),
        magic_map: HashMap::new(),
        magic_counter: MAGIC_BASE + 0x100, // Reserve start for predefined hooks
        heap_ptr: HEAP_START,
        threads: Vec::new(),
        current_thread_idx: 0,
        next_tid: 1, // Main is 0
        last_log: String::new(),
        log_count: 0,
        mapped_pages: 0,
        simulate_live_list,
        simulate_live_list_remaining: simulate_live_list_count,
        simulate_seed: 0xC0FFEE_u64,
        auto_restart,
        restart_limit,
        restart_count: 0,
        ignore_exceptions,
        exception_skip_limit,
        exception_skip_count: 0,
    };

    // Add Main Thread
    state.threads.push(Thread {
        tid: 0,
        context: None, // Will be saved on first switch
        stack_base: STACK_BASE,
        status: ThreadStatus::Running,
    });

    // Init Unicorn with Data
    let mut unicorn = Unicorn::new_with_data(uc_const::Arch::ARM64, uc_const::Mode::ARM, state)?;

    // Map Memory
    unicorn.mem_map(0, 0x10000000, Prot::ALL)?;
    unicorn.mem_write(BASE_ADDR, &code)?;
    unicorn.mem_map(STACK_BASE, 0x10000000, Prot::READ | Prot::WRITE)?;
    unicorn.mem_map(MAGIC_BASE, 0x4000000, Prot::ALL)?;

    // FILL WITH RET (0xD65F03C0)
    // 0x400000 bytes = 1,048,576 instructions? No, 4MB. 4 bytes/instr = 1M instrs.
    // Create a 4MB buffer? might be slow.
    // Or write in chunks.
    // Let's create a buffer of 0x10000 filled with RETs and loop.
    let ret_opcode: u32 = 0xD65F03C0;
    let ret_bytes = ret_opcode.to_le_bytes();
    let mut chunk = Vec::with_capacity(0x10000);
    for _ in 0..(0x10000 / 4) {
        chunk.extend_from_slice(&ret_bytes);
    }

    for i in 0..(0x4000000 / 0x10000) {
        let offset = i * 0x10000;
        unicorn.mem_write(MAGIC_BASE + offset, &chunk)?;
    }

    // Verify memory at 0xF2000000
    let verify_addr = MAGIC_BASE + 0x200000;
    println!("Verifying RET at {:x}...", verify_addr);
    match unicorn.mem_read_as_vec(verify_addr, 4) {
        Ok(v) => println!(
            "Memory at {:x}: {:02x} {:02x} {:02x} {:02x}",
            verify_addr, v[0], v[1], v[2], v[3]
        ),
        Err(e) => println!("Failed to read verification: {:?}", e),
    }
    io::stdout().flush().unwrap();

    // Patch GOT
    println!("Patching GOT...");
    for (off, name) in &imports_map {
        let target = BASE_ADDR + off;
        let magic_addr = unicorn.get_data().magic_counter;

        unicorn
            .get_data_mut()
            .magic_map
            .insert(magic_addr, name.clone());
        unicorn.get_data_mut().magic_counter += 4;

        let patch = magic_addr.to_le_bytes();
        unicorn.mem_write(target, &patch)?;
    }

    // Setup Hooks
    // Code Hook for Magic & JNI
    let magic_cb = move |uc: &mut Unicorn<EmulatorState>, addr: u64, _size: u32| {
        if addr == MAGIC_EXIT {
            // Thread Exit
            let idx = uc.get_data().current_thread_idx;
            let tid = uc.get_data().threads[idx].tid;
            println!("[Sched] T{} Exiting", tid);

            uc.get_data_mut().threads[idx].status = ThreadStatus::Dead;
            uc.emu_stop().unwrap();
            return;
        }

        let data = uc.get_data();
        if let Some(name) = data.magic_map.get(&addr).cloned() {
            handle_import(uc, &name);
            // handle_import for pthread_create sets PC inside.
            // But for simple hooks (malloc), do we return?
            // Yes, checking handle_import: malloc doesn't set PC.
            // We need a uniform return strategy or let handle_import decide.
            // Malloc logic in handle_import just sets X0. It needs return.
            if !name.contains("pthread_create") {
                let lr = uc.reg_read(RegisterARM64::LR).unwrap_or(0);
                uc.reg_write(RegisterARM64::PC, lr).unwrap();
            }
        } else if addr >= 0x21000000 && addr < 0x22000000 {
            handle_jni(uc, (addr - 0x21000000) / 4);
            let lr = uc.reg_read(RegisterARM64::LR).unwrap_or(0);
            uc.reg_write(RegisterARM64::PC, lr).unwrap();
        } else if addr >= 0x22000000 && addr < 0x23000000 {
            // JavaVM Hook
            // Verify if this is GetEnv (mapped to 0x22000000)
            if addr == 0x22000000 {
                // GetEnv(vm, void** env, int version)
                println!("[JavaVM] GetEnv Called");
                let env_ptr_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
                // Write JNIEnv Table Pointer (0xF1000000) to *env
                // Actually JNIEnv* should point to a pointer that points to JNINativeInterface.
                // In handle_jni, we mocked 0xF1000000 as the TABLE base.
                // So JNIEnv* (X0 in JNI func) should be 0xF1000000? No.
                // JNIEnv is a pointer to a VTable Pointer.
                // Let's define JNIEnv Base at 0x70010000.
                // VTable at 0xF1000000.
                // So [0x70010000] = 0xF1000000.
                // And *env = 0x70010000.

                let jni_env_ptr: u64 = 0x70010000;
                let jni_vtable: u64 = 0x70020000;
                let jni_code_base: u64 = 0x21000000;

                // Note: JNI Memory and Code Base are now mapped and filled with RETs in main()

                // Setup Env -> VTable
                uc.mem_write(jni_env_ptr, &jni_vtable.to_le_bytes())
                    .unwrap();

                // Populate VTable with Pointers to Magic Code
                // Each entry i points to jni_code_base + i*4
                // JNI has ~300 functions. 300 * 8 = 2400 bytes.
                let mut buf = Vec::new();
                for i in 0..300 {
                    let code_addr = jni_code_base + (i as u64 * 4);
                    buf.extend_from_slice(&code_addr.to_le_bytes());
                }
                uc.mem_write(jni_vtable, &buf).unwrap();

                // Write to output param
                uc.mem_write(env_ptr_ptr, &jni_env_ptr.to_le_bytes())
                    .unwrap();

                // Return JNI_OK (0)
                uc.reg_write(RegisterARM64::X0, 0).unwrap();
            } else {
                println!("[JavaVM] Unknown Call {:x}", addr);
            }
            // Return
            let lr = uc.reg_read(RegisterARM64::LR).unwrap_or(0);
            uc.reg_write(RegisterARM64::PC, lr).unwrap();
        }
    };
    unicorn.add_code_hook(MAGIC_BASE, MAGIC_BASE + 0x4000000, magic_cb)?;

    // ANTI-LOOP STRATEGY: BRUTE FORCE UNWIND
    // We scan the stack for the first value that looks like a valid return address (Code Segment).
    let ret_addr = 0x847980;
    let smart_unwind_cb = move |uc: &mut Unicorn<EmulatorState>, addr: u64, _size: u32| {
        if addr == ret_addr {
            let sp = uc.reg_read(RegisterARM64::SP).unwrap();

            // PROVEN FIX: RESTORE FROM SP OFFSETS
            // Scan verified:
            // Saved LR is at SP + 0x158 (Value: 0x8476e4)
            // Saved FP is at SP + 0x150 (Value: 0x801fff90)

            // Read Saved LR
            let lr_data = uc.mem_read_as_vec(sp + 0x158, 8).unwrap();
            let mut buf_lr = [0u8; 8];
            buf_lr.copy_from_slice(&lr_data);
            let saved_lr = u64::from_le_bytes(buf_lr);

            // Read Saved FP
            let fp_data = uc.mem_read_as_vec(sp + 0x150, 8).unwrap();
            let mut buf_fp = [0u8; 8];
            buf_fp.copy_from_slice(&fp_data);
            let saved_fp = u64::from_le_bytes(buf_fp);

            println!(
                "[Hack] Proven Restore: Found LR={:x}, FP={:x}",
                saved_lr, saved_fp
            );

            if saved_lr != 0 {
                uc.reg_write(RegisterARM64::PC, saved_lr).unwrap();
                uc.reg_write(RegisterARM64::X29, saved_fp).unwrap();
                // Restore SP: Prologue sub 0x1a0, so Epilogue add 0x1a0
                uc.reg_write(RegisterARM64::SP, sp + 0x1a0).unwrap();
            } else {
                panic!("FATAL: Saved LR is still 0??");
            }
        }
    };
    unicorn.add_code_hook(ret_addr, ret_addr + 4, smart_unwind_cb)?;

    // LOOP BREAKER for 0xbdc11c
    // Breaking infinite linked list traversal?
    let loop_check_addr = BASE_ADDR + 0x7dc11c;
    let mut loop_count = 0;
    let loop_breaker_cb = move |uc: &mut Unicorn<EmulatorState>, _addr: u64, _size: u32| {
        loop_count += 1;
        if loop_count > 1000 {
            println!("[Hack] Breaking Infinite Loop at {:x}", _addr);
            let x19 = uc.reg_read(RegisterARM64::X19).unwrap();
            let x21 = uc.reg_read(RegisterARM64::X21).unwrap();
            let x22 = uc.reg_read(RegisterARM64::X22).unwrap();
            println!(
                "[Hack] Loop Regs: X19={:x}, X21={:x}, X22={:x}",
                x19, x21, x22
            );
            // Try reading X21 as string (it was loaded from [x29 + 0x10])
            let s = read_string(uc, x21);
            if s.len() > 2 {
                println!("[Hack] Loop String X21: {}", s);
            }

            let x27 = uc.reg_read(RegisterARM64::X27).unwrap();
            uc.reg_write(RegisterARM64::X29, x27).unwrap();
            loop_count = 0; // Reset
        }
    };
    unicorn.add_code_hook(loop_check_addr, loop_check_addr + 4, loop_breaker_cb)?;

    // FORCE SUCCESS at Loop Exit
    // 0xbdc1ec: tbz w8, #0, ...
    // We want to fall through (Success). So set w8=1.
    let loop_exit_addr = BASE_ADDR + 0x7dc1ec;
    let force_success_cb = move |uc: &mut Unicorn<EmulatorState>, _addr: u64, _size: u32| {
        println!("[Hack] Forcing Loop Success at {:x}", _addr);
        // tbz checks bit 0. If 0, jump.
        // We want NO jump. So set bit 0 to 1.
        uc.reg_write(RegisterARM64::X8, 1).unwrap();
    };
    unicorn.add_code_hook(loop_exit_addr, loop_exit_addr + 4, force_success_cb)?;

    // BEF_EFFECT_JNI_OnLoad Hook
    let bef_addr = 0x20000100;
    let bef_cb = move |uc: &mut Unicorn<EmulatorState>, _addr: u64, _size: u32| {
        println!("[Import] Executing BEF_EFFECT_JNI_OnLoad Mock");
        // Return JNI_VERSION_1_6
        uc.reg_write(RegisterARM64::X0, 0x10006).unwrap();
        // Return logic: PC = LR
        let lr = uc.reg_read(RegisterARM64::LR).unwrap();
        if lr == 0 {
            panic!("BEF_EFFECT called with LR=0!");
        }
        uc.reg_write(RegisterARM64::PC, lr).unwrap();
    };
    unicorn.add_code_hook(bef_addr, bef_addr + 4, bef_cb)?;

    // EXIT HOOK (0x30000000) - Called when JNI_OnLoad returns
    let exit_addr = 0x30000000;
    let manual_exit_addr = 0x30001000;

    // Manual Exit Hook
    let manual_exit_cb = move |uc: &mut Unicorn<EmulatorState>, _addr: u64, _size: u32| {
        let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
        println!("\n[Success] UpdateLoginToken Returned! Result: {:x}", x0);
        scan_memory_for_strings(uc);
        std::process::exit(0);
    };
    unicorn.add_code_hook(manual_exit_addr, manual_exit_addr + 4, manual_exit_cb)?;

    // JNI_OnLoad Return Handler
    let exit_cb = move |uc: &mut Unicorn<EmulatorState>, _addr: u64, _size: u32| {
        let x0 = uc.reg_read(RegisterARM64::X0).unwrap();
        println!("\n[Success] JNI_OnLoad Returned! Result: {:x}", x0);
        println!("[Info] Now invoking NativeRTCVideoFunctions_nativeUpdateLoginToken...");

        // Setup Arguments for UpdateLoginToken(env, obj, string)
        // Env = 0xF1000000 (Already set in X0? No, verify)
        // Obj = 0xDEADBEEF (Dummy)
        // String = Pointer to "test_token" (in Safe Magic Region)

        let env_ptr = 0xF1000000;
        let token_str_addr = 0x20001000; // Inside MAGIC_BASE (Mapped)
        let token_bytes = b"test_token\0";
        uc.mem_write(token_str_addr, token_bytes).unwrap();

        uc.reg_write(RegisterARM64::X0, env_ptr).unwrap(); // JNIEnv*
        uc.reg_write(RegisterARM64::X1, 0xDEADBEEF).unwrap(); // jobject
        uc.reg_write(RegisterARM64::X2, token_str_addr).unwrap(); // jstring (mock as ptr)

        // Target Function: Java_com_ss_bytertc_engine_NativeRTCVideoFunctions_nativeUpdateLoginToken
        // Offset 0x6426cc
        let func_addr = BASE_ADDR + 0x6426cc;

        uc.reg_write(RegisterARM64::PC, func_addr).unwrap();
        uc.reg_write(RegisterARM64::LR, manual_exit_addr).unwrap();
    };
    unicorn.add_code_hook(exit_addr, exit_addr + 4, exit_cb)?;

    // Auto-Map Hook
    let unmapped_cb = move |uc: &mut Unicorn<EmulatorState>,
                            _type: unicorn_engine::MemType,
                            addr: u64,
                            _size: usize,
                            _val: i64|
          -> bool {
        let base = addr & !0xFFF;

        // Safety: Do NOT auto-map Null Page
        if base == 0 {
            println!("[Crash] Null Pointer Access! Stopping.");
            return false;
        }

        // println!("[OS] Segmentation Fault at PC={:x} accessing {:x}", pc, addr);
        // println!("[OS] Auto-mapping Unmapped Memory: {:x}", base);

        {
            let data = uc.get_data_mut();
            data.mapped_pages += 1;
            if data.mapped_pages > 262144 {
                // 1GB limit
                println!(
                    "[Protection] OOM Prevention: Too many auto-mapped pages ({})",
                    data.mapped_pages
                );
                return false;
            }
        }

        match uc.mem_map(base, 0x1000, Prot::ALL) {
            Ok(_) => true,
            Err(_) => false,
        }
    };
    unicorn.add_mem_hook(
        unicorn_engine::HookType::MEM_UNMAPPED,
        0,
        0xFFFFFFFFFFFFFFFF,
        unmapped_cb,
    )?;

    // Setup Main Register/Stack
    let stack_top = STACK_BASE + STACK_SIZE_MAIN;
    // JNI_OnLoad @ 0x62ed1c (From Symbol Table)
    let default_entry = BASE_ADDR + 0x62ed1c;
    let entry = if let Some(abs) = entry_override {
        abs
    } else if let Some(off) = entry_offset_override {
        BASE_ADDR + off
    } else {
        default_entry
    };

    // MOCK JAVAVM
    let jvm_base: u64 = 0x70000000;
    let jvm_vtable: u64 = 0x70001000;
    let invoke_interface_magic: u64 = 0x22000000; // Hook for JavaVM functions

    unicorn.mem_map(jvm_base, 0x100000, Prot::READ | Prot::WRITE)?;
    // vm->functions = vtable
    unicorn.mem_write(jvm_base, &jvm_vtable.to_le_bytes())?;
    // vtable->GetEnv = magic
    unicorn.mem_write(jvm_vtable + 0x30, &invoke_interface_magic.to_le_bytes())?;

    // Pass arguments to JNI_OnLoad
    reset_main_thread(&mut unicorn, entry, stack_top, jvm_base)?;

    println!("Starting Scheduler Loop...");

    // SCHEDULER LOOP
    let quantum = 200_000; // Instructions per slice
    let mut total_insts: u64 = 0;

    loop {
        // Run current thread
        let current_idx = unicorn.get_data().current_thread_idx;
        // println!("[Sched] Switch to T{}", unicorn.get_data().threads[current_idx].tid);

        if unicorn.get_data().threads[current_idx].status == ThreadStatus::Dead {
            // Skip dead threads or Remove them? For now just skip logic below and switch.
        } else {
            // Restore Context if we have one (not for first run of main)
            if let Some(ctx) = unicorn.get_data_mut().threads[current_idx].context.take() {
                unicorn.context_restore(&ctx)?;
            }

            // Run Quantum
            // Note: emu_start will return Ok(()) when count reached, or Err on crash
            let pc = unicorn.reg_read(RegisterARM64::PC)?;
            let res = unicorn.emu_start(pc, 0, 0, quantum);

            if let Err(e) = res {
                let pc = unicorn.reg_read(RegisterARM64::PC).unwrap_or(0);
                let sp = unicorn.reg_read(RegisterARM64::SP).unwrap_or(0);
                let x0 = unicorn.reg_read(RegisterARM64::X0).unwrap_or(0);
                println!(
                    "[Sched] Thread Crash: {:?} at PC={:x} SP={:x} X0={:x}",
                    e, pc, sp, x0
                );
                scan_memory_for_strings(&unicorn);
                if unicorn.get_data().ignore_exceptions
                    && unicorn.get_data().exception_skip_count < unicorn.get_data().exception_skip_limit
                {
                    unicorn.get_data_mut().exception_skip_count += 1;
                    let next_pc = pc.wrapping_add(4);
                    unicorn.reg_write(RegisterARM64::PC, next_pc)?;
                    println!(
                        "[Sched] Ignored exception ({} of {}), advancing PC to {:x}",
                        unicorn.get_data().exception_skip_count,
                        unicorn.get_data().exception_skip_limit,
                        next_pc
                    );
                } else {
                    // Mark dead
                    unicorn.get_data_mut().threads[current_idx].status = ThreadStatus::Dead;
                }
                if unicorn.get_data().auto_restart
                    && unicorn.get_data().restart_count < unicorn.get_data().restart_limit
                {
                    unicorn.get_data_mut().restart_count += 1;
                    println!(
                        "[Sched] Auto-restart {} of {}",
                        unicorn.get_data().restart_count,
                        unicorn.get_data().restart_limit
                    );
                    reset_main_thread(&mut unicorn, entry, stack_top, jvm_base)?;
                }
            } else {
                // Success - Check for Exit
                let final_pc = unicorn.reg_read(RegisterARM64::PC)?;
                if final_pc == 0 {
                    let tid = unicorn.get_data().threads[current_idx].tid;
                    println!("[Sched] Thread T{} Finished/Exited (PC=0)", tid);
                    scan_memory_for_strings(&unicorn);
                    unicorn.get_data_mut().threads[current_idx].status = ThreadStatus::Dead;
                    if unicorn.get_data().auto_restart
                        && unicorn.get_data().restart_count < unicorn.get_data().restart_limit
                    {
                        unicorn.get_data_mut().restart_count += 1;
                        println!(
                            "[Sched] Auto-restart {} of {}",
                            unicorn.get_data().restart_count,
                            unicorn.get_data().restart_limit
                        );
                        reset_main_thread(&mut unicorn, entry, stack_top, jvm_base)?;
                    }
                } else {
                    // Save Context
                    let mut ctx = unicorn.context_alloc()?;
                    unicorn.context_save(&mut ctx)?;
                    unicorn.get_data_mut().threads[current_idx].context = Some(ctx);
                }
            }
        }

        // Round Robin Switch
        let mut next_idx = (current_idx + 1) % unicorn.get_data().threads.len();

        // Find next non-dead thread
        let start_idx = next_idx;
        while unicorn.get_data().threads[next_idx].status == ThreadStatus::Dead {
            next_idx = (next_idx + 1) % unicorn.get_data().threads.len();
            if next_idx == start_idx {
                // All dead
                if unicorn.get_data().auto_restart
                    && unicorn.get_data().restart_count < unicorn.get_data().restart_limit
                {
                    unicorn.get_data_mut().restart_count += 1;
                    println!(
                        "[Sched] Auto-restart {} of {}",
                        unicorn.get_data().restart_count,
                        unicorn.get_data().restart_limit
                    );
                    reset_main_thread(&mut unicorn, entry, stack_top, jvm_base)?;
                    continue;
                }
                println!("[Sched] All threads dead. Exiting.");
                return Ok(());
            }
        }

        unicorn.get_data_mut().current_thread_idx = next_idx;
        total_insts += quantum as u64;
        if total_insts % 10_000_000 == 0 {
            let pc = unicorn.reg_read(RegisterARM64::PC).unwrap_or(0);
            println!("[Status] {} Insts | PC={:x}", total_insts, pc);
        }

        if total_insts > 5_000_000_000 {
            println!("[Protection] Instruction Limit Reached (5B). Stopping.");
            break;
        }

        // Loop Exit if All Dead
        if unicorn
            .get_data()
            .threads
            .iter()
            .all(|t| t.status == ThreadStatus::Dead)
        {
            if unicorn.get_data().auto_restart
                && unicorn.get_data().restart_count < unicorn.get_data().restart_limit
            {
                unicorn.get_data_mut().restart_count += 1;
                println!(
                    "[Sched] Auto-restart {} of {}",
                    unicorn.get_data().restart_count,
                    unicorn.get_data().restart_limit
                );
                reset_main_thread(&mut unicorn, entry, stack_top, jvm_base)?;
                continue;
            }
            println!("[Sched] All threads dead. Exiting.");
            break;
        }
    }

    Ok(())
}

fn handle_import(uc: &mut Unicorn<EmulatorState>, name: &str) {
    if name.contains("malloc") {
        let size = uc.reg_read(RegisterARM64::X0).unwrap_or(0);
        
        // Handle malloc(-1) or other invalid sizes (treat as error)
        if size > 0x10000000 {  // >256MB is suspicious
            println!("[Warning] Suspicious malloc size: {} (0x{:x}). Returning NULL.", size, size);
            uc.reg_write(RegisterARM64::X0, 0).unwrap();
            return;
        }

        let heap = uc.get_data().heap_ptr;
        let aligned_size = (size + 7) & !7;

        if size > 0x100000 {
            // Log > 1MB
            println!("[Warning] Large malloc: {} bytes", size);
        }

        if heap + aligned_size > HEAP_START + 0x100000000 {
            // 4GB limit - return NULL instead of crashing
            println!("[Protection] OOM Prevention: Heap would exceed 4GB. Returning NULL.");
            uc.reg_write(RegisterARM64::X0, 0).unwrap();
            return;
        }

        println!("[Import] malloc({}): {:x}", size, heap);
        uc.reg_write(RegisterARM64::X0, heap).unwrap();
        uc.get_data_mut().heap_ptr += aligned_size;
    } else if name.contains("pthread_create") {
        if uc.get_data().threads.len() >= 32 {
            println!("[Protection] Thread Limit Exceeded (32). Failing pthread_create.");
            uc.reg_write(RegisterARM64::X0, 11).unwrap(); // EAGAIN
            return;
        }
        // X0=ptr_tid, X1=attr, X2=routine, X3=arg
        let routine = uc.reg_read(RegisterARM64::X2).unwrap();
        let arg = uc.reg_read(RegisterARM64::X3).unwrap();

        // Create Thread
        let new_tid = uc.get_data().next_tid;
        uc.get_data_mut().next_tid += 1;

        // Stack (Already mapped in main)
        let stack_base = 0x81000000 + (new_tid as u64 * STACK_SIZE_THREAD);

        println!("[OS] pthread_create T{} -> {:x}", new_tid, routine);

        // We need to create a context for the NEW thread.
        // Hack: Save CURRENT context (Main), modify it to look like New Thread, Save it as New, Restore Main.

        // Save current Main ctx
        let mut main_ctx = uc.context_alloc().unwrap();
        uc.context_save(&mut main_ctx).unwrap();

        // Modify CPU for New Thread
        // SP = stack_base + SIZE
        uc.reg_write(RegisterARM64::SP, stack_base + STACK_SIZE_THREAD)
            .unwrap();
        // PC = routine
        uc.reg_write(RegisterARM64::PC, routine).unwrap();
        // X0 = arg
        uc.reg_write(RegisterARM64::X0, arg).unwrap();
        // LR = MAGIC_EXIT (Thread Exit Trap)
        uc.reg_write(RegisterARM64::LR, MAGIC_EXIT).unwrap();

        // Save New Context
        let mut new_ctx = uc.context_alloc().unwrap();
        uc.context_save(&mut new_ctx).unwrap();

        // Add to Thread List
        uc.get_data_mut().threads.push(Thread {
            tid: new_tid,
            context: Some(new_ctx),
            stack_base: stack_base,
            status: ThreadStatus::Ready,
        });

        // Restore Main
        uc.context_restore(&main_ctx).unwrap();

        // Return 0 (Success) to Main
        uc.reg_write(RegisterARM64::X0, 0).unwrap();
    } else if name.contains("pthread_mutex_lock") {
        // Mock generic success
        uc.reg_write(RegisterARM64::X0, 0).unwrap();
    } else if name.contains("pthread_mutex_unlock") {
        uc.reg_write(RegisterARM64::X0, 0).unwrap();
    } else if name.contains("dlopen") {
        let filename_ptr = uc.reg_read(RegisterARM64::X0).unwrap();
        let filename = read_string(uc, filename_ptr);
        println!("[Import] dlopen: {}", filename);
        uc.reg_write(RegisterARM64::X0, 0x100).unwrap(); // Mock Handle
    } else if name.contains("dlsym") {
        let _handle = uc.reg_read(RegisterARM64::X0).unwrap();
        let sym_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let sym = read_string(uc, sym_ptr);
        println!("[Import] dlsym: {}", sym);

        if sym == "BEF_EFFECT_JNI_OnLoad" {
            println!("[Import] Hooking BEF_EFFECT_JNI_OnLoad");
            // Return a specific address that we will hook to return JNI_VERSION
            uc.reg_write(RegisterARM64::X0, 0x20000100).unwrap();
        } else {
            // Return generic MAGIC address (RET)
            uc.reg_write(RegisterARM64::X0, 0x20000000).unwrap();
        }
    } else if name.contains("android_log_write") {
        // (prio, tag, text) -> X0, X1, X2
        let tag_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let text_ptr = uc.reg_read(RegisterARM64::X2).unwrap();
        let tag = read_string(uc, tag_ptr);
        let text = read_string(uc, text_ptr);
        println!("[Log] {}: {}", tag, text);
        uc.reg_write(RegisterARM64::X0, 0).unwrap();
    } else if name.contains("android_log_print") {
        // (prio, tag, fmt, ...) -> X0, X1, X2
        let tag_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let fmt_ptr = uc.reg_read(RegisterARM64::X2).unwrap();
        let tag = read_string(uc, tag_ptr);
        let fmt = read_string(uc, fmt_ptr);

        // Try to read common log arguments (X3, X4, X5)
        let x3 = uc.reg_read(RegisterARM64::X3).unwrap_or(0);
        let x4 = uc.reg_read(RegisterARM64::X4).unwrap_or(0);
        let x5 = uc.reg_read(RegisterARM64::X5).unwrap_or(0);

        let mut msg = format!("[LogPrint] {}: {}", tag, fmt);
        if fmt.contains("%s") || fmt.contains("%p") {
            let s3 = if x3 > 0x1000 {
                read_string(uc, x3)
            } else {
                format!("{:x}", x3)
            };
            let s4 = if x4 > 0x1000 {
                read_string(uc, x4)
            } else {
                format!("{:x}", x4)
            };
            msg = format!("{} (Arg1: {}, Arg2: {})", msg, s3, s4);
        } else {
            msg = format!("{} (Args: {:x}, {:x}, {:x})", msg, x3, x4, x5);
        }
        smart_log(uc, msg);
        uc.reg_write(RegisterARM64::X0, 0).unwrap();
    } else if name.contains("connect") {
        // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        let addr_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        // sockaddr_in for IPv4 (typically 16 bytes)
        // struct sockaddr_in {
        //    short sin_family; // 2 bytes
        //    unsigned short sin_port; // 2 bytes (Big Endian)
        //    struct in_addr sin_addr; // 4 bytes
        //    char sin_zero[8];
        // }
        // Note: ARM64 is LE, but network fields are BE.
        if let Ok(data) = uc.mem_read_as_vec(addr_ptr, 16) {
            let family = u16::from_le_bytes([data[0], data[1]]);
            if family == 2 {
                // AF_INET
                let port = u16::from_be_bytes([data[2], data[3]]);
                let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                smart_log(uc, format!("[Network] Connecting to {}:{}", ip, port));
            } else {
                println!("[Network] Connecting to unknown family: {}", family);
            }
        }
        uc.reg_write(RegisterARM64::X0, 0).unwrap();
    } else if name.contains("__system_property_get") {
        // int __system_property_get(const char *name, char *value);
        let name_ptr = uc.reg_read(RegisterARM64::X0).unwrap();
        let value_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let prop_name = read_string(uc, name_ptr);

        let val = match prop_name.as_str() {
            "ro.product.model" => "Pixel 7 Pro",
            "ro.product.brand" => "google",
            "ro.product.manufacturer" => "Google",
            "ro.build.version.release" => "13",
            "ro.build.version.sdk" => "33",
            _ => "",
        };

        if !val.is_empty() {
            println!("[OS] __system_property_get: {} -> {}", prop_name, val);
            let mut val_bytes = val.as_bytes().to_vec();
            val_bytes.push(0);
            uc.mem_write(value_ptr, &val_bytes).unwrap();
            uc.reg_write(RegisterARM64::X0, val.len() as u64).unwrap();
        } else {
            println!(
                "[OS] __system_property_get: {} (Unknown, returning empty)",
                prop_name
            );
            uc.mem_write(value_ptr, &[0]).unwrap();
            uc.reg_write(RegisterARM64::X0, 0).unwrap();
        }
    } else if name.contains("sendto") || name.contains("write") {
        // (fd, buf, len) -> X0, X1, X2
        let buf_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let len = uc.reg_read(RegisterARM64::X2).unwrap();
        if len > 0 {
            let max_log = std::cmp::min(len as usize, 256);
            if let Ok(data) = uc.mem_read_as_vec(buf_ptr, max_log) {
                // Try UTF-8
                if let Ok(s) = std::str::from_utf8(&data) {
                    smart_log(uc, format!("[Network] Send ({} bytes): {}", len, s));
                } else {
                    smart_log(
                        uc,
                        format!(
                            "[Network] Send ({} bytes, Binary/Partial): {:02x?}",
                            len, data
                        ),
                    );
                }

                // Keyword check
                let data_str = String::from_utf8_lossy(&data).to_lowercase();
                if data_str.contains("leaderboard")
                    || data_str.contains("rank")
                    || data_str.contains("top")
                {
                    println!("[CRITICAL] Leaderboard pattern detected in network buffer!");
                }
                if data_str.contains("live")
                    || data_str.contains("stream")
                    || data_str.contains("streamer")
                    || data_str.contains("room")
                    || data_str.contains("anchor")
                    || data_str.contains("popular")
                    || data_str.contains("hot")
                {
                    println!("[CRITICAL] Livestream pattern detected in network buffer!");
                }
            }
        }
        uc.reg_write(RegisterARM64::X0, len).unwrap(); // Success
    } else if name.contains("SSL_write") || name.contains("SSL_send") {
        // int SSL_write(SSL *ssl, const void *buf, int num);
        // X0=ssl, X1=buf, X2=num
        let buf_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let len = uc.reg_read(RegisterARM64::X2).unwrap() as usize;
        
        if len > 0 && len < 0x100000 {
            let read_len = std::cmp::min(len, 4096);
            if let Ok(data) = uc.mem_read_as_vec(buf_ptr, read_len) {
                println!("\n[NETWORK-SSL] SSL_write {} bytes:", len);
                
                // Try UTF-8
                if let Ok(s) = std::str::from_utf8(&data) {
                    println!("  Content: {}", s);
                } else {
                    println!("  Binary: {:02x?}...", &data[..std::cmp::min(128, data.len())]);
                }
                
                // Check for API patterns - ENHANCED for Qiniu Zeus & Moonton GMS
                let data_str = String::from_utf8_lossy(&data).to_lowercase();
                if data_str.contains("zeus") || data_str.contains("shortvideo")
                    || data_str.contains("qiniu") || data_str.contains("appid")
                {
                    println!("  [!!!] QINIU ZEUS API REQUEST [!!!]");
                    
                    // Log to file
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("livestream_api_requests.log")
                    {
                        let _ = writeln!(file, "[SSL_write] Qiniu Zeus Request:");
                        let _ = writeln!(file, "{}", data_str);
                        let _ = writeln!(file, "---");
                    }
                }
                
                // Check for Moonton GMS (Game Management Service) endpoints
                if data_str.contains("gms") || data_str.contains("moontontech")
                    || data_str.contains("match") || data_str.contains("streamer")
                {
                    println!("  [!!!] MOONTON GAME TELEMETRY API REQUEST [!!!]");
                    
                    // Log to file
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("game_telemetry_requests.log")
                    {
                        let _ = writeln!(file, "[SSL_write] Moonton GMS Request:");
                        let _ = writeln!(file, "{}", data_str);
                        let _ = writeln!(file, "---");
                    }
                }
                
                // Check for standard API patterns
                if data_str.contains("leaderboard") || data_str.contains("rank")
                    || data_str.contains("top") || data_str.contains("api")
                    || data_str.contains("http") || data_str.contains("post")
                    || data_str.contains("get ")
                    || data_str.contains("live") || data_str.contains("stream")
                    || data_str.contains("streamer") || data_str.contains("room")
                    || data_str.contains("anchor") || data_str.contains("popular")
                    || data_str.contains("hot") {
                    println!("  [!!!] POTENTIAL API REQUEST DETECTED [!!!]");
                }
            }
        }
        uc.reg_write(RegisterARM64::X0, len as u64).unwrap();
    } else if name.contains("SSL_read") || name.contains("SSL_recv") {
        // int SSL_read(SSL *ssl, void *buf, int num);
        let buf_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let max_len = uc.reg_read(RegisterARM64::X2).unwrap() as usize;

        // Emulate live list responses if enabled
        if uc.get_data().simulate_live_list && uc.get_data().simulate_live_list_remaining > 0 && max_len > 0 {
            let mut seed = uc.get_data().simulate_seed;
            let payload = build_fake_live_list_json(&mut seed, std::cmp::min(uc.get_data().simulate_live_list_remaining, 50));
            uc.get_data_mut().simulate_seed = seed;
            let bytes = payload.as_bytes();
            let write_len = std::cmp::min(bytes.len(), max_len);
            let _ = uc.mem_write(buf_ptr, &bytes[..write_len]);
            uc.get_data_mut().simulate_live_list_remaining = uc.get_data().simulate_live_list_remaining.saturating_sub(1);
            println!("[NETWORK-SSL] Emulated live list response ({} bytes)", write_len);
            uc.reg_write(RegisterARM64::X0, write_len as u64).unwrap();
            return;
        }

        // Simulate successful read with dummy data
        println!("[NETWORK-SSL] SSL_read request for {} bytes (returning 0 - no data)", max_len);
        
        // ENHANCEMENT: Try to intercept response at SSL layer
        // If app writes response data to buf_ptr before calling SSL_read, we can inspect it
        if max_len > 0 && max_len < 1000000 {
            let read_len = std::cmp::min(max_len, 8192);
            if let Ok(potential_response) = uc.mem_read_as_vec(buf_ptr, read_len) {
                let response_str = String::from_utf8_lossy(&potential_response);
                
                // Check for Zeus API or livestream responses
                if response_str.contains("zeus") || response_str.contains("shortvideo") 
                    || response_str.contains("qiniu") || response_str.contains("live")
                    || response_str.contains("stream") || response_str.contains("category")
                    || response_str.contains("room_id") || response_str.contains("anchor")
                {
                    println!("\n[!!!] POTENTIAL QINIU/LIVESTREAM RESPONSE DETECTED [!!!]");
                    println!("[Response] {} bytes:", read_len);
                    println!("{}", response_str);
                    
                    // Log to file
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("livestream_responses.log")
                    {
                        let _ = writeln!(file, "[SSL_read] Response captured:");
                        let _ = writeln!(file, "{}", response_str);
                        let _ = writeln!(file, "---");
                    }
                }
                
                // Check for Moonton GMS game telemetry responses
                if response_str.contains("gms") || response_str.contains("moontontech")
                    || response_str.contains("hero") || response_str.contains("item")
                    || response_str.contains("emblem") || response_str.contains("kda")
                    || response_str.contains("match_id") || response_str.contains("streamer_id")
                    || response_str.contains("game_state") || response_str.contains("picks")
                {
                    println!("\n[!!!] MOONTON GAME TELEMETRY RESPONSE DETECTED [!!!]");
                    println!("[Response] {} bytes:", read_len);
                    println!("{}", response_str);
                    
                    // Log to file
                    if let Ok(mut file) = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("game_telemetry_responses.log")
                    {
                        let _ = writeln!(file, "[SSL_read] Game Telemetry Response:");
                        let _ = writeln!(file, "{}", response_str);
                        let _ = writeln!(file, "---");
                    }
                }
            }
        }
        
        uc.reg_write(RegisterARM64::X0, 0).unwrap(); // No data available
    } else if name.contains("dlclose") {
        uc.reg_write(RegisterARM64::X0, 0).unwrap();
    }
}

fn handle_jni(uc: &mut Unicorn<EmulatorState>, idx: u64) {
    smart_log(uc, format!("[JNI] Call {} (Offset {:x})", idx, idx * 8));

    // Default Success (0)
    let mut retval = 0;

    if idx == 6 {
        // FindClass
        let _env = uc.reg_read(RegisterARM64::X0).unwrap();
        let name_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let name = read_string(uc, name_ptr);
        smart_log(uc, format!("[JNI] FindClass: {}", name));
        retval = 0xDEADBEEF; // Dummy Class Object
    } else if idx == 33 || idx == 113 {
        // GetMethodID / GetStaticMethodID
        let _env = uc.reg_read(RegisterARM64::X0).unwrap();
        let _clazz = uc.reg_read(RegisterARM64::X1).unwrap();
        let name_ptr = uc.reg_read(RegisterARM64::X2).unwrap();
        let sig_ptr = uc.reg_read(RegisterARM64::X3).unwrap();
        let name = read_string(uc, name_ptr);
        let sig = read_string(uc, sig_ptr);
        smart_log(uc, format!("[JNI] GetMethodID ({}): {} {}", idx, name, sig));
        retval = 0xCAFEBABE; // Dummy Method ID
    } else if idx == 34 {
        // CallObjectMethod (env, obj, mid, args...)
        // Checking if this is loadClass(String)
        // X0=env, X1=obj, X2=mid, X3=arg1
        let arg1_ptr = uc.reg_read(RegisterARM64::X3).unwrap();
        // Try reading arg1 as string?
        // Only if we suspect it's a string.
        // We can check if pointer is in Heap or near String ranges?
        // Or just try reading it (safe read).
        let maybe_str = read_string(uc, arg1_ptr);
        smart_log(
            uc,
            format!("[JNI] CallObjectMethod (34): Arg1='{}'", maybe_str),
        );

        // Return 0xDEADBEEF (Dummy Class)
        // Return 0xDEADBEEF (Dummy Class)
        retval = 0xDEADBEEF;
    } else if idx == 115 {
        smart_log(
            uc,
            " [JNI] CallStaticObjectMethod (115) - Returning Dummy ClassLoader".to_string(),
        );
        retval = 0x88888888;
    } else if idx == 21 {
        // NewGlobalRef (env, obj) -> obj
        // Return input object as "Ref"
        let obj = uc.reg_read(RegisterARM64::X1).unwrap();
        smart_log(uc, format!("[JNI] NewGlobalRef (21): {:x}", obj));
        retval = obj;
    } else if idx == 167 {
        // NewStringUTF (env, bytes)
        let bytes_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let s = read_string(uc, bytes_ptr);
        smart_log(uc, format!("[JNI] NewStringUTF (167): '{}'", s));
        // Return dummy string object?
        retval = 0x99999999;
    } else if idx == 169 {
        // GetStringUTFChars (env, string, isCopy)
        let string_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        smart_log(
            uc,
            format!("[JNI] GetStringUTFChars (169): Object {:x}", string_ptr),
        );
        // We assume the object pointer IS the string path for our mocks
        retval = string_ptr;
    } else if idx == 170 {
        // ReleaseStringUTFChars
        smart_log(uc, "[JNI] ReleaseStringUTFChars (170)".to_string());
        retval = 0;
    } else if idx == 215 {
        // RegisterNatives
        let _env = uc.reg_read(RegisterARM64::X0).unwrap();
        let clazz = uc.reg_read(RegisterARM64::X1).unwrap();
        let methods = uc.reg_read(RegisterARM64::X2).unwrap();
        let count = uc.reg_read(RegisterARM64::X3).unwrap();
        println!("\n\n============================================");
        println!("   [VICTORY] JNI RegisterNatives FOUND!");
        println!(
            "   Class: {:x}, Methods: {:x}, Count: {}",
            clazz, methods, count
        );
        println!("============================================\n");
        // We can dump methods here later.
        std::process::exit(0);
    }

    uc.reg_write(RegisterARM64::X0, retval).unwrap();
}

fn smart_log(uc: &mut Unicorn<EmulatorState>, msg: String) {
    let mut exit_flag = false;
    {
        let data = uc.get_data_mut();
        if data.last_log == msg {
            data.log_count += 1;
        } else {
            data.last_log = msg.clone();
            data.log_count = 1;
        }
        if data.log_count >= 50 {
            println!(
                "{}\n[Protection] Force stopping due to 5 consecutive identical outputs.",
                msg
            );
            exit_flag = true;
        } else {
            println!("{}", msg);
        }
    }
    if exit_flag {
        std::process::exit(0);
    }
}

fn read_string(uc: &Unicorn<EmulatorState>, addr: u64) -> String {
    let mut buf = Vec::new();
    let mut cur = addr;
    loop {
        if let Ok(byte_vec) = uc.mem_read_as_vec(cur, 1) {
            let byte = byte_vec[0];
            if byte == 0 {
                break;
            }
            buf.push(byte);
            cur += 1;
            if buf.len() > 1024 {
                break;
            }
        } else {
            break;
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}
