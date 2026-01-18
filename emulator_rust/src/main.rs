#![allow(dead_code)]
use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead, Write};
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
    let code = fs::read(lib_path).expect("Failed to read memory_dump.bin");

    // Init State
    let mut state = EmulatorState {
        imports_map: imports_map.clone(),
        magic_map: HashMap::new(),
        magic_counter: MAGIC_BASE + 0x100, // Reserve start for predefined hooks
        heap_ptr: HEAP_START,
        threads: Vec::new(),
        current_thread_idx: 0,
        next_tid: 1, // Main is 0
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
    let entry = BASE_ADDR + 0x62ed1c;

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
    unicorn.reg_write(RegisterARM64::X0, jvm_base)?; // vm
    unicorn.reg_write(RegisterARM64::X1, 0)?; // reserved

    unicorn.reg_write(RegisterARM64::SP, stack_top)?;
    unicorn.reg_write(RegisterARM64::PC, entry)?;
    unicorn.reg_write(RegisterARM64::LR, 0x30000000)?; // EXIT MAGIC
    unicorn.reg_write(RegisterARM64::CPACR_EL1, 0x300000)?; // VFP
    unicorn.reg_write(RegisterARM64::TPIDR_EL0, HEAP_START + 0x100000)?; // TLS

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
                // Mark dead
                unicorn.get_data_mut().threads[current_idx].status = ThreadStatus::Dead;
            } else {
                // Success - Check for Exit
                let final_pc = unicorn.reg_read(RegisterARM64::PC)?;
                if final_pc == 0 {
                    let tid = unicorn.get_data().threads[current_idx].tid;
                    println!("[Sched] Thread T{} Finished/Exited (PC=0)", tid);
                    scan_memory_for_strings(&unicorn);
                    unicorn.get_data_mut().threads[current_idx].status = ThreadStatus::Dead;
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

        // Loop Exit if All Dead
        if unicorn
            .get_data()
            .threads
            .iter()
            .all(|t| t.status == ThreadStatus::Dead)
        {
            println!("[Sched] All threads dead. Exiting.");
            break;
        }
        total_insts += quantum as u64;
        if total_insts % 10_000_000 == 0 {
            let pc = unicorn.reg_read(RegisterARM64::PC).unwrap_or(0);
            println!("[Status] {} Insts | PC={:x}", total_insts, pc);
        }
    }

    Ok(())
}

fn handle_import(uc: &mut Unicorn<EmulatorState>, name: &str) {
    if name.contains("malloc") {
        let size = uc.reg_read(RegisterARM64::X0).unwrap_or(0);
        let heap = uc.get_data().heap_ptr;
        let aligned_size = (size + 7) & !7;
        uc.reg_write(RegisterARM64::X0, heap).unwrap();
        uc.get_data_mut().heap_ptr += aligned_size;
    } else if name.contains("pthread_create") {
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
        println!("[LogPrint] {}: {} (Args not parsed)", tag, fmt);
        uc.reg_write(RegisterARM64::X0, 0).unwrap();
    } else if name.contains("sendto") || name.contains("write") {
        // (fd, buf, len) -> X0, X1, X2
        let buf_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let len = uc.reg_read(RegisterARM64::X2).unwrap();
        if len > 0 {
            if let Ok(data) = uc.mem_read_as_vec(buf_ptr, len as usize) {
                // Try UTF-8
                if let Ok(s) = std::str::from_utf8(&data) {
                    println!("[Network] Send ({} bytes): {}", len, s);
                } else {
                    println!(
                        "[Network] Send ({} bytes): {:02x?}",
                        len,
                        &data[..std::cmp::min(data.len(), 50)]
                    );
                }
            }
        }
        uc.reg_write(RegisterARM64::X0, len).unwrap(); // Success
    } else if name.contains("dlclose") {
        uc.reg_write(RegisterARM64::X0, 0).unwrap();
    }
}

fn handle_jni(uc: &mut Unicorn<EmulatorState>, idx: u64) {
    println!("[JNI] Call {} (Offset {:x})", idx, idx * 8);

    // Default Success (0)
    let mut retval = 0;

    if idx == 6 {
        // FindClass
        let _env = uc.reg_read(RegisterARM64::X0).unwrap();
        let name_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let name = read_string(uc, name_ptr);
        println!("[JNI] FindClass: {}", name);
        retval = 0xDEADBEEF; // Dummy Class Object
    } else if idx == 33 || idx == 113 {
        // GetMethodID / GetStaticMethodID
        let _env = uc.reg_read(RegisterARM64::X0).unwrap();
        let _clazz = uc.reg_read(RegisterARM64::X1).unwrap();
        let name_ptr = uc.reg_read(RegisterARM64::X2).unwrap();
        let sig_ptr = uc.reg_read(RegisterARM64::X3).unwrap();
        let name = read_string(uc, name_ptr);
        let sig = read_string(uc, sig_ptr);
        println!("[JNI] GetMethodID ({}): {} {}", idx, name, sig);
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
        println!("[JNI] CallObjectMethod (34): Arg1='{}'", maybe_str);

        // Return 0xDEADBEEF (Dummy Class)
        // Return 0xDEADBEEF (Dummy Class)
        retval = 0xDEADBEEF;
    } else if idx == 115 {
        println!("[JNI] CallStaticObjectMethod (115) - Returning Dummy ClassLoader");
        retval = 0x88888888;
    } else if idx == 21 {
        // NewGlobalRef (env, obj) -> obj
        // Return input object as "Ref"
        let obj = uc.reg_read(RegisterARM64::X1).unwrap();
        println!("[JNI] NewGlobalRef (21): {:x}", obj);
        retval = obj;
    } else if idx == 167 {
        // NewStringUTF (env, bytes)
        let bytes_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        let s = read_string(uc, bytes_ptr);
        println!("[JNI] NewStringUTF (167): '{}'", s);
        // Return dummy string object?
        println!("[JNI] NewStringUTF (167): '{}'", s);
        // Return dummy string object?
        retval = 0x99999999;
    } else if idx == 169 {
        // GetStringUTFChars (env, string, isCopy)
        let string_ptr = uc.reg_read(RegisterARM64::X1).unwrap();
        println!("[JNI] GetStringUTFChars (169): Object {:x}", string_ptr);
        // We assume the object pointer IS the string path for our mocks
        retval = string_ptr;
    } else if idx == 170 {
        // ReleaseStringUTFChars
        println!("[JNI] ReleaseStringUTFChars (170)");
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
