# IL2CPP Interpreter Roadmap - MLBB API Discovery Project

## Executive Summary

Building a complete IL2CPP interpreter to extract game API endpoints. Estimate: **12-18 months** for expert Rust developer, split into 5 phases.

---

## Understanding IL2CPP Architecture

### What is IL2CPP?

IL2CPP is Unity's C++ code generation backend. It:
1. **Compiles** C# scripts to IL (Intermediate Language) bytecode
2. **Transpiles** IL bytecode to C++ code
3. **Compiles** C++ to native ARM64 binary (libunity.so)
4. **Stores metadata** in binary serialized format (global-metadata.dat)

### Key Files

```
libunity.so (23.6 MB)           ← Compiled native code
  ├─ IL2CPP Metadata (binary)   ← Type definitions, method signatures
  ├─ IL2CPP Code                ← Actual IL bytecode interpreter
  └─ JNI Exports                ← Android entry points

global-metadata.dat (0 bytes)   ← Empty in this APK (likely stripped)
global-csharp-metadata.dat      ← Empty in this APK
global-first-metadata.dat       ← Empty in this APK
```

**Note**: Metadata files are empty (extraction failed or stripped by developers), so we must:
- Extract metadata directly from libunity.so binary
- Parse IL2CPP type definitions from compiled code
- Reconstruct method signatures from CPU instructions

---

## Phase 1: IL2CPP Binary Analysis & Metadata Extraction

### Goals
1. Identify IL2CPP metadata structures in libunity.so
2. Parse type definitions (classes, methods, fields)
3. Extract method IL bytecode sequences
4. Map all network-related method calls

### Key Technologies

**IL2CPP Metadata Format** (binary structure):
```
[Header]
  magic: u32
  version: u32
  ...

[Types Section]
  - TypeDefinition[]  (class definitions)
  - MethodDefinition[]  (method metadata)
  - ParameterDefinition[]
  - StringLiterals

[Code Section]
  - IL Bytecode for each method
  - Exception handlers
  - Local variable info
```

### Implementation

**File**: `il2cpp_parser/src/lib.rs`

```rust
pub struct IL2CPPHeader {
    magic: u32,
    version: u32,
    strings_offset: u32,
    string_count: u32,
    types_offset: u32,
    type_count: u32,
    methods_offset: u32,
    method_count: u32,
}

pub struct TypeDefinition {
    name_index: u32,
    namespace_index: u32,
    base_type_index: i32,
    method_start: u32,
    method_count: u32,
    field_start: u32,
    field_count: u32,
}

pub struct MethodDefinition {
    name_index: u32,
    class_index: u16,
    flags: u16,
    return_type: u16,
    parameter_start: u32,
    parameter_count: u32,
    il_code_offset: u32,
    il_code_size: u32,
}

// Parse libunity.so
pub fn parse_il2cpp_metadata(binary: &[u8]) -> Result<IL2CPPMetadata> {
    let header = parse_header(binary)?;
    let strings = parse_string_table(binary, &header)?;
    let types = parse_type_definitions(binary, &header, &strings)?;
    let methods = parse_method_definitions(binary, &header, &strings)?;
    Ok(IL2CPPMetadata { header, strings, types, methods })
}
```

### Estimated Effort: **200-300 hours**

**Blockers**:
- IL2CPP format not fully documented (reverse engineering required)
- Metadata offsets need to be discovered from ARM64 code patterns
- Version-specific differences between Unity versions

### Deliverables
- [ ] libunity.so parser
- [ ] Metadata structure extraction
- [ ] Method signature recovery
- [ ] String literal table
- [ ] Network method identification (methods calling socket/SSL APIs)

---

## Phase 2: IL Bytecode Interpreter

### Goals
1. Implement IL opcode executor
2. Support all 250+ IL instructions
3. Execute method sequences up to network calls

### IL Opcodes (subset for Phase 2)

```rust
pub enum ILOpcode {
    // Load constants
    Ldc_I4(i32),              // load 32-bit int constant
    Ldc_I8(i64),              // load 64-bit int constant
    Ldc_R8(f64),              // load 64-bit float constant
    Ldstr(u32),               // load string from metadata
    
    // Load from variables
    Ldloc(u32),               // load local variable
    Stloc(u32),               // store local variable
    Ldarg(u32),               // load argument
    Starg(u32),               // store argument
    
    // Arithmetic
    Add, Sub, Mul, Div, Rem,
    Neg,
    Shl, Shr,
    
    // Comparison
    Ceq,        // compare equal
    Clt,        // compare less than
    Cgt,        // compare greater than
    
    // Branching
    Br(u32),                  // unconditional branch
    Brfalse(u32),             // branch if false
    Brtrue(u32),              // branch if true
    
    // Method calls
    Call(u32),                // call method (method index)
    Callvirt(u32),            // virtual call
    
    // Object operations
    Newobj(u32),              // new instance
    Ldfld(u32),               // load field
    Stfld(u32),               // store field
    
    // Array operations
    Newarr(u32),              // new array
    Ldelem,                   // load array element
    Stelem,                   // store array element
    
    // Return
    Ret,                      // return from method
}

pub struct ILExecutor {
    // Operand stack (runtime values)
    stack: Vec<Value>,
    
    // Local variables for current method
    locals: Vec<Value>,
    
    // Method arguments
    args: Vec<Value>,
    
    // Instruction pointer
    pc: usize,
    
    // Call stack for recursive calls
    call_stack: Vec<CallFrame>,
}

impl ILExecutor {
    pub fn execute_method(&mut self, method: &MethodDefinition) -> Result<Value> {
        let il_bytecode = self.load_il_bytecode(method)?;
        
        loop {
            let opcode = self.fetch_opcode(&il_bytecode)?;
            
            match opcode {
                ILOpcode::Ldc_I4(val) => self.stack.push(Value::I32(val)),
                ILOpcode::Add => {
                    let b = self.stack.pop()?;
                    let a = self.stack.pop()?;
                    self.stack.push(a.add(b)?);
                }
                ILOpcode::Call(method_idx) => {
                    self.call_method(method_idx)?;
                }
                ILOpcode::Ret => {
                    return self.stack.pop().ok_or("Stack underflow");
                }
                // ... other opcodes
            }
        }
    }
}
```

### Estimated Effort: **250-350 hours**

**Blockers**:
- 250+ IL opcodes to implement
- Complex type conversions
- Exception handling
- Generic type support

### Deliverables
- [ ] IL bytecode loader
- [ ] Opcode executor (all 250+ instructions)
- [ ] Stack-based value system
- [ ] Method calling convention
- [ ] Basic type system

---

## Phase 3: Managed Runtime & Type System

### Goals
1. Implement object allocation and GC
2. Support type reflection
3. Handle class hierarchies and virtual methods
4. String and array support

### Type System

```rust
pub enum Value {
    Null,
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    String(Arc<str>),
    Object(Box<ManagedObject>),
    Array(Box<ManagedArray>),
}

pub struct ManagedObject {
    type_id: u32,
    fields: HashMap<u32, Value>,
    gc_mark: AtomicBool,
}

pub struct ManagedArray {
    element_type: u32,
    elements: Vec<Value>,
}

pub struct TypeInfo {
    name: String,
    namespace: String,
    base_type: Option<u32>,
    methods: HashMap<String, MethodDefinition>,
    fields: HashMap<String, FieldDefinition>,
    vtable: Vec<MethodDefinition>,  // virtual method table
}

pub struct GarbageCollector {
    heap: Vec<ManagedObject>,
    roots: Vec<usize>,
}

impl GarbageCollector {
    pub fn mark_and_sweep(&mut self) {
        // Mark phase: traverse from roots
        for &root in &self.roots {
            self.mark(root);
        }
        
        // Sweep phase: collect unmarked objects
        self.heap.retain(|obj| obj.gc_mark.load(Ordering::Relaxed));
    }
}
```

### Estimated Effort: **200-300 hours**

**Blockers**:
- Generic type constraints
- Inheritance and polymorphism
- Interface implementation
- Delegate/lambda support

### Deliverables
- [ ] Managed heap
- [ ] Garbage collector
- [ ] Type hierarchy
- [ ] Virtual method dispatch
- [ ] String/Array implementation
- [ ] Reflection system

---

## Phase 4: Native Interop & Network Hooking

### Goals
1. Implement Android API stubs
2. Hook network calls (socket, SSL, HTTP)
3. Capture API endpoints and parameters
4. Log method arguments and return values

### Network Hooking Strategy

```rust
pub struct NetworkHook {
    // Intercept socket operations
    socket_calls: Vec<SocketCall>,
    ssl_handshakes: Vec<SSLHandshake>,
    send_data: Vec<SendData>,
}

pub struct SocketCall {
    timestamp: u64,
    family: u32,          // AF_INET, AF_INET6
    socktype: u32,        // SOCK_STREAM, SOCK_DGRAM
    protocol: u32,
    error: Option<i32>,
}

pub struct SendData {
    timestamp: u64,
    socket_fd: i32,
    data: Vec<u8>,        // Actual bytes sent
    parsed_http: Option<HttpRequest>,  // If HTTP detected
}

pub struct HttpRequest {
    method: String,        // GET, POST, etc.
    host: String,          // api.gms.moontontech.com
    path: String,          // /api/v1/match/live
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

// Hook into JNI native calls
pub fn hook_network_calls(executor: &mut ILExecutor) {
    // When method calls native socket API, intercept
    executor.register_native_hook("android.os.ParcelFileDescriptor", "createSocket", |args| {
        let socket_fd = args[0].as_i32()?;
        recorder.record_socket_create(socket_fd);
        Ok(Value::I32(socket_fd))
    });
    
    executor.register_native_hook("java.net.Socket", "connect", |args| {
        let addr = args[1].as_string()?;
        let port = args[2].as_i32()?;
        recorder.record_socket_connect(addr, port);
        Ok(Value::Null)
    });
    
    executor.register_native_hook("javax.net.ssl.SSLSocket", "startHandshake", |args| {
        recorder.record_ssl_handshake();
        Ok(Value::Null)
    });
}
```

### Estimated Effort: **150-250 hours**

**Blockers**:
- Android framework API is massive (10,000+ methods)
- Need to stub most of them
- SSL/TLS protocol understanding
- HTTP parsing

### Deliverables
- [ ] JNI stub framework
- [ ] Socket operation hooks
- [ ] SSL/TLS handshake tracking
- [ ] HTTP request capture
- [ ] Data logging system
- [ ] API endpoint extraction

---

## Phase 5: Integration & Validation

### Goals
1. Wire all phases together
2. Execute actual game code paths
3. Capture real API endpoints
4. Validate against known endpoints

### Testing Strategy

```
Test Layer 1: Unit Tests
├─ IL2CPP parser (metadata extraction)
├─ IL bytecode executor (single methods)
├─ Type system (object creation, GC)
└─ Network hooks (API capture)

Test Layer 2: Integration Tests
├─ Execute simple C# methods
├─ Create objects and call virtual methods
├─ Recursive method calls
└─ String operations

Test Layer 3: Game Code Execution
├─ Execute initialization code
├─ Trigger network module setup
├─ Capture socket connections
├─ Log HTTP requests
└─ Extract API endpoints
```

### Estimated Effort: **100-200 hours**

### Deliverables
- [ ] Integrated IL2CPP interpreter
- [ ] Test suite
- [ ] MLBB API endpoint log
- [ ] Documentation

---

## Timeline

### Realistic Schedule (Parallel Development)

```
Month 1-3:   Phase 1 (IL2CPP Binary Analysis)
  ├─ Learn IL2CPP format (reverse engineering)
  ├─ Build metadata parser
  └─ Identify network-related methods

Month 3-5:   Phase 2 (IL Bytecode Interpreter)
  ├─ Implement IL executor
  ├─ Support 250+ opcodes
  └─ Method calling convention

Month 5-7:   Phase 3 (Managed Runtime)
  ├─ GC and heap management
  ├─ Type system and reflection
  └─ Virtual method dispatch

Month 7-9:   Phase 4 (Network Hooking)
  ├─ Native interop framework
  ├─ Socket/SSL hooks
  └─ HTTP capture

Month 9-10:  Phase 5 (Integration & Testing)
  ├─ Wire all components
  ├─ Execute game code
  └─ Extract API endpoints

**Total: ~12-15 months** (assuming 20-30 hours/week)
```

---

## Success Criteria

✅ **Project Complete When**:
1. Execute initialization code from libunity.so without crashes
2. Capture at least 5 distinct HTTP requests to gms.moontontech.com
3. Log full request/response for each API call
4. Extract parameter structure (user IDs, match IDs, etc.)
5. Identify 3+ unknown API endpoints

---

## Current Status

| Phase | Status | Progress |
|-------|--------|----------|
| 0: Analysis | ✅ Complete | Identified libunity.so as target |
| 1: Parser | ⏳ Starting | Ready to begin Phase 1 |
| 2: Interpreter | 🔴 Not Started |  |
| 3: Runtime | 🔴 Not Started |  |
| 4: Hooking | 🔴 Not Started |  |
| 5: Integration | 🔴 Not Started |  |

---

## Next Immediate Steps

1. **Analyze libunity.so structure** (arm64 binary format)
   - Find IL2CPP header signature
   - Identify metadata section offsets
   - Locate IL bytecode regions

2. **Create binary parser** (Rust)
   - Read and parse IL2CPP header
   - Extract type definitions
   - Map method IL bytecode

3. **Document format** as we discover it
   - Build knowledge base
   - Share format specification
   - Enable future improvements

---

## Tools & Dependencies

### Already Available
- ✅ Extracted APK with libunity.so (23.6 MB)
- ✅ Rust toolchain (emulator_rust project)
- ✅ Binary analysis scripts

### Need to Create
- 🔲 IL2CPP binary parser
- 🔲 IL bytecode interpreter
- 🔲 Managed runtime
- 🔲 Network hooking framework
- 🔲 Test harness

### External References
- IL2CPP Source: https://github.com/Unity-Technologies/il2cpp_runtime
- IL Specification: ECMA-335 (CIL standard)
- ARM64 ABI: ARM Architecture Reference Manual

---

## Risk Factors & Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|-----------|
| IL2CPP format undocumented | HIGH | HIGH | Reverse engineer from source code |
| APIs encrypted/obfuscated | MEDIUM | HIGH | Capture at runtime before encryption |
| Game anticheat detection | LOW | CRITICAL | Execute in isolated environment |
| Missing metadata (stripped) | HIGH | MEDIUM | Reconstruct from IL bytecode patterns |
| Complex IL opcodes | HIGH | MEDIUM | Implement incrementally, test each |

---

**Status**: Ready to begin Phase 1 implementation.

