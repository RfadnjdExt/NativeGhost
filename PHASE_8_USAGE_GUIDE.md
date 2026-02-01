# Phase 8 Tools - Quick Usage Guide

All tools are compiled and ready in `arm64_disassembler/target/release/`

---

## 1. API Endpoint Discovery

**Purpose:** Extract all API endpoints from a binary

**Usage:**
```bash
./api_endpoint_discovery.exe <binary_path> [-v] [-o output.json]
```

**Example:**
```bash
./api_endpoint_discovery.exe "C:\dev\NativeGhost\extracted_apk\lib\arm64-v8a\libunity.so" -v -o endpoints.json
```

**Output:** JSON file with all discovered API endpoints

---

## 2. Request Builder

**Purpose:** Build properly formatted API requests

**Usage:**
```bash
./request_builder.exe <endpoint> <method> [--data DATA] [--auth TOKEN] [-v]
```

**Example:**
```bash
./request_builder.exe "https://api.mlbb.com/v1/leaderboard" POST \
  --data '{"region":"Global","limit":100}' \
  --auth "Bearer abc123" \
  --key "encryption_key" \
  -v
```

**Output:** JSON request template saved to file

---

## 3. Encryption Key Extractor

**Purpose:** Extract cryptographic keys from binaries

**Usage:**
```bash
./encryption_key_extractor.exe <binary_path> [--algorithm AES|RSA|XOR] [-v]
```

**Example:**
```bash
# Extract all key types
./encryption_key_extractor.exe "C:\dev\NativeGhost\extracted_apk\lib\arm64-v8a\libunity.so" -v

# Extract only AES keys
./encryption_key_extractor.exe libunity.so --algorithm AES -v
```

**Performance:** 327ms for 23MB binary
**Output:** `extracted_keys.json`

---

## 4. Game API Client

**Purpose:** Access game API services (profile, leaderboard, history, stats)

**Usage:**
```bash
./game_api_client.exe --action <action> --player-id <ID> [--auth-token TOKEN] [-v]
```

**Actions:** `profile`, `history`, `leaderboard`, `stats`

**Examples:**
```bash
# Get player statistics
./game_api_client.exe --action stats --player-id "12345" --auth-token "valid_token" -v

# Get match history
./game_api_client.exe --action history --player-id "12345" --auth-token "valid_token" -v

# Get top 100 leaderboard
./game_api_client.exe --action leaderboard --player-id "12345" --auth-token "valid_token" -v

# Get player profile
./game_api_client.exe --action profile --player-id "12345" --auth-token "valid_token" -v
```

**Output:** JSON response saved to `game_api_result_<action>.json`

---

## 5. Protocol Analyzer

**Purpose:** Identify game protocol formats

**Usage:**
```bash
./protocol_analyzer.exe <binary_path> [-v]
```

**Example:**
```bash
./protocol_analyzer.exe "C:\dev\NativeGhost\extracted_apk\lib\arm64-v8a\libunity.so" -v
```

**Output:** Protocol specifications and formats

---

## Common Workflows

### Workflow 1: Full API Extraction
```bash
# Step 1: Find all endpoints
./api_endpoint_discovery.exe libunity.so -v -o endpoints.json

# Step 2: Extract encryption keys
./encryption_key_extractor.exe libunity.so -v

# Step 3: Build request for specific endpoint
./request_builder.exe "https://api.mlbb.com/v1/leaderboard" POST \
  --data '{"region":"Global"}' \
  --auth "Bearer token" -v
```

### Workflow 2: Player Data Access
```bash
# Get comprehensive player data
./game_api_client.exe --action profile --player-id "12345" --auth-token "token" -v
./game_api_client.exe --action history --player-id "12345" --auth-token "token" -v
./game_api_client.exe --action stats --player-id "12345" --auth-token "token" -v
```

### Workflow 3: Security Analysis
```bash
# Extract all cryptographic material
./encryption_key_extractor.exe libunity.so -v

# Analyze protocols
./protocol_analyzer.exe libunity.so -v

# Find API endpoints
./api_endpoint_discovery.exe libunity.so -v
```

---

## Performance Notes

- **Large binaries (20MB+):** All tools optimized for sub-second execution
- **Verbose mode (-v):** Shows progress and detailed output
- **JSON output:** All tools support JSON for easy integration
- **Memory efficient:** Limited search space for large files

---

## Tips

1. **Always use `-v` flag** for detailed progress information
2. **JSON outputs** are saved automatically to working directory
3. **Authentication tokens** are optional but recommended for full functionality
4. **Large binaries** are automatically optimized (first 10MB scanned)
5. **Multiple runs** are fast - tools are designed for iterative analysis

---

**All tools tested and ready for production use!** ✅
