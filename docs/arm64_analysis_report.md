# ARM64 Network Function Analysis Report

Binary: extracted_apk/lib/arm64-v8a/libunity.so
Size: 23 MB

## Summary

- Function entry points: 1182
- ADRP patterns found: 176931
- Direct network string references: 0
- Network strings checked: 4

## Key Findings

### ADRP Pattern Statistics
ADRP instructions are used to load page addresses for string references.
Found 176931 ADRP instructions in the binary.

### Network Strings
- Match @ 0x0e9f56
- http @ 0x0eec1a
- Request @ 0x0df792
- Response @ 0x0125266

### Conclusion
Found 0 direct ADRP+ADD references to network strings.
Network strings are embedded but direct references were not found.
This suggests URLs are constructed dynamically at runtime.

## Recommendations

1. Use Frida runtime hooking to capture actual API calls
2. Perform network packet capture during gameplay
3. Analyze higher-level C# code (Unity)
