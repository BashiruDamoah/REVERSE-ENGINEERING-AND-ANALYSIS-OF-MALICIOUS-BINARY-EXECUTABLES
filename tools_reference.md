# Tools Reference
## Commands and Configurations Used During Analysis

---

## UPX — Unpacking

```powershell
# Unpack the binary
upx -d ransomware.exe -o ransomware_unpacked.exe

# Verify file hashes after unpacking (Windows)
certutil -hashfile ransomware.exe SHA256
certutil -hashfile ransomware_unpacked.exe SHA256
```

---

## PEStudio — Static Analysis Checklist

1. Load binary → check **file properties** (entropy, compiler, timestamp)
2. Check **sections** for UPX markers (`UPX0`, `UPX1`) and self-modifying flags
3. Review **imports** — sort by flag count; note process injection, network, and privilege APIs
4. Review **strings** — sort by flag value; filter for recon vars, privilege tokens, registry paths
5. Repeat steps 2–4 on the **unpacked binary** for full picture

**Entropy threshold:** Values above 7.0 indicate packing/encryption.

---

## Ghidra — Decompilation Workflow

1. Create new project → Import binary with default analysis settings
2. Navigate to **entry point** (reported by PEStudio)
3. Trace call chain: `entry` → `__tmainCRTStartup` → startup imports
4. Open **Functions window** → sort by **Function Size (descending)**
5. Examine the largest function(s) — rename for clarity (e.g., `main_malicious_logic`)
6. Search for key strings (Window → Search → Program Text) for known API names
7. Use **Symbol Tree → Imports** to cross-reference flagged APIs with their call sites

---

## x32dbg — Debugging Workflow

### Initial Setup
1. Load **packed binary** (not unpacked — more realistic to victim behavior)
2. Install and enable **ScyllaHide** plugin (Options → Preferences → Plugins)
3. Set breakpoints on key APIs before running:
   ```
   bp VirtualProtect
   bp CreateWindowExA
   bp ShowWindow
   ```

### Execution Steps
1. Press **F9** to pass initial `ntdll.dll` system breakpoint
2. Observe second pause at malware entry point — confirm `pushad` as first instruction
3. Monitor **Log tab** for DLL loads and ScyllaHide hook notifications
4. Monitor **Breakpoints tab** for hit counts
5. Allow execution to continue — observe lockscreen deployment

### Anti-Debug Notes
- This sample bypasses API-level breakpoints via direct syscalls
- **Recommended alternatives:**
  - Kernel breakpoints on `NtCreateWindow` / `NtUserBlockInput`
  - Memory-access breakpoints on stack regions
  - Hardware breakpoints (DR0–DR3 registers)

---

## Hash Verification (Windows)

```powershell
# SHA256
certutil -hashfile <filename> SHA256

# MD5
certutil -hashfile <filename> MD5

# SHA1
certutil -hashfile <filename> SHA1
```
