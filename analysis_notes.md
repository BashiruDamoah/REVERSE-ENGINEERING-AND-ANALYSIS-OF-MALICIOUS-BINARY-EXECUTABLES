# Analysis Notes
## LockScreen Ransomware — Reverse Engineering Methodology

---

## Environment

- **OS:** Windows 10 (isolated virtual machine — no internet access during analysis)
- **Snapshot:** Clean snapshot taken before analysis; restored after lockscreen deployment
- **Tools:** PEStudio 9.61, Ghidra, x32dbg (TitanEngine), UPX 5.0.2, ScyllaHide

---

## Phase 1 — Static Analysis (Packed Binary)

**Tool:** PEStudio

### Observations
- File identified as PE32 executable, 32-bit, GUI subsystem
- Compiler: Microsoft Visual Studio 2010 / Linker 10.0
- Compilation timestamp: **Sunday, January 29, 2012, 21:32:28 UTC**
- Entropy: **7.875** (near-maximum; strong indicator of packing/compression)
- Entry point: `0x000CEE90` (within `idata` section)
- UPX section markers (`UPX0`, `UPX1`) and version string `3.07` visible in strings
- PEStudio flagged **self-modifying code** characteristic (consistent with UPX stub)
- Only **21 imports visible**, 9 flagged — typical of packed binary hiding true IAT

### Key Flagged Imports (Packed)
| Import | Reason Flagged |
|---|---|
| `VirtualProtect` | Memory permission modification (unpacking) |
| `VirtualAlloc` | Memory allocation (unpacking) |
| `EnumProcesses` | Process enumeration |
| `FtpOpenFileW` | FTP connectivity |
| `WNetGetConnectionW` | Network drive access |

---

## Phase 2 — UPX Unpacking

**Command used:**
```powershell
upx -d ransomware.exe -o ransomware_unpacked.exe
```

**Output:**
```
File size    Ratio    Format    Name
792879 <-   445231   56.15%    win32/pe    ransomware_unpacked.exe
Unpacked 1 file.
```

- File expanded from **445,231 → 792,879 bytes** (56.15% compression ratio)
- New SHA256 hash computed and recorded for the unpacked variant
- Import table expanded from **21 → 513 imports** (156 flagged)

---

## Phase 3 — Static Analysis (Unpacked Binary)

**Tool:** PEStudio

### Import Highlights (Unpacked)
- **Process Injection:** `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory`
- **Network:** `InternetOpenW`, `InternetConnectW`, `HttpOpenRequestW`, `HttpSendRequestW`, `InternetReadFile`, `FtpOpenFileW`, raw socket functions
- **Privilege:** `LoadUserProfileW`, `CreateProcessWithLogonW`, `LogonUserW`
- **Input:** (via strings) `NtUserBlockInput`, `SwapMouseButtons`

### String Highlights (18,885 strings extracted)
- AutoIt compiler watermark confirmed
- ICMP strings: `IcmpCreateFile`, `IcmpCloseHandle`, `IcmpSendEcho`
- Privilege tokens: `SeDebugPrivilege`, `SeShutdownPrivilege`
- Screen lock: `SW_LOCK`, `WINSETONTOPP`, `WINMINIMIZEALL`, `WINSETTRANS`
- Registry hives: All 5 major hives referenced
- System recon: Full set of AutoIt env variables (see IOCs)

---

## Phase 4 — Decompilation

**Tool:** Ghidra

### Setup
- New project: `RansomwareAnalysis`
- Binary imported with default analysis settings
- **2,222 functions** identified total

### Entry Point
- Address: `0x004165C1` (.text section)
- Entry calls `__security_init_cookie` → `__tmainCRTStartup`
- `__tmainCRTStartup` references `ADVAPI32.DLL` imports including `CreateProcessWithLogonW` and `LogonUserW`

### Primary Malicious Function
- Identified by sorting Functions window by size (descending)
- `FUN_00437262` — **30,796 bytes** — renamed to `main_malicious_logic`
- Accepts 10 parameters; contains thousands of lines of decompiled code
- Consistent with AutoIt runtime interpreter loop processing script opcodes

### Other Notable Functions
| Function | Size | Role |
|---|---|---|
| `FUN_00404170` | 19,272 bytes | String processing / network handling |
| `FUN_0044cf17` | 12,805 bytes | GUI management / supporting ops |

---

## Phase 5 — Dynamic Debugging

**Tool:** x32dbg with ScyllaHide

### Entry Point Behavior
- Debugger paused at `ntdll.dll` system breakpoint (normal)
- After F9: paused at `0x004CEE90` — malware entry point
- First instruction: **`pushad`** — classic UPX unpacking stub signature

### Runtime Libraries Loaded
```
shell32.dll, ole32.dll, oleaut32.dll, psapi.dll, mpr.dll,
userenv.dll, wininet.dll, winmm.dll, wsock32.dll, ws2_32.dll, imm32.dll
```

### ScyllaHide Hooks Observed
Functions hooked by the malware (confirmed via ScyllaHide log):
```
NtUserBlockInput, NtUserQueryWindow, NtUserGetForegroundWindow,
NtUserBuildHwndList, NtUserFindWindowEx, NtUserGetClassName,
NtUserInternalGetWindowText, NtUserGetThreadState
```

### Breakpoint Results
| Breakpoint | Address | Hits |
|---|---|---|
| `VirtualProtect` | `kernel32.dll` | 0 |
| `CreateWindowExA` | `user32.dll` | 0 |
| `ShowWindow` | `user32.dll` | 0 |

> **Note:** Zero hits on all API breakpoints despite lockscreen deploying successfully. Strong evidence of **direct system calls** or alternative code paths bypassing hooked API entry points.

### Lockscreen Deployment
- Malware successfully deployed lockscreen payload during session
- Desktop turned entirely white; all interaction disabled
- VM restored to clean snapshot immediately after observation

---

## Key Analytical Observations

1. **Packing is the primary evasion mechanism** — the vast majority of meaningful indicators are invisible until unpacking is performed.
2. **AutoIt runtime complexity** — 2,222 functions and 18,885 strings make manual analysis difficult; focus on the largest functions by size.
3. **Anti-debugging is effective** — standard API breakpoints are bypassed. Kernel-level or memory-access breakpoints are recommended for future analysis.
4. **Static + dynamic analysis are complementary** — static reveals capability breadth; dynamic confirms what actually executes.
