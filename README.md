# REVERSE-ENGINEERING-AND-ANALYSIS-OF-MALICIOUS-BINARY-EXECUTABLES
# Reverse Engineering and Analysis of a Malicious Binary Executable

**Author:** Damoah Bashiru  
**Date:** March 2026  

---

## Overview

This repository contains the full reverse engineering analysis of a LockScreen ransomware sample (`ransomware.exe`) compiled using the **AutoIt v3** scripting language and protected with **UPX packing**. The analysis was conducted entirely within an isolated Windows 10 virtual machine using industry-standard tools.

The sample was confirmed malicious by **57 out of 72 security vendors** on VirusTotal, with a threat label of `trojan.lockscreen/autoit`.

---

## Repository Structure

```
lockscreen-ransomware-analysis/
├── report/                  # Full academic report (PDF)
├── iocs/                    # Extracted Indicators of Compromise
├── tools/                   # Tool configuration notes and commands used
├── notes/                   # Analysis notes and methodology
├── screenshots/             # Tool screenshots referenced in the report
└── README.md
```

---

## Malware Sample Declaration

> The actual malware binary is included in the repository also analysis artifacts, hashes, and documentation are shared for educational and threat intelligence purposes.
nb pasword for malware is "infected"
> precaustion: Should be execuited in a safe environment
| Property | Value |
|---|---|
| File Name | `ransomware.exe` |
| SHA256 (Packed) | `265041a4e943debd8b6b147085cb8549be110facde2288021e90ae65e87be235` |
| MD5 (Packed) | `63bab74409c514ed8548b1f33d0acedc` |
| SHA1 (Packed) | `abc6bb8dd01fa83d7fd92182601b868d2b6dd1ea` |
| SHA256 (Unpacked) | `31C4B3417521624C769440C3A455261128EB9A032E3533EE1ACEF96109987781` |
| File Size (Packed) | 445,231 bytes |
| File Size (Unpacked) | 792,879 bytes |
| Packer | UPX version 3.07 |
| Compiler | AutoIt v3 Script / Microsoft Linker 10.0 |
| Malware Family | LockScreen Ransomware (AutoIt) |
| VirusTotal Detection | 57 / 72 |

---

## Tools Used

| Tool | Purpose |
|---|---|
| **PEStudio** | Static binary analysis — PE header, imports, strings |
| **Ghidra** | Decompilation and function-level code analysis |
| **x32dbg** | Dynamic debugging and runtime inspection |
| **UPX** | Unpacking the compressed binary |
| **ScyllaHide** | Anti-anti-debug plugin for x32dbg |

---

## Key Findings

### Binary Structure
- 32-bit PE executable with entropy of **7.875** — confirming UPX compression
- Only **21 visible imports** in packed form; expanded to **513 imports** (156 flagged) after unpacking
- Compilation timestamp: January 29, 2012 — suggesting redistribution of an older sample

### Capabilities Identified

| Capability | Evidence |
|---|---|
| **Screen Locking** | `SW_LOCK`, `WINSETONTOPP`, `WINMINIMIZEALL`, `NtUserBlockInput` |
| **System Reconnaissance** | `USERNAME`, `IPADDRESS1-4`, `OSVERSION`, `CPUARCH`, `KBLAYOUT` |
| **Privilege Escalation** | `SeDebugPrivilege`, `SeShutdownPrivilege` |
| **Process Injection** | `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `ReadProcessMemory` |
| **Network Communication** | HTTP, FTP, ICMP, raw sockets via WinINet + Winsock |
| **Registry Manipulation** | All 5 major hives + COM object registration paths |
| **Anti-Debugging** | Bypasses API breakpoints via direct system calls |

---

## Indicators of Compromise (IOCs)

See the [`/iocs`](./iocs/) folder for the full structured IOC list. Summary:

- **File:** Hash values for both packed and unpacked variants
- **Network:** `255.255.255.255` broadcast, HTTP/FTP/ICMP/raw socket protocols
- **Registry:** All major hives, `SOFTWARE\Classes\`, `CLSID` paths
- **Privileges:** `SeDebugPrivilege`, `SeShutdownPrivilege`
- **Behavioral:** Fullscreen lockscreen, input blocking, process injection, ICMP ping sweeps

---

## Methodology

The analysis followed a structured static + dynamic approach:

1. **Static Analysis** — PEStudio examination of PE header, imports, and strings (packed binary)
2. **UPX Unpacking** — Decompression to reveal full import table and embedded strings
3. **Decompilation** — Ghidra analysis identifying 2,222 functions; primary malicious function (`FUN_00437262`) at 30,796 bytes
4. **Dynamic Debugging** — x32dbg runtime inspection confirming lockscreen deployment and anti-debugging evasion

---

## Recommendations

**For defenders:**
- Alert on AutoIt binaries with high entropy or UPX section markers
- Treat `SeDebugPrivilege` / `SeShutdownPrivilege` in process tokens as suspicious
- Monitor for ICMP sweeps, outbound FTP, and unknown HTTP endpoints
- Watch `SOFTWARE\Classes\` and COM object registry paths for persistence

**For analysts:**
- Unpack before deeper analysis — most indicators are in the compressed payload
- Use kernel-level or memory-access breakpoints; this sample bypasses API-level hooks
- Combine static and dynamic analysis — neither alone gives the full picture

---

## Disclaimer

This project is purely for **academic and educational purposes**. The malware binary is not distributed. All analysis was conducted in an isolated virtual machine environment with no risk to host systems or networks.

---
