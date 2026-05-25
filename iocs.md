# Indicators of Compromise (IOCs)
## LockScreen Ransomware — AutoIt/UPX Variant

---

## File Indicators

| Indicator | Value |
|---|---|
| File Name | `ransomware.exe` |
| SHA256 (Packed) | `265041a4e943debd8b6b147085cb8549be110facde2288021e90ae65e87be235` |
| MD5 (Packed) | `63bab74409c514ed8548b1f33d0acedc` |
| SHA1 (Packed) | `abc6bb8dd01fa83d7fd92182601b868d2b6dd1ea` |
| SHA256 (Unpacked) | `31C4B3417521624C769440C3A455261128EB9A032E3533EE1ACEF96109987781` |
| File Size (Packed) | 445,231 bytes |
| File Size (Unpacked) | 792,879 bytes |
| Packer | UPX 3.07 |
| Compiler | AutoIt v3 / Microsoft Linker 10.0 |

---

## Network Indicators

| Indicator Type | Value |
|---|---|
| Broadcast IP | `255.255.255.255` |
| Wildcard Bind Address | `0.0.0.0` |
| Protocols | HTTP, FTP, ICMP, Raw Sockets |
| Network Libraries | `wininet.dll`, `wsock32.dll`, `ws2_32.dll`, `icmp.dll` |

### Relevant API Calls (Network)
- `InternetOpenW`, `InternetConnectW`
- `HttpOpenRequestW`, `HttpSendRequestW`, `InternetReadFile`
- `FtpOpenFileW`, `FtpGetFileSize`
- `InternetCrackUrlW`, `InternetOpenUrlW`
- `setsockopt`, `sendto`, `recvfrom`, `select`, `htons`, `ntohs`
- `IcmpCreateFile`, `IcmpSendEcho`, `IcmpCloseHandle`

---

## Registry Indicators

| Registry Hive / Path | Significance |
|---|---|
| `HKEY_LOCAL_MACHINE` | Core system configuration access |
| `HKEY_CURRENT_USER` | Current user settings modification |
| `HKEY_CLASSES_ROOT` | File association and COM object tampering |
| `HKEY_CURRENT_CONFIG` | Hardware configuration access |
| `HKEY_USERS` | All user profiles access |
| `SOFTWARE\Classes\` | COM object registration modification |
| `SOFTWARE\Classes\CLSID\` | COM hijacking for persistence |
| `SYSTEM\CurrentControlSet\Control\Nls\Language` | System language access |
| `Control Panel\Appearance` | Desktop appearance modification |
| `Control Panel\Mouse` | Mouse settings manipulation |

### Registry Value Types Used
`REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`

---

## Behavioral Indicators

| Behavior | Description |
|---|---|
| Screen Locking | Deploys a fullscreen white window; disables all desktop interaction |
| Input Blocking | Disables keyboard and mouse via `NtUserBlockInput` |
| Process Injection | `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` sequence |
| Privilege Escalation | Requests `SeDebugPrivilege` and `SeShutdownPrivilege` |
| System Fingerprinting | Collects username, IP addresses, OS version, CPU arch, keyboard layout |
| Network Reconnaissance | ICMP ping operations via `IcmpSendEcho` |
| Registry Modification | Reads/writes across all major registry hives |
| Mouse Manipulation | Swaps mouse buttons via `SwapMouseButtons` |
| Anti-Debugging | Bypasses API breakpoints through direct system calls |
| Process Creation | Creates processes under alternate credentials via `CreateProcessWithLogonW` |

---

## Privilege Indicators

| Privilege Token | Significance |
|---|---|
| `SeDebugPrivilege` | Enables process injection and memory manipulation across all processes |
| `SeShutdownPrivilege` | Enables forced system shutdown |

---

## Suspicious API Calls (Key)

### Process Injection Sequence
```
OpenProcess → VirtualAllocEx → WriteProcessMemory → ReadProcessMemory
```

### Privilege / Credential Abuse
```
LogonUserW → CreateProcessWithLogonW → LoadUserProfileW
```

### Screen Locking / Input Control
```
NtUserBlockInput → SetWindowPos (HWND_TOPMOST) → ShowWindow → SwapMouseButtons
```

### AutoIt Window Commands (Strings)
```
WINMINIMIZEALL, WINSETONTOPP, WINSETTRANS, WINWAITNOTACTIVE, WINWAITCLOSE, SW_LOCK
```

---

## System Reconnaissance Strings

AutoIt environment variables observed in string analysis:

```
USERNAME, USERDOMAIN, USERDNSDOMAIN, USERPROFILE
IPADDRESS1, IPADDRESS2, IPADDRESS3, IPADDRESS4
OSVERSION, OSBUILD, OSTYPE, OSLANG, OSSERVICEPACK
CPUARCH, PROCESSORARCH, KBLAYOUT
DESKTOPWIDTH, DESKTOPHEIGHT, DESKTOPDEPTH, DESKTOPREFRESH
```
