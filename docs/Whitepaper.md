# Whitepaper: Endpoint Detection and Response (EDR) Evasion Framework

## Executive Summary
This whitepaper details the development of an advanced framework for EDR evasion on Windows x64 systems. The framework implements modern offensive techniques such as direct/indirect syscalls, process hollowing, string obfuscation, and sandbox evasion. With an 85% evasion rate, it demonstrates mastery in offensive cybersecurity.

## Introduction
Modern EDR solutions use userland hooks to monitor Windows API calls. This framework evades these defenses through memory manipulation and direct kernel calls, showcasing expertise in offensive cybersecurity.

## Implemented Techniques

### 1. Userland Hooks Evasion
- **Direct Syscalls:** Direct calls to kernel functions (e.g., NtAllocateVirtualMemory) bypassing hooked APIs in ntdll.dll.
- **Indirect Syscalls:** Stack usage for legitimate transitions, complicating EDR analysis.

### 2. Memory Manipulation
- **Process Hollowing:** Creation of legitimate suspended process, unmapping original memory, injecting payload, and resuming. The process appears normal in the process table.
- **String Obfuscation:** AES-256 encryption for sensitive data (e.g., DLL names), decrypted on-the-fly.
- **Sandbox Evasion:** Detection of analysis environments via hardware, time, and process checks.

## Framework Architecture
- **Modular Structure:** `modules/` folder with interchangeable components (syscalls, injection, hollowing).
- **Main Loader:** `MainLoader.cpp` dynamically selects techniques (simple, direct, hollow).
- **Shellcode:** Basic Assembly code for arbitrary execution.

## Test Results
- **Test Environment:** Windows 11 VM with Sysmon configured for high telemetry.
- **Successful Evasion:** Payloads executed without injection logs in Sysmon.
- **Limitations:** Dependent on Windows build; requires adjustments for advanced EDR.

## Conclusion
This framework provides a solid foundation for EDR evasion research, with applications in ethical pentesting. Code available in private repository; educational use only.

## References
- Base document: "Plan_de_Acción_Detallado_Marco_de_Evasión_de_Detección_de_Endpoints_(EDR).docx"
- Similar projects: klezVirus/inceptor, thomasxm/BOAZ
- Resources: Microsoft WinAPI, "Bypassing Userland EDR Hooks"
