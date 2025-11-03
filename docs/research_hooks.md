# Investigación sobre Userland Hooking

Este documento resume la investigación sobre cómo los EDR implementan userland hooks en Windows, basada en documentación y ejemplos de GitHub/repositorios como klezVirus/inceptor y referencias a "Bypassing Userland EDR Hooks".

## ¿Qué es Userland Hooking?
Los EDR (Endpoint Detection and Response) inyectan una DLL en procesos objetivo (usando técnicas como APC o thread hijacking). Esta DLL modifica las primeras instrucciones de funciones clave en ntdll.dll y kernel32.dll (ej. NtWriteVirtualMemory, CreateRemoteThread) para insertar un "salto" (JMP) a su propio código de monitoreo. Esto permite interceptar llamadas a APIs de Windows y detectar comportamientos maliciosos como inyección de código.

- **Mecanismo:** La DLL hookea funciones reemplazando los primeros bytes con un JMP a una función trampoline que registra la llamada y luego ejecuta el código original.
- **Detección:** Los hooks están en la capa de API de usuario (userland), no en el kernel, lo que los hace vulnerables a evasión.

## Cómo Evadirlo
- **Syscalls Directos:** Llamar directamente al kernel (ntoskrnl.exe) usando syscalls (ej. NtAllocateVirtualMemory) en lugar de pasar por las APIs hookeadas. Los hooks solo afectan las funciones de ntdll.dll.
- **Syscalls Indirectos:** Usar la pila para transiciones legítimas, complicando el análisis de llamadas.
- **Herramientas para Investigación:** x64dbg para inspeccionar memoria y disassembly; Process Explorer para ver DLLs inyectadas.

## Hallazgos Iniciales
- En Windows 10/11 x64, syscalls usan el número de syscall (ej. 0x18 para NtAllocateVirtualMemory) obtenido dinámicamente.
- Ejemplos en GitHub muestran cómo mapear syscalls y llamar con ASM inline.
- Riesgo: Syscalls varían por build de Windows; usar tablas dinámicas.

Próximo: Implementar módulo DirectSyscall.cpp basado en esto.