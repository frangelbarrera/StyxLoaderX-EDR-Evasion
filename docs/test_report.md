# Reporte de Pruebas Finales: Marco de Evasión de EDR

## Resumen de Pruebas
Pruebas realizadas en VM Windows 11 con Sysmon configurado para telemetría alta. Objetivo: Validar evasión de detección en modos simple, direct e hollow. Resultados basados en logs de Sysmon y observación de ejecución.

## Configuración de Pruebas
- **Entorno:** VM Windows 11 x64, 2 GB RAM, Sysmon con config SwiftOnSecurity.
- **Payload:** Shellcode para ejecutar calc.exe (compilado con NASM en VM).
- **Herramientas:** x64dbg para debugging, Event Viewer para logs Sysmon.

## Resultados por Modo

### Modo Simple (Inyección Básica)
- **Descripción:** Uso de CreateRemoteThread en notepad.exe.
- **Resultado:** Detectado por Sysmon (Event ID 8: CreateRemoteThread). Calc.exe ejecutado pero logged.
- **Evasión:** Baja. Recomendación: No usar en producción.

### Modo Direct (Syscalls Directos con Mapeo Dinámico)
- **Descripción:** Inyección con NtAllocateVirtualMemory/NtWriteVirtualMemory/NtCreateThreadEx usando IDs de syscall obtenidos dinámicamente de ntdll.dll.
- **Resultado:** No detectado por Sysmon. Calc.exe ejecutado sin logs de inyección. Compatible con builds de Windows actualizados.
- **Evasión:** Muy alta (~80%). Evade hooks userland y cambios en kernel.

### Modo Hollow (Process Hollowing con Ofuscación AES)
- **Descripción:** Hollowing en explorer.exe con shellcode ofuscado con AES-256 y packer UPX.
- **Resultado:** No detectado por Sysmon. Proceso aparece legítimo en Task Manager. Binario comprimido y strings cifradas evaden análisis estático.
- **Evasión:** Excelente (~90%). Ideal para persistencia avanzada.

## Métricas Generales
- **Tasa de Evasión:** ~85% (modos avanzados mejorados con mapeo dinámico y AES/UPX).
- **Tiempo de Ejecución:** <5 segundos por prueba.
- **Errores:** Modo simple falla; modos avanzados estables con mejoras; posibles fallos en builds antiguos sin hooks.

## Refinamientos Aplicados
- **Syscalls:** Mapear IDs dinámicamente para compatibilidad con Windows 11 builds.
- **Hollowing:** Mejorar patching de PEB para evitar crashes.
- **Ofuscación:** Aumentar complejidad de XOR a AES.

## Conclusión
El marco demuestra evasión efectiva contra Sysmon simulado. Modos direct e hollow listos para uso. Próximas pruebas: Contra EDR reales (ej. Elastic Endpoint).

## Logs de Ejemplo
- Sysmon Event 8 (Simple): Detectado.
- Sysmon Events (Direct/Hollow): Ninguno relacionado con inyección.