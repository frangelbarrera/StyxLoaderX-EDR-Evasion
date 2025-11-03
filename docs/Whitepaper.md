# Whitepaper: Marco de Evasión de Detección de Endpoints (EDR)

## Resumen Ejecutivo
Este whitepaper detalla el desarrollo de un marco avanzado para evasión de detección de EDR en sistemas Windows x64. El marco implementa técnicas ofensivas modernas como syscalls directos/indirectos, process hollowing, ofuscación de cadenas y evasión de sandboxes, permitiendo la ejecución de payloads maliciosos sin detección por soluciones de seguridad userland.

## Introducción
Los EDR modernos utilizan userland hooks para monitorear llamadas a APIs de Windows. Este marco evade estas defensas mediante manipulación de memoria y llamadas directas al kernel, demostrando dominio en ciberseguridad ofensiva.

## Técnicas Implementadas

### 1. Evasión de Userland Hooks
- **Syscalls Directos:** Llamadas directas a funciones del kernel (ej. NtAllocateVirtualMemory) evitando APIs hookeadas en ntdll.dll.
- **Syscalls Indirectos:** Uso de pila para transiciones legítimas, complicando análisis de EDR.

### 2. Manipulación de Memoria
- **Process Hollowing:** Creación de proceso legítimo suspendido, desasignación de memoria original, inyección de payload y reanudación. El proceso aparece normal en la tabla de procesos.
- **Ofuscación de Cadenas:** Cifrado XOR de nombres sensibles (DLLs, funciones) en compile-time, descifrado en runtime.
- **Evasión de Sandbox:** Detección de entornos de análisis mediante checks de hardware, tiempo y procesos.

## Arquitectura del Marco
- **Estructura Modular:** Carpeta `modules/` con componentes intercambiables (syscalls, hollowing, etc.).
- **Loader Principal:** `MainLoader.cpp` selecciona técnicas dinámicamente (simple, direct, hollow).
- **Shellcode:** Código Assembly básico para ejecución arbitraria.

## Resultados de Pruebas
- **Entorno de Prueba:** VM Windows 11 con Sysmon configurado para alta telemetría.
- **Evasión Exitosa:** Payloads ejecutados sin logs de inyección en Sysmon.
- **Limitaciones:** Dependiente de build de Windows; requiere refinamiento para EDR avanzados.

## Conclusión
Este marco proporciona una base sólida para investigación en evasión de EDR, con aplicaciones en pentesting ético. Código disponible en repositorio privado; uso solo educativo.

## Referencias
- Documento base: "Plan_de_Acción_Detallado_Marco_de_Evasión_de_Detección_de_Endpoints_(EDR).docx"
- Proyectos similares: klezVirus/inceptor, thomasxm/BOAZ
- Recursos: Microsoft WinAPI, "Bypassing Userland EDR Hooks"