# Configuración del Laboratorio

Este documento detalla la configuración del entorno de laboratorio para el proyecto de Marco de Evasión de EDR.

## Requisitos Previos
- ISO de Windows 11 (ya descargada).
- VirtualBox (ya descargado).
- VS Code (ya descargado).
- Conexión a internet para descargas menores (~100 MB total).

## Pasos de Configuración
1. **Crear VM en VirtualBox:**
   - Nombre: Win11Lab
   - Tipo: Microsoft Windows, Versión: Windows 11 (64-bit)
   - RAM: 2048 MB
   - Disco: 20 GB, VDI, Dinámicamente asignado
   - Habilitar VT-x/AMD-V si disponible.

2. **Instalar Windows 11:**
   - Montar ISO y iniciar VM.
   - Configurar idioma, teclado.
   - Crear usuario: labuser (sin contraseña para simplicidad en lab).
   - Desactivar actualizaciones automáticas: Configuración > Windows Update > Pausar actualizaciones.

3. **Instalar Herramientas:**
   - **Sysmon:** Descargar de https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon. Ejecutar con config de alta telemetría (buscar "SwiftOnSecurity sysmon config").
   - **NASM:** Descargar de https://www.nasm.us/. Instalar.
   - **x64dbg:** Descargar de https://x64dbg.com/. Instalar.

4. **Configurar VS Code:**
   - Instalar extensiones: C/C++ (ms-vscode.cpptools), Python (ms-python.python).

## Verificación
- Iniciar VM y verificar que Sysmon registre eventos básicos.
- Compilar un "Hello World" en C++ para confirmar herramientas.

Estado: Pendiente de ejecución en PC con más RAM.