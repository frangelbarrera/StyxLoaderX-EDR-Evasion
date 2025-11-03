; Shellcode básico para ejecutar calc.exe en Windows x64
; Compilar con: nasm -f bin shellcode.asm -o shellcode.bin

BITS 64

section .text

global _start

_start:
    ; Llamar a WinExec para ejecutar calc.exe
    ; WinExec("calc.exe", SW_SHOW)
    mov rcx, calc_str  ; lpCmdLine
    mov rdx, 5         ; uCmdShow (SW_SHOW)
    mov rax, 0x7C8623AD  ; Dirección de WinExec (puede variar, usar GetProcAddress en loader real)
    call rax

    ; Salir
    xor rax, rax
    ret

calc_str db "calc.exe", 0