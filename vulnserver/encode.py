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
