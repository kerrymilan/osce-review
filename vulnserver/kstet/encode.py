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
