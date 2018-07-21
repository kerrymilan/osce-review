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
