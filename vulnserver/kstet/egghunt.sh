#!/bin/bash

./encode.sh > egghunt.py
chmod 755 ./egghunt.py

./egghunt.py
./crash.py
