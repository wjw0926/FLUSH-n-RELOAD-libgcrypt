#!/bin/bash

for i in `seq 1 1000`
do
    ./run.sh 100 $i
    sleep .1
done

tar -cvf result-100.tar result-100-*.txt
