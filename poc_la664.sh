#!/bin/sh

for i in $(seq 1 1000); do
    printf "testtest%08d\n" "$i"
done > /tmp/file

sh -c "while true; do
    numactl -C 1 sort < /tmp/file > /dev/null
done" &

./run.sh
