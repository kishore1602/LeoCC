#!/bin/bash
DIR="/home/nuwins/zach/LeoCC/LeoCC/leoreplayer/replayer/traces/static_traces_20260207/1770506564594-0500/downlink"
DEV=ingress

tcpdump -i $DEV -s 66 -w $DIR/n1.pcap &
CAP=$!

iperf3 -c 100.64.0.1 -C $2 -t $1 -R

kill $CAP
