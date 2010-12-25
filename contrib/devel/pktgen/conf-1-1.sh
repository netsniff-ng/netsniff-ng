#!/bin/bash

modprobe pktgen
echo "pktgen module loaded"

function pgset() {
	local result
	echo $1 > $PGDEV
	result=`cat $PGDEV | fgrep "Result: OK:"`
	if [ "$result" = "" ]; then
		cat $PGDEV | fgrep Result:
	fi
}

function pg() {
	echo inject > $PGDEV
	cat $PGDEV
}

# Config Start Here
PGDEV=/proc/net/pktgen/kpktgend_0
echo "Removing all devices"
pgset "rem_device_all"
echo "Adding eth1"
pgset "add_device eth1"
echo "Setting max_before_softirq 10000"
pgset "max_before_softirq 10000"

# device config
CLONE_SKB="clone_skb 1000000"
# NIC adds 4 bytes CRC
PKT_SIZE="pkt_size 1400"
# COUNT 0 means forever
COUNT="count 0"
#COUNT="count 10000000"
# delay 0 means maximum speed.
DELAY="delay 0"

PGDEV=/proc/net/pktgen/eth1
echo "Configuring $PGDEV"
pgset "$COUNT"
pgset "$CLONE_SKB"
pgset "$PKT_SIZE"
pgset "$DELAY"
pgset "dst 10.10.10.1"
pgset "dst_mac 00:09:FA:10:E2:F7"

# Time to run
PGDEV=/proc/net/pktgen/pgctrl

echo "Running... ctrl^C to stop"
pgset "start"
echo "Done"

# Result can be vieved in /proc/net/pktgen/eth1

