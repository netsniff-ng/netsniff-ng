#!/bin/sh
#
# More stuff: man netsniff-ng
#
#  Replay a pcap file on device wlan0
#

netsniff-ng --replay out.pcap --dev wlan0

