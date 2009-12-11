#!/bin/sh
#
# More stuff: man netsniff-ng
#
#  Start sniffing in deamon mode on device eth0 
#  for ICMP messages and print stats to terminal:
#

netsniff-ng -d eth0 -f /etc/netsniff-ng/rules/icmp.bpf -D -P /var/run/netsniff-ng.pid -L /var/log/netsniff-ng.log -S /tmp/netsniff-ng.uds

# do a kill -USR1 <netsniff-ng process id> to bring the current stats to your term

