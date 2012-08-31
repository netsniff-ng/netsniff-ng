#!/usr/bin/env python

# view_rtp_avg.py - A datafile viewer for Mausezahn
# Copyright (C) 2008 Herbert Haas
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as published 
# by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#  
# You should have received a copy of the GNU General Public License along with 
# this program; if not, see http://www.gnu.org/licenses/gpl-2.0.html

from matplotlib import rcParams
from pylab import *
import sys

if size(sys.argv) < 2:  ### no data file given
 print "You must specify a data file as argument!"
 exit()
 
print "Read datafile. Please be patient..."

datfile = open(sys.argv[1],'r');

javg_list = []

for line in datfile.readlines():
    if len(line)>1:
        words = line.split(" ")
        if words[0]!='#':
          javg = line.split(", ");
          javg_list.append(float(javg[4])/1000) # [x] means xth column (columns 0,1,..)
          #### column 2 is jitter, column 4 is RFC 3550 jitter
 
datfile.close()

print "Data imported. Now calculating statistics..."

# Erase statistical exceptions
                    
javg_list_ordered = sort(javg_list)

s = size(javg_list_ordered);
s=int(s*0.95) ## assume that at maximum 5% of the data are exceptions

print "Will remove exceptional data points. A total of %d packets will be processed." % (s, )
## the histogram of the data
n, bins, patches = hist(javg_list_ordered[1:s], 100, normed=False)

## add a 'best fit' line
#y = normpdf( bins, mu, sigma)
#l = plot(bins, y, 'r--', linewidth=2)
#xlim(40, 160)

xlabel('Jitter (msec)')
ylabel('Number of Packets')
title("Average Jitter Probability")
#title(r'$\rm{IQ:}\/ \mu=100,\/ \sigma=15$')
####suptitle("Mausezahn Viewer (Avg RTP Jitter)")
show()
