#!/usr/bin/python

# Copyright 2008 Marcus D. Hanwell <marcus@cryos.org>
# Copyright 2010 Daniel Borkmann <daniel@netsniff-ng.org>

# Distributed under the terms of the GNU General Public License v2 or later.

import string, re, os

fin = os.popen('git log --summary --stat --no-merges --date=short', 'r')
fout = open('CHANGELOG', 'w')

authorFound = False
dateFound = False
messageFound = False
changesFound = False
message = ""
changes = ""
messageNL = False
prevAuthorLine = ""

for line in fin:
	if string.find(line, 'commit') >= 0:
		authorFound = False
		dateFound = False
		messageFound = False
		changesFound = False
		messageNL = False
		message = ""
		continue
	elif re.match('Author:', line) >=0:
		authorList = re.split(': ', line, 1)
		author = authorList[1]
		author = author[0:len(author)-1]
		authorFound = True
	elif re.match('Date:', line) >= 0:
		dateList = re.split(':   ', line, 1)
		date = dateList[1]
		date = date[0:len(date)-1]
		dateFound = True
	elif re.match('\s+git-svn-id:', line) >= 0:
		continue
	elif re.search('Signed-off-by', line) >= 0:
		continue
	elif re.search('.+files changed.+insertions.+deletions.+', line) \
	     >= 0:
		changes = "\n            :" + line[:-1]
		changesFound = True
	elif authorFound & dateFound & messageFound == False:
		if len(line) == 1:
			if messageNL:
				messageFound = True
			else:
				messageNL = True
		elif len(line) == 4:
			messageFound = True
		else:
			if len(message) == 0:
				message = message + line.strip()
			else:
				message = message + " " + line.strip()
	elif authorFound & dateFound & messageFound:
		authorLine = date + "  " + author + changes
		if len(prevAuthorLine) == 0:
			fout.write(authorLine + "\n\n")
		elif authorLine == prevAuthorLine:
			pass
		else:
			fout.write("\n" + authorLine + "\n\n")
		commitLine = message
		i = 0
		first = False
		commit = "  * "
		while i < len(commitLine):
			if len(commitLine) < i + 72:
				commit = commit +                        \
					 commitLine[i:len(commitLine)] + \
					 "\n    "
				break
			index = commitLine.rfind(' ', i, i + 72)
			if index > i:
				commit = commit + commitLine[i:index] + \
					 "\n    "
				i = index + 1
			else:
				commit = commit + commitLine[i:72] + \
					 "\n    "
				i = i + 73
		commit = commit[:-5]
		fout.write(commit + "\n")
		authorFound = False
		dateFound = False
		messageFound = False
		changesFound = False
		messageNL = False
		message = ""
		prevAuthorLine = authorLine

fin.close()
fout.close()
