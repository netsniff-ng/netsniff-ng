#!/bin/bash

# Based on
# https://github.com/cilium/cilium/blob/master/contrib/scripts/extract_authors.sh

function extract_authors() {
	authors=$(git shortlog --summary | awk '{$1=""; print $0}' | sed -e 's/^ //')
	IFS=$'\n'
	for i in $authors; do
		name=$(git log --use-mailmap --author="$i" --format="%aN" | head -1)
		mail=$(git log --use-mailmap --author="$i" --format="%aE" | head -1)
		printf ' * %s <%s>\n' "$name" "$mail"
	done
}

extract_authors | uniq | sort
