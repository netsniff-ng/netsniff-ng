#
# Makefile for manpages
# Author: Daniel Borkmann
#

include ../src/definitions.mk

A2X_FLAGS += -d manpage 
A2X_MAN   += -f manpage
A2X_PDF   += -f pdf
A2X_HTML  += -f xhtml

netsniff-ng-objs = netsniff-ng.8
ifpps-objs       = ifpps.8

all: clean build
build: netsniff-ng ifpps

netsniff-ng: $(netsniff-ng-objs)
	@$(foreach page, $(netsniff-ng-objs), cat man/$(page) | \
	gzip --best > man/$(page).gz;)

ifpps-ng: $(ifpps-ng-objs)
	@$(foreach page, $(ifpps-ng-objs), cat man/$(page) | \
	gzip --best > man/$(page).gz;)

%.8: %.txt
	@echo -n 'MAN '
	@install -d man
	@$(A2X_NORM) $(A2X_FLAGS) $(A2X_MAN) $<
	@mv $(basename $<).8 man/
	@echo -n 'PDF '
	@install -d pdf
	@$(A2X_NORM) $(A2X_FLAGS) $(A2X_PDF) $<
	@mv $(basename $<).pdf pdf/
	@# Dirty Hack!
	@echo -n 'HTM '
	@install -d html
	@$(A2X_NORM) $(A2X_FLAGS) $(A2X_HTML) $<
	@rm *.css
	@cat extra/header.txt > $(basename $<).out
	@cat $(basename $<).html | sed -n                \
	'1h;1!H;$${g;s/.*<body>\(.*\)<\/body>.*/\1/g;p}' \
	>> $(basename $<).out
	@cat extra/footer.txt >> $(basename $<).out
	@rm $(basename $<).html
	@mv $(basename $<).out html/$(basename $<).html

clean:
	@rm -rf man/ pdf/ html/ *~ > /dev/null 2>&1 || true
