tools = netsniff-ng trafgen curvetun ifpps ashunt bpfc

all:
	@for tool in $(tools) ; do \
	echo "Building $$tool ..."; \
	cd $$tool; $(MAKE) $(MFLAGS); cd ..; \
	done

clean:
	@for tool in $(tools) ; do \
	echo "Cleaning $$tool ..."; \
	cd $$tool; $(MAKE) $(MFLAGS) clean; cd ..; \
	done

install:
	@for tool in $(tools) ; do \
	echo "Intalling $$tool ..."; \
	cd $$tool; $(MAKE) $(MFLAGS) install; cd ..; \
	done

uninstall:
	@for tool in $(tools) ; do \
	echo "Uninstalling $$tool ..."; \
	cd $$tool; $(MAKE) $(MFLAGS) uninstall; cd ..; \
	done

