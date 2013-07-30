bpfc-libs =

bpfc-objs =	xmalloc.o \
		str.o \
		bpf.o \
		bpf_lexer.yy.o \
		bpf_parser.tab.o \
		bpfc.o

bpfc-lex =	bpf_lexer.yy.o

bpfc-yaac =	bpf_parser.tab.o

bpfc-eflags =	-I..

bpfc-confs =

bpfc_clean_custom:
	$(Q)$(call RM,$(BUILD_DIR)/*.h $(BUILD_DIR)/*.c)
