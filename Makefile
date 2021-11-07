CC:=gcc
CFLAGS:=-O3
PHONY:=

TESTS_ENABLED:=1
TEST_TARGETS:=

TEST_OUTDIR:=test
TEST_SRCDIR:=test
TEST_TARGETS:=$(TEST_OUTDIR)/tracee
TEST_CLEAN_TARGETS:=$(TEST_OUTDIR)/tracee $(TEST_OUTDIR)/tracee.o

ifeq ($(V),1)
	Q:=
else
	Q:=@
endif

all: bintrace $(TEST_TARGETS)

bintrace: bintrace.o
	$(Q)$(CC) bintrace.o -o bintrace $(CFLAGS) -lpthread
	@echo 'CC $<'

%.o: %.c
	$(Q)$(CC) -c $< -o $@ $(CFLAGS)
	@echo 'CC $<'

# Tests
ifeq ($(TESTS_ENABLED),1)
$(TEST_OUTDIR)/tracee: $(TEST_OUTDIR)/tracee.o
	$(Q)$(CC) $< -o $@ -O0 -g3
	@echo 'CC $<'

$(TEST_OUTDIR)/tracee.o: $(TEST_SRCDIR)/tracee.c
	$(Q)$(CC) $< -c -o $@ -O0 -g3
	@echo 'CC $<'

runtest:
	$(Q)cd test && ./test.py
endif

PHONY += clean
clean:
	$(Q)rm -f *.o bintrace $(TEST_CLEAN_TARGETS)

.PHONY:= $(PHONY)
