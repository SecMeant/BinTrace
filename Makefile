CC:=gcc
CFLAGS:=-O3
PHONY:=

TESTS_ENABLED:=1
TEST_TARGETS:=

TEST_OUTDIR:=test
TEST_SRCDIR:=test
TEST_TARGETS:=$(TEST_OUTDIR)/tracee
TEST_CLEAN_TARGETS:=$(TEST_OUTDIR)/tracee $(TEST_OUTDIR)/tracee.o

all: tracer $(TEST_TARGETS)

tracer: tracer.o
	$(CC) tracer.o -o tracer $(CFLAGS) -lpthread

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

# Tests
ifeq ($(TESTS_ENABLED),1)
$(TEST_OUTDIR)/tracee: $(TEST_OUTDIR)/tracee.o
	$(CC) $< -o $@ -O0 -g3

$(TEST_OUTDIR)/tracee.o: $(TEST_SRCDIR)/tracee.c
	$(CC) $< -c -o $@ -O0 -g3

runtest:
	cd test && tests.py
endif

PHONY += clean
clean:
	@rm -f *.o tracer $(TEST_CLEAN_TARGETS)

.PHONY:= $(PHONY)