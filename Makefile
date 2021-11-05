CC:=gcc
CFLAGS:=
PHONY:=

all: tracer tracee

tracer: tracer.o
	$(CC) tracer.o -o tracer $(CFLAGS) -lpthread

tracee: tracee.o
	$(CC) tracee.o -o tracee $(CFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

PHONY += clean
clean:
	@rm -f *.o tracer tracee

.PHONY:= $(PHONY)
