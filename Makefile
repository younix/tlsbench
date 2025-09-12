CFLAGS += -Wall -Wextra -Wno-pointer-sign
LDFLAGS += -ltls -lssl -lcrypto
BINDIR ?= /usr/local/bin
MANDIR ?= /usr/local/man/man

.PHONY: all clean install
all: tlsbench

tlsbench: tlsbench.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f tlsbench

install:
	install -m 555 tlsbench ${DESTDIR}${BINDIR}
	install -m 444 tlsbench.1 ${DESTDIR}${MANDIR}1
