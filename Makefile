CFLAGS += -Wall -Wextra
LDFLAGS += -ltls -lssl -lcrypto

all: tlsbench

tlsbench: tlsbench.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f tlsbench
