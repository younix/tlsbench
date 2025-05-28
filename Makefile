CFLAGS=-Wall -Wextra
LDFLAGS=-ltls -lssl -lcrypto

all: tlsbench
clean:
	rm -f tlsbench
