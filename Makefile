# Linux: make; MinGW: make EXE=.exe CC=gcc LDFLAGS=-static-libgcc
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
EXE     ?=

pktsan$(EXE): pktsan.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ pktsan.c

pktsan-asan: pktsan.c
	$(CC) -g -O1 -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=all -o $@ pktsan.c

test: pktsan pktsan-asan
	python3 test_pktsan.py ./pktsan
	python3 test_pktsan.py ./pktsan-asan

clean:
	rm -f pktsan pktsan.exe pktsan-asan

.PHONY: test clean
