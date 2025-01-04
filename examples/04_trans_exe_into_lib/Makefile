CC=gcc
CXX=g++

all: crackme.bin harness.bin

crackme.bin: crackme.c
	$(CC) -Wl,-strip-all $^ -o $@

harness.bin: harness.c
	$(CC) $^ -o $@

.PHONY: clean
clean:
	rm -rf *.bin