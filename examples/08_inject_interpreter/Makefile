CC=gcc
CXX=g++

all: hello.bin

hello.bin: hello.c
	$(CC) $^ -o $@

run: all
	./hello.bin

.PHONY: clean
clean:
	rm -rf *.bin