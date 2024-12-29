CC=gcc
CXX=g++

all: main.bin hello.so

main.bin: main.c hello.so
	$(CC) $^ -o $@

hello.so: hello.c
	$(CC) -shared $^ -o $@

run: all
	unset LD_LIBRARY_PATH
	LD_LIBRARY_PATH=. ./main.bin

.PHONY: clean
clean:
	rm -rf *.so *.bin