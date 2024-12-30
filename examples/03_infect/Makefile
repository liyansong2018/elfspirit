CC=gcc
CXX=g++

all: hello.bin shellcode.bin

hello.bin: hello.c
	$(CC) $^ -o $@

shellcode.bin: shellcode.c
	$(CC) -Wl,-T script.ld -fno-stack-protector -nostdlib -nodefaultlibs -fPIC -Wl,-shared $^ -o $@

run: all
	unset LD_LIBRARY_PATH
	LD_LIBRARY_PATH=. ./hello.bin

.PHONY: clean
clean:
	rm -rf *.bin