CC=gcc
CXX=g++

all: crackme.bin myfunc.bin

crackme.bin: crackme.c
	$(CC) -z lazy $^ -o $@

myfunc.bin: myfunc.c
	$(CC) -Wl,-T script.ld -fno-stack-protector -nostdlib -nodefaultlibs -fPIC -Wl,-shared $^ -o $@

.PHONY: clean
clean:
	rm -rf *.bin