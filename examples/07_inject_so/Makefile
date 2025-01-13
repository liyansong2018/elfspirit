CC=gcc
CXX=g++

all: crackme.bin check.so my.so

crackme.bin: crackme.c check.so
	$(CC) -Wl,-rpath,./ $^ -o $@

check.so: check.c
	$(CC) -shared $^ -o $@

my.so: my.c
	$(CC) -shared $^ -o $@

run: all
	./crackme.bin

.PHONY: clean
clean:
	rm -rf *.so *.bin