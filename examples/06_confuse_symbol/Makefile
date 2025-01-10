CC=gcc
CXX=g++

all: main.bin check.so

main.bin: main.c check.so
	$(CC) -Wl,-rpath,./ $^ -o $@

check.so: check.c
	$(CC) -shared $^ -o $@

run: all
	./main.bin

.PHONY: clean
clean:
	rm -rf *.so *.bin