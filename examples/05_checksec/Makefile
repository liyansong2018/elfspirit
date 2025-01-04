CC=gcc
CXX=g++

all: main

main: main.c
	$(CC) $^ -fstack-protector-all -z now -o $@

run: all
	./main

.PHONY: clean
clean:
	rm -rf main