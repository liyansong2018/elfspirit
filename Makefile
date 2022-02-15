CFLAGS = -w -c
DEBUG = -g
SANIT = -fsanitize=address
elfspirit : addsec.o injectso.o main.o common.o cJSON/cJSON.o delsec.o delshtab.o parse.o
	$(CC) $(DEBUG) addsec.o injectso.o main.o common.o cJSON/cJSON.o delsec.o delshtab.o parse.o -o elfspirit
%.o: %.c
	$(CC) $(CFLAGS) $(DEBUG) $< -o $@

.PHONY: clean
clean:
	rm -rvf *.o
	rm -rvf cJSON/*.o
	rm -vf elfspirit