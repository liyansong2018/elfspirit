TARGET=elfspirit
OUT=/usr/local/bin/
CFLAGS = -w -c
DEBUG = -g -fsanitize=address
$(TARGET) : addsec.o injectso.o main.o common.o cJSON/cJSON.o delsec.o delshtab.o parse.o addelfinfo.o joinelf.o
	$(CC) $(DEBUG) addsec.o injectso.o main.o common.o cJSON/cJSON.o delsec.o delshtab.o parse.o addelfinfo.o joinelf.o -o $(TARGET)
%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	rm -rvf *.o
	rm -rvf cJSON/*.o
	rm -vf $(TARGET)

.PHONY: install
install:$(TARGET)
	@echo "begin install "$(TARGET)
	cp $(TARGET) $(OUT)
	@echo $(TARGET) "install success!"