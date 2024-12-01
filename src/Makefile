TARGET=elfspirit
OUT=/usr/local/bin/
CFLAGS = -w -c

ifeq ($(debug), true)
	CXXFLAGS=-g -fsanitize=address
	CXXFLAGS+=-Ddebug
else
	CXXFLAGS=-O3
endif

$(TARGET) : addsec.o injectso.o main.o common.o cJSON/cJSON.o delsec.o delshtab.o parse.o addelfinfo.o joinelf.o edit.o segment.o section.o
	$(CC) $(CXXFLAGS) addsec.o injectso.o main.o common.o cJSON/cJSON.o delsec.o delshtab.o parse.o addelfinfo.o joinelf.o edit.o segment.o section.o -o $(TARGET)
%.o: %.c
	$(CC) $(CFLAGS) $(CXXFLAGS) $< -o $@

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