TARGET=elfspirit
OUT=/usr/local/bin/
SRCS = $(wildcard *.c cJSON/cJSON.c)
OBJS = $(SRCS:.c=.o)
CFLAGS = -w -c

ifeq ($(debug), true)
	CXXFLAGS=-g -fsanitize=address
	CXXFLAGS+=-Ddebug
else
	CXXFLAGS=-O3
endif

$(TARGET) : $(OBJS)
	$(CC) $(CXXFLAGS) $(OBJS) -o $(TARGET)
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