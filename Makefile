CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -D_FILE_OFFSET_BITS=64
LDLIBS  += -lcrypto

TARGET := wavcrypt

.PHONY: all clean test

all: $(TARGET)

$(TARGET): wavcrypt.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

test: $(TARGET)
	bash smoke_test.sh

clean:
	rm -f $(TARGET)
