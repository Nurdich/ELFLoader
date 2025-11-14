# Makefile for building example object files

CC = gcc
CFLAGS = -c -fPIC -Wall

# Detect architecture
ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
    CFLAGS += -m64
    SUFFIX = x86_64
else ifeq ($(ARCH),i686)
    CFLAGS += -m32
    SUFFIX = x86
else
    SUFFIX = $(ARCH)
endif

all: hello.o

hello.o: hello.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o

.PHONY: all clean
