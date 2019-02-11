#!/bin/bash

CC := gcc
RM := rm

LIBDIR := /usr/local/lib

CFLAGS := -Wall `libgcrypt-config --cflags`

LIBS := `libgcrypt-config --libs`

INCLUDE := $(HOME)/INV-RELOAD/include

.PHONY: all clean

all: encrypt client attack

encrypt.o: encrypt.c
	$(CC) -c encrypt.c $(CFLAGS) -o encrypt.o -I$(INCLUDE)

encrypt: encrypt.o $(INCLUDE)/gcry.o
	$(CC) -o encrypt encrypt.o $(INCLUDE)/gcry.o $(LIBS) -L$(LIBDIR)

client: client.c
	$(CC) client.c -Wall -o client -I$(INCLUDE)

attack: attack.c
	$(CC) attack.c -Wall -o attack

clean:
	$(RM) -f encrypt client attack encrypt.o cipher.txt
