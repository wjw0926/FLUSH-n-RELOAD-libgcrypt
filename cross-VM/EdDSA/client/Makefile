#!/bin/bash

CC := gcc
RM := rm

LIBDIR := /usr/local/lib

INCLUDE := $(HOME)/INV-RELOAD/include

CFLAGS := -Wall `libgcrypt-config --cflags`

LIBS := `libgcrypt-config --libs`

OBJS := client.o

.PHONY: all clean

all: client attack

client.o: client.c
	$(CC) -c client.c $(CFLAGS) -o client.o -I$(INCLUDE)

client: client.o $(INCLUDE)/gcry.o
	$(CC) -o client client.o $(INCLUDE)/gcry.o $(LIBS) -L$(LIBDIR)

attack: attack.c
	$(CC) attack.c -Wall -o attack

clean:
	$(RM) -f client attack $(OBJS)
