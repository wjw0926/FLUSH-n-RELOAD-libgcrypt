#!/bin/bash

CC := gcc
RM := rm

LIBDIR := /usr/local/lib

CFLAGS := -Wall `libgcrypt-config --cflags`

LIBS := `libgcrypt-config --libs`

OBJS := server.o keygen.o

INCLUDE := $(HOME)/INV-RELOAD/include

.PHONY: all clean

all: server keygen

server.o: server.c
	$(CC) -c server.c $(CFLAGS) -o server.o -I$(INCLUDE)

keygen.o: keygen.c
	$(CC) -c keygen.c $(CFLAGS) -o keygen.o -I$(INCLUDE)

server: server.o $(INCLUDE)/gcry.o
	$(CC) -o server server.o $(INCLUDE)/gcry.o $(LIBS) -L$(LIBDIR)

keygen: keygen.o $(INCLUDE)/gcry.o
	$(CC) -o keygen keygen.o $(INCLUDE)/gcry.o $(LIBS) -L$(LIBDIR)

clean:
	$(RM) -f server keygen $(OBJS)
