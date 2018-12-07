#!/bin/bash

CC := gcc
RM := rm

DEFAULT := $(HOME)/INV-RELOAD

LIBDIR := /usr/local/lib

CFLAGS := -Wall `libgcrypt-config --cflags`

LIBS := `libgcrypt-config --libs`

OBJS := client.o

INCLUDE := $(DEFAULT)/include

.PHONY: all clean

all: client attack

client.o: client.c
	$(CC) -c client.c $(CFLAGS) -o client.o -I$(INCLUDE)

client: client.o $(INCLUDE)/gcry.o
	$(CC) -o client client.o $(INCLUDE)/gcry.o $(LIBS) -L$(LIBDIR)

attack: attack.c
	$(CC) attack.c -Wall -g -o attack

clean:
	$(RM) -f client attack $(OBJS)
