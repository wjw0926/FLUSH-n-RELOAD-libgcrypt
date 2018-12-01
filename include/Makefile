#!/bin/bash

CC := gcc
RM := rm

CFLAGS := -Wall `libgcrypt-config --cflags`

LIBS := `libgcrypt-config --libs`

OBJS := gcry.o

.PHONY: all clean

all: gcry.o

gcry.o: gcry.c
	$(CC) -c gcry.c $(CFLAGS) -o gcry.o -I.

clean:
	$(RM) -f $(OBJS)
