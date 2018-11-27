#!/bin/bash

CC := gcc
RM := rm
CFLAGS := -Wall -g

OBJS := attack.o asm.o

.PHONY: all clean

all: attack

asm.o: asm.c
	$(CC) $(CFLAGS) -c asm.c -o asm.o

attack.o: attack.c
	$(CC) $(CFLAGS) -c attack.c -o attack.o

attack: attack.o asm.o
	$(CC) $(CFLAGS) -o attack attack.o asm.o

clean:
	$(RM) -f attack $(OBJS)
