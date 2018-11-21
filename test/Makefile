#!/bin/bash

CC := gcc
RM := rm

OBJS := attack.o asm.o

.PHONY: all clean

all: attack

asm.o: asm.c
	$(CC) -c asm.c -o asm.o

attack.o: attack.c
	$(CC) -c attack.c -o attack.o

attack: attack.o asm.o
	$(CC) -o attack attack.o asm.o

clean:
	$(RM) -f attack $(OBJS)
