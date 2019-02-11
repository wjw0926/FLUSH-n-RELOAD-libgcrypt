#!/bin/bash

CC := gcc
RM := rm

CFLAGS := -Wall -g

.PHONY: all clean

all: attack

attack: attack.c
	$(CC) $(CFLAGS) attack.c -o attack

clean:
	$(RM) -f attack text.txt.gpg
