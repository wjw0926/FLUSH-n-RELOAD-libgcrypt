#!/bin/bash

CC := gcc
RM := rm

.PHONY: all clean

all: page_access

page_access: page_access.c
	$(CC) -o page_access page_access.c

clean:
	$(RM) -f page_access
