#!/bin/bash

CC := gcc
RM := rm

CFLAGS := `libgcrypt-config --cflags`

LIBS := `libgcrypt-config --libs`

OBJS := client.o

TARGET := client

INCLUDE := ../include

.PHONY: all clean

all: $(TARGET)

client.o: client.c
	$(CC) -c client.c $(CFLAGS) -o client.o -I$(INCLUDE)

client: client.o $(INCLUDE)/gcry.o
	$(CC) -o client client.o $(INCLUDE)/gcry.o $(LIBS)

clean:
	$(RM) -f $(TARGET) $(OBJS)
