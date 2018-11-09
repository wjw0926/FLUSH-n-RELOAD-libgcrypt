#!/bin/bash

CC := gcc
RM := rm

CFLAGS := `libgcrypt-config --cflags`

LIBS := `libgcrypt-config --libs`

OBJS := server.o gcry.o

TARGET := server

.PHONY: all clean

all: $(TARGET)

gcry.o: gcry.c
	$(CC) -c gcry.c $(CFLAGS) -o gcry.o -I.

server.o: server.c
	$(CC) -c server.c $(CFLAGS) -o server.o -I.

client.o: client.c
	$(CC) -c client.c $(CFLAGS) -o client.o -I.

client: client.o gcry.o
	$(CC) -o client client.o gcry.o $(LIBS)

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LIBS)

clean:
	$(RM) -f $(TARGET) client $(OBJS) client.o rsa.sp
