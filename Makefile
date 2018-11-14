#!/bin/bash

CC := gcc
RM := rm

CFLAGS := `libgcrypt-config --cflags`

LIBS := `libgcrypt-config --libs`

OBJS := server.o client.o keygen.o gcry.o 

TARGET := server client keygen gcry

.PHONY: all clean

all: server client keygen

gcry.o: gcry.c
	$(CC) -c gcry.c $(CFLAGS) -o gcry.o -I.

server.o: server.c
	$(CC) -c server.c $(CFLAGS) -o server.o -I.

client.o: client.c
	$(CC) -c client.c $(CFLAGS) -o client.o -I.

keygen.o: keygen.c
	$(CC) -c keygen.c $(CFLAGS) -o keygen.o -I.

server: server.o gcry.o
	$(CC) -o server server.o gcry.o $(LIBS)

client: client.o gcry.o
	$(CC) -o client client.o gcry.o $(LIBS)

keygen: keygen.o gcry.o
	$(CC) -o keygen keygen.o gcry.o $(LIBS)

clean:
	$(RM) -f $(TARGET) $(OBJS) rsa.sp
