#!/bin/bash

all: server client attack

server: server.c
	gcc server.c -o server

client: client.c
	gcc client.c -o client

attack: flush_reload.c invept_reload.c
	gcc flush_reload.c -o flush_reload
	gcc invept_reload.c -o invept_reload

clean:
	rm -rf server client flush_reload invept_reload
