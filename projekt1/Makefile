CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -o3
LIBS=-lelf

all: ian-proj1

ian-proj1: ian-proj1.o
	$(CC) $(CFLAGS) -o ian-proj1 ian-proj1.o $(LIBS)

ian-proj1.o: ian-proj1.c
	$(CC) $(CFLAGS) -c ian-proj1.c -o ian-proj1.o $(LIBS)

clean:
	rm ian-proj1.o ian-proj1
