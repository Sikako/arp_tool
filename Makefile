CC = gcc

all: main

main: main.o arp.o 
	$(CC) -o arp main.o arp.o 

main.o: main.c arp.h 
	$(CC) -c main.c

arp.o: arp.c arp.h
	$(CC) -c arp.c


.INTERMEDIATE: main.o arp.o 

clean:
	rm -f *.o main
