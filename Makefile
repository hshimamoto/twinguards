CC = gcc
CFLAGS = -g -O2 -Wall

all: twinguards

twinguards: twinguards.c
	$(CC) $(CFLAGS) -o $@ twinguards.c

clean:
	rm -f twinguards
