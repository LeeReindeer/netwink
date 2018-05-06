PREFIX?=/usr/local
CFLAGS=-g -Wall
LIBS=-levent
cc=gcc
all: 
		 cc $(CFLAGS) -c -o input.o input.c
		 cc $(CFLAGS) netwink.c input.o  -o netwink


install: all
	install -d $(DESTDIR)/$(PREFIX)/bin/
	install netwink $(DESTDIR)/$(PREFIX)/bin/

clean:
	rm -f netwink
	rm -f *.o