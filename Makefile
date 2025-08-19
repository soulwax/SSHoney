# File: Makefile

.POSIX:
CC       = cc
CFLAGS   = -std=c99 -Wall -Wextra -Wno-missing-field-initializers -Os
CPPFLAGS =
LDFLAGS  = -ggdb3
LDLIBS   =
PREFIX   = /usr/local

all: sshoney

sshoney: sshoney.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) -o $@ sshoney.c $(LDLIBS)

install: sshoney
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 sshoney $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	install -m 644 sshoney.1 $(DESTDIR)$(PREFIX)/share/man/man1/

clean:
	rm -rf sshoney
