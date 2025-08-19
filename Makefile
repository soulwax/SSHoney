# File: Makefile

.POSIX:

# Compiler and flags
CC       ?= cc
CFLAGS   ?= -std=c99 -Wall -Wextra -Wno-missing-field-initializers -O2
SECURITY_CFLAGS = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
CPPFLAGS ?=
LDFLAGS  ?= -Wl,-z,relro,-z,now -pie
LDLIBS   ?=
PREFIX   ?= /usr/local

# Directories
BINDIR    = $(PREFIX)/bin
MANDIR    = $(PREFIX)/share/man/man1
SYSCONFDIR = /etc
SYSTEMDDIR = /etc/systemd/system

# Build target
TARGET    = sshoney
SOURCE    = sshoney.c
MANPAGE   = sshoney.1

# Version from git or fallback
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "unknown")

# Combined flags
ALL_CFLAGS = $(CFLAGS) $(SECURITY_CFLAGS) -DSSHONEY_VERSION=\"$(VERSION)\"
ALL_LDFLAGS = $(LDFLAGS)

.PHONY: all clean install uninstall install-service uninstall-service docker test

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(ALL_CFLAGS) $(CPPFLAGS) $(ALL_LDFLAGS) -o $@ $(SOURCE) $(LDLIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 $(MANPAGE) $(DESTDIR)$(MANDIR)/
	install -d $(DESTDIR)$(SYSCONFDIR)/sshoney
	install -m 644 config.example $(DESTDIR)$(SYSCONFDIR)/sshoney/

install-service: install
	install -d $(DESTDIR)$(SYSTEMDDIR)
	install -m 644 sshoney.service $(DESTDIR)$(SYSTEMDDIR)/
	# Create sshoney user
	id -u sshoney >/dev/null 2>&1 || useradd -r -s /bin/false -d /var/lib/sshoney sshoney
	# Set capabilities for binding to low ports
	setcap 'cap_net_bind_service=+ep' $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/$(MANPAGE)
	rm -rf $(DESTDIR)$(SYSCONFDIR)/sshoney

uninstall-service: uninstall
	systemctl stop sshoney || true
	systemctl disable sshoney || true
	rm -f $(DESTDIR)$(SYSTEMDDIR)/sshoney.service
	systemctl daemon-reload

docker:
	docker build -t sshoney:$(VERSION) .
	docker tag sshoney:$(VERSION) sshoney:latest

test: $(TARGET)
	./$(TARGET) -h
	./$(TARGET) -V

# Development targets
format:
	clang-format -i $(SOURCE)

lint:
	cppcheck --enable=all --std=c99 $(SOURCE)
	clang-tidy $(SOURCE) -- $(ALL_CFLAGS)

# Static analysis
analyze:
	scan-build $(CC) $(ALL_CFLAGS) $(CPPFLAGS) $(ALL_LDFLAGS) -o $(TARGET) $(SOURCE) $(LDLIBS)