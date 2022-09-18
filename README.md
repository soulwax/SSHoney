# SSHoney: an SSH tarpit

SSHoney is an SSH tarpit [that _very_ slowly sends an endless, random
SSH banner][np]. It keeps SSH clients locked up for hours or even days
at a time. The purpose is to put your real SSH server on another port
and then let the script kiddies get stuck in this tarpit instead of
bothering a real server.

Since the tarpit is in the banner before any cryptographic exchange
occurs, this program doesn't depend on any cryptographic libraries. It's
a simple, single-threaded, standalone C program. It uses `poll()` to
trap multiple clients at a time.

## Usage

Usage information is printed with `-h`.

```
Usage: sshoney [-vhs] [-d MS] [-f CONFIG] [-l LEN] [-m LIMIT] [-p PORT]
  -4        Bind to IPv4 only
  -6        Bind to IPv6 only
  -d INT    Message millisecond delay [10000]
  -f        Set and load config file [/etc/sshoney/config]
  -h        Print this help message and exit
  -l INT    Maximum banner line length (3-255) [32]
  -m INT    Maximum number of clients [4096]
  -p INT    Listening port [2222]
  -s        Print diagnostics to syslog instead of standard output
  -v        Print diagnostics (repeatable)
```

Argument order matters. The configuration file is loaded when the `-f`
argument is processed, so only the options that follow will override the
configuration file.

By default no log messages are produced. The first `-v` enables basic
logging and a second `-v` enables debugging logging (noisy). All log
messages are sent to standard output by default. `-s` causes them to be
sent to syslog.

    sshoney -v >sshoney.log 2>sshoney.err

A SIGTERM signal will gracefully shut down the daemon, allowing it to
write a complete, consistent log.

A SIGHUP signal requests a reload of the configuration file (`-f`).

A SIGUSR1 signal will print connections stats to the log.

## Sample Configuration File

The configuration file has similar syntax to OpenSSH.

```
# The port on which to listen for new SSH connections.
Port 2222

# The endless banner is sent one line at a time. This is the delay
# in milliseconds between individual lines.
Delay 10000

# The length of each line is randomized. This controls the maximum
# length of each line. Shorter lines may keep clients on for longer if
# they give up after a certain number of bytes.
MaxLineLength 32

# Maximum number of connections to accept at a time. Connections beyond
# this are not immediately rejected, but will wait in the queue.
MaxClients 4096

# Set the detail level for the log.
#   0 = Quiet
#   1 = Standard, useful log messages
#   2 = Very noisy debugging information
LogLevel 0

# Set the family of the listening socket
#   0 = Use IPv4 Mapped IPv6 (Both v4 and v6, default)
#   4 = Use IPv4 only
#   6 = Use IPv6 only
BindFamily 0
```

## Build issues

Some more esoteric systems require extra configuration when building.

### RHEL 6 / CentOS 6

This system uses a version of glibc older than 2.17 (December 2012), and
`clock_gettime(2)` is still in librt. For these systems you will need to
link against librt:

    make LDLIBS=-lrt

### Solaris / illumos

These systems don't include all the necessary functionality in libc and
the linker requires some extra libraries:

    make CC=gcc LDLIBS='-lnsl -lrt -lsocket'

If you're not using GCC or Clang, also override `CFLAGS` and `LDFLAGS`
to remove GCC-specific options. For example, on Solaris:

    make CFLAGS=-fast LDFLAGS= LDLIBS='-lnsl -lrt -lsocket'

The feature test macros on these systems isn't reliable, so you may also
need to use `-D__EXTENSIONS__` in `CFLAGS`.

### OpenBSD

The man page needs to go into a different path for OpenBSD's `man` command:

```
diff --git a/Makefile b/Makefile
index 119347a..dedf69d 100644
--- a/Makefile
+++ b/Makefile
@@ -14,8 +14,8 @@ sshoney: sshoney.c
 install: sshoney
        install -d $(DESTDIR)$(PREFIX)/bin
        install -m 755 sshoney $(DESTDIR)$(PREFIX)/bin/
-       install -d $(DESTDIR)$(PREFIX)/share/man/man1
-       install -m 644 sshoney.1 $(DESTDIR)$(PREFIX)/share/man/man1/
+       install -d $(DESTDIR)$(PREFIX)/man/man1
+       install -m 644 sshoney.1 $(DESTDIR)$(PREFIX)/man/man1/

 clean:
        rm -rf sshoney
```

[np]: https://nullprogram.com/blog/2019/03/22/

# Tutorial:

## 1. Preparation

`sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak`
`sudo nano /etc/ssh/sshd_config`
`Port 2222 (example)`
`sudo ufw allow 2222/tcp`
`sudo systemctl restart sshd`

In a separate terminal session, attempt to connect to your server using the new port:
`ssh username@your_server_ip -p 2222`

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Warning: Do not close your active SSH session unless
you have confirmed you can use SSH on the new port.
If you can’t connect through the new port, you risk
losing access to your server by closing the session.
If you cannot connect to your server in a separate terminal
session, you can restore your original SSH settings
by running the following commands:
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
sudo systemctl restart sshd
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

Once verified the new port works, you can close your original terminal safely.

## 2. Installing SSHoney

`git clone --recursive https://github.com/soulwax/sshoney`
`cd sshoney`
`make`
`sudo apt install build-essential libc6-dev`
Start ssh now:
`sudo ./sshoney -v -p 22`

To test that SSHoney is working, you can attempt to make an SSH connection
to port 22 with the -v verbose flag, which will show the endless banner
being transmitted.
In a new terminal window, make an SSH connection to
the port 22 with either of the following commands:
`ssh username@your_server_ip -v`
`ssh username@your_server_ip -p 22 -v`

## 3. Configuring SShoney

`sudo mv ./sshoney /usr/local/bin/`
`sudo cp util/sshoney.service /etc/systemd/system/`

You will change the service file slightly to run SSHoney on ports under 1024.
Open the service file in nano or your favourite text editor:

`sudo nano /etc/systemd/system/sshoney.service`

Update the file by removing # at the beginning of the line with
`AmbientCapabilities=CAP_NET_BIND_SERVICE`
and adding # to the beginning of the line
`PrivateUsers=true`
like so:

```
## If you want SSHoney to bind on ports < 1024
## 1) run:
##     setcap 'cap_net_bind_service=+ep' /usr/local/bin/sshoney
## 2) uncomment following line
AmbientCapabilities=CAP_NET_BIND_SERVICE
## 3) comment following line
#PrivateUsers=true
```

Save and exit the file.

Next, you will allow SSHoney to run on ports lower than 1024,
also referred to as internet domain privileged ports.
Set this capability for the SSHoney binary with the setcap command:

`sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/sshoney`

You will need to define a config file for SSHoney to tell it
which port to use. Create and open a config file named /etc/sshoney/config

`sudo mkdir /etc/sshoney`
`sudo nano /etc/sshoney/config`
Only content you need to put in is: `Port 22`, save and exit.

Finally:

`sudo systemctl --now enable sshoney`

Including `--now enable` will make the service _persist_
after rebooting your server.
To check that the service started successfully,
you can use the systemctl status command:

`sudo systemctl status sshoney`

If started successfully, you will see an output like this:

```
● sshoney.service - SSHoney SSH Tarpit
Loaded: loaded (/etc/systemd/system/sshoney.service; enabled; vendor preset: enabled)
Active: active (running) since Sun 2022-09-18 18:55:39 CEST; 8s ago
Docs: man:sshoney(1)
Main PID: 4203 (sshoney)
Tasks: 1 (limit: 19118)
Memory: 428.0K
CPU: 70ms
CGroup: /system.slice/sshoney.service
└─4203 /usr/local/bin/sshoney
```

If it is running, you can attempt to connect on port 22 in a new terminal session:

`ssh username@your_server_ip`

Because your tarpit is running, the new terminal session will not
be able to connect and will run in perpetuity
until stopped manually with Ctrl+C in the connecting terminal.
░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄░░░░░░░
░░░░░█░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░▀▀▄░░░░
░░░░█░░░▒▒▒▒▒▒░░░░░░░░▒▒▒░░█░░░
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█░░
░▄▀▒▄▄▄▒░█▀▀▀▀▄▄█░░░██▄▄█░░░░█░
█░▒█▒▄░▀▄▄▄▀░░░░░░░░█░░░▒▒▒▒▒░█
█░▒█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄▒█
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█░
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█░░
░░░█░░░░██░░▀█▄▄▄█▄▄█▄████░█░░░
░░░░█░░░░▀▀▄░█░░░█░█▀██████░█░░
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█░░
░░░░░░░▀▄▄░▒▒▒▒░░░░░░░░░░▒░░░█░
░░░░░░░░░░▀▀▄▄░▒▒▒▒▒▒▒▒▒▒░░░░█░
░░░░░░░░░░░░░░▀▄▄▄▄▄░░░░░░░░█░░
If you wish to stop the service from running, you can use the following command:

`sudo systemctl --now disable sshoney`

## Conclusion

You have successfully installed and configured SSHoney, helped clear up your authentication logs, and prepared to waste the time of random SSH bots.

After setting up your SSHoney tarpit, review other measures on how to protect your servers. Friendly example: [Recommended Measures to Protect Your Servers](https://www.digitalocean.com/community/tutorials/recommended-security-measures-to-protect-your-servers)
