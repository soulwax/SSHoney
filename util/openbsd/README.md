# Running `sshoney` on OpenBSD

## Covering IPv4 and IPv6

If you want to cover both IPv4 and IPv6 you'll need to run _two_ instances of
`sshoney` due to OpenBSD limitations. Here's how I did it:

- copy the `sshoney` script to `rc.d` twice, as `sshoney` and `sshoney6`
- copy the `config` file to `/etc/sshoney` twice, as `config` and `config6`
  - use `BindFamily 4` in `config`
  - use `BindFamily 6` in `config6`
- in `rc.conf.local` force `sshoney6` to load `config6` like so:

```
sshoney6_flags=-s -f /etc/sshoney/config6
sshoney_flags=-s
```

## Covering more than 128 connections

The defaults in OpenBSD only allow for 128 open file descriptors per process,
so regardless of the `MaxClients` setting in `/etc/config` you'll end up with
something like 124 clients at the most.
You can increase these limits in `/etc/login.conf` for `sshoney` (and
`sshoney6`) like so:

```
sshoney:\
	:openfiles=1024:\
	:tc=daemon:
sshoney6:\
	:openfiles=1024:\
	:tc=daemon:
```
