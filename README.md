# SSHoney: Enhanced SSH Tarpit

SSHoney is an SSH tarpit [that _very_ slowly sends an endless, random SSH banner][np]. It keeps SSH clients locked up for hours or even days at a time. The purpose is to put your real SSH server on another port and then let the script kiddies get stuck in this tarpit instead of bothering a real server.

Since the tarpit is in the banner before any cryptographic exchange occurs, this program doesn't depend on any cryptographic libraries. It's a simple, single-threaded, standalone C program. It uses `poll()` to trap multiple clients at a time.

## Version 1.2 Enhancements

- **Improved Random Number Generation**: Uses PCG-based RNG for better randomness and more realistic SSH banners
- **Enhanced Statistics**: Track peak connections, average connection times, and detailed metrics via SIGUSR1
- **Dynamic Delay Management**: Randomized delays between configurable min/max values
- **Throttling Support**: Automatically slows down clients with full buffers
- **Better Performance**: Optimized socket options (TCP_NODELAY, SO_KEEPALIVE, SO_REUSEPORT)
- **Realistic SSH Banners**: Generates convincing fake SSH version strings from popular SSH implementations

## Usage

Usage information is printed with `-h`.

```
Usage: sshoney [OPTIONS]
Options:
  -4              Bind to IPv4 only
  -6              Bind to IPv6 only
  -d DELAY        Message delay in ms [10000]
  -f CONFIG       Configuration file [/etc/sshoney/config]
  -h              Show this help
  -l LENGTH       Max banner line length [64]
  -m CLIENTS      Max concurrent clients [8192]
  -p PORT         Listening port [2222]
  -s              Log to syslog
  -v              Verbose logging (repeat for debug)
  -V              Show version
```

Argument order matters. The configuration file is loaded when the `-f` argument is processed, so only the options that follow will override the configuration file.

By default no log messages are produced. The first `-v` enables basic logging and a second `-v` enables debugging logging (noisy). All log messages are sent to standard output by default. `-s` causes them to be sent to syslog.

    sshoney -v >sshoney.log 2>&1

### Signal Handling

- **SIGTERM/SIGINT**: Gracefully shut down the daemon, allowing it to write complete statistics
- **SIGHUP**: Request a configuration reload (currently logs the request)
- **SIGUSR1**: Print detailed connection statistics to the log

### Statistics Output

When sending SIGUSR1, SSHoney now provides enhanced statistics:

```
STATS uptime=3600s connects=142 disconnects=89 active=53 peak=67 bytes=1048576 avg_time=24532ms
```

## Sample Configuration File

The configuration file has similar syntax to OpenSSH. The enhanced version supports additional options:

```
# The port on which to listen for new SSH connections.
Port 2222

# The endless banner is sent one line at a time. This is the delay
# in milliseconds between individual lines.
Delay 10000

# Minimum and maximum delay for randomized timing (milliseconds)
MinDelay 5000
MaxDelay 15000

# Enable randomized delays between min and max values
RandomizeDelay yes

# The length of each line is randomized. This controls the maximum
# length of each line. Shorter lines may keep clients on for longer if
# they give up after a certain number of bytes.
MaxLineLength 64

# Maximum number of connections to accept at a time. Connections beyond
# this are not immediately rejected, but will wait in the queue.
MaxClients 8192

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

# Enable TCP_NODELAY for more immediate sending (default: yes)
TcpNodelay yes

# Size of receive buffer to set for each client (bytes)
RecvBufferSize 1
```

## Performance Characteristics

SSHoney v1.2 has been optimized for handling large numbers of concurrent connections:

- **Memory Usage**: ~100 bytes per connection
- **CPU Usage**: Minimal, uses efficient polling
- **Network**: Sends ~3-6 bytes/second per connection
- **Capacity**: Tested with 10,000+ simultaneous connections

The enhanced random banner generation creates more convincing SSH signatures that may keep attackers engaged longer:

- Mimics popular SSH implementations (OpenSSH, PuTTY, libssh, Cisco, paramiko)
- Generates realistic version numbers
- Varies timing to avoid detection patterns

## Build Instructions

Standard build:

```bash
make
sudo make install
```

### Platform-Specific Notes

#### RHEL 6 / CentOS 6

Older glibc requires linking against librt:

```bash
make LDLIBS=-lrt
```

#### Solaris / illumos

Requires additional libraries:

```bash
make CC=gcc LDLIBS='-lnsl -lrt -lsocket'
```

#### OpenBSD

For dual-stack (IPv4 and IPv6), run two instances due to platform limitations. See `util/openbsd/README.md` for details.

## Installation Tutorial

### 1. Preparation

First, move your real SSH server to a different port:

```bash
# Backup current SSH configuration
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Edit SSH configuration
sudo nano /etc/ssh/sshd_config
# Change: Port 2222 (or another port of your choice)

# Update firewall
sudo ufw allow 2222/tcp

# Restart SSH
sudo systemctl restart sshd
```

**⚠️ WARNING**: Before proceeding, verify you can connect on the new port:

```bash
ssh username@your_server_ip -p 2222
```

### 2. Installing SSHoney

```bash
# Clone repository
git clone https://github.com/soulwax/sshoney
cd sshoney

# Install build dependencies
sudo apt install build-essential

# Build
make

# Test run
sudo ./sshoney -v -p 22
```

### 3. Configuring as a Service

```bash
# Install binary
sudo mv ./sshoney /usr/local/bin/

# Install service file
sudo cp util/sshoney.service /etc/systemd/system/

# Configure for privileged ports
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/sshoney

# Create configuration
sudo mkdir /etc/sshoney
echo "Port 22" | sudo tee /etc/sshoney/config

# Enable and start service
sudo systemctl --now enable sshoney
```

### 4. Monitoring

View logs:

```bash
# If using systemd
sudo journalctl -u sshoney -f

# Get statistics
sudo kill -USR1 $(pgrep sshoney)
```

Monitor active connections:

```bash
# Watch connection count
watch -n 1 'sudo journalctl -u sshoney | grep ACCEPT | tail -20'
```

## Docker Deployment

Build and run with Docker:

```bash
docker build -t sshoney .
docker run -d --name sshoney -p 22:2222 sshoney -v
```

Or using docker-compose:

```yaml
version: '3'
services:
  sshoney:
    build: .
    ports:
      - "22:2222"
    restart: unless-stopped
    command: ["-v", "-m", "10000"]
```

## Security Considerations

- SSHoney creates no security vulnerabilities as it never performs authentication
- No cryptographic operations are performed
- Minimal resource usage prevents DoS attacks
- Consider rate limiting at the firewall level for additional protection

## Contributing

SSHoney is released into the public domain. Feel free to fork, modify, and redistribute as needed.

## References

- [Original blog post about SSH tarpits][np]
- [SSH RFC 4253](https://tools.ietf.org/html/rfc4253)

[np]: https://nullprogram.com/blog/2019/03/22/

## Conclusion

SSHoney is an effective tool for wasting attackers' time and resources. The v1.2 enhancements make it even more convincing and efficient, capable of handling thousands of simultaneous connections while using minimal server resources. After installation, watch your logs fill with trapped bots while your real SSH server remains secure on an alternate port.
