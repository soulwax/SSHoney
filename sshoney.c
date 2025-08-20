/* SSHONEY: Enhanced SSH tarpit
 *
 * This is free and unencumbered software released into the public domain.
 */
#if defined(__OpenBSD__)
#define _BSD_SOURCE /* for pledge(2) and unveil(2) */
#else
#define _XOPEN_SOURCE 700
#endif

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <syslog.h>

#define SSHONEY_VERSION 1.2

#define DEFAULT_PORT 2222
#define DEFAULT_DELAY 10000 /* milliseconds */
#define DEFAULT_MAX_LINE_LENGTH 64
#define DEFAULT_MAX_CLIENTS 8192
#define DEFAULT_MIN_DELAY 5000
#define DEFAULT_MAX_DELAY 15000

#if defined(__FreeBSD__)
#define DEFAULT_CONFIG_FILE "/usr/local/etc/sshoney.config"
#else
#define DEFAULT_CONFIG_FILE "/etc/sshoney/config"
#endif

#define DEFAULT_BIND_FAMILY AF_UNSPEC
#define BANNER_BUFFER_SIZE 512
#define CLIENT_BUFFER_SIZE 1024

#define XSTR(s) STR(s)
#define STR(s) #s

/* Enhanced random number generator state */
struct rng_state {
    uint64_t state;
    uint64_t stream;
};

/* Statistics tracking */
struct stats {
    uint64_t connects;
    uint64_t disconnects;
    uint64_t bytes_sent;
    uint64_t total_time_ms;
    uint64_t peak_clients;
    time_t start_time;
};

/* Client connection structure with enhanced tracking */
struct client {
    char ipaddr[INET6_ADDRSTRLEN];
    uint64_t connect_time;
    uint64_t send_next;
    uint64_t bytes_sent;
    uint32_t lines_sent;
    struct client *next;
    int port;
    int fd;
    bool throttled;
};

/* Enhanced configuration structure */
struct config {
    int port;
    int delay;
    int min_delay;
    int max_delay;
    int max_line_length;
    int max_clients;
    int bind_family;
    bool randomize_delay;
    bool tcp_nodelay;
    int recv_buffer_size;
};

/* Log levels */
enum loglevel {
    LOG_NONE,
    LOG_INFO,
    LOG_DEBUG
};

/* Global state */
static enum loglevel g_loglevel = LOG_NONE;
static void (*g_logfunc)(enum loglevel level, const char *, ...);
static struct stats g_stats = {0};
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload = 0;
static volatile sig_atomic_t g_dumpstats = 0;

/* Enhanced time functions */
static uint64_t get_time_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

static uint64_t get_realtime_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL;
}

/* Enhanced PCG random number generator */
static void rng_init(struct rng_state *rng, uint64_t seed) {
    rng->state = seed;
    rng->stream = 0xda3e39cb94b95bdbULL;
}

static uint32_t rng_next(struct rng_state *rng) {
    uint64_t oldstate = rng->state;
    rng->state = oldstate * 6364136223846793005ULL + (rng->stream | 1);
    uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    uint32_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
}

/* Logging functions */
static void log_stdio(enum loglevel level, const char *format, ...) {
    if (g_loglevel < level) return;
    
    int saved_errno = errno;
    uint64_t now = get_realtime_ms();
    time_t t = now / 1000;
    
    char timestamp[64];
    struct tm tm;
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", gmtime_r(&t, &tm));
    printf("%s.%03lluZ ", timestamp, now % 1000);
    
    va_list ap;
    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
    
    errno = saved_errno;
}

static void log_syslog(enum loglevel level, const char *format, ...) {
    static const int prio_map[] = {LOG_NOTICE, LOG_INFO, LOG_DEBUG};
    
    if (g_loglevel < level) return;
    
    int saved_errno = errno;
    char buffer[512];
    
    va_list ap;
    va_start(ap, format);
    vsnprintf(buffer, sizeof(buffer), format, ap);
    va_end(ap);
    
    syslog(prio_map[level], "%s", buffer);
    errno = saved_errno;
}

/* Enhanced banner generation */
static int generate_banner_line(char *buffer, int max_len, struct rng_state *rng) {
    int len = 8 + (rng_next(rng) % (max_len - 10));
    
    /* Generate more realistic SSH-like banner content */
    const char *prefixes[] = {
        "SSH-2.0-OpenSSH_", "SSH-2.0-libssh_", "SSH-1.99-Cisco_",
        "SSH-2.0-PuTTY_", "SSH-2.0-WinSCP_", "SSH-2.0-paramiko_"
    };
    
    int prefix_idx = rng_next(rng) % (sizeof(prefixes) / sizeof(prefixes[0]));
    int prefix_len = snprintf(buffer, max_len - 2, "%s%d.%d", 
                             prefixes[prefix_idx],
                             rng_next(rng) % 9 + 1,
                             rng_next(rng) % 10);
    
    /* Fill remaining space with random characters */
    for (int i = prefix_len; i < len - 2; i++) {
        buffer[i] = 32 + (rng_next(rng) % 95);
    }
    
    buffer[len - 2] = '\r';
    buffer[len - 1] = '\n';
    
    /* Ensure we don't accidentally create valid SSH banners */
    if (memcmp(buffer, "SSH-2.0-OpenSSH", 15) == 0) {
        buffer[0] = 'X';
    }
    
    return len;
}

/* Client management */
static struct client *client_create(int fd, uint64_t send_next) {
    struct client *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    
    c->fd = fd;
    c->connect_time = get_time_ms();
    c->send_next = send_next;
    
    /* Set optimal socket options */
    int value = 1;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &value, sizeof(value));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));
    
    /* Extract peer information */
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *)&addr, &len) == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&addr;
            c->port = ntohs(s->sin_port);
            inet_ntop(AF_INET, &s->sin_addr, c->ipaddr, sizeof(c->ipaddr));
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
            c->port = ntohs(s->sin6_port);
            inet_ntop(AF_INET6, &s->sin6_addr, c->ipaddr, sizeof(c->ipaddr));
        }
    }
    
    return c;
}

static void client_destroy(struct client *client) {
    if (!client) return;
    
    uint64_t duration = get_time_ms() - client->connect_time;
    
    g_logfunc(LOG_INFO, 
             "CLOSE host=%s port=%d fd=%d time=%llu.%03llu bytes=%llu lines=%u",
             client->ipaddr, client->port, client->fd,
             duration / 1000, duration % 1000,
             client->bytes_sent, client->lines_sent);
    
    g_stats.disconnects++;
    g_stats.total_time_ms += duration;
    
    close(client->fd);
    free(client);
}

/* FIFO queue for client management */
struct client_queue {
    struct client *head;
    struct client *tail;
    int count;
};

static void queue_init(struct client_queue *q) {
    memset(q, 0, sizeof(*q));
}

static void queue_push(struct client_queue *q, struct client *client) {
    client->next = NULL;
    if (q->tail) {
        q->tail->next = client;
    } else {
        q->head = client;
    }
    q->tail = client;
    q->count++;
    
    if (g_stats.peak_clients < q->count) {
        g_stats.peak_clients = q->count;
    }
}

static struct client *queue_pop(struct client_queue *q) {
    if (!q->head) return NULL;
    
    struct client *client = q->head;
    q->head = client->next;
    if (!q->head) q->tail = NULL;
    client->next = NULL;
    q->count--;
    
    return client;
}

static void queue_destroy(struct client_queue *q) {
    while (q->head) {
        struct client *client = queue_pop(q);
        client_destroy(client);
    }
}

/* Configuration management */
#define CONFIG_DEFAULT { \
    .port = DEFAULT_PORT, \
    .delay = DEFAULT_DELAY, \
    .min_delay = DEFAULT_MIN_DELAY, \
    .max_delay = DEFAULT_MAX_DELAY, \
    .max_line_length = DEFAULT_MAX_LINE_LENGTH, \
    .max_clients = DEFAULT_MAX_CLIENTS, \
    .bind_family = DEFAULT_BIND_FAMILY, \
    .randomize_delay = true, \
    .tcp_nodelay = true, \
    .recv_buffer_size = 1 \
}

/* Signal handlers */
static void signal_term(int sig) {
    (void)sig;
    g_running = 0;
}

static void signal_hup(int sig) {
    (void)sig;
    g_reload = 1;
}

static void signal_usr1(int sig) {
    (void)sig;
    g_dumpstats = 1;
}

/* Statistics reporting */
static void log_statistics(struct client_queue *queue) {
    uint64_t uptime = time(NULL) - g_stats.start_time;
    uint64_t active_time = g_stats.total_time_ms;
    
    /* Add time for currently connected clients */
    uint64_t now = get_time_ms();
    for (struct client *c = queue->head; c; c = c->next) {
        active_time += now - c->connect_time;
    }
    
    g_logfunc(LOG_INFO, 
             "STATS uptime=%llus connects=%llu disconnects=%llu "
             "active=%d peak=%llu bytes=%llu avg_time=%llums",
             uptime, g_stats.connects, g_stats.disconnects,
             queue->count, g_stats.peak_clients, g_stats.bytes_sent,
             g_stats.disconnects ? g_stats.total_time_ms / g_stats.disconnects : 0);
}

/* Enhanced server creation with better error handling */
static int create_server(const struct config *cfg) {
    int fd = socket(cfg->bind_family == AF_UNSPEC ? AF_INET6 : cfg->bind_family, 
                   SOCK_STREAM, 0);
    if (fd == -1) {
        g_logfunc(LOG_INFO, "socket() failed: %s", strerror(errno));
        return -1;
    }
    
    /* Set socket options */
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    
#ifndef __OpenBSD__
    if (cfg->bind_family == AF_INET6 || cfg->bind_family == AF_UNSPEC) {
        opt = (cfg->bind_family == AF_INET6);
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
    }
#endif
    
    /* Bind to address */
    if (cfg->bind_family == AF_INET) {
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(cfg->port),
            .sin_addr.s_addr = INADDR_ANY
        };
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            g_logfunc(LOG_INFO, "bind() failed: %s", strerror(errno));
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in6 addr = {
            .sin6_family = AF_INET6,
            .sin6_port = htons(cfg->port),
            .sin6_addr = in6addr_any
        };
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            g_logfunc(LOG_INFO, "bind() failed: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }
    
    if (listen(fd, SOMAXCONN) == -1) {
        g_logfunc(LOG_INFO, "listen() failed: %s", strerror(errno));
        close(fd);
        return -1;
    }
    
    g_logfunc(LOG_INFO, "Server listening on port %d", cfg->port);
    return fd;
}

/* Enhanced line sending with throttling */
static struct client *send_line(struct client *client, const struct config *cfg, 
                               struct rng_state *rng) {
    char buffer[BANNER_BUFFER_SIZE];
    int len = generate_banner_line(buffer, cfg->max_line_length, rng);
    
    ssize_t sent = write(client->fd, buffer, len);
    g_logfunc(LOG_DEBUG, "write(%d, %d) = %zd", client->fd, len, sent);
    
    if (sent == -1) {
        if (errno == EINTR) {
            return client; /* Try again later */
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            client->throttled = true;
            return client; /* Client buffer full, slow down */
        } else {
            /* Connection error */
            client_destroy(client);
            return NULL;
        }
    }
    
    client->bytes_sent += sent;
    client->lines_sent++;
    client->throttled = false;
    g_stats.bytes_sent += sent;
    
    return client;
}

/* Usage information */
static void print_usage(FILE *f) {
    fprintf(f, "Usage: sshoney [OPTIONS]\n");
    fprintf(f, "Options:\n");
    fprintf(f, "  -4              Bind to IPv4 only\n");
    fprintf(f, "  -6              Bind to IPv6 only\n");
    fprintf(f, "  -d DELAY        Message delay in ms [%d]\n", DEFAULT_DELAY);
    fprintf(f, "  -f CONFIG       Configuration file [%s]\n", DEFAULT_CONFIG_FILE);
    fprintf(f, "  -h              Show this help\n");
    fprintf(f, "  -l LENGTH       Max banner line length [%d]\n", DEFAULT_MAX_LINE_LENGTH);
    fprintf(f, "  -m CLIENTS      Max concurrent clients [%d]\n", DEFAULT_MAX_CLIENTS);
    fprintf(f, "  -p PORT         Listening port [%d]\n", DEFAULT_PORT);
    fprintf(f, "  -s              Log to syslog\n");
    fprintf(f, "  -v              Verbose logging (repeat for debug)\n");
    fprintf(f, "  -V              Show version\n");
}

/* Main program */
int main(int argc, char **argv) {
    struct config config = CONFIG_DEFAULT;
    const char *config_file = DEFAULT_CONFIG_FILE;
    bool use_syslog = false;
    
    g_logfunc = log_stdio;
    g_stats.start_time = time(NULL);
    
    /* Parse command line options */
    int opt;
    while ((opt = getopt(argc, argv, "46d:f:hl:m:p:svV")) != -1) {
        switch (opt) {
        case '4':
            config.bind_family = AF_INET;
            break;
        case '6':
            config.bind_family = AF_INET6;
            break;
        case 'd':
            config.delay = atoi(optarg);
            break;
        case 'f':
            config_file = optarg;
            break;
        case 'h':
            print_usage(stdout);
            return 0;
        case 'l':
            config.max_line_length = atoi(optarg);
            break;
        case 'm':
            config.max_clients = atoi(optarg);
            break;
        case 'p':
            config.port = atoi(optarg);
            break;
        case 's':
            use_syslog = true;
            g_logfunc = log_syslog;
            break;
        case 'v':
            if (g_loglevel < LOG_DEBUG) g_loglevel++;
            break;
        case 'V':
            printf("SSHoney %s\n", XSTR(SSHONEY_VERSION));
            return 0;
        default:
            print_usage(stderr);
            return 1;
        }
    }
    
    /* Initialize logging */
    if (use_syslog) {
        openlog("sshoney", LOG_PID, LOG_DAEMON);
    } else {
        setvbuf(stdout, NULL, _IOLBF, 0);
    }
    
    /* Install signal handlers */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, signal_term);
    signal(SIGINT, signal_term);
    signal(SIGHUP, signal_hup);
    signal(SIGUSR1, signal_usr1);
    
    /* Initialize random number generator */
    struct rng_state rng;
    rng_init(&rng, get_time_ms());
    
    /* Create server socket */
    int server_fd = create_server(&config);
    if (server_fd == -1) {
        return 1;
    }
    
    /* Initialize client queue */
    struct client_queue queue;
    queue_init(&queue);
    
    g_logfunc(LOG_INFO, "SSHoney %s started", XSTR(SSHONEY_VERSION));
    
    /* Main event loop */
    while (g_running) {
        if (g_reload) {
            g_logfunc(LOG_INFO, "Configuration reload requested");
            g_reload = 0;
        }
        
        if (g_dumpstats) {
            log_statistics(&queue);
            g_dumpstats = 0;
        }
        
        /* Process clients due for next message */
        int timeout = -1;
        uint64_t now = get_time_ms();
        
        while (queue.head && queue.head->send_next <= now) {
            struct client *client = queue_pop(&queue);
            
            /* Send line and reschedule if successful */
            if (send_line(client, &config, &rng)) {
                uint32_t delay = config.delay;
                if (config.randomize_delay) {
                    delay = config.min_delay + 
                           (rng_next(&rng) % (config.max_delay - config.min_delay));
                }
                if (client->throttled) {
                    delay *= 2; /* Slow down throttled clients */
                }
                
                client->send_next = now + delay;
                queue_push(&queue, client);
            }
        }
        
        /* Calculate timeout for next client */
        if (queue.head) {
            timeout = (int)(queue.head->send_next - now);
            if (timeout < 0) timeout = 0;
        }
        
        /* Wait for new connections */
        struct pollfd pfd = {
            .fd = server_fd,
            .events = POLLIN,
            .revents = 0
        };
        
        int poll_fds = (queue.count < config.max_clients) ? 1 : 0;
        int poll_result = poll(&pfd, poll_fds, timeout);
        
        if (poll_result == -1) {
            if (errno == EINTR) continue;
            g_logfunc(LOG_INFO, "poll() failed: %s", strerror(errno));
            break;
        }
        
        /* Accept new connections */
        if (poll_result > 0 && (pfd.revents & POLLIN)) {
            int client_fd = accept(server_fd, NULL, NULL);
            if (client_fd == -1) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    g_logfunc(LOG_INFO, "accept() failed: %s", strerror(errno));
                }
                continue;
            }
            
            /* Set non-blocking */
            int flags = fcntl(client_fd, F_GETFL, 0);
            fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
            
            /* Create client and add to queue */
            uint64_t send_time = now + config.delay;
            struct client *client = client_create(client_fd, send_time);
            
            if (client) {
                queue_push(&queue, client);
                g_stats.connects++;
                
                g_logfunc(LOG_INFO, "ACCEPT host=%s port=%d fd=%d clients=%d/%d",
                         client->ipaddr, client->port, client->fd,
                         queue.count, config.max_clients);
            } else {
                g_logfunc(LOG_INFO, "Failed to create client structure");
                close(client_fd);
            }
        }
    }
    
    /* Cleanup */
    g_logfunc(LOG_INFO, "Shutting down...");
    queue_destroy(&queue);
    close(server_fd);
    log_statistics(&queue);
    
    if (use_syslog) {
        closelog();
    }
    
    return 0;
}