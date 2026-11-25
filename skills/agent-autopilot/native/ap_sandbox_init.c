/*
 * ap_sandbox_init.c
 * Static C sandbox initializer (compiled as separate binary/inode from ap-safe-sh):
 *   1) Ensures fds 0,1,2 are open and verifies open/dup2 succeed (exits 126 on failure before socket()).
 *   2) Optionally forks in-namespace loopback TCP -> Unix socket proxy bridge with:
 *      - Non-blocking Unix `connect()` bounded by a strict 5,000 ms monotonic deadline:
 *        * On Linux AF_UNIX `EAGAIN`/`EWOULDBLOCK` (listen backlog full, no connection queued), closes the
 *          unconnected socket, sleeps <=10 ms within deadline, and retries `connect()`;
 *        * On `EINPROGRESS`, waits via `poll(POLLOUT)` + `SO_ERROR == 0`;
 *        * Always verifies `getpeername() == 0` before handing `ufd` to the pump loop.
 *      - Non-blocking sockets and bounded 64 KiB ring buffers in both directions (`!a_eof || !b_eof` + drain).
 *   3) Applies Linux Landlock LSM rules restricting LANDLOCK_ACCESS_FS_EXECUTE strictly to `--allow-exec`.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PROXY_BUF_CAP 65536U
#define PROXY_CONNECT_TIMEOUT_MS 5000L
#define PROXY_EAGAIN_BACKOFF_MS 10L
#define PROXY_IDLE_MS 300000L
#define PROXY_MAX_CHILDREN 32

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
                                          const size_t size, const __u32 flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif
#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd, const enum landlock_rule_type rule_type,
                                    const void *const rule_attr, const __u32 flags) {
    return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr, flags);
}
#endif
#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd, const __u32 flags) {
    return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

static long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int ensure_stdio_open(void) {
    struct stat st;
    for (int fd = 0; fd <= 2; fd++) {
        if (fstat(fd, &st) < 0) {
            if (errno != EBADF) return -1;
            int nfd = open("/dev/null", fd == 0 ? O_RDONLY : O_WRONLY);
            if (nfd < 0) return -1;
            if (nfd != fd) {
                if (dup2(nfd, fd) != fd) {
                    close(nfd);
                    return -1;
                }
                close(nfd);
            }
        }
        if (fstat(fd, &st) < 0) return -1;
    }
    return 0;
}

static int verify_unix_connected(int ufd) {
    struct sockaddr_un peer;
    socklen_t plen = sizeof(peer);
    return getpeername(ufd, (struct sockaddr *)&peer, &plen) == 0 ? 0 : -1;
}

static int connect_unix_with_deadline(const char *unix_sock_path, long timeout_ms) {
    if (!unix_sock_path || strlen(unix_sock_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        return -1;
    }
    struct sockaddr_un uaddr;
    memset(&uaddr, 0, sizeof(uaddr));
    uaddr.sun_family = AF_UNIX;
    strncpy(uaddr.sun_path, unix_sock_path, sizeof(uaddr.sun_path) - 1);

    long deadline = mono_ms() + timeout_ms;
    for (;;) {
        long rem = deadline - mono_ms();
        if (rem <= 0) return -1;

        int ufd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (ufd < 0) return -1;

        int rc;
        do {
            rc = connect(ufd, (struct sockaddr *)&uaddr, sizeof(uaddr));
        } while (rc < 0 && errno == EINTR && mono_ms() < deadline);

        if (rc == 0 || (rc < 0 && errno == EISCONN)) {
            if (verify_unix_connected(ufd) == 0) return ufd;
            close(ufd);
            return -1;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            /* Linux AF_UNIX stream backlog full: socket remains SS_UNCONNECTED. Close, pace, and retry. */
            close(ufd);
            rem = deadline - mono_ms();
            if (rem <= 0) return -1;
            int wait_ms = (int)(rem < PROXY_EAGAIN_BACKOFF_MS ? rem : PROXY_EAGAIN_BACKOFF_MS);
            (void)poll(NULL, 0, wait_ms);
            continue;
        }

        if (errno != EINPROGRESS) {
            close(ufd);
            return -1;
        }

        for (;;) {
            rem = deadline - mono_ms();
            if (rem <= 0) {
                close(ufd);
                return -1;
            }
            struct pollfd pfd = { .fd = ufd, .events = POLLOUT, .revents = 0 };
            int pr = poll(&pfd, 1, (int)rem);
            if (pr < 0) {
                if (errno == EINTR) continue;
                close(ufd);
                return -1;
            }
            if (pr == 0) {
                close(ufd);
                return -1;
            }
            int so_err = 0;
            socklen_t slen = sizeof(so_err);
            if (getsockopt(ufd, SOL_SOCKET, SO_ERROR, &so_err, &slen) != 0 || so_err != 0) {
                close(ufd);
                if (so_err == EAGAIN || so_err == EWOULDBLOCK) break; /* Retry outer loop if time remains */
                return -1;
            }
            if (verify_unix_connected(ufd) == 0) {
                return ufd;
            }
            close(ufd);
            return -1;
        }
    }
}

/* Fully non-blocking bidirectional bounded-buffer pump with half-close drain & idle deadline */
static void pump_loop_nonblocking(int a, int b) {
    signal(SIGPIPE, SIG_IGN);
    int fla = fcntl(a, F_GETFL, 0);
    int flb = fcntl(b, F_GETFL, 0);
    if (fla < 0 || flb < 0 ||
        fcntl(a, F_SETFL, fla | O_NONBLOCK) < 0 ||
        fcntl(b, F_SETFL, flb | O_NONBLOCK) < 0) {
        close(a);
        close(b);
        return;
    }

    char ab[PROXY_BUF_CAP];
    char ba[PROXY_BUF_CAP];
    size_t ab_len = 0, ba_len = 0;
    int a_read_eof = 0, b_read_eof = 0;
    int b_write_shut = 0, a_write_shut = 0;
    long last_active = mono_ms();

    while (!(a_read_eof && ab_len == 0 && b_read_eof && ba_len == 0)) {
        long idle = mono_ms() - last_active;
        if (idle >= PROXY_IDLE_MS) break;
        int wait_ms = (int)(PROXY_IDLE_MS - idle);
        if (wait_ms > 5000) wait_ms = 5000;

        struct pollfd pfd[2];
        pfd[0].events = ((!a_read_eof && ab_len < PROXY_BUF_CAP) ? POLLIN : 0) |
                        ((ba_len > 0 && !a_write_shut) ? POLLOUT : 0);
        pfd[0].fd = (pfd[0].events != 0) ? a : -1;
        pfd[1].events = ((!b_read_eof && ba_len < PROXY_BUF_CAP) ? POLLIN : 0) |
                        ((ab_len > 0 && !b_write_shut) ? POLLOUT : 0);
        pfd[1].fd = (pfd[1].events != 0) ? b : -1;

        if (pfd[0].fd < 0 && pfd[1].fd < 0) break;

        int r = poll(pfd, 2, wait_ms);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (r == 0) continue;

        if ((pfd[0].revents & POLLNVAL) || (pfd[1].revents & POLLNVAL)) break;

        if (!a_read_eof && ab_len < PROXY_BUF_CAP && (pfd[0].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(a, ab + ab_len, PROXY_BUF_CAP - ab_len, 0);
            if (n > 0) {
                ab_len += (size_t)n;
                last_active = mono_ms();
            } else if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
                a_read_eof = 1;
                if (ab_len == 0 && !b_write_shut) {
                    shutdown(b, SHUT_WR);
                    b_write_shut = 1;
                }
            }
        }

        if (!b_read_eof && ba_len < PROXY_BUF_CAP && (pfd[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(b, ba + ba_len, PROXY_BUF_CAP - ba_len, 0);
            if (n > 0) {
                ba_len += (size_t)n;
                last_active = mono_ms();
            } else if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
                b_read_eof = 1;
                if (ba_len == 0 && !a_write_shut) {
                    shutdown(a, SHUT_WR);
                    a_write_shut = 1;
                }
            }
        }

        if (ab_len > 0 && !b_write_shut && (pfd[1].revents & (POLLOUT | POLLERR))) {
            ssize_t nw = send(b, ab, ab_len, MSG_NOSIGNAL);
            if (nw > 0) {
                memmove(ab, ab + nw, ab_len - (size_t)nw);
                ab_len -= (size_t)nw;
                last_active = mono_ms();
                if (ab_len == 0 && a_read_eof && !b_write_shut) {
                    shutdown(b, SHUT_WR);
                    b_write_shut = 1;
                }
            } else if (nw < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                b_write_shut = 1;
                ab_len = 0;
                a_read_eof = 1;
            }
        }

        if (ba_len > 0 && !a_write_shut && (pfd[0].revents & (POLLOUT | POLLERR))) {
            ssize_t nw = send(a, ba, ba_len, MSG_NOSIGNAL);
            if (nw > 0) {
                memmove(ba, ba + nw, ba_len - (size_t)nw);
                ba_len -= (size_t)nw;
                last_active = mono_ms();
                if (ba_len == 0 && b_read_eof && !a_write_shut) {
                    shutdown(a, SHUT_WR);
                    a_write_shut = 1;
                }
            } else if (nw < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                a_write_shut = 1;
                ba_len = 0;
                b_read_eof = 1;
            }
        }
    }
    close(a);
    close(b);
}

static int start_proxy_bridge(const char *unix_sock_path, int *out_port) {
    if (strlen(unix_sock_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return -1;
    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) return -1;
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = 0;
    if (bind(lfd, (struct sockaddr *)&sin, sizeof(sin)) != 0 || listen(lfd, 32) != 0) {
        close(lfd);
        return -1;
    }
    socklen_t slen = sizeof(sin);
    if (getsockname(lfd, (struct sockaddr *)&sin, &slen) != 0) {
        close(lfd);
        return -1;
    }
    *out_port = ntohs(sin.sin_port);
    pid_t pid = fork();
    if (pid < 0) {
        close(lfd);
        return -1;
    }
    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        int active_children = 0;
        for (;;) {
            while (active_children > 0 && waitpid(-1, NULL, WNOHANG) > 0) {
                active_children--;
            }
            if (active_children >= PROXY_MAX_CHILDREN) {
                if (waitpid(-1, NULL, 0) > 0) active_children--;
                continue;
            }
            int cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (cfd < 0) {
                if (errno == EINTR || errno == ECONNABORTED || errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                if (errno == EMFILE || errno == ENFILE) {
                    (void)poll(NULL, 0, 20);
                    continue;
                }
                _exit(0);
            }
            pid_t cpid = fork();
            if (cpid == 0) {
                close(lfd);
                int ufd = connect_unix_with_deadline(unix_sock_path, PROXY_CONNECT_TIMEOUT_MS);
                if (ufd >= 0) {
                    pump_loop_nonblocking(cfd, ufd);
                } else {
                    close(cfd);
                }
                _exit(0);
            } else if (cpid > 0) {
                active_children++;
            }
            close(cfd);
        }
    }
    close(lfd);
    return 0;
}

static int apply_landlock_exec_allowlist(char **allow_exec, int n_exec) {
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE,
    };
    int ruleset_fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
    if (ruleset_fd < 0) {
        perror("ap-sandbox-init: landlock_create_ruleset");
        return -1;
    }
    for (int i = 0; i < n_exec; i++) {
        int pfd = open(allow_exec[i], O_PATH | O_CLOEXEC);
        if (pfd < 0) {
            fprintf(stderr, "ap-sandbox-init: open allow_exec %s: %s\n", allow_exec[i], strerror(errno));
            close(ruleset_fd);
            return -1;
        }
        struct landlock_path_beneath_attr pb = {
            .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE,
            .parent_fd = pfd,
        };
        if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) != 0) {
            perror("ap-sandbox-init: landlock_add_rule");
            close(pfd);
            close(ruleset_fd);
            return -1;
        }
        close(pfd);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("ap-sandbox-init: PR_SET_NO_NEW_PRIVS");
        close(ruleset_fd);
        return -1;
    }
    if (landlock_restrict_self(ruleset_fd, 0) != 0) {
        perror("ap-sandbox-init: landlock_restrict_self");
        close(ruleset_fd);
        return -1;
    }
    close(ruleset_fd);
    return 0;
}

int main(int argc, char **argv) {
    if (ensure_stdio_open() != 0) {
        return 126;
    }
    const char *proxy_sock = NULL;
    char *allow_exec[64];
    int n_exec = 0;
    int cmd_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_idx = i + 1;
            break;
        } else if (strcmp(argv[i], "--proxy-sock") == 0 && i + 1 < argc) {
            proxy_sock = argv[++i];
        } else if (strcmp(argv[i], "--allow-exec") == 0 && i + 1 < argc) {
            if (n_exec >= 64) return 2;
            allow_exec[n_exec++] = argv[++i];
        } else {
            fprintf(stderr, "ap-sandbox-init: unknown arg %s\n", argv[i]);
            return 2;
        }
    }
    if (cmd_idx < 0 || cmd_idx >= argc) {
        fprintf(stderr, "ap-sandbox-init: missing command after --\n");
        return 2;
    }

    if (proxy_sock && *proxy_sock) {
        int port = 0;
        if (start_proxy_bridge(proxy_sock, &port) != 0) {
            fprintf(stderr, "ap-sandbox-init: proxy bridge startup failed\n");
            return 126;
        }
        char url[64];
        snprintf(url, sizeof(url), "http://127.0.0.1:%d", port);
        setenv("HTTPS_PROXY", url, 1);
        setenv("HTTP_PROXY", url, 1);
        setenv("https_proxy", url, 1);
        setenv("http_proxy", url, 1);
    }

    if (apply_landlock_exec_allowlist(allow_exec, n_exec) != 0) {
        return 126;
    }

    execv(argv[cmd_idx], &argv[cmd_idx]);
    perror("ap-sandbox-init: execv");
    return 127;
}
