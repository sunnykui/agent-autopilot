/*
 * ap_safe_sh.c
 * Static C non-blocking shell proxy client (separate binary/inode from ap-sandbox-init):
 *   - Repairs & verifies fds 0,1,2 BEFORE creating socket (exits 126 on failure).
 *   - Explicitly unblocks SIGALRM (`sigprocmask`), verifies `sigaction` + `setitimer(ITIMER_REAL)` return 0
 *     (exits 126 if kernel timer setup fails), guaranteeing hard deadline termination (`124`).
 *   - Connects to `AP_TOOL_SOCK` with bounded monotonic deadline, pacing & retrying on Linux AF_UNIX `EAGAIN`
 *     (full backlog) and verifying `getpeername() == 0` so an unconnected fd is never used.
 *   - Never alters O_NONBLOCK on shared stdio fds (0,1,2); uses SOCK_NONBLOCK on `sfd` and bounded buffers.
 *   - Polls non-TTY `STDOUT_FILENO` and `STDERR_FILENO` (`events = 0` when buffer empty, `POLLOUT` when non-empty;
 *     TTY fds are polled only when `buf.len > 0` to avoid `POLLHUP` spin):
 *     when downstream closes the last pipe reader (`POLLERR`) or fully closes a Unix stream socket (`POLLHUP`),
 *     wakes immediately even during silent zero-output execution, closing `sfd` (cancelling `tool_ring`) and
 *     exiting `141`; if a bidirectional Unix socket peer only calls `shutdown(SHUT_RD)` without `close()`, Linux
 *     `af_unix` reports breakage on the next `write()` (`EPIPE`), which likewise exits `141` and closes `sfd`.
 *   - Packet-boundary-invariant terminal `R:<0..255>\n` + clean `EOF` (`recv == 0`, or `ECONNRESET` after complete `R:` with zero residual bytes when server closed unread stdin) verification.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_STDIN_BYTES 1048576U
#define MAX_CHUNK_BYTES 4194304U
#define TX_CAP 65536U
#define OUT_CAP 65536U
#define CONNECT_TIMEOUT_MS 5000L
#define EAGAIN_BACKOFF_MS 10L
#define TOTAL_TIMEOUT_SEC 660

#ifndef SYS_kcmp
#define SYS_kcmp 312
#endif
#define KCMP_FILE 0

static void on_sigalrm(int sig) {
    (void)sig;
    _exit(124);
}

static long now_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static int parse_exact_uint(const char *p, size_t len, size_t max_val, size_t *out) {
    if (len == 0 || len > 16) return -1;
    size_t v = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c < '0' || c > '9') return -1;
        size_t d = (size_t)(c - '0');
        if (v > (max_val - d) / 10) return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} DynBuf;

static int buf_append(DynBuf *b, const void *src, size_t n) {
    if (n == 0) return 0;
    if (b->len + n > b->cap) {
        size_t ncap = b->cap ? b->cap * 2 : 8192;
        while (ncap < b->len + n) ncap *= 2;
        char *nd = (char *)realloc(b->data, ncap);
        if (!nd) return -1;
        b->data = nd;
        b->cap = ncap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

static void buf_consume(DynBuf *b, size_t n) {
    if (n >= b->len) {
        b->len = 0;
    } else {
        memmove(b->data, b->data + n, b->len - n);
        b->len -= n;
    }
}

static int repair_and_verify_stdio(int *stdin_originally_valid) {
    struct stat st;
    *stdin_originally_valid = (fstat(STDIN_FILENO, &st) == 0);
    for (int fd = 0; fd <= 2; fd++) {
        if (fstat(fd, &st) < 0) {
            if (errno != EBADF) return -1;
            int dn = open("/dev/null", fd == 0 ? O_RDONLY : O_WRONLY);
            if (dn < 0) return -1;
            if (dn != fd) {
                if (dup2(dn, fd) != fd) {
                    close(dn);
                    return -1;
                }
                close(dn);
            }
        }
        if (fstat(fd, &st) < 0) return -1;
    }
    return 0;
}

static int install_verified_hard_alarm(int seconds) {
    sigset_t unblock;
    if (sigemptyset(&unblock) != 0 || sigaddset(&unblock, SIGALRM) != 0) return -1;
    if (sigprocmask(SIG_UNBLOCK, &unblock, NULL) != 0) return -1;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigalrm;
    if (sigemptyset(&sa.sa_mask) != 0) return -1;
    sa.sa_flags = 0; /* No SA_RESTART: interrupt any blocked write() immediately */
    if (sigaction(SIGALRM, &sa, NULL) != 0) return -1;

    struct itimerval itv;
    memset(&itv, 0, sizeof(itv));
    itv.it_value.tv_sec = seconds;
    if (setitimer(ITIMER_REAL, &itv, NULL) != 0) return -1;
    return 0;
}

static int verify_unix_connected(int sfd) {
    struct sockaddr_un peer;
    socklen_t plen = sizeof(peer);
    return getpeername(sfd, (struct sockaddr *)&peer, &plen) == 0 ? 0 : -1;
}

static int connect_tool_sock_with_deadline(const char *sock_path, long timeout_ms) {
    if (!sock_path || strlen(sock_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    long deadline = now_mono_ms() + timeout_ms;
    for (;;) {
        long rem = deadline - now_mono_ms();
        if (rem <= 0) return -1;

        int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (sfd <= 2) {
            if (sfd >= 0) close(sfd);
            return -1;
        }

        int rc;
        do {
            rc = connect(sfd, (struct sockaddr *)&addr, sizeof(addr));
        } while (rc < 0 && errno == EINTR && now_mono_ms() < deadline);

        if (rc == 0 || (rc < 0 && errno == EISCONN)) {
            if (verify_unix_connected(sfd) == 0) return sfd;
            close(sfd);
            return -1;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            close(sfd);
            rem = deadline - now_mono_ms();
            if (rem <= 0) return -1;
            int wait_ms = (int)(rem < EAGAIN_BACKOFF_MS ? rem : EAGAIN_BACKOFF_MS);
            (void)poll(NULL, 0, wait_ms);
            continue;
        }

        if (errno != EINPROGRESS) {
            close(sfd);
            return -1;
        }

        for (;;) {
            rem = deadline - now_mono_ms();
            if (rem <= 0) {
                close(sfd);
                return -1;
            }
            struct pollfd pfd = { .fd = sfd, .events = POLLOUT, .revents = 0 };
            int pr = poll(&pfd, 1, (int)rem);
            if (pr < 0) {
                if (errno == EINTR) continue;
                close(sfd);
                return -1;
            }
            if (pr == 0) {
                close(sfd);
                return -1;
            }
            int so_err = 0;
            socklen_t slen = sizeof(so_err);
            if (getsockopt(sfd, SOL_SOCKET, SO_ERROR, &so_err, &slen) != 0 || so_err != 0) {
                close(sfd);
                if (so_err == EAGAIN || so_err == EWOULDBLOCK) break;
                return -1;
            }
            if (verify_unix_connected(sfd) == 0) {
                return sfd;
            }
            close(sfd);
            return -1;
        }
    }
}

static int same_open_file(int fd1, int fd2) {
    pid_t self = getpid();
    long r = syscall(SYS_kcmp, self, self, KCMP_FILE, fd1, fd2);
    if (r == 0) return 1;
    if (r > 0) return 0;
    struct stat s1, s2;
    if (fstat(fd1, &s1) == 0 && fstat(fd2, &s2) == 0) {
        return (s1.st_dev == s2.st_dev && s1.st_ino == s2.st_ino);
    }
    return 0;
}

static int is_downstream_broken(int fd, short revents, int shared_with_stdin) {
    if (revents & (POLLERR | POLLNVAL)) return 1;
    if (revents & POLLHUP) {
        if (!shared_with_stdin && !isatty(fd)) return 1;
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode)) {
            /* On Linux AF_UNIX, POLLHUP means SHUTDOWN_MASK (both directions shut down) */
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        return 126;
    }

    int stdin_valid = 0;
    if (repair_and_verify_stdio(&stdin_valid) != 0) {
        return 126;
    }
    if (install_verified_hard_alarm(TOTAL_TIMEOUT_SEC) != 0) {
        return 126;
    }

    int arg_start = 1;
    if (argc > 1 && strcmp(argv[1], "--safe-sh") == 0) {
        arg_start = 2;
    }

    const char *sock_path = getenv("AP_TOOL_SOCK");
    if (!sock_path || !*sock_path) {
        return 126;
    }

    long deadline_ms = now_mono_ms() + (long)TOTAL_TIMEOUT_SEC * 1000L;
    int sfd = connect_tool_sock_with_deadline(sock_path, CONNECT_TIMEOUT_MS);
    if (sfd < 0) {
        return 126;
    }

    int out_shared_stdin = same_open_file(STDOUT_FILENO, STDIN_FILENO);
    int err_shared_stdin = same_open_file(STDERR_FILENO, STDIN_FILENO);
    int out_is_tty = isatty(STDOUT_FILENO);
    int err_is_tty = isatty(STDERR_FILENO);

    DynBuf tx = {0}, rx = {0}, out_b = {0}, err_b = {0};
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) strcpy(cwd, "/");

    char hdr[128];
    int hlen = snprintf(hdr, sizeof(hdr), "CWD:%zu\nARGC:%d\n", strlen(cwd), argc - arg_start);
    if (buf_append(&tx, hdr, (size_t)hlen) < 0 ||
        buf_append(&tx, cwd, strlen(cwd)) < 0 ||
        buf_append(&tx, "\n", 1) < 0) {
        close(sfd);
        free(tx.data);
        return 126;
    }
    for (int i = arg_start; i < argc; i++) {
        size_t alen = strlen(argv[i]);
        int plen = snprintf(hdr, sizeof(hdr), "A:%zu\n", alen);
        if (buf_append(&tx, hdr, (size_t)plen) < 0 ||
            buf_append(&tx, argv[i], alen) < 0 ||
            buf_append(&tx, "\n", 1) < 0) {
            close(sfd);
            free(tx.data);
            return 126;
        }
    }

    int stdin_open = stdin_valid && !isatty(STDIN_FILENO);
    int tx_eof_queued = 0;
    if (!stdin_open) {
        if (buf_append(&tx, "Z:0\n", 4) < 0) {
            close(sfd);
            free(tx.data);
            return 126;
        }
        tx_eof_queued = 1;
    }

    size_t total_stdin = 0;
    char pending_stream = 0;
    size_t pending_rem = 0;
    int got_rc = 0;
    int sock_eof = 0;
    int latched_code = 125;
    int final_override_code = -1;
    int proto_err = 0;

    while (!proto_err && final_override_code < 0 &&
           !(sock_eof && got_rc && rx.len == 0 && pending_rem == 0 && out_b.len == 0 && err_b.len == 0)) {
        long rem_ms = deadline_ms - now_mono_ms();
        if (rem_ms <= 0) {
            final_override_code = 124;
            break;
        }

        int can_rx = (!sock_eof && out_b.len < OUT_CAP && err_b.len < OUT_CAP);
        short sfd_events = (can_rx ? POLLIN : 0) | ((tx.len > 0) ? POLLOUT : 0);
        struct pollfd pfds[4];
        pfds[0].fd = (sfd_events != 0) ? sfd : -1;
        pfds[0].events = sfd_events;
        pfds[1].fd = (stdin_open && !got_rc && tx.len < TX_CAP) ? STDIN_FILENO : -1;
        pfds[1].events = (pfds[1].fd >= 0) ? POLLIN : 0;
        /* Monitor non-tty stdout/stderr even when empty for POLLERR/POLLHUP; avoid tty POLLHUP busy-spin */
        pfds[2].fd = (!out_is_tty || out_b.len > 0) ? STDOUT_FILENO : -1;
        pfds[2].events = (out_b.len > 0) ? POLLOUT : 0;
        pfds[3].fd = (!err_is_tty || err_b.len > 0) ? STDERR_FILENO : -1;
        pfds[3].events = (err_b.len > 0) ? POLLOUT : 0;

        int pr = poll(pfds, 4, (int)(rem_ms > 5000 ? 5000 : rem_ms));
        if (pr < 0) {
            if (errno == EINTR) continue;
            proto_err = 1;
            break;
        }
        if (pr == 0) continue;

        /* 1. Detect downstream broken pipe/socket immediately (even with 0 buffered output) & flush */
        if (pfds[2].fd >= 0 && is_downstream_broken(STDOUT_FILENO, pfds[2].revents, out_shared_stdin)) {
            final_override_code = 141;
            break;
        }
        if (pfds[3].fd >= 0 && is_downstream_broken(STDERR_FILENO, pfds[3].revents, err_shared_stdin)) {
            final_override_code = 141;
            break;
        }
        if (out_b.len > 0 && pfds[2].fd >= 0 && (pfds[2].revents & POLLOUT)) {
            size_t chunk = out_b.len > 4096 ? 4096 : out_b.len;
            ssize_t nw = write(STDOUT_FILENO, out_b.data, chunk);
            if (nw > 0) buf_consume(&out_b, (size_t)nw);
            else if (nw < 0 && errno != EINTR && errno != EAGAIN) { final_override_code = 141; break; }
        }
        if (err_b.len > 0 && pfds[3].fd >= 0 && (pfds[3].revents & POLLOUT)) {
            size_t chunk = err_b.len > 4096 ? 4096 : err_b.len;
            ssize_t nw = write(STDERR_FILENO, err_b.data, chunk);
            if (nw > 0) buf_consume(&err_b, (size_t)nw);
            else if (nw < 0 && errno != EINTR && errno != EAGAIN) { final_override_code = 141; break; }
        }

        /* 2. Read from socket FIRST so early child exit (R:<code> + EOF) is captured even if tx hits EPIPE */
        if (pfds[0].fd >= 0 && !sock_eof && can_rx && (pfds[0].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
            if (pfds[0].revents & POLLNVAL) {
                proto_err = 1;
                break;
            }
            char rbuf[16384];
            ssize_t nr = recv(sfd, rbuf, sizeof(rbuf), 0);
            if (nr > 0) {
                if (got_rc) {
                    proto_err = 1;
                    break;
                }
                if (buf_append(&rx, rbuf, (size_t)nr) < 0) {
                    proto_err = 1;
                    break;
                }
            } else if (nr == 0) {
                sock_eof = 1;
            } else if (errno == ECONNRESET && got_rc && rx.len == 0 && pending_rem == 0) {
                /* Linux AF_UNIX delivers ECONNRESET if server closed with unread stdin after sending R: */
                sock_eof = 1;
            } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                proto_err = 1;
                break;
            }

            while (rx.len > 0 && !proto_err) {
                if (got_rc) {
                    proto_err = 1;
                    break;
                }
                if (pending_rem > 0) {
                    size_t take = rx.len < pending_rem ? rx.len : pending_rem;
                    DynBuf *dst = (pending_stream == 'O') ? &out_b : &err_b;
                    if (buf_append(dst, rx.data, take) < 0) {
                        proto_err = 1;
                        break;
                    }
                    buf_consume(&rx, take);
                    pending_rem -= take;
                    continue;
                }
                char *nl = (char *)memchr(rx.data, '\n', rx.len);
                if (!nl) {
                    if (rx.len > 64) proto_err = 1;
                    break;
                }
                size_t line_len = (size_t)(nl - rx.data);
                if (line_len < 3 || rx.data[1] != ':' || memchr(rx.data, '\0', line_len) != NULL) {
                    proto_err = 1;
                    break;
                }
                char tag = rx.data[0];
                if (tag == 'O' || tag == 'E') {
                    size_t clen = 0;
                    if (parse_exact_uint(rx.data + 2, line_len - 2, MAX_CHUNK_BYTES, &clen) != 0) {
                        proto_err = 1;
                        break;
                    }
                    buf_consume(&rx, line_len + 1);
                    pending_stream = tag;
                    pending_rem = clen;
                } else if (tag == 'R') {
                    size_t code_u = 0;
                    if (parse_exact_uint(rx.data + 2, line_len - 2, 255U, &code_u) != 0) {
                        proto_err = 1;
                        break;
                    }
                    buf_consume(&rx, line_len + 1);
                    latched_code = (int)code_u;
                    got_rc = 1;
                    stdin_open = 0;
                    tx.len = 0;
                } else {
                    proto_err = 1;
                    break;
                }
            }

            if (sock_eof && (!got_rc || rx.len != 0 || pending_rem != 0)) {
                proto_err = 1;
                break;
            }
        }

        /* 3. Read stdin when ready and child has not exited */
        if (stdin_open && !got_rc && pfds[1].fd >= 0 && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL))) {
            if (pfds[1].revents & POLLNVAL) {
                stdin_open = 0;
                if (!tx_eof_queued) {
                    if (buf_append(&tx, "Z:0\n", 4) < 0) { proto_err = 1; break; }
                    tx_eof_queued = 1;
                }
            } else {
                char ibuf[16384];
                ssize_t nr = read(STDIN_FILENO, ibuf, sizeof(ibuf));
                if (nr > 0) {
                    if (total_stdin + (size_t)nr > MAX_STDIN_BYTES) {
                        proto_err = 1;
                        break;
                    }
                    total_stdin += (size_t)nr;
                    int ilen = snprintf(hdr, sizeof(hdr), "I:%zd\n", nr);
                    if (buf_append(&tx, hdr, (size_t)ilen) < 0 ||
                        buf_append(&tx, ibuf, (size_t)nr) < 0) {
                        proto_err = 1;
                        break;
                    }
                } else if (nr == 0 || (nr < 0 && errno != EINTR && errno != EAGAIN)) {
                    stdin_open = 0;
                    if (!tx_eof_queued) {
                        if (buf_append(&tx, "Z:0\n", 4) < 0) { proto_err = 1; break; }
                        tx_eof_queued = 1;
                    }
                }
            }
        }

        /* 4. Flush tx buffer to socket (keep sfd open after Z:0\n; if peer closed early, drop tx and read R:) */
        if (tx.len > 0 && pfds[0].fd >= 0 && (pfds[0].revents & (POLLOUT | POLLERR))) {
            ssize_t nw = send(sfd, tx.data, tx.len, MSG_NOSIGNAL);
            if (nw > 0) {
                buf_consume(&tx, (size_t)nw);
            } else if (nw < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                stdin_open = 0;
                tx.len = 0;
            }
        }
    }

    close(sfd);
    free(tx.data);
    free(rx.data);
    free(out_b.data);
    free(err_b.data);
    if (final_override_code >= 0) return final_override_code;
    return (!proto_err && got_rc && sock_eof) ? latched_code : 125;
}
