/*
 * transport.c
 * Data transport layer
 * Author: Michael Czigler
 * License: MIT
 */

#include "transport.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <syscall.h>

static uint32_t rtc_to_days_since_1970(int y, int m, int d) {
    static const int days_before_month[] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    uint32_t days = (y - 1970) * 365;
    int leap_years = 0;
    for (int year = 1970; year < y; year++) {
        if ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)) {
            leap_years++;
        }
    }
    days += leap_years;
    days += days_before_month[m - 1];
    if (m > 2 && ((y % 4 == 0 && y % 100 != 0) || (y % 400 == 0))) {
        days++;
    }
    days += (d - 1);
    return days;
}

static int has_rdrand(void) {
    uint32_t eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(1));
    return (ecx & (1U << 30)) != 0;
}

static uint64_t get_rdrand(void) {
    uint64_t val = 0;
    unsigned char ok = 0;
    for (int i = 0; i < 10; i++) {
        __asm__ volatile("rdrand %0; setc %1"
                         : "=r"(val), "=qm"(ok));
        if (ok) return val;
    }
    return 0;
}

static uint64_t get_rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static br_x509_trust_anchor *dynamic_TAs = NULL;
static size_t dynamic_TAs_num = 0;

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
} der_buffer;

static void der_append(void *ctx, const void *src, size_t len) {
    der_buffer *buf = (der_buffer *)ctx;
    if (buf->len + len > buf->cap) {
        buf->cap = (buf->cap + len) * 2 + 1024;
        unsigned char *new_data = realloc(buf->data, buf->cap);
        if (new_data) {
            buf->data = new_data;
        } else {
            return;
        }
    }
    memcpy(buf->data + buf->len, src, len);
    buf->len += len;
}

static int clone_pkey(br_x509_pkey *dst, const br_x509_pkey *src) {
    dst->key_type = src->key_type;
    if (src->key_type == BR_KEYTYPE_RSA) {
        dst->key.rsa.nlen = src->key.rsa.nlen;
        dst->key.rsa.n = malloc(src->key.rsa.nlen);
        if (!dst->key.rsa.n) return -1;
        memcpy(dst->key.rsa.n, src->key.rsa.n, src->key.rsa.nlen);

        dst->key.rsa.elen = src->key.rsa.elen;
        dst->key.rsa.e = malloc(src->key.rsa.elen);
        if (!dst->key.rsa.e) {
            free(dst->key.rsa.n);
            return -1;
        }
        memcpy(dst->key.rsa.e, src->key.rsa.e, src->key.rsa.elen);
    } else if (src->key_type == BR_KEYTYPE_EC) {
        dst->key.ec.curve = src->key.ec.curve;
        dst->key.ec.qlen = src->key.ec.qlen;
        dst->key.ec.q = malloc(src->key.ec.qlen);
        if (!dst->key.ec.q) return -1;
        memcpy(dst->key.ec.q, src->key.ec.q, src->key.ec.qlen);
    } else {
        return -1;
    }
    return 0;
}

static void load_dynamic_certs(void) {
    if (dynamic_TAs != NULL) return;
    FAT32_FileInfo *entries = malloc(sizeof(FAT32_FileInfo) * 128);
    if (!entries) return;
    int count = sys_list("/Library/Certificates", entries, 128);
    if (count <= 0) {
        free(entries);
        return;
    }

    size_t ta_capacity = 8;
    dynamic_TAs = malloc(ta_capacity * sizeof(br_x509_trust_anchor));
    if (!dynamic_TAs) {
        free(entries);
        return;
    }

    for (int idx = 0; idx < count; idx++) {
        if (entries[idx].is_directory) continue;

        const char *name = entries[idx].name;
        size_t nlen = strlen(name);
        if (nlen < 4 || strcmp(name + nlen - 4, ".pem") != 0) {
            continue;
        }

        char path[512];
        strcpy(path, "/Library/Certificates/");
        strcat(path, name);

        int fd = sys_open(path, "r");
        if (fd < 0) continue;

        uint32_t size = entries[idx].size;
        if (size == 0) {
            sys_close(fd);
            continue;
        }

        char *file_buf = malloc(size + 1);
        if (!file_buf) {
            sys_close(fd);
            continue;
        }

        int read_bytes = sys_read(fd, file_buf, size);
        sys_close(fd);

        if (read_bytes <= 0) {
            free(file_buf);
            continue;
        }
        file_buf[read_bytes] = '\0';

        br_pem_decoder_context pem_ctx;
        br_pem_decoder_init(&pem_ctx);

        der_buffer der = { NULL, 0, 0 };
        br_pem_decoder_setdest(&pem_ctx, der_append, &der);

        size_t pos = 0;
        size_t file_len = (size_t)read_bytes;
        int in_cert = 0;

        while (pos < file_len) {
            size_t consumed = br_pem_decoder_push(&pem_ctx, file_buf + pos, file_len - pos);
            pos += consumed;

            int event = br_pem_decoder_event(&pem_ctx);
            if (event == BR_PEM_BEGIN_OBJ) {
                const char *banner = br_pem_decoder_name(&pem_ctx);
                if (banner && strcmp(banner, "CERTIFICATE") == 0) {
                    in_cert = 1;
                    der.len = 0;
                }
            } else if (event == BR_PEM_END_OBJ) {
                if (in_cert && der.len > 0) {
                    br_x509_decoder_context x509_ctx;
                    der_buffer dn = { NULL, 0, 0 };
                    br_x509_decoder_init(&x509_ctx, der_append, &dn);
                    br_x509_decoder_push(&x509_ctx, der.data, der.len);

                    const br_x509_pkey *pkey = br_x509_decoder_get_pkey(&x509_ctx);
                    int err = br_x509_decoder_last_error(&x509_ctx);

                    if (pkey && err == 0 && dn.len > 0) {
                        if (dynamic_TAs_num >= ta_capacity) {
                            ta_capacity *= 2;
                            br_x509_trust_anchor *new_tas = realloc(dynamic_TAs, ta_capacity * sizeof(br_x509_trust_anchor));
                            if (new_tas) {
                                dynamic_TAs = new_tas;
                            } else {
                                free(dn.data);
                                break;
                            }
                        }

                        br_x509_trust_anchor *ta = &dynamic_TAs[dynamic_TAs_num];
                        ta->dn.len = dn.len;
                        ta->dn.data = malloc(dn.len);
                        if (ta->dn.data) {
                            memcpy(ta->dn.data, dn.data, dn.len);
                            if (clone_pkey(&ta->pkey, pkey) == 0) {
                                ta->flags = BR_X509_TA_CA;
                                dynamic_TAs_num++;
                            } else {
                                free(ta->dn.data);
                            }
                        }
                    }
                    free(dn.data);
                    in_cert = 0;
                }
            } else if (event == BR_PEM_ERROR) {
                in_cert = 0;
            }
        }

        free(der.data);
        free(file_buf);
    }

    free(entries);
}

/**
 * poll_wait_write() - Wait for socket to be writable
 */
static int poll_wait_write(int fd, int timeout_ms)
{
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;

    for (;;) {
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc > 0)
            return 0;
        if (rc == 0)
            return -1;
        if (errno == EINTR)
            continue;
        return -1;
    }
}

static int transport_tls_step(struct transport *transport) {
    br_ssl_engine_context *eng = &transport->sc.eng;
    unsigned int state = br_ssl_engine_current_state(eng);

    if (state & BR_SSL_CLOSED) {
        return -1;
    }

    int active = 0;

    if (state & BR_SSL_SENDREC) {
        size_t len = 0;
        unsigned char *buf = br_ssl_engine_sendrec_buf(eng, &len);
        if (len > 0) {
            int r = send(transport->fd, buf, len, 0);
            if (r > 0) {
                br_ssl_engine_sendrec_ack(eng, r);
                active = 1;
            } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                return -1;
            }
        }
    }

    if (state & BR_SSL_RECVREC) {
        size_t len = 0;
        unsigned char *buf = br_ssl_engine_recvrec_buf(eng, &len);
        if (len > 0) {
            int r = recv(transport->fd, buf, len, 0);
            if (r > 0) {
                br_ssl_engine_recvrec_ack(eng, r);
                active = 1;
            } else if (r == 0) {
                return -1;
            } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                return -1;
            }
        }
    }

    return active;
}

/**
 * transport_send() - Send data over transport connection
 */
ssize_t transport_send(struct transport *transport,
        const char *buffer, size_t len)
{
    if (transport == NULL || transport->fd < 0)
        return -1;

    if (!transport->tls_active) {
        ssize_t rc = write(transport->fd, buffer, len);
        return (rc < 0) ? -1 : rc;
    }

    size_t total_sent = 0;
    while (total_sent < len) {
        unsigned int state = br_ssl_engine_current_state(&transport->sc.eng);
        if (state & BR_SSL_CLOSED)
            return -1;

        if (state & BR_SSL_SENDAPP) {
            size_t send_len = 0;
            unsigned char *buf = br_ssl_engine_sendapp_buf(&transport->sc.eng, &send_len);
            size_t chunk = len - total_sent;
            if (chunk > send_len) chunk = send_len;
            if (chunk > 0) {
                memcpy(buf, buffer + total_sent, chunk);
                br_ssl_engine_sendapp_ack(&transport->sc.eng, chunk);
                br_ssl_engine_flush(&transport->sc.eng, 0);
                total_sent += chunk;
            }
        }

        transport_tls_step(transport);
    }

    while (br_ssl_engine_current_state(&transport->sc.eng) & BR_SSL_SENDREC) {
        if (transport_tls_step(transport) <= 0)
            break;
    }

    return (ssize_t)total_sent;
}

/**
 * transport_receive() - Receive data from transport connection
 */
ssize_t transport_receive(struct transport *transport,
        char *buffer, size_t len)
{
    if (transport == NULL || transport->fd < 0)
        return -1;

    if (!transport->tls_active) {
        ssize_t nread = read(transport->fd, buffer, len);
        if (nread < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            } else {
                return -1;
            }
        }
        if (nread == 0) {
            return -1;
        }
        return nread;
    }

    transport_tls_step(transport);

    unsigned int state = br_ssl_engine_current_state(&transport->sc.eng);
    if (state & BR_SSL_RECVAPP) {
        size_t app_len = 0;
        unsigned char *buf = br_ssl_engine_recvapp_buf(&transport->sc.eng, &app_len);
        if (app_len > 0) {
            size_t to_copy = (len < app_len) ? len : app_len;
            memcpy(buffer, buf, to_copy);
            br_ssl_engine_recvapp_ack(&transport->sc.eng, to_copy);
            return (ssize_t)to_copy;
        }
    }

    if (state & BR_SSL_CLOSED) {
        return -1;
    }

    return 0;
}

/**
 * transport_connect() - Establish transport connection to server
 */
int transport_connect(struct transport *transport)
{
    struct addrinfo hints, *res = NULL, *p = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    int status = getaddrinfo(transport->ctx->server,
        transport->ctx->port, &hints, &res);

    transport->fd = -1;

    if (status == 0 && res != NULL) {
        for (p = res; p; p = p->ai_next) {
            int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (fd < 0) continue;

            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) {
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            }

            int rc = connect(fd, p->ai_addr, p->ai_addrlen);
            if (rc == 0) {
                transport->fd = fd;
                break;
            }

            if (errno == EINPROGRESS) {
                if (poll_wait_write(fd, KIRC_TIMEOUT_MS) == 0) {
                    int soerr = 0;
                    socklen_t slen = sizeof(soerr);
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                    if (soerr == 0) {
                        transport->fd = fd;
                        break;
                    }
                }
            }

            close(fd);
        }
        freeaddrinfo(res);
    }

    if (transport->fd < 0) {
        net_ipv4_address_t ip;
        int port = atoi(transport->ctx->port);
        if (port <= 0) port = 6667;

        if (inet_pton(AF_INET, transport->ctx->server, &ip) != 1) {
            if (dns_lookup(transport->ctx->server, &ip) != 0) {
                return -1;
            }
        }

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            memcpy(&addr.sin_addr, &ip, 4);

            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) {
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            }

            int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
            if (rc == 0 || (errno == EINPROGRESS && poll_wait_write(fd, KIRC_TIMEOUT_MS) == 0)) {
                int soerr = 0;
                socklen_t slen = sizeof(soerr);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                if (soerr == 0) {
                    transport->fd = fd;
                } else {
                    close(fd);
                }
            } else {
                close(fd);
            }
        }
    }

    if (transport->fd < 0) {
        return -1;
    }

    if (transport->ctx->tls || strcmp(transport->ctx->port, "6697") == 0) {
        load_dynamic_certs();

        static br_x509_minimal_context xc;
        if (dynamic_TAs && dynamic_TAs_num > 0) {
            br_ssl_client_init_full(&transport->sc, &xc, dynamic_TAs, dynamic_TAs_num);
        } else {
            br_ssl_client_init_full(&transport->sc, &xc, NULL, 0);
        }

        int dt[6];
        if (rtc_get(dt) == 0) {
            if (dt[0] >= 1970 && dt[1] >= 1 && dt[1] <= 12 && dt[2] >= 1 && dt[2] <= 31) {
                uint32_t days = rtc_to_days_since_1970(dt[0], dt[1], dt[2]) + 719528;
                uint32_t seconds = dt[3] * 3600 + dt[4] * 60 + dt[5];
                br_x509_minimal_set_time(&xc, days, seconds);
            }
        }

        uint64_t seed[4];
        if (has_rdrand()) {
            seed[0] = get_rdrand();
            seed[1] = get_rdrand();
            seed[2] = get_rdrand();
            seed[3] = get_rdrand();
        } else {
            seed[0] = (uint64_t)get_ticks();
            seed[1] = (uintptr_t)transport;
            seed[2] = get_rdtsc();
            seed[3] = 0x5a5a5a5aULL;
        }
        br_ssl_engine_inject_entropy(&transport->sc.eng, seed, sizeof(seed));
        br_ssl_engine_set_buffer(&transport->sc.eng, transport->iobuf, sizeof(transport->iobuf), 1);

        if (br_ssl_client_reset(&transport->sc, transport->ctx->server, 0) == 0) {
            close(transport->fd);
            transport->fd = -1;
            return -1;
        }

        transport->tls_active = 1;

        int start_time = get_ticks();
        while (!(br_ssl_engine_current_state(&transport->sc.eng) & (BR_SSL_SENDAPP | BR_SSL_RECVAPP | BR_SSL_CLOSED))) {
            int r = transport_tls_step(transport);
            if (r < 0) {
                close(transport->fd);
                transport->fd = -1;
                transport->tls_active = 0;
                return -1;
            }
            if (get_ticks() - start_time > 10000) {
                close(transport->fd);
                transport->fd = -1;
                transport->tls_active = 0;
                return -1;
            }
            if (!r) {
                struct pollfd pfd = { .fd = transport->fd, .events = POLLIN | POLLOUT, .revents = 0 };
                poll(&pfd, 1, 50);
            }
        }

        if (br_ssl_engine_current_state(&transport->sc.eng) & BR_SSL_CLOSED) {
            close(transport->fd);
            transport->fd = -1;
            transport->tls_active = 0;
            return -1;
        }
    }

    return 0;
}

/**
 * transport_init() - Initialize transport structure
 */
int transport_init(struct transport *transport,
        struct kirc_context *ctx)
{
    if ((transport == NULL) || (ctx == NULL)) {
        return -1;
    }

    memset(transport, 0, sizeof(*transport));
    transport->ctx = ctx;
    transport->fd = -1;
    transport->tls_active = 0;

    return 0;
}

/**
 * transport_free() - Close and cleanup transport connection
 */
int transport_free(struct transport *transport)
{
    if (transport == NULL) {
        return -1;
    }

    if (transport->tls_active) {
        br_ssl_engine_close(&transport->sc.eng);
        transport_tls_step(transport);
        transport->tls_active = 0;
    }

    if (transport->fd != -1) {
        close(transport->fd);
        transport->fd = -1;
    }
    return 0;
}
