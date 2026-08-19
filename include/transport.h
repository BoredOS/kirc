/*
 * transport.h
 * Header for the transport module
 * Author: Michael Czigler
 * License: MIT
 */

#ifndef __KIRC_TRANSPORT_H
#define __KIRC_TRANSPORT_H

#include "kirc.h"
#include <bearssl.h>

struct transport {
    struct kirc_context *ctx;
    int fd;
    int tls_active;
    br_ssl_client_context sc;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
};

ssize_t transport_send(struct transport *transport,
        const char *buffer, size_t len);
ssize_t transport_receive(struct transport *transport,
        char *buffer, size_t len);

int transport_connect(struct transport *transport);
int transport_init(struct transport *transport,
        struct kirc_context *ctx);
int transport_free(struct transport *transport);

#endif  // __KIRC_TRANSPORT_H
