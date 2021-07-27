// Copyright (C) 2013 - Will Glozer.  All rights reserved.

#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ssl.h"

#define IS_TLS_ERR_WANT_RW(e) (SSL_ERROR_WANT_READ == (e) || SSL_ERROR_WANT_WRITE == (e))

#define TLS_WAIT_WHICH(e)                                                                          \
    (((e) == SSL_ERROR_WANT_READ || (e) == SSL_ERROR_WANT_CONNECT) ? WAIT_READ : 0) |          \
        (((e) == SSL_ERROR_WANT_WRITE || (e) == SSL_ERROR_WANT_CONNECT) ? WAIT_WRITE : 0)

SSL_CTX *ssl_init() {
    SSL_CTX *ctx = NULL;

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    if ((ctx = SSL_CTX_new(SSLv23_client_method()))) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_verify_depth(ctx, 0);
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    }

    return ctx;
}

status ssl_connect(connection *c, char *host) {
    int r;
    SSL_set_fd(c->ssl, c->fd);
    SSL_set_tlsext_host_name(c->ssl, host);
    if ((r = SSL_connect(c->ssl)) != 1) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    return OK;
}

status ssl_close(connection *c, bool clean) {
    /*if (!clean) {
       SSL_shutdown(c->ssl);
    } else {
       bool shuttingDown = true;
       while (shuttingDown) {
           int rc = SSL_shutdown(c->ssl);
           if (rc < 0) {
               int err = SSL_get_error(c->ssl, rc);
               if (IS_TLS_ERR_WANT_RW(err)) {
	           if (!wait_for_single_socket_simple(SSL_get_fd(c->ssl), TLS_WAIT_WHICH(err)))
                       shuttingDown = false;
               } else {
                   printf("Error: SSL_shutdown, errno=%d\n", errno);
                   shuttingDown = false;
               } 
      	   } else if (rc > 0) {
               shuttingDown = false;
           }
        }
    }*/

    SSL_clear(c->ssl);
    return OK;
}

status ssl_read(connection *c, size_t *n) {
    int r;
    if ((r = SSL_read(c->ssl, c->buf, sizeof(c->buf))) <= 0) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    *n = (size_t) r;
    return OK;
}

status ssl_write(connection *c, char *buf, size_t len, size_t *n) {
    int r;
    if ((r = SSL_write(c->ssl, buf, len)) <= 0) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    *n = (size_t) r;
    return OK;
}

size_t ssl_readable(connection *c) {
    return SSL_pending(c->ssl);
}
