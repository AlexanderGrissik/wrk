#ifndef NET_H
#define NET_H

#include "config.h"
#include <stdint.h>
#include <openssl/ssl.h>
#include "wrk.h"

#define WAIT_READ 1
#define WAIT_WRITE 2

typedef enum {
    OK,
    ERROR,
    RETRY
} status;

struct sock {
    status ( *connect)(connection *, char *);
    status (   *close)(connection *, bool clean);
    status (    *read)(connection *, size_t *);
    status (   *write)(connection *, char *, size_t, size_t *);
    size_t (*readable)(connection *);
};

status sock_connect(connection *, char *);
status sock_close(connection *, bool clean);
status sock_read(connection *, size_t *);
status sock_write(connection *, char *, size_t, size_t *);
size_t sock_readable(connection *);

int wait_for_single_socket(int fd, int which, int to_msec);
bool wait_for_single_socket_simple(int fd, int which);

#endif /* NET_H */
