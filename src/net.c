// Copyright (C) 2013 - Will Glozer.  All rights reserved.

#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <poll.h>
#include "net.h"

status sock_connect(connection *c, char *host) {
    return OK;
}

status sock_close(connection *c, bool clean) {
    return OK;
}

status sock_read(connection *c, size_t *n) {
    ssize_t r = read(c->fd, c->buf, sizeof(c->buf));
    *n = (size_t) r;
    return r >= 0 ? OK : ERROR;
}

status sock_write(connection *c, char *buf, size_t len, size_t *n) {
    ssize_t r;
    if ((r = write(c->fd, buf, len)) == -1) {
        switch (errno) {
            case EAGAIN: return RETRY;
            default:     return ERROR;
        }
    }
    *n = (size_t) r;
    return OK;
}

size_t sock_readable(connection *c) {
    int n, rc;
    rc = ioctl(c->fd, FIONREAD, &n);
    return rc == -1 ? 0 : n;
}

int wait_for_single_socket(int fd, int which, int to_msec) {
    struct pollfd pfd = {
	fd,
	(which & WAIT_READ ? POLLIN : 0) | (which & WAIT_WRITE ? POLLOUT : 0),
	0
    };

    return poll(&pfd, 1, to_msec);
}

bool wait_for_single_socket_simple(int fd, int which) {
    int rc = wait_for_single_socket(fd, which, 5000);
    if (rc <= 0) {
        if (rc == 0)
            printf("Error: wait_for_single_socket, timeout\n");
	else 
            printf("Error: wait_for_single_socket, errno=%d, fd=%d\n", errno, fd);

	return false;
    }

    return true;
}

