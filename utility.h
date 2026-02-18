#pragma once
#include <cstddef>
#include <sys/types.h>
#include <sys/socket.h>
#include <iostream>

inline bool send_all(int fd, const void* data, size_t len) {
#ifdef DEBUG
    std::cout << "send: " << len << std::endl;
#endif
    const unsigned char* p = (const unsigned char*)data;
    while (len > 0) {
        ssize_t s = send(fd, p, len, 0);
        if (s <= 0) return false;
        p += s; len -= s;
    }
    return true;
}

inline bool recv_all(int fd, void* data, size_t len) {
#ifdef DEBUG
    std::cout << "recv: " << len << std::endl;
#endif
    unsigned char* p = (unsigned char*)data;
    while (len > 0) {
        ssize_t r = recv(fd, p, len, 0);
        if (r <= 0) return false;
        p += r; len -= r;
    }
    return true;
}