#pragma once
#include <cstddef>
#include <sys/types.h>
#include <sys/socket.h>
#include <iostream>
#include <openssl/crypto.h>
#include <limits>
#include <vector>

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

// overwrite std::allocator<T> of std::vector<T, std::allocator<T>>, default std::allocator<T> is lazy
template <typename T>
struct SecureAllocator {
    using value_type = T; // must-have

    SecureAllocator() noexcept {}
    template <typename U> SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) { // must-have
        if (n > std::numeric_limits<std::size_t>::max() / sizeof(T)) // make sure n * sizeof(T) is legit
            throw std::bad_alloc();
        
        T* p = static_cast<T*>(OPENSSL_secure_malloc(n * sizeof(T)));
        if (!p) throw std::bad_alloc();
        return p;
    }

    void deallocate(T* p, std::size_t n) noexcept { // must-have
        if (p) {
            OPENSSL_secure_free(p); // no need for OPENSSL_cleanse
        }
    }
};

using SecureVector = std::vector<unsigned char, SecureAllocator<unsigned char>>;