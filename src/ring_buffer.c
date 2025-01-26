#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include "ring_buffer.h"

struct RingBuffer *rb_init(size_t size) {
    if ((size % sysconf(_SC_PAGESIZE)) != 0)
        return NULL;

    int fd;

#ifdef __linux__
    fd = memfd_create("myhttpringbuffer", 0);

    if (fd == -1) {
        perror("memfd_create failed");
        return NULL;
    }
#else
    const char *name = "/myhttpringbuffer";

    fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (fd == -1) {
        perror("shm_open failed");
        return NULL;
    }

    shm_unlink(name);
#endif

    if (ftruncate(fd, size) == -1) {
        perror("ftruncate failed");
        close(fd);
        return NULL;
    }

    uint8_t *addr = mmap(NULL, 2 * size, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (addr == MAP_FAILED) {
        perror("anon mmap failed");
        close(fd);
        return NULL;
    }

    void *res = mmap(addr, size, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_FIXED, fd, 0);

    if (res == MAP_FAILED) {
        perror("first half mmap failed");
        munmap(addr, size * 2);
        close(fd);
        return NULL;
    }

    res = mmap(addr + size, size, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_FIXED, fd, 0);

    if (res == MAP_FAILED) {
        perror("second half mmap failed");
        munmap(addr, size * 2);
        close(fd);
        return NULL;
    }

    struct RingBuffer *rb = malloc(sizeof(struct RingBuffer));

    if (rb == NULL) {
        perror("malloc failed");
        munmap(addr, size * 2);
        close(fd);
        return NULL;
    }

    close(fd);

    rb->buffer = addr;
    rb->buffer_size = size;
    rb->write_index = 0;
    rb->read_index = 0;

    return rb;
}

void rb_destroy(struct RingBuffer *rb) {
    munmap(rb->buffer, 2 * rb->buffer_size);
    free(rb);
}

bool rb_write(struct RingBuffer *rb, const uint8_t *src, size_t size) {
    if (rb->buffer_size - (rb->write_index - rb->read_index) < size)
        return false;

    memcpy(&rb->buffer[rb->write_index], src, size);
    rb->write_index += size;

    return true;
}

bool rb_read(struct RingBuffer *rb, uint8_t *dst, size_t size) {
    if (rb->write_index - rb->read_index < size)
        return false;

    memcpy(dst, &rb->buffer[rb->read_index], size);
    rb->read_index += size;

    if (rb->read_index >= rb->buffer_size) {
        rb->read_index -= rb->buffer_size;
        rb->write_index -= rb->buffer_size;
    }

    return true;
}

/* testing */


static inline char randchar() {
    return ('A' + (rand() % 26));
}

static inline size_t count(struct RingBuffer *rb) {
    return rb->write_index - rb->read_index;
}
