#include <stdlib.h>
#include "allocator.h"
#include "gpa.h"

static void *
gpa_alloc([[maybe_unused]] void *ctx, size_t size)
{
    return malloc(size);
}

static void *
gpa_realloc([[maybe_unused]] void *ctx, void *ptr, size_t size)
{
    return realloc(ptr, size);
}

static void
gpa_free([[maybe_unused]] void *ctx, void *ptr)
{
    free(ptr);
}

struct Allocator *
get_gpalloc() {
    static struct Allocator gpa = {
        .alloc = gpa_alloc,
        .realloc = gpa_realloc,
        .free = gpa_free,
    };

    return &gpa;
}

