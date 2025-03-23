#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stddef.h>

typedef void (*init_func)(void *ctx);
typedef void *(*alloc_func)(void *ctx, size_t size);
typedef void *(*realloc_func)(void *ctx, void *ptr, size_t new_size);
typedef void (*free_func)(void *ctx, void *ptr);
typedef void (*destroy_func)(void *ctx);
typedef void (*reset_func)(void *ctx);

struct Allocator {
    init_func init;
    alloc_func alloc;       /* guaranteed to be implemented */
    realloc_func realloc;
    free_func free;
    destroy_func destroy;
    reset_func reset;
    void *context;
};

#define HAS_REALLOC(a) ((a)->realloc != nullptr)
#define HAS_FREE(a) ((a)->free != nullptr)
#define HAS_INIT(a) ((a)->init != nullptr)
#define HAS_DESTROY(a) ((a)->destroy != nullptr)
#define HAS_RESET(a) ((a)->reset != nullptr)

#define ALLOC(a, size) ((a)->alloc((a)->context, (size)))

#define REALLOC(a, ptr, size) ((a)->realloc((a)->context, (ptr), (size)))
#define FREE(a, ptr) ((a)->free((a)->context, (ptr)))
#define INIT_ALLOCATOR(a) ((a)->init((a)->context))
#define DESTROY_ALLOCATOR(a) ((a)->destroy((a)->context))
#define RESET_ALLOCATOR(a) ((a)->reset((a)->context))

#define SAFE_REALLOC(a, ptr, size) \
    (HAS_REALLOC(a) ? (a)->realloc((a)->context, (ptr), (size)) : nullptr)

#define SAFE_FREE(a, ptr) \
    do { if (HAS_FREE(a) && (ptr)) (a)->free((a)->context, (ptr)); } while (0)

#define SAFE_INIT_ALLOCATOR(a) \
    do { if (HAS_INIT(a)) (a)->init((a)->context); } while (0)

#define SAFE_DESTROY_ALLOCATOR(a) \
    do { if (HAS_DESTROY(a)) (a)->destroy((a)->context); } while (0)

#define SAFE_RESET_ALLOCATOR(a) \
    do { if (HAS_RESET(a)) (a)->reset((a)->context); } while (0)

#endif
