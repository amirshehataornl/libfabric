#ifndef container_of
#define container_of(ptr, type, field) \
    ((type *) ((char *)ptr - offsetof(type, field)))
#endif

