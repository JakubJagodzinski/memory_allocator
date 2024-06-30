#ifndef HEAP_H
#define HEAP_H
#define MACHINE_WORD_SIZE sizeof(void *)
#define STRUCT_SIZE sizeof(struct memory_chunk_t)
#define FENCE_SIZE 16
#define MEMORY_PAGE_SIZE 4096

#include <stdio.h>
#include <stdint.h>

struct memory_manager_t {
    void *memory_start;
    size_t memory_size;
    struct memory_chunk_t *first_memory_chunk;
    uint8_t is_init: 1;
};
struct memory_chunk_t {
    struct memory_chunk_t *prev;
    struct memory_chunk_t *next;
    size_t size;
    uint8_t free: 1;
    char *filename;
    int fileline;
    uint32_t crc;
};
enum pointer_type_t {
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};

size_t count_crc(const struct memory_chunk_t *chunk);

enum pointer_type_t get_pointer_type(const void *pointer);

size_t heap_get_largest_used_block_size(void);

int heap_setup(void);

void heap_clean(void);

int heap_validate(void);

void *heap_malloc(size_t size);

void *heap_calloc(size_t number, size_t size);

void *heap_realloc(void *memblock, size_t count);

void heap_free(void *memblock);

void merge_chunks(struct memory_chunk_t *chunk);

void *heap_malloc_aligned(size_t count);

void *heap_calloc_aligned(size_t number, size_t size);

void *heap_realloc_aligned(void *memblock, size_t size);

void *heap_malloc_debug(size_t count, int fileline, const char *filename);

void *heap_calloc_debug(size_t number, size_t size, int fileline, const char *filename);

void *heap_realloc_debug(void *memblock, size_t size, int fileline, const char *filename);

void *heap_malloc_aligned_debug(size_t count, int fileline, const char *filename);

void *heap_calloc_aligned_debug(size_t number, size_t size, int fileline, const char *filename);

void *heap_realloc_aligned_debug(void *memblock, size_t size, int fileline, const char *filename);

#endif
