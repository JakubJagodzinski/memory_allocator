#include "heap.h"
#include "custom_unistd.h"
#include <string.h>
#include <stdint.h>

struct memory_manager_t memory_manager;

size_t count_crc(const struct memory_chunk_t *chunk) {
    uint8_t *byte_ptr = (uint8_t *) chunk;
    size_t sum = 0;
    while (byte_ptr != (uint8_t *) &(chunk->crc)) {
        sum += *byte_ptr++;
    }
    return sum;
}

enum pointer_type_t get_pointer_type(const void *const pointer) {
    if (pointer == NULL) {
        return pointer_null;
    }
    struct memory_chunk_t *chunk = memory_manager.first_memory_chunk;
    while (chunk) {
        if ((uint8_t *) pointer >= (uint8_t *) chunk &&
            (uint8_t *) pointer < (uint8_t *) chunk + sizeof(struct memory_chunk_t)) {
            return pointer_control_block;
        }
        if (chunk->free == 1) {
            if ((uint8_t *) pointer >= (uint8_t *) chunk + sizeof(struct memory_chunk_t) &&
                (uint8_t *) pointer < (uint8_t *) chunk + sizeof(struct memory_chunk_t) + chunk->size) {
                return pointer_unallocated;
            }
        } else {
            if ((uint8_t *) pointer >= (uint8_t *) chunk + sizeof(struct memory_chunk_t) &&
                (uint8_t *) pointer < (uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE) {
                return pointer_inside_fences;
            }
            if ((uint8_t *) pointer == (uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE) {
                return pointer_valid;
            }
            if ((uint8_t *) pointer > (uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE &&
                (uint8_t *) pointer < (uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE + chunk->size) {
                return pointer_inside_data_block;
            }
            if ((uint8_t *) pointer >= (uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE + chunk->size &&
                (uint8_t *) pointer <
                (uint8_t *) chunk + sizeof(struct memory_chunk_t) + chunk->size + 2 * FENCE_SIZE) {
                return pointer_inside_fences;
            }
            if (chunk->next && (uint8_t *) pointer < (uint8_t *) chunk->next) {
                return pointer_unallocated;
            }
        }
        chunk = chunk->next;
    }
    return pointer_unallocated;
}

size_t heap_get_largest_used_block_size(void) {
    if (heap_validate() != 0) {
        return 0;
    }
    size_t max_size = 0;
    struct memory_chunk_t *chunk = memory_manager.first_memory_chunk;
    while (chunk) {
        if (chunk->free == 0 && chunk->size > max_size) {
            max_size = chunk->size;
        }
        chunk = chunk->next;
    }
    return max_size;
}

int heap_setup(void) {
    if (memory_manager.is_init) {
        return 0;
    }
    memory_manager.memory_start = custom_sbrk(0);
    if (memory_manager.memory_start == (void *) -1) {
        return -1;
    }
    memory_manager.memory_size = 0;
    memory_manager.first_memory_chunk = NULL;
    memory_manager.is_init = 1;
    return 0;
}

void heap_clean(void) {
    if (memory_manager.is_init == 0) {
        return;
    }
    custom_sbrk(-((int) memory_manager.memory_size));
    memory_manager.memory_start = NULL;
    memory_manager.memory_size = 0;
    memory_manager.first_memory_chunk = NULL;
    memory_manager.is_init = 0;
}

int heap_validate(void) {
    if (memory_manager.is_init == 0) {
        return 2;
    }
    struct memory_chunk_t *chunk = memory_manager.first_memory_chunk;
    while (chunk) {
        if (chunk->crc != count_crc(chunk)) {
            return 3;
        }
        uint8_t *ptr = (uint8_t *) chunk + sizeof(struct memory_chunk_t);
        if (chunk->free == 0) {
            for (size_t i = 0; i < FENCE_SIZE; ++i) {
                if (*(ptr + i) != '#' || *(ptr + FENCE_SIZE + chunk->size + i) != '#') {
                    return 1;
                }
            }
        }
        chunk = chunk->next;
    }
    return 0;
}

void *heap_malloc(size_t size) {
    if (size < 1 || heap_validate() != 0) {
        return NULL;
    }
    struct memory_chunk_t *chunk = memory_manager.first_memory_chunk;
    while (chunk) {
        if (chunk->free && chunk->size >= size + 2 * FENCE_SIZE) {
            chunk->size = size;
            chunk->free = 0;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) chunk + sizeof(struct memory_chunk_t), '#', FENCE_SIZE);
            memset((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
            return (void *) ((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE);
        }
        chunk = chunk->next;
    }
    size_t padding = 0;
    if (memory_manager.memory_size) {
        padding = memory_manager.memory_size % PADDING_SIZE;
        if (padding) {
            padding = PADDING_SIZE - padding;
        }
    }
    size_t delta = padding + sizeof(struct memory_chunk_t) + size + 2 * FENCE_SIZE;
    if (custom_sbrk((int) delta) == (void *) -1) {
        return NULL;
    }
    memory_manager.memory_size += delta;
    if (memory_manager.first_memory_chunk == NULL) {
        memory_manager.first_memory_chunk = memory_manager.memory_start;
        chunk = memory_manager.first_memory_chunk;
        chunk->prev = NULL;
    } else {
        chunk = memory_manager.first_memory_chunk;
        while (chunk->next) {
            chunk = chunk->next;
        }
        chunk->next = (void *) ((uint8_t *) memory_manager.memory_start + memory_manager.memory_size - delta + padding);
        chunk->crc = count_crc(chunk);
        chunk->next->prev = chunk;
        chunk = chunk->next;
    }
    chunk->next = NULL;
    chunk->size = size;
    chunk->free = 0;
    chunk->crc = count_crc(chunk);
    memset((uint8_t *) chunk + sizeof(struct memory_chunk_t), '#', FENCE_SIZE);
    memset((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
    return (void *) ((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE);
}

void *heap_calloc(size_t number, size_t size) {
    void *memblock = heap_malloc(number * size);
    if (memblock == NULL) {
        return NULL;
    }
    memset(memblock, '\0', number * size);
    return memblock;
}

void *heap_realloc(void *memblock, size_t count) {
    if (memblock == NULL) {
        return heap_malloc(count);
    }
    if (count == 0) {
        heap_free(memblock);
        return NULL;
    }
    if (heap_validate() != 0 || get_pointer_type(memblock) != pointer_valid) {
        return NULL;
    }
    struct memory_chunk_t *chunk = (void *) ((uint8_t *) memblock - sizeof(struct memory_chunk_t) - FENCE_SIZE);
    if (count == chunk->size) {
        return memblock;
    }
    size_t space_between_chunks = 0;
    if (chunk->next) {
        space_between_chunks = (size_t) ((uint8_t *) chunk->next - ((uint8_t *) memblock + chunk->size + FENCE_SIZE));
    }
    if (count <= chunk->size + space_between_chunks) {
        chunk->size = count;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        return memblock;
    }
    size_t padding = (count + FENCE_SIZE) % PADDING_SIZE;
    if (padding) {
        padding = PADDING_SIZE - padding;
    }
    size_t delta = count + padding - chunk->size - space_between_chunks;
    if (chunk->next && chunk->next->free && sizeof(struct memory_chunk_t) + chunk->next->size >= delta) {
        if (chunk->next->size > delta) {
            struct memory_chunk_t *next_next_chunk = chunk->next->next;
            size_t remaining_bytes = chunk->next->size - delta;
            chunk->next = (void *) ((uint8_t *) memblock + count + FENCE_SIZE + padding);
            chunk->size = count;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
            chunk->next->next = next_next_chunk;
            chunk->next->prev = chunk;
            chunk->next->size = remaining_bytes;
            chunk->next->free = 1;
            chunk->next->crc = count_crc(chunk->next);
            if (chunk->next->next) {
                chunk->next->next->prev = chunk->next;
                chunk->next->next->crc = count_crc(chunk->next->next);
            }
        } else {
            chunk->size = count;
            chunk->next = chunk->next->next;
            chunk->crc = count_crc(chunk);
            if (chunk->next) {
                chunk->next->prev = chunk;
                chunk->next->crc = count_crc(chunk->next);
            }
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        }
    } else if (chunk->next == NULL) {
        delta -= padding;
        if (custom_sbrk((int) delta) == (void *) -1) {
            return NULL;
        }
        memory_manager.memory_size += delta;
        chunk->size = count;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
    } else {
        void *new_block = heap_malloc(count);
        if (new_block == NULL) {
            return NULL;
        }
        memcpy(new_block, memblock, chunk->size);
        heap_free(memblock);
        return new_block;
    }
    return memblock;
}

void heap_free(void *memblock) {
    if (heap_validate() != 0 || get_pointer_type(memblock) != pointer_valid) {
        return;
    }
    struct memory_chunk_t *chunk = (void *) ((uint8_t *) memblock - sizeof(struct memory_chunk_t) - FENCE_SIZE);
    chunk->free = 1;
    chunk->size += 2 * FENCE_SIZE;
    if (chunk->next) {
        chunk->size += (size_t) ((uint8_t *) chunk->next - ((uint8_t *) memblock - FENCE_SIZE + chunk->size));
    }
    if (chunk->prev && chunk->prev->free) {
        chunk = chunk->prev;
        merge_chunks(chunk);
    }
    if (chunk->next && chunk->next->free) {
        merge_chunks(chunk);
    }
    chunk->crc = count_crc(chunk);
    if (chunk->next == NULL) {
        size_t bytes_to_clear = sizeof(struct memory_chunk_t) + chunk->size;
        if (chunk->prev == NULL) {
            memory_manager.first_memory_chunk = NULL;
        } else {
            bytes_to_clear += (size_t) ((uint8_t *) chunk -
                                        ((uint8_t *) chunk->prev + sizeof(struct memory_chunk_t) + chunk->prev->size +
                                         2 * FENCE_SIZE));
            chunk = chunk->prev;
            chunk->next = NULL;
            chunk->crc = count_crc(chunk);
        }
        custom_sbrk(-((int) (bytes_to_clear)));
        memory_manager.memory_size -= bytes_to_clear;
    }
}

void merge_chunks(struct memory_chunk_t *chunk) {
    chunk->size += sizeof(struct memory_chunk_t) + chunk->next->size;
    chunk->next = chunk->next->next;
    chunk->crc = count_crc(chunk);
    if (chunk->next) {
        chunk->next->prev = chunk;
        chunk->next->crc = count_crc(chunk->next);
    }
}

void *heap_malloc_aligned(size_t count) {
    if (count < 1 || heap_validate() != 0) {
        return NULL;
    }
    struct memory_chunk_t *chunk = memory_manager.first_memory_chunk;
    while (chunk) {
        if (chunk->free && chunk->size >= count + 2 * FENCE_SIZE &&
            (size_t) ((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE) % PAGE_SIZE_BYTES == 0) {
            chunk->size = count;
            chunk->free = 0;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) chunk + sizeof(struct memory_chunk_t), '#', FENCE_SIZE);
            memset((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
            return (void *) ((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE);
        }
        chunk = chunk->next;
    }
    size_t padding;
    if (memory_manager.first_memory_chunk == NULL) {
        padding = PAGE_SIZE_BYTES - sizeof(struct memory_chunk_t) - FENCE_SIZE;
    } else {
        padding = memory_manager.memory_size % PAGE_SIZE_BYTES;
        if (padding > PAGE_SIZE_BYTES - sizeof(struct memory_chunk_t) - FENCE_SIZE) {
            padding = 2 * PAGE_SIZE_BYTES - padding - sizeof(struct memory_chunk_t) - FENCE_SIZE;
        } else {
            padding = PAGE_SIZE_BYTES - padding - sizeof(struct memory_chunk_t) - FENCE_SIZE;
        }
    }
    size_t delta = padding + sizeof(struct memory_chunk_t) + count + 2 * FENCE_SIZE;
    if (custom_sbrk((int) delta) == (void *) -1) {
        return NULL;
    }
    memory_manager.memory_size += delta;
    if (memory_manager.first_memory_chunk == NULL) {
        memory_manager.first_memory_chunk = (void *) ((uint8_t *) memory_manager.memory_start + padding);
        chunk = memory_manager.first_memory_chunk;
        chunk->prev = NULL;
    } else {
        chunk = memory_manager.first_memory_chunk;
        while (chunk->next) {
            chunk = chunk->next;
        }
        chunk->next = (void *) ((uint8_t *) memory_manager.memory_start + memory_manager.memory_size - delta + padding);
        chunk->crc = count_crc(chunk);
        chunk->next->prev = chunk;
        chunk = chunk->next;
    }
    chunk->next = NULL;
    chunk->size = count;
    chunk->free = 0;
    chunk->crc = count_crc(chunk);
    memset((uint8_t *) chunk + sizeof(struct memory_chunk_t), '#', FENCE_SIZE);
    memset((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
    return (void *) ((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE);
}

void *heap_calloc_aligned(size_t number, size_t size) {
    void *memblock = heap_malloc_aligned(number * size);
    if (memblock == NULL) {
        return NULL;
    }
    memset(memblock, '\0', number * size);
    return memblock;
}

void *heap_realloc_aligned(void *memblock, size_t size) {
    if (memblock == NULL) {
        return heap_malloc_aligned(size);
    }
    if (size == 0) {
        heap_free(memblock);
        return NULL;
    }
    if (heap_validate() != 0 || get_pointer_type(memblock) != pointer_valid) {
        return NULL;
    }
    struct memory_chunk_t *chunk = (void *) ((uint8_t *) memblock - sizeof(struct memory_chunk_t) - FENCE_SIZE);
    if (size == chunk->size) {
        return memblock;
    }
    size_t space_between_chunks = 0;
    if (chunk->next) {
        space_between_chunks += (size_t) ((uint8_t *) chunk->next - ((uint8_t *) memblock + chunk->size + FENCE_SIZE));
    }
    if (size <= chunk->size + space_between_chunks) {
        chunk->size = size;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        return memblock;
    }
    size_t padding = (size + FENCE_SIZE) % PAGE_SIZE_BYTES;
    if (padding > PAGE_SIZE_BYTES - sizeof(struct memory_chunk_t) - FENCE_SIZE) {
        padding = 2 * PAGE_SIZE_BYTES - padding - sizeof(struct memory_chunk_t) - FENCE_SIZE;
    } else {
        padding = PAGE_SIZE_BYTES - padding - sizeof(struct memory_chunk_t) - FENCE_SIZE;
    }
    size_t delta = size + padding - chunk->size - space_between_chunks;
    if (chunk->next && chunk->next->free && sizeof(struct memory_chunk_t) + chunk->next->size >= delta) {
        if (chunk->next->size > delta) {
            struct memory_chunk_t *next_next_chunk = chunk->next->next;
            size_t remaining_bytes = chunk->next->size - delta;
            chunk->next = (void *) ((uint8_t *) memblock + size + FENCE_SIZE + padding);
            chunk->size = size;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
            chunk->next->next = next_next_chunk;
            chunk->next->prev = chunk;
            chunk->next->size = remaining_bytes;
            chunk->next->free = 1;
            chunk->next->crc = count_crc(chunk->next);
            if (chunk->next->next) {
                chunk->next->next->prev = chunk->next;
                chunk->next->next->crc = count_crc(chunk->next->next);
            }
        } else {
            chunk->size = size;
            chunk->next = chunk->next->next;
            chunk->crc = count_crc(chunk);
            if (chunk->next) {
                chunk->next->prev = chunk;
                chunk->next->crc = count_crc(chunk->next);
            }
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        }
    } else if (chunk->next == NULL) {
        if (custom_sbrk((int) delta) == (void *) -1) {
            return NULL;
        }
        memory_manager.memory_size += delta;
        chunk->size = size;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
    } else {
        void *new_block = heap_malloc_aligned(size);
        if (new_block == NULL) {
            return NULL;
        }
        memcpy(new_block, memblock, chunk->size);
        heap_free(memblock);
        return new_block;
    }
    return memblock;
}
