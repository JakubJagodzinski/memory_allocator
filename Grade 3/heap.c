#include "heap.h"
#include "custom_unistd.h"
#include <string.h>
#include <stdint.h>

struct memory_manager_t memory_manager;

size_t count_crc(const struct memory_chunk_t *chunk) {
    uint8_t *byte_ptr = (uint8_t *) chunk;
    size_t sum = 0;
    size_t i = 1;
    while (byte_ptr != (uint8_t *) &(chunk->crc)) {
        sum += *byte_ptr++ * i++;
    }
    return sum;
}

enum pointer_type_t get_pointer_type(const void *const pointer) {
    if (pointer == NULL) {
        return pointer_null;
    }
    struct memory_chunk_t *chunk = memory_manager.first_memory_chunk;
    while (chunk) {
        uint8_t *byte_ptr = (uint8_t *) chunk;
        for (size_t i = 0; i < sizeof(struct memory_chunk_t); ++i) {
            if (byte_ptr++ == pointer) {
                return pointer_control_block;
            }
        }
        if (chunk->free == 1) {
            for (size_t i = 0; i < chunk->size; ++i) {
                if (byte_ptr++ == pointer) {
                    return pointer_unallocated;
                }
            }
        } else {
            for (size_t i = 0; i < FENCE_SIZE; ++i) {
                if (byte_ptr++ == pointer) {
                    return pointer_inside_fences;
                }
            }
            if (byte_ptr++ == pointer) {
                return pointer_valid;
            }
            for (size_t i = 1; i < chunk->size; ++i) {
                if (byte_ptr++ == pointer) {
                    return pointer_inside_data_block;
                }
            }
            for (size_t i = 0; i < FENCE_SIZE; ++i) {
                if (byte_ptr++ == pointer) {
                    return pointer_inside_fences;
                }
            }
            if (chunk->next) {
                while (byte_ptr != (uint8_t *) chunk->next) {
                    if (byte_ptr++ == pointer) {
                        return pointer_unallocated;
                    }
                }
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
    size_t padding = 0;
    while (chunk) {
        if (chunk->free && chunk->size >= size + 2 * FENCE_SIZE) {
            chunk->size = size;
            chunk->free = 0;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) chunk + sizeof(struct memory_chunk_t), '#', FENCE_SIZE);
            memset((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
            return (void *) ((uint8_t *) chunk + sizeof(struct memory_chunk_t) + FENCE_SIZE);
        }
        if (chunk->next == NULL) {
            padding = ((size_t) ((uint8_t *) memory_manager.memory_start + memory_manager.memory_size)) % PADDING_SIZE;
            if (padding) {
                padding = PADDING_SIZE - padding;
            }
        }
        chunk = chunk->next;
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
        chunk->next = NULL;
        chunk->size = size;
        chunk->free = 0;
        chunk->crc = count_crc(chunk);
    } else {
        chunk = memory_manager.first_memory_chunk;
        while (chunk->next) {
            chunk = chunk->next;
        }
        chunk->next = (void *) ((uint8_t *) memory_manager.first_memory_chunk + memory_manager.memory_size - delta + padding);
        chunk->crc = count_crc(chunk);
        struct memory_chunk_t *chunk_ptr = chunk;
        chunk = chunk->next;
        chunk->prev = chunk_ptr;
        chunk->next = NULL;
        chunk->size = size;
        chunk->free = 0;
        chunk->crc = count_crc(chunk);
    }
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
    if ((memblock == NULL && count == 0) || heap_validate() != 0 || (get_pointer_type(memblock) != pointer_valid && get_pointer_type(memblock) != pointer_null)) {
        return NULL;
    }
    if (memblock == NULL) {
        return heap_malloc(count);
    }
    if (count == 0) {
        heap_free(memblock);
        return NULL;
    }
    struct memory_chunk_t *chunk = (void *) ((uint8_t *) memblock - sizeof(struct memory_chunk_t) - FENCE_SIZE);
    if (count == chunk->size) {
        return memblock;
    }
    uint8_t *byte_ptr = (uint8_t *) memblock + chunk->size + FENCE_SIZE;
    size_t free_space = chunk->size;
    if (chunk->next) {
        while (byte_ptr++ != (uint8_t *) chunk->next) {
            ++free_space;
        }
    }
    if (count <= free_space) {
        chunk->size = count;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        return memblock;
    }
    size_t padding = ((size_t) ((uint8_t *) memblock + count + FENCE_SIZE)) % PADDING_SIZE;
    if (padding) {
        padding = PADDING_SIZE - padding;
    }
    size_t delta = count + padding - free_space;
    if (chunk->next && chunk->next->free && chunk->next->size + sizeof(struct memory_chunk_t) >= delta) {
        if (chunk->next->size >= delta) {
            struct memory_chunk_t *next_next_chunk = chunk->next->next;
            size_t remaining_bytes = chunk->next->size - delta;
            chunk->size = count;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
            struct memory_chunk_t *next_chunk = (void *) ((uint8_t *) memblock + chunk->size + FENCE_SIZE + padding);
            chunk->next = next_chunk;
            chunk->crc = count_crc(chunk);
            next_chunk->next = next_next_chunk;
            if (next_next_chunk) {
                next_next_chunk->prev = next_chunk;
                next_next_chunk->crc = count_crc(next_next_chunk);
            }
            next_chunk->prev = chunk;
            next_chunk->size = remaining_bytes;
            next_chunk->free = 1;
            next_chunk->crc = count_crc(next_chunk);
        }else {
            chunk->size = count;
            chunk->next=chunk->next->next;
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
    chunk->crc = count_crc(chunk);
    if (chunk->next == NULL) {
        chunk->size += 2 * FENCE_SIZE;
    } else {
        uint8_t *byte_ptr = (uint8_t *) memblock + chunk->size + FENCE_SIZE;
        size_t block_size = chunk->size + 2 * FENCE_SIZE;
        while (byte_ptr++ != (uint8_t *) chunk->next) {
            ++block_size;
        }
        chunk->size = block_size;
    }
    chunk->crc = count_crc(chunk);
    if (chunk->prev && chunk->prev->free) {
        chunk = chunk->prev;
        merge_chunks(chunk);
    }
    if (chunk->next && chunk->next->free) {
        merge_chunks(chunk);
    }
    if (chunk->next == NULL) {
        size_t bytes_to_clear = sizeof(struct memory_chunk_t) + chunk->size;
        if (chunk->prev == NULL) {
            memory_manager.first_memory_chunk = NULL;
        } else {
            uint8_t *byte_ptr = (uint8_t *) chunk->prev + sizeof(struct memory_chunk_t) + chunk->prev->size + 2 * FENCE_SIZE;
            size_t padding = 0;
            while (byte_ptr++ != (uint8_t *) chunk) {
                ++padding;
            }
            bytes_to_clear += padding;
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
