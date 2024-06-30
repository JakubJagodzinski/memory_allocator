#include "heap.h"
#include "custom_unistd.h"
#include <string.h>
#include <stdint.h>

struct memory_manager_t memory_manager;

size_t count_crc(const struct memory_chunk_t *chunk) {
    uint8_t *ptr = (uint8_t *) chunk;
    size_t sum = 0;
    while (ptr != (uint8_t *) &chunk->crc) {
        sum += *ptr++;
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
            (uint8_t *) pointer < (uint8_t *) chunk + STRUCT_SIZE) {
            return pointer_control_block;
        }
        if (chunk->free == 1) {
            if ((uint8_t *) pointer >= (uint8_t *) chunk + STRUCT_SIZE &&
                (uint8_t *) pointer < (uint8_t *) chunk + STRUCT_SIZE + chunk->size) {
                return pointer_unallocated;
            }
        } else {
            if ((uint8_t *) pointer >= (uint8_t *) chunk + STRUCT_SIZE &&
                (uint8_t *) pointer < (uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE) {
                return pointer_inside_fences;
            }
            if ((uint8_t *) pointer == (uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE) {
                return pointer_valid;
            }
            if ((uint8_t *) pointer > (uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE &&
                (uint8_t *) pointer < (uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE + chunk->size) {
                return pointer_inside_data_block;
            }
            if ((uint8_t *) pointer >= (uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE + chunk->size &&
                (uint8_t *) pointer <
                (uint8_t *) chunk + STRUCT_SIZE + chunk->size + 2 * FENCE_SIZE) {
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
    custom_sbrk(-((intptr_t) memory_manager.memory_size));
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
        if (chunk->free == 0) {
            uint8_t *ptr = (uint8_t *) chunk + STRUCT_SIZE;
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
            size_t machine_word_padding = size % MACHINE_WORD_SIZE;
            if (machine_word_padding) {
                machine_word_padding = MACHINE_WORD_SIZE - machine_word_padding;
            }
            size_t remaining_size = chunk->size - size - 2 * FENCE_SIZE;
            if (remaining_size > machine_word_padding + STRUCT_SIZE) {
                struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) chunk + STRUCT_SIZE + size + 2 * FENCE_SIZE + machine_word_padding);
                struct memory_chunk_t *chunk_after_free_chunk = chunk->next;
                free_chunk_after->prev = chunk;
                chunk->next = free_chunk_after;
                free_chunk_after->next = chunk_after_free_chunk;
                if (chunk_after_free_chunk) {
                    chunk_after_free_chunk->prev = free_chunk_after;
                    chunk_after_free_chunk->crc = count_crc(free_chunk_after->next);
                }
                free_chunk_after->size = remaining_size - machine_word_padding - STRUCT_SIZE;
                free_chunk_after->free = 1;
                if (chunk_after_free_chunk && chunk_after_free_chunk->free) {
                    merge_chunks(free_chunk_after);
                }
                free_chunk_after->crc = count_crc(free_chunk_after);
            }
            chunk->size = size;
            chunk->free = 0;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) chunk + STRUCT_SIZE, '#', FENCE_SIZE);
            memset((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
            return (void *) ((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE);
        }
        chunk = chunk->next;
    }
    size_t machine_word_padding = memory_manager.memory_size % MACHINE_WORD_SIZE;
    if (machine_word_padding) {
        machine_word_padding = MACHINE_WORD_SIZE - machine_word_padding;
    }
    size_t delta = machine_word_padding + STRUCT_SIZE + size + 2 * FENCE_SIZE;
    if (custom_sbrk((intptr_t) delta) == (void *) -1) {
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
        chunk->next = (void *) ((uint8_t *) memory_manager.memory_start + memory_manager.memory_size - delta + machine_word_padding);
        chunk->next->prev = chunk;
        chunk->crc = count_crc(chunk);
        chunk = chunk->next;
    }
    chunk->next = NULL;
    chunk->size = size;
    chunk->free = 0;
    chunk->crc = count_crc(chunk);
    memset((uint8_t *) chunk + STRUCT_SIZE, '#', FENCE_SIZE);
    memset((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
    return (void *) ((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE);
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
    struct memory_chunk_t *chunk = (void *) ((uint8_t *) memblock - FENCE_SIZE - STRUCT_SIZE);
    if (count == chunk->size) {
        return memblock;
    }
    size_t space_after_chunk = 0;
    if (chunk->next) {
        space_after_chunk = (size_t) ((uint8_t *) chunk->next - ((uint8_t *) memblock + chunk->size + FENCE_SIZE));
    }
    size_t machine_word_padding = count % MACHINE_WORD_SIZE;
    if (machine_word_padding) {
        machine_word_padding = MACHINE_WORD_SIZE - machine_word_padding;
    }
    if (count <= chunk->size + space_after_chunk) {
        size_t remaining_size = chunk->size + space_after_chunk - count;
        if (remaining_size > machine_word_padding + STRUCT_SIZE) {
            struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) chunk + STRUCT_SIZE + count + 2 * FENCE_SIZE + machine_word_padding);
            struct memory_chunk_t *chunk_after_free_chunk = chunk->next;
            free_chunk_after->prev = chunk;
            chunk->next = free_chunk_after;
            free_chunk_after->next = chunk_after_free_chunk;
            if (chunk_after_free_chunk) {
                chunk_after_free_chunk->prev = free_chunk_after;
                chunk_after_free_chunk->crc = count_crc(free_chunk_after->next);
            }
            free_chunk_after->size = remaining_size - machine_word_padding - STRUCT_SIZE;
            free_chunk_after->free = 1;
            if (chunk_after_free_chunk && chunk_after_free_chunk->free) {
                merge_chunks(free_chunk_after);
            }
            free_chunk_after->crc = count_crc(free_chunk_after);
        }
        chunk->size = count;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        return memblock;
    }
    size_t delta = count - chunk->size - space_after_chunk + machine_word_padding;
    if (chunk->next && chunk->next->free && STRUCT_SIZE + chunk->next->size >= delta) {
        if (chunk->next->size > delta) {
            struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) memblock + count + FENCE_SIZE + machine_word_padding);
            struct memory_chunk_t *chunk_after_free_chunk = chunk->next->next;
            size_t remaining_bytes = chunk->next->size - delta;
            free_chunk_after->next = chunk_after_free_chunk;
            free_chunk_after->prev = chunk;
            chunk->next = free_chunk_after;
            chunk->size = count;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
            free_chunk_after->size = remaining_bytes;
            free_chunk_after->free = 1;
            free_chunk_after->crc = count_crc(free_chunk_after);
            if (chunk_after_free_chunk) {
                chunk_after_free_chunk->prev = free_chunk_after;
                chunk_after_free_chunk->crc = count_crc(chunk_after_free_chunk);
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
        delta -= machine_word_padding;
        if (custom_sbrk((intptr_t) delta) == (void *) -1) {
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
    struct memory_chunk_t *chunk = (void *) ((uint8_t *) memblock - STRUCT_SIZE - FENCE_SIZE);
    chunk->free = 1;
    chunk->size += 2 * FENCE_SIZE;
    if (chunk->next) {
        chunk->size += (size_t) ((uint8_t *) chunk->next - ((uint8_t *) chunk + STRUCT_SIZE + chunk->size));
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
        size_t bytes_to_clear = STRUCT_SIZE + chunk->size;
        if (chunk->prev == NULL) {
            memory_manager.first_memory_chunk = NULL;
        } else {
            bytes_to_clear += (size_t) ((uint8_t *) chunk - ((uint8_t *) chunk->prev + STRUCT_SIZE + chunk->prev->size + 2 * FENCE_SIZE));
            chunk = chunk->prev;
            chunk->next = NULL;
            chunk->crc = count_crc(chunk);
        }
        custom_sbrk(-((intptr_t) (bytes_to_clear)));
        memory_manager.memory_size -= bytes_to_clear;
    }
}

void merge_chunks(struct memory_chunk_t *chunk) {
    chunk->size += STRUCT_SIZE + chunk->next->size;
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
        size_t page_size_padding = (intptr_t) chunk % MEMORY_PAGE_SIZE;
        if (page_size_padding) {
            page_size_padding = MEMORY_PAGE_SIZE - page_size_padding;
            if (page_size_padding < STRUCT_SIZE + FENCE_SIZE) {
                page_size_padding += MEMORY_PAGE_SIZE;
            }
        } else {
            page_size_padding = MEMORY_PAGE_SIZE;
        }
        if (chunk->free && STRUCT_SIZE + chunk->size >= page_size_padding + count + FENCE_SIZE) {
            struct memory_chunk_t *new_chunk = (void *) ((uint8_t *) chunk + page_size_padding - STRUCT_SIZE - FENCE_SIZE);
            struct memory_chunk_t *prev_chunk = chunk->prev;
            struct memory_chunk_t *next_chunk = chunk->next;
            struct memory_chunk_t *free_chunk_before = NULL;
            struct memory_chunk_t *free_chunk_after = NULL;
            uint8_t *space_address = (uint8_t *) chunk;
            size_t space_size = STRUCT_SIZE + chunk->size;
            size_t remaining_size_before = page_size_padding - STRUCT_SIZE - FENCE_SIZE;
            if (remaining_size_before > STRUCT_SIZE) {
                free_chunk_before = chunk;
                free_chunk_before->next = new_chunk;
                new_chunk->prev = free_chunk_before;
                free_chunk_before->size = remaining_size_before - STRUCT_SIZE;
                free_chunk_before->free = 1;
                free_chunk_before->crc = count_crc(free_chunk_before);
            } else {
                new_chunk->prev = prev_chunk;
                if (prev_chunk) {
                    prev_chunk->next = new_chunk;
                    prev_chunk->crc = count_crc(prev_chunk);
                }
            }
            size_t machine_word_padding_after = (page_size_padding + count) % MACHINE_WORD_SIZE;
            if (machine_word_padding_after) {
                machine_word_padding_after = MACHINE_WORD_SIZE - machine_word_padding_after;
            }
            size_t remaining_size_after = space_size - page_size_padding - count - FENCE_SIZE;
            if (remaining_size_after > machine_word_padding_after + STRUCT_SIZE) {
                free_chunk_after = (void *) (space_address + page_size_padding + count + FENCE_SIZE + machine_word_padding_after);
                free_chunk_after->prev = new_chunk;
                new_chunk->next = free_chunk_after;
                free_chunk_after->next = next_chunk;
                if (next_chunk) {
                    next_chunk->prev = free_chunk_after;
                    next_chunk->crc = count_crc(next_chunk);
                }
                free_chunk_after->size = remaining_size_after - machine_word_padding_after - STRUCT_SIZE;
                free_chunk_after->free = 1;
                free_chunk_after->crc = count_crc(free_chunk_after);
            } else {
                new_chunk->next = next_chunk;
                if (next_chunk) {
                    next_chunk->prev = new_chunk;
                    next_chunk->crc = count_crc(next_chunk);
                }
            }
            new_chunk->size = count;
            new_chunk->free = 0;
            new_chunk->crc = count_crc(new_chunk);
            memset((uint8_t *) new_chunk + STRUCT_SIZE, '#', FENCE_SIZE);
            memset((uint8_t *) new_chunk + STRUCT_SIZE + FENCE_SIZE + new_chunk->size, '#', FENCE_SIZE);
            return (void *) ((uint8_t *) new_chunk + STRUCT_SIZE + FENCE_SIZE);
        }
        chunk = chunk->next;
    }
    size_t page_size_padding = memory_manager.memory_size % MEMORY_PAGE_SIZE;
    if (page_size_padding) {
        page_size_padding = MEMORY_PAGE_SIZE - page_size_padding;
        if (page_size_padding < STRUCT_SIZE + FENCE_SIZE) {
            page_size_padding += MEMORY_PAGE_SIZE;
        }
    } else {
        page_size_padding = MEMORY_PAGE_SIZE;
    }
    size_t delta = page_size_padding + count + FENCE_SIZE;
    if (custom_sbrk((intptr_t) delta) == (void *) -1) {
        return NULL;
    }
    memory_manager.memory_size += delta;
    if (memory_manager.first_memory_chunk == NULL) {
        memory_manager.first_memory_chunk = memory_manager.memory_start;
        chunk = memory_manager.first_memory_chunk;
        chunk->prev = NULL;
        chunk->next = (void *) ((uint8_t *) memory_manager.memory_start + page_size_padding - STRUCT_SIZE - FENCE_SIZE);
        chunk->next->prev = chunk;
        chunk->size = page_size_padding - 2 * STRUCT_SIZE - FENCE_SIZE;
        chunk->free = 1;
        chunk->crc = count_crc(chunk);
        chunk = chunk->next;
    } else {
        chunk = memory_manager.first_memory_chunk;
        while (chunk->next) {
            chunk = chunk->next;
        }
        struct memory_chunk_t *free_chunk_before = NULL;
        size_t free_chunk_padding = chunk->size % MACHINE_WORD_SIZE;
        if (free_chunk_padding) {
            free_chunk_padding = MACHINE_WORD_SIZE - free_chunk_padding;
        }
        if (page_size_padding - STRUCT_SIZE - FENCE_SIZE > free_chunk_padding + STRUCT_SIZE) {
            if (chunk->free) {
                free_chunk_before = (void *) ((uint8_t *) chunk + STRUCT_SIZE + chunk->size + free_chunk_padding);
            } else {
                free_chunk_before = (void *) ((uint8_t *) chunk + STRUCT_SIZE + chunk->size + 2 * FENCE_SIZE + free_chunk_padding);
            }
        }
        struct memory_chunk_t *new_chunk = (void *) ((uint8_t *) memory_manager.memory_start + memory_manager.memory_size - delta + page_size_padding - STRUCT_SIZE - FENCE_SIZE);
        if (free_chunk_before) {
            chunk->next = free_chunk_before;
            new_chunk->prev = free_chunk_before;
            free_chunk_before->prev = chunk;
            free_chunk_before->next = new_chunk;
            free_chunk_before->size = page_size_padding - free_chunk_padding - 2 * STRUCT_SIZE - FENCE_SIZE;
            free_chunk_before->free = 1;
            free_chunk_before->crc = count_crc(free_chunk_before);
        } else {
            chunk->next = new_chunk;
            new_chunk->prev = chunk;
        }
        chunk->crc = count_crc(chunk);
        chunk = new_chunk;
    }
    chunk->next = NULL;
    chunk->size = count;
    chunk->free = 0;
    chunk->crc = count_crc(chunk);
    memset((uint8_t *) chunk + STRUCT_SIZE, '#', FENCE_SIZE);
    memset((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
    return (void *) ((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE);
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
    struct memory_chunk_t *chunk = (void *) ((uint8_t *) memblock - FENCE_SIZE - STRUCT_SIZE);
    if (size == chunk->size) {
        return memblock;
    }
    size_t space_after_chunk = 0;
    if (chunk->next) {
        space_after_chunk += (size_t) ((uint8_t *) chunk->next - ((uint8_t *) memblock + chunk->size + FENCE_SIZE));
    }
    size_t page_size_padding = (intptr_t) memblock % MEMORY_PAGE_SIZE;
    if (page_size_padding) {
        page_size_padding = MEMORY_PAGE_SIZE - page_size_padding;
        if (page_size_padding < STRUCT_SIZE + FENCE_SIZE) {
            page_size_padding += MEMORY_PAGE_SIZE;
        }
    }
    if (size <= chunk->size + space_after_chunk) {
        size_t remaining_size = chunk->size + space_after_chunk - size;
        if (remaining_size > STRUCT_SIZE + page_size_padding) {
            struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) chunk + STRUCT_SIZE + size +
                                                                2 * FENCE_SIZE + page_size_padding);
            struct memory_chunk_t *chunk_after_free_chunk = chunk->next;
            free_chunk_after->prev = chunk;
            chunk->next = free_chunk_after;
            free_chunk_after->next = chunk_after_free_chunk;
            if (chunk_after_free_chunk) {
                chunk_after_free_chunk->prev = free_chunk_after;
                chunk_after_free_chunk->crc = count_crc(chunk_after_free_chunk);
            }
            free_chunk_after->size = remaining_size - STRUCT_SIZE - page_size_padding;
            free_chunk_after->free = 1;
            if (chunk_after_free_chunk && chunk_after_free_chunk->free) {
                merge_chunks(free_chunk_after);
            }
            free_chunk_after->crc = count_crc(free_chunk_after);
        }
        chunk->size = size;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        return memblock;
    }
    size_t delta = size + page_size_padding - chunk->size - space_after_chunk;
    if (chunk->next && chunk->next->free && STRUCT_SIZE + chunk->next->size >= delta) {
        if (chunk->next->size > delta) {
            struct memory_chunk_t *chunk_after_free_chunk = chunk->next->next;
            size_t free_chunk_size = chunk->next->size - delta;
            struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) memblock + size + FENCE_SIZE + page_size_padding);
            chunk->next = free_chunk_after;
            free_chunk_after->prev = chunk;
            free_chunk_after->next = chunk_after_free_chunk;
            if (chunk_after_free_chunk) {
                chunk_after_free_chunk->prev = free_chunk_after;
                chunk_after_free_chunk->crc = count_crc(chunk_after_free_chunk);
            }
            free_chunk_after->size = free_chunk_size;
            free_chunk_after->free = 1;
            free_chunk_after->crc = count_crc(free_chunk_after);
            chunk->size = size;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
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
        delta -= page_size_padding;
        if (custom_sbrk((intptr_t) delta) == (void *) -1) {
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

void *heap_malloc_debug(size_t count, int fileline, const char *filename) {
    if (count < 1 || heap_validate() != 0) {
        return NULL;
    }
    struct memory_chunk_t *chunk = memory_manager.first_memory_chunk;
    while (chunk) {
        if (chunk->free && chunk->size >= count + 2 * FENCE_SIZE) {
            size_t machine_word_padding = count % MACHINE_WORD_SIZE;
            if (machine_word_padding) {
                machine_word_padding = MACHINE_WORD_SIZE - machine_word_padding;
            }
            size_t remaining_size = chunk->size - count - 2 * FENCE_SIZE;
            if (remaining_size > machine_word_padding + STRUCT_SIZE) {
                struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) chunk + STRUCT_SIZE + count + 2 * FENCE_SIZE + machine_word_padding);
                struct memory_chunk_t *chunk_after_free_chunk = chunk->next;
                free_chunk_after->prev = chunk;
                chunk->next = free_chunk_after;
                free_chunk_after->next = chunk_after_free_chunk;
                if (chunk_after_free_chunk) {
                    chunk_after_free_chunk->prev = free_chunk_after;
                    chunk_after_free_chunk->crc = count_crc(free_chunk_after->next);
                }
                free_chunk_after->size = remaining_size - machine_word_padding - STRUCT_SIZE;
                free_chunk_after->free = 1;
                if (chunk_after_free_chunk && chunk_after_free_chunk->free) {
                    merge_chunks(free_chunk_after);
                }
                free_chunk_after->filename = (char *) filename;
                free_chunk_after->fileline = fileline;
                free_chunk_after->crc = count_crc(free_chunk_after);
            }
            chunk->size = count;
            chunk->free = 0;
            chunk->filename = (char *) filename;
            chunk->fileline = fileline;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) chunk + STRUCT_SIZE, '#', FENCE_SIZE);
            memset((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
            return (void *) ((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE);
        }
        chunk = chunk->next;
    }
    size_t machine_word_padding = memory_manager.memory_size % MACHINE_WORD_SIZE;
    if (machine_word_padding) {
        machine_word_padding = MACHINE_WORD_SIZE - machine_word_padding;
    }
    size_t delta = machine_word_padding + STRUCT_SIZE + count + 2 * FENCE_SIZE;
    if (custom_sbrk((intptr_t) delta) == (void *) -1) {
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
        chunk->next = (void *) ((uint8_t *) memory_manager.memory_start + memory_manager.memory_size - delta + machine_word_padding);
        chunk->next->prev = chunk;
        chunk->crc = count_crc(chunk);
        chunk = chunk->next;
    }
    chunk->next = NULL;
    chunk->size = count;
    chunk->free = 0;
    chunk->filename = (char *) filename;
    chunk->fileline = fileline;
    chunk->crc = count_crc(chunk);
    memset((uint8_t *) chunk + STRUCT_SIZE, '#', FENCE_SIZE);
    memset((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
    return (void *) ((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE);
}

void *heap_calloc_debug(size_t number, size_t size, int fileline, const char *filename) {
    void *memblock = heap_malloc_debug(number * size, fileline, filename);
    if (memblock == NULL) {
        return NULL;
    }
    memset(memblock, '\0', number * size);
    return memblock;
}

void *heap_realloc_debug(void *memblock, size_t size, int fileline, const char *filename) {
    if (memblock == NULL) {
        return heap_malloc_debug(size, fileline, filename);
    }
    if (size == 0) {
        heap_free(memblock);
        return NULL;
    }
    if (heap_validate() != 0 || get_pointer_type(memblock) != pointer_valid) {
        return NULL;
    }
    struct memory_chunk_t *chunk = (void *) ((uint8_t *) memblock - FENCE_SIZE - STRUCT_SIZE);
    if (size == chunk->size) {
        return memblock;
    }
    size_t space_after_chunk = 0;
    if (chunk->next) {
        space_after_chunk = (size_t) ((uint8_t *) chunk->next - ((uint8_t *) memblock + chunk->size + FENCE_SIZE));
    }
    size_t machine_word_padding = size % MACHINE_WORD_SIZE;
    if (machine_word_padding) {
        machine_word_padding = MACHINE_WORD_SIZE - machine_word_padding;
    }
    if (size <= chunk->size + space_after_chunk) {
        size_t remaining_size = chunk->size + space_after_chunk - size;
        if (remaining_size > machine_word_padding + STRUCT_SIZE) {
            struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) chunk + STRUCT_SIZE + size + 2 * FENCE_SIZE + machine_word_padding);
            struct memory_chunk_t *chunk_after_free_chunk = chunk->next;
            free_chunk_after->prev = chunk;
            chunk->next = free_chunk_after;
            free_chunk_after->next = chunk_after_free_chunk;
            if (chunk_after_free_chunk) {
                chunk_after_free_chunk->prev = free_chunk_after;
                chunk_after_free_chunk->crc = count_crc(free_chunk_after->next);
            }
            free_chunk_after->size = remaining_size - machine_word_padding - STRUCT_SIZE;
            free_chunk_after->free = 1;
            if (chunk_after_free_chunk && chunk_after_free_chunk->free) {
                merge_chunks(free_chunk_after);
            }
            free_chunk_after->filename = (char *) filename;
            free_chunk_after->fileline = fileline;
            free_chunk_after->crc = count_crc(free_chunk_after);
        }
        chunk->size = size;
        chunk->filename = (char *) filename;
        chunk->fileline = fileline;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        return memblock;
    }
    size_t delta = size - chunk->size - space_after_chunk + machine_word_padding;
    if (chunk->next && chunk->next->free && STRUCT_SIZE + chunk->next->size >= delta) {
        if (chunk->next->size > delta) {
            struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) memblock + size + FENCE_SIZE + machine_word_padding);
            struct memory_chunk_t *chunk_after_free_chunk = chunk->next->next;
            size_t remaining_bytes = chunk->next->size - delta;
            free_chunk_after->next = chunk_after_free_chunk;
            free_chunk_after->prev = chunk;
            chunk->next = free_chunk_after;
            chunk->size = size;
            chunk->filename = (char *) filename;
            chunk->fileline = fileline;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
            free_chunk_after->size = remaining_bytes;
            free_chunk_after->free = 1;
            free_chunk_after->filename = (char *) filename;
            free_chunk_after->fileline = fileline;
            free_chunk_after->crc = count_crc(free_chunk_after);
            if (chunk_after_free_chunk) {
                chunk_after_free_chunk->prev = free_chunk_after;
                chunk_after_free_chunk->crc = count_crc(chunk_after_free_chunk);
            }
        } else {
            chunk->size = size;
            chunk->next = chunk->next->next;
            chunk->filename = (char *) filename;
            chunk->fileline = fileline;
            chunk->crc = count_crc(chunk);
            if (chunk->next) {
                chunk->next->prev = chunk;
                chunk->next->crc = count_crc(chunk->next);
            }
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        }
    } else if (chunk->next == NULL) {
        delta -= machine_word_padding;
        if (custom_sbrk((intptr_t) delta) == (void *) -1) {
            return NULL;
        }
        memory_manager.memory_size += delta;
        chunk->size = size;
        chunk->filename = (char *) filename;
        chunk->fileline = fileline;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
    } else {
        void *new_block = heap_malloc_debug(size, fileline, filename);
        if (new_block == NULL) {
            return NULL;
        }
        memcpy(new_block, memblock, chunk->size);
        heap_free(memblock);
        return new_block;
    }
    return memblock;
}

void *heap_malloc_aligned_debug(size_t count, int fileline, const char *filename) {
    if (count < 1 || heap_validate() != 0) {
        return NULL;
    }
    struct memory_chunk_t *chunk = memory_manager.first_memory_chunk;
    while (chunk) {
        size_t page_size_padding = (intptr_t) chunk % MEMORY_PAGE_SIZE;
        if (page_size_padding) {
            page_size_padding = MEMORY_PAGE_SIZE - page_size_padding;
            if (page_size_padding < STRUCT_SIZE + FENCE_SIZE) {
                page_size_padding += MEMORY_PAGE_SIZE;
            }
        } else {
            page_size_padding = MEMORY_PAGE_SIZE;
        }
        if (chunk->free && STRUCT_SIZE + chunk->size >= page_size_padding + count + FENCE_SIZE) {
            struct memory_chunk_t *new_chunk = (void *) ((uint8_t *) chunk + page_size_padding - STRUCT_SIZE - FENCE_SIZE);
            struct memory_chunk_t *prev_chunk = chunk->prev;
            struct memory_chunk_t *next_chunk = chunk->next;
            struct memory_chunk_t *free_chunk_before = NULL;
            struct memory_chunk_t *free_chunk_after = NULL;
            uint8_t *space_address = (uint8_t *) chunk;
            size_t space_size = STRUCT_SIZE + chunk->size;
            size_t remaining_size_before = page_size_padding - STRUCT_SIZE - FENCE_SIZE;
            if (remaining_size_before > STRUCT_SIZE) {
                free_chunk_before = chunk;
                free_chunk_before->next = new_chunk;
                new_chunk->prev = free_chunk_before;
                free_chunk_before->size = remaining_size_before - STRUCT_SIZE;
                free_chunk_before->free = 1;
                free_chunk_before->filename = (char *) filename;
                free_chunk_before->fileline = fileline;
                free_chunk_before->crc = count_crc(free_chunk_before);
            } else {
                new_chunk->prev = prev_chunk;
                if (prev_chunk) {
                    prev_chunk->next = new_chunk;
                    prev_chunk->crc = count_crc(prev_chunk);
                }
            }
            size_t machine_word_padding_after = (page_size_padding + count) % MACHINE_WORD_SIZE;
            if (machine_word_padding_after) {
                machine_word_padding_after = MACHINE_WORD_SIZE - machine_word_padding_after;
            }
            size_t remaining_size_after = space_size - page_size_padding - count - FENCE_SIZE;
            if (remaining_size_after > machine_word_padding_after + STRUCT_SIZE) {
                free_chunk_after = (void *) (space_address + page_size_padding + count + FENCE_SIZE + machine_word_padding_after);
                free_chunk_after->prev = new_chunk;
                new_chunk->next = free_chunk_after;
                free_chunk_after->next = next_chunk;
                if (next_chunk) {
                    next_chunk->prev = free_chunk_after;
                    next_chunk->crc = count_crc(next_chunk);
                }
                free_chunk_after->size = remaining_size_after - machine_word_padding_after - STRUCT_SIZE;
                free_chunk_after->free = 1;
                free_chunk_after->filename = (char *) filename;
                free_chunk_after->fileline = fileline;
                free_chunk_after->crc = count_crc(free_chunk_after);
            } else {
                new_chunk->next = next_chunk;
                if (next_chunk) {
                    next_chunk->prev = new_chunk;
                    next_chunk->crc = count_crc(next_chunk);
                }
            }
            new_chunk->size = count;
            new_chunk->free = 0;
            new_chunk->filename = (char *) filename;
            new_chunk->fileline = fileline;
            new_chunk->crc = count_crc(new_chunk);
            memset((uint8_t *) new_chunk + STRUCT_SIZE, '#', FENCE_SIZE);
            memset((uint8_t *) new_chunk + STRUCT_SIZE + FENCE_SIZE + new_chunk->size, '#', FENCE_SIZE);
            return (void *) ((uint8_t *) new_chunk + STRUCT_SIZE + FENCE_SIZE);
        }
        chunk = chunk->next;
    }
    size_t page_size_padding = memory_manager.memory_size % MEMORY_PAGE_SIZE;
    if (page_size_padding) {
        page_size_padding = MEMORY_PAGE_SIZE - page_size_padding;
        if (page_size_padding < STRUCT_SIZE + FENCE_SIZE) {
            page_size_padding += MEMORY_PAGE_SIZE;
        }
    } else {
        page_size_padding = MEMORY_PAGE_SIZE;
    }
    size_t delta = page_size_padding + count + FENCE_SIZE;
    if (custom_sbrk((intptr_t) delta) == (void *) -1) {
        return NULL;
    }
    memory_manager.memory_size += delta;
    if (memory_manager.first_memory_chunk == NULL) {
        memory_manager.first_memory_chunk = memory_manager.memory_start;
        chunk = memory_manager.first_memory_chunk;
        chunk->prev = NULL;
        chunk->next = (void *) ((uint8_t *) memory_manager.memory_start + page_size_padding - STRUCT_SIZE - FENCE_SIZE);
        chunk->next->prev = chunk;
        chunk->size = page_size_padding - 2 * STRUCT_SIZE - FENCE_SIZE;
        chunk->free = 1;
        chunk->filename = (char *) filename;
        chunk->fileline = fileline;
        chunk->crc = count_crc(chunk);
        chunk = chunk->next;
    } else {
        chunk = memory_manager.first_memory_chunk;
        while (chunk->next) {
            chunk = chunk->next;
        }
        struct memory_chunk_t *free_chunk_before = NULL;
        size_t free_chunk_padding = chunk->size % MACHINE_WORD_SIZE;
        if (free_chunk_padding) {
            free_chunk_padding = MACHINE_WORD_SIZE - free_chunk_padding;
        }
        if (page_size_padding - STRUCT_SIZE - FENCE_SIZE > free_chunk_padding + STRUCT_SIZE) {
            if (chunk->free) {
                free_chunk_before = (void *) ((uint8_t *) chunk + STRUCT_SIZE + chunk->size + free_chunk_padding);
            } else {
                free_chunk_before = (void *) ((uint8_t *) chunk + STRUCT_SIZE + chunk->size + 2 * FENCE_SIZE + free_chunk_padding);
            }
        }
        struct memory_chunk_t *new_chunk = (void *) ((uint8_t *) memory_manager.memory_start + memory_manager.memory_size - delta + page_size_padding - STRUCT_SIZE - FENCE_SIZE);
        if (free_chunk_before) {
            chunk->next = free_chunk_before;
            new_chunk->prev = free_chunk_before;
            free_chunk_before->prev = chunk;
            free_chunk_before->next = new_chunk;
            free_chunk_before->size = page_size_padding - free_chunk_padding - 2 * STRUCT_SIZE - FENCE_SIZE;
            free_chunk_before->free = 1;
            free_chunk_before->filename = (char *) filename;
            free_chunk_before->fileline = fileline;
            free_chunk_before->crc = count_crc(free_chunk_before);
        } else {
            chunk->next = new_chunk;
            new_chunk->prev = chunk;
        }
        chunk->crc = count_crc(chunk);
        chunk = new_chunk;
    }
    chunk->next = NULL;
    chunk->size = count;
    chunk->free = 0;
    chunk->filename = (char *) filename;
    chunk->fileline = fileline;
    chunk->crc = count_crc(chunk);
    memset((uint8_t *) chunk + STRUCT_SIZE, '#', FENCE_SIZE);
    memset((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE + chunk->size, '#', FENCE_SIZE);
    return (void *) ((uint8_t *) chunk + STRUCT_SIZE + FENCE_SIZE);
}

void *heap_calloc_aligned_debug(size_t number, size_t size, int fileline, const char *filename) {
    void *memblock = heap_malloc_aligned_debug(number * size, fileline, filename);
    if (memblock == NULL) {
        return NULL;
    }
    memset(memblock, '\0', number * size);
    return memblock;
}

void *heap_realloc_aligned_debug(void *memblock, size_t size, int fileline, const char *filename) {
    if (memblock == NULL) {
        return heap_malloc_aligned_debug(size, fileline, filename);
    }
    if (size == 0) {
        heap_free(memblock);
        return NULL;
    }
    if (heap_validate() != 0 || get_pointer_type(memblock) != pointer_valid) {
        return NULL;
    }
    struct memory_chunk_t *chunk = (void *) ((uint8_t *) memblock - FENCE_SIZE - STRUCT_SIZE);
    if (size == chunk->size) {
        return memblock;
    }
    size_t space_after_chunk = 0;
    if (chunk->next) {
        space_after_chunk += (size_t) ((uint8_t *) chunk->next - ((uint8_t *) memblock + chunk->size + FENCE_SIZE));
    }
    size_t page_size_padding = (intptr_t) memblock % MEMORY_PAGE_SIZE;
    if (page_size_padding) {
        page_size_padding = MEMORY_PAGE_SIZE - page_size_padding;
        if (page_size_padding < STRUCT_SIZE + FENCE_SIZE) {
            page_size_padding += MEMORY_PAGE_SIZE;
        }
    }
    if (size <= chunk->size + space_after_chunk) {
        size_t remaining_size = chunk->size + space_after_chunk - size;
        if (remaining_size > STRUCT_SIZE + page_size_padding) {
            struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) chunk + STRUCT_SIZE + size + 2 * FENCE_SIZE + page_size_padding);
            struct memory_chunk_t *chunk_after_free_chunk = chunk->next;
            free_chunk_after->prev = chunk;
            chunk->next = free_chunk_after;
            free_chunk_after->next = chunk_after_free_chunk;
            if (chunk_after_free_chunk) {
                chunk_after_free_chunk->prev = free_chunk_after;
                chunk_after_free_chunk->crc = count_crc(chunk_after_free_chunk);
            }
            free_chunk_after->size = remaining_size - STRUCT_SIZE - page_size_padding;
            free_chunk_after->free = 1;
            if (chunk_after_free_chunk && chunk_after_free_chunk->free) {
                merge_chunks(free_chunk_after);
            }
            free_chunk_after->filename = (char *) filename;
            free_chunk_after->fileline = fileline;
            free_chunk_after->crc = count_crc(free_chunk_after);
        }
        chunk->size = size;
        chunk->filename = (char *) filename;
        chunk->fileline = fileline;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        return memblock;
    }
    size_t delta = size + page_size_padding - chunk->size - space_after_chunk;
    if (chunk->next && chunk->next->free && STRUCT_SIZE + chunk->next->size >= delta) {
        if (chunk->next->size > delta) {
            struct memory_chunk_t *chunk_after_free_chunk = chunk->next->next;
            size_t free_chunk_size = chunk->next->size - delta;
            struct memory_chunk_t *free_chunk_after = (void *) ((uint8_t *) memblock + size + FENCE_SIZE + page_size_padding);
            chunk->next = free_chunk_after;
            free_chunk_after->prev = chunk;
            free_chunk_after->next = chunk_after_free_chunk;
            if (chunk_after_free_chunk) {
                chunk_after_free_chunk->prev = free_chunk_after;
                chunk_after_free_chunk->crc = count_crc(chunk_after_free_chunk);
            }
            free_chunk_after->size = free_chunk_size;
            free_chunk_after->free = 1;
            free_chunk_after->filename = (char *) filename;
            free_chunk_after->fileline = fileline;
            free_chunk_after->crc = count_crc(free_chunk_after);
            chunk->size = size;
            chunk->filename = (char *) filename;
            chunk->fileline = fileline;
            chunk->crc = count_crc(chunk);
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        } else {
            chunk->size = size;
            chunk->next = chunk->next->next;
            chunk->filename = (char *) filename;
            chunk->fileline = fileline;
            chunk->crc = count_crc(chunk);
            if (chunk->next) {
                chunk->next->prev = chunk;
                chunk->next->crc = count_crc(chunk->next);
            }
            memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
        }
    } else if (chunk->next == NULL) {
        delta -= page_size_padding;
        if (custom_sbrk((intptr_t) delta) == (void *) -1) {
            return NULL;
        }
        memory_manager.memory_size += delta;
        chunk->size = size;
        chunk->filename = (char *) filename;
        chunk->fileline = fileline;
        chunk->crc = count_crc(chunk);
        memset((uint8_t *) memblock + chunk->size, '#', FENCE_SIZE);
    } else {
        void *new_block = heap_malloc_aligned_debug(size, fileline, filename);
        if (new_block == NULL) {
            return NULL;
        }
        memcpy(new_block, memblock, chunk->size);
        heap_free(memblock);
        return new_block;
    }
    return memblock;
}
