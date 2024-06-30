#include "heap.h"

int main() {
    heap_setup();
    heap_realloc(NULL, 0);
    heap_realloc_debug(NULL, 0, 0, NULL);
    heap_realloc_aligned(NULL, 0);
    heap_realloc_aligned_debug(NULL, 0, 0, NULL);
    heap_calloc(0, 0);
    heap_calloc_debug(0, 0, 0, NULL);
    heap_calloc_aligned(0, 0);
    heap_calloc_aligned_debug(0, 0, 0, NULL);
    heap_get_largest_used_block_size();
    heap_clean();
    return 0;
}
