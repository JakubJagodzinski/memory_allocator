#include "heap.h"

int main() {
    heap_setup();
    heap_realloc(NULL, 0);
    heap_calloc(0, 0);
    heap_get_largest_used_block_size();
    heap_clean();
    return 0;
}
