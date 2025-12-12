#include "arena.h"

#define MODULE_NAME "arena.c"

Arena* arena_create(size_t size) {
	Arena* arena = (Arena*)malloc(sizeof(Arena));
	
	if (!arena) {
		log_malloc_error("Could not allocate memory for Arena struct!", MODULE_NAME, __func__);
		return NULL;
	}

	arena->memory = malloc(size);

	if (!arena->memory) {
		log_malloc_error("Could not allocate memory for Arena memory space!", MODULE_NAME, __func__);
		free(arena);
		return NULL;
	}

	arena->size = size;

	return arena;
}

void arena_destroy(Arena* arena) {
	if (arena) {
		free(arena->memory);
		free(arena);
	}
}