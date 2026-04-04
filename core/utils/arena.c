#include "../include/arena.h"

#define MODULE_NAME "arena.c"

Arena* arena_create(size_t size) {
	Arena* arena = (Arena*)malloc(sizeof(Arena));
	
	if (!arena || errno != 0) {
		log_error(errno, MODULE_NAME, __func__, strerror(errno), "");
		
		return NULL;
	}

	arena->memory = malloc(size);

	if (!arena->memory) {
		log_error(errno, MODULE_NAME, __func__, strerror(errno), "");
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