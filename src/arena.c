#include "arena.h"

#define MODULE_NAME "arena.c"

Arena* arena_create(size_t size) {
	Arena* arena = (Arena*)malloc(sizeof(Arena));
	
	if (!arena) {
		log_error(errno, "arena.c", __func__, "Failed to allocate memory for Arena struct!",
			"Default error code was overwritten to the corresponding errno for malloc");
		perror(strerror(errno));
		return NULL;
	}

	arena->memory = malloc(size);

	if (!arena->memory) {
		log_error(errno, "arena.c", __func__, "Failed to allocate memory for Arena memory!",
			"Default error code was overwritten to the corresponding errno for malloc");
		perror(strerror(errno));
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