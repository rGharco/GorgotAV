#pragma once

#include "logging.h"

#include <stdio.h>
#include <windows.h>

typedef struct Arena {
	void* memory;
	size_t size;
}Arena;

Arena* arena_create(size_t size);
void arena_destroy(Arena* arena);