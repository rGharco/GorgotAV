#pragma once

#include <windows.h>
#include <stdio.h>

typedef struct FileContext FileContext;
typedef struct FileContext* PFileContext;

PFileContext create_file_context(LPCSTR fileName);
void close_file_context(PFileContext fileContext);

HANDLE get_file_handle(const PFileContext fc);
LPVOID get_base_address(const PFileContext fc);