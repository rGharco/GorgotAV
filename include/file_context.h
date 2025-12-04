#pragma once

#include <windows.h>
#include <stdio.h>

typedef struct FileContext FileContext;
typedef struct FileContext* PFileContext;

PFileContext create_file_context(LPCSTR fileName);
void close_file_context(PFileContext fileContext);