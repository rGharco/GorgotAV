#pragma once

#include <windows.h>
#include <stdio.h>

typedef struct FileContext FileContext;
typedef struct FileContext* PFileContext;

PFileContext create_file_context(LPCSTR fileName);
void close_file_context(PFileContext fileContext);

extern inline HANDLE get_file_handle(const PFileContext fc);
extern inline LPVOID get_base_address(const PFileContext fc);
extern inline WORD get_nr_of_sections(const PFileContext fc);
extern inline PIMAGE_SECTION_HEADER get_ptr_to_section_start(const PFileContext fc);

extern inline void set_nr_of_sections(const PFileContext fc, WORD sectionNr);
extern inline void set_sections_ptr(const PFileContext fc, PIMAGE_SECTION_HEADER ptr);