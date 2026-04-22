#pragma once

#include <windows.h>
#include <stdio.h>

typedef struct FileContext FileContext;
typedef struct FileContext* PFileContext;

typedef enum PeFormat PeFormat;

enum PeFormat {
    PE32,
    PE32_PLUS
};

PFileContext create_file_context(LPCSTR fileName);
void close_file_context(PFileContext fileContext);

extern inline HANDLE get_file_handle(const PFileContext fc);
extern inline LPVOID get_base_address(const PFileContext fc);
extern inline WORD get_nr_of_sections(const PFileContext fc);
extern inline PIMAGE_SECTION_HEADER get_ptr_to_section_start(const PFileContext fc);
extern inline PeFormat get_pe_format(const PFileContext fc);
extern inline PIMAGE_NT_HEADERS32 get_optional_header_32(const PFileContext fc);
extern inline PIMAGE_NT_HEADERS64 get_optional_header_64(const PFileContext fc);
extern inline LONGLONG get_file_size(_In_ const PFileContext fc);

extern inline void set_optional_header_ptr(const PFileContext fc, const PeFormat format, const LPVOID* optHeaderPtr);
extern inline void set_nr_of_sections(const PFileContext fc, WORD sectionNr);
extern inline void set_sections_ptr(const PFileContext fc, PIMAGE_SECTION_HEADER ptr);
extern inline void set_pe_format(PFileContext fc, PeFormat format);
extern inline void set_file_size(_Inout_ PFileContext fc, _In_ LONGLONG size);