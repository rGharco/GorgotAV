#include "file_context.h"
#include "logging.h"
#include "cli.h"

#define MODULE_NAME "file_context.c"    
#define _CRT_SECURE_NO_WARNINGS_

//----------------------------------------------------------------------------------
// Struct definition
//----------------------------------------------------------------------------------

struct FileContext {
    HANDLE hFile;
    HANDLE hFileMap;
    LPVOID baseAddress;
    PIMAGE_SECTION_HEADER ptrToSectionStart;
    PeFormat peFormat;
    WORD nrOfSections;
    union{
        PIMAGE_NT_HEADERS32 nt32;
        PIMAGE_NT_HEADERS64 nt64;
    } nt;
    LONGLONG fileSize;
};

//----------------------------------------------------------------------------------
// Function Prototypes
//----------------------------------------------------------------------------------

static HANDLE open_file_handle(LPCSTR fileName);
static HANDLE open_file_map(HANDLE hFile);
static LPVOID open_map_view(HANDLE hFileMap);

PFileContext create_file_context(LPCSTR fileName) {
    PFileContext fileContext = calloc(1, sizeof(FileContext));

    if (fileContext == NULL || errno != 0) {
        char errBuf[128];
        strerror_s(errBuf, sizeof(errBuf), errno);
        log_error(errno, MODULE_NAME, __func__,
            "Could not initialize memory for fileContext",
            errBuf);
        return NULL;
    }

    fileContext->hFile = open_file_handle(fileName);

    if (fileContext->hFile == NULL) {
        goto Cleanup;
    }

    fileContext->hFileMap = open_file_map(fileContext->hFile);

    if (fileContext->hFileMap == NULL) {
        goto Cleanup;
    }

    fileContext->baseAddress = open_map_view(fileContext->hFileMap);

    if (fileContext->baseAddress == NULL) {
        goto Cleanup;
    }

    return fileContext;

Cleanup:
    if (fileContext->baseAddress != NULL) UnmapViewOfFile(fileContext->baseAddress);
    if (fileContext->hFileMap != NULL) CloseHandle(fileContext->hFileMap);
    if (fileContext->hFile != NULL) CloseHandle(fileContext->hFile);
    free(fileContext);

    return NULL;
}

static HANDLE open_file_handle(LPCSTR fileName) {
    HANDLE hFile = CreateFile(
        fileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        log_error_winapi(err, MODULE_NAME, __func__, "");

        return NULL;
    }

    return hFile;
}

static HANDLE open_file_map(HANDLE hFile) {
    HANDLE hFileMap = NULL;

    hFileMap = CreateFileMapping(
        hFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
    );

    if (hFileMap == NULL) {
        DWORD err = GetLastError();
        log_error_winapi(err, MODULE_NAME, __func__, "");

        return hFileMap;
    }

    return hFileMap;
}

static LPVOID open_map_view(HANDLE hFileMap) {
    LPVOID baseAddress = MapViewOfFile(
        hFileMap,
        FILE_MAP_READ,
        0,
        0,
        0
    );

    if (baseAddress == NULL) {
        DWORD err = GetLastError();
        log_error_winapi(err, MODULE_NAME, __func__, "");

        return baseAddress;
    }

    return baseAddress;
}

//----------------------------------------------------------------------------------
// Getters
//----------------------------------------------------------------------------------

HANDLE get_file_handle(const PFileContext fc) {
    return fc->hFile;
}

LPVOID get_base_address(const PFileContext fc) {
    return fc->baseAddress; 
}

WORD get_nr_of_sections(const PFileContext fc) {
    return fc->nrOfSections;
}

PIMAGE_SECTION_HEADER get_ptr_to_section_start(const PFileContext fc) {
    return fc->ptrToSectionStart;
}

PeFormat get_pe_format(const PFileContext fc) {
    return fc->peFormat;
}

PIMAGE_NT_HEADERS32 get_optional_header_32(const PFileContext fc) {
    return fc->nt.nt32;
}

PIMAGE_NT_HEADERS64 get_optional_header_64(const PFileContext fc) {
    return fc->nt.nt64;
}

void* get_optional_header(void* nt_headers, int format) {
    if (format == PE32)
        return get_optional_header_32(nt_headers);
    else
        return get_optional_header_64(nt_headers);
}

LONGLONG get_file_size(_In_ const PFileContext fc) {
    return fc->fileSize;
}

//----------------------------------------------------------------------------------
// Setters
//----------------------------------------------------------------------------------

void set_optional_header_ptr(const PFileContext fc, const PeFormat format, const LPVOID* optHeaderPtr) {
    if (format == PE32) {
        fc->nt.nt32 = (PIMAGE_NT_HEADERS32)optHeaderPtr;
    }
    else {
        fc->nt.nt64 = (PIMAGE_NT_HEADERS64)optHeaderPtr;
    }
}

void set_sections_ptr(const PFileContext fc, PIMAGE_SECTION_HEADER ptr) {
    fc->ptrToSectionStart = ptr;
}

void set_nr_of_sections(const PFileContext fc, WORD sectionNr) {
    fc->nrOfSections = sectionNr;
}

void set_pe_format(PFileContext fc, PeFormat format) {
    fc->peFormat = format;
}

void set_file_size(_Inout_ PFileContext fc, _In_ LONGLONG size) {
    fc->fileSize = size;
}

//----------------------------------------------------------------------------------
// Cleanup
//----------------------------------------------------------------------------------

void close_file_context(PFileContext fileContext) {
    if (fileContext == NULL) return;
    if (fileContext->baseAddress != NULL) UnmapViewOfFile(fileContext->baseAddress);;
    if (fileContext->hFileMap != NULL) CloseHandle(fileContext->hFileMap);
    if (fileContext->hFile != NULL) CloseHandle(fileContext->hFile);

    free(fileContext);
}