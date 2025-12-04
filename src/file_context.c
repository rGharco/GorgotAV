#include "file_context.h"
#include "logging.h"
#include "cli.h"

#define MODULE_NAME "file_context.c"

//----------------------------------------------------------------------------------
// Struct definition
//----------------------------------------------------------------------------------

struct FileContext {
    HANDLE hFile;
    HANDLE hFileMap;
    LPVOID baseAddress;
};

//----------------------------------------------------------------------------------
// Function Prototypes
//----------------------------------------------------------------------------------

static HANDLE open_file_handle(LPCSTR fileName);
static HANDLE open_file_map(HANDLE hFile);
static LPVOID open_map_view(HANDLE hFileMap);

PFileContext create_file_context(LPCSTR fileName) {
    PFileContext fileContext = calloc(1, sizeof(FileContext));

    if (fileContext == NULL) {
        log_error(errno, MODULE_NAME, __func__,
            "Could not initialize memory for fileContext",
            strerror(errno));
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
        log_error(GetLastError(), MODULE_NAME, __func__, "Could not find file to open",
            fileName);
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
        log_error(GetLastError(), MODULE_NAME, __func__, "Could not map file to memory",
            NULL);
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
        log_error(GetLastError(), MODULE_NAME, __func__, "Could not retrieve map view",
            NULL);
        return baseAddress;
    }

    return baseAddress;
}

void close_file_context(PFileContext fileContext) {
    if (fileContext == NULL) return;
    if (fileContext->baseAddress != NULL) UnmapViewOfFile(fileContext->baseAddress);;
    if (fileContext->hFileMap != NULL) CloseHandle(fileContext->hFileMap);
    if (fileContext->hFile != NULL) CloseHandle(fileContext->hFile);

    free(fileContext);
}