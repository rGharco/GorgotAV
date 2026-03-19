#pragma once

#include "cli.h"

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <Windows.h>

#define LOG_VERBOSE(out, msg)                   \
    do {                                        \
        if (config.flags & FLAG_VERBOSE) {      \
            if (out != NULL)                    \
                log_verbose_file(msg);          \
            else                                \
                log_verbose_stdout(msg);        \
        }                                       \
    } while (0)        

#define NO_DESCRIPTION ((const char*)"")

// These codes are utilized for functions that are not part of the C standard library. For those we use a combination of
// perrr() with errno. 
// DO NOT FORGET TO UPDATE logging.c -> strError cases when adding a new error code.
enum LoggingCodes {
    BAD_OPERATION_ERR,
    UNKNOWN_FLAG_ERR, // - defines errors that happen when a CLI flag is unknown, currently not implemented
    MISSING_REQ_PARAMETER_FOR_FLAG, // - defines errors that happen when a CLI flag requires a parameter but none is supplied
    BAD_FLAG_PARAMETER_FORMAT, // - defines errors that happen when parsing CLI flags and finds bad formatted flags 
    MEMORY_ALLOCATION_ERR, // - defines errors that happen when you allocate memory
    HASHING_ERR, // - defines errors that happen when using a hashing algorithm 
    INITIALIZING_ARENA_ERR, // - defines errors that happen upon creating memory arenas
    FILE_READING_ERR, // - defines errors that happen when reading bytes from a file 

    UNKNOWN_ERROR_CODE
};

void log_error(int code, const char* module, const char* function, const char* message, const char* details);
void log_error_winapi(DWORD err, const char* module, const char* function, const char* details);
void log_warning(const char* module, const char* function, const char* message, const char* details);

void log_verbose_stdout(const char* msg);
void log_verbose_file(const char* msg);

extern inline void log_success(_In_z_ const char* msg);

typedef struct AnalysisResult AnalysisResult;

void log_analysis_result(const AnalysisResult* result);