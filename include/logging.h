#pragma once

#include "cli.h"

#include <stdio.h>
#include <time.h>
#include <string.h>

#define LOG_VERBOSE(out, msg)                   \
    do {                                        \
        if (config.flags & FLAG_VERBOSE) {      \
            if (out != NULL)                    \
                log_verbose_file(msg);          \
            else                                \
                log_verbose_stdout(msg);        \
        }                                       \
    } while (0)                                              

enum LoggingCodes {
    MISSING_VARIABLE_ERR, 
    BAD_OPERATION_ERR,
    MEMORY_ALLOCATION_ERR,

    UNKNOWN_ERROR_CODE
};

void log_error(int code, const char* module, const char* function, const char* message, const char* details);
void log_warning(const char* module, const char* function, const char* message, const char* details);

void log_verbose_stdout(const char* msg);
void log_verbose_file(const char* msg);

typedef struct AnalysisResult AnalysisResult;

void log_malloc_error(const char* msg, const char* module, const char* func);

void log_analysis_result(const AnalysisResult* result);