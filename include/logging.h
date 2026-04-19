#pragma once

#include "cli.h"

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <Windows.h>

#define BOX_H (ui_ansi_enabled ? "\xe2\x94\x80" : "-")

#define ICON_CHECK (ui_ansi_enabled ? "\xE2\x9C\x93" : "x")
#define ICON_WARNING (ui_ansi_enabled ? "\xE2\x9A\xA0" : "!")
#define WIDTH 64

#define _A(seq)  ((ui_ansi_enabled && config.outFile == stdout) ? "\033[" seq : "")
#define RST       _A("0m")

#define BOLD      _A("1m")
#define CYAN_LT   _A("96m")   // bright cyan  — app name, short flags (-v)
#define BLUE_DK   _A("34m")   // dark blue    — section headers, icons
#define MUTED     _A("90m")   // dark gray    — descriptions, dim chrome
#define BOLD_YELLOW _A("33m") // bright yellow - warnings 
#define BOLD_GREEN _A("32m") // bright green - completion

#define LOG_VERBOSE(out, msg)                                                   \
    do {                                                                        \
        if (config.flags & FLAG_VERBOSE && config.outFile) {                    \
           fprintf(config.outFile,"%s%-5s%s %s%s\n", BLUE_DK , " " , ICON_CHECK , msg, RST);   \
        } \
    } while (0)

#define LOG_VERBOSE_SUSPICIOUS_INDICATOR(msg, details)                                         \
    do {                                                                        \
        if (config.flags & FLAG_VERBOSE && config.outFile) {                    \
           fprintf(config.outFile,"%s%-5s%s %s%s", BOLD_YELLOW , " " , ICON_WARNING , msg, RST);   \
           if (strcmp(details, "") != 0) { \
                fprintf(config.outFile,": %s%-5s %s%s", BOLD_YELLOW , " " , details, RST);  \
           } \
           fprintf(config.outFile, "\n"); \
        } \
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
    LOG_MEMORY_ALLOCATION_ERR, // - defines errors that happen when you allocate memory
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
void section(_In_ const char* label);
void show_analysis_steps_banner(_In_z_ const char* label);
void show_app_banner();