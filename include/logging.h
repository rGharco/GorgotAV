#pragma once

#include <stdio.h>
#include <time.h>
#include <string.h>

#include "cli.h"

#define LOG_VERBOSE(out, msg)                   \
    do {                                        \
        if (config.flags & FLAG_VERBOSE) {      \
            if (out != NULL)                    \
                log_verbose_file(msg);          \
            else                                \
                log_verbose_stdout(msg);        \
        }                                       \
    } while (0)                                              

void log_error(int code, const char* module, const char* function, const char* message, const char* details);
void log_warning(const char* module, const char* function, const char* message, const char* details);

void log_verbose_stdout(const char* msg);
void log_verbose_file(const char* msg);