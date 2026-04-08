#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "logging.h"
#include "integrity.h"
#include <io.h>

#define IS_TTY(f) _isatty(_fileno(f))

#define _A(seq)  (ui_ansi_enabled ? "\033[" seq : "")
#define RST       _A("0m")

#define BOLD      _A("1m")
#define CYAN_LT   _A("96m")   // bright cyan  — app name, short flags (-v)
#define BLUE_DK   _A("34m")   // dark blue    — section headers, icons
#define MUTED     _A("90m")   // dark gray    — descriptions, dim chrome

typedef struct Option Option;

typedef struct AppConfig {
    char* target;
    FILE* outFile;
    uint32_t flags;
}AppConfig;

enum ConfigFlag {
    FLAG_VERBOSE = 1 << 0
};

// Define it's existance here and the initialization in cli.c
extern AppConfig config;
extern bool ui_ansi_enabled;

typedef enum ParseStatus {
    PARSE_STATUS_OK,
    PARSE_STATUS_FAIL,
}ParseStatus;

void ui_init(void);
void init_config();
ParseStatus parse_args(int argc, char* argv[]);
void disable_config();