#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "logging.h"
#include "integrity.h"

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

typedef enum ParseStatus {
    PARSE_STATUS_OK,
    PARSE_STATUS_FAIL,
}ParseStatus;

void init_config();
ParseStatus parse_args(int argc, char* argv[]);
void disable_config();