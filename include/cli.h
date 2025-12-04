#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include "logging.h"

typedef struct Option Option;

typedef struct AppConfig {
    char* target;
    FILE* outFile;
    uint32_t flags;
}AppConfig;

typedef enum ConfigFlag ConfigFlag;

extern AppConfig config;

typedef enum ParseStatus {
    PARSE_STATUS_OK,
    PARSE_STATUS_FAIL,
}ParseStatus;

ParseStatus parse_args(int argc, char* argv[]);