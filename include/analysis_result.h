#pragma once

#include "logging.h"
#include "file_context.h"
#include "static_analysis.h"

#include <stdio.h>
#include <stdlib.h>

#define SHA256_HASH_HEX_STRING_SIZE  ((SHA256_HASH_BYTES * 2) + 1) // + 1 for NULL terminator

typedef struct AnalysisResult {
    PFileContext fc;
    char* sha256Hash;
    double entropy;
    char** execSections; // non-standard exec sections
    char* certificateStatus;
    float confidenceScore;
    WORD suspiciousSectCount;
} AnalysisResult;

AnalysisResult* create_analysis_result(const PFileContext fc);
void destroy_analysis_result(AnalysisResult* result);