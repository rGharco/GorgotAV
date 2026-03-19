#pragma once

#include "logging.h"
#include "file_context.h"

#include <stdio.h>
#include <stdlib.h>

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