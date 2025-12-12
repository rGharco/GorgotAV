#pragma once

#include "logging.h"
#include "file_context.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct AnalysisResult {
	PFileContext fc;
	char* sha256Hash;
	double entropy;
	char** execSections; // non-standard exec sections (others beside .text, .textbss, .code)
	WORD sectCount;
	float confidenceScore;
} AnalysisResult;

AnalysisResult* create_analysis_result(const PFileContext fc);
void destroy_analysis_result(AnalysisResult* result);