#pragma once

#include "logging.h"
#include "file_context.h"

#include <stdio.h>
#include <stdlib.h>

typedef struct AnalysisResult {
	PFileContext fc;
	char* sha256Hash;
	double entropy;
	float confidenceScore;
} AnalysisResult;

AnalysisResult* create_analysis_result(const PFileContext fc);
void destroy_analysis_result(AnalysisResult* result);