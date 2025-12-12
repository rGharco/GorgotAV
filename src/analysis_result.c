#include "analysis_result.h"

#define MODULE_NAME "analysis_result.c"

AnalysisResult* create_analysis_result(const PFileContext fc) {
	AnalysisResult* result = (AnalysisResult*)calloc(1, sizeof(AnalysisResult));

	if (!result) {
		log_malloc_error("Could not allocate memory for Analysis result struct!", MODULE_NAME, __func__);
		return NULL;
	}

	result->fc = fc;

	return result;
}

void destroy_analysis_result(AnalysisResult* result) {
	if (result) {
		if (result->sha256Hash) {
			free(result->sha256Hash);
		}
		if (result->sectCount > 0) {
			for (WORD i = 0; i < result->sectCount; i++) {
				free(result->execSections[i]);
			}

			free(result->execSections);
		}
		free(result);
	}
}
