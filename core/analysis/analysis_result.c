#include "../include/analysis_result.h"

#define MODULE_NAME "analysis_result.c"

AnalysisResult* create_analysis_result(const PFileContext fc) {
	AnalysisResult* result = (AnalysisResult*)calloc(1, sizeof(AnalysisResult));

	if (!result || errno != 0) {
		log_error(errno, strerror(errno), MODULE_NAME, __func__, "");
		
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
		if (result->suspiciousSectCount > 0) {
			for (WORD i = 0; i < result->suspiciousSectCount; i++) {
				free(result->execSections[i]);
			}

			free(result->execSections);
		}
		free(result);
	}
}
