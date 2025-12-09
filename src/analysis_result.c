#include "analysis_result.h"

#define MODULE_NAME "analysis_result.c"

AnalysisResult* create_analysis_result(const PFileContext fc) {
	AnalysisResult* result = (AnalysisResult*)calloc(1, sizeof(AnalysisResult));

	if (!result) {
		log_error(errno, MODULE_NAME, __func__, "Memory allocation failed!",
			"Default code was overwritten by errno code!");
		perror(strerror(errno));
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
		free(result);
	}
}
