#include "../include/analysis_result.h"

#define MODULE_NAME "analysis_result.c"

AnalysisResult* create_analysis_result(const PFileContext fc) {
	AnalysisResult* result = (AnalysisResult*)calloc(1, sizeof(AnalysisResult));

	if (!result || errno != 0) {
		char errBuf[128];
        strerror_s(errBuf, sizeof(errBuf), errno);
        log_error(errno, MODULE_NAME, __func__,
            "",
            errBuf);
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
			free_suspicious_sections(result->execSections);
		}
		free(result);
	}
}
