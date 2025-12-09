#include "logging.h"
#include "analysis_result.h"

void log_verbose_stdout(const char* msg) {
    printf("[VERBOSE] %s\n", msg);
}

void log_verbose_file(const char* msg) {
    fprintf(config.outFile, "[VERBOSE] %s\n", msg);
}

void log_error(int code, const char* module, const char* function, const char* message, const char* details) {
    time_t currentTime;
    time(&currentTime);

    char timeStamp[26];
    strcpy(timeStamp, ctime(&currentTime));
    timeStamp[strcspn(timeStamp, "\n")] = '\0';

    fprintf(stderr, "[%s] ERROR (%s:%s) [CODE %d] %s", timeStamp, module, function,
        code,
        message);

    if (details) {
        fprintf(stderr, "%s\n", details);
    }

    fflush(stderr);
}

void log_warning(const char* module, const char* function, const char* message, const char* details)  {
    time_t currentTime;
    time(&currentTime);

    char timeStamp[26];
    strcpy(timeStamp, ctime(&currentTime));
    timeStamp[strcspn(timeStamp, "\n")] = '\0';

    fprintf(stderr, "[%s] WARNING (%s:%s) %s", timeStamp, module, function, message);

    if (details) {
        fprintf(stderr, "%s\n", details);
    }

    fflush(stderr);
}  

void log_analysis_result(const AnalysisResult* result) {
	fprintf(config.outFile, "\n-------------------- RESULTS --------------------\n\n");

	fprintf(config.outFile, "\t> %-15s: %-s\n", "Sha256 Hash", result->sha256Hash);
	fprintf(config.outFile, "\t> %-15s: %-.6f\n", "Entropy", result->entropy);

    fprintf(config.outFile, "\n-------------------- RESULTS --------------------\n\n");
}