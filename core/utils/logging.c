#include "logging.h"
#include "analysis_result.h"

static const char* strError(int loggingCode) {
    switch (loggingCode) {
        case BAD_OPERATION_ERR:
            return "Bad Operation Error";
        case UNKNOWN_FLAG_ERR:
            return "Unknown Flag Error";
        case MISSING_REQ_PARAMETER_FOR_FLAG:
            return "Missing Required Parameter For Flag Error";
        case BAD_FLAG_PARAMETER_FORMAT:
            return "Bad Flag Parameter Format Error";
        case LOG_MEMORY_ALLOCATION_ERR:
            return "Memory Allocation Error";
        case HASHING_ERR:
            return "Hashing Error";
        case INITIALIZING_ARENA_ERR:
            return "Initializing Arena Error";
        case FILE_READING_ERR:
            return "File Reading Error";
        default: 
            return "Unknown Error";
    }
}

void log_error(int code, const char* module, const char* function, const char* message, const char* details) {
    time_t currentTime;
    time(&currentTime);

    char timeStamp[26];
    strcpy(timeStamp, ctime(&currentTime));
    timeStamp[strcspn(timeStamp, "\n")] = '\0';

    fprintf(stderr, "[%s] ERROR (%s:%s) [CODE %d : %s] %s", timeStamp, module, function,
        code,
        strError(code),
        message);

    if (details) {
        fprintf(stderr, "%s\n", details);
    }

    fflush(stderr);
}

// As for now the error code will have the message set to CODE X : Unknown Error Code due to the fact that we do not treat
// WINAPI error codes differently but instead treat them as LoggingCodes (the enumeration)
void log_error_winapi(DWORD err, const char* module, const char* function, const char* details) {
    char* errorDescriptionBuffer = NULL;

    size_t errorDescriptionSize = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        0, err, 0, (LPSTR)&errorDescriptionBuffer, 0, NULL); // Returns the size of the error message without null terminating character

    char* errorDescription = malloc(errorDescriptionSize + 1); // Null terminating character

    if (errorDescription == NULL) {
        log_error(err, module, function, "Failed to identify exact error!", details);
        return;
    }

    strcpy_s(errorDescription, errorDescriptionSize + 1, errorDescriptionBuffer); // the message DOES have a null terminated character in the string itself

    log_error(err, module, function, errorDescription, details);

    LocalFree(errorDescriptionBuffer);
    free(errorDescription);

    return;
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
    show_analysis_steps_banner("Analysis Result");

    fprintf(config.outFile, "%-5s> %-30s: %-u\n", "" ,"Indicators", result->indicators);

	fprintf(config.outFile, "%-5s> %-30s: %-s\n", "" ,"Sha256 Hash", result->sha256Hash);
	fprintf(config.outFile, "%-5s> %-30s: %-.6f\n", "" ,"Entropy", result->entropy);
    fprintf(config.outFile, "%-5s> %-30s: %-d\n", "" ,"Suspicious sections found", result->suspiciousSectCount);

    if (result->suspiciousSectCount > 0) {
        for (WORD i = 0; i < result->suspiciousSectCount; i++) {
            fprintf(config.outFile, "%-5s> %-15s: %-s -> has executable flag set!\n", "" ,"Section", result->execSections[i]);
        }
    }

    fprintf(config.outFile, "%-5s> %-30s: %-s\n", "" ,"Digital certificate status", result->certificateStatus);
}

void log_success(_In_z_ const char* msg) {
    fprintf(config.outFile, "[SUCCESS] %s\n", msg);
}

void section(_In_ const char* label) {
    int llen = (int)strlen(label);

    int right = WIDTH - (llen + 1);
    if (right < 0) right = 0;

    printf("%s%s%s ", CYAN_LT, label, RST);
    printf("%s", BLUE_DK);
    for (int i = 0; i < right; i++) {
        fputs(BOX_H, stdout);
    }
    printf("%s\n", RST);
}

void show_analysis_steps_banner(_In_z_ const char* label) {
    if (config.outFile == stdout && config.flags & FLAG_VERBOSE) {
        section(label);          
    }              
}

void show_app_banner() {
    printf("%s%sGrogotAV %s", BOLD, CYAN_LT, RST);
    printf("%sv1.0.0%s", BLUE_DK, RST);
    printf("  %sIntegrity checker & antivirus utility%s", MUTED, RST);
    printf("\n");
}