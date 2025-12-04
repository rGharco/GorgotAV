#include "logging.h"

struct ErrorLog {
    int code;
    const char* module;
    const char* function;
    const char* message;
    const char* timeStamp;
    const char* details;
};

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

void log_warning(const char* module, const char* function, const char* message, const char* details) {
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