#pragma once

#include <stdio.h>
#include <time.h>
#include <string.h>

void log_error(int code, const char* module, const char* function, const char* message, const char* details);
void log_warning(const char* module, const char* function, const char* message, const char* details);