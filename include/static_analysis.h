#pragma once

#include "analysis_result.h"
#include "file_context.h"


#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <math.h>

void static_analysis(const PFileContext fc, AnalysisResult* result);