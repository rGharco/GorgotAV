#pragma once

#include "logging.h"
#include "file_context.h"
#include "arena.h"
#include "analysis_result.h"

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <math.h>

void static_analysis(const PFileContext fc, AnalysisResult* result);