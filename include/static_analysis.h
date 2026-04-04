#pragma once

#include "analysis_result.h"
#include "file_context.h"


#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <math.h>
#include <wincrypt.h>
#include <Softpub.h>
#include <Wintrust.h>

#pragma comment (lib, "bcrypt")
#pragma comment (lib, "wintrust")

// From GorgotLib.lib
PBYTE create_hash(_In_ HANDLE hFile, _Out_ DWORD* outCbHash);
void static_analysis(const PFileContext fc, AnalysisResult* result);