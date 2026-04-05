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

// -- From section_analysis.c
void import_table_analysis(_In_ const PFileContext fc);

// -- Static Analysis functions
void static_analysis(const PFileContext fc, AnalysisResult* result);
DWORD rva_to_raw(const PFileContext fc, DWORD rva);
