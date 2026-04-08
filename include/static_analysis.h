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

#define SECTION_NAME_LENGTH 9 // 8 + null terminator

typedef enum CERTIFICATE_STATUS CERTIFICATE_STATUS;

typedef struct SectionInfo{
	_Field_size_(SECTION_NAME_LENGTH) char sectionName[SECTION_NAME_LENGTH];
	double entropy;
	DWORD startAddr;
	DWORD endAddr;
	bool isExec;
}SectionInfo;

// From GorgotLib.lib
PBYTE create_hash(_In_ HANDLE hFile, _Out_ DWORD* outCbHash);

// -- From section_analysis.c
void import_table_analysis(_In_ const PFileContext fc);
_Check_return_ _Ret_maybenull_
char** get_suspicious_executable_sections(_In_ const PFileContext fc, WORD* outCount);
void free_suspicious_sections(_In_ char** sections);
_Check_return_ 
bool is_standard_exec_sect(_In_reads_bytes_(SECTION_NAME_LENGTH) const char* sectionName);
_Check_return_ _Ret_maybenull_
SectionInfo* get_sect_info(_In_ const PFileContext fc);
_Check_return_
bool has_tls_callbacks(_In_ const PFileContext fc);

// -- From certificate_analysis.c
const char* certStatusStr(enum CERTIFICATE_STATUS status);
CERTIFICATE_STATUS check_certificate_status(const PFileContext fc);

// -- From field_malformations.c
_Check_return_
bool verify_checksum_validity(_In_ const PFileContext fc);


// -- Static Analysis functions
void static_analysis(const PFileContext fc, AnalysisResult* result);
_Check_return_
double memory_entropy_calculation(_In_ const uint64_t size, _In_ const BYTE* dataPtr);
DWORD rva_to_raw(const PFileContext fc, DWORD rva);
