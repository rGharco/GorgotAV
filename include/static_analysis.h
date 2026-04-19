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
// As per: https://practicalsecurityanalytics.com/file-entropy/ we will define the ranges as follow
typedef enum ENTROPY_STATUS 
{
	ENTROPY_NORMAL, // 4.8 < entropy < 7.2
	ENTROPY_SUSPICIOUS, // 7.2 < entropy < 7.6
	ENTROPY_HIGHLY_SUSPICIOUS // 7.6 < entropy < 8
}ENTROPY_STATUS;

typedef struct SectionInfo{
	_Field_size_(SECTION_NAME_LENGTH) BYTE sectionName[SECTION_NAME_LENGTH];
	double entropy;
	DWORD startAddr;
	DWORD endAddr;
	bool isExec;
	ENTROPY_STATUS entropyStatus;
}SectionInfo;


//-----------------------------------------------------------
// From GorgotLib
//-----------------------------------------------------------
PBYTE create_hash(_In_ HANDLE hFile, _Out_ DWORD* outCbHash);

//-----------------------------------------------------------
// From section_analysis.c
//-----------------------------------------------------------
void import_table_analysis(_In_ const PFileContext fc, _In_ int* indicators);

_Check_return_ _Ret_maybenull_
char** get_suspicious_executable_sections(_In_ const PFileContext fc, WORD* outCount);

void free_suspicious_sections(_In_ char** sections);

_Check_return_ 
bool is_standard_exec_sect(_In_reads_bytes_(SECTION_NAME_LENGTH) const BYTE* sectionName);

_Check_return_ _Ret_maybenull_
SectionInfo* get_sect_info(_In_ const PFileContext fc);

_Check_return_ 
bool peb_walking_detected(_In_ const BYTE* startAddress, _In_ WORD nrBytesToCheck);

_Check_return_
void tls_callback_analysis(_In_ const PFileContext fc, _Inout_ int* indicators, _In_ const SectionInfo* sectInfo);

//-----------------------------------------------------------
// From certificate_analysis.c
//-----------------------------------------------------------
const char* certStatusStr(enum CERTIFICATE_STATUS status);
CERTIFICATE_STATUS check_certificate_status(const PFileContext fc);

//-----------------------------------------------------------
// From field_malformations.c
//-----------------------------------------------------------
_Check_return_
bool verify_checksum_validity(_In_ const PFileContext fc);

//-----------------------------------------------------------
// Static Analysis functions
//-----------------------------------------------------------
void static_analysis(const PFileContext fc, AnalysisResult* result);

_Check_return_
double memory_entropy_calculation(_In_ const uint64_t size, _In_ const BYTE* dataPtr);
ENTROPY_STATUS verify_entropy_status(_In_ double entropy);

DWORD rva_to_raw(const PFileContext fc, DWORD rva);
