/*
	@brief: This module has two purposes:
		- run a verify_integrity() function which analyzes the integrity of important modules and checks them against a previous
		  metadata file, to see if any changes happended to them (hash, timestamp, file size, file path)
			- if integrity is verified -> log results, if integrity is not verified -> alert user with a MessageBox 
		- log results inside a log file stored in: C:\Users\<user>\AppData\Local\GorgotAV\integrity_log.txt	
*/

#include <stdio.h>
#include <Windows.h>
#include <ShlObj.h>
#include <wchar.h>
#include <PathCch.h>
#include <strsafe.h>
#include <time.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Pathcch.lib")
#pragma comment(lib, "GorgotLib.lib")

#define SHA256_LENGTH 32
#define NO_DETAILS_A NULL
#define NO_DETAILS_W NULL

// ---------------------------------------------------
// From GorgotLib
// ---------------------------------------------------

// Caller must free with HeapFree(GetProcessHeap(), 0, ...)
_Check_return_
PBYTE create_hash(_In_ HANDLE hFile, _Out_ DWORD* outCbHash);

_Check_return_
BOOL construct_appdata_file_path(_Out_writes_z_(MAX_PATH) WCHAR* outPath, _In_z_ const WCHAR* basePath, _In_z_ const WCHAR* fileName);

_Check_return_ 
BOOL construct_antivirus_appdata_path(_Out_writes_z_(MAX_PATH) WCHAR* outPath);

// ---------------------------------------------------
// From GorgotLib
// ---------------------------------------------------

typedef struct IntegrityData {
	DWORD cbHash;
	BYTE hash[SHA256_LENGTH];
	LONGLONG fileSize;
	time_t timestamp;
	_Field_z_ WCHAR modulePath[MAX_PATH];
}IntegrityData;

typedef struct ModuleInfo {
	HANDLE hFile;
	WCHAR modulePath[MAX_PATH];
} ModuleInfo;

static const WCHAR* const GORGOTAV_APPDATA_FOLDER_NAME = L"GorgotAV";
static const WCHAR* const INTEGRITY_BINARY_DATA_FILE = L"integrity.bin";
static const WCHAR* const INTEGRITY_LOG_FILE_NAME = L"integrity_log.txt";

int verificationError = 0;

// ---------------------------------------------------
// Global definitions
// ---------------------------------------------------
static const LPCWSTR modulesToVerify[] = {
	L"ntoskrnl.exe",
	L"hal.dll",
	L"winload.exe",
	L"winresume.exe",
	L"ci.dll",
	L"wintrust.dll",
	L"crypt32.dll",
	L"bcrypt.dll",
	L"bcryptprimitives.dll",
	L"lsass.exe",
	L"ntdll.dll",
	L"kernel32.dll",
	L"kernelbase.dll",
	L"user32.dll",
	L"advapi32.dll",
	L"sechost.dll",
	L"combase.dll",
	L"rpcrt4.dll",
	L"services.exe",
	L"svchost.exe",
	L"taskhostw.exe",
	L"dllhost.exe",
	L"RuntimeBroker.exe",
	L"conhost.exe",
	L"explorer.exe",
	L"winlogon.exe",
	L"wininit.exe",
	L"csrss.exe",
	L"smss.exe",
	L"dwm.exe",
	L"fontdrvhost.exe",
	L"ws2_32.dll",
	L"wininet.dll",
	L"winhttp.dll",
	L"urlmon.dll",
	L"wevtutil.exe",
	L"werfault.exe",
	L"werfaultsecure.exe",
	L"esent.dll",
	L"sfc.exe",
	L"wuauclt.exe",
	L"usoclient.exe"
};

// -- Prototype 
_Check_return_ 
static BOOL construct_log_file_path(_Out_writes_z_(MAX_PATH) WCHAR* outPath);

static void show_error_msg() {
	if (verificationError == 1) {
		return;
	}

	MessageBoxW(
        NULL,                          
        L"There was an error while trying to verify your device integrity. Check the logs for extended information!",  
        L"Integrity Checking",             
        MB_OK | MB_ICONERROR     
    );
}

static void log_error_integrity(_In_z_ const char* restrict function, _In_z_ const char* restrict message, _In_opt_z_ const char* restrict detailsA, _In_opt_z_ const WCHAR* restrict detailsW) {
	WCHAR logPath[MAX_PATH] = {0};
	if (!construct_log_file_path(logPath)) {
		printf("Error trying to construct log file path!\n");
		return;
	}

	FILE* logFile = _wfopen(logPath, L"a");

	if (!logFile) {
		printf("Error trying to open log file\n");
		return;
	}

    time_t currentTime;
	time(&currentTime);

	struct tm localTime;
	localtime_s(&localTime, &currentTime);

	char timeStamp[64];
	strftime(timeStamp, sizeof(timeStamp), "%Y-%m-%d %H:%M:%S", &localTime);

	function = function ? function : "UNKNOWN_FUNCTION";
    message  = message  ? message  : "UNKNOWN_MESSAGE";

    fprintf(logFile, "[%s] ERROR at function: %s -> %s", timeStamp, function, message);

    if (detailsA) {
        fprintf(logFile, ": %s\n", detailsA);
    }
	// This is AI fix to handle _wfprintf, mixing _wfprintf with fprintf causes undefined behavior so this is a workaround for the moment 
	else if (detailsW) {
		char buffer[512];
		size_t converted = 0;

		errno_t err = wcstombs_s(
			&converted,
			buffer,
			sizeof(buffer),
			detailsW,
			_TRUNCATE
		);

		if (err == 0) {
			fprintf(logFile, ": %s\n", buffer);
		} else {
			fprintf(logFile, ": [WIDE STRING CONVERSION FAILED]\n");
		}
	}
	else {
        fprintf(logFile, "\n");
    }

    fflush(logFile);
	fclose(logFile);

	show_error_msg();

	verificationError = 1;
}

//	The caller then hashes and performs operation on the items
_Check_return_ _Ret_maybenull_
static ModuleInfo* get_module_info() {
	ModuleInfo* modInfo = calloc(ARRAYSIZE(modulesToVerify), sizeof(ModuleInfo));

	if (modInfo == NULL) {
		log_error_integrity(__func__, "Failed to allocate memory for module information struct", "calloc() failed!", NO_DETAILS_W);
		return NULL;
	}

	for (size_t i = 0; i < ARRAYSIZE(modulesToVerify); i++) {
		WCHAR path[MAX_PATH] = { 0 };

		DWORD res = SearchPathW(
			NULL,
			modulesToVerify[i],
			NULL,
			MAX_PATH,
			path,
			NULL
		);

		if (res == 0) {
			log_error_integrity(__func__, "Could not find specified module", NO_DETAILS_A, path);
			continue; // skip this module
		}

		HANDLE hFile = CreateFileW(
			path,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
		);

		if (hFile == INVALID_HANDLE_VALUE) {
			log_error_integrity(__func__, "Could not open handle for specified module", NO_DETAILS_A, path);
			continue;
		}

		modInfo[i].hFile = hFile;
		wcscpy_s(modInfo[i].modulePath, MAX_PATH, path);
	}

	return modInfo;
}

_Check_return_ 
static BOOL construct_integrity_path(_Out_writes_z_(MAX_PATH) WCHAR* outPath) {
	if (!construct_antivirus_appdata_path(outPath)) return FALSE;  
	if (!construct_appdata_file_path(outPath, outPath, INTEGRITY_BINARY_DATA_FILE)) return FALSE; 

	return TRUE;
}

_Check_return_ 
static BOOL construct_log_file_path(_Out_writes_z_(MAX_PATH) WCHAR* outPath) {
	if (!construct_antivirus_appdata_path(outPath)) return FALSE;  
	if (!construct_appdata_file_path(outPath, outPath, INTEGRITY_LOG_FILE_NAME)) return FALSE; 

	return TRUE;
}

// Caller closes the handle
_Check_return_ _Success_(return != INVALID_HANDLE_VALUE)
static HANDLE get_integrity_file_handle(_In_z_ const WCHAR* integrityFilePath) {
	HANDLE hFile = NULL;

	hFile = CreateFileW(
        integrityFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        log_error_integrity(__func__, "Failed to initiate handle for integrity binary file","CreateFileW() failed!", NO_DETAILS_W);

        return INVALID_HANDLE_VALUE;
    }

    return hFile;
} 

_Check_return_ 
static BOOL verify_file_size_tampering(_In_ HANDLE hIntegFile, _In_ size_t inExpectedFileSize) {
	LARGE_INTEGER fileSize = { 0 };
	if (!GetFileSizeEx(hIntegFile, &fileSize)) {
		log_error_integrity(__func__, "Failed to retrieve file size for integrity binary data.", "GetFileSizeEx() failed!", NO_DETAILS_W);
		return FALSE;
	}

	if (fileSize.QuadPart != inExpectedFileSize) {
		log_error_integrity(__func__, "Integrity binary file size does not match expected size!", "integrity.bin has been tampered", NO_DETAILS_W);
		return FALSE;
	}

	return TRUE;
}

_Check_return_
static BOOL verify_binary_format_tampering(_In_ size_t inIntegDataCount, _In_reads_(inIntegDataCount) IntegrityData* inStoredData) { 
	for (size_t i = 0; i < inIntegDataCount; i++) {
		IntegrityData* entry = &inStoredData[i];

		// 1. Ensure modulePath is null-terminated
		if (entry->modulePath[MAX_PATH - 1] != L'\0') {
			log_error_integrity(__func__, "File path not null-terminated for a module ", NO_DETAILS_A, NO_DETAILS_W);
			return FALSE;
		}

		// 2. Ensure path is not empty
		if (entry->modulePath[0] == L'\0') {
			log_error_integrity(__func__, "Empty module path for a module", NO_DETAILS_A, NO_DETAILS_W);
			return FALSE;
		}

		// 3. Hash length check
		if (entry->cbHash != SHA256_LENGTH) {
			log_error_integrity(__func__, "Hash length differs from expected hash length for module", NO_DETAILS_A, entry->modulePath);
			return FALSE;
		}

		// 4. File size check 
		if (entry->fileSize < 0) {
			log_error_integrity(__func__, "Abnormal file size ( < 0 ) for module", NO_DETAILS_A, entry->modulePath);
			return FALSE;
		}

		// 5. Timestamp check 
		if (entry->timestamp <= 0 || entry->timestamp > time(NULL) + 86400) {
			log_error_integrity(__func__, "Abnormal timestamp for module", NO_DETAILS_A, entry->modulePath);
			return FALSE;
		}

		// 6. Hash content check (not all zero)
		BOOL allZero = TRUE;
		for (DWORD j = 0; j < entry->cbHash; j++) {
			if (((BYTE*)entry->hash)[j] != 0) {
				allZero = FALSE;
				break;
			}
		}
		if (allZero) {
			log_error_integrity(__func__, "Hash initiated with only 0's for module", NO_DETAILS_A, entry->modulePath);
			return FALSE;
		}
	}
	
	return TRUE;
}

// TODO: Fix warnings regarding signed/unsigned match
// TODO: Fix warning regarding potential ReadFile() loss of data and decide a pattern if file size > something than use LARGE_INTEGER else DWORD 
_Check_return_ 
static BOOL verify_integrity() {
	ModuleInfo* modInfo = NULL;
	HANDLE hIntegFile = INVALID_HANDLE_VALUE;
	WCHAR integPath[MAX_PATH] = { 0 };
	BOOL verifiedIntegrity = TRUE;
	size_t integDataCount = ARRAYSIZE(modulesToVerify);
	IntegrityData* storedData = NULL;

	// -- 1. Build integrity file path
	if (!construct_integrity_path(integPath)) {
		log_error_integrity(__func__, "Failed to construct path to integrity.bin", "construct_integrity_path() failed!", NO_DETAILS_W);
		goto IntegCleanup;
	}

	// -- 2. Obtain file handle 
	hIntegFile = get_integrity_file_handle(integPath);
	if (hIntegFile == INVALID_HANDLE_VALUE) goto IntegCleanup;

	// -- 3. Verify file size tampering
	size_t expectedFileSize = sizeof(IntegrityData) * integDataCount;
	if(!verify_file_size_tampering(hIntegFile, expectedFileSize)) goto IntegCleanup;

	// -- 4. Allocate buffer for stored integrity data
	storedData = calloc(1, expectedFileSize);
	if (!storedData) {
		log_error_integrity(__func__, "Failed to allocate memory for IntegrityData structure", "calloc() failed!", NO_DETAILS_W);
		goto IntegCleanup;
	}

	// -- 5. Read integrity data and verify its format
	DWORD bytesRead;
	if (!ReadFile(hIntegFile, storedData, expectedFileSize, &bytesRead, NULL)) {
		log_error_integrity(__func__, "Failed to read data from binary file", "ReadFile() failed!", NO_DETAILS_W);
		goto IntegCleanup;
	}

	if (!(bytesRead == expectedFileSize)) {
		log_error_integrity(__func__, "Expected file size does not match the bytes read using ReadFile", "error at reading from file", NO_DETAILS_W);
		goto IntegCleanup;
	}

	if (!verify_binary_format_tampering(integDataCount,storedData)) goto IntegCleanup;

	// -- 6. Fill module informations to perform checking on
	modInfo = get_module_info();
	if(modInfo == NULL) {
		log_error_integrity(__func__, "Failed to allocate memory to ModuleInfo struct", "calloc() failed!", NO_DETAILS_W);
		goto IntegCleanup;
	}

	// -- 7. Verify integrity
	for (size_t i = 0; i < integDataCount; i++) {
		if (modInfo[i].hFile == INVALID_HANDLE_VALUE) {
			log_error_integrity(__func__, "Current module does not contain any information / failed to retrieve module information", "skipping module with path", modInfo[i].modulePath);
			goto IntegCleanup;
		}

		DWORD cbHash = 0;
		PBYTE hash = create_hash(modInfo[i].hFile, &cbHash);

		if (hash == NULL) {
			log_error_integrity(__func__, "Failed to create hash for current verified module", NO_DETAILS_A, modInfo[i].modulePath);
			goto IntegCleanup;
		}

		if (cbHash != SHA256_LENGTH || cbHash == 0) {
			log_error_integrity(__func__, "Hash length missmatch / abnormal hash length for current verified module", NO_DETAILS_A, modInfo[i].modulePath);
			HeapFree(GetProcessHeap(), 0, hash);
			goto IntegCleanup;
		}

		LARGE_INTEGER fileSize = { 0 };

		if (!GetFileSizeEx(modInfo[i].hFile, &fileSize)) {
			log_error_integrity(__func__, "Failed to retrieve file size for current verified module", NO_DETAILS_A, modInfo[i].modulePath);
			HeapFree(GetProcessHeap(), 0, hash);
			goto IntegCleanup;
		}

		if (cbHash != storedData[i].cbHash) {
			log_error_integrity(__func__, "Hash length missmatch for module", NO_DETAILS_A, modInfo[i].modulePath);
			verifiedIntegrity = FALSE;
		}

		if (memcmp(hash, storedData[i].hash, SHA256_LENGTH) != 0) {
			log_error_integrity(__func__, "Hash missmatch for module", NO_DETAILS_A, modInfo[i].modulePath);
			verifiedIntegrity = FALSE;
		}

		if (fileSize.QuadPart != storedData[i].fileSize) {
			log_error_integrity(__func__, "File size missmatch for module", NO_DETAILS_A, modInfo[i].modulePath);
			verifiedIntegrity = FALSE;
		}

		if (_wcsicmp(modInfo[i].modulePath, storedData[i].modulePath) != 0) {
			log_error_integrity(__func__, "File path missmatch for module", NO_DETAILS_A, modInfo[i].modulePath);
			verifiedIntegrity = FALSE;
		}

		
        HeapFree(GetProcessHeap(), 0, hash);
	}

IntegCleanup:
    if (modInfo) {
        for (size_t i = 0; i < ARRAYSIZE(modulesToVerify); i++)
            if (modInfo[i].hFile) CloseHandle(modInfo[i].hFile);
        free(modInfo);
    }
    if (storedData) free(storedData);
    if (hIntegFile != INVALID_HANDLE_VALUE) CloseHandle(hIntegFile);

    return verifiedIntegrity;
}

int main() {
	if (!verify_integrity()) {
		exit(EXIT_FAILURE);
	}
	
	return 0;
}