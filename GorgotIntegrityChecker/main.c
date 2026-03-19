/*
	@brief: This module has two purposes:
		- run a verify_integrity() function which analyzes the integrity of important modules and checks them against a previous
		  metadata file, to see if any changes happended to them (hash, timestamp, file size, file path)
			- if integrity is verified -> log results, if integrity is not verified -> alert user with popup 
		- log results inside a log file stored in: C:\Users\<user>\AppData\Local\GorgotAV\integrity_logs.txt	
*/


// TODO !!!!!!!!!!!!!!!!!!!
// After wrapping up the integrity checking functions remember to not print anything to the terminal but instead log everythign
// in a file that resides in AppData folder. Fix this after finishing the whole computing operations

#include <stdio.h>
#include <Windows.h>
#include <ShlObj.h>
#include <wchar.h>
#include <PathCch.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Pathcch.lib")

#define STATIC_ARRAY_LENGTH(x) sizeof((x)) / sizeof((x)[0])

typedef struct IntegrityData {
	_Field_z_ PBYTE sha256Hash;
	LARGE_INTEGER fileSize;
	time_t timestamp;
	_Field_z_ WCHAR modulePath[MAX_PATH];
}IntegrityData;

typedef struct ModuleInfo {
	HANDLE hFile;
	WCHAR modulePath[MAX_PATH];
} ModuleInfo;

// ---------------------------------------------------
// Global definitions
// ---------------------------------------------------
LPCWSTR modulesToVerify[] = {
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
	L"dism.exe",
	L"wuauclt.exe",
	L"usoclient.exe"
};

// TODO: Create a ModuleInfo* array that stores module information and return it to the caller
//		 The caller then hashes and performs operation on the items
static ModuleInfo* get_module_info() {
	ModuleInfo* modInfo = calloc(STATIC_ARRAY_LENGTH(modulesToVerify), sizeof(ModuleInfo));

	if (modInfo == NULL) {
		// TODO: Log error in log file
		exit(EXIT_FAILURE);
	}

	for (size_t i = 0; i < STATIC_ARRAY_LENGTH(modulesToVerify); i++) {
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
			// TODO: Add logging to log file for missing modules
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
			// Log error in log file
			continue;
		}

		modInfo[i].hFile = hFile;
		wcscpy_s(modInfo[i].modulePath, MAX_PATH, path);
	}

	return modInfo;
}

static int create_folder_if_missing(const WCHAR* folderPath) {
	DWORD attribs = GetFileAttributesW(folderPath);

	if (attribs != INVALID_FILE_ATTRIBUTES && (attribs & FILE_ATTRIBUTE_DIRECTORY)) {
		// Folder already exists
		return 1;
	}

	if (!CreateDirectoryW(folderPath, NULL)) {
		DWORD err = GetLastError();
		wprintf(L"Failed to create directory '%ls'. Error: %lu\n", folderPath, err);
		return -1;
	}

	return 0;
}

static int check_first_integrity(WCHAR* outFolderPath, size_t maxLen) {
	if (!outFolderPath || maxLen == 0) return -1;

	WCHAR appDataPath[MAX_PATH] = { 0 };

	if (!SUCCEEDED(SHGetFolderPathW(
		NULL,
		CSIDL_LOCAL_APPDATA,
		NULL,
		SHGFP_TYPE_CURRENT,
		appDataPath)))
	{
		// TODO: log error
		return -1;
	}

	HRESULT hr = PathCchCombine(outFolderPath, maxLen, appDataPath, L"GorgotAV");
	if (FAILED(hr)) {
		// TODO: log error
		return -1;
	}

	// Delegate folder creation to auxiliary function
	if (create_folder_if_missing(outFolderPath) == 1) {
		return 1;
	}
	else if (create_folder_if_missing(outFolderPath) == -1) {
		return -1;
	}
	else {
		return 0;
	}
}

// TODO: Make sure to check for the existance of the integrity.bin in AppData, if that file does not exist then it is the first time
// performing an integrity check and we can skip the comparing operations 
static void verify_integrity() {
	ModuleInfo* modInfo = get_module_info();

	WCHAR gorgotFolder[MAX_PATH] = { 0 };

	// TODO: Replace random magic numbers with enum literals for clarity, here it would be FIRST_INTEGRITY or CREATION_ERROR or smth
	if (check_first_integrity(gorgotFolder, MAX_PATH) == 0) {
		// TODO: Log creation success using timestamp

		// Build log file path
		WCHAR logFilePath[MAX_PATH] = { 0 };
		PathCchCombine(logFilePath, MAX_PATH, gorgotFolder, L"integrity_logs.txt");
	}
	else {
		// TODO: Log error
		exit(EXIT_FAILURE);
	}

	
	if (modInfo) {
		for (size_t i = 0; i < STATIC_ARRAY_LENGTH(modulesToVerify); i++) {
			if (modInfo[i].hFile) CloseHandle(modInfo[i].hFile);
		}
	}

	free(modInfo);
	modInfo = NULL;
}

int main() {
	verify_integrity();
	
	return 0;
}