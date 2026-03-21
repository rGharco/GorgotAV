#include "integrity.h"

#define MODULE_NAME ((const char*)"integrity_check.c")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define MEMORY_SIZE_8KB 8192 
#define SHA256_HASH_SIZE 32

LPCSTR STARTUP_KEY_NAME = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
LPCWSTR STARTUP_VALUE_NAME_W = L"GorgotIntegrityChecker";
LPCSTR STARTUP_VALUE_NAME_A = "GorgotIntegrityChecker";
LPCWSTR INTEGRITY_CHECKER_EXEC_NAME = L"GorgotIntegrityChecker.exe";
LPCWSTR INTEGRITY_LOG_FILE_NAME = L"integrity_log.txt";
LPCWSTR INTEGRITY_BINARY_FILE_NAME = L"integrity.bin";

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

typedef struct IntegrityData {
	LONGLONG fileSize;
	time_t timestamp;
	_Field_z_ WCHAR modulePath[MAX_PATH];
}IntegrityData;

typedef struct ModuleInfo {
	HANDLE hFile;
	_Field_z_ WCHAR modulePath[MAX_PATH];
}ModuleInfo;

// ---------------------------------------------------
// Integrity Check on startup functions
// ---------------------------------------------------

_Check_return_ _Success_(return != FALSE) 
static BOOL get_integrity_checker_file_path(_Out_writes_z_(MAX_PATH) WCHAR* outExecPath) {
	DWORD pathLength = 0;
	HRESULT res = 0;
	WCHAR selfDir[MAX_PATH] = { 0 };

	pathLength = GetModuleFileNameW(NULL, selfDir, ARRAYSIZE(selfDir));

	if (pathLength == 0 || pathLength >= MAX_PATH) {
		log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to obtain file path for current executable!.");
		return FALSE;
	}

	/* Remove the current module name so from : C:\GorgotAV.exe->C:\ */
	res = PathCchRemoveFileSpec(selfDir, MAX_PATH);

	if (FAILED(res)) {
		log_error_winapi(res, MODULE_NAME, __func__, "Failed to construct path to integrity checker!");
		return FALSE;
	}

	// -- Append to the end of the path GorgotIntegrityChecker.exe to form the final path to the executable
	res = PathCchAppend(selfDir, MAX_PATH, INTEGRITY_CHECKER_EXEC_NAME);

	if (FAILED(res)) {
		log_error_winapi(res, MODULE_NAME, __func__, "Failed to construct path to integrity checker!");
		return FALSE;
	}

	res = StringCchCopyW(outExecPath, MAX_PATH, selfDir);

	if (FAILED(res)) {
		log_error_winapi(res, MODULE_NAME, __func__, "Failed to construct path to integrity checker!");
		return FALSE;
	}
 
	return TRUE;
}

_Check_return_ 
static inline BOOL FileExistsAndNotDirectory(_In_z_ LPCWSTR filePath)
{
	DWORD dwAttrib = GetFileAttributesW(filePath);
	
	if (dwAttrib == INVALID_FILE_ATTRIBUTES) {
		log_error_winapi(GetLastError(), MODULE_NAME, __func__, "GetFileAttributesW failed");
		return FALSE;
	}

	return !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

_Check_return_ _Ret_maybenull_
static HKEY get_registry_run_key_handle() {
	HKEY hKey = NULL;
	LSTATUS opStatus = 0;

	opStatus = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,
		STARTUP_KEY_NAME,
		0,
		KEY_READ | KEY_WRITE,
		&hKey
	);

	if (opStatus != ERROR_SUCCESS || hKey == NULL) {
		log_error_winapi(opStatus, MODULE_NAME, __func__, "Failed to open startup registry key!");
		return NULL;
	}

	return hKey;
}

_Check_return_ _Success_(return == INTEGRITY_CHECK_AT_STARTUP_EXIST)
static IntegrityStatus has_integrity_on_startup(const HKEY hStartupKey, _Out_writes_z_(MAX_PATH) CHAR* outStoredPath) {
	if (outStoredPath) outStoredPath[0] = '\0'; // satisfy SAL contract (string is zero-terminated)
	
	LSTATUS opStatus = 0;
	CHAR storedPath[MAX_PATH] = { 0 };
	DWORD pathBufferSize = sizeof(storedPath);

	opStatus = RegQueryValueExA(
		hStartupKey,
		STARTUP_VALUE_NAME_A,
		NULL,
		NULL,
		(LPBYTE)storedPath,
		&pathBufferSize
	);
	
	if (opStatus != ERROR_SUCCESS) {
		if (opStatus == ERROR_FILE_NOT_FOUND) {
			return INTEGRITY_CHECK_AT_STARTUP_MISSING;
		}
		else {
			log_error_winapi(opStatus, MODULE_NAME, __func__, "Failed to query registry value for savepoint!");
			return INTEGRITY_CHECK_AT_STARTUP_ERR;
		}
	}

	printf("Stored path: %s\n", storedPath);

	HRESULT res = StringCchCopyA(outStoredPath, MAX_PATH, storedPath);

	if (FAILED(res)) {
		log_error_winapi(res, MODULE_NAME, __func__, "Failed to retrived stored executable path!");
		return INTEGRITY_CHECK_AT_STARTUP_ERR;
	}

	return INTEGRITY_CHECK_AT_STARTUP_EXIST;
}

_Check_return_ 
static BOOL set_integrity_on_startup(_In_ const HKEY hStartupKey, _In_z_ const WCHAR* integrityCheckerPath, const DWORD integrityPathLen) {
	LSTATUS opStatus = 0;

	opStatus = RegSetValueExW(
		hStartupKey,
		STARTUP_VALUE_NAME_W,
		0,
		REG_SZ,
		(const BYTE*)integrityCheckerPath,
		integrityPathLen
	);

	if (opStatus != ERROR_SUCCESS) {
		log_error_winapi(opStatus, MODULE_NAME, __func__,
			"Could not set integrity checking on startup. RegSetValueExA() failed!");
		return FALSE;
	}

	return TRUE;
}

// ---------------------------------------------------
// Integrity Check AppData functions
// ---------------------------------------------------

_Check_return_
static BOOL construct_appdata_file_path(_Out_writes_z_(MAX_PATH) WCHAR* outPath, _In_z_ const WCHAR* basePath, _In_z_ const WCHAR* fileName) {
	HRESULT res = 0;
	
	res = StringCchCopyW(outPath, MAX_PATH, basePath);

	if (FAILED(res)) {
		log_error_winapi(res, MODULE_NAME, __func__, "Failed to construct log file path!");
		return FALSE;
	}

	res = PathCchAppend(outPath, MAX_PATH, fileName);

	if (FAILED(res)) {
		log_error_winapi(res, MODULE_NAME, __func__, "Failed to append log file name to path!");
		return FALSE;
	}

	return TRUE;
}

_Check_return_ 
static BOOL construct_antivirus_appdata_path(_Out_writes_z_(MAX_PATH) WCHAR* outPath) {
	HRESULT res = 0;

	// -- 1. Obtain AppData\Local path to create GorgotAV folder at
	res = SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, outPath);
	if (res != S_OK) {
		log_error_winapi(res, MODULE_NAME, __func__, "Failed to find path to AppData\\Local folder\n");
		return FALSE;
	}

	// -- 2. Append the GorgotAV folder to create the full path.
	res = PathCchAppend(outPath, MAX_PATH, L"GorgotAV");
	if (res != S_OK) {
		log_error_winapi(res, MODULE_NAME, __func__, "Failed to construct path to AppData\\Local\\GorgotAV folder\n");
		return FALSE;
	}

	return TRUE;
}

_Check_return_
static BOOL create_log_file(_In_z_ const WCHAR* antivirusFilePath) {
	HANDLE hLogFile = NULL;
	WCHAR logFilePath[MAX_PATH] = { 0 };
	
	if (!construct_appdata_file_path(logFilePath, antivirusFilePath, INTEGRITY_LOG_FILE_NAME)) return FALSE;

	hLogFile = CreateFileW(
		logFilePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hLogFile == INVALID_HANDLE_VALUE) {
		log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to create log file!");
		return FALSE;
	}

	CloseHandle(hLogFile);

	return TRUE;
}

// ---------------------------------------------------
// Integrity Check first integ. functions
// ---------------------------------------------------

_Check_return_ _Ret_maybenull_
static ModuleInfo* get_module_data() {
	ModuleInfo* modInfo = calloc(ARRAYSIZE(modulesToVerify), sizeof(*modInfo));

	if (modInfo == NULL) {
		log_error(MEMORY_ALLOCATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory for module information!", "calloc() failed!");
		return NULL;
	}

	for (size_t i = 0; i < ARRAYSIZE(modulesToVerify); i++) {
		WCHAR path[MAX_PATH] = { 0 };
		HRESULT res = 0;

		DWORD pathLen = SearchPathW(
			NULL,
			modulesToVerify[i],
			NULL,
			MAX_PATH,
			path,
			NULL
		);

		if (pathLen == 0) {
			wprintf(L"Could not find path for module: %ls\n", path);
			continue;
		};


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
			log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to create a file handle for module");
			continue;
		}

		modInfo[i].hFile = hFile;
		res = StringCchCopyW(modInfo[i].modulePath, MAX_PATH, path);

		if (FAILED(res)) {
			log_error_winapi(res, MODULE_NAME, __func__, "Failed to copy module path to module info struct");
			continue;
		}
	}

	return modInfo;
}

_Check_return_ 
IntegrityStatus add_integrity_check_to_startup() {
	WCHAR integrityCheckerPath[MAX_PATH] = { 0 };
	CHAR storedPath[MAX_PATH] = { 0 };

	if (!get_integrity_checker_file_path(integrityCheckerPath)) return INTEGRITY_CHECK_AT_STARTUP_ERR;

	if (!FileExistsAndNotDirectory(integrityCheckerPath)) return INTEGRITY_CHECK_AT_STARTUP_ERR;

	HKEY hStartupKey = get_registry_run_key_handle();

	if (hStartupKey == NULL) return INTEGRITY_CHECK_AT_STARTUP_ERR;

	IntegrityStatus startupValueStatus = has_integrity_on_startup(hStartupKey, storedPath);

	if (startupValueStatus == INTEGRITY_CHECK_AT_STARTUP_EXIST || storedPath[0] != '\0') {
		log_warning(MODULE_NAME, __func__, "There is already a path set for integrity checking: ", storedPath);

		goto Cleanup;
	}
	
	if (startupValueStatus == INTEGRITY_CHECK_AT_STARTUP_ERR) goto Cleanup;

	if (!set_integrity_on_startup(hStartupKey, integrityCheckerPath, (DWORD)ARRAYSIZE(integrityCheckerPath))) goto Cleanup;

	return INTEGRITY_CHECK_AT_STARTUP_SET;
Cleanup:
	if (hStartupKey) RegCloseKey(hStartupKey);

	return INTEGRITY_CHECK_AT_STARTUP_ERR;
}

_Check_return_
IntegrityStatus create_app_data_folder() {
	WCHAR appDataPath[MAX_PATH] = { 0 };
	DWORD fileAttrCode = 0;

	if (!construct_antivirus_appdata_path(appDataPath)) return INTEGRITY_APPDATA_CREATE_ERR;

	// -- 1. Check folder existance and naming conflicts
	fileAttrCode = GetFileAttributesW(appDataPath);
	if (fileAttrCode != INVALID_FILE_ATTRIBUTES) {
		if (fileAttrCode & FILE_ATTRIBUTE_DIRECTORY) {
			if (!create_log_file(appDataPath)) return INTEGRITY_APPDATA_CREATE_ERR;
		}
		else {
			log_error_winapi(GetLastError(), MODULE_NAME, __func__, "A file exists with the same name as the folder.");
			return INTEGRITY_APPDATA_CREATE_ERR;
		}
	}

	// -- 2. Create folder GorgotAV
	if (CreateDirectoryW(appDataPath, NULL) == FALSE) {
		log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Something went wrong creating the GorgotAV folder");
		return INTEGRITY_APPDATA_CREATE_ERR;
	}

	// -- 3. Create log file
	if (!create_log_file(appDataPath)) {
		return INTEGRITY_APPDATA_CREATE_ERR;
	}

	return INTEGRITY_APPDATA_CREATE_SUCCESS;
}

_Check_return_
IntegrityStatus store_integrity_data() {
	ModuleInfo* modInfo = NULL;
	HANDLE hIntegDataFile = INVALID_HANDLE_VALUE;

	// -- 1. Get module information to use for hashing, timestamping, file size etc.
	modInfo = get_module_data();

	if (modInfo == NULL) goto IntegCleanup;

	// -- 2. Construct path towards integrity.bin file to store data to
	WCHAR appDataFolder[MAX_PATH] = { 0 };
	if (!construct_antivirus_appdata_path(appDataFolder)) goto IntegCleanup;

	WCHAR integDataFilePath[MAX_PATH] = { 0 };
	if (!construct_appdata_file_path(integDataFilePath, appDataFolder, INTEGRITY_BINARY_FILE_NAME)) goto IntegCleanup;

	hIntegDataFile = CreateFileW(
		integDataFilePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hIntegDataFile == INVALID_HANDLE_VALUE) {
		log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to create integrity binary file!");
		free(modInfo);
		return INTEGRITY_CHECK_ERR;
	}

	// -- 3. Compute integrity information for files
	for (size_t i = 0; i < ARRAYSIZE(modulesToVerify); i++) {
		DWORD cbHash = 0;
		PBYTE hash = create_hash(modInfo[i].hFile, &cbHash);

		if (hash == NULL || cbHash == 0) {
			log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to create hash for current module", NO_DESCRIPTION);
			continue;
		}

		LARGE_INTEGER fileSize = { 0 };

		if (!GetFileSizeEx(modInfo[i].hFile, &fileSize)) {
			log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to get module file size");
			HeapFree(GetProcessHeap(), 0, hash);
			goto IntegCleanup;
		}

		IntegrityData info = { 0 };

		info.timestamp = time(NULL);
		info.fileSize = fileSize.QuadPart;
		StringCchCopyW(info.modulePath, MAX_PATH, modInfo[i].modulePath);

		DWORD bytesWritten = 0;

        // -- 1. Write hash size (cbHash)
        if (!WriteFile(hIntegDataFile, &cbHash, sizeof(cbHash), &bytesWritten, NULL)) {
            log_error_winapi(GetLastError(), MODULE_NAME, __func__,
                "WriteFile failed for hash size");
            HeapFree(GetProcessHeap(), 0, hash);
            goto IntegCleanup;
        }

        // -- 2. Write hash bytes
        if (!WriteFile(hIntegDataFile, hash, cbHash, &bytesWritten, NULL)) {
            log_error_winapi(GetLastError(), MODULE_NAME, __func__,
                "WriteFile failed for hash bytes");
            HeapFree(GetProcessHeap(), 0, hash);
            goto IntegCleanup;
        }

        // -- 3. Write info struct
        if (!WriteFile(hIntegDataFile, &info, sizeof(info), &bytesWritten, NULL)) {
            log_error_winapi(GetLastError(), MODULE_NAME, __func__,
                "WriteFile failed for info struct");
            HeapFree(GetProcessHeap(), 0, hash);
            goto IntegCleanup;
        }

        HeapFree(GetProcessHeap(), 0, hash);
	}

	if (modInfo) free(modInfo);
	if (hIntegDataFile) CloseHandle(hIntegDataFile);

	return INTEGRITY_CHECK_SUCCESS;
IntegCleanup:
	if (modInfo) free(modInfo);
	if (hIntegDataFile) CloseHandle(hIntegDataFile);

	return INTEGRITY_CHECK_ERR;	
}

_Check_return_
IntegrityStatus remove_integrity_check_from_startup() {
	HKEY hKey = NULL;
	LSTATUS opStatus = 0;
	WCHAR antivirusAppDataPath[MAX_PATH] = { 0 };
	WCHAR logFilePath[MAX_PATH] = { 0 };
	WCHAR integBinaryFilePath[MAX_PATH] = { 0 };

	opStatus = RegOpenKeyExA(
		HKEY_LOCAL_MACHINE,       
		STARTUP_KEY_NAME,
		0,
		KEY_SET_VALUE,            
		&hKey
	);

	if (opStatus != ERROR_SUCCESS) {
		log_error(opStatus, MODULE_NAME, __func__, "Failed to open startup registry key!", "RegOpenKeyExA() failed!");
		goto DeleteCleanup;
	}

	opStatus = RegDeleteValueW(hKey, STARTUP_VALUE_NAME_W);
	if (opStatus != ERROR_SUCCESS) {
		if (opStatus == ERROR_FILE_NOT_FOUND) {
			log_warning(MODULE_NAME, __func__, "Startup registry value for integrity checker does not exist!", NO_DESCRIPTION);
			if (hKey) RegCloseKey(hKey); // dont return here we can still check to delete the folder
		}
		else {
			log_error(opStatus, MODULE_NAME, __func__, "Failed to delete registry value!", "RegDeleteValueA() failed!");
			goto DeleteCleanup;
		}
	}

	// -- 1. Construct paths to delete log file and AppData folder and integrity.bin
	if (!construct_antivirus_appdata_path(antivirusAppDataPath)) goto DeleteCleanup;

	if (!construct_appdata_file_path(logFilePath, antivirusAppDataPath, INTEGRITY_LOG_FILE_NAME)) goto DeleteCleanup;

	if (!construct_appdata_file_path(integBinaryFilePath, antivirusAppDataPath, INTEGRITY_BINARY_FILE_NAME)) goto DeleteCleanup;

	// -- 2. Remove log file 
	if (FileExistsAndNotDirectory(logFilePath)) {
		if (!DeleteFileW(logFilePath)) {
			log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to delete log file!");
			goto DeleteCleanup;
		}
	}

	// -- 3. Remove log file 
	if (FileExistsAndNotDirectory(integBinaryFilePath)) {
		if (!DeleteFileW(integBinaryFilePath)) {
			log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to delete log file!");
			goto DeleteCleanup;
		}
	}

	// -- 4. Remove AppData folder
	if (GetFileAttributesW(antivirusAppDataPath) != INVALID_FILE_ATTRIBUTES) {
		if (!RemoveDirectoryW(antivirusAppDataPath)) {
			log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to delete antivirus AppData folder!");
			goto DeleteCleanup;
		}
	}

	log_success("Successfully integrity checking");

	if (hKey) RegCloseKey(hKey);

	return INTEGRITY_REMOVE_STARTUP_SUCCESS;

DeleteCleanup:
	if (hKey) RegCloseKey(hKey);

	return INTEGRITY_REMOVE_STARTUP_ERR;
}