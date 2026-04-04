#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include "logging.h"

_Check_return_ 
BOOL construct_antivirus_appdata_path(_Out_writes_z_(MAX_PATH) WCHAR* outPath) {
	const WCHAR* const GORGOTAV_APPDATA_FOLDER_NAME = L"GorgotAV";

	HRESULT res = 0;

	// -- 1. Obtain AppData\Local path to create GorgotAV folder at
	res = SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, outPath);
	if (res != S_OK) {
		// TODO: Log error to log file instead of stoudt
		// log_error_winapi(res, MODULE_NAME, __func__, "Failed to find path to AppData\\Local folder\n");
		return FALSE;
	}

	// -- 2. Append the GorgotAV folder to create the full path.
	res = PathCchAppend(outPath, MAX_PATH, GORGOTAV_APPDATA_FOLDER_NAME);
	if (res != S_OK) {
		// TODO: Log error to log file instead of stoudt
		// log_error_winapi(res, MODULE_NAME, __func__, "Failed to construct path to AppData\\Local\\GorgotAV folder\n");
		return FALSE;
	}

	return TRUE;
}

_Check_return_
BOOL construct_appdata_file_path(_Out_writes_z_(MAX_PATH) WCHAR* outPath, _In_z_ const WCHAR* basePath, _In_z_ const WCHAR* fileName) {
	HRESULT res = 0;
	
	res = StringCchCopyW(outPath, MAX_PATH, basePath);

	if (FAILED(res)) {
		// TODO: Log error to log file
		// log_error_winapi(res, MODULE_NAME, __func__, "Failed to construct log file path!");
		return FALSE;
	}

	res = PathCchAppend(outPath, MAX_PATH, fileName);

	if (FAILED(res)) {
		// log_error_winapi(res, MODULE_NAME, __func__, "Failed to append log file name to path!");
		// TODO: Log error to log file
		return FALSE;
	}

	return TRUE;
}
