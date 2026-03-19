#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <ShlObj.h>
#include <tchar.h>
#include <pathcch.h>
#include <sal.h>
#include <bcrypt.h>
#include <strsafe.h>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Pathcch.lib")
#pragma comment (lib, "bcrypt.lib")
#pragma comment(lib, "Advapi32.lib")

#include "logging.h"

typedef enum IntegrityStatus {
	INTEGRITY_CHECK_AT_STARTUP_ERR,
	INTEGRITY_CHECK_AT_STARTUP_EXIST,
	INTEGRITY_CHECK_AT_STARTUP_MISSING,
	INTEGRITY_CHECK_AT_STARTUP_SET,

	INTEGRITY_APPDATA_CREATE_SUCCESS,
	INTEGRITY_APPDATA_CREATE_ERR,

	INTEGRITY_REMOVE_STARTUP_ERR,
	INTEGRITY_REMOVE_STARTUP_SUCCESS,

	INTEGRITY_CHECK_ERR,
	INTEGRITY_CHECK_SUCCESS,
}IntegrityStatus;

typedef struct IntegrityData IntegrityData;

_Check_return_
IntegrityStatus add_integrity_check_to_startup();

_Check_return_
IntegrityStatus create_app_data_folder();

_Check_return_
IntegrityStatus remove_integrity_check_from_startup();

_Check_return_
IntegrityStatus store_integrity_data();