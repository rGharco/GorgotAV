#pragma once

#include "file_context.h"

#include <windows.h>
#include <stdio.h>

typedef enum PEStatus PEStatus;

enum PEStatus {
	NOT_PE_FILE_ERR,
	PE_STATUS_OK,

	UNKNOWN_PE_FORMAT_ERR,
};

BOOL parse_pe(PFileContext fc);