#include "pe_utils.h"

#define MODULE_NAME "pe_utils.c"

#define PE32 0x10b
#define PE32_PLUS 0x20b

PEStatus parse_pe(PFileContext fc) {
	LPVOID baseAddress = get_base_address(fc);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	
	// Check for 'MZ' signature
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NOT_PE_FILE_ERR;
	}

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader->e_lfanew);
	// Check for 'PE\0\0' signature
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NOT_PE_FILE_ERR;
	}

	// Check if it is PE32 or PE32+
	WORD Magic = ntHeaders->OptionalHeader.Magic;

	if (Magic == PE32_PLUS) {
		PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHeaders;

		WORD nrOfSections = nt64->FileHeader.NumberOfSections;

		PIMAGE_SECTION_HEADER ptrToSectionsStart = (PIMAGE_SECTION_HEADER)((BYTE*)nt64 + sizeof(IMAGE_NT_HEADERS64));

		set_nr_of_sections(fc, nrOfSections);
		set_sections_ptr(fc, ptrToSectionsStart);
	}
	else if (Magic == PE32) {
		PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)ntHeaders;

	}
	else {
		return UNKNOWN_PE_FORMAT_ERR;
	}

	return PE_STATUS_OK;
}