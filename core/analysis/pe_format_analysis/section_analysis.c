#include "file_context.h"
#include "static_analysis.h"

#define MODULE_NAME "section_analysis.c"

// -- Standard executable sections name
static const BYTE TEXT_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', '\0', '\0', '\0' };
static const BYTE TEXT_BSS_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', 'b', 's', 's' };
static const BYTE CODE_SECTION_NAME[8] = { '.', 'c', 'o', 'd', 'e', '\0', '\0', '\0' };

// -- If a section that is not .text, .textbss, or .code has the exectuable flag set return it in the array --
_Check_return_ _Ret_maybenull_
char** get_suspicious_executable_sections(_In_ const PFileContext fc, WORD* outCount) {
	*outCount = 0;

	WORD nrOfSections = get_nr_of_sections(fc);
	PIMAGE_SECTION_HEADER ptrToSections = get_ptr_to_section_start(fc);

	if (ptrToSections == NULL) {
		return NULL;
	}

	WORD count = 0;
	for (WORD i = 0; i < nrOfSections; i++) {
		bool ok = memcmp(ptrToSections[i].Name, TEXT_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME) == 0 ||
				  memcmp(ptrToSections[i].Name, TEXT_BSS_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME) == 0 ||
				  memcmp(ptrToSections[i].Name, CODE_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME) == 0;
		
		if ((ptrToSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && !ok) {
			count++;
		}
	}

	if (count == 0) {
		return NULL;
	}

	char** result = malloc(count * sizeof(*result));
	if (result == NULL) {
		return NULL;
	}

	char* buffer = malloc(count * SECTION_NAME_LENGTH);
    if (buffer == NULL) {
        free(result);
        return NULL;
    }

	WORD idx = 0;
	for (WORD i = 0; i < nrOfSections; i++) {
		bool ok = memcmp(ptrToSections[i].Name, TEXT_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME) == 0 ||
				  memcmp(ptrToSections[i].Name, TEXT_BSS_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME) == 0 ||
				  memcmp(ptrToSections[i].Name, CODE_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME) == 0;
		
		if ((ptrToSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && !ok) {
			char* section = buffer + (idx * SECTION_NAME_LENGTH);

            memcpy(section, ptrToSections[i].Name, IMAGE_SIZEOF_SHORT_NAME);
            section[IMAGE_SIZEOF_SHORT_NAME] = '\0';

            result[idx] = section;
            idx++;
		}
	}

	*outCount = count;
	return result;
}

void free_suspicious_sections(_In_ char** sections) {
    if (!sections) return;

    free(sections[0]); // contiguous buffer
    free(sections);
}

void import_table_analysis(_In_ const PFileContext fc) {
    LPVOID baseAddress = get_base_address(fc);
    PeFormat peFormat = get_pe_format(fc);

    DWORD importRVA = 0;
    DWORD importSize = 0;

    if (peFormat == PE32) {
        PIMAGE_NT_HEADERS32 nt = get_optional_header_32(fc);
        importRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        PIMAGE_NT_HEADERS64 nt = get_optional_header_64(fc);
        importRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (importRVA == 0) {
        LOG_VERBOSE_SUSPICIOUS_INDICATOR("Invalid import table (possible packing or manual import resolution)!", "");
        return;
    }

    if (importSize == 0) {
        LOG_VERBOSE_SUSPICIOUS_INDICATOR("Invalid import table size(possible packing or manual import resolution)!", "");
        return;
    }

    DWORD importOffset = rva_to_raw(fc, importRVA);
    if (importOffset == 0) {
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR imp =(PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddress + importOffset);

    while (imp->Name != 0) {
        DWORD nameOffset = rva_to_raw(fc, imp->Name);
        if (nameOffset == 0) break;

        char* lib = (char*)((BYTE*)baseAddress + nameOffset);
        printf("Library: %s\n", lib); 

        imp++;
    }
}

_Check_return_
bool has_tls_callbacks(_In_ const PFileContext fc) {
    PeFormat peFormat = get_pe_format(fc);
    DWORD importRVA = 0;
    DWORD importSize = 0;

    if (peFormat == PE32) {
        PIMAGE_NT_HEADERS32 nt = get_optional_header_32(fc);
        importRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        PIMAGE_NT_HEADERS64 nt = get_optional_header_64(fc);
        importRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    return importRVA != 0 && importSize != 0;
}

_Check_return_ 
bool is_standard_exec_sect(_In_reads_bytes_(SECTION_NAME_LENGTH) const char* sectionName) {
	if (strcmp(sectionName, TEXT_SECTION_NAME) == 0) return true;
	if (strcmp(sectionName, TEXT_BSS_SECTION_NAME) == 0) return true;
	if (strcmp(sectionName, CODE_SECTION_NAME) == 0) return true;

	return false;
}

_Check_return_ _Ret_maybenull_
SectionInfo* get_sect_info(_In_ const PFileContext fc) {
	WORD nrOfSections = get_nr_of_sections(fc);
	PIMAGE_SECTION_HEADER ptrSections = get_ptr_to_section_start(fc);
	BYTE* baseAddress = (BYTE*)get_base_address(fc);

	SectionInfo* sectInfo = calloc(nrOfSections, sizeof(*sectInfo));
	if (sectInfo == NULL) {
		log_error(MEMORY_ALLOCATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory to SectionInfo struct.", "get_sect_info() failed!");
		return NULL;
	}

	for (WORD i = 0; i < nrOfSections; i++) {
        DWORD rawSize = ptrSections[i].SizeOfRawData;
        DWORD rawPtr  = ptrSections[i].PointerToRawData;
        LARGE_INTEGER fileSize;
        
        if (!GetFileSizeEx(get_file_handle(fc), &fileSize)) {
            log_warning(MODULE_NAME, __func__, "Failed to get file size for section analysis.", "GetFileSizeEx() failed for section info!");
            return NULL;
        }

        if (rawSize == 0 || rawPtr == 0) {
            continue;
        }

        if (rawPtr >= fileSize.QuadPart || rawSize > fileSize.QuadPart - rawPtr) {
            log_warning(MODULE_NAME,__func__, "Skipping entropy for section %s (invalid bounds)", sectInfo[i].sectionName);
            continue;
        } 

		memcpy(sectInfo[i].sectionName, ptrSections[i].Name, SECTION_NAME_LENGTH - 1); // they do not contain NULL terminator by default
		sectInfo[i].sectionName[SECTION_NAME_LENGTH - 1] = '\0';

		sectInfo[i].isExec = (ptrSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        sectInfo[i].startAddr = ptrSections[i].VirtualAddress;
		sectInfo[i].endAddr = ptrSections[i].VirtualAddress + max(ptrSections[i].Misc.VirtualSize, rawSize);
        
        double entropy = memory_entropy_calculation(rawSize, baseAddress + rawPtr);

        if (entropy == 0) {
            LOG_VERBOSE_SUSPICIOUS_INDICATOR("Entropy is 0 for section: ", sectInfo[i].sectionName);
        }

        sectInfo[i].entropy = entropy ;
	}

	return sectInfo;
}