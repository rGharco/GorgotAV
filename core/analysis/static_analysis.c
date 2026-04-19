#include "static_analysis.h"
#include "pe_utils.h"
#include "logging.h"

#define MODULE_NAME "static_analysis.c"

#define MEMORY_512B 512 
#define MEMORY_100KB 102400 
#define SHA256_HASH_BYTES 32
#define SHA256_HASH_HEX_STRING_SIZE  ((SHA256_HASH_BYTES * 2) + 1) // + 1 for NULL terminator
#define HIGH_ENTROPY_THRESHOLD 7.2 

#define JMP_OPCODE 0xE9
#define CALL_OPCODE 0xE8
#define RET_OPCODE 0xC3
#define e_lfanew 0x3C
#define BYTE_SIZE 256 

#define ENTROPY_TH1 7.2
#define ENTROPY_TH2 7.6

// -- Standard executable sections name
static const BYTE TEXT_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', '\0', '\0', '\0' };
static const BYTE TEXT_BSS_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', 'b', 's', 's' };
static const BYTE CODE_SECTION_NAME[8] = { '.', 'c', 'o', 'd', 'e', '\0', '\0', '\0' };

int indicators = 0; // contains the number of found indicators so far

//-----------------------------------------------------------
// Hashing
//-----------------------------------------------------------

// This function has been AI generated to improve performance when transforming from binary data to hex readable strings
static void binaryToHexHash(_In_ const PBYTE restrict pHash, _Out_writes_z_(SHA256_HASH_BYTES) char* restrict outHashHex) {
    static const char hex[] = "0123456789ABCDEF";
    const unsigned char* bytes = (const unsigned char*)pHash;

    for (ULONG i = 0; i < SHA256_HASH_BYTES; ++i) {
        unsigned char b = bytes[i];

        // High nibble (first hex char)
        outHashHex[2 * i]     = hex[(b >> 4) & 0x0F];

        // Low nibble (second hex char)
        outHashHex[2 * i + 1] = hex[b & 0x0F];
    }

    outHashHex[2 * SHA256_HASH_BYTES] = '\0';
}

//-----------------------------------------------------------
// Entropy
//-----------------------------------------------------------

_Check_return_ 
double memory_entropy_calculation(_In_ const uint64_t size, _In_ const BYTE* dataPtr) {
	// Counts how many times a byte appears to the make its probability. As per Shanon's entropy function we need the probability
	// of an event happening (p(xi)) * log_2(p(xi))
	if (!dataPtr || size == 0)
        return 0.0;

    unsigned long long byteCount[BYTE_SIZE] = { 0 };

    for (uint64_t i = 0; i < size; i++) {
        byteCount[(unsigned char)dataPtr[i]]++;
    }

    double entropy = 0.0;

    for (int i = 0; i < 256; i++) {
        if (byteCount[i] == 0) continue;

        double p = (double)byteCount[i] / (double)size;
        entropy -= p * log2(p);
    }

	return entropy;
}

ENTROPY_STATUS verify_entropy_status(_In_ double entropy) {
	if (entropy < ENTROPY_TH1) return ENTROPY_NORMAL;
    if (entropy < ENTROPY_TH2) return ENTROPY_SUSPICIOUS;

    return ENTROPY_HIGHLY_SUSPICIOUS;
}

//-----------------------------------------------------------
// PE format functions
//-----------------------------------------------------------

DWORD rva_to_raw(const PFileContext fc, DWORD rva) {
    WORD n = get_nr_of_sections(fc);
    PIMAGE_SECTION_HEADER sections = get_ptr_to_section_start(fc);

    for (WORD i = 0; i < n; i++) {

        DWORD va = sections[i].VirtualAddress;

        DWORD size = sections[i].Misc.VirtualSize;
        if (size < sections[i].SizeOfRawData)
            size = sections[i].SizeOfRawData;

        DWORD end = va + size;
        if (end < va)
            continue;

        if (rva >= va && rva < end) {
            return (rva - va) + sections[i].PointerToRawData;
        }
    }

    return 0;
}

static void appending_file_infection_check(_In_ const PFileContext fc, _In_ const SectionInfo* sectInfo) {
	WORD nrOfSections = get_nr_of_sections(fc);
	PeFormat peFormat = get_pe_format(fc);
	DWORD aep = peFormat == PE32 ? get_optional_header_32(fc)->OptionalHeader.AddressOfEntryPoint : get_optional_header_64(fc)->OptionalHeader.AddressOfEntryPoint;

	bool insideSection = false;
	DWORD aepOffset = rva_to_raw(fc, aep);
	
	for (WORD i = 0; i < nrOfSections; i++) {
		if (insideSection) break;  

		if (aep >= sectInfo[i].startAddr && aep < sectInfo[i].endAddr) {
			// AEP is inside this section
			insideSection = true;

			bool isStandardExec = is_standard_exec_sect(sectInfo[i].sectionName);

			// -- 1. Verify section name + permissions
			if (sectInfo[i].isExec && !isStandardExec) {
				indicators += 5;
				LOG_VERBOSE_SUSPICIOUS_INDICATOR("Executable non-standard section detected (exec + non-standard name)\n", sectInfo[i].sectionName);
			}
			
			// -- 2. Verify entropy 
			if (sectInfo[i].entropy >= HIGH_ENTROPY_THRESHOLD) {
				indicators += 3;
				LOG_VERBOSE_SUSPICIOUS_INDICATOR("High entropy section detected (possible packed/encrypted code)\n", sectInfo[i].sectionName);
			}

			// -- 3. Verify JMP instructions or PUSH and RET combination
			BYTE* baseAddr = get_base_address(fc);
			baseAddr += aepOffset;
			
			// -- 3.1 Verify JMP to another section
			for (int k = 0; k < 50; k++) {
				if (baseAddr[k] == JMP_OPCODE) {
					INT32 rel = *(INT32*)(baseAddr + k + 1);
					DWORD targetRVA = aep + k + 5 + rel;

					int dstSection = -1;

					for (WORD j = 0; j < nrOfSections; j++) {
						if (targetRVA >= sectInfo[j].startAddr &&
							targetRVA < sectInfo[j].endAddr) {
							dstSection = j;
							break;
						}
					}

					if (dstSection == -1) {
						indicators += 10;
						LOG_VERBOSE(config.outFile,"[INDICATOR] JMP target is outside all sections\n");
					}
					else if (dstSection != i) {
						if (!is_standard_exec_sect(sectInfo[dstSection].sectionName) && sectInfo[dstSection].isExec) {
							printf("[INDICATOR] Highly suspicious, JMP redirects execution to a non-standard executable section!");
							indicators += 1;
						}
						indicators += 1;
						LOG_VERBOSE_SUSPICIOUS_INDICATOR("JMP redirects execution to a different section\n", "");
					}
				}

				// -- CALL + RET pattern
				if (baseAddr[k] == CALL_OPCODE && baseAddr[k + 5] == RET_OPCODE) {
					indicators += 5;
					LOG_VERBOSE_SUSPICIOUS_INDICATOR("Detected CALL + RET sequence\n", "");
				}
			}
		}
	}

	if (insideSection == false) {
		indicators += 10;
		LOG_VERBOSE(config.outFile,"[INDICATOR] AEP is outside all sections (possible overlay or infection stub)\n");
		return;
	}

	return;
}

_Check_return_ 
static bool detect_overlay_exist(_In_ const PFileContext fc, _Out_ DWORD* restrict overlaySize, _Out_ DWORD* restrict overlayOffset ) {
	WORD nrOfSections = get_nr_of_sections(fc);
	PIMAGE_SECTION_HEADER ptrToSections = get_ptr_to_section_start(fc);

	*overlaySize = 0;
	*overlayOffset = 0;

	DWORD maxEnd = 0;
	for (WORD i = 0; i < nrOfSections; i++) {
		DWORD end = ptrToSections[i].PointerToRawData + ptrToSections[i].SizeOfRawData;
		if (end > maxEnd) { 
			maxEnd = end;
		}
	}

	LARGE_INTEGER lFileSize;
	if (!GetFileSizeEx(get_file_handle(fc), &lFileSize)) {
		log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to get file size for overlay detection!, GetFileSizeEx() failed!");
		return false;
	}

	// -- Verify certificate existance and remove the bytes of it to not be treated as overlay
	DWORD certOffset = 0;
	DWORD certSize = 0;
	PeFormat peFormat = get_pe_format(fc);

	if (peFormat == PE32) {
		PIMAGE_NT_HEADERS32 nt = get_optional_header_32(fc);
		certOffset = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
		certSize   = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	}
	else {
		PIMAGE_NT_HEADERS64 nt = get_optional_header_64(fc);
		certOffset = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
		certSize   = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	}

	DWORD effectiveEnd = maxEnd;

	if (certOffset > maxEnd && certSize > 0) {
		effectiveEnd = certOffset + certSize;
	}

	if (lFileSize.QuadPart > effectiveEnd) {
		DWORD size = (DWORD)(lFileSize.QuadPart - effectiveEnd);
		if (size < MEMORY_512B) {
			return false; // Noise filter for padding/alignment overlays
		}

		*overlaySize = (DWORD)(lFileSize.QuadPart - effectiveEnd);
		*overlayOffset = effectiveEnd;
		return true;
	}

	return false;
}

static void check_overlay_anomalies(_In_ const PFileContext fc) {
	DWORD overlaySize = 0;
	DWORD overlayOffset = 0;

	if (!detect_overlay_exist(fc, &overlaySize, &overlayOffset)) {
		return;
	}

	BYTE* overlayAddress = (BYTE*)get_base_address(fc) + overlayOffset;

	if (overlaySize > MEMORY_100KB) {
		indicators += 5;
		LOG_VERBOSE_SUSPICIOUS_INDICATOR("Large overlay section detected...", "");
	}

	if (overlaySize > 1024) {
		double entropy = memory_entropy_calculation(overlaySize, overlayAddress);

		if (entropy > 7.2) {
			indicators += 4;
			LOG_VERBOSE_SUSPICIOUS_INDICATOR("High entropy overlay detected...", "");
		}
	}
	
	// -- Check for 'MZ' signature
	const int MZ_SCAN_LIMIT = 2028;
	DWORD scanLimit = min(overlaySize, MZ_SCAN_LIMIT);

	for (DWORD i = 0; i + 1 < scanLimit; i++) {
		if (overlayAddress[i] == 'M' && overlayAddress[i + 1] == 'Z') {
			indicators += 6;

			DWORD peOffset = *(DWORD*)(overlayAddress + i + e_lfanew);
			if (peOffset < 0x1000 && i + peOffset + 4 < overlaySize) {
				if (!memcmp(overlayAddress + i + peOffset, "PE\0\0", 4)) {
					indicators += 10;
					LOG_VERBOSE(config.outFile, "[INDICATOR] Valid embedded PE detected in overlay!\n");
				}
			}
			break;
		}
	}
	// -- Check for ZIP archive signature (PK)
	const int PK_SCAN_LIMIT = 1024;
	for (DWORD i = 0; i + 1 < min(PK_SCAN_LIMIT, overlaySize); i++) {
		if (overlayAddress[i] == 'P' && overlayAddress[i + 1] == 'K') {
			indicators += 5;
			LOG_VERBOSE(config.outFile, "Embedded ZIP detected in overlay...");
			break;
		}
	}

	// -- Check for JMP or CALL opcodes
	for (DWORD i = 0; i < min(50, overlaySize); i++) {
        if (overlayAddress[i] == JMP_OPCODE || overlayAddress[i] == CALL_OPCODE) {
            indicators += 3;
            break;
        }
    }
}

// We do not free the pointers allocated in this function as their lifetime is dependent of AnalaysisResult 
void static_analysis(const PFileContext fc, AnalysisResult* result) {
	// -- Hashing 
	show_analysis_steps_banner("Analysis Steps");

	PBYTE hash = create_hash(get_file_handle(fc), NULL);
	char* sha256Hash = calloc(1, SHA256_HASH_HEX_STRING_SIZE);

	if (sha256Hash == NULL) {
		log_error(LOG_MEMORY_ALLOCATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory for SHA256 hash.", "calloc() failed!");
	}

	binaryToHexHash(hash, sha256Hash);

	result->sha256Hash = sha256Hash;

	// -- Entropy calculation
	LOG_VERBOSE(config.outFile, "Starting entropy calculation...");

	LARGE_INTEGER lInt;
	if (!GetFileSizeEx(get_file_handle(fc), &lInt)) {
		log_error_winapi(GetLastError(), MODULE_NAME, __func__, "Failed to get file size for entropy calculation! GetFileSizeEx() failed!");
	}
	else {
		double entropy = memory_entropy_calculation(lInt.QuadPart, get_base_address(fc));
		if (entropy <= 0) {
			log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to compute entropy for target!", "");
			return;
		}

		result->entropy = entropy;

		if (verify_entropy_status(entropy) == ENTROPY_SUSPICIOUS) 
		{
			LOG_VERBOSE_SUSPICIOUS_INDICATOR("Slightly high entropy detected!", "");
		}

		if(verify_entropy_status(entropy) == ENTROPY_HIGHLY_SUSPICIOUS)
		{
			LOG_VERBOSE_SUSPICIOUS_INDICATOR("High entropy detected!", "");
		}
	}

	// -- PE Header parsing
	LOG_VERBOSE(config.outFile, "Parsing PE headers...");

	PEStatus status = parse_pe(fc);
	if (status != PE_STATUS_OK) {
		printf("[INFO] The file is not an executable! Proceeding with file type identification!\n");
		// TODO: Implement different checking mechanisms that work for files that do not respect the PE format
	}

	LOG_VERBOSE(config.outFile, "Analyzing section flags...");

	// We need for reporting analysis results to know how many suspicous sections were found and the name of them
	WORD suspiciousSectCount = 0;
	char** suspiciousSect = get_suspicious_executable_sections(fc, &suspiciousSectCount);

	result->suspiciousSectCount = suspiciousSectCount;
	result->execSections = suspiciousSect; 

	LOG_VERBOSE(config.outFile, "Checking digital certificate status...");

	CERTIFICATE_STATUS certificateStatus = check_certificate_status(fc); 
	result->certificateStatus = certStatusStr(certificateStatus);	

	SectionInfo* sectInfo = get_sect_info(fc);
	if (sectInfo == NULL) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to retrieve section information.", "Cannot proceed with further analysis");
		return;
	}
	
	LOG_VERBOSE(config.outFile, "Checking for file infection strategies...");
	appending_file_infection_check(fc, sectInfo);

	LOG_VERBOSE(config.outFile, "Checking overlay existance and anomalies...");
	check_overlay_anomalies(fc);

	LOG_VERBOSE(config.outFile, "Checking import table...");
	import_table_analysis(fc);

	LOG_VERBOSE(config.outFile, "Checking field malformations...");
	if (!verify_checksum_validity(fc)) {
		indicators += 2;
	}

	LOG_VERBOSE(config.outFile, "Checking TLS Callbacks...");
	tls_callback_analysis(fc, &indicators, sectInfo);

	result->indicators = indicators;
	
	return;
}