#include "static_analysis.h"
#include "arena.h"
#include "pe_utils.h"
#include "logging.h"

#define MODULE_NAME "static_analysis.c"

#define SHA256_HASH_BYTES 32
#define SHA256_HASH_HEX_STRING_SIZE  ((SHA256_HASH_BYTES * 2) + 1) // + 1 for NULL terminator
#define HIGH_ENTROPY_THRESHOLD 7.2 

// Used to verify the status of a hashing operation from bcrypt.h in the main hashing function
#define CHECK_HASH_STATUS(status, msg, details) \
	if (status != STATUS_SUCCESS) { \
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, msg, details); \
		goto Cleanup; \
	} \

// Any hWVTStateData must be released by a call with close. 
#define CERTIFICATE_VERIFICATION_CLEANUP(WinTrustData, verificationStatus) \
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE; \
	\
	verificationStatus = WinVerifyTrust( \
		NULL, \
		&WVTPolicyGUID, \
		&WinTrustData); \
	\

#define BYTE_SIZE 256 
#define SECTION_NAME_LENGTH 9 // 8 + null terminator

typedef struct SectionInfo{
	_Field_size_(SECTION_NAME_LENGTH) char sectionName[SECTION_NAME_LENGTH];
	double entropy;
	DWORD startAddr;
	DWORD endAddr;
	bool isExec;
}SectionInfo;

typedef enum CERTIFICATE_STATUS CERTIFICATE_STATUS;

enum CERTIFICATE_STATUS {
	CLEAN_CERTIFICATE, // trusted published, no verification errors, everything is "clean"
	NOT_SIGNED_CERTIFICATE, // certificate had no signature
	INVALID_SIGNATURE_CERTIFICATE, // certificate had an invalid signature
	DISSALLOWED_CERTIFICATE, // the admin or user specfiically dissalowed the certificate
	DISSALLOWED_BY_ADMIN_POLICY_CERTIFICATE, // the hash and timestamp are valid but the admin policy dissalowed the certificate
	CERTIFICATE_ERROR 
};

// Caller does not free the pointer
static const char* certStatusStr(enum CERTIFICATE_STATUS status) {
	switch (status) {
		case CLEAN_CERTIFICATE:
			return "Clean certificate (trusted publisher, no verification errors)";

		case NOT_SIGNED_CERTIFICATE:
			return "Not signed (no Authenticode signature present)";

		case INVALID_SIGNATURE_CERTIFICATE:
			return "Invalid signature (signature verification failed)";

		case DISSALLOWED_CERTIFICATE:
			return "Disallowed certificate (explicitly blocked by user or admin)";

		case DISSALLOWED_BY_ADMIN_POLICY_CERTIFICATE:
			return "Disallowed by admin policy (valid signature, blocked by policy)";

		case CERTIFICATE_ERROR:
			return "Certificate error (unspecified verification failure)";

		default:
			return "Unknown certificate status";
		}
}


// -- Standard executable sections name
const BYTE TEXT_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', '\0', '\0', '\0' };
const BYTE TEXT_BSS_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', 'b', 's', 's' };
const BYTE CODE_SECTION_NAME[8] = { '.', 'c', 'o', 'd', 'e', '\0', '\0', '\0' };

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

static double memory_entropy_calculation(_In_ const uint64_t size, _In_ const BYTE* dataPtr) {
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

//-----------------------------------------------------------
// PE format functions
//-----------------------------------------------------------

static DWORD rva_to_raw(const PFileContext fc, DWORD rva) {
    WORD n = get_nr_of_sections(fc);
    PIMAGE_SECTION_HEADER sections = get_ptr_to_section_start(fc);

    for (WORD i = 0; i < n; i++) {

        DWORD va = sections[i].VirtualAddress;
        DWORD size = sections[i].Misc.VirtualSize;

        // Some binaries use SizeOfRawData instead if VirtualSize is 0
        if (size == 0)
            size = sections[i].SizeOfRawData;

        if (rva >= va && rva < va + size) {
            return (rva - va) + sections[i].PointerToRawData;
        }
    }

    // fallback: invalid RVA
    return 0;
}

static inline bool is_standard_exec_sect(_In_reads_bytes_(SECTION_NAME_LENGTH) const char* sectionName) {
	if (strcmp(sectionName, TEXT_SECTION_NAME) == 0) return true;
	if (strcmp(sectionName, TEXT_BSS_SECTION_NAME) == 0) return true;
	if (strcmp(sectionName, CODE_SECTION_NAME) == 0) return true;

	return false;
}

_Check_return_ _Ret_maybenull_
static SectionInfo* get_sect_info(_In_ const PFileContext fc) {
	WORD nrOfSections = get_nr_of_sections(fc);
	PIMAGE_SECTION_HEADER ptrSections = get_ptr_to_section_start(fc);
	BYTE* baseAddress = (BYTE*)get_base_address(fc);

	SectionInfo* sectInfo = calloc(nrOfSections, sizeof(*sectInfo));
	if (sectInfo == NULL) {
		log_error(MEMORY_ALLOCATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory to SectionInfo struct.", "get_sect_info() failed!");
		return NULL;
	}

	for (WORD i = 0; i < nrOfSections; i++) {
		memcpy(sectInfo[i].sectionName, ptrSections[i].Name, SECTION_NAME_LENGTH - 1); // they do not contain NULL terminator by default
		sectInfo[i].sectionName[SECTION_NAME_LENGTH - 1] = '\0';

		sectInfo[i].isExec = (ptrSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		sectInfo[i].entropy = memory_entropy_calculation(ptrSections[i].SizeOfRawData, baseAddress + ptrSections[i].PointerToRawData);
		sectInfo[i].startAddr = ptrSections[i].VirtualAddress;
		sectInfo[i].endAddr = ptrSections[i].VirtualAddress + max(ptrSections[i].Misc.VirtualSize, ptrSections[i].SizeOfRawData);
	}

	return sectInfo;
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
				LOG_VERBOSE(config.outFile,"[INDICATOR] Executable non-standard section detected (exec + non-standard name)\n");
			}
			
			// -- 2. Verify entropy 
			if (sectInfo[i].entropy >= HIGH_ENTROPY_THRESHOLD) {
				indicators += 3;
				LOG_VERBOSE(config.outFile,"[INDICATOR] High entropy section detected (possible packed/encrypted code)\n");
			}

			// -- 3. Verify JMP instructions or PUSH and RET combination
			BYTE* baseAddr = get_base_address(fc);
			baseAddr += aepOffset;
			
			// -- 3.1 Verify JMP to another section
			if (baseAddr[0] == 0xE9) {
				INT32 rel = *(INT32*)(baseAddr + 1);
				DWORD targetRVA = aep + 5 + rel;

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
					LOG_VERBOSE(config.outFile,"[INDICATOR] JMP redirects execution to a different section\n");
				}
			}
			if (baseAddr[0] == 0xE8 && baseAddr[5] == 0xC3) {
				indicators += 5;
				LOG_VERBOSE(config.outFile,"[INDICATOR] Detected CALL + RET sequence\n");
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

// -- If a section that is not .text, .textbss, or .code has the exectuable flag set return it in the array --
_Check_return_ _Ret_maybenull_
static char** get_suspicious_executable_sections(_In_ const PFileContext fc, WORD* outCount) {
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

static void free_suspicious_sections(char** sections) {
    if (!sections) return;

    free(sections[0]); // contiguous buffer
    free(sections);
}

// Verify the certificate existance using Authenticode policy provider. We check if there is any signature present for a file
// but the existance itself does not give any clear indicator to whether or not a file is malicious. Context matters, just 
// because a file is not signed with a certificate does not mean it is malicious (e.g Steam games are unsigned)
static CERTIFICATE_STATUS check_certificate_status(const PFileContext fc) {
	WINTRUST_FILE_INFO fileData; // struct used to verify an individual file
	memset(&fileData, 0, sizeof(fileData));

	fileData.cbStruct = sizeof(WINTRUST_FILE_INFO); // count bytes Struct -> size of the struct 
	fileData.pcwszFilePath = (LPCWSTR)config.target; // file to check certificate for 
	fileData.hFile = get_file_handle(fc); // handle to the file to check the certificate for
	fileData.pgKnownSubject = NULL; // optional field if the subject type is unknown

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2; // Verify a file or object using the Authenticode policy provider.
	WINTRUST_DATA WinTrustData;

	// Default all fields to 0.
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	// Set size of struct 
	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &fileData;

	LONG verificationStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	switch (verificationStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
			- Hash that represents the subject is trusted.

			- Trusted publisher without any verification errors.

			- UI was disabled in dwUIChoice. No publisher or
				time stamp chain errors.
		*/
		CERTIFICATE_VERIFICATION_CLEANUP(WinTrustData, verificationStatus)

		return CLEAN_CERTIFICATE;
	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.
		DWORD err = GetLastError();
		if (TRUST_E_NOSIGNATURE == err ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == err ||
			TRUST_E_PROVIDER_UNKNOWN == err)
		{
			CERTIFICATE_VERIFICATION_CLEANUP(WinTrustData, verificationStatus)

			// The file was not signed.
			return NOT_SIGNED_CERTIFICATE;
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
			CERTIFICATE_VERIFICATION_CLEANUP(WinTrustData, verificationStatus)

			return INVALID_SIGNATURE_CERTIFICATE;
		}
		break;
	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
		CERTIFICATE_VERIFICATION_CLEANUP(WinTrustData, verificationStatus)

		return DISSALLOWED_CERTIFICATE;
	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
		CERTIFICATE_VERIFICATION_CLEANUP(WinTrustData, verificationStatus)

		return DISSALLOWED_BY_ADMIN_POLICY_CERTIFICATE;
	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. verificationStatus contains the 
		// publisher or time stamp chain error.
		log_error(verificationStatus,MODULE_NAME,__func__, "An error occured while verifying the file certificate!", "WinVerifyTrust() failed!");
		CERTIFICATE_VERIFICATION_CLEANUP(WinTrustData, verificationStatus)

		return CERTIFICATE_ERROR;
	}
}

// We do not free the pointers allocated in this function as their lifetime is dependent of AnalaysisResult 
void static_analysis(const PFileContext fc, AnalysisResult* result) {
	// -- Hashing 
	LOG_VERBOSE(config.outFile, "Starting static analysis...");

	PBYTE hash = create_hash(get_file_handle(fc), NULL);
	char* sha256Hash = calloc(1, SHA256_HASH_HEX_STRING_SIZE);

	if (sha256Hash == NULL) {
		log_error(MEMORY_ALLOCATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory for SHA256 hash.", "calloc() failed!");
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
	
	appending_file_infection_check(fc, sectInfo);

	printf("Found indicators: %d\n", indicators);
	
	return;
}