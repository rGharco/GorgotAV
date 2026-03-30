#include "static_analysis.h"
#include "arena.h"
#include "pe_utils.h"
#include "logging.h"

#define MODULE_NAME "static_analysis.c"

#define SHA256_HASH_BYTES 32
#define SHA256_HASH_HEX_STRING_SIZE  ((SHA256_HASH_BYTES * 2) + 1) // + 1 for NULL terminator

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

static double calculate_entropy(const PFileContext fc) {
	// Counts how many times a byte appears to the make its probability. As per Shanon's entropy function we need the probability
	// of an event happening (p(xi)) * log_2(p(xi))
	unsigned long long byteCount[BYTE_SIZE] = { 0 };
	BYTE* baseAddress = get_base_address(fc);

	LARGE_INTEGER fileSize = { 0 };

	if (!GetFileSizeEx(get_file_handle(fc), &fileSize)) {
		DWORD err = GetLastError();
		log_error_winapi(err, MODULE_NAME, __func__, "GetFileSizeEx() failed!");

		return -1;
	}

	LONGLONG size = fileSize.QuadPart;

	for (LONGLONG i = 0; i < size; i++) {
		byteCount[baseAddress[i]]++;
	}

	double entropy = 0;

	for (int i = 0; i < BYTE_SIZE; i++) {
		if (byteCount[i] == 0) continue;

		double frequency = (double)byteCount[i] / (double)size;
		entropy -= frequency * log2(frequency);
	}

	return entropy;
}

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

		if (ptrSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) sectInfo[i].isExec = true;

		sectInfo[i].entropy = memory_entropy_calculation(ptrSections[i].SizeOfRawData, baseAddress + ptrSections[i].PointerToRawData);

		sectInfo[i].startAddr = ptrSections[i].VirtualAddress;
		sectInfo[i].endAddr = ptrSections[i].VirtualAddress + max(ptrSections[i].Misc.VirtualSize, ptrSections[i].SizeOfRawData);
	}

	return sectInfo;
}

// -- If a section that is not .text, .textbss, or .code has the exectuable flag set return it in the array --
static char** get_suspicious_executable_sections(const PFileContext fc, WORD* outCount) {
	WORD nrOfSections = get_nr_of_sections(fc);
	PIMAGE_SECTION_HEADER ptrSections = get_ptr_to_section_start(fc);

	char** foundSections = (char**)malloc(sizeof(char*) * nrOfSections);

	if (foundSections == NULL || errno != 0) {
		log_error(errno, MODULE_NAME, __func__, strerror(errno), "Could not allocate memory for section names!");
	}

	for (WORD i = 0; i < nrOfSections; i++) {
		foundSections[i] = malloc(sizeof(char) * SECTION_NAME_LENGTH);

		if (foundSections[i] == NULL || errno != 0) {
			log_error(errno, MODULE_NAME, __func__,strerror(errno),"Could not allocate memory for individual section names!");
		}
	}

	const BYTE TEXT_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', '\0', '\0', '\0' };
	const BYTE TEXT_BSS_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', 'b', 's', 's' };
	const BYTE CODE_SECTION_NAME[8] = { '.', 'c', 'o', 'd', 'e', '\0', '\0', '\0' };

	bool isNormalExecSection;
	WORD sectFound = 0;
	char* currSlot = (*foundSections);

	// IMAGE_SIZEOF_SHORT_NAME is a macro defined by winnt.h and it stores the length of a section name 
	for (WORD i = 0; i < nrOfSections; i++) {
		isNormalExecSection = false;

		if (memcmp(ptrSections->Name, TEXT_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME) == 0) {
			isNormalExecSection = true;
		}
		else if (memcmp(ptrSections->Name, TEXT_BSS_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME) == 0) {
			isNormalExecSection = true;
		}
		else if (memcmp(ptrSections->Name, CODE_SECTION_NAME, IMAGE_SIZEOF_SHORT_NAME) == 0) {
			isNormalExecSection = true;
		}

		if ((ptrSections->Characteristics & IMAGE_SCN_MEM_EXECUTE) && !isNormalExecSection) {
			memcpy(currSlot, ptrSections->Name, IMAGE_SIZEOF_SHORT_NAME);
			currSlot[IMAGE_SIZEOF_SHORT_NAME] = '\0';
			currSlot += SECTION_NAME_LENGTH;

			sectFound++;
		}

		ptrSections++;
	}

	*outCount = sectFound;

	return foundSections;
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

	double entropy = calculate_entropy(fc);

	if (entropy <= 0) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to compute entropy for target!", "");
		return;
	}

	result->entropy = entropy;

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

	if (suspiciousSectCount > 0) {
		result->execSections = suspiciousSect;
		result->suspiciousSectCount = suspiciousSectCount;
	}
	else {
		result->execSections = 0; // for reporting, we must tell the user what we found either way

		for (WORD i = 0; i < get_nr_of_sections(fc); i++) {
			free(suspiciousSect[i]);
		}

		free(suspiciousSect); 
	}

	LOG_VERBOSE(config.outFile, "Checking digital certificate status...");

	CERTIFICATE_STATUS certificateStatus = check_certificate_status(fc); 
	result->certificateStatus = certStatusStr(certificateStatus);	
	
	return;
}