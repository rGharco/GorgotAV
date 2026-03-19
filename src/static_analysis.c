#include "static_analysis.h"
#include "arena.h"
#include "pe_utils.h"
#include "logging.h"

#define MODULE_NAME "static_analysis.c"

#define SHA256_HASH_BYTES 32
#define SHA256_HASH_HEX_STRING_SIZE  ((SHA256_HASH_BYTES * 2) + 1) // + 1 for NULL terminator

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

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
#define MEMORY_SIZE_8KB 8192 // Used to compute a hash by reading chunks of 8KB and then hashing them
#define SECTION_NAME_LENGTH 9 // 8 + null terminator

// -- Global variables --

BCRYPT_ALG_HANDLE hAlg = NULL;
ULONG hashObjectLength = 0; // nr of bytes bytes for SHA256 hash object
ULONG hashDigestLength = 0; // the size of SHA256 hash string 
HANDLE hProcessHeap = NULL;
HANDLE hFile = NULL;

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
// Functions for hashing
//-----------------------------------------------------------

static BOOL init_hash_variables(const PFileContext fc);
static Arena* allocate_memory_for_hash(LPVOID * pHashObj, LPVOID * pHash);
static inline void binaryToHexHash(const LPVOID pHash, char* sha256Hash);

static char* get_file_sha256_hash(const PFileContext fc) {
	// -- Open algorithm handle --
	BCRYPT_HASH_HANDLE hHash = NULL;

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	LPVOID pHash = NULL; // points to where the hash string will be stored in memory
	LPVOID pHashObject = NULL; // pointer to memory zone where we store the hash object

	// After calling init_hash_variables, we have the digest length, object length, and hash algorithm handle all ready to use
	if (!init_hash_variables(fc)) {
		log_error(HASHING_ERR, MODULE_NAME, __func__, "Failed to initialize hash variables!", "");
		return NULL;
	}

	Arena* pointersArena = allocate_memory_for_hash(&pHashObject, &pHash);

	// After calling the arena function, pHash and pHashObject both have their pointers to valid memory zones to store the designated values
	if (!pointersArena) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory for hash!", "");
		return NULL;
	}

	// -- Create hash object --
	status = BCryptCreateHash(
		hAlg,
		&hHash,
		pHashObject,
		hashObjectLength,
		NULL,
		0,
		0
	);

	CHECK_HASH_STATUS(status, "Failed to create the hash object!", "BCryptCreateHash() failed!")

	// -- Hash the file --
	BYTE buffer[MEMORY_SIZE_8KB] = { 0 };
	DWORD bytesRead;

	BOOL ok; // used to check if the ReadFile call was successfull or not
	while (TRUE) {
		ok = ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL);

		if (!ok) {
			log_error(FILE_READING_ERR,MODULE_NAME,__func__,"ReadFile failed", "");
			goto Cleanup;
		}

		if (bytesRead == 0) break; // reached EOF

		status = BCryptHashData(hHash, buffer, bytesRead, 0);
		CHECK_HASH_STATUS(status, "Failed hashing chunks of file!", "Sequential ReadFile() + BCryptHashData() failed!");
	}

	// -- Finish hashing and store the hash result (bytes) --
	status = BCryptFinishHash(
		hHash,
		pHash,
		hashDigestLength,
		0
	);

	CHECK_HASH_STATUS(status, "Failed to create the hash digest", "BCryptFinishHash() failed!");

	// --- Hash string conversion --- 
	char* sha256Hash = (char*)malloc(SHA256_HASH_HEX_STRING_SIZE);

	if (sha256Hash == NULL || errno != 0) {
		log_error(errno, MODULE_NAME, __func__,strerror(errno), "Could not allocate memory for SHA256 hash string!");
		return NULL;
	}

	binaryToHexHash(pHash, sha256Hash);

	// -- Cleanup and return --

	LARGE_INTEGER li = { 0 };
	li.QuadPart = 0;

	// We use ReadFile so the file pointer moves to a different offset and we must reset
	SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);

	arena_destroy(pointersArena);
	BCryptDestroyHash(hHash);

	LOG_VERBOSE(config.outFile, "Computed SHA256 hash successfully!");

	return sha256Hash;

Cleanup:
	if (hHash != NULL) BCryptDestroyHash(hHash);
	if (pointersArena != NULL) arena_destroy(pointersArena);

	return NULL;
}

static BOOL init_hash_variables(const PFileContext fc) {
	// This is a pseudo-handler available in Windows 10 and above 
	hAlg = BCRYPT_SHA256_ALG_HANDLE; 
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbTemp = 0; // we use this to store values returned by BCryptGetProperty (things like hash length, hash object length)
	hProcessHeap = GetProcessHeap();
	hFile = get_file_handle(fc);

	// Calculate size of buffer to hold hash object
	status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&hashObjectLength,
		sizeof(ULONG),
		&cbTemp,
		0
	);

	if (status != STATUS_SUCCESS) {
		log_error(HASHING_ERR, MODULE_NAME, __func__, "Failed to get hash object length!", "BCryptGetProperty() failed!");
		return FALSE;
	}

	// Calculate the length of the hash (as a string) 
	status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(PUCHAR)&hashDigestLength,
		sizeof(ULONG),
		&cbTemp,
		0
	);

	if (status != STATUS_SUCCESS) {
		log_error(HASHING_ERR, MODULE_NAME, __func__, "Failed to get hash digest length!", "BCryptGetProperty() failed!");
		return FALSE;
	}

	return TRUE;
}

static Arena* allocate_memory_for_hash(LPVOID* pHashObj, LPVOID* pHash) {
	ULONG totalHeapSize = hashObjectLength + hashDigestLength;

	Arena* arena = arena_create(totalHeapSize);

	if (!arena) {
		log_error(INITIALIZING_ARENA_ERR, MODULE_NAME, __func__, "Failed to create arena for hash!", "");
		return NULL;
	}

	BYTE* currPointer = arena->memory;

	*pHashObj = currPointer;
	currPointer += hashObjectLength;

	*pHash = currPointer;

	return arena;
}

static void binaryToHexHash(const LPVOID pHash, char* sha256Hash) {
	char* out = sha256Hash;

	for (ULONG i = 0; i < hashDigestLength; i++) {
		unsigned char byte = ((PUCHAR)pHash)[i];
		snprintf(out, 3, "%02X", byte); // the 3 is because snprintf writes size - 1 chars, it adds null terminator
		// We rewrite the null terminator on each iteration 
		out += 2; // advance by the two chars just written
	}

	sha256Hash[SHA256_HASH_HEX_STRING_SIZE - 1] = '\0'; // null terminate the string
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

	if (!GetFileSizeEx(hFile, &fileSize)) {
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

//-----------------------------------------------------------
// PE format functions
//-----------------------------------------------------------

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

void static_analysis(const PFileContext fc, AnalysisResult* result) {
	LOG_VERBOSE(config.outFile, "Starting static analysis...");

	char* sha256Hash = get_file_sha256_hash(fc);

	result->sha256Hash = sha256Hash;

	LOG_VERBOSE(config.outFile, "Starting entropy calculation...");

	double entropy = calculate_entropy(fc);

	if (entropy < 0) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to compute entropy for target!", "");
		return;
	}

	result->entropy = entropy;

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
}