#include "static_analysis.h"
#include "arena.h"
#include "pe_utils.h"
#include "logging.h"

#define MODULE_NAME "static_analysis.c"

#define SHA256_HASH_BYTES 32
#define SHA256_HASH_HEX_STRING_SIZE  ((SHA256_HASH_BYTES * 2) + 1) // + 1 for NULL terminator

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

#define CHECK_STATUS(status, msg) \
	if (status != STATUS_SUCCESS) { \
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "The following operation failed: ", msg); \
		goto Cleanup; \
	} \

#define INIT_VARIABLES_STATUS_CHECK(status, msg) \
	if (status != STATUS_SUCCESS) { \
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, msg, ""); \
		hAlg = NULL; \
		return FALSE; \
	} \

#define BYTE_SIZE 256 
#define MEMORY_SIZE_8KB 8192
#define SECTION_NAME_AS_CHAR_IN_BYTES 9 // 8 + null terminator

// -- Global variables --

BCRYPT_ALG_HANDLE hAlg = NULL;
ULONG cbHashObject = 0; // cb = count bytes for SHA256 hash object
ULONG cbHashSize = 0; // the size of SHA256 hash string 
HANDLE hProcessHeap = NULL;
HANDLE hFile = NULL;

//-----------------------------------------------------------
// Functions for hashing
//-----------------------------------------------------------

static BOOL init_hash_variables(const PFileContext fc) {
	hAlg = BCRYPT_SHA256_ALG_HANDLE;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG cbTemp = 0; // we use this to store pcbResult for GetProperty calls
	hProcessHeap = GetProcessHeap();
	hFile = get_file_handle(fc);

	// Calculate size of buffer to hold hash object
	status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&cbHashObject,
		sizeof(ULONG),
		&cbTemp,
		0
	);

	INIT_VARIABLES_STATUS_CHECK(status, "Get Hash Object Length failed!");

	// Calculate the length of the hash (as a string) 
	status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(PUCHAR)&cbHashSize,
		sizeof(ULONG),
		&cbTemp,
		0
	);

	INIT_VARIABLES_STATUS_CHECK(status, "Get Hash size failed!");

	return TRUE;
}

static Arena* allocate_memory_for_hash(LPVOID* pHashObj, LPVOID* pHash) {
	ULONG totalHeapSize = cbHashObject + cbHashSize;

	Arena* arena = arena_create(totalHeapSize);

	if (!arena) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to create arena for hash!", "");
		return NULL;
	}

	BYTE* currPointer = arena->memory;

	*pHashObj = currPointer;               
	currPointer += cbHashObject;   
       
	*pHash = currPointer;                  

	return arena;
}

static inline void binaryToHexHash(const LPVOID pHash, char* sha256Hash) {
	char* out = sha256Hash;

	for (ULONG i = 0; i < cbHashSize; i++) {
		unsigned char byte = ((PUCHAR)pHash)[i];
		snprintf(out, 3, "%02X", byte); // the 3 is because snprintf writes size - 1 chars, it adds null terminator
		// We rewrite the null terminator on each iteration 
		out += 2; // advance by the two chars just written
	}

	sha256Hash[SHA256_HASH_HEX_STRING_SIZE - 1] = '\0'; // null terminate the string
}

static char* compute_hash(const PFileContext fc) { 
	// -- Open algorithm handle --
	BCRYPT_HASH_HANDLE hHash = NULL;

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	LPVOID pHash = NULL; // actual hash string
	LPVOID pHashObject = NULL; // pointer to memory zone where we store the hash object

	if (!init_hash_variables(fc)) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to initialize hash variables!", "");
		return NULL;
	}

	Arena* pointersArena = allocate_memory_for_hash(&pHashObject, &pHash);

	if (!pointersArena) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory for hash!", "");
		return NULL;
	}

	// -- Create hash object --
	status = BCryptCreateHash(
		hAlg,
		&hHash,
		pHashObject,
		cbHashObject,
		NULL,
		0,
		0
	);

	CHECK_STATUS(status, "Create Hash Object");

	// -- Hash the file --
	BYTE buffer[MEMORY_SIZE_8KB] = { 0 };
	DWORD bytesRead;

	BOOL ok;
	while (TRUE) {
		ok = ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL);

		if (!ok) {
			log_error(BAD_OPERATION_ERR,MODULE_NAME,__func__,"ReadFile failed", "");
			goto Cleanup;
		}

		if (bytesRead == 0) break; // EOF

		status = BCryptHashData(hHash, buffer, bytesRead, 0);
		CHECK_STATUS(status, "Hashing file");
	}

	// -- Finish hashing and store the hash result --
	status = BCryptFinishHash(
		hHash,
		pHash,
		cbHashSize,
		0
	);

	CHECK_STATUS(status, "Storing Hash value!");
	
	char* sha256Hash = (char*)malloc(SHA256_HASH_HEX_STRING_SIZE);

	if (sha256Hash == NULL) {
		log_malloc_error("Could not allocate memory for SHA256 hash string!", MODULE_NAME, __func__);
		return NULL;
	}

	binaryToHexHash(pHash, sha256Hash);

	// -- Cleanup and return --

	LARGE_INTEGER li = { 0 };
	li.QuadPart = 0;

	SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);

	arena_destroy(pointersArena);
	BCryptDestroyHash(hHash);

	LOG_VERBOSE(config.outFile, "Computed SHA256 hash successfully!");

	return sha256Hash;

Cleanup:
	if (hHash != NULL) BCryptDestroyHash(hHash);
	arena_destroy(pointersArena);

	return NULL;
}

//-----------------------------------------------------------
// Entropy
//-----------------------------------------------------------

static double shanon_entropy(const PFileContext fc) {
	unsigned long long byteCount[BYTE_SIZE] = { 0 };
	BYTE* baseAddress = get_base_address(fc);

	LARGE_INTEGER fileSize = { 0 };
	if (!GetFileSizeEx(hFile, &fileSize)) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "GetFileSizeEx() failed!", "");
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
static char** analyze_suspicious_executable_sections(const PFileContext fc, WORD* outCount) {
	WORD nrOfSections = get_nr_of_sections(fc);
	PIMAGE_SECTION_HEADER ptrSections = get_ptr_to_section_start(fc);

	char** foundSections = (char**)malloc(sizeof(char*) * nrOfSections);

	if (foundSections == NULL) {
		log_malloc_error("Could not allocate memory for section names!", MODULE_NAME, __func__);
	}

	for (WORD i = 0; i < nrOfSections; i++) {
		foundSections[i] = malloc(sizeof(char) * SECTION_NAME_AS_CHAR_IN_BYTES);

		if (foundSections[i] == NULL) {
			log_malloc_error("Could not allocate memory for individual section names!", MODULE_NAME, __func__);
		}
	}

	const BYTE TEXT_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', '\0', '\0', '\0' };
	const BYTE TEXT_BSS_SECTION_NAME[8] = { '.', 't', 'e', 'x', 't', 'b', 's', 's' };
	const BYTE CODE_SECTION_NAME[8] = { '.', 'c', 'o', 'd', 'e', '\0', '\0', '\0' };

	bool isNormalExecSection;
	int sectFound = 0;
	char* currSlot = (*foundSections);

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
			currSlot += SECTION_NAME_AS_CHAR_IN_BYTES;

			sectFound++;
		}

		ptrSections++;
	}

	*outCount = sectFound;

	return foundSections;
}

void static_analysis(const PFileContext fc, AnalysisResult* result) {
	LOG_VERBOSE(config.outFile, "Starting static analysis...");

	char* sha256Hash = compute_hash(fc);

	if (sha256Hash == NULL) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to compute hash for target!", "");
		return;
	}

	result->sha256Hash = sha256Hash;

	double entropy = shanon_entropy(fc);

	if (entropy < 0) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to compute entropy for target!", "");
		return;
	}

	result->entropy = entropy;

	PEStatus status = parse_pe(fc);

	if (status != PE_STATUS_OK) {
		printf("[INFO] The file is not an executable! Proceeding with file type identification!\n");
	}

	WORD sectCount = 0;
	char** suspiciousSect = analyze_suspicious_executable_sections(fc, &sectCount);

	if (sectCount > 0) {
		result->execSections = suspiciousSect;
		result->sectCount = sectCount;
	}
	else {
		free(suspiciousSect); // free unused memory
	}

}