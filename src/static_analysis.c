#include "static_analysis.h"

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
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to create memory arena for hash!", "");
		return NULL;
	}

	BYTE* currPointer = arena->memory;

	*pHashObj = currPointer;               
	currPointer += cbHashObject;   
       
	*pHash = currPointer;                  

	return arena;
}

static inline BOOL binaryToHexHash(const LPVOID pHash, char* sha256Hash) {
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
	BYTE buffer[4096] = { 0 };
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
		log_error(errno, MODULE_NAME, __func__, "Failed to allocate memory for SHA256 hash string!", 
			"Default code was overwritten by errno");
		perror(strerror(errno));
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
// Functions for hashing
//-----------------------------------------------------------

static double shanon_entropy(const PFileContext fc) {
	unsigned long long byteCount[BYTE_SIZE] = { 0 };
	BYTE buffer[4096] = { 0 };
	DWORD bytesRead = 0;

	BOOL ok;
	while (true) {
		ok = ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL);

		if (!ok) {
			log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "ReadFile failed!", "");
			return -1;
		}

		if (bytesRead == 0) break;

		for (DWORD i = 0; i < bytesRead; i++) {
			byteCount[buffer[i]]++;
		}
	}

	LARGE_INTEGER fileSize = { 0 };
	if (!GetFileSizeEx(hFile, &fileSize)) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "GetFileSizeEx() failed!", "");
		return -1;
	}

	LONGLONG size = fileSize.QuadPart;

	double entropy = 0;

	for (int i = 0; i < BYTE_SIZE; i++) {
		if (byteCount[i] == 0) continue;

		double frequency = (double)byteCount[i] / (double)size;
		entropy -= frequency * log2(frequency);
	}

	return entropy;
}

void static_analysis(const PFileContext fc) {
	LOG_VERBOSE(config.outFile, "Starting static analysis...");

	char* sha256Hash = compute_hash(fc);

	if (sha256Hash == NULL) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to compute hash for target!", "");
		return;
	}

	printf("Sha256: %s\n", sha256Hash);

	double entropy = shanon_entropy(fc);

	printf("Entropy: %llf\n", entropy);

	// -- Cleanup --
	free(sha256Hash);
}