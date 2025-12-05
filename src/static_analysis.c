#include "static_analysis.h"

#define MODULE_NAME "static_analysis.c"

#define SHA256_HASH_BYTES 32
#define SHA256_HASH_HEX  (SHA256_HASH_BYTES * 2)

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

#define CHECK_STATUS(status, msg) \
	if (status != STATUS_SUCCESS) { \
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "The following operation failed: ", msg); \
		goto Cleanup; \
	} \

// Caller must set file pointer to start using SetFilePointer() before performing actions on the file
static char* compute_hash(const PFileContext fc) { 
	// Open algorithm handle
	BCRYPT_ALG_HANDLE hAlg = BCRYPT_SHA256_ALG_HANDLE;
	BCRYPT_HASH_HANDLE hHash = NULL;

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ULONG cbHashObject = 0; // cb = count bytes
	ULONG cbTemp = 0; // we use this to store pcbResult for GetProperty calls
	ULONG cbHashSize = 0; // the size of hash string

	LPVOID pHashObject = NULL; // pointer to memory zone where we store the hash string
	HANDLE hCurrProcess = GetProcessHeap();
	LPVOID pHash = NULL; // actual hash string

	// Calculate size of buffer to hold hash object
	status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&cbHashObject,
		sizeof(ULONG),
		&cbTemp,
		0
	);

	CHECK_STATUS(status, "Get Hash Object Length");

	// Allocate hash object on heap
	pHashObject = HeapAlloc(hCurrProcess, 0, cbHashObject);

	if (pHashObject == NULL) {
		log_error(MEMORY_ALLOCATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory to hash object!", "");
		goto Cleanup;
	}

	// Calculate the length of the hash (as a string) 
	status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(PUCHAR) &cbHashSize,
		sizeof(ULONG),
		&cbTemp,
		0
	);

	CHECK_STATUS(status, "Get Hash Size");

	// Allocate hash string obj on the heap
	pHash = HeapAlloc(hCurrProcess, 0, cbHashSize);

	if (pHash == NULL) {
		log_error(MEMORY_ALLOCATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory to hash!", "");
		goto Cleanup;
	}

	// Create hash object
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

	HANDLE hFile = get_file_handle(fc);

	// Hash the file
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

	// Finish hashing and store the hash result
	status = BCryptFinishHash(
		hHash,
		pHash,
		cbHashSize,
		0
	);

	CHECK_STATUS(status, "Storing Hash value!");

	char sha256_hash[SHA256_HASH_HEX + 1] = { 0 }; // hex string + null
	char* out = sha256_hash;

	for (ULONG i = 0; i < cbHashSize; i++) {
		unsigned char byte = ((PUCHAR)pHash)[i];
		snprintf(out, 3, "%02X", byte);
		out += 2; // advance by the two chars just written
	}

	printf("SHA256 Hash: %s\n", sha256_hash);

	return sha256_hash;

Cleanup:
	if (hHash != NULL) BCryptDestroyHash(hHash);
	if (pHashObject != NULL) HeapFree(hCurrProcess, 0, pHashObject);
	if (pHash != NULL) HeapFree(hCurrProcess, 0, pHash);

	return -1;
}

void static_analysis(const PFileContext fc) {
	char* sha256_hash = compute_hash(fc);

	if (sha256_hash == NULL) {
		log_error(BAD_OPERATION_ERR, MODULE_NAME, __func__, "Failed to compute hash for target!", "");
		return;
	}


}