#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include "logging.h"

#pragma comment (lib, "bcrypt.lib")
#pragma comment(lib, "Shell32.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define MODULE_NAME "GorgotScanLib.lib"
#define MEMORY_SIZE_8KB 8192 

// Code taken from: https://learn.microsoft.com/en-us/windows/win32/seccng/creating-a-hash-with-cng
_Check_return_ _Ret_maybenull_
PBYTE create_hash(_In_ HANDLE hFile, _Out_opt_ DWORD* outCbHash) {
	BCRYPT_ALG_HANDLE       hAlg = BCRYPT_SHA256_ALG_HANDLE; 
	BCRYPT_HASH_HANDLE      hHash = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   cbData = 0, cbHash = 0, cbHashObject = 0;
	PBYTE                   pbHashObject = NULL;
	PBYTE                   pbHash = NULL;

	if (outCbHash != NULL) *outCbHash = 0;

	//calculate the size of the buffer to hold the hash object
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&cbHashObject,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		log_error_winapi(status, MODULE_NAME, __func__, "BCryptGetProperty() failed!");
		goto Cleanup;
	}

	//allocate the hash object on the heap
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject)
	{
		log_error(MEMORY_ALLOCATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory for hash object", "HeapAlloc() failed!");
		goto Cleanup;
	}

	//calculate the length of the hash
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(PBYTE)&cbHash,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		log_error_winapi(status, MODULE_NAME, __func__, "BCryptGetProperty() failed!");
		goto Cleanup;
	}

	//allocate the hash buffer on the heap
	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash)
	{
		log_error(MEMORY_ALLOCATION_ERR, MODULE_NAME, __func__, "Failed to allocate memory for hash buffer", "HeapAlloc() failed!");
		goto Cleanup;
	}

	//create a hash
	if (!NT_SUCCESS(status = BCryptCreateHash(
		hAlg,
		&hHash,
		pbHashObject,
		cbHashObject,
		NULL,
		0,
		0)))
	{
		log_error_winapi(status, MODULE_NAME, __func__, "BCryptCreateHash() failed!");
		goto Cleanup;
	}


	// -- Hash the file --
	BYTE buffer[MEMORY_SIZE_8KB];
	DWORD bytesRead;

	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

	BOOL ok; // used to check if the ReadFile call was successfull or not
	while (TRUE) {
		ok = ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL);

		if (!ok) {
			log_error_winapi(GetLastError(),  MODULE_NAME, __func__, "ReadFile() failed!");
			goto Cleanup;
		}

		if (bytesRead == 0) break; // reached EOF

		status = BCryptHashData(hHash, buffer, bytesRead, 0);
		if (!NT_SUCCESS(status)) {
			log_error_winapi(status, MODULE_NAME, __func__, "Failed to hash module.");
			goto Cleanup;
		}
	}

	//close the hash
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHash,
		cbHash,
		0)))
	{
		log_error_winapi(status, MODULE_NAME, __func__, "BCryptFinishHash() failed!");
		goto Cleanup;
	}

	if(outCbHash != NULL) *outCbHash = cbHash;

	if (hHash) BCryptDestroyHash(hHash);
	if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

	return pbHash;
Cleanup:
	if (hHash) BCryptDestroyHash(hHash);
	if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
	if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

	return NULL;
}

