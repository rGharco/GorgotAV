#include "static_analysis.h"

#define MODULE_NAME "certificate_analysis.c"

// Any hWVTStateData must be released by a call with close. 
#define CERTIFICATE_VERIFICATION_CLEANUP(WinTrustData, verificationStatus) \
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE; \
	\
	verificationStatus = WinVerifyTrust( \
		NULL, \
		&WVTPolicyGUID, \
		&WinTrustData); \
	\

enum CERTIFICATE_STATUS {
	CLEAN_CERTIFICATE, // trusted published, no verification errors, everything is "clean"
	NOT_SIGNED_CERTIFICATE, // certificate had no signature
	INVALID_SIGNATURE_CERTIFICATE, // certificate had an invalid signature
	DISSALLOWED_CERTIFICATE, // the admin or user specfiically dissalowed the certificate
	DISSALLOWED_BY_ADMIN_POLICY_CERTIFICATE, // the hash and timestamp are valid but the admin policy dissalowed the certificate
	CERTIFICATE_ERROR 
};

// Caller does not free the pointer
const char* certStatusStr(enum CERTIFICATE_STATUS status) {
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


// Verify the certificate existance using Authenticode policy provider. We check if there is any signature present for a file
// but the existance itself does not give any clear indicator to whether or not a file is malicious. Context matters, just 
// because a file is not signed with a certificate does not mean it is malicious (e.g Some Steam games are unsigned)
CERTIFICATE_STATUS check_certificate_status(const PFileContext fc) {
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