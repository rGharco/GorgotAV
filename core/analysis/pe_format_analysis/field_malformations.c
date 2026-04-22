#include "static_analysis.h"
#include <ImageHlp.h>

#define MODULE_NAME "field_malformations.c"

#pragma comment(lib ,"imagehlp")

// -- As pe the article of Practical Security Analysis LLC - https://practicalsecurityanalytics.com/pe-checksum/ we will use checksum as a verification method
_Check_return_
bool verify_checksum_validity(_In_ const PFileContext fc) {
    LPVOID baseAddress = get_base_address(fc);
    HANDLE hFile = get_file_handle(fc);
    DWORD checksum = 0;
    DWORD headerSum = 0;

    LONGLONG fileSize = get_file_size(fc);

    if (fileSize > MAXDWORD) {
        log_error_winapi(0, MODULE_NAME, __func__, "Cannot compute checksum for file, file too large!");
        return false;
    }

    if (!CheckSumMappedFile(baseAddress, (DWORD)fileSize, &headerSum, &checksum)) {
        log_error_winapi(GetLastError(), MODULE_NAME, __func__, "CheckSumMappedFile() failed! Failed to compute checksum for file");
        return false;
    }

    PeFormat peFormat = get_pe_format(fc);
    if (peFormat == PE32) {
        PIMAGE_NT_HEADERS32 ntHeaders = get_optional_header_32(fc);
        if (ntHeaders->OptionalHeader.CheckSum != checksum) {
            LOG_VERBOSE_SUSPICIOUS_INDICATOR("Checksum missmatch found!", "");
            return false;
        }
    } else {
        PIMAGE_NT_HEADERS64 ntHeaders = get_optional_header_64(fc);
        if (ntHeaders->OptionalHeader.CheckSum != checksum) {
            LOG_VERBOSE_SUSPICIOUS_INDICATOR("Checksum missmatch found!", "");
            return false;
        }
    }

    return true;
}