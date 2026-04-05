#include "file_context.h"
#include "static_analysis.h"
#include <excpt.h>

void import_table_analysis(const PFileContext fc) {
    LPVOID baseAddress = get_base_address(fc);
    PeFormat peFormat = get_pe_format(fc);

    DWORD importRVA = 0;
    DWORD importSize = 0;

    if (peFormat == PE32) {
        PIMAGE_NT_HEADERS32 nt = get_optional_header_32(fc);
        importRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    } else {
        PIMAGE_NT_HEADERS64 nt = get_optional_header_64(fc);
        importRVA  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    }

    if (importRVA == 0) {
        LOG_VERBOSE(config.outFile, "Invalid import table (possible packing or manual import resolution)!\n");
        return;
    }

    if (importSize == 0) {
        LOG_VERBOSE(config.outFile, "Invalid import table size(possible packing or manual import resolution)!\n");
        return;
    }

    DWORD importOffset = rva_to_raw(fc, importRVA);
    if (importOffset == 0) {
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR imp =(PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)baseAddress + importOffset);

    while (imp->Name != 0) {
        DWORD nameOffset = rva_to_raw(fc, imp->Name);
        if (nameOffset == 0) break;

        char* lib = (char*)((BYTE*)baseAddress + nameOffset);
        printf("Library: %s\n", lib); 

        imp++;
    }
}