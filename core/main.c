#include "file_context.h"
#include "cli.h"
#include "static_analysis.h"
#include "analysis_result.h"
#include "logging.h"
#include "pe_utils.h"

#define MODULE_NAME "main.c" 

int main(int argc, char* argv[]) {
    //-----------------------------------------------------------
    // Parse command line arguments
    //-----------------------------------------------------------
    
    ui_init();
    init_config(&config);
    show_app_banner();

    ParseStatus argParseStatus = parse_args(argc, argv);

    if (argParseStatus != PARSE_STATUS_OK) {
        exit(EXIT_FAILURE);
    }

    printf("\n%s%sTarget: %s%s\n\n", BOLD, CYAN_LT ,config.target, RST);

    //-----------------------------------------------------------
    // Create file context
    //-----------------------------------------------------------

    PFileContext fileContext = create_file_context(config.target);

    if (fileContext == NULL) {
        exit(EXIT_FAILURE);
    }

	AnalysisResult* analysisResult = create_analysis_result(fileContext);

    if (analysisResult == NULL) {
        exit(EXIT_FAILURE);
    }

    //----------------------------------------------------------------------------------
    // Metadata
    //----------------------------------------------------------------------------------

    LARGE_INTEGER lInt;
    if (!GetFileSizeEx(get_file_handle(fileContext), &lInt)) {
        log_error_winapi(GetLastError(), MODULE_NAME, __func__, "GetFileSizeEx() failed!");
        return;
    }

    set_file_size(fileContext, lInt.QuadPart);

    //----------------------------------------------------------------------------------
    // PE parsing 
    //----------------------------------------------------------------------------------
	LOG_VERBOSE(config.outFile, "Parsing PE headers...");

	PEStatus status = parse_pe(fileContext);
	if (status != PE_STATUS_OK) {
		printf("[INFO] The file is not an executable! Proceeding with file type identification!\n");
		// TODO: Implement different checking mechanisms that work for files that do not respect the PE format
	}
    else {
        static_analysis_pe(fileContext, analysisResult);
    }

	log_analysis_result(analysisResult);
    
    if (config.outFile != stdout) {
        printf("%s\n","Analysis results have been saved inside output file!");
    }

    //-----------------------------------------------------------
    // Cleanup
    //-----------------------------------------------------------

    disable_config(&config);
	destroy_analysis_result(analysisResult);
    close_file_context(fileContext);

    return 0;
}
