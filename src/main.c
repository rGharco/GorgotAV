#include "file_context.h"
#include "cli.h"
#include "static_analysis.h"
#include "analysis_result.h"
#include "logging.h"

int main(int argc, char* argv[]) {
    //-----------------------------------------------------------
    // Parse command line arguments
    //-----------------------------------------------------------

    init_config(&config);

    ParseStatus argParseStatus = parse_args(argc, argv);

    if (argParseStatus != PARSE_STATUS_OK) {
        exit(EXIT_FAILURE);
    }

    printf("Target: %s\n", config.target);

    //-----------------------------------------------------------
    // Create file context
    //-----------------------------------------------------------

    PFileContext fileContext = create_file_context(config.target);

    if (fileContext == NULL) {
        exit(EXIT_FAILURE);
    }

	AnalysisResult* analysisResult = create_analysis_result(fileContext);

    static_analysis(fileContext, analysisResult);

	log_analysis_result(analysisResult);

    //-----------------------------------------------------------
    // Cleanup
    //-----------------------------------------------------------

    disable_config(&config);
	destroy_analysis_result(analysisResult);
    close_file_context(fileContext);

    return 0;
}
