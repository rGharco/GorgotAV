#include "file_context.h"
#include "cli.h"
#include "static_analysis.h"
#include "analysis_result.h"
#include "logging.h"

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

    static_analysis(fileContext, analysisResult);

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
