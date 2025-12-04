#include "file_context.h"
#include "cli.h"

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

    close_file_context(fileContext);

    //-----------------------------------------------------------
    // Close configuration struct
    //-----------------------------------------------------------

    disable_config(&config);

    return 0;
}
