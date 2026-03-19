#include "cli.h"

#define MODULE_NAME "cli.c"

#define ARRAY_LEN(arr) sizeof(arr)/sizeof(arr[0])

#define CHECK_UNKNOWN_FLAG(option, flagName) \
    do { \
        if ((option) == NULL) { \
            log_error(UNKNOWN_FLAG_ERR, MODULE_NAME, __func__, \
            "No option found for the specified flag: ",(flagName)); \
            return PARSE_STATUS_FAIL; \
        } \
    } while (0)

#define GET_OPT(value) _Generic((value),              \
    const char  : get_short_opt_struct,               \
    char        : get_short_opt_struct,               \
    const char* : get_long_opt_struct,                \
    char*       : get_long_opt_struct                 \
)(value) 

#define CHECK_BOUNDARY(i, argc) \
    do { \
        if ((i) == (argc)) { \
            return PARSE_STATUS_OK; \
        } \
    } while (0)

typedef enum FLAG_CODES {
    VERBOSE,
    HELP,
    OUTPUT,
    INIT,

    BAD_KEY_CODE
}FLAG_CODES;

static const char* helpInstructions =
    "\nUsage: GrogotAV.exe <Target> <Options>\n"
    "\tAvailable Options:\n\n"
    "\t--init          - Registers the integrity checker to run automatically at system startup.\n"
    "\t--remove        - Removes the integrity checker from system startup.\n"
    "\t--status        - Displays whether the integrity checker is currently registered to run at startup.\n"
    "\t-h / --help     - Displays usage instructions and available options.\n"
    "\t-v / --verbose  - Enables verbose mode, printing detailed execution information.\n"
    "\t-o / --output   - Redirects output to a file. If the file exists, results are appended.\n"
    "\n"
;

struct Option {
    char* flagName;
    int key;
    bool reqParam; 
};

// Mandatory, we use extern in cli.h to define it and we initialize here
AppConfig config;

void init_config() {
    config.target = NULL;
    config.outFile = stdout;
    config.flags = 0;
};

static Option shortOptions[] = {
    ['v'] = {"-v", VERBOSE, false},
    ['h'] = {"-h", HELP, false},
    ['o'] = {"-o", OUTPUT, true}
};

static Option longOptions[] = {
    {"--verbose", VERBOSE, false},
    {"--help", HELP, false},
    {"--output", OUTPUT, true},
    {"--init", INIT, false}
};

static inline Option* get_short_opt_struct(const char option) {
    if (shortOptions[option].flagName == NULL) {
        return NULL;
    }

    return &shortOptions[option];
}

static Option* get_long_opt_struct(const char* option) {
    for (size_t i = 0; i < ARRAY_LEN(longOptions); i++) {
        if (strcmp(option, longOptions[i].flagName) == 0) {
            return &longOptions[i];
        }
    }
    return NULL;
}

static bool is_valid_parameter(const char* parameter, const char* functionName, const char* flag) {
    if (parameter == NULL) {
        log_error(MISSING_REQ_PARAMETER_FOR_FLAG, MODULE_NAME, functionName, "Missing required parameter for flag: ", flag);
        return false;
    }

    if (parameter[0] == '-') {
        log_error(BAD_FLAG_PARAMETER_FORMAT, MODULE_NAME, functionName, "Parameters cannot start with a -. Error for flag: ", flag);
        return false;
    }

    return true;
}

static int get_opt(const Option* option, const char* param) {
    switch (option->key) {
    case VERBOSE:
        config.flags |= FLAG_VERBOSE;
        return 0;
    case OUTPUT: 
        // We do not want to WRITE to a file because it will overwrite it. In the event of a user autocompleting wrong or by accident
        // selecting a file that has content inside we should append the results instead.
        FILE* outFile = fopen(param, "a");
        errno = 0;

        if (outFile == NULL) {
            perror(strerror(errno));
            return -1;
        }

        LOG_VERBOSE(config.outFile, "Created output file!");

        config.outFile = outFile;
        return 0;
    default:
        return -1; // won't reach this branch because option cannot be NULL
    }
}

ParseStatus parse_args(int argc, char* argv[]) {
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        printf(helpInstructions);
        exit(EXIT_SUCCESS);
    }

    // TODO: Maybe find a bettwe way to check for both of these values (since we will add more single flags too like --remove
    // --status etc.
    if (strcmp(argv[1], "--init") == 0) {
        IntegrityStatus integStatus = add_integrity_check_to_startup();

        if (integStatus == INTEGRITY_CHECK_AT_STARTUP_ERR) exit(EXIT_FAILURE);

        if (integStatus == INTEGRITY_CHECK_AT_STARTUP_EXIST) exit(EXIT_SUCCESS);

        integStatus = create_app_data_folder();

        if (integStatus == INTEGRITY_APPDATA_CREATE_ERR) {
            exit(EXIT_FAILURE);
        }

        integStatus = store_integrity_data();

        if (integStatus != INTEGRITY_CHECK_SUCCESS) exit(EXIT_FAILURE);
            
        exit(EXIT_SUCCESS);
    }

    if (strcmp(argv[1], "--remove") == 0) {
        if (remove_integrity_check_from_startup() != INTEGRITY_REMOVE_STARTUP_SUCCESS) exit(EXIT_FAILURE);

        exit(EXIT_SUCCESS);
    }

    if (argc <= 1) {
        log_error(PARSE_STATUS_FAIL, MODULE_NAME, __func__, "Missing required target!", "");
        return PARSE_STATUS_FAIL;
    }

    // This works because CLI arguments persist until program terminations
    config.target = argv[1];

    if (argc == 2) {
        log_warning(MODULE_NAME, __func__, "Program will start in default mode!", "");
        return PARSE_STATUS_OK;
    }

    int i = 2;
    Option* opt = NULL;

    while (i != argc) {
        // As of this moment if you insert gibberish between actual arguments the program wont call it out or stop from executing
        // It is a concious decision for the moment since I wanna focus more on implementing other features rather than how users
        // use the CLI component. If they wish to instert random stuff then so be it the program will work just fine.
        if (argv[i][0] != '-') {
            i++;
            continue;
        }

        int returnCode = 0;
        const char* currArg = argv[i];
        const char* nextArg = (i + 1 < argc) ? argv[i + 1] : NULL; //check boundaries to see if next argument exists
        size_t argLen = strlen(argv[i]);

        // By this point the currArg[0] is already check if it's a - (above if statement) so we go for double dash options (--)
        if (currArg[1] == '-') {
            // Check if its an option with a parameter supplied
            char* hasParam = strchr(argv[i], '=');

            //-----------------------------------------------------------
            // Long Option with parameter (e.g output=file.txt)
            //-----------------------------------------------------------

            if (hasParam != NULL) {
                char* param = hasParam + 1;

                ptrdiff_t optLen = hasParam - currArg;

                // Option BEFORE = 
                char optStr[64] = { 0 };
                memcpy(optStr, currArg, optLen);
                optStr[optLen] = '\0';

                // We cast to const char* beucase in the generic declaration const char* corresponds to long options
                opt = GET_OPT((const char*)optStr);

                CHECK_UNKNOWN_FLAG(opt, param);

                if (opt->reqParam) {
                    if (is_valid_parameter(param, __func__, opt->flagName)) {
                        returnCode = get_opt(opt, param);

                        if (returnCode != 0) return PARSE_STATUS_FAIL;

                        i++;
                        continue;
                    }
                    else {
                        return PARSE_STATUS_FAIL;
                    }
                }
            }

            //-----------------------------------------------------------
            // Long Option (e.g --verbose) no parameter
            //-----------------------------------------------------------
            opt = GET_OPT(currArg);
            CHECK_UNKNOWN_FLAG(opt, currArg);

            returnCode = get_opt(opt, NULL);

            if (returnCode != 0) return PARSE_STATUS_FAIL;

            i++;
            continue;
        }

        //-----------------------------------------------------------
        // Combined short options (e.g -vh)
        //-----------------------------------------------------------

        if (argLen >= 3) {
            for (size_t j = 1; j < argLen; j++) {
                const char flag = currArg[j];
                char flagStr[2] = { 0 };
                flagStr[0] = flag;
                flagStr[1] = '\0';

                opt = GET_OPT(flag);

                // We cast to const char* because the logging function for errors expects a char*
                CHECK_UNKNOWN_FLAG(opt, flagStr);

                if (opt->reqParam) {
                    if (is_valid_parameter(nextArg ,__func__, opt->flagName)) {
                        returnCode = get_opt(opt, nextArg);

                        if (returnCode != 0) return PARSE_STATUS_FAIL;

                        i++;  // No need for boundry check because the parameter is in the current flag
                        continue;
                    }
                    else {
                        return PARSE_STATUS_FAIL;
                    }
                }

                returnCode = get_opt(opt, NULL);

                if (returnCode != 0) return PARSE_STATUS_FAIL;
            }

            i++;
            continue;
        }

        //-----------------------------------------------------------
        // Singular short options (e.g -v -h)
        //-----------------------------------------------------------

        // Get only the short flag char for lookup table
        opt = GET_OPT(currArg[1]);

        CHECK_UNKNOWN_FLAG(opt, currArg);

        if (opt->reqParam) {
            if (is_valid_parameter(nextArg, __func__, opt->flagName)) {
                returnCode = get_opt(opt, nextArg);

                if (returnCode != 0) return PARSE_STATUS_FAIL;

                i += 2; // Consume value
                CHECK_BOUNDARY(i, argc);

                continue;
            }
            else {
                return PARSE_STATUS_FAIL;
            }
        }

        returnCode = get_opt(opt, NULL);

        if (returnCode != 0) return PARSE_STATUS_FAIL;
        i++;
    }

    return PARSE_STATUS_OK;
}

void disable_config() {
    if (config.outFile != NULL) fclose(config.outFile);
}