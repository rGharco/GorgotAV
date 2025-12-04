#include "cli.h"

#define MODULE_NAME "cli.c"

#define ARRAY_LEN(arr) sizeof(arr)/sizeof(arr[0])

#define NULL_CHECK(option, flagName) \
    do { \
        if ((option) == NULL) { \
            log_error(BAD_KEY_CODE, MODULE_NAME, __func__, \
            "The option struct is NULL! No option found for the specified flag: ",(flagName)); \
            return PARSE_STATUS_FAIL; \
        } \
    } while (0)

#define GET_OPT(value) _Generic((value),              \
    const char  : get_short_opt_struct,               \
    char        : get_short_opt_struct,               \
    const char* : get_long_opt_struct,                \
    char*       : get_long_opt_struct                 \
)(value) 

#define MISSING_PARAM_ERR(flag) \
    do { \
        log_error(404, MODULE_NAME, __func__, "Missing required parameter for flag: ", (flag)); \
        return PARSE_STATUS_FAIL; \
    } while (0)

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

    BAD_KEY_CODE
}FLAG_CODES;

struct Option {
    char* flagName;
    int key;
    bool reqParam;
};

AppConfig config = { 0 };

void init_config(AppConfig* config) {
    config->outFile = NULL;
};

static Option shortOptions[] = {
    ['v'] = {"-v", VERBOSE, false},
    ['h'] = {"-h", HELP, false},
    ['o'] = {"-o", OUTPUT, true}
};

static Option longOptions[] = {
    {"--verbose", VERBOSE, false},
    {"--help", HELP, false},
    {"--output", OUTPUT, true}
};

static inline Option* get_short_opt_struct(const char option) {
    if (shortOptions[option].flagName == NULL) {
        return NULL;
    }

    return &shortOptions[option];
}

static Option* get_long_opt_struct(const char* option) {
    for (int i = 0; i < ARRAY_LEN(longOptions); i++) {
        if (strcmp(option, longOptions[i].flagName) == 0) {
            return &longOptions[i];
        }
    }
    return NULL;
}

static int get_opt(const Option* option, const char* param) {
    switch (option->key) {
    case VERBOSE:
        config.flags |= FLAG_VERBOSE;
        return 0;
    case HELP:
        printf("Usage: \n");
        return 0;
    case OUTPUT:
        printf("Parameter received: %s\n", param);
        FILE* outFile = fopen(param, "w");
        errno = 0;

        if (outFile == NULL) {
            perror(strerror(errno));
            return -1;
        }

        LOG_VERBOSE(config.outFile, "Created output file!");

        config.outFile = outFile;
        return 0;
    default:
        break; // won't reach this branch because option cannot be NULL
    }
}

ParseStatus parse_args(int argc, char* argv[]) {
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
        if (argv[i][0] != '-') {
            i++;
            continue;
        }

        int r = 0;
        const char* currArg = argv[i];
        const char* nextArg = (i + 1 < argc) ? argv[i + 1] : NULL;
        size_t argLen = strlen(argv[i]);

        if (currArg[1] == '-') {
            // Check if its an option with a parameter supplied
            char* hasParam = strchr(argv[i], '=');

            //-----------------------------------------------------------
            // Long Option with parameter (e.g output=file.txt)
            //-----------------------------------------------------------

            if (hasParam != NULL) {
                char* param = hasParam + 1;

                __int64 optLen = hasParam - currArg;

                // Option BEFORE = 
                char optStr[64] = { 0 };
                memcpy(optStr, currArg, optLen);
                optStr[optLen] = '\0';

                opt = GET_OPT((const char*)optStr);

                NULL_CHECK(opt, param);

                if (opt->reqParam) {
                    if (strlen(param) != 0) {
                        r = get_opt(opt, param);

                        if (r != 0) return PARSE_STATUS_FAIL;

                        i++;
                        continue;
                    }
                    else {
                        MISSING_PARAM_ERR(optStr);
                    }
                }
            }

            //-----------------------------------------------------------
            // Long Option (e.g --verbose) no parameter
            //-----------------------------------------------------------
            opt = GET_OPT(currArg);
            NULL_CHECK(opt, currArg);

            r = get_opt(opt, NULL);

            if (r != 0) return PARSE_STATUS_FAIL;

            i++;
            continue;
        }

        //-----------------------------------------------------------
        // Combined short options (e.g -vh)
        //-----------------------------------------------------------

        if (argLen >= 3) {
            for (int j = 1; j < argLen; j++) {
                const char flag = currArg[j];
                const char flagString[3] = { '-' ,flag, '\0' };

                opt = GET_OPT(flag);

                NULL_CHECK(opt, (const char*)flag);

                if (opt->reqParam) {
                    if (nextArg != NULL) {
                        r = get_opt(opt, nextArg);

                        if (r != 0) return PARSE_STATUS_FAIL;

                        i++;  // No need for boundry check because the parameter is in the current flag
                        continue;
                    }
                    else {
                        MISSING_PARAM_ERR((char*)flagString);
                    }
                }

                r = get_opt(opt, NULL);

                if (r != 0) return PARSE_STATUS_FAIL;
            }

            i++;
            continue;
        }

        //-----------------------------------------------------------
        // Singular short options (e.g -v -h)
        //-----------------------------------------------------------

        // Get only the short flag char for lookup table
        opt = GET_OPT(currArg[1]);

        NULL_CHECK(opt, currArg);

        if (opt->reqParam) {
            if (nextArg != NULL) {
                r = get_opt(opt, nextArg);

                if (r != 0) return PARSE_STATUS_FAIL;

                i += 2; // Consume value
                CHECK_BOUNDARY(i, argc);

                continue;
            }
            else {
                MISSING_PARAM_ERR(currArg);
            }
        }

        r = get_opt(opt, NULL);

        if (r != 0) return PARSE_STATUS_FAIL;
        i++;
    }

    return PARSE_STATUS_OK;
}

void disable_config(AppConfig* config) {
    if (config->outFile != NULL) fclose(config->outFile);
}