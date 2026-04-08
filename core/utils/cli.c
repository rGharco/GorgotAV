#include "cli.h"

#define MODULE_NAME "cli.c"

#define ARRAY_LEN(arr) (sizeof(arr) / sizeof(arr[0]))

#define CHECK_UNKNOWN_FLAG(option, flagName)                                                       \
    do {                                                                                           \
        if ((option) == NULL) {                                                                    \
            log_error(UNKNOWN_FLAG_ERR, MODULE_NAME, __func__,                                    \
                      "No option found for the specified flag: ", (flagName));                     \
            return PARSE_STATUS_FAIL;                                                              \
        }                                                                                          \
    } while (0)

#define GET_OPT(value)                                                                             \
    _Generic((value),                                                                              \
        const char  : get_short_opt_struct,                                                        \
        char        : get_short_opt_struct,                                                        \
        const char* : get_long_opt_struct,                                                         \
        char*       : get_long_opt_struct)(value)

#define CHECK_BOUNDARY(i, argc)                                                                    \
    do {                                                                                           \
        if ((i) == (argc)) {                                                                       \
            return PARSE_STATUS_OK;                                                                \
        }                                                                                          \
    } while (0)

// Maximum length for a long option string (e.g. "--output"), not including the '=' or parameter.
#define MAX_OPT_STR_LEN 64

#define BOX_H (ui_ansi_enabled ? "\xe2\x94\x80" : "-")
#define WIDTH 64

// Icons
#define ICON_LONG   "\xe2\xac\xa1"   // ⬡  long-only flags  (startup group)
#define ICON_SHORT  "\xe2\x97\x88"   // ◈  short+long pairs (general group)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
bool ui_ansi_enabled = false;
 
void ui_init(void) {
    if (IS_TTY(stdout)) {
        SetConsoleOutputCP(CP_UTF8);
        ui_ansi_enabled = true;
    } else {
        ui_ansi_enabled = false;
    }
}

// ---------------------------------------------------------------------------
// Help command construction
// ---------------------------------------------------------------------------

static void section(_In_ const char* label) {
    int llen = (int)strlen(label);

    int right = WIDTH - (llen + 1);
    if (right < 0) right = 0;

    printf("%s%s%s ", CYAN_LT, label, RST);
    printf("%s", BLUE_DK);
    for (int i = 0; i < right; i++) {
        fputs(BOX_H, stdout);
    }
    printf("%s\n", RST);
}

// A single flag row.
// icon      — ICON_LONG or ICON_SHORT
// shortf    — e.g. "-v" or NULL for long-only flags
// longf     — e.g. "--verbose"
// param     — e.g. "<file>" or NULL
// desc      — description string
static void flag_row(_In_ const char* restrict icon, _In_ const char* restrict shortf, _In_ const char* restrict longf, _In_ const char* restrict param, _In_ const char* restrict desc) { 
    printf("%s%s%s ", BLUE_DK, icon, RST);            // ⬡ / ◈
 
    if (shortf) {
        printf("%s%s%s", CYAN_LT, shortf, RST);       // -v
        printf("%s / %s", MUTED, RST);                // /
        printf("%s%-14s%s", CYAN_LT, longf, RST);     // --verbose      (14 wide)
    } else {
        printf("  %s%-16s%s", CYAN_LT, longf, RST);   // --init         (16 wide, no short)
    }
 
    if (param) {
        printf(" %s%-8s%s", MUTED, param, RST);       // <file>
    } else {
        printf("  %8s", "");                           // blank spacer
    }

    printf("%s%s%s", MUTED, desc, RST);               // description
    printf("\n");
}

static void show_help() {
    printf("%s%sGrogotAV %s", BOLD, CYAN_LT, RST);
    printf("%sv1.0.0%s", BLUE_DK, RST);
    printf("  %sIntegrity checker & antivirus utility%s", MUTED, RST);
    printf("\n\n");

    // ── usage row ──────────────────────────────────────────────────────────
    printf("Usage: %sGrogotAV.exe%s ", CYAN_LT, RST);
    printf("<target>");
    printf("%s [options]%s", BLUE_DK, RST);
    printf("\n\n");

    // ── STARTUP section ────────────────────────────────────────────────────
    section("Startup");
    flag_row(ICON_LONG,  NULL, "--init",
             NULL,    "Register integrity checker at system startup");
    flag_row(ICON_LONG,  NULL, "--remove",
             NULL,    "Remove integrity checker from system startup");
    flag_row(ICON_LONG,  NULL, "--status",
             NULL,    "Show whether startup registration is active");
    printf("\n");

    // ── GENERAL section ────────────────────────────────────────────────────
    section("GENERAL");
    flag_row(ICON_SHORT, "-h", "--help",
             NULL,    "Display this help message");
    flag_row(ICON_SHORT, "-v", "--verbose",
             NULL,    "Print detailed execution information");
    flag_row(ICON_SHORT, "-o", "--output",
             "<file>", "Append output to file instead of stdout");
    printf("\n");


    // ── footer row ─────────────────────────────────────────────────────────
    printf("%s", BLUE_DK);
    for(int i = 0; i < WIDTH; i++) fputs(BOX_H, stdout);
    printf("%s", RST);
    printf("\n%sTip: combined flags are supported  ", BLUE_DK);
    printf("GrogotAV.exe <target> -vo out.txt%s\n", RST);
}

struct Option {
    char*    flagName;
    int      key;
    bool     reqParam;
};

typedef enum FLAG_CODES {
    VERBOSE,
    HELP,
    OUTPUT,
    INIT,
    REMOVE,
    STATUS,

    BAD_KEY_CODE
} FLAG_CODES;

// Mandatory: extern-declared in cli.h, defined and initialised here.
AppConfig config;

void init_config(void) {
    config.target  = NULL;
    config.outFile = stdout;
    config.flags   = 0;
}

static Option shortOptions[] = {
    ['v'] = { "-v", VERBOSE, false },
    ['h'] = { "-h", HELP,    false },
    ['o'] = { "-o", OUTPUT,  true  },
};

static Option longOptions[] = {
    { "--verbose", VERBOSE, false },
    { "--help",    HELP,    false },
    { "--output",  OUTPUT,  true  },
    { "--init",    INIT,    false },
    { "--remove",  REMOVE,  false },
    { "--status",  STATUS,  false },
};

// ---------------------------------------------------------------------------
// Option lookup helpers
// ---------------------------------------------------------------------------

static inline Option* get_short_opt_struct(const char option) {
    if ((unsigned char)option >= ARRAY_LEN(shortOptions) ||
        shortOptions[(unsigned char)option].flagName == NULL) {
        return NULL;
    }
    return &shortOptions[(unsigned char)option];
}

static Option* get_long_opt_struct(const char* option) {
    for (size_t i = 0; i < ARRAY_LEN(longOptions); i++) {
        if (strcmp(option, longOptions[i].flagName) == 0) {
            return &longOptions[i];
        }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Parameter validation
// ---------------------------------------------------------------------------

static bool is_valid_parameter(const char* parameter, const char* functionName, const char* flag) {
    if (parameter == NULL) {
        log_error(MISSING_REQ_PARAMETER_FOR_FLAG, MODULE_NAME, functionName,
                  "Missing required parameter for flag: ", flag);
        return false;
    }
    if (parameter[0] == '-') {
        log_error(BAD_FLAG_PARAMETER_FORMAT, MODULE_NAME, functionName,
                  "Parameters cannot start with '-'. Error for flag: ", flag);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Output-file helper  (extracted from get_opt to keep dispatch clean)
// ---------------------------------------------------------------------------

static int open_output_file(const char* path) {
    FILE* outFile = fopen(path, "a");
    if (outFile == NULL) {
        perror(path);
        return -1;
    }
    LOG_VERBOSE(config.outFile, "Opened output file for appending.");
    config.outFile = outFile;
    return 0;
}

// ---------------------------------------------------------------------------
// Central option dispatcher
// ---------------------------------------------------------------------------

static int get_opt(const Option* option, const char* param) {
    switch (option->key) {
    case VERBOSE:
        config.flags |= FLAG_VERBOSE;
        return 0;

    case OUTPUT:
        return open_output_file(param);

    case HELP:
        show_help();
        exit(EXIT_SUCCESS);

    case INIT: {
        IntegrityStatus s = add_integrity_check_to_startup();
        if (s == INTEGRITY_CHECK_AT_STARTUP_ERR)    exit(EXIT_FAILURE);
        if (s == INTEGRITY_CHECK_AT_STARTUP_EXIST)  exit(EXIT_SUCCESS);

        s = create_app_data_folder();
        if (s == INTEGRITY_APPDATA_CREATE_ERR)      exit(EXIT_FAILURE);

        s = store_integrity_data();
        if (s != INTEGRITY_CHECK_SUCCESS)           exit(EXIT_FAILURE);

        exit(EXIT_SUCCESS);
    }

    case REMOVE:
        if (remove_integrity_check_from_startup() != INTEGRITY_REMOVE_STARTUP_SUCCESS)
            exit(EXIT_FAILURE);
        exit(EXIT_SUCCESS);

    case STATUS:
        // TODO: implement status query
        exit(EXIT_SUCCESS);

    default:
        return -1;
    }
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

ParseStatus parse_args(int argc, char* argv[]) {
    // Guard first — before any argv[1] access.
    if (argc <= 1) {
        log_error(PARSE_STATUS_FAIL, MODULE_NAME, __func__, "Missing required target!", "");
        return PARSE_STATUS_FAIL;
    }

    // argv[1] is safe from here onwards.
    // Standalone/meta flags that do not require a target come first.
    {
        Option* opt = GET_OPT(argv[1]);
        if (opt != NULL && !opt->reqParam) {
            if (opt->key == HELP || opt->key == INIT || opt->key == REMOVE || opt->key == STATUS) {
                get_opt(opt, NULL);
                // get_opt exits above; unreachable, but keeps flow explicit.
                return PARSE_STATUS_OK;
            }
        }
    }

    // argv[1] must be the scan target, not a flag.
    if (argv[1][0] == '-') {
        log_error(PARSE_STATUS_FAIL, MODULE_NAME, __func__,
                  "Expected a target path but got a flag: ", argv[1]);
        return PARSE_STATUS_FAIL;
    }

    config.target = argv[1]; 

    if (argc == 2) {
        log_warning(MODULE_NAME, __func__, "No flags supplied — running in default mode.", "");
        return PARSE_STATUS_OK;
    }

    int i = 2;
    while (i != argc) {
        if (argv[i][0] != '-') {
            i++;
            continue;
        }

        int         returnCode = 0;
        const char* currArg   = argv[i];
        const char* nextArg   = (i + 1 < argc) ? argv[i + 1] : NULL;
        size_t      argLen    = strlen(currArg);
        Option*     opt       = NULL;

        // ----------------------------------------------------------------
        // Long options  (start with --)
        // ----------------------------------------------------------------
        if (currArg[1] == '-') {
            char* hasParam = strchr(currArg, '=');

            // Long option with inline parameter: --output=file.txt
            if (hasParam != NULL) {
                ptrdiff_t optLen = hasParam - currArg;

                if (optLen <= 0 || (size_t)optLen >= MAX_OPT_STR_LEN) {
                    log_error(UNKNOWN_FLAG_ERR, MODULE_NAME, __func__,
                              "Option name too long or malformed: ", currArg);
                    return PARSE_STATUS_FAIL;
                }

                char optStr[MAX_OPT_STR_LEN] = { 0 };
                memcpy(optStr, currArg, (size_t)optLen);

                opt = GET_OPT((const char*)optStr);
                CHECK_UNKNOWN_FLAG(opt, currArg);

                if (opt->reqParam) {
                    const char* param = hasParam + 1;
                    if (!is_valid_parameter(param, __func__, opt->flagName))
                        return PARSE_STATUS_FAIL;

                    returnCode = get_opt(opt, param);
                    if (returnCode != 0) return PARSE_STATUS_FAIL;

                    i++;
                    continue;
                }
            }

            // Long option without parameter: --verbose
            opt = GET_OPT(currArg);
            CHECK_UNKNOWN_FLAG(opt, currArg);

            returnCode = get_opt(opt, NULL);
            if (returnCode != 0) return PARSE_STATUS_FAIL;

            i++;
            continue;
        }

        // ----------------------------------------------------------------
        // Combined short options: -vh, -vo file.txt
        // ----------------------------------------------------------------
        if (argLen >= 3) {
            bool consumed_next = false;

            for (size_t j = 1; j < argLen; j++) {
                char flag = currArg[j];

                opt = GET_OPT(flag);

                char flagStr[3] = { '-', flag, '\0' };
                CHECK_UNKNOWN_FLAG(opt, flagStr);

                if (opt->reqParam) {
                    if (!is_valid_parameter(nextArg, __func__, opt->flagName))
                        return PARSE_STATUS_FAIL;

                    returnCode = get_opt(opt, nextArg);
                    if (returnCode != 0) return PARSE_STATUS_FAIL;

                    consumed_next = true;
                    break; 
                }

                returnCode = get_opt(opt, NULL);
                if (returnCode != 0) return PARSE_STATUS_FAIL;
            }

            i += consumed_next ? 2 : 1;
            CHECK_BOUNDARY(i, argc);
            continue;
        }

        // ----------------------------------------------------------------
        // Singular short option: -v, -h
        // ----------------------------------------------------------------
        opt = GET_OPT(currArg[1]);
        CHECK_UNKNOWN_FLAG(opt, currArg);

        if (opt->reqParam) {
            if (!is_valid_parameter(nextArg, __func__, opt->flagName))
                return PARSE_STATUS_FAIL;

            returnCode = get_opt(opt, nextArg);
            if (returnCode != 0) return PARSE_STATUS_FAIL;

            i += 2; 
            CHECK_BOUNDARY(i, argc);
            continue;
        }

        returnCode = get_opt(opt, NULL);
        if (returnCode != 0) return PARSE_STATUS_FAIL;
        i++;
    }

    return PARSE_STATUS_OK;
}

// ---------------------------------------------------------------------------
// Cleanup
// ---------------------------------------------------------------------------

void disable_config(void) {
    if (config.outFile != NULL && config.outFile != stdout) {
        fclose(config.outFile);
        config.outFile = NULL;
    }
}