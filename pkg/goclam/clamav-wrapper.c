
#include <stdio.h>
#include <stdlib.h>
#include <clamav.h>
#include "clamav-wrapper.h"

struct cl_scan_options* get_default_options() {
	struct cl_scan_options *options = (struct cl_scan_options *) malloc(sizeof(struct cl_scan_options));

	options->general = CL_SCAN_GENERAL_ALLMATCHES | CL_SCAN_GENERAL_COLLECT_METADATA | CL_SCAN_GENERAL_HEURISTICS;

	options->parse = CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF | CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_HWP3
	| CL_SCAN_PARSE_XMLDOCS | CL_SCAN_PARSE_MAIL | CL_SCAN_PARSE_HTML | CL_SCAN_PARSE_PE | CL_SCAN_PARSE_OLE2;

	options->heuristic = CL_SCAN_HEURISTIC_BROKEN | CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH
	| CL_SCAN_HEURISTIC_PHISHING_CLOAK | CL_SCAN_HEURISTIC_MACROS | CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE | CL_SCAN_HEURISTIC_ENCRYPTED_DOC |
	 CL_SCAN_HEURISTIC_PARTITION_INTXN | CL_SCAN_HEURISTIC_STRUCTURED | CL_SCAN_HEURISTIC_STRUCTURED_CC | CL_SCAN_HEURISTIC_BROKEN_MEDIA;

	return options;
}

struct cl_engine *create_cl_engine() {
    unsigned int sigs;
    cl_error_t ret;

    printf("clamav init...\n");
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
        printf("could not initialize clamav\n");
        exit(1);
    }

    printf("creating clamav engine...\n");
    struct cl_engine *engine = cl_engine_new();
    if (engine == NULL) {
        printf("could not create new engine\n");
        exit(1);
    }

    printf("loading clamav database...\n");
    ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);
    if (ret != CL_SUCCESS) {
        printf("could not initialize database\n");
        cl_engine_free(engine); // Remember to free the engine to avoid memory leaks.
        exit(1);
    }

    printf("Prepare clamav engine + database...\n");
    if (cl_engine_compile(engine) != CL_SUCCESS) {
        printf("could not initialize database\n");
        cl_engine_free(engine); // Remember to free the engine to avoid memory leaks.
        exit(1);
    }


    return engine;
}