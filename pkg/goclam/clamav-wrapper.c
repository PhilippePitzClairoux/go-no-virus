
#include <stdio.h>
#include <stdlib.h>
#include <clamav.h>
#include "clamav-wrapper.h"



struct cl_scan_options* get_default_options() {
	struct cl_scan_options *options = (struct cl_scan_options *) malloc(sizeof(struct cl_scan_options));

	options->general = CL_SCAN_GENERAL_ALLMATCHES;
	options->parse = ~0;
	options->heuristic = 0;

	return options;
}

struct cl_engine *create_cl_engine(clamav_init_errors *err_raised) {
    unsigned int sigs;
    cl_error_t ret;

    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
        *err_raised = CLE_ERR_INIT;
        return NULL;
    }

    struct cl_engine *engine = cl_engine_new();
    if (engine == NULL) {
        *err_raised = CLE_ERR_ENGINE_CREATE;
        return NULL;
    }

    ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_BYTECODE | CL_DB_PUA );
    if (ret != CL_SUCCESS) {
        cl_engine_free(engine); // Remember to free the engine to avoid memory leaks.
        *err_raised = CLE_ERR_DATABASE_LOAD;
        return NULL;
    }

    if (cl_engine_compile(engine) != CL_SUCCESS) {
        cl_engine_free(engine); // Remember to free the engine to avoid memory leaks.
        *err_raised = CLE_ERR_COMPILE;
        return NULL;
    }

    return engine;
}