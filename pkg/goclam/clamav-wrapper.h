// error enum
typedef enum {
    CLE_ERR_INIT = 1,
    CLE_ERR_ENGINE_CREATE,
    CLE_ERR_DATABASE_LOAD,
    CLE_ERR_COMPILE
} clamav_init_errors;

// exported methods
struct cl_scan_options* get_default_options();

struct cl_engine *create_cl_engine(clamav_init_errors *);