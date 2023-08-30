package go_clam

const (
	/* general */
	CL_SCAN_GENERAL_ALLMATCHES           = 0x1  /* scan in all-match mode */
	CL_SCAN_GENERAL_COLLECT_METADATA     = 0x2  /* collect metadata (--gen-json) */
	CL_SCAN_GENERAL_HEURISTICS           = 0x4  /* option to enable heuristic alerts */
	CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE = 0x8  /* allow heuristic match to take precedence. */
	CL_SCAN_GENERAL_UNPRIVILEGED         = 0x10 /* scanner will not have read access to files. */

	/* parsing capabilities options */
	CL_SCAN_PARSE_ARCHIVE = 0x1
	CL_SCAN_PARSE_ELF     = 0x2
	CL_SCAN_PARSE_PDF     = 0x4
	CL_SCAN_PARSE_SWF     = 0x8
	CL_SCAN_PARSE_HWP3    = 0x10
	CL_SCAN_PARSE_XMLDOCS = 0x20
	CL_SCAN_PARSE_MAIL    = 0x40
	CL_SCAN_PARSE_OLE2    = 0x80
	CL_SCAN_PARSE_HTML    = 0x100
	CL_SCAN_PARSE_PE      = 0x200

	/* heuristic alerting options */
	CL_SCAN_HEURISTIC_BROKEN                  = 0x2    /* alert on broken PE and broken ELF files */
	CL_SCAN_HEURISTIC_EXCEEDS_MAX             = 0x4    /* alert when files exceed scan limits (filesize, max scansize, or max recursion depth) */
	CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH   = 0x8    /* alert on SSL mismatches */
	CL_SCAN_HEURISTIC_PHISHING_CLOAK          = 0x10   /* alert on cloaked URLs in emails */
	CL_SCAN_HEURISTIC_MACROS                  = 0x20   /* alert on OLE2 files containing macros */
	CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE       = 0x40   /* alert if archive is encrypted (rar, zip, etc) */
	CL_SCAN_HEURISTIC_ENCRYPTED_DOC           = 0x80   /* alert if a document is encrypted (pdf, docx, etc) */
	CL_SCAN_HEURISTIC_PARTITION_INTXN         = 0x100  /* alert if partition table size doesn't make sense */
	CL_SCAN_HEURISTIC_STRUCTURED              = 0x200  /* data loss prevention options, i.e. alert when detecting personal information */
	CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL   = 0x400  /* alert when detecting social security numbers */
	CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED = 0x800  /* alert when detecting stripped social security numbers */
	CL_SCAN_HEURISTIC_STRUCTURED_CC           = 0x1000 /* alert when detecting credit card numbers */
	CL_SCAN_HEURISTIC_BROKEN_MEDIA            = 0x2000 /* alert if a file does not match the identified file format, works with JPEG, TIFF, GIF, PNG */

	/* mail scanning options */
	CL_SCAN_MAIL_PARTIAL_MESSAGE = 0x1

	/* dev options */
	CL_SCAN_DEV_COLLECT_SHA              = 0x1 /* Enables hash output in sha-collect builds - for internal use only */
	CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO = 0x2 /* collect performance timings */

	/* cl_countsigs options */
	CL_COUNTSIGS_OFFICIAL   = 0x1
	CL_COUNTSIGS_UNOFFICIAL = 0x2
	CL_COUNTSIGS_ALL        = (CL_COUNTSIGS_OFFICIAL | CL_COUNTSIGS_UNOFFICIAL)

	/* For the new engine_options bit field in the engine */
	ENGINE_OPTIONS_NONE             = 0x0
	ENGINE_OPTIONS_DISABLE_CACHE    = 0x1
	ENGINE_OPTIONS_FORCE_TO_DISK    = 0x2
	ENGINE_OPTIONS_DISABLE_PE_STATS = 0x4
	ENGINE_OPTIONS_DISABLE_PE_CERTS = 0x8
	ENGINE_OPTIONS_PE_DUMPCERTS     = 0x10
)
