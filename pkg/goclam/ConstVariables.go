package goclam

const (
	/* general */
	CL_SCAN_GENERAL_ALLMATCHES           uint32 = 0x1  /* scan in all-match mode */
	CL_SCAN_GENERAL_COLLECT_METADATA     uint32 = 0x2  /* collect metadata (--gen-json) */
	CL_SCAN_GENERAL_HEURISTICS           uint32 = 0x4  /* option to enable heuristic alerts */
	CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE uint32 = 0x8  /* allow heuristic match to take precedence. */
	CL_SCAN_GENERAL_UNPRIVILEGED         uint32 = 0x10 /* scanner will not have read access to files. */

	/* parsing capabilities options */
	CL_SCAN_PARSE_ARCHIVE uint32 = 0x1
	CL_SCAN_PARSE_ELF     uint32 = 0x2
	CL_SCAN_PARSE_PDF     uint32 = 0x4
	CL_SCAN_PARSE_SWF     uint32 = 0x8
	CL_SCAN_PARSE_HWP3    uint32 = 0x10
	CL_SCAN_PARSE_XMLDOCS uint32 = 0x20
	CL_SCAN_PARSE_MAIL    uint32 = 0x40
	CL_SCAN_PARSE_OLE2    uint32 = 0x80
	CL_SCAN_PARSE_HTML    uint32 = 0x100
	CL_SCAN_PARSE_PE      uint32 = 0x200

	/* heuristic alerting options */
	CL_SCAN_HEURISTIC_BROKEN                  uint32 = 0x2    /* alert on broken PE and broken ELF files */
	CL_SCAN_HEURISTIC_EXCEEDS_MAX             uint32 = 0x4    /* alert when files exceed scan limits (filesize, max scansize, or max recursion depth) */
	CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH   uint32 = 0x8    /* alert on SSL mismatches */
	CL_SCAN_HEURISTIC_PHISHING_CLOAK          uint32 = 0x10   /* alert on cloaked URLs in emails */
	CL_SCAN_HEURISTIC_MACROS                  uint32 = 0x20   /* alert on OLE2 files containing macros */
	CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE       uint32 = 0x40   /* alert if archive is encrypted (rar, zip, etc) */
	CL_SCAN_HEURISTIC_ENCRYPTED_DOC           uint32 = 0x80   /* alert if a document is encrypted (pdf, docx, etc) */
	CL_SCAN_HEURISTIC_PARTITION_INTXN         uint32 = 0x100  /* alert if partition table size doesn't make sense */
	CL_SCAN_HEURISTIC_STRUCTURED              uint32 = 0x200  /* data loss prevention options, i.e. alert when detecting personal information */
	CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL   uint32 = 0x400  /* alert when detecting social security numbers */
	CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED uint32 = 0x800  /* alert when detecting stripped social security numbers */
	CL_SCAN_HEURISTIC_STRUCTURED_CC           uint32 = 0x1000 /* alert when detecting credit card numbers */
	CL_SCAN_HEURISTIC_BROKEN_MEDIA            uint32 = 0x2000 /* alert if a file does not match the identified file format, works with JPEG, TIFF, GIF, PNG */

	/* mail scanning options */
	CL_SCAN_MAIL_PARTIAL_MESSAGE uint32 = 0x1

	/* dev options */
	CL_SCAN_DEV_COLLECT_SHA              uint32 = 0x1 /* Enables hash output in sha-collect builds - for internal use only */
	CL_SCAN_DEV_COLLECT_PERFORMANCE_INFO uint32 = 0x2 /* collect performance timings */

	/* cl_countsigs options */
	CL_COUNTSIGS_OFFICIAL   uint32 = 0x1
	CL_COUNTSIGS_UNOFFICIAL uint32 = 0x2
	CL_COUNTSIGS_ALL        uint32 = (CL_COUNTSIGS_OFFICIAL | CL_COUNTSIGS_UNOFFICIAL)

	/* For the new engine_options bit field in the engine */
	ENGINE_OPTIONS_NONE             uint32 = 0x0
	ENGINE_OPTIONS_DISABLE_CACHE    uint32 = 0x1
	ENGINE_OPTIONS_FORCE_TO_DISK    uint32 = 0x2
	ENGINE_OPTIONS_DISABLE_PE_STATS uint32 = 0x4
	ENGINE_OPTIONS_DISABLE_PE_CERTS uint32 = 0x8
	ENGINE_OPTIONS_PE_DUMPCERTS     uint32 = 0x10
)
