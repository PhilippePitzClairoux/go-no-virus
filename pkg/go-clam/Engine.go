package go_clam

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lclamav
#include <stdio.h>
#include <clamav.h>
#include <string.h>

struct cl_scan_options* getDefaultOptions() {
	struct cl_scan_options *options = (struct cl_scan_options *) malloc(sizeof(struct cl_scan_options));

	options->general = CL_SCAN_GENERAL_ALLMATCHES | CL_SCAN_GENERAL_COLLECT_METADATA | CL_SCAN_GENERAL_HEURISTICS;
	options->parse = CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF | CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_HWP3 | CL_SCAN_PARSE_HTML | CL_SCAN_PARSE_PE;
	options->heuristic = CL_SCAN_HEURISTIC_BROKEN | CL_SCAN_HEURISTIC_EXCEEDS_MAX | CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH | CL_SCAN_HEURISTIC_PHISHING_CLOAK | CL_SCAN_HEURISTIC_MACROS | CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE | CL_SCAN_HEURISTIC_ENCRYPTED_DOC | CL_SCAN_HEURISTIC_PARTITION_INTXN | CL_SCAN_HEURISTIC_STRUCTURED | CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL | CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED | CL_SCAN_HEURISTIC_STRUCTURED_CC | CL_SCAN_HEURISTIC_BROKEN_MEDIA;

	return options;
}

*/
import "C"

import (
	"errors"
	"log"
	"time"
	"unsafe"
)

var GlobalEngine ClEngine

const (
	ClEngineMaxScansize = iota
	ClEngineMaxFilesize
	ClEngineMaxRecursion
	ClEngineMaxFiles
	ClEngineMinCcCount
	ClEngineMinSsnCount
	ClEnginePuaCategories
	ClEngineDbOptions
	ClEngineDbVersion
	ClEngineDbTime
	ClEngineAcOnly
	ClEngineAcMindepth
	ClEngineAcMaxdepth
	ClEngineTmpdir
	ClEngineKeeptmp
	ClEngineBytecodeSecurity
	ClEngineBytecodeTimeout
	ClEngineBytecodeMode
	ClEngineMaxEmbeddedpe
	ClEngineMaxHtmlnormalize
	ClEngineMaxHtmlnotags
	ClEngineMaxScriptnormalize
	ClEngineMaxZiptypercg
	ClEngineForcetodisk
	ClEngineDisableCache
	ClEngineDisablePeStats
	ClEngineStatsTimeout
	ClEngineMaxPartitions
	ClEngineMaxIconspe
	ClEngineMaxRechwp3
	ClEngineMaxScantime
	ClEnginePcreMatchLimit
	ClEnginePcreRecmatchLimit
	ClEnginePcreMaxFilesize
	ClEngineDisablePeCerts
	ClEnginePeDumpcerts
)

//var (
//	ClEngineFieldType = map[int]any{
//		ClEngineMaxScansize:        new(uint64),
//		ClEngineMaxFilesize:        new(uint64),
//		ClEngineMaxRecursion:       new(uint32),
//		ClEngineMaxFiles:           new(uint32),
//		ClEngineMinCcCount:         new(uint32),
//		ClEngineMinSsnCount:        new(uint32),
//		ClEnginePuaCategories:      new(string),
//		ClEngineDbOptions:          new(uint32),
//		ClEngineDbVersion:          new(uint32),
//		ClEngineDbTime:             new(time.Time),
//		ClEngineAcOnly:             new(uint32),
//		ClEngineAcMindepth:         new(uint32),
//		ClEngineAcMaxdepth:         new(uint32),
//		ClEngineTmpdir:             new(string),
//		ClEngineKeeptmp:            new(uint32),
//		ClEngineBytecodeSecurity:   new(uint32),
//		ClEngineBytecodeTimeout:    new(uint32),
//		ClEngineBytecodeMode:       new(uint32),
//		ClEngineMaxEmbeddedpe:      new(uint64),
//		ClEngineMaxHtmlnormalize:   new(uint64),
//		ClEngineMaxHtmlnotags:      new(uint64),
//		ClEngineMaxScriptnormalize: new(uint64),
//		ClEngineMaxZiptypercg:      new(uint64),
//		ClEngineForcetodisk:        new(uint32),
//		ClEngineDisableCache:       new(uint32),
//		ClEngineDisablePeStats:     new(uint32),
//		ClEngineStatsTimeout:       new(uint32),
//		ClEngineMaxPartitions:      new(uint32),
//		ClEngineMaxIconspe:         new(uint32),
//		ClEngineMaxRechwp3:         new(uint32),
//		ClEngineMaxScantime:        new(uint32),
//		ClEnginePcreMatchLimit:     new(uint64),
//		ClEnginePcreRecmatchLimit:  new(uint64),
//		ClEnginePcreMaxFilesize:    new(uint64),
//		ClEngineDisablePeCerts:     new(uint32),
//		ClEnginePeDumpcerts:        new(uint32),
//	}
//)

type ClEngine struct {
	instance                   *C.struct_cl_engine
	defaultScanOptions         *C.struct_cl_scan_options
	ClEngineMaxScansize        uint64
	ClEngineMaxFilesize        uint64
	ClEngineMaxRecursion       uint32
	ClEngineMaxFiles           uint32
	ClEngineMinCcCount         uint32
	ClEngineMinSsnCount        uint32
	ClEnginePuaCategories      string
	ClEngineDbOptions          uint32
	ClEngineDbVersion          uint32
	ClEngineDbTime             time.Time
	ClEngineAcOnly             uint32
	ClEngineAcMindepth         uint32
	ClEngineAcMaxdepth         uint32
	ClEngineTmpdir             string
	ClEngineKeeptmp            uint32
	ClEngineBytecodeSecurity   uint32
	ClEngineBytecodeTimeout    uint32
	ClEngineBytecodeMode       uint32
	ClEngineMaxEmbeddedpe      uint64
	ClEngineMaxHtmlnormalize   uint64
	ClEngineMaxHtmlnotags      uint64
	ClEngineMaxScriptnormalize uint64
	ClEngineMaxZiptypercg      uint64
	ClEngineForcetodisk        uint32
	ClEngineDisableCache       uint32
	ClEngineDisablePeStats     uint32
	ClEngineStatsTimeout       uint32
	ClEngineMaxPartitions      uint32
	ClEngineMaxIconspe         uint32
	ClEngineMaxRechwp3         uint32
	ClEngineMaxScantime        uint32
	ClEnginePcreMatchLimit     uint64
	ClEnginePcreRecmatchLimit  uint64
	ClEnginePcreMaxFilesize    uint64
	ClEngineDisablePeCerts     uint32
	ClEnginePeDumpcerts        uint32
}

//func (cle *ClEngine) setField(ClEngineProperty int, value any) error {
//	target := ClEngineFieldType[ClEngineProperty]
//	valueType := reflect.TypeOf(value)
//	targetType := reflect.TypeOf(target)
//	var err C.int
//
//	if valueType != targetType {
//		return errors.New(fmt.Sprintf("value does not match target type (got %s, expected %s)", valueType, targetType))
//	}
//
//	switch targetType.Kind() {
//	case reflect.Uint64:
//	case reflect.Uint32:
//		C.cl_engine_set_num(cle.instance, ClEngineProperty, value)
//	case reflect.Struct:
//		if t, ok := value.(time.Time); ok {
//			C.cl_engine_set_num(cle.instance, ClEngineProperty, t.Unix())
//		} else {
//			return errors.New("could not convert value to time struct")
//		}
//	case reflect.String:
//		cValue := C.CString(value)
//		C.cl_engine_set_str(cle.instance, ClEngineProperty, cValue)
//		C.free(unsafe.Pointer(cValue))
//	}
//
//	return nil
//}

func init() {
	var sigs C.uint
	var ret C.cl_error_t

	log.Println("clamav init...")
	if C.cl_init(C.CL_INIT_DEFAULT) != 0 {
		log.Fatal("could not initialize clamav")
	}

	log.Println("creating clamav engine...")
	engine := C.cl_engine_new()
	if engine == nil {
		log.Fatal("could not create new engine")
	}

	log.Println("loading clamav database...")
	ret = C.cl_load(C.cl_retdbdir(), engine, &sigs, C.CL_DB_STDOPT)
	if ret != C.CL_SUCCESS {
		log.Fatal("could not initialize database")
	}

	log.Println("compile clamav engine + database...")
	if C.cl_engine_compile(engine) != C.CL_SUCCESS {
		log.Fatal("could not initialize database")
	}
	GlobalEngine = ClEngine{
		instance:           engine,
		defaultScanOptions: C.getDefaultOptions(),
	}

	log.Println("Done setting up clamav!")
}

func GetClEngineInstance() ClEngine {
	return GlobalEngine
}

func CloseClEngine() {
	C.cl_engine_free(GlobalEngine.instance)
	C.free(unsafe.Pointer(GlobalEngine.defaultScanOptions))
}

func (cle *ClEngine) ScanFile(filePath string) (bool, error) {
	var virusName *C.char
	var scanned C.ulong = 0

	cFilePath := C.CString(filePath)
	defer C.free(unsafe.Pointer(cFilePath))

	err := C.cl_scanfile(cFilePath, &virusName, &scanned, cle.instance, cle.defaultScanOptions)

	if err == C.CL_VIRUS {
		return true, nil
	} else if err != C.CL_SUCCESS {
		return false, errors.New(C.GoString(C.cl_strerror((C.int)(err))))
	} else {
		return false, nil
	}
}
