package goclam

/*
#cgo CFLAGS: -I/usr/include
#cgo LDFLAGS: -lclamav
#include <stdio.h>
#include <clamav.h>
#include <string.h>
#include "clamav-wrapper.h"

*/
import "C"

import (
	"errors"
	"unsafe"
)

type clEnginePtr *C.struct_cl_engine
type clScanOptionsPtr *C.struct_cl_scan_options
type ClEngineProperty int

var GlobalEngine ClEngine

type ClEngine struct {
	instance           clEnginePtr
	defaultScanOptions clScanOptionsPtr
}

type ClEngineFileReport struct {
	Path               string
	BytesScanned       uint64
	HasPotentialIssue  bool
	ClEngineFlagRaised string
	ClEngineError      string
}

func InitClEngine() error {
	var errorRaised C.clamav_init_errors
	var err error

	GlobalEngine = ClEngine{
		instance:           C.create_cl_engine(&errorRaised),
		defaultScanOptions: C.get_default_options(),
	}

	switch errorRaised {
	case C.CLE_ERR_INIT:
		err = errors.New("could not initialize clamav library")
	case C.CLE_ERR_ENGINE_CREATE:
		err = errors.New("could not create instance of clamav scan engine")
	case C.CLE_ERR_DATABASE_LOAD:
		err = errors.New("could not load clamav database")
	case C.CLE_ERR_COMPILE:
		err = errors.New("could not compile clamav with its database")
	default:
		err = nil
	}

	return err
}

func GetClEngineInstance() ClEngine {
	return GlobalEngine
}

func CloseClEngine() {
	C.cl_engine_free(GlobalEngine.instance)
	C.free(unsafe.Pointer(GlobalEngine.defaultScanOptions))
}

// setGeneralOptions sets general field in cl_engine_options
// (value example : CL_SCAN_GENERAL_ALLMATCHES | CL_SCAN_GENERAL_HEURISTICS | CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE)
func (cle *ClEngine) setGeneralOptions(value uint32) {
	(*cle.defaultScanOptions).general = C.uint(value)
}

// setParseOptions sets parse field in cl_engine_options
// (value example : CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_PDF)
func (cle *ClEngine) setParseOptions(value uint32) {
	(*cle.defaultScanOptions).parse = C.uint(value)
}

// setHeuristicOptions sets heuristic field in cl_engine_options
// (value example : CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE | CL_SCAN_HEURISTIC_PARTITION_INTXN | CL_SCAN_HEURISTIC_STRUCTURED)
func (cle *ClEngine) setHeuristicOptions(value uint32) {
	(*cle.defaultScanOptions).heuristic = C.uint(value)
}

func (cle *ClEngine) ScanFile(filePath string) ClEngineFileReport {
	var virusName *C.char
	var scanned C.ulong = 0

	cFilePath := C.CString(filePath)

	defer C.free(unsafe.Pointer(cFilePath))
	defer C.free(unsafe.Pointer(virusName))

	err := C.cl_scanfile(cFilePath, &virusName, &scanned, cle.instance, cle.defaultScanOptions)

	return ClEngineFileReport{
		filePath,
		uint64(scanned),
		err == C.CL_VIRUS,
		C.GoString(virusName),
		C.GoString(C.cl_strerror(err)),
	}

}
