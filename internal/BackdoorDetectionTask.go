package internal

import (
	go_clam "endpointSecurityAgent/pkg/go-clam"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"time"
)

type BackdoorDetectionTask struct {
	AllDirectories       bool     `yaml:"all_directories" cli:"all-directories" description:"Index every single file on OS"`
	SpecificDirectories  []string `yaml:"specific_directories" cli:"specific-dirs" description:"Parse only the following directories"`
	ExcludedDirectories  []string `yaml:"excluded_directories" cli:"exclude-dirs" description:"Parse all directories but exclude the ones that are part of this list"`
	initialScanCompleted bool
}

func (t BackdoorDetectionTask) ExecuteTask() error {
	err := t.initialScan()
	if err != nil {
		return err
	}

	return err
}

func (t BackdoorDetectionTask) initialScan() error {
	var err error = nil

	if t.initialScanCompleted {
		return err
	}

	if t.AllDirectories {
		err = t.walkPath("/")
	} else {
		for _, dir := range t.SpecificDirectories {
			err = t.walkPath(dir)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (t BackdoorDetectionTask) walkPath(rootPath string) error {
	log.Printf("Scanning directory for backdoor : %s", rootPath)

	err := filepath.Walk(rootPath, func(path string, info fs.FileInfo, err error) error {
		// ignore files we dont have access to
		if errors.Is(err, fs.ErrPermission) {
			log.Printf("Skipping directory %s - access denied", path)
			return filepath.SkipDir
		}

		if info.IsDir() && t.ignoreDirectory(path) {
			return filepath.SkipDir
		}

		if !info.IsDir() && info.Mode().Type().Type() != fs.ModeSymlink {
			clamav := go_clam.GetClEngineInstance()
			fileReport := clamav.ScanFile(path)
			if fileReport.ClEngineFlagRaised != "" {
				return errors.New(fmt.Sprintln(fileReport.ClEngineError, fileReport.ClEngineFlagRaised, path))
			}

			if fileReport.HasPotentialIssue {
				log.Printf("%s %s (%d bytes)\n", fileReport.Path, fileReport.ClEngineFlagRaised, fileReport.BytesScanned)
			}

		}

		return nil
	})

	return err
}

func (t BackdoorDetectionTask) GetNewTimer() time.Timer {
	return *time.NewTimer(time.Minute * 15)
}

func (t BackdoorDetectionTask) GetTaskName() string {
	return "BackdoorDetectionTask"
}

func (t BackdoorDetectionTask) ignoreDirectory(path string) bool {
	for _, file := range t.ExcludedDirectories {
		if strings.Contains(path, file) {
			return true
		}
	}

	return false
}
