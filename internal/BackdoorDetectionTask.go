package internal

import (
	go_clam "endpointSecurityAgent/pkg/go-clam"
	"errors"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"time"
)

type BackdoorDetectionTask struct {
	AllDirectories       bool     `yaml:"all_directories"`
	SpecificDirectories  []string `yaml:"specific_directories"`
	ExcludedDirectories  []string `yaml:"excluded_directories"`
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

func (t BackdoorDetectionTask) walkPath(startingPath string) error {
	err := filepath.Walk(startingPath, func(path string, info fs.FileInfo, err error) error {
		//ignore files we dont have access to
		if errors.Is(err, fs.ErrPermission) {
			log.Printf("Skipping directory %s - access denied", path)
			return filepath.SkipDir
		}

		if info.IsDir() && t.ignoreDirectory(path) {
			log.Println(path, " is listed in exclude configuration - skipping")
			return filepath.SkipDir
		}

		if info.Mode().IsRegular() {
			clamav := go_clam.GetClEngineInstance()
			fileReport := clamav.ScanFile(path)

			if fileReport.HasPotentialIssue {
				log.Printf("%s %s %s (%d bytes)\n", fileReport.Path, fileReport.ClEngineFlagRaised, fileReport.ClEngineError, fileReport.BytesScanned)
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
