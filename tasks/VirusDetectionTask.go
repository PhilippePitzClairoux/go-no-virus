package tasks

import (
	"endpointSecurityAgent/pkg/goclam"
	"errors"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"time"
)

type VirusDetection struct {
	AllDirectories       bool     `yaml:"all_directories"`
	SpecificDirectories  []string `yaml:"specific_directories"`
	ExcludedDirectories  []string `yaml:"excluded_directories"`
	initialScanCompleted bool
	stopTask             bool
	timer                *time.Timer
}

func (t *VirusDetection) StopTask() {
	t.stopTask = true
}

func (t *VirusDetection) IsStopped() bool {
	return t.stopTask
}

func (t *VirusDetection) ExecuteTask() error {
	err := t.initialScan()
	if err != nil {
		return err
	}

	return nil
}

func (t *VirusDetection) initialScan() error {
	var err error = nil

	if t.initialScanCompleted {
		return err
	}

	if t.AllDirectories {
		t.walkPath("/")
	} else {
		t.walkPaths(t.SpecificDirectories)
	}

	t.initialScanCompleted = true
	return nil
}

func (t *VirusDetection) walkPaths(paths []string) {
	for _, path := range paths {
		t.walkPath(path)
	}
}

func (t *VirusDetection) walkPath(startingPath string) {
	err := filepath.Walk(startingPath, func(path string, info fs.FileInfo, err error) error {

		if t.stopTask {
			return filepath.SkipAll
		}

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
			clamav := goclam.GetClEngineInstance()
			fileReport := clamav.ScanFile(path)

			if fileReport.HasPotentialIssue {
				err := virusDetected(fileReport)
				return err
			}

		}

		return nil
	})

	log.Println("there was an error during the initial scan : ", err)
}

func (t *VirusDetection) GetDuration() time.Duration {
	return 15 * time.Minute
}

func (t *VirusDetection) GetTaskName() string {
	return "VirusDetectionCron"
}

func (t *VirusDetection) ignoreDirectory(path string) bool {
	for _, file := range t.ExcludedDirectories {
		if strings.Contains(path, file) {
			return true
		}
	}

	return false
}
