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
	AllDirectories      bool     `yaml:"all_directories"`
	SpecificDirectories []string `yaml:"specific_directories"`
	ExcludedDirectories []string `yaml:"excluded_directories"`
	stopTask            bool
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

	if t.AllDirectories {
		return t.walkPath("/")
	} else {
		return t.walkPaths(t.SpecificDirectories)
	}

}

func (t *VirusDetection) walkPaths(paths []string) error {
	for _, path := range paths {
		err := t.walkPath(path)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *VirusDetection) walkPath(startingPath string) error {
	err := filepath.Walk(startingPath, func(path string, info fs.FileInfo, err error) error {

		if t.stopTask {
			return filepath.SkipAll
		}

		//ignore files we don't have access to
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

	return err
}

func (t *VirusDetection) GetDuration() time.Duration {
	return 60 * time.Minute
}

func (t *VirusDetection) GetTaskName() string {
	return "VirusDetection"
}

func (t *VirusDetection) ignoreDirectory(path string) bool {
	for _, file := range t.ExcludedDirectories {
		if strings.Contains(path, file) {
			return true
		}
	}

	return false
}
