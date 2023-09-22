package tasks

import (
	"errors"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"time"
)

type FullSystemVirusDetection struct {
	AllDirectories      bool     `yaml:"all_directories"`
	SpecificDirectories []string `yaml:"specific_directories"`
	ExcludedDirectories []string `yaml:"excluded_directories"`
	stopTask            bool
	stopChan            chan interface{}
}

func (t *FullSystemVirusDetection) StopChan() chan interface{} {
	if t.stopChan == nil {
		t.stopChan = make(chan interface{})
	}

	return t.stopChan
}

func (t *FullSystemVirusDetection) StopTask() {
	t.stopTask = true
}

func (t *FullSystemVirusDetection) IsStopped() bool {
	return t.stopTask
}

func (t *FullSystemVirusDetection) ExecuteTask() error {
	err := t.doScan()
	if err != nil {
		return err
	}

	return nil
}

func (t *FullSystemVirusDetection) doScan() error {

	if t.AllDirectories {
		return t.walkPath("/")
	} else {
		return t.walkPaths(t.SpecificDirectories)
	}

}

func (t *FullSystemVirusDetection) walkPaths(paths []string) error {
	for _, path := range paths {
		err := t.walkPath(path)
		if err != nil {
			return err
		}
	}

	return nil
}

func (t *FullSystemVirusDetection) walkPath(startingPath string) error {
	err := filepath.Walk(startingPath, func(path string, info fs.FileInfo, err error) error {

		if t.stopTask {
			return filepath.SkipAll
		}

		//ignore files we don't have access to
		if errors.Is(err, fs.ErrPermission) {
			if info != nil && info.IsDir() {
				log.Printf("Skipping directory %s - access denied", path)
				return filepath.SkipDir
			} else {
				return nil
			}
		}

		if info != nil && info.IsDir() && t.ignoreDirectory(path) {
			log.Println(path, " is listed in exclude configuration - skipping")
			return filepath.SkipDir
		}

		if info != nil && info.Mode().IsRegular() {
			err = scanFileAndReact(path)
			if err != nil {
				return err
			}

		}

		return nil
	})

	return err
}

func (t *FullSystemVirusDetection) GetDuration() time.Duration {
	return 120 * time.Minute
}

func (t *FullSystemVirusDetection) GetTaskName() string {
	return "FullSystemVirusDetection"
}

func (t *FullSystemVirusDetection) ignoreDirectory(path string) bool {
	for _, file := range t.ExcludedDirectories {
		if strings.Contains(path, file) {
			return true
		}
	}

	return false
}
