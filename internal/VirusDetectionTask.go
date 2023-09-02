package internal

import (
	"endpointSecurityAgent/pkg/goclam"
	"errors"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
	"time"
)

type VirusDetectionTask struct {
	AllDirectories       bool     `yaml:"all_directories"`
	SpecificDirectories  []string `yaml:"specific_directories"`
	ExcludedDirectories  []string `yaml:"excluded_directories"`
	initialScanCompleted bool
}

func (t VirusDetectionTask) ExecuteTask() error {
	err := t.initialScan()
	if err != nil {
		return err
	}

	files, err := t.getFilesDelta()
	if err != nil {
		return err
	}

	return t.handleFilesDelta(files)
}

func (t VirusDetectionTask) initialScan() error {
	var err error = nil

	if t.initialScanCompleted {
		return err
	}

	if t.AllDirectories {
		go t.walkPath("/")
	} else {
		go t.walkPaths(t.SpecificDirectories)
	}

	t.initialScanCompleted = true
	return nil
}

func (t VirusDetectionTask) walkPaths(paths []string) {
	for _, path := range paths {
		t.walkPath(path)
	}
}

func (t VirusDetectionTask) walkPath(startingPath string) {
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
			clamav := goclam.GetClEngineInstance()
			fileReport := clamav.ScanFile(path)

			if fileReport.HasPotentialIssue {
				err := t.virusDetected(fileReport)
				return err
			}

		}

		return nil
	})

	log.Println("there was an error during the initial scan : ", err)
}

func (t VirusDetectionTask) GetNewTimer() time.Timer {
	return *time.NewTimer(time.Minute * 15)
}

func (t VirusDetectionTask) GetTaskName() string {
	return "VirusDetectionTask"
}

func (t VirusDetectionTask) ignoreDirectory(path string) bool {
	for _, file := range t.ExcludedDirectories {
		if strings.Contains(path, file) {
			return true
		}
	}

	return false
}

func (t VirusDetectionTask) getFilesDelta() ([]string, error) {
	db := GetDatabase()
	var results []string
	var path string

	query, err := db.Query(`SELECT path FROM file_monitoring_conflicts WHERE checked = false`)
	if err != nil {
		return nil, err
	}

	for query.Next() {
		err := query.Scan(&path)
		if err != nil {
			return nil, err
		}

		results = append(results, path)
	}

	return results, nil
}

func (t VirusDetectionTask) handleFilesDelta(files []string) error {

	for _, file := range files {
		engine := goclam.GetClEngineInstance()
		report := engine.ScanFile(file)

		if report.HasPotentialIssue {
			err := t.virusDetected(report)
			if err != nil {
				return err
			}
		}

		err := t.updateFileStatus(file)
		if err != nil {
			log.Println("could not update row after checking file : ", file)
		}
	}

	return nil
}

func (t VirusDetectionTask) updateFileStatus(file string) error {
	db := GetDatabase()
	_, err := db.Exec("UPDATE file_monitoring_conflicts ON checked = true WHERE path = ?", file)
	if err != nil {
		return err
	}
	return nil
}

func (t VirusDetectionTask) virusDetected(report goclam.ClEngineFileReport) error {
	log.Printf("%s %s %s (%d bytes)\n", report.Path, report.ClEngineFlagRaised, report.ClEngineError, report.BytesScanned)
	db := GetDatabase()
	_, err := db.Exec("INSERT OR IGNORE INTO virus_detected(path, cause) VALUES (?, ?)", report.Path, report.ClEngineFlagRaised)
	return err
}