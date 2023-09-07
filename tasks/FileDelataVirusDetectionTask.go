package tasks

import (
	"endpointSecurityAgent/internal"
	"endpointSecurityAgent/pkg/goclam"
	"errors"
	"io/fs"
	"log"
	"path/filepath"
	"time"
)

type FileDeltaVirusDetection struct {
	Activate bool `yaml:"activate"`
	stopTask bool
}

func (t *FileDeltaVirusDetection) StopTask() {
	t.stopTask = true
}

func (t *FileDeltaVirusDetection) IsStopped() bool {
	return t.stopTask
}

func (t *FileDeltaVirusDetection) ExecuteTask() error {
	files, err := t.getFilesDelta()
	if err != nil {
		return err
	}

	return t.handleFilesDelta(files)
}

func (t *FileDeltaVirusDetection) walkPaths(paths []string) {
	for _, path := range paths {
		t.walkPath(path)
	}
}

func (t *FileDeltaVirusDetection) walkPath(startingPath string) {
	err := filepath.Walk(startingPath, func(path string, info fs.FileInfo, err error) error {

		if t.stopTask {
			return filepath.SkipAll
		}

		//ignore files we dont have access to
		if errors.Is(err, fs.ErrPermission) {
			log.Printf("Skipping directory %s - access denied", path)
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

func (t *FileDeltaVirusDetection) GetDuration() time.Duration {
	return 2 * time.Minute
}

func (t *FileDeltaVirusDetection) GetTaskName() string {
	return "FileDeltaVirusDetection"
}

func (t *FileDeltaVirusDetection) getFilesDelta() ([]string, error) {
	db := internal.GetDatabase()
	defer db.Close()

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

func (t *FileDeltaVirusDetection) handleFilesDelta(files []string) error {

	for _, file := range files {
		engine := goclam.GetClEngineInstance()
		report := engine.ScanFile(file)

		if report.HasPotentialIssue {
			err := virusDetected(report)
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

func (t *FileDeltaVirusDetection) updateFileStatus(file string) error {
	db := internal.GetDatabase()
	defer db.Close()

	_, err := db.Exec("UPDATE file_monitoring_conflicts ON checked = true WHERE path = ?", file)
	if err != nil {
		return err
	}
	return nil
}
