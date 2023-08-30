package internal

import (
	go_clam "endpointSecurityAgent/pkg/go-clam"
	"io/fs"
	"log"
	"path/filepath"
	"time"
)

type BackdoorDetectionTask struct {
}

func (t BackdoorDetectionTask) ExecuteTask() error {
	filepath.Walk("/home/x", func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			clamav := go_clam.GetClEngineInstance()
			hasVirus, err := clamav.ScanFile(path)
			if err != nil {
				return err
			}

			if hasVirus {
				log.Printf("FILE HAS VIRUS (%s)\n", path)
			}

		}

		return nil
	})
	return nil
}

func (t BackdoorDetectionTask) GetNewTimer() time.Timer {
	return *time.NewTimer(time.Minute * 15)
}

func (t BackdoorDetectionTask) GetTaskName() string {
	return "BackdoorDetectionTask"
}
