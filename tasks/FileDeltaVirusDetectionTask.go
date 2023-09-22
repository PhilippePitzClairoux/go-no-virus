package tasks

import (
	"endpointSecurityAgent/internal"
	"log"
	"time"
)

type FileDeltaVirusDetection struct {
	Activate bool `yaml:"activate"`
	stopTask bool
	stopChan chan interface{}
}

func (t *FileDeltaVirusDetection) StopChan() chan interface{} {
	if t.stopChan == nil {
		t.stopChan = make(chan interface{})
	}

	return t.stopChan
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

func (t *FileDeltaVirusDetection) GetDuration() time.Duration {
	return 2 * time.Minute
}

func (t *FileDeltaVirusDetection) GetTaskName() string {
	return "FileDeltaVirusDetection"
}

func (t *FileDeltaVirusDetection) getFilesDelta() ([][]string, error) {

	res, err := internal.SelectData(internal.QueryHolder{
		Query:    `SELECT path FROM file_monitoring_conflicts WHERE checked = false`,
		RowCount: 1,
	})

	return res, err
}

func (t *FileDeltaVirusDetection) handleFilesDelta(files [][]string) error {
	for _, file := range files {
		if t.stopTask {
			return nil
		}

		err := scanFileAndReact(file[0])
		if err != nil {
			return err
		}

		err = updateFileStatus(file[0])
		if err != nil {
			log.Println("could not update row after checking file : ", file, err)
		}
	}

	return nil
}

func updateFileStatus(file string) error {
	_, err := internal.ExecuteQuery(
		internal.QueryHolder{
			Query: "UPDATE file_monitoring_conflicts SET checked = true WHERE path = ?",
			Args:  []interface{}{file},
		},
	)

	return err
}
