package configuration

import (
	"endpointSecurityAgent/internal"
	taskinstances "endpointSecurityAgent/tasks"
	"gopkg.in/yaml.v2"
	"io"
	"os"
)

type ApplicationConfiguration struct {
	FileMonitoring         *taskinstances.FileMonitoring           `yaml:"file_monitoring"`
	ProcessMonitoring      *taskinstances.ProcessMonitoring        `yaml:"process_monitoring"`
	BackDoorMonitoring     *taskinstances.FullSystemVirusDetection `yaml:"virus_monitoring"`
	FileDeltaVirusScanning *taskinstances.FileDeltaVirusDetection  `yaml:"file_delta_virus_detection"`
	EmailNotifier          *internal.EmailNotifier                 `yaml:"email_notifier"`
}

func LoadApplicationConfiguration(location string) (ApplicationConfiguration, error) {
	file, err := os.Open(location)
	if err != nil {
		return ApplicationConfiguration{}, err
	}

	var config ApplicationConfiguration
	content, err := io.ReadAll(file)
	if err != nil {
		return ApplicationConfiguration{}, err
	}

	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return ApplicationConfiguration{}, err
	}

	return config, nil
}
