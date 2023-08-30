package internal

import (
	"gopkg.in/yaml.v2"
	"io"
	"os"
)

type ApplicationConfiguration struct {
	FileMonitoring     FileMonitoringTask    `yaml:"file_monitoring"`
	ProcessMonitoring  ProcessMonitoringTask `yaml:"process_monitoring"`
	BackDoorMonitoring BackdoorDetectionTask `yaml:"backdoor_monitoring"`
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
