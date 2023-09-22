package main

import (
	"endpointSecurityAgent/configuration"
	"endpointSecurityAgent/internal"
	go_clam "endpointSecurityAgent/pkg/goclam"
	"log"
	"os"
)

func main() {
	err := go_clam.InitClEngine()
	if err != nil {
		log.Fatal("Could not start clamav : ", err)
	}

	defer go_clam.CloseClEngine()

	errChan := make(chan internal.ErrorEvent)
	exitChan := make(chan os.Signal)
	scheduler := internal.NewScheduler(errChan, exitChan)
	conf, err := configuration.LoadApplicationConfiguration("./default.yaml.local")

	// register file monitoring
	if conf.FileMonitoring.AllDirectories {
		err = scheduler.RegisterTask(internal.Task(conf.FileMonitoring))
		if err != nil {
			log.Fatal(err)
		}
	}

	// register process monitoring
	if conf.ProcessMonitoring.AuditAllProcesses {
		err = scheduler.RegisterTask(internal.Task(conf.ProcessMonitoring))
		if err != nil {
			log.Fatal(err)
		}
	}

	// register virus detection
	if conf.BackDoorMonitoring.AllDirectories {
		err = scheduler.RegisterTask(internal.Task(conf.BackDoorMonitoring))
		if err != nil {
			log.Fatal(err)
		}
	}

	if conf.FileDeltaVirusScanning.Activate {
		err = scheduler.RegisterTask(internal.Task(conf.FileDeltaVirusScanning))
		if err != nil {
			log.Fatal(err)
		}
	}

	scheduler.StartTasks()
}
