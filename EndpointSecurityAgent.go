package main

import (
	"endpointSecurityAgent/internal"
	go_clam "endpointSecurityAgent/pkg/goclam"
	"log"
	"os"
)

func main() {
	defer go_clam.CloseClEngine()
	errChan := make(chan internal.ErrorEvent)
	exitChan := make(chan os.Signal)
	scheduler := internal.NewScheduler(errChan, exitChan)
	conf, err := internal.LoadApplicationConfiguration("./default.yaml")

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
	err = scheduler.RegisterTask(internal.Task(conf.BackDoorMonitoring))
	if err != nil {
		log.Fatal(err)
	}

	scheduler.StartTasks()
}
